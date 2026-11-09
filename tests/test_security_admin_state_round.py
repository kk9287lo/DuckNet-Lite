"""Management request framing must have one meaning before a state change."""
import json
import http.client
import socket
import tempfile

from test_falco_admin_boundaries import _Admin, _signed


_BODY = b'{"on":false}'


def _wire(admin, content_length):
    request = (b"POST /api/shield/toggle HTTP/1.1\r\n"
               + b"Host: 127.0.0.1:" + str(admin.port).encode() + b"\r\n"
               + b"X-Token: " + admin.token.encode() + b"\r\n"
               + b"Content-Length: " + content_length + b"\r\n"
               + b"Connection: close\r\n\r\n" + _BODY)
    with socket.create_connection(("127.0.0.1", admin.port), timeout=2) as peer:
        peer.settimeout(2)
        peer.sendall(request)
        chunks = []
        while True:
            chunk = peer.recv(65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


def test_single_decimal_length_keeps_authenticated_operation():
    with _Admin() as admin:
        response = _wire(admin, b"0" + str(len(_BODY)).encode())
        assert response.startswith(b"HTTP/1.0 200") or response.startswith(b"HTTP/1.1 200"), response
        assert not admin.sh.is_enabled()


def test_duplicate_length_cannot_mutate_configuration():
    with _Admin() as admin:
        status, _, data = admin.request([("X-Token", admin.token),
                                         ("Content-Length", str(len(_BODY)))], body=_BODY)
        assert status == 400 and json.loads(data)["ok"] is False, (status, data)
        assert admin.sh.is_enabled() and not admin.adm.audit_log()["entries"]
        good_status, _, good_data = admin.request([("X-Token", admin.token)], body=_BODY)
        assert good_status == 200 and json.loads(good_data)["ok"] is True
        assert not admin.sh.is_enabled()


def test_shadowed_transfer_encoding_cannot_mutate_configuration():
    with _Admin() as admin:
        status, _, data = admin.request([("X-Token", admin.token),
                                         ("Transfer-Encoding", ""),
                                         ("Transfer-Encoding", "chunked")], body=_BODY)
        assert status == 400 and json.loads(data)["ok"] is False, (status, data)
        assert admin.sh.is_enabled() and not admin.adm.audit_log()["entries"]


def test_signed_content_length_is_rejected_before_dispatch():
    with _Admin() as admin:
        response = _wire(admin, b"+" + str(len(_BODY)).encode())
        assert response.startswith(b"HTTP/1.0 400") or response.startswith(b"HTTP/1.1 400"), response
        assert admin.sh.is_enabled() and not admin.adm.audit_log()["entries"]


def test_malformed_get_framing_is_rejected_before_browser_nonce_is_consumed():
    with _Admin() as admin:
        for malformed in (("Content-Length", "0"), ("Transfer-Encoding", "chunked")):
            proof = _signed(admin, method="GET", path="/api/state", body=b"")
            before = len(admin.adm._browser_nonces)
            status, _, _ = admin.request(proof + [malformed], method="GET", body=b"")
            assert status == 400 and len(admin.adm._browser_nonces) == before, status
            status, _, data = admin.request(proof, method="GET", body=b"")
            assert status == 200 and "shield" in json.loads(data), (status, data)
            assert len(admin.adm._browser_nonces) == before + 1


def _config_post(admin, value):
    body = json.dumps({"sec_headers_extra": value}).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=2)
    try:
        conn.request("POST", "/api/shield/config", body=body,
                     headers={"X-Token": admin.token, "Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def test_invalid_extra_response_headers_reject_the_whole_admin_replacement():
    with _Admin() as admin:
        good = {"X-Existing": "public"}
        assert _config_post(admin, good)[1]["ok"] is True
        before = len(admin.adm.audit_log()["entries"])
        bad = (
            {"X-Public": "safe\r\nX-Marker: injected"},
            {"X-Public\r\nX-Marker": "injected"},
            {"X-Public": "safe\x00opaque"},
            {"Content-Length": "0"},
            {"Transfer-Encoding": "chunked"},
            {"X-Origin-IP": "private-origin.example"},
            {"X-Public": "one", "x-public": "two"},
            {f"X-{index}": "public" for index in range(129)},
            {"X-Public": "v" * 16385},
            {"X-First": "v" * 16384, "X-Second": "v" * 16384},
            {"X-Public": "\u6c34"},
        )
        for entry in bad:
            status, result = _config_post(admin, entry)
            # The admin preflight now rejects an invalid value before any
            # cluster quiesce or state mutation.
            assert status == 400 and result["ok"] is False, (entry, status, result)
            assert result.get("rejected") == ["sec_headers_extra"], (entry, result)
            assert admin.sh.cfg["sec_headers_extra"] == good, entry
            assert len(admin.adm.audit_log()["entries"]) == before


def test_valid_extra_response_headers_preserve_previous_wire_meaning():
    from test_sweep_proxy_request import _through

    with _Admin() as admin:
        status, result = _config_post(admin, {"X-Public": "safe", "X-Count": 3,
                                              "X-Latin": "caf\u00e9"})
        assert status == 200 and result["ok"] is True, (status, result)
        saved = admin.sh.cfg["sec_headers_extra"]
        assert saved["X-Public"] == "safe" and str(saved["X-Count"]) == "3"
        assert saved["X-Latin"] == "caf\u00e9"
    request = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    got, out, _ = _through([request], backend_resp=response, sec_headers_enabled=True,
                           sec_headers_extra={"X-Public": "safe"},
                           cookie_harden_enabled=False, cors_harden_enabled=False,
                           open_redirect_enabled=False)
    assert got.startswith(b"GET /public HTTP/1.1\r\n")
    assert b"\r\nX-Public: safe\r\n" in out and out.endswith(b"\r\n\r\nok"), out


def test_invalid_runtime_extra_header_cannot_publish_a_second_header_line():
    from test_sweep_proxy_request import _through

    request = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    got, out, metrics = _through([request], backend_resp=response, sec_headers_enabled=True,
                                 sec_headers_extra={"X-Public": "safe\r\nX-Marker: injected"},
                                 cookie_harden_enabled=False, cors_harden_enabled=False,
                                 open_redirect_enabled=False)
    assert got.startswith(b"GET /public HTTP/1.1\r\n")
    assert out == b"" and metrics.get("response_config_invalid") == 1, (out, metrics)


def test_exact_extra_header_value_limit_remains_usable_on_the_wire():
    from test_sweep_proxy_request import _through

    value = b"v" * 16384
    request = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    got, out, _ = _through([request], backend_resp=response, sec_headers_enabled=True,
                           sec_headers_extra={"X-Public": value.decode("ascii")},
                           cookie_harden_enabled=False, cors_harden_enabled=False,
                           open_redirect_enabled=False)
    assert got.startswith(b"GET /public HTTP/1.1\r\n")
    assert b"\r\nX-Public: " + value + b"\r\n" in out and out.endswith(b"\r\n\r\nok")


def test_legacy_signed_extra_headers_sanitize_invalid_entries_with_a_visible_event():
    from dataplane.engine.lifeform.pipeline import NetShield

    with tempfile.TemporaryDirectory() as state:
        old = NetShield(state_dir=state)
        old.cfg["sec_headers_extra"] = {"X-Public": "safe", "X-Unsafe": "v\r\nX-Marker: injected"}
        assert old._save() is True
        current = NetShield(state_dir=state)
        assert current.cfg["sec_headers_extra"] == {"X-Public": "safe"}, current.cfg
        assert any(event.get("kind") == "cfg_load_rejected"
                   and event.get("elements", {}).get("sec_headers_extra") == 1
                   for event in current.events(500)), current.events(500)
