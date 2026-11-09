"""Private management data must remain authenticated and uncacheable."""
import http.client
import json
import os
from unittest import mock

from test_admin_browser_mac import _signed, _response_is_signed
from test_sweep_admin_ui import _Admin


_MARKER = "privacy_canary_example_invalid"


def _request(admin, method, path, *, authenticated=False, headers=None, body=None):
    supplied = {"X-Token": admin.token} if authenticated else {}
    supplied.update(headers or {})
    if isinstance(body, dict):
        supplied["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    connection = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=supplied)
        response = connection.getresponse()
        return response.status, response.headers, response.read()
    finally:
        connection.close()


def _not_cacheable(response):
    status, headers, _body = response
    assert headers.get_all("Cache-Control") == ["no-store"], (status, list(headers.items()))
    assert headers.get_all("Pragma") == ["no-cache"], (status, list(headers.items()))
    assert headers.get_all("Expires") == ["0"], (status, list(headers.items()))


def test_private_admin_state_requires_authentication_and_forbids_storage():
    with _Admin() as admin:
        assert admin.fw.add_rule("198.51.100.61/32", "deny", note=_MARKER)["ok"]
        private = _request(admin, "GET", "/api/state", authenticated=True)
        assert private[0] == 200 and _MARKER.encode() in private[2]
        assert admin.token.encode() not in private[2]
        rejected = []
        for path in ("/api/state", "/api/admin_audit", "/api/analysis", "/api/edge",
                     "/api/shield/signatures", "/api/state?token=" + admin.token,
                     "/.statekey", "/app.env", "/acl.json"):
            response = _request(admin, "GET", path)
            assert response[0] == 401 and _MARKER.encode() not in response[2], path
            assert admin.token.encode() not in response[2]
            rejected.append(response)
        cookie = _request(admin, "GET", "/api/state",
                          headers={"Cookie": "ducknet_admin=" + admin.token})
        assert cookie[0] == 401
        for response in (private, cookie, *rejected):
            _not_cacheable(response)


def test_html_icons_json_and_download_are_never_cacheable():
    with _Admin() as admin:
        admin.adm._icon_bytes = b"privacy test image bytes"
        admin.adm._icon_ct = "image/png"
        for path, authenticated, content in (("/", False, "text/html"),
                                              ("/index.html", False, "text/html"),
                                              ("/brand-icon", False, "image/png"),
                                              ("/api/edge", True, "text/plain"),
                                              ("/api/metrics", True, "text/plain"),
                                              ("/api/admin_audit", True, "application/json")):
            response = _request(admin, "GET", path, authenticated=authenticated)
            assert response[0] == 200 and response[1].get("Content-Type").startswith(content)
            assert admin.token.encode() not in response[2]
            _not_cacheable(response)
        changed = _request(admin, "POST", "/api/firewall/toggle", authenticated=True,
                           body={"on": True})
        assert changed[0] == 200 and json.loads(changed[2])["ok"] is True
        _not_cacheable(changed)


def test_all_admin_error_paths_including_base_http_errors_forbid_storage():
    with _Admin() as admin, mock.patch.dict(os.environ, {"DUCKNET_ADMIN_ALLOWED_HOSTS": ""}):
        cases = [(400, _request(admin, "POST", "/api/firewall/toggle", authenticated=True, body={})),
                 (401, _request(admin, "GET", "/api/state")),
                 (403, _request(admin, "POST", "/api/firewall/toggle", authenticated=True,
                                headers={"Origin": "http://untrusted.example.invalid"}, body={"on": True})),
                 (404, _request(admin, "GET", "/not-found", authenticated=True)),
                 (421, _request(admin, "GET", "/", headers={"Host": "untrusted.example.invalid"})),
                 (501, _request(admin, "HEAD", "/api/state")),
                 (501, _request(admin, "OPTIONS", "/api/state"))]
        with mock.patch.object(admin.adm, "state", side_effect=RuntimeError("synthetic read failure")):
            cases.append((500, _request(admin, "GET", "/api/state", authenticated=True)))
        for expected, response in cases:
            assert response[0] == expected, (expected, response[0])
            _not_cacheable(response)


def test_no_store_does_not_weaken_browser_proofs_or_replay_rejection():
    with _Admin() as admin:
        instance = admin.adm._browser_instance_id
        headers = _signed(admin.token, instance, "GET", "/api/state")
        first = _request(admin, "GET", "/api/state", headers=headers)
        assert first[0] == 200
        _response_is_signed(admin.token, instance, headers["X-Admin-Auth-Nonce"], *first)
        replay = _request(admin, "GET", "/api/state", headers=headers)
        assert replay[0] == 401
        page = _request(admin, "GET", "/?token=" + admin.token)
        assert page[0] == 200 and admin.token.encode() not in page[2]
        assert b"sessionStorage.getItem" not in page[2]
        assert b"sessionStorage.setItem" not in page[2]
        assert "Max-Age=0" in page[1].get("Set-Cookie", "")
        assert admin.token not in page[1].get("Set-Cookie", "")
        for response in (first, replay, page):
            _not_cacheable(response)
