"""A backend's CGI header aliases must not revive fields removed at the edge."""

import contextlib
import json
import os
import socket
import threading
from unittest.mock import patch
from wsgiref.simple_server import WSGIRequestHandler, make_server

from test_sweep_proxy_request import (_Backend, _exchange, _guard, _shield,
                                      _read_framed_request)


_WATCH = ("HTTP_X_FORWARDED_HOST", "HTTP_X_FORWARDED_FOR",
          "HTTP_X_FORWARDED_PROTO", "HTTP_X_ORIGINAL_URL",
          "HTTP_X_HTTP_METHOD_OVERRIDE", "HTTP_X_EDGE_TOKEN",
          "HTTP_X_TRACE_ID", "HTTP_X_CUSTOM_NOTE", "HTTP_X_SESSION_TENANT",
          "HTTP_X_APP_ROLE",
          "HTTP_CONTENT_LENGTH", "HTTP_TRANSFER_ENCODING", "CONTENT_LENGTH")


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *_args):
        pass


class _WsgiRelay(_Backend):
    """Capture exact origin wire, then relay it to a real stdlib WSGI origin."""

    def __init__(self, origin_port):
        self.origin_port = origin_port
        super().__init__()

    def _one(self, conn):
        conn.settimeout(2)
        try:
            request = _read_framed_request(conn, limit=65536)
            self.got.append(request)
            with socket.create_connection(("127.0.0.1", self.origin_port), timeout=2) as origin:
                origin.sendall(request)
                origin.shutdown(socket.SHUT_WR)
                response = bytearray()
                origin.settimeout(2)
                while True:
                    part = origin.recv(65536)
                    if not part:
                        break
                    response.extend(part)
            conn.sendall(response)
        except OSError:
            pass
        finally:
            conn.close()


@contextlib.contextmanager
def _origin_pair():
    seen = []

    def app(environ, start_response):
        captured = {name: environ.get(name) for name in _WATCH}
        seen.append(captured)
        body = json.dumps(captured, sort_keys=True).encode("ascii")
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Content-Length", str(len(body)))])
        return [body]

    origin = make_server("127.0.0.1", 0, app, handler_class=_QuietHandler)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    relay = _WsgiRelay(origin.server_port)
    try:
        yield relay, seen
    finally:
        relay.close()
        origin.shutdown()
        origin.server_close()
        thread.join(2)


def _request(*header_lines):
    return b"GET /safe HTTP/1.1\r\nHost: origin.test\r\n" + b"\r\n".join(header_lines) + b"\r\n\r\n"


def test_cgi_aliases_of_protected_fields_never_reach_origin():
    # Python's real WSGIRequestHandler maps '-' to '_' when producing CGI env
    # names. The old edge strips/checks only hyphenated names, yet forwards
    # these aliases unchanged; the origin sees spoofed routing/trust values.
    attack = _request(
        b"X_Forwarded_Host: poison.example",
        b"X_Forwarded_For: 203.0.113.77",
        b"X_Forwarded_Proto: https",
        b"X_Original_URL: /private",
        b"X_HTTP_Method_Override: DELETE",
        b"X_Edge_Token: attacker",
    )
    with _origin_pair() as (backend, seen):
        with _shield(strip_cache_poison_headers=True, path_override_block=True,
                     method_override_check=True), _guard(backend) as guard:
            response = _exchange(guard, [attack])
        assert backend.got == [] and seen == [], (backend.got, seen, response)


def test_hyphenated_poison_header_is_stripped_and_unrelated_header_survives():
    benign = _request(b"X-Forwarded-Host: poison.example",
                      b"X-Trace-Id: safe-note")
    with _origin_pair() as (backend, seen):
        with _shield(strip_cache_poison_headers=True), _guard(backend) as guard:
            response = _exchange(guard, [benign])
        assert response.startswith(b"HTTP/1.0 200") or response.startswith(b"HTTP/1.1 200"), response
        assert len(backend.got) == len(seen) == 1
        assert b"X-Forwarded-Host:" not in backend.got[0]
        assert seen[0]["HTTP_X_FORWARDED_HOST"] is None
        assert seen[0]["HTTP_X_TRACE_ID"] == "safe-note"


def test_unrelated_underscore_header_remains_usable():
    # An alias that does not collide with an inspected or rewritten field
    # remains a legitimate HTTP token and must retain its ordinary behavior.
    with _origin_pair() as (backend, seen):
        with _shield(), _guard(backend) as guard:
            response = _exchange(guard, [_request(b"X_Custom_Note: safe-note")])
        assert response.startswith(b"HTTP/1.0 200") or response.startswith(b"HTTP/1.1 200"), response
        assert len(backend.got) == len(seen) == 1
        assert b"X_Custom_Note: safe-note\r\n" in backend.got[0]
        assert seen[0]["HTTP_X_CUSTOM_NOTE"] == "safe-note"


def test_two_distinct_names_collapsing_to_one_cgi_key_are_rejected():
    # Real WSGI joins these as HTTP_X_APP_ROLE='user,admin'. An application
    # may take either endpoint value while the edge sees separate fields.
    attack = _request(b"X-App-Role: user", b"X_App_Role: admin")
    with _origin_pair() as (backend, seen):
        with _shield(), _guard(backend) as guard:
            response = _exchange(guard, [attack])
        assert backend.got == [] and seen == [], (backend.got, seen, response)


def test_single_app_header_keeps_ordinary_cgi_mapping():
    with _origin_pair() as (backend, seen):
        with _shield(), _guard(backend) as guard:
            response = _exchange(guard, [_request(b"X-App-Role: user")])
        assert response.startswith(b"HTTP/1.0 200") or response.startswith(b"HTTP/1.1 200"), response
        assert len(backend.got) == len(seen) == 1
        assert seen[0]["HTTP_X_APP_ROLE"] == "user"


def test_mixed_delimiter_and_custom_poison_aliases_never_reach_origin():
    # Mixed separators map to the same WSGI key as a hyphenated field.
    # A configured custom removal rule must cover the same alias space.
    for header in (b"X-Forwarded_Host: poison.example",
                   b"X_Forwarded-Host: poison.example",
                   b"X_Session_Tenant: untrusted"):
        with _origin_pair() as (backend, seen):
            with _shield(strip_cache_poison_headers=True,
                         cache_poison_headers=["x-forwarded-host", "x-session-tenant"]), \
                    _guard(backend) as guard:
                response = _exchange(guard, [_request(header)])
            assert backend.got == [] and seen == [], (header, backend.got, seen, response)


def test_cgi_framing_aliases_cannot_reach_origin_as_distinct_app_metadata():
    # WSGI does not frame on these aliases. It exposes Transfer_Encoding as
    # HTTP_TRANSFER_ENCODING, whereas it treats Content_Length specially and
    # omits the HTTP_ alias. Other origins can canonicalize field names before
    # framing, so the edge must not forward a second spelling for CL or TE.
    for header in (b"Content_Length: 4", b"Transfer_Encoding: chunked"):
        with _origin_pair() as (backend, seen):
            with _shield(), _guard(backend) as guard:
                response = _exchange(guard, [_request(header)])
            assert backend.got == [] and seen == [], (header, backend.got, seen, response)


def test_connection_options_cannot_alias_edge_owned_fields():
    from dataplane.engine.services.proxy import _framing_ambiguous

    for header in (b"Connection: X_Forwarded_For",
                   b"Proxy-Connection: X_Original_URL"):
        assert _framing_ambiguous(_request(header)), header
    assert not _framing_ambiguous(_request(b"Connection: X_Custom_Note"))


def test_configured_underscore_origin_header_cannot_be_preceded_by_hyphen_alias():
    # The configured edge-owned header may itself contain '_' (HTTP token).
    # WSGI maps both spellings to HTTP_X_EDGE_TOKEN and comma-joins values.
    with patch.dict(os.environ, {"DUCKNET_ORIGIN_KEY": "r12-synthetic-origin-key"}):
        with _origin_pair() as (backend, seen):
            with _shield(origin_cloaking_enabled=True, origin_header="X_Edge_Token"), \
                    _guard(backend) as guard:
                response = _exchange(guard, [_request(b"X-Edge-Token: attacker")])
            if backend.got:
                assert b"X-Edge-Token: attacker\r\n" not in backend.got[0], \
                    (backend.got, seen, response)
                assert len(seen) == 1 and "attacker" not in (seen[0]["HTTP_X_EDGE_TOKEN"] or "")
            else:
                assert seen == [] and response.startswith(b"HTTP/1.1 400"), response


def test_exact_configured_origin_header_is_replaced_by_edge_token():
    with patch.dict(os.environ, {"DUCKNET_ORIGIN_KEY": "r12-synthetic-origin-key"}):
        with _origin_pair() as (backend, seen):
            with _shield(origin_cloaking_enabled=True, origin_header="X_Edge_Token"), \
                    _guard(backend) as guard:
                response = _exchange(guard, [_request(b"X_Edge_Token: attacker")])
            assert response.startswith(b"HTTP/1.0 200") or response.startswith(b"HTTP/1.1 200"), response
            assert len(backend.got) == len(seen) == 1
            assert b"X_Edge_Token: attacker\r\n" not in backend.got[0]
            assert (seen[0]["HTTP_X_EDGE_TOKEN"] and
                    "attacker" not in seen[0]["HTTP_X_EDGE_TOKEN"])


def test_forwarding_helpers_remove_cgi_aliases_after_head_validation():
    from dataplane.engine.services.proxy import _set_request_header, _strip_request_headers

    raw = _request(b"X_Session_Tenant: untrusted", b"X_Custom_Note: safe-note")
    stripped = _strip_request_headers(raw, ["x-session-tenant"])
    assert b"X_Session_Tenant:" not in stripped, stripped
    assert b"X_Custom_Note: safe-note\r\n" in stripped

    raw = _request(b"X-Edge-Token: attacker", b"X_Edge_Token: old")
    replaced = _set_request_header(raw, "X_Edge_Token", "edge-generated")
    assert b"X-Edge-Token: attacker\r\n" not in replaced, replaced
    assert b"X_Edge_Token: old\r\n" not in replaced
    assert replaced.count(b"X_Edge_Token: edge-generated\r\n") == 1


def test_canonical_path_override_is_rejected_before_origin():
    with _origin_pair() as (backend, seen):
        with _shield(path_override_block=True), _guard(backend) as guard:
            response = _exchange(guard, [_request(b"X-Original-URL: /private")])
        assert backend.got == [] and seen == [], (backend.got, seen, response)
