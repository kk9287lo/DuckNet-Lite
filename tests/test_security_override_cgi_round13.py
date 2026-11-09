"""CGI aliases of route and method override headers must meet edge policy."""

import contextlib
import socket
import threading
from wsgiref.simple_server import WSGIRequestHandler, make_server

from test_security_header_underscore_round12 import _WsgiRelay
from test_sweep_proxy_request import _exchange, _guard, _shield


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def _origin_pair():
    seen = []

    def app(environ, start_response):
        method = environ.get("HTTP_X_HTTP_METHOD") or environ["REQUEST_METHOD"]
        route = environ.get("HTTP_X_OVERRIDE_URL") or environ["PATH_INFO"]
        seen.append((method, route, environ.get("HTTP_X_CUSTOM_NOTE")))
        body = (b"PRIVATE" if method == "DELETE" or route == "/vault-round13"
                else b"PUBLIC")
        start_response("200 OK", [("Content-Type", "text/plain"),
                                  ("Content-Length", str(len(body)))])
        return [body]

    origin = make_server("127.0.0.1", 0, app, handler_class=_QuietHandler)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    relay = _WsgiRelay(origin.server_port)
    try:
        yield origin.server_port, relay, seen
    finally:
        relay.close()
        origin.shutdown()
        origin.server_close()
        thread.join(2)


def _request(header):
    return (b"GET /public HTTP/1.1\r\nHost: origin.test\r\n" +
            header + b"\r\n\r\n")


def _direct(port, request):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


def test_single_cgi_override_alias_cannot_reach_origin():
    cases = (
        (b"X_HTTP_Method: DELETE", ("DELETE", "/public", None)),
        (b"X_Override_URL: /vault-round13", ("GET", "/vault-round13", None)),
    )
    for header, expected in cases:
        for mode in ("enforce", "audit"):
            request = _request(header)
            with _origin_pair() as (port, backend, seen):
                direct = _direct(port, request)
                assert direct.startswith(b"HTTP/1.0 200") and b"PRIVATE" in direct
                assert seen == [expected], (header, seen)
                seen.clear()

                with _shield(mode=mode, blocked_methods=["DELETE"],
                             path_override_block=True, block_score=1000), \
                        _guard(backend) as guard:
                    response = _exchange(guard, [request])
                    metrics = dict(guard.metrics)
                assert backend.got == [] and seen == [] and metrics["proxied"] == 0, \
                    (header, response, backend.got, seen, metrics)
                assert response.startswith(b"HTTP/1.1 400"), (header, mode, response)


def test_unrelated_header_still_reaches_wsgi_origin():
    request = _request(b"X_Custom_Note: benign")
    with _origin_pair() as (_port, backend, seen):
        with _shield(mode="enforce", blocked_methods=["DELETE"],
                     path_override_block=True), _guard(backend) as guard:
            response = _exchange(guard, [request])
        assert response.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")), response
        assert b"PUBLIC" in response
        assert len(backend.got) == 1 and seen == [("GET", "/public", "benign")]
