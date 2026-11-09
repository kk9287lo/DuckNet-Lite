"""One backend credential cannot become many edge rate-limit identities."""

import contextlib
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from test_sweep_proxy_request import _exchange, _guard, _shield


_SECRET = b"SECRET-DATA"
_KEY = b"secret"
_VARIANTS = (b"secret\x85", b"secret\x85\x85",
             b"secret\xa0", b"secret\xa0\xa0")


@contextlib.contextmanager
def _backend():
    seen = []

    class Capture:
        def __init__(self, source):
            self.source = source
            self.lines = []

        def readline(self, *args):
            line = self.source.readline(*args)
            self.lines.append(line)
            return line

        def __getattr__(self, name):
            return getattr(self.source, name)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.rfile = Capture(self.rfile)

        def do_GET(self):
            raw = self.headers.get("X-API-Key", "")
            allowed = raw.strip() == "secret"
            seen.append((b"".join(self.rfile.lines), raw, allowed))
            body = _SECRET if allowed else b"DENIED"
            self.send_response(200 if allowed else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port, seen
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def _request(key, *, user_agent=b""):
    head = b"GET /api/data HTTP/1.1\r\nHost: local.test\r\nX-API-Key: " + key + b"\r\n"
    if user_agent:
        head += b"User-Agent: " + user_agent + b"\r\n"
    return head + b"\r\n"


def _direct(port, request):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        return b"".join(iter(lambda: client.recv(65536), b""))


def test_latin1_space_cannot_rotate_one_backend_api_key_across_edge_buckets():
    with _backend() as (port, seen):
        for key in _VARIANTS:
            direct = _direct(port, _request(key))
            assert direct.startswith(b"HTTP/1.0 200") and _SECRET in direct
            assert seen[-1][1:] == (key.decode("latin-1"), True)
        seen.clear()

        for mode in ("enforce", "audit"):
            with _shield(mode=mode, cred_rate_enabled=True, cred_rate_limit=2,
                         block_score=1000, flood_threshold=100000) as shield, \
                    _guard(SimpleNamespace(port=port)) as guard:
                for key in _VARIANTS:
                    response = _exchange(guard, [_request(key)])
                    assert response.startswith(b"HTTP/1.1 400"), (mode, key, response)
                assert guard.metrics["proxied"] == 0 and seen == []
                assert not shield._cred_rate


def test_plain_key_limit_and_unrelated_utf8_header_keep_exact_backend_bytes():
    with _backend() as (port, seen):
        with _shield(cred_rate_enabled=True, cred_rate_limit=2,
                     block_score=1000, flood_threshold=100000) as shield, \
                _guard(SimpleNamespace(port=port)) as guard:
            request = _request(_KEY, user_agent=b"Caf\xc3\xa9")
            results = [_exchange(guard, [request]) for _ in range(3)]
            assert [r.split(b"\r\n", 1)[0] for r in results] == [
                b"HTTP/1.0 200 OK", b"HTTP/1.0 200 OK", b"HTTP/1.1 403 Forbidden"]
            assert all(_SECRET in r for r in results[:2])
            assert len(seen) == 2 and guard.metrics["proxied"] == 2
            assert shield.metrics().get("cred_rate_hit", 0) == 1
            for wire, raw, allowed in seen:
                assert wire.startswith(request[:-2]) and wire.endswith(b"\r\n\r\n")
                assert (raw, allowed) == ("secret", True)
