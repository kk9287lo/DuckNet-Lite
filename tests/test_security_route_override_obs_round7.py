"""Route override headers must have the same path meaning at edge and origin."""

import contextlib
import socket
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from test_sweep_proxy_request import _exchange, _guard, _shield


_FIELDS = (b"X-Original-URL", b"X-Rewrite-URL", b"X-Override-URL")
_PRIVATE = b"PRIVATE-ADMIN-CONTENT"
_PUBLIC = b"PUBLIC-CONTENT"


@contextlib.contextmanager
def _backend():
    with tempfile.TemporaryDirectory() as root:
        Path(root, "admin").write_bytes(_PRIVATE)
        Path(root, "public").write_bytes(_PUBLIC)
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

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=root, **kwargs)

            def setup(self):
                super().setup()
                self.rfile = Capture(self.rfile)

            def do_GET(self):
                supplied = next((self.headers.get(name.decode("ascii"))
                                 for name in _FIELDS
                                 if self.headers.get(name.decode("ascii")) is not None), None)
                route = supplied.strip() if supplied is not None else self.path
                seen.append((b"".join(self.rfile.lines), supplied, route))
                self.path = route
                super().do_GET()

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


def _request(field=b"", value=b"", user_agent=b""):
    head = b"GET /public HTTP/1.1\r\nHost: local.test\r\n"
    if field:
        head += field + b": " + value + b"\r\n"
    if user_agent:
        head += b"User-Agent: " + user_agent + b"\r\n"
    return head + b"\r\n"


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


def _via_guard(port, request, mode, *, override_block=False):
    with _shield(mode=mode, private_paths=["/admin"],
                 path_override_block=override_block, block_score=1000), \
            _guard(SimpleNamespace(port=port)) as guard:
        response = _exchange(guard, [request])
        return response, dict(guard.metrics)


def test_latin1_space_in_route_override_cannot_reach_private_backend_route():
    # Python's header reader preserves Latin-1 NEL/NBSP; ordinary str.strip()
    # then routes /admin<space> to /admin. DuckNet's byte trim used a different
    # path when path overrides were explicitly allowed by the operator.
    for mode in ("enforce", "audit"):
        with _backend() as (port, seen):
            for field in _FIELDS:
                for space in (b"\x85", b"\xa0"):
                    request = _request(field, b"/admin" + space)
                    direct = _direct(port, request)
                    assert direct.startswith(b"HTTP/1.0 200") and _PRIVATE in direct
                    assert seen[-1] == (request, "/admin" + space.decode("latin-1"), "/admin")
                    seen.clear()

                    response, metrics = _via_guard(port, request, mode)
                    assert response.startswith(b"HTTP/1.1 400"), (mode, field, space, response)
                    assert seen == [] and metrics["proxied"] == 0, (mode, field, space, seen)


def test_route_override_ascii_and_unrelated_nonascii_header_keep_their_wire():
    with _backend() as (port, seen):
        request = _request(b"X-Original-URL", b"/public", b"Caf\xc3\xa9")
        response, metrics = _via_guard(port, request, "enforce")
        assert response.startswith(b"HTTP/1.0 200") and _PUBLIC in response
        wire, supplied, route = seen[-1]
        assert wire.startswith(request[:-2]) and wire.endswith(b"\r\n\r\n")
        assert (supplied, route) == ("/public", "/public")
        assert metrics["proxied"] == 1

        private = _request(b"X-Original-URL", b"/admin")
        response, metrics = _via_guard(port, private, "enforce")
        assert response.startswith(b"HTTP/1.1 403")
        assert len(seen) == 1 and metrics["proxied"] == 0

        # The default override ban remains effective as a separate control.
        response, metrics = _via_guard(port, _request(b"X-Original-URL", b"/admin\x85"),
                                       "enforce", override_block=True)
        assert response.startswith((b"HTTP/1.1 400", b"HTTP/1.1 403"))
        assert len(seen) == 1 and metrics["proxied"] == 0
