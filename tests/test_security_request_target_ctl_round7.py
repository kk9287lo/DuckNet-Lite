"""Raw request-target controls cannot create a different backend route."""

import contextlib
import socket
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from dataplane.engine.services.proxy import _framing_ambiguous
from test_sweep_proxy_request import _exchange, _guard, _shield


_PRIVATE = b"PRIVATE-ADMIN-CONTENT"
_PUBLIC = b"PUBLIC-CONTENT"


@contextlib.contextmanager
def _backend():
    with tempfile.TemporaryDirectory() as root:
        Path(root, "admin").write_bytes(_PRIVATE)
        Path(root, "public").write_bytes(_PUBLIC)
        Path(root, "caf\u00e9").write_bytes(_PUBLIC)
        seen = []

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=root, **kwargs)

            def do_GET(self):
                seen.append((self.raw_requestline, self.path))
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


def _request(target):
    return b"GET " + target + b" HTTP/1.1\r\nHost: local.test\r\n\r\n"


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


def _via_guard(port, request, mode):
    with _shield(mode=mode, private_paths=["/admin"]), \
            _guard(SimpleNamespace(port=port)) as guard:
        response = _exchange(guard, [request])
        return response, dict(guard.metrics)


def test_request_target_control_cannot_reach_private_backend_route():
    # Python http.server treats 0x1c..0x1f and Latin-1 0x85/0xa0 as
    # request-line whitespace. It routes /admin<byte> to /admin, while
    # DuckNet sees a different path.
    public = _request(b"/public")
    private = _request(b"/admin")
    for mode in ("enforce", "audit"):
        with _backend() as (port, seen):
            for control in (*range(0x1c, 0x20), 0x85, 0xa0):
                attack = _request(b"/admin" + bytes((control,)))
                direct = _direct(port, attack)
                assert direct.startswith(b"HTTP/1.0 200") and _PRIVATE in direct
                assert seen == [(b"GET /admin" + bytes((control,))
                                 + b" HTTP/1.1\r\n", "/admin")]
                seen.clear()

                response, metrics = _via_guard(port, attack, mode)
                assert response.startswith(b"HTTP/1.1 400"), (mode, control, response)
                assert seen == [] and metrics["proxied"] == 0, (mode, control, seen, metrics)

            response, metrics = _via_guard(port, public, mode)
            assert response.startswith(b"HTTP/1.0 200") and _PUBLIC in response
            assert seen == [(b"GET /public HTTP/1.1\r\n", "/public")]
            assert metrics["proxied"] == 1

            if mode == "enforce":
                response, metrics = _via_guard(port, private, mode)
                assert response.startswith(b"HTTP/1.1 403")
                assert seen == [(b"GET /public HTTP/1.1\r\n", "/public")]
                assert metrics["proxied"] == 0


def test_all_raw_target_controls_are_invalid_but_encoded_letters_still_route():
    for control in (*range(0x20), 0x7f, *range(0x80, 0x100)):
        assert _framing_ambiguous(_request(b"/public" + bytes((control,)))), control

    with _backend() as (port, seen):
        response, metrics = _via_guard(port, _request(b"/pub%6cic"), "enforce")
        assert response.startswith(b"HTTP/1.0 200") and _PUBLIC in response
        assert seen == [(b"GET /pub%6cic HTTP/1.1\r\n", "/pub%6cic")]
        assert metrics["proxied"] == 1

        response, metrics = _via_guard(port, _request(b"/caf%C3%A9"), "enforce")
        assert response.startswith(b"HTTP/1.0 200") and _PUBLIC in response
        assert seen[-1] == (b"GET /caf%C3%A9 HTTP/1.1\r\n", "/caf%C3%A9")
        assert metrics["proxied"] == 1

        response, metrics = _via_guard(port, _request(b"/ad%6din"), "enforce")
        assert response.startswith(b"HTTP/1.1 403")
        assert len(seen) == 2 and metrics["proxied"] == 0

        absolute = b"GET http://local.test/public HTTP/1.1\r\nHost: local.test\r\n\r\n"
        response, metrics = _via_guard(port, absolute, "enforce")
        assert response.startswith(b"HTTP/1.1 400")
        assert len(seen) == 2 and metrics["proxied"] == 0
