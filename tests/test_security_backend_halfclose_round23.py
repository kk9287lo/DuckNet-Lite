"""A framed backend must receive one request without a premature TCP FIN."""

import os
import select
import socket
import tempfile
import threading
import time
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _guard


_REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class _FramedOrigin:
    """Model an HTTP origin that aborts on client FIN before sending its reply.

    Nginx with proxy_request_buffering on does this even after it buffered a
    complete Content-Length body. We observed the behavior with a real Docker
    Nginx; this local server makes the boundary portable to Windows CI.
    """

    def __init__(self, expected_body):
        self.expected_body = expected_body
        self.wire = b""
        self.problem = None
        self.done = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(4)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @staticmethod
    def _exact(conn, count):
        out = bytearray()
        while len(out) < count:
            part = conn.recv(count - len(out))
            if not part:
                break
            out.extend(part)
        return bytes(out)

    def _serve(self):
        try:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                self.problem = "no backend connection"
                return
            with conn:
                conn.settimeout(4)
                head = bytearray()
                while not head.endswith(b"\r\n\r\n"):
                    part = conn.recv(1)
                    if not part or len(head) > 8192:
                        self.problem = "incomplete request head"
                        return
                    head.extend(part)
                body = self._exact(conn, len(self.expected_body))
                self.wire = bytes(head) + body
                if body != self.expected_body:
                    self.problem = "incomplete or changed request body"
                    return
                # A complete framed request needs no TCP FIN. If one is
                # already queued, this origin behaves like observed Nginx:
                # it abandons the response and never invokes the app.
                if select.select([conn], [], [], 0.15)[0]:
                    extra = conn.recv(1)
                    self.problem = ("premature backend FIN" if extra == b"" else
                                    "pipelined suffix reached backend")
                    return
                conn.sendall(_REPLY)
        finally:
            self.done.set()

    def close(self):
        self.listener.close()
        self.thread.join(5)


def _case(request, expected_body, *, force_conn_close=True):
    origin = _FramedOrigin(expected_body)
    try:
        with tempfile.TemporaryDirectory(prefix="ducknet-r23-fin-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            shield = NetShield(state_dir=state)
            firewall = AppFirewall(state_dir=state)
            assert shield.set_config(enabled=True, block_page=False,
                                     body_scan_enabled=False,
                                     upload_scan_enabled=False,
                                     graphql_enabled=False,
                                     force_conn_close=force_conn_close)["ok"]
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(origin) as guard:
                with socket.create_connection(("127.0.0.1", guard.listen_port), 4) as client:
                    client.settimeout(4)
                    client.sendall(request)
                    reply = bytearray()
                    while True:
                        try:
                            part = client.recv(65536)
                        except OSError:
                            break
                        if not part:
                            break
                        reply.extend(part)
                assert origin.done.wait(4)
                assert origin.problem is None, origin.problem
                assert bytes(reply).startswith(b"HTTP/1.1 200 OK\r\n"), reply[:120]
                return origin.wire
    finally:
        origin.close()


def test_content_length_body_reaches_framed_backend_without_fin_or_suffix():
    body = b"safe-body"
    suffix = b"GET /hidden HTTP/1.1\r\nHost: app.example\r\n\r\n"
    request = (b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
               b"Content-Length: 9\r\n\r\n" + body + suffix)
    wire = _case(request, body)
    assert wire.endswith(body) and suffix not in wire


def test_chunked_body_reaches_framed_backend_without_fin_or_suffix():
    body = b"4\r\nDATA\r\n0\r\n\r\n"
    suffix = b"GET /hidden HTTP/1.1\r\nHost: app.example\r\n\r\n"
    request = (b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n" + body + suffix)
    wire = _case(request, body)
    assert wire.endswith(body) and suffix not in wire


def test_bodyless_keepalive_head_has_no_fin_or_pipelined_suffix():
    suffix = b"GET /hidden HTTP/1.1\r\nHost: app.example\r\n\r\n"
    request = (b"GET /safe HTTP/1.1\r\nHost: app.example\r\n"
               b"Connection: keep-alive\r\n\r\n" + suffix)
    wire = _case(request, b"", force_conn_close=False)
    assert b"GET /safe HTTP/1.1" in wire and suffix not in wire
