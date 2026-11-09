"""A streamed request cannot earn an early backend response before framing completes."""

import socket
import threading
import time

from test_sweep_proxy_request import _guard, _shield


class _EarlyReplyOrigin:
    def __init__(self, status=b"200 OK", body=b"INTERNAL-OK"):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.status, self.body = status, body
        self.wire = b""
        self.sent = threading.Event()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            try:
                connection, _ = self.listener.accept()
            except (OSError, socket.timeout):
                return
            with connection:
                connection.settimeout(3)
                while True:
                    try:
                        data = connection.recv(65536)
                    except OSError:
                        break
                    if not data:
                        break
                    self.wire += data
                    if not self.sent.is_set() and b"hello" in self.wire:
                        response = (b"HTTP/1.1 " + self.status + b"\r\nContent-Length: "
                                    + str(len(self.body)).encode() + b"\r\n"
                                    + b"Connection: close\r\n\r\n" + self.body)
                        try:
                            connection.sendall(response)
                        except OSError:
                            pass
                        self.sent.set()
        finally:
            self.done.set()

    def close(self):
        self.listener.close()
        self.thread.join(4)


def _case(head, first, tail, *, mode="enforce", scan=False,
          status=b"200 OK", body=b"INTERNAL-OK", timeout=0.6,
          body_timeout=True):
    origin = _EarlyReplyOrigin(status, body)
    try:
        with _shield(mode=mode, body_scan_enabled=scan,
                     body_timeout_enabled=body_timeout,
                     upload_scan_enabled=False, graphql_enabled=False):
            with _guard(origin, head_timeout=0.3 if not body_timeout else 2.0,
                        write_timeout=0.3 if not body_timeout else 2.0) as guard:
                with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                    client.sendall(head + first)
                    client.settimeout(timeout)
                    try:
                        before = client.recv(65536)
                    except socket.timeout:
                        before = b""
                    tail_sent = False
                    if tail is None:
                        try:
                            client.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                    elif tail:
                        try:
                            client.sendall(tail)
                            tail_sent = True
                        except OSError:
                            pass
                    client.settimeout(2)
                    after = b""
                    while True:
                        try:
                            part = client.recv(65536)
                        except OSError:
                            break
                        if not part:
                            break
                        after += part
                origin.done.wait(3)
                return before, after, bytes(origin.wire), tail_sent, guard.metrics.copy()
    finally:
        origin.close()


_CHUNK_HEAD = (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n")
_CHUNK_FIRST = b"5\r\nhello\r\n"
_BAD_TAIL = b"0\r\nX-Bad: 1\r\n\r\n"


def test_late_bad_chunked_trailer_cannot_release_early_200_in_enforce_or_audit():
    for mode in ("enforce", "audit"):
        before, after, backend, sent, _ = _case(
            _CHUNK_HEAD, _CHUNK_FIRST, _BAD_TAIL, mode=mode)
        assert sent
        assert before == b"" and after.startswith(b"HTTP/1.1 400 Bad Request\r\n"), (mode, before, after)
        assert backend == b""


def test_clean_chunked_body_finishes_upstream_before_early_200_is_released():
    before, after, backend, sent, _ = _case(
        _CHUNK_HEAD, _CHUNK_FIRST, b"0\r\n\r\n")
    assert sent and before == b"", (before, after)
    assert after.startswith(b"HTTP/1.1 200 OK\r\n") and after.endswith(b"INTERNAL-OK")
    assert backend.endswith(_CHUNK_FIRST + b"0\r\n\r\n"), backend[-60:]


def test_truncated_content_length_cannot_release_early_200():
    head = (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
            b"Content-Length: 10\r\n\r\n")
    before, after, backend, _sent, _ = _case(head, b"hello", None)
    assert before == after == b"", (before, after)
    assert backend == b""


def test_complete_content_length_releases_early_200_after_full_backend_wire():
    head = (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
            b"Content-Length: 10\r\n\r\n")
    before, after, backend, sent, _ = _case(head, b"hello", b"world")
    assert sent and before == b"", (before, after)
    assert after.startswith(b"HTTP/1.1 200 OK\r\n") and after.endswith(b"INTERNAL-OK")
    assert backend.endswith(b"helloworld"), backend[-60:]


def test_early_413_is_delivered_after_valid_body_but_not_for_abandoned_body():
    before, after, backend, sent, _ = _case(
        _CHUNK_HEAD, _CHUNK_FIRST, b"0\r\n\r\n",
        status=b"413 Payload Too Large", body=b"NO")
    assert sent and before == b""
    assert after.startswith(b"HTTP/1.1 413 Payload Too Large\r\n")
    assert backend.endswith(_CHUNK_FIRST + b"0\r\n\r\n")

    started = time.monotonic()
    before, after, backend, _sent, _ = _case(
        _CHUNK_HEAD, _CHUNK_FIRST, b"", status=b"413 Payload Too Large",
        body=b"NO", timeout=1.0, body_timeout=False)
    assert time.monotonic() - started < 4.0, "disabled total body timer hung"
    assert before == after == b"", (before, after)
    assert backend == b""


def test_default_full_body_scan_still_rejects_bad_trailer_before_backend():
    before, after, backend, sent, _ = _case(
        _CHUNK_HEAD, _CHUNK_FIRST, _BAD_TAIL, scan=True)
    assert sent and before == b""
    assert after.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert backend == b""


def test_large_audit_body_waits_for_valid_tail_before_backend_transfer():
    payload = b"hello" + b"A" * 131100
    first = format(len(payload), "x").encode() + b"\r\n" + payload + b"\r\n"
    for tail in (b"0\r\n\r\n", _BAD_TAIL):
        before, after, backend, sent, _ = _case(
            _CHUNK_HEAD, first, tail, mode="audit", scan=True)
        assert sent and before == b"", (before, after)
        if tail == _BAD_TAIL:
            assert after.startswith(b"HTTP/1.1 400 Bad Request\r\n")
            assert backend == b""
        else:
            assert backend.endswith(first + tail)
            assert after.startswith(b"HTTP/1.1 200 OK\r\n")


def test_expect_continue_with_empty_or_partial_body_is_local_and_finite():
    for scan in (False, True):
        for mode in ("enforce", "audit"):
            for head, early, rest, body in (
            (_CHUNK_HEAD, b"", _CHUNK_FIRST + b"0\r\n\r\n",
             _CHUNK_FIRST + b"0\r\n\r\n"),
            (_CHUNK_HEAD, b"5\r\nh", b"ello\r\n0\r\n\r\n",
             _CHUNK_FIRST + b"0\r\n\r\n"),
            (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
             b"Content-Length: 5\r\n\r\n", b"", b"hello", b"hello"),
            (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
             b"Content-Length: 5\r\n\r\n", b"h", b"ello", b"hello"),
            ):
                origin = _EarlyReplyOrigin()
                try:
                    with _shield(mode=mode, body_scan_enabled=scan,
                                 upload_scan_enabled=False, graphql_enabled=False,
                                 body_timeout_enabled=False):
                        with _guard(origin, head_timeout=0.8, write_timeout=0.8) as guard:
                            with socket.create_connection(
                                    ("127.0.0.1", guard.listen_port), 3) as client:
                                client.settimeout(2)
                                client.sendall(head[:-2] + b"Expect: 100-continue\r\n\r\n"
                                               + early)
                                interim = b""
                                while b"\r\n\r\n" not in interim:
                                    part = client.recv(65536)
                                    assert part, "client never received local 100 Continue"
                                    interim += part
                                assert interim == b"HTTP/1.1 100 Continue\r\n\r\n", interim
                                client.sendall(rest)
                                final = b""
                                while True:
                                    try:
                                        part = client.recv(65536)
                                    except OSError:
                                        break
                                    if not part:
                                        break
                                    final += part
                            origin.done.wait(3)
                            assert final.startswith(b"HTTP/1.1 200 OK\r\n")
                            assert final.endswith(b"INTERNAL-OK")
                            assert b"Expect:" not in origin.wire
                            assert origin.wire.endswith(body), origin.wire[-80:]
                finally:
                    origin.close()
