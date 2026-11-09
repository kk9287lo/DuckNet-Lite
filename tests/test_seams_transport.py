"""Harmless, bounded loopback finite-response completion probes."""
import socket
import threading
from types import SimpleNamespace
import asyncio
import inspect
from dataplane.engine.services.proxy import AsyncEdgeGuard, _ChunkedEnd
from test_sweep_proxy_request import _guard, _shield


def _exchange(response, *, method=b"GET", eof=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    release = threading.Event()
    errors = []

    def serve():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        break
                    request += part
                connection.sendall(response)
                if not eof:
                    release.wait(2)
        except OSError as error:
            errors.append(type(error).__name__)

    worker = threading.Thread(target=serve)
    worker.start()
    output, closed = bytearray(), False
    try:
        with _shield(dlp_enabled=True, dlp_action="block", cookie_harden_enabled=False,
                     cors_harden_enabled=False, open_redirect_enabled=False):
            with _guard(SimpleNamespace(port=listener.getsockname()[1])) as guard:
                try:
                    with socket.create_connection(("127.0.0.1", guard.listen_port), timeout=2) as client:
                        # The backend waits two seconds in the no-EOF control.
                        # Give the local event loop one second to deliver its
                        # close under concurrent VM/Windows validation load.
                        client.settimeout(1.0)
                        client.sendall(method + b" /public/sample HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                        while True:
                            try:
                                part = client.recv(4096)
                            except socket.timeout:
                                break
                            if not part:
                                closed = True
                                break
                            output += part
                finally:
                    release.set()
    finally:
        release.set()
        listener.close()
        worker.join(3)
        assert not worker.is_alive(), "fixture worker was not reclaimed"
    assert not errors, errors
    return bytes(output), closed


def _cases():
    body = b'{"sample":true}'
    trailers = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                + b"%x\r\n" % len(body) + body
                + b'\r\n0\r\nX-Public: "blue\\sample"\r\n\r\n')
    return (
        ("length", b"GET", b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsample"),
        ("chunked", b"GET", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nsample\r\n0\r\n\r\n"),
        ("empty", b"GET", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        ("no-content", b"GET", b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"),
        ("not-modified", b"GET", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 600\r\nConnection: close\r\n\r\n"),
        ("head", b"HEAD", b"HTTP/1.1 200 OK\r\nContent-Length: 600\r\nConnection: close\r\n\r\n"),
        ("lowercase-head", b"head", b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsample"),
        ("mixedcase-head", b"Head", b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsample"),
        ("head-metadata", b"HEAD", b"HTTP/1.1 200 OK\r\nContent-Type: application/zip; charset=utf-16le\r\nContent-Encoding: gzip\r\nContent-Length: 600\r\nConnection: close\r\n\r\n"),
        ("json-trailer", b"GET", trailers),
    )


def test_finite_response_completes_without_waiting_for_backend_eof():
    failures = []
    for name, method, response in _cases():
        received, closed = _exchange(response, method=method)
        if received != response or not closed:
            failures.append((name, received.partition(b"\r\n\r\n")[2].decode(), closed))
    assert failures == [], failures


def test_backend_eof_control_is_byte_complete():
    for name, method, response in _cases():
        received, closed = _exchange(response, method=method, eof=True)
        assert received == response and closed, (name, received, response, closed)


class _ReadPlan:
    def __init__(self, pieces, *, eof=False, fail=False):
        self.pieces = list(pieces)
        self.eof, self.fail = eof, fail
        self.waiting = asyncio.Event()
    async def read(self, count):
        if self.pieces:
            piece = self.pieces.pop(0)
            if len(piece) > count:
                self.pieces.insert(0, piece[count:])
            return piece[:count]
        if self.fail:
            raise ConnectionResetError("inert fixture disconnect")
        if self.eof:
            return b""
        self.waiting.set()
        await asyncio.Event().wait()


class _Sink:
    def __init__(self):
        self.buf, self.closed = bytearray(), False
    def write(self, data): self.buf += data
    async def drain(self): pass
    def close(self): self.closed = True


async def _direct(response, *, step=65536, method="GET", eof=False, fail=False, extra=b"", **cfg):
    with _shield(cookie_harden_enabled=False, cors_harden_enabled=False,
                 open_redirect_enabled=False, **cfg) as shield:
        data = response + extra
        reader = _ReadPlan([data[i:i+step] for i in range(0, len(data), step)], eof=eof, fail=fail)
        sink = _Sink()
        timed_out = False
        context = ({"req_method": method}
                   if "req_method" in inspect.signature(AsyncEdgeGuard._pipe).parameters else {})
        try:
            count = await asyncio.wait_for(AsyncEdgeGuard()._pipe(
                reader, sink, scan=True, ip="192.0.2.52", **context), 0.3)
        except asyncio.TimeoutError:
            timed_out, count = True, None
        return bytes(sink.buf), count, timed_out, sink.closed, shield.metrics()


def test_protected_logical_end_survives_split_reads_and_ignores_unframed_suffix():
    async def run():
        failures = []
        for name, method, response in _cases():
            for step in (1, 17, 65536):
                out, count, timed_out, closed, metrics = await _direct(
                    response, step=step, method=method.decode(), extra=b"UNRELATED",
                    dlp_enabled=True, dlp_action="block")
                if (out != response or timed_out or count != len(out) or not closed
                        or metrics.get("dlp_unscannable", 0)):
                    failures.append((name, step, timed_out, len(out)))
        assert failures == [], failures
    asyncio.run(run())


def test_interim_head_then_final_entity_has_one_logical_end():
    final = _cases()[0][2]
    response = b"HTTP/1.1 103 Early Hints\r\nLink: </public.css>; rel=preload\r\n\r\n" + final
    async def run():
        for step in (1, 17, 65536):
            out, count, timed_out, closed, _ = await _direct(
                response, step=step, extra=b"UNRELATED", dlp_enabled=True, dlp_action="block")
            assert out == response and count == len(out) and closed and not timed_out
    asyncio.run(run())


def test_logical_end_runs_last_dlp_check_before_releasing_body_or_trailer():
    marker = b"ghp_" + b"a" * 36  # synthetic, inactive marker
    responses = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n" + marker,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n28\r\n" + marker + b"\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nsample\r\n0\r\nX-Note: " + marker + b"\r\n\r\n",
    )
    async def run():
        for response in responses:
            for action in ("block", "audit"):
                out, count, timed_out, closed, metrics = await _direct(
                    response, step=1, dlp_enabled=True, dlp_action=action)
                assert not timed_out and closed and count == len(out)
                assert metrics.get("dlp_leak", 0) == 1
                if action == "block":
                    assert marker[:12] not in out
                else:
                    assert out == response
    asyncio.run(run())


def test_partial_entity_eof_reset_and_invalid_trailers_do_not_finalize_as_clean():
    partials = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsam",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nsam",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nsampleX\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nsample\r\n0\r\nContent-Length: 6\r\n\r\n",
    )
    async def run():
        for index, response in enumerate(partials):
            for fail in (False, True):
                for action in ("block", "audit"):
                    out, count, timed_out, closed, metrics = await _direct(
                        response, step=1, eof=True, fail=fail, dlp_enabled=True, dlp_action=action)
                    assert closed and not timed_out and count == len(out)
                    assert metrics.get("dlp_unscannable", 0) == 1
                    if action == "block":
                        assert out.endswith(b"\r\n\r\n")  # no undecided body suffix
                    elif index < 2:
                        assert out == response
                    else:
                        # Incomplete transport can follow audit policy; known
                        # chunk/trailer syntax errors cannot become pass-through.
                        assert response.startswith(out) and out != response
    asyncio.run(run())


def test_cancellation_closes_client_and_discards_undecided_bytes():
    async def run():
        with _shield(dlp_enabled=True, dlp_action="block"):
            reader = _ReadPlan([b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsam"])
            sink = _Sink()
            task = asyncio.create_task(AsyncEdgeGuard()._pipe(reader, sink, scan=True, ip="192.0.2.53"))
            await asyncio.wait_for(reader.waiting.wait(), 1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            assert sink.closed and bytes(sink.buf).endswith(b"\r\n\r\n")
    asyncio.run(run())


def test_response_trailer_option_does_not_loosen_request_validation():
    body = b'6\r\nsample\r\n0\r\nX-Public: "blue\\sample"\r\n\r\n'
    request = _ChunkedEnd()
    request.feed(body)
    assert request.bad and not request.done
    if "response_trailers" in inspect.signature(_ChunkedEnd).parameters:
        response = _ChunkedEnd(response_trailers=True)
        assert response.feed(body) == len(body) and response.done and not response.bad


def test_all_protection_off_still_respects_the_http_response_boundary():
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nUNRELATED"
    async def run():
        out, count, timed_out, closed, _ = await _direct(
            response, eof=True, method="HEAD", enabled=False, dlp_enabled=False)
        assert out == response.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
        assert count == len(out) and closed and not timed_out
    asyncio.run(run())


def test_empty_entity_charset_metadata_is_exempt_only_after_strict_framing():
    metadata = b"Content-Type: application/xml; charset=utf-16le\r\n"
    final = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    normal = (b"HTTP/1.1 200 OK\r\n" + metadata + b"Content-Length: 0\r\n\r\n",
              b"HTTP/1.1 103 Early Hints\r\n" + metadata + b"\r\n" + final)
    bad = (b"HTTP/1.1 200 OK\r\n" + metadata + b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n",
           b"HTTP/1.1 200 OK\r\n" + metadata + b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
           b"HTTP/1.1 103 Early Hints\r\n" + metadata + b"Content-Length: 0\r\n\r\n" + final,
           b"HTTP/1.1 200 OK\r\n" + metadata + b"Content-Length: 6\r\n\r\nsample",
           b"HTTP/1.1 200 OK\r\n" + metadata + b"\r\nsample",
           b"HTTP/1.1 101 Switching Protocols\r\n" + metadata + b"Upgrade: fixture\r\n\r\n")
    async def run():
        for response in normal:
            for step in (1, 65536):
                out, count, timed_out, closed, metrics = await _direct(
                    response, step=step, dlp_enabled=True, dlp_action="block")
                assert out == response and count == len(out) and closed and not timed_out
                assert metrics.get("dlp_unscannable", 0) == 0
        for response in bad:
            out, count, timed_out, closed, metrics = await _direct(
                response, eof=True, dlp_enabled=True, dlp_action="block")
            assert not out and count == 0 and closed and not timed_out
            assert metrics.get("dlp_unscannable", 0) == 1
    asyncio.run(run())
