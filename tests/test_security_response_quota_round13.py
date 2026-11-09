"""A finite egress quota must bound bytes on the current response wire."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from unittest.mock import patch

from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import (_Backend, _exchange, _guard, _shield,
                                      _read_framed_request)


_GET = b"GET /download HTTP/1.1\r\nHost: local.test\r\n\r\n"
_QUIET = dict(sec_headers_enabled=False, cookie_harden_enabled=False,
              cors_harden_enabled=False, open_redirect_enabled=False,
              dlp_enabled=False, usage_record=False, persist_bans=False)
_CAP = 256


def _response(framing: str, body: bytes) -> bytes:
    if framing == "fixed":
        return (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body)
    if framing == "chunked":
        return (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n" + format(len(body), "x").encode()
                + b"\r\n" + body + b"\r\n0\r\n\r\n")
    assert framing == "eof"
    return b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body


def _wire(framing: str, body: bytes, mode: str):
    backend = _Backend(_response(framing, body))
    try:
        with _shield(quota_enabled=True, quota_max_gb=_CAP / 1e9,
                     mode=mode, **_QUIET) as sh:
            with _guard(backend) as guard:
                wire = _exchange(guard, [_GET])
            return wire, backend.saw(), sh.events(100), sh._window_totals("127.0.0.1")
    finally:
        backend.close()


def test_enforce_quota_bounds_current_response_wire():
    for framing in ("fixed", "chunked", "eof"):
        body = b"public-data-" * 40  # Innocuous 480-byte export, larger than quota.
        expected = _response(framing, body)
        assert len(expected) > _CAP
        wire, backend_request, events, totals = _wire(framing, body, "enforce")
        assert backend_request.startswith(b"GET /download HTTP/1.1\r\n")
        assert len(wire) <= _CAP, (framing, len(wire), _CAP)
        assert wire != expected
        assert totals[0] == len(wire)
        assert any(e.get("kind") == "quota_exceeded" for e in events)


def test_audit_quota_records_but_preserves_response_wire():
    for framing in ("fixed", "chunked", "eof"):
        body = b"public-data-" * 40
        expected = _response(framing, body)
        wire, backend_request, events, totals = _wire(framing, body, "audit")
        assert backend_request.startswith(b"GET /download HTTP/1.1\r\n")
        assert wire == expected
        assert totals[0] == len(wire)
        assert any(e.get("rule") == "quota_exceeded" and e.get("kind") == "audit"
                   for e in events)


def test_benign_response_within_quota_is_preserved():
    for framing in ("fixed", "chunked", "eof"):
        body = b"public-data"
        expected = _response(framing, body)
        assert len(expected) < _CAP
        wire, backend_request, events, totals = _wire(framing, body, "enforce")
        assert backend_request.startswith(b"GET /download HTTP/1.1\r\n")
        assert wire == expected
        assert totals[0] == len(wire)
        assert not any(e.get("kind") == "quota_exceeded" for e in events)


class _BarrierBackend(_Backend):
    """Release both responses only after both requests crossed the request gate."""

    def __init__(self, resp):
        self._both = threading.Barrier(2)
        super().__init__(resp)

    def _one(self, c):
        c.settimeout(2.0)
        try:
            self.got.append(_read_framed_request(c))
            self._both.wait(timeout=3.0)
            c.sendall(self.resp)
        except (OSError, threading.BrokenBarrierError):
            pass
        finally:
            c.close()


def test_simultaneous_responses_share_one_ip_quota_atomically():
    cap = 300
    response = _response("fixed", b"public-data-" * 15)
    assert len(response) < cap < 2 * len(response)
    backend = _BarrierBackend(response)
    try:
        with _shield(quota_enabled=True, quota_max_gb=cap / 1e9,
                     mode="enforce", **_QUIET) as sh:
            with _guard(backend) as guard:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(_exchange, guard, [_GET]) for _ in range(2)]
                    wires = [future.result(timeout=5) for future in futures]
            assert len(backend.got) == 2, backend.got
            assert all(request.startswith(b"GET /download HTTP/1.1\r\n")
                       for request in backend.got)
            assert sum(map(len, wires)) <= cap, [len(wire) for wire in wires]
            assert sh._window_totals("127.0.0.1")[0] == sum(map(len, wires))
            assert any(e.get("kind") == "quota_exceeded" for e in sh.events(100))
    finally:
        backend.close()


class _SlowBackend(_Backend):
    def __init__(self, early, late, delay=0.35):
        self.late = late
        self.delay = delay
        super().__init__(early)

    def _one(self, c):
        c.settimeout(2.0)
        try:
            self.got.append(_read_framed_request(c))
            c.sendall(self.resp)
            time.sleep(self.delay)
            c.sendall(self.late)
        except OSError:
            pass
        finally:
            c.close()


class _SlowBarrierBackend(_SlowBackend):
    def __init__(self, early, late, delay=0.55):
        self._both = threading.Barrier(2)
        super().__init__(early, late, delay)

    def _one(self, c):
        c.settimeout(2.0)
        try:
            self.got.append(_read_framed_request(c))
            self._both.wait(timeout=3.0)
            c.sendall(self.resp)
            time.sleep(self.delay)
            c.sendall(self.late)
        except (OSError, threading.BrokenBarrierError):
            pass
        finally:
            c.close()


def _slow_wire(mode, max_sec):
    early_body, late_body = b"early-public", b"late-public"
    head = (b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(early_body) + len(late_body)).encode()
            + b"\r\nConnection: close\r\n\r\n")
    backend = _SlowBackend(head + early_body, late_body)
    try:
        with _shield(quota_enabled=True, quota_max_conn_sec=max_sec,
                     mode=mode, **_QUIET) as sh:
            with _guard(backend) as guard:
                wire = _exchange(guard, [_GET])
            return wire, backend.saw(), sh.events(100), sh._window_totals("127.0.0.1")
    finally:
        backend.close()


def test_finite_connection_time_cuts_off_late_stream_bytes():
    wire, upstream, events, totals = _slow_wire("enforce", 0.15)
    assert upstream.startswith(b"GET /download HTTP/1.1\r\n")
    assert b"late-public" not in wire, wire
    assert any(e.get("kind") == "quota_exceeded" for e in events)
    assert totals[2] >= 0.15


def test_connection_time_audit_and_benign_preserve_stream():
    for mode, limit in (("audit", 0.15), ("enforce", 1.0)):
        wire, upstream, events, totals = _slow_wire(mode, limit)
        assert upstream.startswith(b"GET /download HTTP/1.1\r\n")
        assert wire.endswith(b"early-publiclate-public"), (mode, wire)
        assert totals[2] > 0
        if mode == "audit":
            assert any(e.get("kind") == "audit" and e.get("rule") == "quota_exceeded"
                       for e in events)


def test_simultaneous_long_streams_share_aggregate_connection_time():
    early_body, late_body = b"early-public", b"late-public"
    head = (b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(early_body) + len(late_body)).encode()
            + b"\r\nConnection: close\r\n\r\n")
    backend = _SlowBarrierBackend(head + early_body, late_body)
    try:
        with _shield(quota_enabled=True, quota_max_conn_sec=0.8,
                     mode="enforce", **_QUIET) as sh:
            with _guard(backend) as guard:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(_exchange, guard, [_GET]) for _ in range(2)]
                    wires = [future.result(timeout=5) for future in futures]
            assert len(backend.got) == 2, backend.got
            assert all(request.startswith(b"GET /download HTTP/1.1\r\n")
                       for request in backend.got)
            assert all(b"late-public" not in wire for wire in wires), wires
            assert any(e.get("kind") == "quota_exceeded" for e in sh.events(100))
    finally:
        backend.close()


def test_time_quota_race_rejects_before_backend_gets_request_bytes():
    backend = _Backend(_response("fixed", b"public"))
    try:
        with _shield(quota_enabled=True, quota_max_conn_sec=0.15,
                     mode="enforce", **_QUIET) as sh:
            with patch.object(sh, "begin_egress_time", return_value=False):
                with _guard(backend) as guard:
                    wire = _exchange(guard, [_GET])
            assert wire == b"", wire
            assert backend.saw() == b""
            assert guard.metrics["proxied"] == 0 and guard.metrics["dropped"] == 1
            assert any(e.get("kind") == "quota_exceeded" for e in sh.events(100))
    finally:
        backend.close()


class _NeverRead:
    def __init__(self):
        self.entered = asyncio.Event()

    async def read(self, _size):
        self.entered.set()
        await asyncio.Event().wait()


class _OneHead:
    def __init__(self):
        self.sent = False

    async def read(self, _size):
        if not self.sent:
            self.sent = True
            return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        await asyncio.Event().wait()


class _StalledDrain:
    def __init__(self):
        self.wrote = asyncio.Event()
        self.writes = []

    def write(self, data):
        self.writes.append(data)
        self.wrote.set()

    async def drain(self):
        await asyncio.Event().wait()


class _NoWrite:
    def write(self, _data):
        raise AssertionError("read-stalled response must not write")

    async def drain(self):
        raise AssertionError("read-stalled response must not drain")


async def _shortened_active_time_probe(*, drain):
    cap = 2.0
    with _shield(quota_enabled=True, quota_max_conn_sec=cap,
                 mode="enforce", **_QUIET) as shield:
        ip = "192.0.2.77"
        first, second = object(), object()
        start = time.monotonic()
        assert shield.begin_egress_time(ip, first, start)
        quota = (shield, first, {"hit": False, "time_ok": True})
        source, writer = (_OneHead(), _StalledDrain()) if drain else (_NeverRead(), _NoWrite())
        task = asyncio.create_task(AsyncEdgeGuard()._pipe(
            source, writer, ip=ip, strict_http=drain, quota=quota))
        try:
            if drain:
                await writer.wrote.wait()
            else:
                await source.entered.wait()
            await asyncio.sleep(0.1)
            second_start = time.monotonic()
            assert shield.begin_egress_time(ip, second, second_start)
            shared_deadline = (cap + start + second_start) / 2
            await asyncio.wait_for(task, 3.5)
            return (time.monotonic() - shared_deadline, quota[2]["hit"],
                    len(writer.writes) if drain else 0)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            shield.finalize_egress(first)
            shield.finalize_egress(second)


def test_new_same_ip_stream_shortens_existing_backend_read_deadline():
    overshoot, hit, _writes = asyncio.run(_shortened_active_time_probe(drain=False))
    assert hit
    assert overshoot < 0.35, overshoot


def test_new_same_ip_stream_shortens_existing_client_drain_deadline():
    overshoot, hit, writes = asyncio.run(_shortened_active_time_probe(drain=True))
    assert hit
    assert overshoot < 0.35, overshoot
    assert writes == 1, writes


async def _temporary_time_mode_probe(*, drain):
    with _shield(quota_enabled=True, quota_max_conn_sec=0.5,
                 mode="enforce", **_QUIET) as shield:
        ip, token = "192.0.2.78", object()
        started = time.monotonic()
        assert shield.begin_egress_time(ip, token, started)
        quota = (shield, token, {"hit": False, "time_ok": True,
                                "time_watch": shield.has_egress_time_lease(token)})
        source, writer = (_OneHead(), _StalledDrain()) if drain else (_NeverRead(), _NoWrite())
        task = asyncio.create_task(AsyncEdgeGuard()._pipe(
            source, writer, ip=ip, strict_http=drain, quota=quota))
        try:
            await (writer.wrote.wait() if drain else source.entered.wait())
            with shield._lock:
                shield.cfg["mode"] = "audit"
            await asyncio.sleep(0.15)  # Allow the active finite-quota wait to recheck.
            with shield._lock:
                shield.cfg["mode"] = "enforce"
            await asyncio.wait_for(task, 1.2)
            return time.monotonic() - started, quota[2]["hit"]
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            shield.finalize_egress(token)


def test_finite_time_lease_rechecks_after_temporary_audit_mode():
    for drain in (False, True):
        elapsed, hit = asyncio.run(_temporary_time_mode_probe(drain=drain))
        assert hit and elapsed < 0.8, (drain, elapsed, hit)
