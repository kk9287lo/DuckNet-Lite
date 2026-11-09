"""Local proxy resource and deadline controls without external traffic."""

import asyncio
import math
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.services.proxy import AsyncEdgeGuard


class _ResponsiveHttpBackend:
    """Reply after the framed request head; never require a premature FIN."""

    def __init__(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class _IdleReader:
    def __init__(self):
        self.calls = 0

    async def read(self, n):
        self.calls += 1
        await asyncio.sleep(1)
        return b""


class _OnceReader:
    def __init__(self, data):
        self.data = data

    async def read(self, n):
        data, self.data = self.data, b""
        return data


class _ResponseReads:
    def __init__(self, chunks):
        self.chunks = deque(chunks)

    async def read(self, n):
        if not self.chunks:
            return b""
        delay, data = self.chunks[0]
        if delay:
            await asyncio.sleep(delay)
        # A cancelled real StreamReader.read() leaves unread bytes available.
        # Pop only after the simulated wait completes; otherwise a deadline
        # retry sees a fabricated EOF and mislabels the incomplete head.
        self.chunks.popleft()
        return data


class _Transport:
    def __init__(self):
        self.aborted = False

    def abort(self):
        self.aborted = True


class _Writer:
    def __init__(self, *, slow=False):
        self.transport = _Transport()
        self.slow = slow
        self.data = b""
        self.closed = self.eof = False

    def get_extra_info(self, name):
        return ("127.0.0.1", 43210) if name == "peername" else None

    def write(self, data):
        self.data += data

    async def drain(self):
        if self.slow:
            await asyncio.sleep(1)

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof = True

    def close(self):
        self.closed = True


class _ByteSink(_Writer):
    def __init__(self):
        super().__init__()
        self.data = bytearray()

    def write(self, data):
        self.data.extend(data)


def test_unavailable_shield_closes_before_occupying_header_slot():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=0.06)
        reader, writer = _IdleReader(), _Writer()
        with patch("dataplane.engine.lifeform.pipeline.net_shield",
                   side_effect=RuntimeError("state unavailable")):
            await guard._handle(reader, writer)
        assert reader.calls == 0   # never wait for a header with no resource gate
        assert writer.closed and guard._active == 0 and not guard._live
        assert guard.metrics.get("defense_unavailable", 0) == 1
    asyncio.run(go())


def test_backend_request_drain_obeys_total_body_deadline_and_aborts():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=0.5, write_timeout=0.2)
        loop = asyncio.get_running_loop()
        slow = _Writer(slow=True)
        count = await asyncio.wait_for(guard._pipe_body_bounded(
            _OnceReader(b"safe"), slow, 4, None, loop.time() + 0.03), timeout=0.3)
        assert count == 0 and slow.data == b"safe"
        assert slow.transport.aborted and not slow.eof
        assert guard.metrics.get("backend_write_timeout", 0) == 1

        normal = _Writer()
        count = await guard._pipe_body_bounded(
            _OnceReader(b"safe"), normal, 4, None, loop.time() + 0.2)
        assert count == 4 and normal.data == b"safe"
        assert normal.eof and not normal.transport.aborted
    asyncio.run(go())


def test_initial_backend_drain_uses_finite_write_timeout():
    async def go():
        guard = AsyncEdgeGuard(write_timeout=0.03)
        writer = _Writer(slow=True)
        try:
            await guard._drain_backend(writer)
            assert False, "stalled backend drain returned normally"
        except asyncio.TimeoutError:
            pass
        assert writer.transport.aborted
        assert guard.metrics.get("backend_write_timeout", 0) == 1

        normal = _Writer()
        await guard._drain_backend(normal)
        assert not normal.transport.aborted
    asyncio.run(go())


def test_cancelled_backend_drain_aborts_partial_request():
    async def go():
        guard = AsyncEdgeGuard(write_timeout=1.0)
        writer = _Writer(slow=True)
        task = asyncio.create_task(guard._drain_backend(writer))
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
            assert False, "cancelled drain returned normally"
        except asyncio.CancelledError:
            pass
        assert writer.transport.aborted
        assert guard.metrics.get("backend_write_timeout", 0) == 0
    asyncio.run(go())


def test_invalid_timeouts_cannot_disable_read_or_drain_deadlines():
    for raw in ("nan", "inf", "-1", "0", "invalid", "1e308"):
        with patch.dict(os.environ, {"DUCKNET_DRAIN_TIMEOUT": raw}):
            guard = AsyncEdgeGuard(head_timeout=float("nan"), write_timeout=float("inf"))
            assert guard.head_timeout == 10.0
            assert guard.write_timeout == 60.0
            assert math.isfinite(guard.head_timeout) and math.isfinite(guard.write_timeout)
    with patch.dict(os.environ, {"DUCKNET_DRAIN_TIMEOUT": "0.025"}):
        guard = AsyncEdgeGuard(head_timeout=0.04)
        assert guard.head_timeout == 0.04 and guard.write_timeout == 0.025
    with patch.dict(os.environ, {}, clear=True):
        guard = AsyncEdgeGuard(head_timeout=True, write_timeout=True)
        assert guard.head_timeout == 10.0 and guard.write_timeout == 60.0
        guard = AsyncEdgeGuard(head_timeout=1e308, write_timeout=1e308)
        assert guard.head_timeout == 10.0 and guard.write_timeout == 60.0


def test_nonfinite_body_deadline_fails_closed_before_backend_write():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=0.05)
        writer = _Writer()
        count = await guard._pipe_body_bounded(
            _OnceReader(b"safe"), writer, 4, None, float("inf"))
        assert count == 0 and writer.data == b""
        assert writer.transport.aborted and not writer.eof
    asyncio.run(go())


def test_partial_backend_response_head_has_total_deadline():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=0.04)
        sink = _ByteSink()
        reader = _ResponseReads([(0, b"HTTP/1.1 200"), (1, b" OK\r\n\r\n")])
        await asyncio.wait_for(guard._pipe(reader, sink, private_response=True), 0.3)
        assert sink.closed and sink.data == b""
        assert guard.metrics.get("response_head_timeout", 0) == 1
    asyncio.run(go())


def test_interim_heads_do_not_reset_response_head_deadline():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=0.035)
        sink = _ByteSink()
        interim = b"HTTP/1.1 103 Early Hints\r\nLink: </safe.css>; rel=preload\r\n\r\n"
        final = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        reader = _ResponseReads([(0, interim), (0.02, interim), (0.02, final)])
        await asyncio.wait_for(guard._pipe(reader, sink, private_response=True), 0.3)
        assert final not in sink.data
        assert guard.metrics.get("response_head_timeout", 0) == 1
    asyncio.run(go())


def test_valid_response_head_preserves_idle_sse_body():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=0.03)
        sink = _ByteSink()
        reader = asyncio.StreamReader()
        task = asyncio.create_task(guard._pipe(reader, sink, private_response=True))
        reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        await asyncio.sleep(0.07)  # body idle is longer than head deadline
        assert not task.done()
        reader.feed_data(b"data: safe\n\n")
        reader.feed_eof()
        await asyncio.wait_for(task, 0.3)
        assert sink.data.endswith(b"data: safe\n\n")
        assert b"Cache-Control: private, no-store" in sink.data
        assert guard.metrics.get("response_head_timeout", 0) == 0
    asyncio.run(go())


def test_fragmented_response_head_is_byte_complete():
    async def go():
        guard = AsyncEdgeGuard(head_timeout=5.0)
        sink = _ByteSink()
        head = (b"HTTP/1.1 200 OK\r\nX-Benign: " + b"a" * 60000
                + b"\r\nContent-Length: 2\r\n\r\n")
        reader = _ResponseReads([(0, bytes([c])) for c in head + b"ok"])
        await guard._pipe(reader, sink, private_response=True)
        assert sink.data.endswith(b"\r\n\r\nok")
        assert b"X-Benign: " + b"a" * 60000 in sink.data
        assert b"Cache-Control: private, no-store" in sink.data
    asyncio.run(go())


def test_slow_usage_log_does_not_stall_unrelated_local_response():
    """A benign JSONL write may wait on disk without freezing the event loop."""
    import dataplane.engine.lifeform.pipeline as pipeline
    from test_sweep_proxy_request import _guard, _exchange, _shield

    request = b"GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n"
    backend = _ResponsiveHttpBackend()
    entered, release = threading.Event(), threading.Event()
    original = pipeline._open_state_write
    try:
        with _shield() as shield:
            def paused(path, mode):
                if path == shield._usage_log_path and mode == "a" and not entered.is_set():
                    entered.set()
                    assert release.wait(3)
                return original(path, mode)

            with patch.object(pipeline, "_open_state_write", side_effect=paused):
                with _guard(backend) as guard:
                    first = threading.Thread(target=lambda: _exchange(guard, [request], timeout=2))
                    first.start()
                    try:
                        assert entered.wait(2), "first request did not reach the usage log"
                        second = _exchange(guard, [request], timeout=0.5)
                        assert second.startswith(b"HTTP/1.1 200"), second
                    finally:
                        release.set()
                        first.join(3)
                    assert not first.is_alive()
                    assert guard.stop(grace=1.0)["stopped"] is True
            assert len(shield.usage_log(limit=5)) == 2
    finally:
        release.set()
        backend.close()


def test_slow_acl_log_does_not_stall_unrelated_local_response():
    import dataplane.engine.lifeform.policy as policy
    from test_sweep_proxy_request import _guard, _exchange, _shield

    request = b"GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n"
    backend = _ResponsiveHttpBackend()
    entered, release = threading.Event(), threading.Event()
    try:
        with _shield():
            fw = policy._FW
            original = fw.write_acl_log

            def paused(work):
                if not entered.is_set():
                    entered.set()
                    assert release.wait(3)
                return original(work)

            with patch.object(fw, "write_acl_log", side_effect=paused):
                with _guard(backend) as guard:
                    first = threading.Thread(target=lambda: _exchange(guard, [request], timeout=2))
                    first.start()
                    try:
                        assert entered.wait(2), "first decision did not reach the ACL log"
                        second = _exchange(guard, [request], timeout=0.5)
                        assert second.startswith(b"HTTP/1.1 200"), second
                    finally:
                        release.set()
                        first.join(3)
                    assert not first.is_alive()
                    assert guard.stop(grace=1.0)["stopped"] is True
            with open(fw.log_path, encoding="utf-8") as handle:
                assert len(handle.readlines()) >= 2
    finally:
        release.set()
        backend.close()


def test_network_fixture_waits_for_its_owned_log_before_temp_cleanup():
    import dataplane.engine.lifeform.policy as policy
    from test_sweep_proxy_request import _Backend, _guard, _exchange, _shield

    backend = _Backend()
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    timer = None
    try:
        with _shield():
            fw = policy._FW
            original = fw.write_acl_log

            def delayed(work):
                entered.set()
                assert release.wait(2)
                try:
                    return original(work)
                finally:
                    finished.set()

            with patch.object(fw, "write_acl_log", side_effect=delayed):
                try:
                    with _guard(backend) as guard:
                        request = b"GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n"
                        assert _exchange(guard, [request]).startswith(b"HTTP/1.1 200")
                        assert entered.wait(1)
                        timer = threading.Timer(0.25, release.set)
                        timer.start()
                    assert finished.is_set(), "fixture returned with a live log writer"
                finally:
                    release.set()
                    assert finished.wait(2)
    finally:
        release.set()
        if timer is not None:
            timer.join(2)
        backend.close()


def test_acl_deny_early_return_still_owns_deferred_log_until_completion():
    import dataplane.engine.lifeform.policy as policy
    from test_sweep_proxy_request import _shield

    async def go():
        with _shield():
            fw = policy._FW
            entered, release = threading.Event(), threading.Event()

            def paused(work):
                entered.set()
                assert release.wait(2)
                return True

            with patch.object(fw, "evaluate", return_value={
                    "action": "deny", "_acl_log_work": {"action": "deny"}}), \
                    patch.object(fw, "write_acl_log", side_effect=paused):
                guard, writer = AsyncEdgeGuard(), _Writer()
                req = b"GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n"
                task = asyncio.create_task(guard._handle(_OnceReader(req), writer))
                try:
                    assert await asyncio.to_thread(entered.wait, 1)
                    assert writer.closed and not task.done()
                finally:
                    release.set()
                await asyncio.wait_for(task, 1)
                assert guard._active == 0 and guard._acl_pending == 0
                assert guard.metrics.get("acl_log_write_failed", 0) == 0
                guard._close_usage_jobs()
    asyncio.run(go())


def test_stop_reports_pending_acl_log_without_claiming_success():
    import dataplane.engine.lifeform.policy as policy
    from test_sweep_proxy_request import _Backend, _exchange, _shield

    backend = _Backend()
    guard = AsyncEdgeGuard(backend_port=backend.port, listen_port=0)
    entered, release = threading.Event(), threading.Event()
    try:
        with _shield():
            fw = policy._FW
            original = fw.write_acl_log

            def paused(work):
                entered.set()
                assert release.wait(3)
                return original(work)

            with patch.object(fw, "write_acl_log", side_effect=paused):
                assert guard.start()["ok"]
                request = b"GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n"
                assert _exchange(guard, [request], timeout=2).startswith(b"HTTP/1.1 200")
                assert entered.wait(2)
                stopped = guard.stop(grace=0)
                assert stopped["stopped"] is False and stopped["acl_log_pending"] == 1
                assert stopped["usage_log_pending"] == 0
                assert guard.start()["ok"] is False
                release.set()
                for _ in range(100):
                    if guard._log_pending == 0:
                        break
                    threading.Event().wait(0.01)
                assert guard.stop()["stopped"] is True
    finally:
        release.set()
        guard.stop()
        backend.close()


def test_usage_worker_has_global_bounded_queue_and_drops_only_its_guard_jobs():
    class FakeShield:
        def __init__(self):
            self.entered, self.release = threading.Event(), threading.Event()
            self.rows = []

        def write_usage_log(self, work):
            self.entered.set()
            assert self.release.wait(3)
            self.rows.append(work)
            return True

    async def go():
        shield = FakeShield()
        first, second = AsyncEdgeGuard(), AsyncEdgeGuard()
        try:
            jobs = [first._submit_usage_log(shield, i) for i in range(32)]
            assert all(job is not None for job in jobs)
            assert shield.entered.wait(1)
            assert first._submit_usage_log(shield, 32) is None
            assert first.metrics.get("usage_log_dropped", 0) == 1
            first._close_usage_jobs()
            assert first.metrics.get("usage_log_dropped", 0) == 32
            assert first._submit_usage_log(shield, "after-stop") is None
            assert first.metrics.get("usage_log_dropped", 0) == 33
            second_job = second._submit_usage_log(shield, "second-guard")
            assert second_job is not None
        finally:
            shield.release.set()
        results = await asyncio.wait_for(asyncio.gather(*jobs, second_job), 2)
        assert results.count(True) == 2 and results.count(False) == 31
        assert shield.rows == [0, "second-guard"]
        assert first._usage_pending == second._usage_pending == 0
        second._close_usage_jobs()
    asyncio.run(go())


def test_usage_worker_reports_write_failure_and_stale_generation_is_not_replayed():
    class FakeShield:
        def __init__(self):
            self.current = 1
            self.rows = []

        def write_usage_log(self, work):
            generation, row = work
            if row == "fail":
                return False
            if generation == self.current:
                self.rows.append(row)
            return True

    async def go():
        guard, shield = AsyncEdgeGuard(), FakeShield()
        try:
            failed = guard._submit_usage_log(shield, (1, "fail"))
            assert await asyncio.wait_for(failed, 1) is False
            assert guard.metrics.get("usage_log_write_failed", 0) == 1
            shield.current = 2
            stale = guard._submit_usage_log(shield, (1, "stale"))
            current = guard._submit_usage_log(shield, (2, "fresh"))
            assert await asyncio.wait_for(stale, 1) is True
            assert await asyncio.wait_for(current, 1) is True
            assert shield.rows == ["fresh"]
        finally:
            guard._close_usage_jobs()
    asyncio.run(go())


def test_acl_log_worker_failure_and_poststop_drop_have_separate_metrics():
    async def go():
        guard = AsyncEdgeGuard()
        done = guard._submit_log_job(lambda work: False, {"safe": True}, "acl")
        assert await asyncio.wait_for(done, 1) is False
        assert guard.metrics.get("acl_log_write_failed", 0) == 1
        assert guard._acl_pending == guard._log_pending == 0
        guard._close_usage_jobs()
        assert guard._submit_log_job(lambda work: True, {"safe": True}, "acl") is None
        assert guard.metrics.get("acl_log_dropped", 0) == 1
        assert guard.metrics.get("usage_log_dropped", 0) == 0
    asyncio.run(go())


def test_one_guards_pending_log_does_not_make_another_guard_unstoppable():
    class FakeShield:
        def __init__(self):
            self.entered, self.release = threading.Event(), threading.Event()

        def write_usage_log(self, work):
            self.entered.set()
            assert self.release.wait(3)
            return True

    async def go():
        shield = FakeShield()
        first, second = AsyncEdgeGuard(), AsyncEdgeGuard()
        job = first._submit_usage_log(shield, "first")
        try:
            assert shield.entered.wait(1)
            assert second.stop()["stopped"] is True
            assert first.stop()["stopped"] is False
        finally:
            shield.release.set()
        assert await asyncio.wait_for(job, 2) is True
        assert first.stop()["stopped"] is True
    asyncio.run(go())


def test_usage_worker_start_failure_has_no_orphaned_job():
    from worker_start_probe import run_probe

    result = run_probe()
    assert result["ok"] and result["reaped"], result


def test_usage_connection_duration_ignores_wall_clock_jump():
    import dataplane.engine.services.proxy as proxy

    class Shield:
        def __init__(self):
            self.seen = None

        def record_traffic(self, *args, **kw):
            self.seen = kw
            return {"counted": False}

    async def go():
        guard, shield = AsyncEdgeGuard(), Shield()
        started = time.monotonic() - 0.03
        with patch.object(proxy.time, "time", return_value=-1_000_000_000):
            await guard._record_traffic_deferred(
                shield, "192.0.2.5", 1, 1, started, "safe.test", "GET", "/safe")
        assert 0 <= shield.seen["conn_sec"] < 1
    asyncio.run(go())


def test_response_egress_count_matches_completed_client_writes():
    from test_sweep_det_response import _shield

    marker = b"ghp_" + b"a" * 36  # inert DLP fixture

    async def one(response, *, private=False, sink=None, **cfg):
        with _shield(**cfg):
            guard, sink = AsyncEdgeGuard(), (sink or _ByteSink())
            chunks = [(0, response[i:i + 31]) for i in range(0, len(response), 31)]
            count = await guard._pipe(_ResponseReads(chunks), sink, scan=True,
                                      ip="192.0.2.70", private_response=private)
            return count, bytes(sink.data)

    async def go():
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        blocked = head + b"Content-Length: 45\r\n\r\n" + b"safe=" + marker
        count, out = await one(blocked, dlp_enabled=True, dlp_action="block")
        assert marker not in out and count == len(out) < len(blocked)

        count, out = await one(blocked, dlp_enabled=True, dlp_action="audit")
        assert out == blocked and count == len(out)

        long_body = b"A" * 600 + b" " + marker
        split = (head + b"Content-Length: " + str(len(long_body)).encode()
                 + b"\r\n\r\n" + long_body)
        count, out = await one(split, dlp_enabled=True, dlp_action="block")
        assert b"A" * 100 in out and marker not in out
        assert count == len(out) < len(split)

        clean = head + b"Content-Length: 4\r\n\r\nsafe"
        count, out = await one(clean, dlp_enabled=False)
        assert out == clean and count == len(out)
        count, out = await one(clean, private=True, dlp_enabled=False)
        assert b"Cache-Control: private, no-store" in out
        assert count == len(out) > len(clean)

        # The cumulative stall cap fires *after* drain completed; that write counts.
        class SlowerSink(_ByteSink):
            async def drain(self):
                await asyncio.sleep(0.05)

        count, out = await one(clean, sink=SlowerSink(), dlp_enabled=False,
                               resp_stall_sec=0.001)
        assert out and count == len(out) < len(clean), (count, len(out), len(clean))
    asyncio.run(go())


def test_stop_reports_running_log_and_restart_waits_for_owned_worker():
    from test_sweep_proxy_request import _Backend, _exchange, _shield

    backend = _Backend()
    guard = AsyncEdgeGuard(backend_port=backend.port, listen_port=0)
    entered, release = threading.Event(), threading.Event()
    try:
        with _shield() as shield:
            original = shield.write_usage_log

            def paused(work):
                entered.set()
                assert release.wait(3)
                return original(work)

            with patch.object(shield, "write_usage_log", side_effect=paused):
                assert guard.start()["ok"]
                request = b"GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n"
                response = _exchange(guard, [request], timeout=2)
                assert response.startswith(b"HTTP/1.1 200")
                assert entered.wait(2)
                stopped = guard.stop(grace=0)
                assert stopped["stopped"] is False and stopped["usage_log_pending"] == 1
                assert guard.start()["ok"] is False
                release.set()
                for _ in range(100):
                    if guard._usage_pending == 0:
                        break
                    threading.Event().wait(0.01)
                assert guard.stop()["stopped"] is True
                assert guard.start()["ok"] is True
                assert guard.stop()["stopped"] is True
    finally:
        release.set()
        guard.stop()
        backend.close()


def test_fork_child_has_fresh_usage_locks_while_parent_job_is_preserved():
    if not hasattr(os, "fork"):
        raise SkipTest("POSIX fork is required")
    import dataplane.engine.services.proxy as proxy
    import signal

    class ParentShield:
        def __init__(self):
            self.entered, self.release = threading.Event(), threading.Event()
            self.rows = []

        def write_usage_log(self, work):
            self.entered.set()
            assert self.release.wait(4)
            self.rows.append(work)
            return True

    class ChildShield:
        def record_traffic(self, *args, **kw):
            return {"_usage_log_work": (0, {"safe": True})}

        def write_usage_log(self, work):
            return True

    guard, shield = AsyncEdgeGuard(), ParentShield()
    holder_ready, holder_release = threading.Event(), threading.Event()
    parent_result = []

    def parent_job():
        async def go():
            fut = guard._submit_usage_log(shield, "parent")
            parent_result.append(await fut)
        asyncio.run(go())

    def hold_parent_submit_lock():
        with proxy._USAGE_SUBMIT_LOCK:
            holder_ready.set()
            holder_release.wait(4)

    parent_thread = threading.Thread(target=parent_job)
    lock_thread = threading.Thread(target=hold_parent_submit_lock)
    parent_thread.start()
    pid = None
    read_fd = write_fd = None
    try:
        assert shield.entered.wait(2)
        lock_thread.start()
        assert holder_ready.wait(2)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                async def child():
                    await guard._record_traffic_deferred(
                        ChildShield(), "192.0.2.10", 1, 1, time.monotonic(), "safe.test", "GET", "/safe")
                    guard._close_usage_jobs()
                    assert guard._usage_pending == 0
                asyncio.run(child())
                os.write(write_fd, b"ok")
                os._exit(0)
            except BaseException:
                os.write(write_fd, b"error")
                os._exit(1)
        os.close(write_fd)
        write_fd = None
        deadline = time.monotonic() + 2
        while True:
            got, status = os.waitpid(pid, os.WNOHANG)
            if got:
                pid = None
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
                assert os.read(read_fd, 16) == b"ok"
                break
            if time.monotonic() >= deadline:
                raise AssertionError("fork child waited on inherited usage lock")
            time.sleep(0.01)
    finally:
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            os.waitpid(pid, 0)
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        holder_release.set()
        shield.release.set()
        parent_thread.join(3)
        if lock_thread.ident is not None:
            lock_thread.join(3)
        guard._close_usage_jobs()
    assert parent_result == [True] and shield.rows == ["parent"]
