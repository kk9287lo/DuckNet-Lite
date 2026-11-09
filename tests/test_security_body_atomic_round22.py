"""A malformed late request body must not create backend side effects."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import io
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest import SkipTest
from unittest.mock import patch

import dataplane.engine.services.proxy as proxy
import dataplane.engine.lifeform.pipeline as nd
import dataplane.engine.lifeform.policy as fw
from test_security_body_response_barrier_round19 import (
    _BAD_TAIL, _CHUNK_FIRST, _CHUNK_HEAD, _case,
)
from test_sweep_proxy_request import _Backend, _guard, _shield


def _read_all(client):
    client.settimeout(5)
    out = bytearray()
    while True:
        try:
            part = client.recv(65536)
        except OSError:
            break
        if not part:
            break
        out.extend(part)
    return bytes(out)


class _CountingOrigin:
    def __init__(self, reply_gate=None):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.reply_gate = reply_gate
        self.received = threading.Event()
        self.body_bytes = 0
        self.body_hash = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        digest = hashlib.sha256()
        try:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                head = bytearray()
                body_started = False
                content_len = None
                while True:
                    try:
                        part = conn.recv(65536)
                    except OSError:
                        break
                    if not part:
                        break
                    if not body_started:
                        head.extend(part)
                        pos = head.find(b"\r\n\r\n")
                        if pos < 0:
                            continue
                        part = bytes(head[pos + 4:])
                        content_len = int(next(
                            line.split(b":", 1)[1].strip()
                            for line in head[:pos].split(b"\r\n")
                            if line.lower().startswith(b"content-length:")))
                        body_started = True
                    useful = part[:content_len - self.body_bytes]
                    digest.update(useful)
                    self.body_bytes += len(useful)
                    if self.body_bytes == content_len:
                        break  # A framed origin need not wait for TCP FIN.
                self.body_hash = digest.digest()
                self.received.set()
                if self.reply_gate is not None:
                    self.reply_gate.wait(5)
                try:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nok")
                except OSError:
                    pass
        finally:
            self.received.set()

    def close(self):
        self.listener.close()
        self.thread.join(6)


def test_late_malformed_chunked_trailer_has_zero_backend_bytes():
    for mode in ("enforce", "audit"):
        before, after, backend, sent, _metrics = _case(
            _CHUNK_HEAD, _CHUNK_FIRST, _BAD_TAIL, mode=mode,
            scan=False)
        assert sent, mode
        assert before == b"" and after.startswith(b"HTTP/1.1 400 Bad Request\r\n"), (mode, before, after)
        assert after.partition(b"\r\n\r\n")[2] == b'{"error":"malformed chunked body"}'
        assert backend == b"", (mode, backend)


def test_malformed_chunked_browser_gets_html_with_zero_backend_bytes():
    head = _CHUNK_HEAD.replace(
        b"\r\n\r\n",
        b"\r\nAccept: text/html,application/xhtml+xml\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    before, after, backend, sent, _metrics = _case(
        head, _CHUNK_FIRST, _BAD_TAIL, scan=False)
    assert sent and before == b""
    assert after.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert b"Content-Type: text/html" in after
    assert after.partition(b"\r\n\r\n")[2].lower().startswith(b"<!doctype html>")
    assert backend == b""


def test_truncated_content_length_has_zero_backend_bytes():
    head = (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
            b"Content-Length: 10\r\n\r\n")
    before, after, backend, _sent, _metrics = _case(
        head, b"hello", None, scan=False)
    assert before == after == b"", (before, after)
    assert backend == b"", backend


def test_complete_small_chunked_and_content_length_reach_backend():
    before, after, backend, sent, _metrics = _case(
        _CHUNK_HEAD, _CHUNK_FIRST, b"0\r\n\r\n", scan=False)
    assert sent and before == b""
    assert after.startswith(b"HTTP/1.1 200 OK\r\n")
    assert backend.endswith(_CHUNK_FIRST + b"0\r\n\r\n"), backend

    head = (b"POST /side-effect HTTP/1.1\r\nHost: app.example\r\n"
            b"Content-Length: 10\r\n\r\n")
    before, after, backend, sent, _metrics = _case(
        head, b"hello", b"world", scan=False)
    assert sent and before == b""
    assert after.startswith(b"HTTP/1.1 200 OK\r\n")
    assert backend.endswith(b"helloworld"), backend


@patch.object(proxy, "_BODY_STAGE_MAX", 32)
def test_declared_overcap_is_413_before_continue_or_backend():
    origin = _Backend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False), _guard(origin) as guard:
            with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                               b"Content-Length: 33\r\nExpect: 100-continue\r\n\r\n")
                response = _read_all(client)
            assert response.startswith(b"HTTP/1.1 413 Payload Too Large\r\n"), response
            assert b"100 Continue" not in response
            assert guard._body_stage_bytes == 0
        assert origin.saw() == b""
    finally:
        origin.close()


def test_real_64mib_boundary_rejects_just_over_cap_without_body():
    assert proxy._BODY_STAGE_MAX == 64 * 1024 * 1024
    origin = _Backend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False), _guard(origin) as guard:
            with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                               b"Content-Length: 67108865\r\n\r\n")
                response = _read_all(client)
            assert response.startswith(b"HTTP/1.1 413 Payload Too Large\r\n")
            assert guard._body_stage_bytes == 0
        assert origin.saw() == b""
    finally:
        origin.close()


@patch.object(proxy, "_BODY_STAGE_MAX", 32)
def test_chunked_overcap_is_413_with_zero_backend_bytes():
    origin = _Backend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False), _guard(origin) as guard:
            with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                client.sendall(_CHUNK_HEAD + b"21\r\n" + b"X" * 33 + b"\r\n0\r\n\r\n")
                response = _read_all(client)
            assert response.startswith(b"HTTP/1.1 413 Payload Too Large\r\n"), response
            assert guard._body_stage_bytes == 0
        assert origin.saw() == b""
    finally:
        origin.close()


@patch.object(proxy, "_BODY_STAGE_MAX", 64)
@patch.object(proxy, "_BODY_STAGE_TOTAL", 16)
def test_aggregate_budget_releases_after_aborted_upload():
    origin = _Backend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False), _guard(origin) as guard:
            first = socket.create_connection(("127.0.0.1", guard.listen_port), 3)
            try:
                first.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                              b"Content-Length: 16\r\n\r\n" + b"A" * 8)
                end = time.monotonic() + 2
                while guard._body_stage_bytes != 8 and time.monotonic() < end:
                    time.sleep(0.01)
                assert guard._body_stage_bytes == 8
                with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                    client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                                   b"Content-Length: 16\r\n\r\n" + b"B" * 16)
                    response = _read_all(client)
                assert response.startswith(b"HTTP/1.1 503 Service Unavailable\r\n"), response
                assert guard._body_stage_bytes == 8
            finally:
                first.close()
            end = time.monotonic() + 2
            while guard._body_stage_bytes != 0 and time.monotonic() < end:
                time.sleep(0.01)
            assert guard._body_stage_bytes == 0
            with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                               b"Content-Length: 16\r\n\r\n" + b"C" * 16)
                assert _read_all(client).startswith(b"HTTP/1.1 200 OK\r\n")
            assert guard._body_stage_bytes == 0
        assert origin.saw().endswith(b"C" * 16), origin.saw()
        assert b"A" * 8 not in origin.saw() and b"B" * 16 not in origin.saw()
    finally:
        origin.close()


def test_spooled_megabyte_replays_exact_and_releases_before_slow_response():
    payload = b"hello" + b"Z" * (1024 * 1024 - 5)
    gate = threading.Event()
    origin = _CountingOrigin(gate)
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False), _guard(origin) as guard:
            with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                head = (b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n")
                client.sendall(head + payload)
                assert origin.received.wait(5)
                end = time.monotonic() + 5
                while guard._body_stage_bytes and time.monotonic() < end:
                    time.sleep(0.01)
                assert guard._body_stage_bytes == 0, "response wait retained spool quota"
                gate.set()
                assert _read_all(client).startswith(b"HTTP/1.1 200 OK\r\n")
            assert origin.body_bytes == len(payload)
            assert origin.body_hash == hashlib.sha256(payload).digest()
    finally:
        gate.set()
        origin.close()


def test_valid_chunked_body_excludes_pipelined_second_request():
    suffix = b"GET /hidden HTTP/1.1\r\nHost: app.example\r\n\r\n"
    before, after, backend, sent, _ = _case(
        _CHUNK_HEAD, _CHUNK_FIRST, b"0\r\n\r\n" + suffix, scan=False)
    assert sent and before == b"" and after.startswith(b"HTTP/1.1 200 OK\r\n")
    assert backend.endswith(_CHUNK_FIRST + b"0\r\n\r\n")
    assert suffix not in backend


def test_disconnect_during_large_stage_releases_all_bytes():
    patches = ExitStack()
    if os.name == "nt":
        def no_disk_spool(*_args, **_kwargs):
            raise AssertionError("Windows request body must stay in bounded memory")
        patches.enter_context(patch.object(proxy.tempfile, "SpooledTemporaryFile",
                                           no_disk_spool))
    origin = _Backend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False), _guard(origin) as guard:
            client = socket.create_connection(("127.0.0.1", guard.listen_port), 3)
            try:
                client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                               b"Content-Length: 2097152\r\n\r\n" + b"K" * 1048576)
                end = time.monotonic() + 3
                while guard._body_stage_bytes < 1048576 and time.monotonic() < end:
                    time.sleep(0.01)
                assert guard._body_stage_bytes == 1048576
            finally:
                client.close()
            end = time.monotonic() + 3
            while guard._body_stage_bytes and time.monotonic() < end:
                time.sleep(0.01)
            assert guard._body_stage_bytes == 0
        assert origin.saw() == b""
    finally:
        patches.close()
        origin.close()


def test_tiny_windows_reads_coalesce_into_bounded_pages():
    pages = []
    for _ in range(65537):
        proxy.AsyncEdgeGuard._append_memory_stage(pages, b"q")
    assert len(pages) == 2
    assert len(pages[0]) == 65536 and len(pages[1]) == 1
    assert b"".join(pages) == b"q" * 65537


def test_real_fork_aggregate_counter_and_crash_reset():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import os, struct, tempfile
from types import SimpleNamespace
import dataplane.engine.services.proxy as p
p._BODY_STAGE_TOTAL = 16
with tempfile.TemporaryDirectory() as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    shield = SimpleNamespace(path=os.path.join(state, "shield.json"))
    guard._prepare_shared_body_stage(shield)
    assert guard._adjust_body_stage(10)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        guard._claim_body_stage_owner(1)
        denied = not guard._adjust_body_stage(7)
        admitted = guard._adjust_body_stage(6)
        os.write(w, bytes([denied, admitted]))
        os._exit(0)  # simulated worker crash with six bytes reserved
    os.close(w)
    assert os.read(r, 2) == b"\x01\x01"
    assert os.waitpid(pid, 0)[1] == 0
    assert struct.unpack_from("!Q", guard._body_stage_shm)[0] == 16
    guard._close_shared_body_stage()  # only after the child is reaped
    guard._prepare_shared_body_stage(shield)
    assert struct.unpack_from("!Q", guard._body_stage_shm)[0] == 0
    guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_graceful_fork_worker_stop_releases_its_staged_bytes():
    if os.name != "posix" or not hasattr(socket, "SO_REUSEPORT"):
        raise SkipTest("requires POSIX fork and SO_REUSEPORT")
    old_shield, old_firewall = nd._SHIELD, fw._FW
    client = None
    with tempfile.TemporaryDirectory(prefix="ducknet-r22-stage-",
                                     dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
        nd._SHIELD = nd.NetShield(state_dir=state)
        fw._FW = fw.AppFirewall(state_dir=state)
        try:
            assert nd._SHIELD.set_config(enabled=False, block_page=False,
                                         max_total_conn=0, max_conn_per_ip=0,
                                         conn_rate_per_ip=0)["ok"]
            assert fw._FW.disable()["ok"]
        except BaseException:
            nd._SHIELD, fw._FW = old_shield, old_firewall
            raise
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        backend_port = probe.getsockname()[1]
        probe.close()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        listen_port = probe.getsockname()[1]
        probe.close()
        guard = proxy.AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                                     listen_host="127.0.0.1", listen_port=listen_port)
        report_read, report_write = os.pipe()
        os.set_blocking(report_read, False)
        parent_pid = os.getpid()
        original_new_loop = asyncio.new_event_loop

        def observed_new_loop():
            loop = original_new_loop()
            if os.getpid() != parent_pid:
                original_close = loop.close

                def observed_close():
                    handlers = getattr(loop, "_signal_handlers", {})
                    try:
                        os.write(report_write, b"0" if signal.SIGTERM in handlers else b"1")
                    except OSError:
                        pass
                    original_close()

                loop.close = observed_close
            return loop

        loop_patch = patch.object(proxy.asyncio, "new_event_loop", observed_new_loop)
        loop_patch.start()
        signal_report = b""
        try:
            started = guard.serve_cluster(workers=2)
            assert started.get("ok") and started.get("mode") == "cluster", started
            child = started["child_pids"][0]

            def reserved():
                return struct.unpack_from("!Q", guard._body_stage_shm)[0]

            for _ in range(30):
                client = socket.create_connection(("127.0.0.1", guard.listen_port), 2)
                client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                               b"Content-Length: 10\r\n\r\nhello")
                end = time.monotonic() + 2
                while reserved() != 5 and time.monotonic() < end:
                    time.sleep(0.01)
                assert reserved() == 5
                if guard._active == 0:
                    break  # SO_REUSEPORT routed this connection to the child
                client.close()
                client = None
                end = time.monotonic() + 2
                while reserved() and time.monotonic() < end:
                    time.sleep(0.01)
                assert reserved() == 0
            else:
                raise AssertionError("no request reached the fork worker")
            os.kill(child, signal.SIGTERM)
            end = time.monotonic() + 5
            while reserved() and time.monotonic() < end:
                time.sleep(0.01)
            assert reserved() == 0, "graceful child exit stranded shared staging quota"
        finally:
            if client is not None:
                client.close()
            guard.stop(grace=0)
            loop_patch.stop()
            os.close(report_write)
            try:
                signal_report = os.read(report_read, 16)
            except BlockingIOError:
                pass
            os.close(report_read)
            nd._SHIELD, fw._FW = old_shield, old_firewall
        assert signal_report == b"1", "worker closed its loop before removing SIGTERM"


def test_canceled_spool_close_finishes_before_quota_release():
    entered = threading.Event()
    allow_close = threading.Event()
    amount = proxy._BODY_STAGE_MEMORY + 1

    class SlowClose:
        closed = False

        def close(self):
            entered.set()
            assert allow_close.wait(3)
            self.closed = True

    async def case():
        guard = proxy.AsyncEdgeGuard()
        guard._body_stage_bytes = amount
        stage = SlowClose()
        task = asyncio.create_task(guard._release_staged_body(stage, amount))
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel()
        assert guard._body_stage_bytes == amount, "quota released before file close"
        allow_close.set()
        assert await task is True, "caller must re-raise cancellation after cleanup"
        assert stage.closed
        assert guard._body_stage_bytes == 0

    asyncio.run(case())


def test_cancelled_asyncio_spool_wrapper_yields_until_real_io_finishes():
    entered = threading.Event()
    allow_write = threading.Event()
    captured = []
    original_wrap = asyncio.wrap_future

    def capture(future, *args, **kwargs):
        wrapped = original_wrap(future, *args, **kwargs)
        captured.append(wrapped)
        return wrapped

    def blocked_write():
        entered.set()
        assert allow_write.wait(3)

    async def case():
        guard = proxy.AsyncEdgeGuard()
        with patch.object(proxy.asyncio, "wrap_future", capture):
            task = asyncio.create_task(guard._stage_file_call(blocked_write))
            end = asyncio.get_running_loop().time() + 3
            while not entered.is_set() and asyncio.get_running_loop().time() < end:
                await asyncio.sleep(0.01)
            assert entered.is_set()
            assert captured
            captured[0].cancel()
            heartbeat = False

            async def beat():
                nonlocal heartbeat
                await asyncio.sleep(0.02)
                heartbeat = True

            await beat()
            assert heartbeat and not task.done(), "cancelled wrapper blocked the event loop"
            allow_write.set()
            try:
                await task
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("cancelled wrapper was treated as successful I/O")
        guard._close_body_stage_executor()

    try:
        asyncio.run(case())
    finally:
        allow_write.set()


def test_cancelled_queued_close_retries_before_quota_release():
    gate = threading.Event()
    amount = proxy._BODY_STAGE_MEMORY + 1

    class Stage:
        closed = False

        def close(self):
            self.closed = True

    async def case():
        guard = proxy.AsyncEdgeGuard()
        guard._body_stage_bytes = amount
        guard._body_stage_executor = ThreadPoolExecutor(max_workers=1)
        guard._body_stage_executor_pid = os.getpid()
        guard._body_stage_executor.submit(gate.wait, 3)
        stage = Stage()
        captured = []
        original_wrap = asyncio.wrap_future

        def capture(future, *args, **kwargs):
            wrapped = original_wrap(future, *args, **kwargs)
            captured.append(wrapped)
            return wrapped

        try:
            with patch.object(proxy.asyncio, "wrap_future", capture):
                task = asyncio.create_task(guard._release_staged_body(stage, amount))
                end = asyncio.get_running_loop().time() + 2
                while not captured and asyncio.get_running_loop().time() < end:
                    await asyncio.sleep(0.01)
                assert captured
                captured[0].cancel()
                assert await task is True
            assert stage.closed and guard._body_stage_bytes == 0
        finally:
            gate.set()
            guard._close_body_stage_executor()

    asyncio.run(case())


def test_repeated_cancel_during_contended_quota_release_still_releases():
    async def case():
        guard = proxy.AsyncEdgeGuard()
        guard._body_stage_bytes = 1
        original = guard._adjust_body_stage
        tried = 0

        def contended(delta):
            nonlocal tried
            if delta < 0 and tried < 3:
                tried += 1
                return False
            return original(delta)

        guard._adjust_body_stage = contended
        task = asyncio.create_task(guard._release_staged_body([bytearray(b"x")], 1))
        end = asyncio.get_running_loop().time() + 2
        while tried == 0 and asyncio.get_running_loop().time() < end:
            await asyncio.sleep(0.001)
        assert tried > 0
        task.cancel()
        task.cancel()
        assert await task is True
        assert guard._body_stage_bytes == 0

    asyncio.run(case())


def test_stop_waits_for_inflight_posix_spool_write_before_release():
    if os.name != "posix":
        raise SkipTest("requires POSIX spooled file path")
    entered = threading.Event()
    allow_write = threading.Event()
    stages = []

    class BlockingSpool:
        def __init__(self, *_args, **_kwargs):
            self.file = io.BytesIO()
            self.closed = False
            stages.append(self)

        def write(self, data):
            entered.set()
            assert allow_write.wait(4)
            return self.file.write(data)

        def close(self):
            self.file.close()
            self.closed = True

    origin = _Backend()
    with patch.object(proxy, "_BODY_STAGE_MEMORY", 1), patch.object(
            proxy.tempfile, "SpooledTemporaryFile", BlockingSpool):
        try:
            with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                         graphql_enabled=False), _guard(origin) as guard:
                client = socket.create_connection(("127.0.0.1", guard.listen_port), 3)
                try:
                    client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                                   b"Content-Length: 2\r\n\r\nab")
                    assert entered.wait(3)
                    assert guard._body_stage_bytes == 2
                    result = []
                    stopper = threading.Thread(target=lambda: result.append(guard.stop(grace=0)))
                    stopper.start()
                    time.sleep(0.1)
                    assert stopper.is_alive(), "stop returned while disk write was pending"
                    assert guard._body_stage_bytes == 2
                    assert stages and not stages[0].closed
                    allow_write.set()
                    stopper.join(6)
                    assert not stopper.is_alive()
                    assert result[0]["stopped"] is True
                    assert guard._body_stage_bytes == 0
                    assert stages[0].closed
                finally:
                    allow_write.set()
                    client.close()
        finally:
            origin.close()


def test_replay_deadline_checks_before_write_and_bounds_slow_drain():
    class SlowWriter:
        def __init__(self):
            self.wire = bytearray()
            self.aborted = False
            self.transport = self

        def write(self, data):
            self.wire.extend(data)

        async def drain(self):
            await asyncio.sleep(0.2)

        def abort(self):
            self.aborted = True

    async def case():
        guard = proxy.AsyncEdgeGuard(write_timeout=1)
        writer = SlowWriter()
        expired = asyncio.get_running_loop().time() - 1
        try:
            await guard._checked_backend_write(writer, b"HEAD", None, expired)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("expired deadline accepted a backend write")
        assert writer.wire == b"" and writer.aborted

        writer = SlowWriter()
        deadline = asyncio.get_running_loop().time() + 0.02
        try:
            await guard._checked_backend_write(writer, b"BODY", None, deadline)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("slow backend drain outlived deadline")
        assert writer.wire == b"BODY" and writer.aborted
        try:
            await guard._checked_backend_write(
                writer, b"SECOND", None, asyncio.get_running_loop().time() - 1)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("expired deadline accepted a second write")
        assert writer.wire == b"BODY", "expired replay sent another chunk"

    asyncio.run(case())


def test_cancel_during_backend_connect_releases_stage_and_egress():
    started = threading.Event()

    async def stalled_connect(_guard):
        started.set()
        await proxy.asyncio.sleep(60)

    original_open = proxy.AsyncEdgeGuard._open_backend
    proxy.AsyncEdgeGuard._open_backend = stalled_connect
    origin = _Backend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                     graphql_enabled=False) as shield, _guard(origin) as guard:
            with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                               b"Content-Length: 5\r\n\r\nhello")
                assert started.wait(3)
                assert guard._body_stage_bytes == 5
                result = guard.stop(grace=0.0)
                assert result["stopped"] is True, result
                assert guard._body_stage_bytes == 0
                assert not shield._egress_time_active
        assert origin.saw() == b""
    finally:
        proxy.AsyncEdgeGuard._open_backend = original_open
        origin.close()


def test_backend_connect_refusal_releases_stage_before_502():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    unused_port = probe.getsockname()[1]
    probe.close()
    with _shield(body_scan_enabled=False, upload_scan_enabled=False,
                 graphql_enabled=False) as shield, _guard(SimpleNamespace(port=unused_port)) as guard:
        with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
            client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                           b"Content-Length: 5\r\n\r\nhello")
            response = _read_all(client)
        assert response.startswith(b"HTTP/1.1 502 Bad Gateway\r\n"), response
        assert guard._body_stage_bytes == 0
        assert not shield._egress_time_active
