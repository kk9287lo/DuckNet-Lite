"""A fork worker must stop serving if its parent dies without a drain."""

import json
import os
from pathlib import Path
import select
import signal
import socket
import tempfile
import threading
import time
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline as nd, policy as fw
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_security_cluster_round14 import _backend, _port, _received


def _requires_cluster():
    if not (hasattr(os, "fork") and hasattr(os, "setsid") and
            hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("POSIX fork, setsid and SO_REUSEPORT required")


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-parent-death-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _request(port, path):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as conn:
            conn.settimeout(2)
            conn.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: test.local\r\n\r\n")
            conn.shutdown(socket.SHUT_WR)
            data = bytearray()
            while len(data) < 8192:
                chunk = conn.recv(8192 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            return bytes(data)
    except OSError:
        return b""


def _configure(state):
    nd._SHIELD = nd.NetShield(state_dir=state)
    fw._FW = fw.AppFirewall(state_dir=state)
    # Exercise a genuinely safe fork: mutable Shield/ACL/connection counters
    # are process-local and now force an honest single-worker fallback.
    result = nd._SHIELD.set_config(enabled=False, block_page=False,
                                   persist_bans=False, max_total_conn=0,
                                   max_conn_per_ip=0, conn_rate_per_ip=0)
    assert result["ok"], result
    assert fw._FW.disable()["ok"]


class _DenyVaultBeforeWrite(AsyncEdgeGuard):
    """Test-only next-generation policy; old orphan must never forward it."""

    async def _checked_backend_write(self, bwr, data, admission_stamp,
                                     deadline=None):
        if b"/orphan-vault" in data:
            raise RuntimeError("next generation denies vault")
        return await super()._checked_backend_write(bwr, data,
                                                   admission_stamp, deadline)


def _read_report(fd):
    data = bytearray()
    deadline = time.monotonic() + 10
    while b"\n" not in data and time.monotonic() < deadline:
        if select.select([fd], [], [], .2)[0]:
            data.extend(os.read(fd, 4096))
    assert b"\n" in data, "cluster parent did not report startup"
    return json.loads(data.split(b"\n", 1)[0])


def _fork_generation(state, backend_port, listen_port, *, blocked=False,
                     guard_class=AsyncEdgeGuard, guard_args=None):
    report_r, report_w = os.pipe()
    parent = os.fork()
    if parent == 0:
        os.close(report_r)
        os.setsid()  # unique process group; cleanup cannot signal unrelated PIDs
        try:
            _configure(state)
            chosen_guard = _DenyVaultBeforeWrite if blocked else guard_class
            edge = chosen_guard(backend_host="127.0.0.1", backend_port=backend_port,
                               listen_host="127.0.0.1", listen_port=listen_port,
                               **(guard_args or {}))
            stopping = False

            def term(_signum, _frame):
                nonlocal stopping
                stopping = True

            signal.signal(signal.SIGTERM, term)
            info = edge.serve_cluster(workers=2)
            os.write(report_w, (json.dumps(info) + "\n").encode("ascii"))
            while not stopping:
                time.sleep(.05)
            edge.stop(grace=0)
        finally:
            os._exit(0)
    os.close(report_w)
    try:
        info = _read_report(report_r)
    except BaseException:
        _stop_group(parent)
        raise
    finally:
        os.close(report_r)
    assert info.get("ok") and info.get("mode") == "cluster", info
    assert len(info.get("child_pids") or []) == 1, info
    return parent, info


def _stop_group(parent):
    if parent is None:
        return
    try:
        os.killpg(parent, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(parent, 0)
    except ChildProcessError:
        pass


def _kill_parent(parent):
    os.kill(parent, signal.SIGKILL)
    os.waitpid(parent, 0)


class _PausedBeforeListener(AsyncEdgeGuard):
    def __init__(self, *args, ready_fd, release_fd, **kwargs):
        super().__init__(*args, **kwargs)
        self._birth_pid = os.getpid()
        self._ready_fd, self._release_fd = ready_fd, release_fd

    def _worker_blocking(self):
        if os.getpid() != self._birth_pid:
            os.write(self._ready_fd, b"1")
            os.read(self._release_fd, 1)
        super()._worker_blocking()


class _PausedBeforeWrite(AsyncEdgeGuard):
    def __init__(self, *args, ready_fd, release_fd, **kwargs):
        super().__init__(*args, **kwargs)
        self._birth_pid = os.getpid()
        self._ready_fd, self._release_fd = ready_fd, release_fd
        self._paused_once = False

    async def _handle(self, reader, writer):
        if os.getpid() == self._birth_pid:
            writer.close()
            return
        return await super()._handle(reader, writer)

    async def _checked_backend_write(self, bwr, data, admission_stamp,
                                     deadline=None):
        if os.getpid() != self._birth_pid and not self._paused_once:
            self._paused_once = True
            os.write(self._ready_fd, b"1")
            os.read(self._release_fd, 1)
        return await super()._checked_backend_write(bwr, data, admission_stamp, deadline)


def test_parent_sigkill_orphan_cannot_overlap_new_generation():
    _requires_cluster()
    backend_port, backend_pid, backend_report = _backend()
    listen_port = _port()
    first_parent = second_parent = None
    with _state_dir() as base:
        try:
            first_parent, first = _fork_generation(
                str(Path(base) / "first"), backend_port, listen_port)
            warm = [_request(listen_port, b"/warm") for _ in range(12)]
            assert any(w.startswith(b"HTTP/1.1 200") for w in warm), warm
            assert b"GET /warm" in _received(backend_report)
            _kill_parent(first_parent)
            time.sleep(1)
            after_kill = [_request(listen_port, b"/orphan-vault") for _ in range(24)]
            after_wire = _received(backend_report)
            second_parent, second = _fork_generation(
                str(Path(base) / "second"), backend_port, listen_port, blocked=True)
            overlap = [_request(listen_port, b"/orphan-vault") for _ in range(64)]
            overlap_wire = _received(backend_report)
            assert first["mode"] == second["mode"] == "cluster"
            assert not any(w.startswith(b"HTTP/1.1 200") for w in after_kill + overlap)
            assert b"GET /orphan-vault" not in after_wire + overlap_wire
        finally:
            _stop_group(second_parent)
            _stop_group(first_parent)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)


def test_parent_death_before_child_listener_prevents_late_bind():
    _requires_cluster()
    backend_port, backend_pid, backend_report = _backend()
    listen_port = _port()
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    parent = None
    with _state_dir() as state:
        try:
            parent, _ = _fork_generation(
                state, backend_port, listen_port,
                guard_class=_PausedBeforeListener,
                guard_args={"ready_fd": ready_w, "release_fd": release_r})
            assert select.select([ready_r], [], [], 10)[0]
            assert os.read(ready_r, 1) == b"1"
            _kill_parent(parent)
            os.write(release_w, b"1")
            time.sleep(1)
            wires = [_request(listen_port, b"/prelisten-after-death") for _ in range(24)]
            assert not any(w.startswith(b"HTTP/1.1 200") for w in wires)
            assert b"GET /prelisten-after-death" not in _received(backend_report)
        finally:
            _stop_group(parent)
            for fd in (ready_r, ready_w, release_r, release_w):
                os.close(fd)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)


def test_parent_death_after_admission_prevents_first_backend_write():
    _requires_cluster()
    backend_port, backend_pid, backend_report = _backend()
    listen_port = _port()
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    parent = None
    attempts = []
    halt = threading.Event()

    def drive():
        while not halt.is_set() and len(attempts) < 30:
            attempts.append(_request(listen_port, b"/prewrite-after-death"))

    driver = threading.Thread(target=drive, daemon=True)
    with _state_dir() as state:
        try:
            parent, _ = _fork_generation(
                state, backend_port, listen_port,
                guard_class=_PausedBeforeWrite,
                guard_args={"ready_fd": ready_w, "release_fd": release_r})
            driver.start()
            assert select.select([ready_r], [], [], 10)[0]
            assert os.read(ready_r, 1) == b"1"
            _kill_parent(parent)
            os.write(release_w, b"1")
            driver.join(5)
            halt.set()
            assert not any(w.startswith(b"HTTP/1.1 200") for w in attempts)
            assert b"GET /prewrite-after-death" not in _received(backend_report)
        finally:
            halt.set()
            _stop_group(parent)
            for fd in (ready_r, ready_w, release_r, release_w):
                os.close(fd)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)


def test_fork_failure_closes_parent_guard_pipe():
    _requires_cluster()
    old_shield, old_firewall = nd._SHIELD, fw._FW
    with _state_dir() as state:
        try:
            _configure(state)
            edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=_port(),
                                  listen_host="127.0.0.1", listen_port=_port())
            observed = []
            real_pipe = os.pipe

            def recording_pipe():
                pair = real_pipe()
                observed.extend(pair)
                return pair

            with patch.object(os, "pipe", side_effect=recording_pipe), \
                    patch.object(os, "fork", side_effect=OSError("injected")):
                result = edge.serve_cluster(workers=2)
            assert result.get("ok") is False and "fork failed" in result.get("error", "")
            assert observed and edge._parent_guard_read is edge._parent_guard_write is None
            for fd in observed:
                try:
                    os.fstat(fd)
                except OSError:
                    continue
                raise AssertionError(f"parent guard FD {fd} leaked")
        finally:
            nd._SHIELD, fw._FW = old_shield, old_firewall


def test_normal_cluster_stop_keeps_writer_through_drain():
    _requires_cluster()
    old_shield, old_firewall = nd._SHIELD, fw._FW
    with _state_dir() as state:
        _configure(state)
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        try:
            result = edge.serve_cluster(workers=2)
            assert result.get("ok") and result.get("mode") == "cluster", result
            benign = [_request(edge.listen_port, b"/normal-stop-before") for _ in range(20)]
            assert all(w.startswith(b"HTTP/1.1 200") for w in benign), benign
            assert _received(backend_report).count(b"GET /normal-stop-before") == 20
            original_stop = edge._stop_workers
            held = []

            def checked_stop(*args, **kwargs):
                held.append(edge._parent_guard_write is not None)
                return original_stop(*args, **kwargs)

            edge._stop_workers = checked_stop
            stopped = edge.stop(grace=.5)
            assert stopped.get("stopped") and stopped.get("workers_stopped") == 1, stopped
            assert held == [True] and edge._parent_guard_read is None
            assert edge._parent_guard_write is None
            assert _request(edge.listen_port, b"/normal-stop-after") == b""
            assert b"GET /normal-stop-after" not in _received(backend_report)
        finally:
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            nd._SHIELD, fw._FW = old_shield, old_firewall
