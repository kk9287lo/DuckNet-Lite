"""A fork-style policy commit must not overtake the first backend write."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import SkipTest
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import _Backend, _exchange, _guard


def test_policy_ack_cannot_overtake_final_check_and_backend_wire():
    """The parent may commit while a worker holds a pre-commit decision."""
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-barrier-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        backend = _Backend()
        between = threading.Event()
        release = threading.Event()
        acknowledged = threading.Event()
        wires, edits, errors = [], [], []
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                edge._cluster_policy_sync = True
                # Internal barrier seam: stateful fork startup is separately
                # rejected by the cluster fallback wire tests.
                edge._cluster_unshared_reason = lambda *_: ""
                benign = _exchange(edge, [
                    b"GET /r16benign HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                assert benign.startswith(b"HTTP/1.1 200"), benign
                assert b"GET /r16benign" in backend.saw()

                original_sync = edge._sync_cluster_policy
                sync_calls = 0

                def pause_after_final_sync():
                    nonlocal sync_calls
                    stamp = original_sync()
                    sync_calls += 1
                    if sync_calls == 3:
                        between.set()
                        assert release.wait(10), "final policy check did not resume"
                    return stamp

                edge._sync_cluster_policy = pause_after_final_sync

                def request():
                    try:
                        wires.append(_exchange(edge, [
                            b"GET /r16race HTTP/1.1\r\nHost: local.test\r\n\r\n"]))
                    except Exception as exc:
                        errors.append(exc)

                def edit():
                    try:
                        edits.append(shield.set_config(blocked_urls=["/r16race"]))
                    except Exception as exc:
                        errors.append(exc)
                    finally:
                        acknowledged.set()

                client = threading.Thread(target=request, daemon=True)
                writer = threading.Thread(target=edit, daemon=True)
                client.start()
                try:
                    assert between.wait(5), "request did not reach final policy check"
                    writer.start()
                    # An unprotected parent commit can return before the
                    # worker's first write. A commit barrier must wait here.
                    ack_before_release = acknowledged.wait(2)
                finally:
                    release.set()
                client.join(5)
                writer.join(5)
                assert not client.is_alive() and not writer.is_alive(), errors
                assert not errors, errors
                assert edits and edits[0].get("ok") is True, edits
                assert wires, "client received no outcome"
                race_reached_backend = b"GET /r16race" in backend.saw()
                assert not (ack_before_release and race_reached_backend), (
                    edits, wires, backend.got)

                # A connection begun after the acknowledged edit is denied.
                after = _exchange(edge, [
                    b"GET /r16race HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                assert not after.startswith(b"HTTP/1.1 200"), after
        finally:
            release.set()
            backend.close()


def test_unavailable_commit_barrier_rejects_all_signed_policy_mutations():
    """An unavailable commit lock cannot turn an unsaved edit into ok:true."""
    from dataplane.engine.core import commit_barrier

    class RefusingLock:
        def acquire(self, *args, **kwargs):
            return False

        def release(self):
            raise AssertionError("refused lock must never be released")

    with tempfile.TemporaryDirectory(prefix="ducknet-r16-refuse-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert firewall.set_policy("public", "allow")["ok"]
        before_cfg = Path(shield.path).read_bytes()
        before_sigs = (Path(shield._sig_path).read_bytes()
                       if Path(shield._sig_path).exists() else None)
        before_acl = Path(firewall.path).read_bytes()
        before_rules = firewall.status()["rules"]

        key = commit_barrier._lock_path(shield.path)
        with patch.dict(commit_barrier._ACTIVE_LOCKS, {key: [RefusingLock(), 1]}):
            cfg = shield.set_config(blocked_urls=["/must-not-appear"])
            sig = shield.add_signature("must-not-appear", "r16marker")
            acl = firewall.add_rule("127.0.0.1/32", "deny")
        assert cfg.get("ok") is False and cfg.get("changed") == {}, cfg
        assert sig.get("ok") is False and sig.get("conflict") is False, sig
        assert acl.get("ok") is False and acl.get("published") is not True, acl
        assert Path(shield.path).read_bytes() == before_cfg
        assert (Path(shield._sig_path).read_bytes()
                if Path(shield._sig_path).exists() else None) == before_sigs
        assert Path(firewall.path).read_bytes() == before_acl
        assert firewall.status()["rules"] == before_rules


def test_first_backend_write_keeps_original_body_deadline_under_barrier():
    """A queued backend write cannot reset the request's total-body timer."""
    class StalledWriter:
        def __init__(self):
            self.transport = self
            self.aborted = False
            self.queued = b""

        def write(self, data):
            self.queued += data

        async def drain(self):
            await asyncio.sleep(10)

        def abort(self):
            self.aborted = True

    with tempfile.TemporaryDirectory(prefix="ducknet-r16-deadline-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        edge = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0)
        edge._cluster_policy_sync = True
        edge._cluster_unshared_reason = lambda *_: ""
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall):
                stamp = edge._sync_cluster_policy()
                writer = StalledWriter()

                async def attempt():
                    deadline = asyncio.get_running_loop().time() + 0.03
                    await edge._checked_backend_write(writer, b"POST /slow", stamp,
                                                      deadline)

                started = time.monotonic()
                try:
                    asyncio.run(attempt())
                except asyncio.TimeoutError:
                    pass
                else:
                    raise AssertionError("expired body deadline was ignored")
                assert time.monotonic() - started < 1.0
                assert writer.queued == b"POST /slow" and writer.aborted
        finally:
            edge._release_cluster_commit_lock()


def test_separate_process_policy_writer_waits_for_first_backend_drain():
    if os.name != "posix":
        raise SkipTest("POSIX file locks are required")
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-external-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        backend = _Backend()
        entered, release = threading.Event(), threading.Event()
        result = []
        child = None
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                edge._cluster_policy_sync = True
                edge._cluster_unshared_reason = lambda *_: ""
                assert _exchange(edge, [
                    b"GET /r16external-before HTTP/1.1\r\nHost: local.test\r\n\r\n"
                ]).startswith(b"HTTP/1.1 200")
                real_drain = edge._drain_backend

                async def paused_drain(writer, deadline=None):
                    await real_drain(writer, deadline)
                    entered.set()
                    while not release.is_set():
                        await asyncio.sleep(0.005)

                edge._drain_backend = paused_drain
                client = threading.Thread(target=lambda: result.append(_exchange(
                    edge, [b"GET /r16external HTTP/1.1\r\nHost: local.test\r\n\r\n"])),
                    daemon=True)
                client.start()
                assert entered.wait(5), "first backend drain did not start"
                code = ("import json,sys\n"
                        "from dataplane.engine.lifeform.pipeline import NetShield\n"
                        "print('ready', flush=True)\n"
                        "print(json.dumps(NetShield(state_dir=sys.argv[1]).set_config("
                        "blocked_urls=['/r16external'])), flush=True)\n")
                child = subprocess.Popen([sys.executable, "-c", code, state],
                                         cwd=Path(__file__).resolve().parents[1],
                                         env={**os.environ, "DUCKNET_STATE_DIR": state},
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True)
                assert select.select([child.stdout], [], [], 5)[0], "writer never started"
                assert child.stdout.readline().strip() == "ready"
                assert child.poll() is None, "writer finished before first drain released"
                time.sleep(0.2)
                assert child.poll() is None, "separate process bypassed commit lock"
                release.set()
                client.join(5)
                assert not client.is_alive() and result
                out, err = child.communicate(timeout=5)
                assert child.returncode == 0, (out, err)
                assert '"ok": true' in out.lower(), out
                assert b"GET /r16external" in backend.saw(), backend.got
                after = _exchange(edge, [
                    b"GET /r16external HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                assert not after.startswith(b"HTTP/1.1 200"), after
        finally:
            release.set()
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(3)
            backend.close()


def test_posix_commit_file_lock_is_released_after_sigkill():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("POSIX fork and file locks are required")
    from dataplane.engine.core.commit_barrier import CommitFileLock

    with tempfile.TemporaryDirectory(prefix="ducknet-r16-lock-death-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        path = str(Path(state) / "state.json")
        lock = CommitFileLock(path)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                lock.after_fork_child()
                if lock.acquire(timeout=2):
                    os.write(write_fd, b"held")
                    signal.pause()
            finally:
                os._exit(1)
        os.close(write_fd)
        try:
            assert select.select([read_fd], [], [], 3)[0]
            assert os.read(read_fd, 4) == b"held"
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            pid = 0
            assert lock.acquire(timeout=2), "SIGKILL stranded policy commit lock"
            lock.release()
        finally:
            if pid:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(read_fd)
            lock.close()


def test_cluster_fork_waits_for_acl_setter_and_keeps_child_wire_live():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("POSIX fork and SO_REUSEPORT are required")
    from test_security_cluster_round14 import _backend, _port, _received, _request

    with tempfile.TemporaryDirectory(prefix="ducknet-r16-fork-freeze-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        # This lifecycle test needs a real fork. Stateful Shield/ACL decisions
        # now correctly force a single-worker fallback until state is shared.
        assert shield.set_config(enabled=False, block_page=False,
                                 max_total_conn=0, max_conn_per_ip=0,
                                 conn_rate_per_ip=0)["ok"]
        assert firewall.disable()["ok"]
        backend_port, backend_pid, report_fd = _backend()
        edge = None
        entered, release = threading.Event(), threading.Event()
        edits = []
        real_save = firewall._save

        def paused_save(*args, **kwargs):
            entered.set()
            assert release.wait(5), "ACL edit did not resume"
            return real_save(*args, **kwargs)

        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(firewall, "_save", paused_save):
                setter = threading.Thread(target=lambda: edits.append(
                    firewall.add_rule("198.51.100.0/24", "deny")), daemon=True)
                setter.start()
                assert entered.wait(5), "ACL setter did not enter locked save"
                releaser = threading.Timer(0.75, release.set)
                releaser.start()
                edge = AsyncEdgeGuard(
                    backend_host="127.0.0.1", backend_port=backend_port,
                    listen_host="127.0.0.1", listen_port=_port())
                started_at = time.monotonic()
                result = edge.serve_cluster(workers=2)
                start_seconds = time.monotonic() - started_at
                setter.join(5)
                releaser.join(5)
                assert not setter.is_alive() and edits and edits[0]["ok"], edits
                assert result.get("ok") and result.get("mode") == "cluster", result
                with ThreadPoolExecutor(max_workers=12) as pool:
                    futures = [pool.submit(_request, edge.listen_port,
                                           b"/r16fork-benign") for _ in range(12)]
                    wires = [future.result(timeout=5) for future in futures]
                assert all(wire.startswith(b"HTTP/1.1 200") for wire in wires), wires
                assert _received(report_fd).count(b"GET /r16fork-benign") == 12
                assert start_seconds >= 0.5, start_seconds
        finally:
            release.set()
            if edge is not None:
                edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(report_fd)


def test_policy_change_stops_later_streamed_body_bytes_at_backend():
    """A policy change during staging denies the entire request wire."""

    class RecordingBackend:
        def __init__(self):
            self.first = threading.Event()
            self.any_bytes = threading.Event()
            self.done = threading.Event()
            self.got = b""
            self.listener = socket.socket()
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(1)
            self.listener.settimeout(5)
            self.port = self.listener.getsockname()[1]
            self.thread = threading.Thread(target=self.serve, daemon=True)
            self.thread.start()

        def serve(self):
            data = bytearray()
            try:
                try:
                    conn, _ = self.listener.accept()
                except (OSError, socket.timeout):
                    return  # policy may deny before any backend connection
                with conn:
                    conn.settimeout(3)
                    while True:
                        try:
                            chunk = conn.recv(65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        data.extend(chunk)
                        self.got = bytes(data)
                        self.any_bytes.set()
                        if b"AAAA" in data:
                            self.first.set()
                    try:
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    except OSError:
                        pass
            finally:
                self.got = bytes(data)
                self.done.set()

        def close(self):
            self.listener.close()
            self.thread.join(5)

    with tempfile.TemporaryDirectory(prefix="ducknet-r16-stream-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 body_scan_enabled=False)["ok"]
        backend = RecordingBackend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                edge._cluster_policy_sync = True
                edge._cluster_unshared_reason = lambda *_: ""
                client = socket.create_connection(("127.0.0.1", edge.listen_port),
                                                  timeout=5)
                try:
                    client.settimeout(5)
                    client.sendall(b"POST /r16upload HTTP/1.1\r\nHost: local.test\r\n"
                                   b"Content-Length: 8\r\n\r\nAAAA")
                    end = time.monotonic() + 5
                    while edge._body_stage_bytes != 4 and time.monotonic() < end:
                        time.sleep(0.01)
                    assert edge._body_stage_bytes == 4, "first half was not staged"
                    assert not backend.first.wait(0.2), "partial body reached backend before framing completed"
                    change = shield.set_config(blocked_urls=["/r16upload"])
                    assert change.get("ok") is True, change
                    client.sendall(b"BBBB")
                    client.shutdown(socket.SHUT_WR)
                    try:
                        while client.recv(65536):
                            pass
                    except OSError:
                        pass
                finally:
                    client.close()
                end = time.monotonic() + 5
                while edge._body_stage_bytes and time.monotonic() < end:
                    time.sleep(0.01)
                assert edge._body_stage_bytes == 0, "stale request retained staging quota"
                assert not backend.any_bytes.wait(1), "staged request crossed a stale policy barrier"
                assert backend.got == b"", backend.got
        finally:
            backend.close()


def test_cluster_refuses_split_shield_acl_state_before_listener():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("POSIX fork and SO_REUSEPORT are required")
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-split-state-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as base:
        shield = NetShield(state_dir=str(Path(base) / "shield"))
        firewall = AppFirewall(state_dir=str(Path(base) / "acl"))
        assert shield.set_config(enabled=True)["ok"]
        edge = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0)
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall):
                started = edge.serve_cluster(workers=2)
                assert started.get("ok") is False and started.get("mode") == "single", started
                assert started.get("workers") == 0 and started.get("cluster_downgraded") is False
                assert "directories differ" in started.get("reason", ""), started
                assert started.get("error") == "signed single-worker policy is unavailable"
                assert not edge.is_alive() and edge._server is None
                assert edge._listen_sock is None
                assert not edge._workers and edge._cluster_commit_lock is None
        finally:
            edge.stop(grace=0)
