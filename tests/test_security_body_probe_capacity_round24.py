"""A full cluster body budget must not trigger one owner scan per worker."""

import os
import subprocess
import sys
from unittest import SkipTest


def test_full_body_budget_scans_dead_owners_once_across_fork_workers():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import os, tempfile
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

p._BODY_STAGE_TOTAL = 16
# Stretch the proposed shared cooldown only in the test so slow CI scheduling
# cannot make the second or third fork look like a new pressure window.
if hasattr(p, "_BODY_STAGE_PROBE_INTERVAL_NS"):
    p._BODY_STAGE_PROBE_INTERVAL_NS = 5_000_000_000
with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    guard._prepare_shared_body_stage(
        SimpleNamespace(path=os.path.join(state, "shield.json")), slots=8)
    assert guard._adjust_body_stage(16)
    scans = []
    for slot in range(1, 5):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            guard._claim_body_stage_owner(slot)
            original = guard._rebuild_body_stage_total
            calls = [0]
            def counted(*args):
                calls[0] += 1
                return original(*args)
            guard._rebuild_body_stage_total = counted
            denied = not guard._adjust_body_stage(1)
            os.write(write_fd, bytes((int(denied), calls[0])))
            os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 2)
        os.close(read_fd)
        assert os.waitpid(pid, 0)[1] == 0
        assert len(result) == 2 and result[0] == 1, (slot, result)
        scans.append(result[1])
    assert sum(scans) <= 1, ("per-worker pressure amplification", scans)
    # A full but healthy parent reservation is never evicted for availability.
    assert not guard._adjust_body_stage(1)
    assert guard._adjust_body_stage(-16)
    assert guard._adjust_body_stage(16)
    assert guard._adjust_body_stage(-16)
    guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok", result.stdout


def test_sigkill_during_shared_probe_deadline_recovers_after_bounded_retry():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import os, select, signal, struct, tempfile, time
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

p._BODY_STAGE_TOTAL = 16
with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    guard._prepare_shared_body_stage(
        SimpleNamespace(path=os.path.join(state, "shield.json")), slots=3)
    assert guard._adjust_body_stage(8)
    ready, notify = os.pipe()
    owner = os.fork()
    if owner == 0:
        os.close(ready)
        guard._claim_body_stage_owner(1)
        assert guard._adjust_body_stage(8)
        os.write(notify, b"R")
        signal.pause()
        os._exit(2)
    os.close(notify)
    scanner = None
    try:
        assert select.select([ready], [], [], 5)[0]
        assert os.read(ready, 1) == b"R"
        scanner = os.fork()
        if scanner == 0:
            guard._claim_body_stage_owner(2)
            target = 32 + 16 * guard._body_stage_slot_count
            original = p.struct.pack_into
            def crash_after_first_deadline_write(fmt, buffer, offset, *values):
                original(fmt, buffer, offset, *values)
                if buffer is guard._body_stage_shm and offset == target:
                    os._exit(77)
            p.struct.pack_into = crash_after_first_deadline_write
            guard._adjust_body_stage(1)
            os._exit(78)
        assert os.waitstatus_to_exitcode(os.waitpid(scanner, 0)[1]) == 77
        scanner = None
        os.kill(owner, signal.SIGKILL)
        assert os.waitpid(owner, 0)[0] == owner
        owner = None
        # A torn deadline suppresses one pressure scan instead of letting
        # every worker perform an unbounded recovery scan. The live parent
        # reservation remains charged throughout.
        assert not guard._adjust_body_stage(8)
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 16
        time.sleep(p._BODY_STAGE_PROBE_INTERVAL_NS / 1e9 + 0.05)
        assert guard._adjust_body_stage(8), "dead owner's bytes were not reclaimed"
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 16
        assert not guard._adjust_body_stage(1)
        assert guard._adjust_body_stage(-16)
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 0
    finally:
        os.close(ready)
        for pid in (scanner, owner):
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
        guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok", result.stdout


def test_replaced_global_lock_never_splits_fork_accounting():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import fcntl, os, select, struct, tempfile
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    guard._prepare_shared_body_stage(
        SimpleNamespace(path=os.path.join(state, "shield.json")), slots=2)
    old_fd = guard._body_stage_fd()
    fcntl.flock(old_fd, fcntl.LOCK_EX)
    original = guard._body_stage_lock_path
    backup = original + ".saved"
    os.rename(original, backup)
    replacement = os.open(original, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(replacement)
    read_fd, write_fd = os.pipe()
    child = None
    try:
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            guard._claim_body_stage_owner(1)
            try:
                admitted = guard._adjust_body_stage(1)
            except OSError:
                admitted = False
            os.write(write_fd, b"A" if admitted else b"R")
            os._exit(0)
        os.close(write_fd)
        assert select.select([read_fd], [], [], 5)[0]
        outcome = os.read(read_fd, 1)
        assert os.waitpid(child, 0)[0] == child
        child = None
        # The parent still owns the ORIGINAL flock. An admitted child must
        # have locked a different inode, so the shared mmap had split owners.
        assert outcome == b"R", ("replaced global lock admitted a child", outcome)
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 0
    finally:
        os.close(read_fd)
        if child is not None:
            os.kill(child, 9)
            os.waitpid(child, 0)
        fcntl.flock(old_fd, fcntl.LOCK_UN)
        os.unlink(original)
        os.rename(backup, original)
    assert guard._adjust_body_stage(1), "restored original lock denied a benign reservation"
    assert guard._adjust_body_stage(-1)
    guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok", result.stdout


def test_replaced_global_lock_recovers_after_original_inode_is_restored():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import os, select, tempfile
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    guard._prepare_shared_body_stage(
        SimpleNamespace(path=os.path.join(state, "shield.json")), slots=2)
    original = guard._body_stage_lock_path
    backup = original + ".saved"
    os.rename(original, backup)
    fd = os.open(original, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    status_read, status_write = os.pipe()
    go_read, go_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(status_read)
        os.close(go_write)
        guard._claim_body_stage_owner(1)
        try:
            first = guard._adjust_body_stage(1)
        except OSError:
            first = False
        os.write(status_write, b"A" if first else b"R")
        assert os.read(go_read, 1) == b"G"
        try:
            restored = guard._adjust_body_stage(1)
        except OSError:
            restored = False
        os.write(status_write, b"S" if restored else b"F")
        if restored:
            assert guard._adjust_body_stage(-1)
        os._exit(0)
    os.close(status_write)
    os.close(go_read)
    try:
        assert select.select([status_read], [], [], 5)[0]
        first = os.read(status_read, 1)
        os.unlink(original)
        os.rename(backup, original)
        os.write(go_write, b"G")
        assert select.select([status_read], [], [], 5)[0]
        restored = os.read(status_read, 1)
        assert os.waitpid(child, 0)[1] == 0
        child = None
        assert (first, restored) == (b"R", b"S"), (first, restored)
        assert guard._adjust_body_stage(1)
        assert guard._adjust_body_stage(-1)
    finally:
        os.close(status_read)
        os.close(go_write)
        if child is not None:
            os.kill(child, 9)
            os.waitpid(child, 0)
        if os.path.exists(backup):
            if os.path.exists(original):
                os.unlink(original)
            os.rename(backup, original)
        guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok", result.stdout


def test_replaced_global_lock_sends_no_post_bytes_to_real_backend():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    import socket
    import tempfile
    import time
    from unittest.mock import patch

    import dataplane.engine.lifeform.pipeline as pipeline
    import dataplane.engine.lifeform.policy as policy
    import dataplane.engine.services.proxy as proxy
    from test_sweep_proxy_request import _Backend

    with tempfile.TemporaryDirectory(prefix="ducknet-r24-stage-lock-",
                                     dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=False, block_page=False,
                                 body_scan_enabled=False, upload_scan_enabled=False,
                                 graphql_enabled=False, max_total_conn=0,
                                 max_conn_per_ip=0, conn_rate_per_ip=0)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        listen_port = probe.getsockname()[1]
        probe.close()
        guard = proxy.AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                     listen_host="127.0.0.1", listen_port=listen_port)
        original = backup = None
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall):
                started = guard.serve_cluster(workers=2)
                assert started.get("ok") and started.get("mode") == "cluster", started
                time.sleep(0.1)
                original = guard._body_stage_lock_path
                backup = original + ".saved"
                os.rename(original, backup)
                fd = os.open(original, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                for _ in range(24):
                    with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                        client.settimeout(3)
                        client.sendall(b"POST /must-not-reach HTTP/1.1\r\n"
                                       b"Host: app.example\r\nContent-Length: 1\r\n\r\nx")
                        response = bytearray()
                        try:
                            while True:
                                part = client.recv(65536)
                                if not part:
                                    break
                                response.extend(part)
                        except OSError:
                            pass
                    assert not response.startswith(b"HTTP/1.1 200"), response
                assert backend.saw() == b"", backend.saw()
                os.unlink(original)
                os.rename(backup, original)
                backup = None
                for _ in range(24):
                    with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                        client.settimeout(3)
                        client.sendall(b"POST /after-restore HTTP/1.1\r\n"
                                       b"Host: app.example\r\nContent-Length: 1\r\n\r\nx")
                        response = bytearray()
                        while True:
                            part = client.recv(65536)
                            if not part:
                                break
                            response.extend(part)
                    assert response.startswith(b"HTTP/1.1 200 OK\r\n"), response
                assert backend.saw().count(b"POST /after-restore") == 24, backend.saw()
        finally:
            if original is not None and backup is not None and os.path.exists(backup):
                if os.path.exists(original):
                    os.unlink(original)
                os.rename(backup, original)
            guard.stop(grace=0)
            backend.close()
