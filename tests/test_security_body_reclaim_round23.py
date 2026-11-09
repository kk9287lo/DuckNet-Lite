"""A killed POSIX worker must not strand the live cluster's body budget."""

import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from unittest import SkipTest
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
import dataplane.engine.services.proxy as proxy
from test_sweep_proxy_request import _Backend


def test_sigkill_reclaims_only_dead_worker_body_reservation():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    # Run the real fork/SIGKILL probe in a child interpreter so a failed
    # assertion cannot leave process-global fork state in the test runner.
    script = r'''
import os, signal, struct, tempfile
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

p._BODY_STAGE_TOTAL = 16
with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    shield = SimpleNamespace(path=os.path.join(state, "shield.json"))
    guard._prepare_shared_body_stage(shield)
    assert guard._adjust_body_stage(8), "healthy parent reservation failed"
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            # The old runtime has no owner claim; it still executes this
            # probe and fails only when the leaked reservation denies parent.
            claim = getattr(guard, "_claim_body_stage_owner", None)
            if claim is not None:
                claim(1)
            assert guard._adjust_body_stage(8), "child reservation failed"
            os.write(write_fd, b"R")
            signal.pause()
        finally:
            os._exit(2)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 1) == b"R", "child never reserved body bytes"
        os.kill(child, signal.SIGKILL)
        assert os.waitpid(child, 0)[0] == child
        child = None
        assert guard._adjust_body_stage(8), "dead worker stranded the live budget"
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 16
        assert not guard._adjust_body_stage(1), "live parent reservation was lost"
        assert guard._adjust_body_stage(-16)
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 0
    finally:
        os.close(read_fd)
        if child is not None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok", result.stdout


def test_sigkill_at_every_journal_write_recovers_without_undercount():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import os, signal, struct, sys, tempfile
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

target, occurrence = map(int, sys.argv[1:])
p._BODY_STAGE_TOTAL = 16
with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    guard._prepare_shared_body_stage(SimpleNamespace(path=os.path.join(state, "shield.json")))
    assert guard._adjust_body_stage(8)
    child = os.fork()
    if child == 0:
        guard._claim_body_stage_owner(1)
        original = p.struct.pack_into
        hits = 0
        def crash_after_write(fmt, buffer, offset, *values):
            global hits
            original(fmt, buffer, offset, *values)
            if buffer is guard._body_stage_shm and offset == target:
                hits += 1
                if hits == occurrence:
                    os._exit(77)
        p.struct.pack_into = crash_after_write
        guard._adjust_body_stage(8)
        os._exit(78)
    done, status = os.waitpid(child, 0)
    assert done == child and os.waitstatus_to_exitcode(status) == 77, (target, occurrence, status)
    assert guard._adjust_body_stage(8), (target, occurrence, "dead writer denied parent")
    assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 16
    assert not guard._adjust_body_stage(1)
    assert guard._adjust_body_stage(-16)
    assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 0
    guard._close_shared_body_stage()
print("ok")
'''
    # begin marker, slot value/complement, cached total/complement, and both
    # clear-marker writes. Offset 16/24 occur twice in one mutation.
    phases = ((16, 1), (24, 1), (48, 1), (56, 1),
              (0, 1), (8, 1), (16, 2), (24, 2))
    for offset, occurrence in phases:
        result = subprocess.run([sys.executable, "-c", script,
                                 str(offset), str(occurrence)],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, (offset, occurrence, result.stderr)
        assert result.stdout.strip() == "ok", (offset, occurrence, result.stdout)


def test_owner_lock_path_replacement_never_reclaims_a_live_slot():
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SkipTest("requires real POSIX fork")
    script = r'''
import os, signal, struct, tempfile, time
from types import SimpleNamespace
import dataplane.engine.services.proxy as p

p._BODY_STAGE_TOTAL = 16
with tempfile.TemporaryDirectory(dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
    guard = p.AsyncEdgeGuard()
    guard._serving_lease = SimpleNamespace(held=True)
    guard._prepare_shared_body_stage(SimpleNamespace(path=os.path.join(state, "shield.json")))
    assert guard._adjust_body_stage(8)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        guard._claim_body_stage_owner(1)
        assert guard._adjust_body_stage(8)
        os.write(write_fd, b"R")
        signal.pause()
        os._exit(2)
    os.close(write_fd)
    owner_path = guard._body_stage_owner_paths[1]
    backup = owner_path + ".saved"
    try:
        assert os.read(read_fd, 1) == b"R"
        os.rename(owner_path, backup)
        with open(owner_path, "xb"):
            pass
        os.chmod(owner_path, 0o600)
        try:
            guard._adjust_body_stage(8)
        except OSError:
            pass
        else:
            raise AssertionError("replaced owner path reopened a live reservation")
        assert struct.unpack_from("!Q", guard._body_stage_shm, 0)[0] == 16
        os.unlink(owner_path)
        os.rename(backup, owner_path)
        os.kill(child, signal.SIGKILL)
        assert os.waitpid(child, 0)[0] == child
        child = None
        # A failed tamper probe leaves the shared pressure scan on a short
        # cooldown. Once the original inode is restored and the owner dies,
        # reclaim must succeed by the next bounded retry without resetting
        # any still-live reservation.
        until = time.monotonic() + 1.0
        while not guard._adjust_body_stage(8):
            assert time.monotonic() < until, "restored owner never reclaimed"
            time.sleep(0.01)
        assert guard._adjust_body_stage(-16)
    finally:
        os.close(read_fd)
        if child is not None:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        guard._close_shared_body_stage()
print("ok")
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok", result.stdout


def test_replaced_owner_lock_at_cluster_start_never_opens_frontend():
    if os.name != "posix" or not hasattr(socket, "SO_REUSEPORT"):
        raise SkipTest("requires real POSIX fork and SO_REUSEPORT")
    with tempfile.TemporaryDirectory(prefix="ducknet-r23-owner-start-",
                                     dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=False, block_page=False,
                                 max_total_conn=0, max_conn_per_ip=0,
                                 conn_rate_per_ip=0)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        listen_port = probe.getsockname()[1]
        probe.close()
        guard = proxy.AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                     listen_host="127.0.0.1", listen_port=listen_port)
        original_open = guard._open_body_stage_owner

        def replace_then_open(slot):
            path = guard._body_stage_owner_paths[slot]
            os.rename(path, path + ".saved")
            with open(path, "xb"):
                pass
            os.chmod(path, 0o600)
            return original_open(slot)

        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(guard, "_open_body_stage_owner", replace_then_open):
                started = guard.serve_cluster(workers=2)
            assert started.get("ok") is False, started
            assert "body staging owner unavailable" in started.get("error", ""), started
            assert not guard.is_alive() and not guard._workers
            try:
                with socket.create_connection(("127.0.0.1", listen_port), 1) as client:
                    client.sendall(b"POST /must-not-reach HTTP/1.1\r\nHost: h\r\n"
                                   b"Content-Length: 1\r\n\r\nx")
            except OSError:
                pass
            else:
                raise AssertionError("failed owner claim left a serving frontend")
            assert backend.saw() == b""
        finally:
            guard.stop(grace=0)
            backend.close()


def test_real_cluster_sigkill_reclaims_dead_upload_and_preserves_live_sibling():
    if os.name != "posix" or not hasattr(socket, "SO_REUSEPORT"):
        raise SkipTest("requires real POSIX fork and SO_REUSEPORT")
    old_shield, old_firewall = pipeline._SHIELD, policy._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r23-reclaim-",
                                     dir=os.environ.get("DUCKNET_STATE_DIR")) as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=False, block_page=False,
                                 body_scan_enabled=False,
                                 upload_scan_enabled=False,
                                 graphql_enabled=False, max_total_conn=0,
                                 max_conn_per_ip=0, conn_rate_per_ip=0)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        port_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port_probe.bind(("127.0.0.1", 0))
        listen_port = port_probe.getsockname()[1]
        port_probe.close()
        guard = proxy.AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                     listen_host="127.0.0.1", listen_port=listen_port)
        held = {}
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(proxy, "_BODY_STAGE_TOTAL", 12):
                started = guard.serve_cluster(workers=3)
                assert started.get("ok") and started.get("mode") == "cluster", started
                time.sleep(0.1)
                for child_pid in started["child_pids"]:
                    done, status = os.waitpid(child_pid, os.WNOHANG)
                    assert done == 0, ("worker exited before upload", child_pid, status)
                child1 = started["child_pids"][0]

                def slots():
                    return tuple(struct.unpack_from("!Q", guard._body_stage_shm,
                                                    32 + 16 * i)[0] for i in range(3))

                for _ in range(40):
                    if 1 in held and 2 in held:
                        break
                    before = slots()
                    client = socket.create_connection(("127.0.0.1", guard.listen_port), 3)
                    client.sendall(b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                                   b"Content-Length: 8\r\n\r\nAAAA")
                    end = time.monotonic() + 3
                    while slots() == before and time.monotonic() < end:
                        time.sleep(0.01)
                    after = slots()
                    changed = [i for i in range(3) if after[i] == before[i] + 4]
                    if len(changed) == 1 and changed[0] in (1, 2) and changed[0] not in held:
                        held[changed[0]] = client
                    else:
                        client.close()
                        end = time.monotonic() + 3
                        while slots() != before and time.monotonic() < end:
                            time.sleep(0.01)
                        assert slots() == before, (before, after, slots())
                assert set(held) == {1, 2}, (slots(), guard.metrics, shield.cfg.get("enabled"))
                assert slots() == (0, 4, 4), slots()
                assert backend.saw() == b"", backend.saw()

                os.kill(child1, signal.SIGKILL)
                assert os.waitpid(child1, 0)[0] == child1
                held[1].close()
                del held[1]
                # Cached total still includes the killed child's four bytes.
                # An eight-byte POST needs that space while sibling slot2 is
                # still charged. The origin must receive exactly this valid
                # request, never either incomplete POST.
                with socket.create_connection(("127.0.0.1", guard.listen_port), 3) as client:
                    client.settimeout(5)
                    client.sendall(b"POST /healthy HTTP/1.1\r\nHost: app.example\r\n"
                                   b"Content-Length: 8\r\n\r\nGOODBODY")
                    response = bytearray()
                    while True:
                        part = client.recv(65536)
                        if not part:
                            break
                        response.extend(part)
                assert bytes(response).startswith(b"HTTP/1.1 200 OK\r\n"), response
                end = time.monotonic() + 3
                while slots() != (0, 0, 4) and time.monotonic() < end:
                    time.sleep(0.01)
                assert slots() == (0, 0, 4), slots()
                assert b"GOODBODY" in backend.saw(), backend.saw()
                assert b"AAAA" not in backend.saw(), backend.saw()
                held[2].close()
                del held[2]
                end = time.monotonic() + 3
                while slots() != (0, 0, 0) and time.monotonic() < end:
                    time.sleep(0.01)
                assert slots() == (0, 0, 0), slots()
        finally:
            for client in held.values():
                client.close()
            guard.stop(grace=0)
            backend.close()
            pipeline._SHIELD, policy._FW = old_shield, old_firewall
