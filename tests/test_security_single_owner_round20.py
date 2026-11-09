"""Two serving processes must not spend one finite quota independently."""

import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

from dataplane import service
from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.core.serving_lease import ServingLease
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import _Backend


ROOT = Path(__file__).resolve().parents[1]
CHILD = r'''
import json, sys, time
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import AsyncEdgeGuard
state, backend = sys.argv[1], int(sys.argv[2])
shield = ND._SHIELD = ND.NetShield(state_dir=state)
FW._FW = FW.AppFirewall(state_dir=state)
edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend,
                      listen_host="127.0.0.1", listen_port=0)
started = edge.start()
print(json.dumps({"ok": started.get("ok"), "port": edge.listen_port,
                  "alive": edge.is_alive(), "error": started.get("error", "")}), flush=True)
if started.get("ok"):
    command = sys.stdin.readline().strip()
    if command == "stop_pause":
        # The HTTP reply can reach the client before the handler enqueues and
        # finishes its deferred usage log. Stop must retain the lease meanwhile.
        deadline = time.monotonic() + 5.0
        while (edge._active or edge._log_pending) and time.monotonic() < deadline:
            time.sleep(0.01)
        if edge._active or edge._log_pending:
            print(json.dumps({"phase": "request_pending", "active": edge._active,
                              "log_pending": edge._log_pending}),
                  flush=True)
            sys.exit(1)
        original_flush = shield.flush_state
        def paused_flush():
            print(json.dumps({"phase": "before_flush"}), flush=True)
            sys.stdin.readline()
            return original_flush()
        shield.flush_state = paused_flush
    stopped = edge.stop(grace=0)
    print(json.dumps({"phase": "stopped", "ok": stopped.get("ok")}), flush=True)
'''


def _env(state):
    env = dict(os.environ)
    env["DUCKNET_STATE_DIR"] = str(state)
    env["TEMP"] = env["TMP"] = str(state)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _start(state, backend_port):
    child = subprocess.Popen([sys.executable, "-B", "-c", CHILD, str(state),
                              str(backend_port)], env=_env(state),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    line = _readline(child)
    if not line:
        child.kill()
        _out, err = child.communicate(timeout=8)
        raise AssertionError(f"listener child failed before reporting: {err}")
    return child, json.loads(line)


def _readline(child, timeout=6.0):
    output = queue.Queue(maxsize=1)
    reader = threading.Thread(target=lambda: output.put(child.stdout.readline()),
                              daemon=True)
    reader.start()
    try:
        return output.get(timeout=timeout)
    except queue.Empty:
        child.kill()
        child.wait(timeout=3)
        reader.join(timeout=1)
        child.stdin.close()
        child.stdout.close()
        child.stderr.close()
        raise AssertionError("listener child did not report within deadline") from None


def _stop(child):
    if child is None:
        return
    if child.poll() is None:
        try:
            child.stdin.write("stop\n")
            child.stdin.flush()
            child.wait(timeout=5)
        except Exception:
            child.kill()
            child.wait(timeout=3)
    child.stdin.close()
    child.stdout.close()
    child.stderr.close()


def _pause_before_final_flush(child):
    child.stdin.write("stop_pause\n")
    child.stdin.flush()
    line = _readline(child, timeout=8.0)
    assert line and json.loads(line) == {"phase": "before_flush"}, line


def _complete_final_flush(child):
    child.stdin.write("flush\n")
    child.stdin.flush()
    line = _readline(child)
    assert line and json.loads(line) == {"phase": "stopped", "ok": True}, line
    assert child.wait(timeout=5) == 0


def _request(port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.settimeout(3)
        client.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: local.test\r\n"
                       b"Connection: close\r\n\r\n")
        client.shutdown(socket.SHUT_WR)
        wire = bytearray()
        while True:
            part = client.recv(65536)
            if not part:
                return bytes(wire)
            wire.extend(part)


def test_same_state_second_listener_refuses_before_bind_then_recovers_after_flush():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 quota_enabled=True, quota_max_gb=1e-6)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        first = second = during = third = None
        try:
            first, ready = _start(state, backend.port)
            assert ready["ok"] and ready["alive"] and ready["port"] > 0, ready

            second, denied = _start(state, backend.port)
            assert denied["ok"] is False and denied["alive"] is False, denied
            assert denied["port"] == 0, "lease failure must precede listener bind"
            assert backend.saw() == b"", "refused owner must not forward bytes"

            primary = _request(ready["port"], b"/first-still-owns")
            assert primary.startswith(b"HTTP/1.1 200"), primary[:100]
            assert b"GET /first-still-owns" in backend.saw(), backend.saw()

            _pause_before_final_flush(first)
            during, still_denied = _start(state, backend.port)
            assert still_denied["ok"] is False and still_denied["port"] == 0, (
                "lease released before final state flush", still_denied)
            _complete_final_flush(first)
            _stop(first)
            first = None
            third, recovered = _start(state, backend.port)
            assert recovered["ok"] and recovered["alive"] and recovered["port"] > 0, recovered
            again = _request(recovered["port"], b"/new-owner-after-flush")
            assert again.startswith(b"HTTP/1.1 200"), again[:100]
            assert b"GET /new-owner-after-flush" in backend.saw(), backend.saw()
        finally:
            _stop(third)
            _stop(during)
            _stop(second)
            _stop(first)
            backend.close()


def test_service_busy_state_refuses_before_default_or_declarative_mutation():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        with ServingLease(state) as owner:
            with patch.dict(os.environ, {"DUCKNET_STATE_DIR": state}), \
                    patch.object(service, "app_firewall", side_effect=AssertionError(
                        "default ACL mutated before lease")) as firewall, \
                    patch.object(service, "net_shield", side_effect=AssertionError(
                        "Shield/config mutated before lease")) as shield:
                try:
                    service.run(backend="127.0.0.1:1", listen=0, admin_port=0,
                                defaults_on=True, config_path="unused.json")
                except SystemExit as exc:
                    assert "既に稼働中" in str(exc), exc
                else:
                    assert False, "second service acquired an active state"
                assert not firewall.called and not shield.called
            assert owner.held, "failed second service released first owner's lease"


def test_service_prelistener_config_error_releases_lease_for_retry():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        with patch.dict(os.environ, {"DUCKNET_STATE_DIR": state}), \
                patch.object(service, "net_shield", return_value=shield):
            try:
                service.run(backend="127.0.0.1:1", listen=0, admin_port=0,
                            defaults_on=False, config_path=str(Path(state) / "missing.json"))
            except SystemExit as exc:
                assert "宣言的設定を適用できません" in str(exc), exc
            else:
                assert False, "missing config was applied"
        with ServingLease(state) as retry:
            assert retry.held


def test_service_failed_start_retains_dirty_lease_when_flush_fails():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        finished = []
        guard = SimpleNamespace(
            _workers=[], _listen_sock=None, _server=None, _serving_lease=None,
            is_alive=lambda: False,
            start=lambda: {"ok": False, "error": "synthetic pre-bind failure"},
            _finish_serving_lease=lambda: finished.append(True) or False,
        )
        with patch.dict(os.environ, {"DUCKNET_STATE_DIR": state}), \
                patch.object(service, "net_shield", return_value=shield), \
                patch.object(service, "AsyncEdgeGuard", return_value=guard):
            try:
                service.run(backend="127.0.0.1:1", listen=0, admin_port=0,
                            defaults_on=False)
            except SystemExit as exc:
                assert "synthetic pre-bind failure" in str(exc), exc
            else:
                assert False, "failed listener startup was accepted"
        try:
            assert finished, "failed flush was not attempted"
            assert guard._serving_lease.held, "dirty owner lease was released"
            contender = ServingLease(state)
            try:
                assert contender.acquire() is False
            finally:
                contender.close()
        finally:
            guard._serving_lease.close()


def test_usage_only_flush_failure_reports_failure_but_releases_safe_quota_owner():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        lease = ServingLease(state)
        assert lease.acquire()
        shield = SimpleNamespace(
            cfg={"persist_bans": True}, _traffic_dirty=False, _bans_dirty=False,
            _serving_lease=lease,
            flush_state=lambda: {"ok": False, "traffic_saved": True,
                                 "bans": "saved", "usage_saved": False},
        )
        edge = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                              backend_host="127.0.0.1", backend_port=1)
        edge._serving_lease = lease
        with patch.object(ND, "_SHIELD", shield):
            assert edge._finish_serving_lease() is False
        assert edge._serving_lease is None and not lease.held
        with ServingLease(state) as next_owner:
            assert next_owner.held


def test_dirty_quota_flush_failure_retains_owner_against_valid_disk():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        lease = ServingLease(state)
        assert lease.acquire()

        def read_valid(_path, _default, _kind, *, status_out):
            status_out.append("ok")
            return {}, False

        shield = SimpleNamespace(
            cfg={"persist_bans": True}, _traffic_dirty=True, _bans_dirty=False,
            _traffic_path=str(Path(state) / "traffic.json"),
            _bans_path=str(Path(state) / "blocklist.json"),
            _serving_lease=lease, _read_state=read_valid,
            flush_state=lambda: {"ok": False, "traffic_saved": False,
                                 "bans": "saved", "usage_saved": True},
        )
        edge = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                              backend_host="127.0.0.1", backend_port=1)
        edge._serving_lease = lease
        try:
            with patch.object(ND, "_SHIELD", shield):
                assert edge._finish_serving_lease() is False
            assert edge._serving_lease is lease and lease.held
            contender = ServingLease(state)
            try:
                assert contender.acquire() is False
            finally:
                contender.close()
        finally:
            lease.close()
