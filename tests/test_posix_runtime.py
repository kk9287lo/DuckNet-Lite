"""POSIX 実プロセス・所有者の境界。Linux のテスト用環境で実行する。"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.services import edge_config


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_port(port, proc, log_path, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.05)
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        output = handle.read()[-1200:]
    raise AssertionError(f"admin did not start: exit={proc.poll()} log={output!r}")


def test_posix_real_sigterm_flushes_pending_ban_after_safe_cluster_fallback():
    """Default stateful --cluster safely becomes single, then SIGTERM flushes."""
    if (os.name != "posix" or not hasattr(os, "fork")
            or not hasattr(socket, "SO_REUSEPORT") or not os.path.isdir("/proc/self/fd")):
        raise SkipTest("fork/SO_REUSEPORT と /proc が使える Linux が必要")
    from dataplane.engine.lifeform.pipeline import NetShield

    with tempfile.TemporaryDirectory() as directory:
        state_dir = os.path.join(directory, "state")
        start_file = os.path.join(directory, "cluster-start.json")
        flush_file = os.path.join(directory, "flush.json")
        ready_file = os.path.join(directory, "handlers.txt")
        log_file = os.path.join(directory, "service.log")
        listen, admin = _free_port(), _free_port()
        code = """
import json, os, sys, time
from dataplane.engine.lifeform.pipeline import NetShield, net_shield
from dataplane.engine.services.proxy import AsyncEdgeGuard
import dataplane.service as service
from dataplane.service import run
sh = net_shield()
original_cluster = AsyncEdgeGuard.serve_cluster
def two_workers(self, *args, **kwargs):
    info = original_cluster(self, workers=2)
    # The cluster preflight reloads signed defaults. Apply these test-only
    # debounce knobs after that reload so shutdown must flush a pending BAN.
    if info.get("ok"):
        with sh._lock:
            sh.cfg["ban_persist_debounce_from"] = 1
            sh.cfg["ban_persist_min_interval_sec"] = 3600.0
            sh._bans_last_save = time.time()
            sh._refresh_cfg_mac()
    with open(os.environ["DUCKNET_TEST_CLUSTER_START"], "w") as out:
        json.dump(info, out)
    return info
AsyncEdgeGuard.serve_cluster = two_workers
original_flush = NetShield.flush_state
def marked_flush(self):
    result = original_flush(self)
    with open(os.environ["DUCKNET_TEST_FLUSH"], "w") as out:
        json.dump(result, out)
    return result
NetShield.flush_state = marked_flush
original_install = service._install_shutdown_handlers
def marked_install(event):
    names = original_install(event)
    with open(os.environ["DUCKNET_TEST_READY"], "w") as out:
        out.write(",".join(names))
    return names
service._install_shutdown_handlers = marked_install
run(backend="127.0.0.1:9", listen=int(sys.argv[1]), admin_port=int(sys.argv[2]),
    host="127.0.0.1", admin_host="127.0.0.1", token="posix-test-token",
    cluster=True, drain_grace=0.2)
"""
        env = dict(os.environ)
        env.update({"DUCKNET_STATE_DIR": state_dir, "DUCKNET_OFFLINE": "1",
                    "DUCKNET_SELF_DEFENSE": "0", "DUCKNET_TEST_CLUSTER_START": start_file,
                    "DUCKNET_TEST_FLUSH": flush_file, "DUCKNET_TEST_READY": ready_file,
                    "PYTHONUNBUFFERED": "1"})
        env.pop("DUCKNET_STATE_KEY", None)
        with open(log_file, "wb") as output:
            proc = subprocess.Popen([sys.executable, "-c", code, str(listen), str(admin)],
                                    stdout=output, stderr=subprocess.STDOUT, env=env,
                                    start_new_session=True)
        try:
            _wait_port(admin, proc, log_file)
            assert os.path.exists(start_file), "cluster fallback was not recorded"
            with open(start_file, encoding="utf-8") as handle:
                started = json.load(handle)
            assert (started.get("ok") is True and started.get("mode") == "single"
                    and started.get("workers") == 1
                    and started.get("cluster_downgraded") is True
                    and not started.get("child_pids")), started
            deadline = time.monotonic() + 8
            while not os.path.exists(ready_file) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert os.path.exists(ready_file), "SIGTERM handler was not installed"
            with open(ready_file, encoding="ascii") as handle:
                assert "SIGTERM" in handle.read()
            data = json.dumps({"ip": "203.0.113.91"}).encode()
            request = urllib.request.Request(
                f"http://127.0.0.1:{admin}/api/shield/ban", data=data,
                headers={"X-Token": "posix-test-token",
                         "Content-Type": "application/json"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=3) as response:
                ban = json.load(response)
            assert ban.get("ok") and ban.get("persistence_pending"), ban
            assert not os.path.exists(os.path.join(state_dir, "blocklist.json"))

            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=10) == 0
            assert os.path.exists(flush_file), "SIGTERM path skipped flush_state"
            with open(flush_file, encoding="utf-8") as handle:
                flush_result = json.load(handle)
            assert flush_result.get("persisted") is True, flush_result
            restored = NetShield(state_dir=state_dir)
            assert any(b["ip"] == "203.0.113.91" for b in restored.bans())
            for port in (listen, admin):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                except OSError:
                    pass
                else:
                    raise AssertionError(f"listener survived SIGTERM: {port}")
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                proc.wait(timeout=5)


def test_posix_export_rejects_foreign_owner_then_preserves_read_only_group():
    """root 所有の公開 banlist は別 UID から読めるが書き換えられない。"""
    if os.name != "posix" or os.geteuid() != 0:
        raise SkipTest("別 UID 所有ファイルを作れる POSIX root が必要")
    import stat

    class Shield:
        cfg = {"mode": "enforce"}

        def is_enabled(self):
            return True

        def bans(self):
            return [{"ip": "192.0.2.9"}]

    class Firewall:
        rules = []

        def is_enabled(self):
            return True

    with tempfile.TemporaryDirectory() as directory:
        os.chown(directory, 0, 10001)
        os.chmod(directory, 0o750)              # 別グループは通過・読取のみ
        path = os.path.join(directory, "edge_banlist.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("old\n")
        os.chown(path, 10001, 10001)
        os.chmod(path, 0o640)
        with patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=Shield()), \
                patch("dataplane.engine.lifeform.policy.app_firewall", return_value=Firewall()):
            result = edge_config.export_banlist(path)
            assert result.get("ok") is False, result
            with open(path, encoding="utf-8") as handle:
                assert handle.read() == "old\n"
            os.chown(path, 0, 10001)
            before = os.stat(path)
            result = edge_config.export_banlist(path)
        assert result.get("ok") is True, result
        after = os.stat(path)
        assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
            before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
        with open(path, encoding="utf-8") as handle:
            assert "192.0.2.9\n" in handle.read()

        code = ("import sys\n"
                "p = sys.argv[1]\n"
                "with open(p, 'rb') as f: assert b'192.0.2.9' in f.read()\n"
                "try:\n"
                " with open(p, 'ab') as f: f.write(b'attack')\n"
                "except PermissionError:\n"
                " print('read-only')\n"
                "else:\n"
                " print('writable')\n")
        checked = subprocess.run([sys.executable, "-c", code, path], user=10001,
                                 group=10001, capture_output=True, text=True, timeout=3)
        assert checked.returncode == 0 and checked.stdout.strip() == "read-only", checked

        os.chmod(path, 0o666)
        with patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=Shield()), \
                patch("dataplane.engine.lifeform.policy.app_firewall", return_value=Firewall()):
            result = edge_config.export_banlist(path)
        assert result.get("ok") is False, result
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o666
