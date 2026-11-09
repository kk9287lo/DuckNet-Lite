"""Runtime regressions for ACL publication and admin operation results."""
import json
import copy
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

from dataplane import admin as A
from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.lifeform import policy as FW
from dataplane.engine.core import atomic_io as AIO
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_admin_ui import _Admin


def test_acl_public_results_cannot_modify_live_or_durable_rules():
    with tempfile.TemporaryDirectory() as directory:
        fw = FW.AppFirewall(state_dir=directory)
        result = fw.add_rule("1.1.1.1/32", "deny")
        assert result["ok"] is True
        result["rules"][0]["action"] = "allow"
        assert fw.evaluate("1.1.1.1")["action"] == "deny"
        status = fw.status()
        status["rules"][0]["action"] = "allow"
        assert fw.evaluate("1.1.1.1")["action"] == "deny"
        # An unrelated successful save must not persist a mutation of a snapshot.
        assert fw.set_policy("private", "deny")["ok"] is True
        assert FW.AppFirewall(state_dir=directory).evaluate("1.1.1.1")["action"] == "deny"


def test_acl_pending_snapshots_and_input_metadata_are_independent():
    with tempfile.TemporaryDirectory() as directory:
        fw = FW.AppFirewall(state_dir=directory)
        assert fw.set_policy("public", "prompt")["ok"] is True
        metadata = {"headers": {"label": "original"}}
        pid = fw.evaluate("1.1.1.1", meta=metadata)["pending_id"]
        metadata["headers"]["label"] = "changed"
        assert fw.pending()[0]["meta"]["headers"]["label"] == "original"
        pending = fw.pending()
        pending[0]["ip"] = "2.2.2.2"
        pending[0]["meta"]["headers"]["label"] = "changed again"
        status = fw.status()
        status["pending"][0]["ip"] = "3.3.3.3"
        assert fw.approve(pid, remember=True)["ok"] is True
        restored = FW.AppFirewall(state_dir=directory)
        assert restored.evaluate("1.1.1.1")["action"] == "allow"
        assert restored.evaluate("2.2.2.2")["action"] == "pending"


def test_acl_invalid_policy_is_rejected_as_a_whole_on_reload():
    for signed in (False, True):
        for invalid in ({"public": "allow", "loopback": "dney"},
                        {"public": "allow", "publci": "deny"},
                        ["public", "allow"]):
            with tempfile.TemporaryDirectory() as directory:
                payload = {"enabled": False, "policy": invalid,
                           "rules": [{"net": "1.1.1.1/32", "action": "allow"}]}
                path = os.path.join(directory, "acl.json")
                if signed:
                    key = FW.AppFirewall(state_dir=directory)._state_key
                    assert FW.write_signed_json(path, payload, key)
                else:
                    with open(path, "w", encoding="utf-8") as stream:
                        json.dump(payload, stream)
                fw = FW.AppFirewall(state_dir=directory)
                assert fw.is_enabled() is True
                assert fw.evaluate("1.1.1.1")["action"] == "deny"
                assert fw.evaluate("127.0.0.1")["action"] == "deny"
                assert fw.status()["load_warning"]
        # Partial *valid* legacy policy retains the established default merge.
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "acl.json"), "w", encoding="utf-8") as stream:
                json.dump({"enabled": True, "policy": {"public": "allow"}}, stream)
            fw = FW.AppFirewall(state_dir=directory)
            assert fw.evaluate("1.1.1.1")["action"] == "allow"
            assert not fw.status()["load_warning"]


def test_admin_does_not_invent_success_for_missing_or_nonboolean_ok():
    with _Admin() as admin:
        for result in ({"error": "operation did not commit"}, {"ok": "false"}, {"ok": 1}):
            with patch.object(admin.sh, "set_paranoia", return_value=result):
                _, body = admin.post("/api/shield/paranoia", {"level": 2})
            assert body["ok"] is False, body
        assert admin.get("/api/admin_audit")["entries"] == []
        _, body = admin.post("/api/shield/paranoia", {"level": 2})
        assert body["ok"] is True and body["paranoia"] == 2


def test_admin_mutation_snapshot_and_audit_are_under_the_state_lock():
    with _Admin() as admin:
        observed = []
        workers = []
        original = admin.adm.record_audit

        def record(*args):
            completed = threading.Event()
            def update():
                assert admin.fw.set_policy("public", "deny")["ok"] is True
                completed.set()
            worker = threading.Thread(target=update)
            workers.append(worker)
            worker.start()
            observed.append(not completed.wait(0.1))
            original(*args)

        with patch.object(admin.adm, "record_audit", side_effect=record):
            _, body = admin.post("/api/firewall/policy", {"zone": "public", "action": "allow"})
        assert body["ok"] is True
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
        assert observed == [True]
        audit = admin.get("/api/admin_audit")["entries"][0]
        assert audit["before"] == "deny" and audit["after"] == "allow"


def test_admin_thread_start_failure_releases_its_bound_listener():
    dashboard = A.AdminDashboard(host="127.0.0.1", port=0)
    original = threading.Thread.start
    captured = []

    def fail(thread):
        if thread.name == "shield-admin":
            captured.append(dashboard.port)
            raise RuntimeError("thread creation failed")
        return original(thread)

    try:
        with patch.object(threading.Thread, "start", fail):
            try:
                dashboard.start()
            except RuntimeError:
                pass
            else:
                raise AssertionError("thread creation failure was reported as success")
        assert captured
        with socket.socket() as probe:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", captured[0])) != 0
        assert dashboard._server is None and dashboard._thread is None
        # The same instance can subsequently start and stop normally.
        assert dashboard.start()["ok"] is True
        assert dashboard.stop()["ok"] is True
    finally:
        # A failed old implementation has no serving thread; shutdown() would block.
        if dashboard._server is not None:
            if dashboard._thread is not None and dashboard._thread.is_alive():
                dashboard.stop()
            else:
                dashboard._server.server_close()


def test_admin_serving_thread_early_exit_cannot_report_ready_or_keep_listener():
    """A bound socket is not proof that the HTTP serving loop is alive."""
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix=".validation-admin-start-", dir=root) as state:
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        try:
            with patch.object(A.ThreadingHTTPServer, "serve_forever", return_value=None):
                result = dashboard.start()
                if dashboard._thread is not None:
                    dashboard._thread.join(timeout=1)
            assert result.get("ok") is False, result
            with socket.socket() as probe:
                probe.settimeout(0.2)
                assert probe.connect_ex(("127.0.0.1", dashboard.port)) != 0
            assert dashboard._server is None and dashboard._thread is None
        finally:
            # The old implementation reports success with a dead serving thread;
            # BaseServer.shutdown() would wait forever in this injected failure.
            if dashboard._server is not None:
                dashboard._server.server_close()


def test_admin_live_but_nonserving_thread_times_out_and_releases_listener():
    """A thread stalled before serve_forever cannot hold a false-ready port."""
    root = Path(__file__).resolve().parents[1]
    gate = threading.Event()
    workers = []

    def stall(_server):
        workers.append(threading.current_thread())
        gate.wait(5)

    with tempfile.TemporaryDirectory(prefix=".validation-admin-start-", dir=root) as state:
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        try:
            with patch.object(A.ThreadingHTTPServer, "serve_forever", stall):
                started = time.monotonic()
                result = dashboard.start()
                elapsed = time.monotonic() - started
            assert result.get("ok") is False, result
            assert elapsed < 6.5, elapsed
            with socket.socket() as probe:
                probe.settimeout(0.2)
                assert probe.connect_ex(("127.0.0.1", dashboard.port)) != 0
            assert dashboard._server is None and dashboard._thread is None
        finally:
            gate.set()
            for worker in workers:
                worker.join(timeout=2)
                assert not worker.is_alive()
            if dashboard._server is not None:
                dashboard._server.server_close()


def test_admin_start_waits_for_real_http_and_stop_releases_port():
    """The healthy path still serves a complete response after start returns."""
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix=".validation-admin-start-", dir=root) as state:
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        try:
            result = dashboard.start()
            assert result.get("ok") is True, result
            with urllib.request.urlopen(f"http://127.0.0.1:{dashboard.port}/", timeout=2) as response:
                assert response.status == 200 and response.read(16)
        finally:
            port = dashboard.port
            assert dashboard.stop().get("ok") is True
        with socket.socket() as probe:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", port)) != 0


def test_image_healthcheck_requires_live_edge_and_admin_http():
    """Run the shipped stdlib health command against both real listeners."""
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    health_line = next(line.strip() for line in dockerfile.splitlines()
                       if line.strip().startswith("CMD python -c "))
    argv = shlex.split(health_line[4:])
    assert argv[:2] == ["python", "-c"], argv
    with tempfile.TemporaryDirectory(prefix=".validation-docker-health-", dir=root) as state:
        with patch.object(ND, "_SHIELD", ND.NetShield(state_dir=state)), \
                patch.object(FW, "_FW", FW.AppFirewall(state_dir=state)):
            guard = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                                   backend_host="127.0.0.1", backend_port=9,
                                   health_path="/healthz")
            admin = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
            assert guard.start().get("ok") is True
            try:
                assert admin.start().get("ok") is True
                try:
                    script = argv[2].replace("8443", str(guard.listen_port)).replace(
                        "8081", str(admin.port))
                    def check():
                        return subprocess.run([sys.executable, "-c", script],
                                              capture_output=True, timeout=5)
                    assert check().returncode == 0, "healthy listeners failed image healthcheck"
                    guard.stop()
                    assert check().returncode != 0, "dead edge passed image healthcheck"
                finally:
                    admin.stop()
            finally:
                guard.stop()
    assert '"--health-path", "/healthz"' in dockerfile
    assert '"--health-path", "/healthz"' in compose


def test_acl_remove_and_admin_operation_reject_invalid_commands():
    with _Admin() as admin:
        assert admin.fw.add_rule("1.1.1.1/32", "deny")["ok"] is True
        for net in (None, False, [], "", "invalid", "x" * 65):
            assert admin.fw.remove_rule(net)["ok"] is False, net
        for body in ({"op": "remove"},
                     {"op": "rmove", "net": "1.1.1.1/32", "action": "allow"},
                     {"op": False, "net": "1.1.1.1/32", "action": "allow"}):
            _, result = admin.post("/api/firewall/rule", body)
            assert result["ok"] is False, (body, result)
        assert admin.fw.evaluate("1.1.1.1")["action"] == "deny"
        _, result = admin.post("/api/firewall/rule", {"op": "remove", "net": "1.1.1.1/32"})
        assert result["ok"] is True and result["removed"] == 1


def _assert_published_not_durable(result):
    assert result["ok"] is False, result
    assert result["applied_in_memory"] is True and result["published"] is True, result
    assert result["persisted"] is False and result["durable"] is False, result
    assert result["error"], result


def test_acl_all_commits_report_post_publication_sync_failure_without_rollback():
    for operation in ("enable", "disable", "policy", "global", "add", "remove", "approve", "deny"):
        with tempfile.TemporaryDirectory() as directory:
            fw = FW.AppFirewall(state_dir=directory)
            assert fw.enable()["ok"]
            if operation in ("enable", "global"):
                assert fw.disable()["ok"]
            if operation == "remove":
                assert fw.add_rule("1.1.1.1/32", "deny")["ok"]
            if operation in ("approve", "deny"):
                assert fw.set_policy("public", "prompt")["ok"]
                pid = fw.evaluate("1.1.1.1")["pending_id"]
            with patch.object(AIO, "_sync_directory", side_effect=[True, True, True, False]):
                if operation == "enable":
                    result = fw.enable()
                elif operation == "disable":
                    result = fw.disable()
                elif operation == "policy":
                    result = fw.set_policy("public", "allow")
                elif operation == "global":
                    result = fw.set_global_block(False)
                elif operation == "add":
                    result = fw.add_rule("1.1.1.1/32", "deny")
                elif operation == "remove":
                    result = fw.remove_rule("1.1.1.1/32")
                elif operation == "approve":
                    result = fw.approve(pid, remember=True)
                else:
                    result = fw.deny_pending(pid, remember=True)
            _assert_published_not_durable(result)
            restored = FW.AppFirewall(state_dir=directory)
            assert restored.is_enabled() == fw.is_enabled()
            assert restored.policy == fw.policy and restored.rules == fw.rules
            if operation == "enable":
                assert fw.is_enabled()
            elif operation == "disable":
                assert not fw.is_enabled()
            elif operation in ("policy", "global", "approve"):
                assert fw.evaluate("1.1.1.1")["action"] == "allow"
            elif operation in ("add", "deny"):
                assert fw.evaluate("1.1.1.1")["action"] == "deny"
            else:
                assert fw.rules == []
            if operation in ("approve", "deny"):
                assert fw.pending() == [] and result["resolved"] == pid
                assert result["remembered"] is False
                assert any("保存先同期失敗" in row["reason"] for row in fw.log())


def test_acl_old_durability_failure_is_not_attached_to_non_saving_operations():
    with tempfile.TemporaryDirectory() as directory:
        fw = FW.AppFirewall(state_dir=directory)
        assert fw.set_policy("public", "prompt")["ok"]
        pid = fw.evaluate("1.1.1.1")["pending_id"]
        with patch.object(AIO, "_sync_directory", side_effect=[True, True, True, False]):
            result = fw.add_rule("2.2.2.2/32", "deny")
        _assert_published_not_durable(result)
        result = fw.approve(pid, remember=False)
        assert result["ok"] is True and result["remembered"] is False
        assert "durable" not in result and "published" not in result


def test_admin_published_not_durable_update_is_failure_with_actual_state_and_audit():
    with _Admin() as admin:
        # Establish the one-time ACL history marker before faulting the four
        # syncs of a signed ACL commit (.hw pre/post, main pre/post).
        assert admin.fw.enable()["ok"]
        with patch.object(AIO, "_sync_directory", side_effect=[True, True, True, False]):
            _, result = admin.post("/api/firewall/toggle", {"on": False})
        _assert_published_not_durable(result)
        assert admin.get("/api/state")["firewall"]["enabled"] is False
        audit = admin.get("/api/admin_audit")["entries"][0]
        assert audit["before"] is True and audit["after"] is False
        assert audit["persisted"] is False and audit["durable"] is False
        assert admin.fw.enable()["ok"]
        assert admin.fw.set_policy("public", "prompt")["ok"]
        pid = admin.fw.evaluate("1.1.1.1")["pending_id"]
        with patch.object(AIO, "_sync_directory", side_effect=[True, True, True, False]):
            _, result = admin.post("/api/firewall/resolve",
                                   {"id": pid, "approve": True, "remember": True})
        _assert_published_not_durable(result)
        assert result["resolved"] == pid and result["remembered"] is False
        assert admin.fw.evaluate("1.1.1.1")["action"] == "allow"
        audit = admin.get("/api/admin_audit")["entries"][0]
        assert "保存未確認" in audit["summary"]
        assert audit["persisted"] is False and audit["after"]["remember"] is False


def test_acl_stale_writer_cannot_replace_a_newer_deny_snapshot():
    for operation in ("enable", "disable", "policy", "global", "add", "remove", "approve", "deny"):
        with tempfile.TemporaryDirectory() as directory:
            seed = FW.AppFirewall(state_dir=directory)
            assert seed.set_policy("public", "prompt")["ok"]
            assert seed.add_rule("1.1.1.1/32", "deny")["ok"]
            first = FW.AppFirewall(state_dir=directory)
            stale = FW.AppFirewall(state_dir=directory)
            if operation in ("approve", "deny"):
                pid = stale.evaluate("2.2.2.2")["pending_id"]
            before = copy.deepcopy((stale.enabled, stale.policy, stale.rules))
            assert first.add_rule("3.3.3.3/32", "deny")["ok"]
            with open(first.path, "rb") as handle:
                latest = handle.read()
            with open(first.path + ".hw", "rb") as handle:
                latest_hw = handle.read()
            if operation == "enable":
                result = stale.enable()
            elif operation == "disable":
                result = stale.disable()
            elif operation == "policy":
                result = stale.set_policy("public", "allow")
            elif operation == "global":
                result = stale.set_global_block(False)
            elif operation == "add":
                result = stale.add_rule("4.4.4.4/32", "allow")
            elif operation == "remove":
                result = stale.remove_rule("1.1.1.1/32")
            elif operation == "approve":
                result = stale.approve(pid, remember=True)
            else:
                result = stale.deny_pending(pid, remember=True)
            assert result["ok"] is False and result["conflict"] is True, (operation, result)
            assert "更新" in result["error"]
            assert (stale.enabled, stale.policy, stale.rules) == before
            with open(first.path, "rb") as handle:
                assert handle.read() == latest
            with open(first.path + ".hw", "rb") as handle:
                assert handle.read() == latest_hw
            if operation in ("approve", "deny"):
                assert [row["id"] for row in stale.pending()] == [pid]
            refreshed = FW.AppFirewall(state_dir=directory)
            assert refreshed.evaluate("3.3.3.3")["action"] == "deny"
            assert refreshed.set_policy("private", "deny")["ok"] is True
            assert FW.AppFirewall(state_dir=directory).evaluate("3.3.3.3")["action"] == "deny"


def test_acl_missing_state_baseline_and_nondurable_publication_advance_cas():
    with tempfile.TemporaryDirectory() as directory:
        first = FW.AppFirewall(state_dir=directory)
        stale = FW.AppFirewall(state_dir=directory)
        assert first.add_rule("1.1.1.1/32", "deny")["ok"]
        result = stale.set_policy("public", "allow")
        assert result["ok"] is False and result["conflict"] is True
        assert FW.AppFirewall(state_dir=directory).evaluate("1.1.1.1")["action"] == "deny"
        with patch.object(AIO, "_sync_directory", side_effect=[True, True, True, False]):
            _assert_published_not_durable(first.add_rule("2.2.2.2/32", "deny"))
        assert first.set_policy("private", "deny")["ok"] is True
        restored = FW.AppFirewall(state_dir=directory)
        assert restored.evaluate("1.1.1.1")["action"] == "deny"
        assert restored.evaluate("2.2.2.2")["action"] == "deny"


def test_admin_stale_acl_write_is_rejected_without_false_success_audit():
    with _Admin() as admin:
        other = FW.AppFirewall(state_dir=admin.tmp.name)
        assert other.add_rule("3.3.3.3/32", "deny")["ok"]
        _, result = admin.post("/api/global_block", {"on": False})
        assert result["ok"] is False and result["conflict"] is True
        assert admin.get("/api/admin_audit")["entries"] == []
        latest = FW.AppFirewall(state_dir=admin.tmp.name)
        assert latest.evaluate("3.3.3.3")["action"] == "deny"
        assert any(rule["net"] == "3.3.3.3/32" for rule in latest.rules)
