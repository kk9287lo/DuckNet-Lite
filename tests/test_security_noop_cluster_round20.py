"""A verified no-op admin save must not needlessly reap live fork workers."""

import http.client
import json
import os
from unittest.mock import patch

from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_security_config_preflight_round19 import _ForkGuard
from test_sweep_admin_ui import _Admin


class _SyncedForkGuard(_ForkGuard):
    _cluster_policy_sync = True


def _audit_size(admin):
    return len(admin.get("/api/admin_audit")["entries"])


def test_noop_admin_saves_keep_cluster_and_still_verify_persistence():
    for route in ("config", "shield_toggle", "firewall_policy", "firewall_toggle"):
        with _Admin() as admin:
            if route in ("shield_toggle", "firewall_toggle"):
                result = (admin.sh.disable() if route == "shield_toggle"
                          else admin.fw.disable())
                assert result["ok"] is True, result
            before_cfg = dict(admin.sh.cfg)
            before_fw = {"enabled": admin.fw.enabled,
                         "policy": dict(admin.fw.policy)}
            audit_before = _audit_size(admin)
            guard = _SyncedForkGuard()
            admin.adm.edge_guard = guard
            if route == "config":
                path = "/api/shield/config"
                body = {"rate_per_sec": admin.sh.cfg["rate_per_sec"]}
            elif route == "shield_toggle":
                path, body = "/api/shield/toggle", {"on": False}
            elif route == "firewall_policy":
                path = "/api/firewall/policy"
                body = {"zone": "private", "action": admin.fw.policy["private"]}
            else:
                path, body = "/api/firewall/toggle", {"on": False}
            status, result = admin.post(path, body)
            assert status == 200 and result["ok"] is True, (route, status, result)
            assert guard.quiesced == 0, (route, guard.quiesced)
            assert result.get("cluster_downgraded") is not True
            assert admin.sh.cfg == before_cfg and admin.fw.enabled == before_fw["enabled"]
            assert admin.fw.policy == before_fw["policy"]
            assert _audit_size(admin) == audit_before + 1
            reloaded_sh = NetShield(state_dir=admin.tmp.name)
            reloaded_fw = AppFirewall(state_dir=admin.tmp.name)
            if route in ("config", "shield_toggle"):
                assert reloaded_sh.cfg["rate_per_sec"] == admin.sh.cfg["rate_per_sec"]
                assert reloaded_sh.is_enabled() == admin.sh.is_enabled()
            else:
                assert reloaded_fw.enabled == admin.fw.enabled
                assert reloaded_fw.policy == admin.fw.policy


def test_real_admin_changes_still_quiesce_before_signed_commit():
    for route in ("config", "shield_toggle", "firewall_policy", "firewall_toggle"):
        with _Admin() as admin:
            if route in ("shield_toggle", "firewall_toggle"):
                result = (admin.sh.disable() if route == "shield_toggle"
                          else admin.fw.disable())
                assert result["ok"] is True, result
            guard = _SyncedForkGuard()
            admin.adm.edge_guard = guard
            if route == "config":
                path = "/api/shield/config"
                body = {"rate_per_sec": admin.sh.cfg["rate_per_sec"] + 1.0}
            elif route == "shield_toggle":
                path, body = "/api/shield/toggle", {"on": True}
            elif route == "firewall_policy":
                path, body = "/api/firewall/policy", {"zone": "private", "action": "deny"}
            else:
                path, body = "/api/firewall/toggle", {"on": True}
            status, result = admin.post(path, body)
            assert status == 200 and result["ok"] is True, (route, status, result)
            assert guard.quiesced == 1 and result.get("cluster_downgraded") is True
            reloaded_sh = NetShield(state_dir=admin.tmp.name)
            reloaded_fw = AppFirewall(state_dir=admin.tmp.name)
            if route == "config":
                assert reloaded_sh.cfg["rate_per_sec"] == body["rate_per_sec"]
            elif route == "shield_toggle":
                assert reloaded_sh.is_enabled() is True
            elif route == "firewall_policy":
                assert reloaded_fw.policy["private"] == "deny"
            else:
                assert reloaded_fw.enabled is True


def test_external_signed_writer_between_noop_preview_and_setter_is_not_success():
    with _Admin() as admin:
        assert admin.sh.disable()["ok"] is True  # match a stateless live fork
        guard = _SyncedForkGuard()
        admin.adm.edge_guard = guard
        before_audit = _audit_size(admin)
        parent_rate = admin.sh.cfg["rate_per_sec"]
        outsider = NetShield(state_dir=admin.tmp.name)
        original = admin.sh.set_config

        def race(**kw):
            changed = outsider.set_config(enabled=True, site_mode="whitelist",
                                          site_whitelist=["safe.example"])
            assert changed["ok"] is True, changed
            return original(**kw)

        with patch.object(admin.sh, "set_config", side_effect=race):
            status, result = admin.post("/api/shield/config",
                                        {"rate_per_sec": parent_rate})
        assert status == 200 and result["ok"] is False, (status, result)
        assert guard.quiesced == 0
        assert _audit_size(admin) == before_audit
        assert admin.sh.cfg["rate_per_sec"] == parent_rate
        assert admin.sh.is_enabled() is False
        reloaded = NetShield(state_dir=admin.tmp.name)
        assert reloaded.is_enabled() is True
        assert reloaded.cfg["site_mode"] == "whitelist"
        assert reloaded.cfg["site_whitelist"] == ["safe.example"]


def test_real_posix_fork_noop_admin_post_keeps_workers_and_backend_wire():
    from dataplane.admin import AdminDashboard
    from test_security_cluster_direct_setter_round15 import _cluster, _received, _request

    with _cluster() as (shield, _firewall, edge, report_fd):
        workers = list(edge._workers)
        assert workers and edge._cluster_policy_sync is True
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               state_dir=os.path.dirname(shield.path), edge_guard=edge)
        started = admin.start()
        assert started.get("ok") is True, started

        def post(value):
            body = json.dumps({"rate_per_sec": value}).encode("utf-8")
            connection = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
            try:
                connection.request("POST", "/api/shield/config", body=body,
                                   headers={"X-Token": admin.token,
                                            "Content-Type": "application/json"})
                reply = connection.getresponse()
                return reply.status, json.loads(reply.read())
            finally:
                connection.close()

        try:
            current = shield.cfg["rate_per_sec"]
            status, result = post(current)
            assert status == 200 and result["ok"] is True, (status, result)
            assert result.get("cluster_downgraded") is not True
            assert edge._workers == workers and edge.is_alive()
            good = _request(edge.listen_port, b"/noop-r20")
            assert good.startswith(b"HTTP/1.1 200"), good
            assert b"GET /noop-r20" in _received(report_fd)
            assert NetShield(state_dir=os.path.dirname(shield.path)).cfg["rate_per_sec"] == current

            status, changed = post(current + 1.0)
            assert status == 200 and changed["ok"] is True, (status, changed)
            assert changed.get("cluster_downgraded") is True
            assert edge._workers == [] and edge.is_alive()
            good = _request(edge.listen_port, b"/changed-r20")
            assert good.startswith(b"HTTP/1.1 200"), good
            assert b"GET /changed-r20" in _received(report_fd)
        finally:
            admin.stop()
