"""Cross-field config rejection must precede a cluster downgrade."""

import copy
import http.client
import json
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_admin_ui import _Admin


class _ForkGuard:
    _workers = [123]

    def __init__(self):
        self.quiesced = 0

    def quiesce_cluster_for_mutation(self):
        self.quiesced += 1
        return {"ok": True, "cluster_downgraded": True}


def test_cross_field_invalid_patch_never_quiesces_or_changes_signed_state():
    with _Admin() as admin:
        guard = _ForkGuard()
        admin.adm.edge_guard = guard
        before = copy.deepcopy(admin.sh.cfg)
        state_path = Path(admin.sh.path)
        saved = state_path.read_bytes() if state_path.exists() else None
        audit = admin.get("/api/admin_audit")["entries"]
        for body in (
            {"site_mode": "whitelist"},
            {"site_mode": "whitelist", "site_whitelist": []},
            {"cadence_min_mean_interval": 4.0,
             "cadence_max_mean_interval": 3.0},
        ):
            status, result = admin.post("/api/shield/config", body)
            assert status == 400 and result["ok"] is False, (body, status, result)
            assert guard.quiesced == 0, (body, guard.quiesced)
            assert admin.sh.cfg == before
            assert (state_path.read_bytes() if state_path.exists() else None) == saved
            assert admin.get("/api/admin_audit")["entries"] == audit


def test_valid_cross_field_patch_still_commits_after_quiesce():
    with _Admin() as admin:
        guard = _ForkGuard()
        admin.adm.edge_guard = guard
        for body in (
            {"site_mode": "whitelist", "site_whitelist": ["app.example"]},
            {"cadence_min_mean_interval": 0.1,
             "cadence_max_mean_interval": 0.5},
        ):
            status, result = admin.post("/api/shield/config", body)
            assert status == 200 and result["ok"] is True, (body, status, result)
        assert guard.quiesced == 2
        reloaded = NetShield(state_dir=admin.tmp.name)
        for key in ("site_mode", "site_whitelist", "cadence_min_mean_interval",
                    "cadence_max_mean_interval"):
            assert reloaded.cfg[key] == admin.sh.cfg[key]
        assert reloaded.cfg["site_mode"] == "whitelist"
        assert reloaded.cfg["site_whitelist"] == ["app.example"]


def test_config_that_becomes_invalid_before_mutation_gate_never_quiesces():
    with _Admin() as admin:
        guard = _ForkGuard()
        admin.adm.edge_guard = guard
        before_audit = admin.get("/api/admin_audit")["entries"]
        original_preview = admin.sh.preview_config_patch
        previews = []

        def between_preflight_and_gate(body):
            result = original_preview(body)
            previews.append(result)
            if len(previews) == 1:
                # Another legitimate writer publishes an incompatible policy
                # after the first preview but before this POST enters the gate.
                changed = admin.sh.set_config(site_mode="whitelist",
                                              site_whitelist=["app.example"])
                assert changed["ok"] is True, changed
            return result

        with patch.object(admin.sh, "preview_config_patch",
                          side_effect=between_preflight_and_gate):
            status, rejected = admin.post("/api/shield/config", {"site_whitelist": []})
        assert status == 400 and rejected["ok"] is False, (status, rejected)
        assert len(previews) == 2, previews
        assert guard.quiesced == 0
        assert admin.sh.cfg["site_mode"] == "whitelist"
        assert admin.sh.cfg["site_whitelist"] == ["app.example"]
        reloaded = NetShield(state_dir=admin.tmp.name)
        assert reloaded.cfg["site_mode"] == "whitelist"
        assert reloaded.cfg["site_whitelist"] == ["app.example"]
        assert admin.get("/api/admin_audit")["entries"] == before_audit


def test_real_posix_fork_keeps_workers_and_backend_wire_after_bad_patch():
    from dataplane.admin import AdminDashboard
    from test_security_cluster_direct_setter_round15 import _cluster, _received, _request

    with _cluster() as (shield, _firewall, edge, report_fd):
        workers = list(edge._workers)
        assert workers
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               state_dir=str(Path(shield.path).parent), edge_guard=edge)
        started = admin.start()
        assert started.get("ok") is True, started
        try:
            body = json.dumps({"site_mode": "whitelist"}).encode("utf-8")
            conn = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
            try:
                conn.request("POST", "/api/shield/config", body=body,
                             headers={"X-Token": admin.token,
                                      "Content-Type": "application/json"})
                reply = conn.getresponse()
                status, result = reply.status, json.loads(reply.read())
            finally:
                conn.close()
            assert status == 400 and result["ok"] is False, (status, result)
            assert edge._workers == workers and edge.is_alive()
            wire = _request(edge.listen_port, b"/after-r19-rejected")
            assert wire.startswith(b"HTTP/1.1 200"), wire
            assert b"GET /after-r19-rejected" in _received(report_fd)
        finally:
            admin.stop()
