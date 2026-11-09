"""A fork cluster must label parent-only dashboard counters as incomplete."""

import json
import os
from types import SimpleNamespace
import tempfile
from unittest.mock import patch

import dataplane.admin as admin_module
import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from test_security_admin_gui_status_round13 import _get
from test_security_admin_integrity_status_round15 import _shown


def test_live_child_metrics_are_explicitly_parent_only_on_real_admin_wire_and_gui():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-telemetry-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=False)["ok"]
        assert firewall.disable()["ok"]
        edge = SimpleNamespace(_workers=[12345], metrics={"accepted": 7})
        with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall):
            admin = admin_module.AdminDashboard(host="127.0.0.1", port=0,
                token="cluster-telemetry-probe", state_dir=state, edge_guard=edge)
            try:
                assert admin.start()["ok"]
                html_status, html = _get(admin.port, "/")
                assert html_status == 200
                cluster_status, cluster_bytes = _get(admin.port, "/api/state", admin.token)
                assert cluster_status == 200
                cluster = json.loads(cluster_bytes)
                assert cluster["edge_metrics"]["accepted"] == 7
                assert cluster["telemetry_complete"] is False, cluster
                assert cluster["telemetry_scope"] == "per-worker", cluster
                for route in ("/api/metrics", "/api/shield/events", "/api/shield/top",
                              "/api/series", "/api/analysis", "/api/shield/bans"):
                    status, raw = _get(admin.port, route, admin.token)
                    assert status == 503, (route, status, raw)
                    assert json.loads(raw)["telemetry_scope"] == "per-worker"

                edge._workers = []
                single_status, single_bytes = _get(admin.port, "/api/state", admin.token)
                assert single_status == 200
                single = json.loads(single_bytes)
                assert single["telemetry_complete"] is True, single
                assert single["telemetry_scope"] == "single", single
                for route in ("/api/metrics", "/api/shield/events", "/api/shield/top",
                              "/api/series", "/api/analysis", "/api/shield/bans"):
                    status, raw = _get(admin.port, route, admin.token)
                    assert status == 200, (route, status, raw)

                contradictory = dict(single, telemetry_complete=False)
                shown = _shown(html, {"cluster": cluster, "single": single,
                                      "contradictory": contradictory}, state)
                assert shown["cluster"]["threw"] is False, shown
                assert shown["cluster"]["connection"] == "pill warn", shown
                assert "親ワーカーのみ" in shown["cluster"]["label"], shown
                assert shown["single"]["threw"] is False, shown
                assert shown["single"]["connection"] == "pill ok", shown
                assert shown["contradictory"]["connection"] == "pill bad", shown
            finally:
                admin.stop()
