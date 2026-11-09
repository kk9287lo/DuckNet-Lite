"""An untrusted signed defense state must not paint a healthy dashboard."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest
from unittest.mock import patch

import dataplane.admin as A
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from test_security_admin_gui_status_round13 import _get, _GUI_PROBE
from test_security_health_signed_state_round14 import _wire


def _seed(state, kind):
    shield = ND.NetShield(state_dir=state)
    firewall = FW.AppFirewall(state_dir=state)
    assert shield.set_config(enabled=True, block_page=False)["ok"]
    if kind == "config":
        target = shield.path
    elif kind == "signatures":
        assert shield.add_signature("admin-integrity", "private-health-probe", weight=200)["ok"]
        target = shield._sig_path
    elif kind == "bans":
        assert shield.ban("127.0.0.1", permanent=True)["ok"]
        target = shield._bans_path
    elif kind == "traffic":
        assert shield.set_config(quota_enabled=True, quota_max_gb=1e-6)["ok"]
        assert shield.flush_state()["ok"]
        target = shield._traffic_path
    elif kind == "acl":
        assert firewall.enable()["ok"]
        target = firewall.path
    else:
        raise AssertionError(kind)
    Path(target).write_bytes(b"{}")
    return ND.NetShield(state_dir=state), FW.AppFirewall(state_dir=state)


def _state_from_real_http(state, shield, firewall):
    with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
        admin = A.AdminDashboard(host="127.0.0.1", port=0,
                                 token="integrity-status-probe", state_dir=state)
        try:
            assert admin.start()["ok"]
            html_status, html = _get(admin.port, "/")
            api_status, raw = _get(admin.port, "/api/state", admin.token)
            assert html_status == api_status == 200
            return html, json.loads(raw)
        finally:
            admin.stop()


def _shown(html, states, state):
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for dashboard execution")
    html_path = Path(state, "dashboard.html")
    states_path = Path(state, "states.json")
    html_path.write_bytes(html)
    states_path.write_text(json.dumps(states), encoding="utf-8")
    result = subprocess.run([node, "-e", _GUI_PROBE, str(html_path), str(states_path)],
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return json.loads(result.stdout)


def _read_authenticated(state, shield, firewall, paths):
    with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
        admin = A.AdminDashboard(host="127.0.0.1", port=0,
                                 token="integrity-list-probe", state_dir=state)
        try:
            assert admin.start()["ok"]
            return {path: _get(admin.port, path, admin.token) for path in paths}
        finally:
            admin.stop()


def test_signed_untrusted_sources_make_admin_connection_unavailable():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as root:
        states, html = {}, None
        for kind in ("config", "signatures", "bans", "traffic", "acl"):
            with tempfile.TemporaryDirectory(dir=root) as state:
                shield, firewall = _seed(state, kind)
                assert (kind == "acl" and firewall.status()["load_warning"]
                        or kind != "acl" and any((shield._cfg_state_untrusted,
                                                   shield._sig_state_untrusted,
                                                   shield._ban_state_untrusted,
                                                   shield._traffic_state_untrusted)))
                served, states[kind] = _state_from_real_http(state, shield, firewall)
                source = "firewall" if kind == "acl" else "shield"
                assert states[kind][source] == {"error": "source unavailable"}, kind
                html = html or served
                health, normal, upstream, _metrics = _wire(shield, firewall)
                assert health.startswith(b"HTTP/1.1 503 Service Unavailable"), kind
                assert not normal.startswith(b"HTTP/1.1 200 OK"), kind
                assert upstream == [], kind
        shown = _shown(html, states, root)
        for kind in states:
            assert shown[kind]["threw"] is False, (kind, shown[kind])
            assert shown[kind]["connection"] == "pill bad", (kind, shown[kind])
            assert shown[kind]["label"] == "状態取得不可", (kind, shown[kind])


def test_verified_and_intentionally_disabled_sources_keep_connected_display():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as root:
        states, html = {}, None
        for name, enabled in (("healthy", True), ("intentional_off", False)):
            with tempfile.TemporaryDirectory(dir=root) as state:
                shield = ND.NetShield(state_dir=state)
                firewall = FW.AppFirewall(state_dir=state)
                assert shield.set_config(enabled=enabled)["ok"]
                assert (firewall.enable() if enabled else firewall.disable())["ok"]
                served, states[name] = _state_from_real_http(state, shield, firewall)
                html = html or served
        shown = _shown(html, states, root)
        for name, enabled in (("healthy", True), ("intentional_off", False)):
            assert shown[name]["threw"] is False, (name, shown[name])
            assert shown[name]["connection"] == "pill ok", (name, shown[name])
            assert shown[name]["firewall"] is enabled, (name, shown[name])
            assert shown[name]["shield"] is enabled, (name, shown[name])


def test_audit_mode_keeps_backend_wire_but_never_paints_untrusted_quota_healthy():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as state:
        shield = ND.NetShield(state_dir=state)
        assert shield.set_config(enabled=True, mode="audit", quota_enabled=True,
                                 quota_max_gb=1e-6, block_page=False)["ok"]
        assert shield.flush_state()["ok"]
        Path(shield._traffic_path).write_bytes(b"{}")
        restarted = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert restarted._traffic_state_untrusted
        html, api_state = _state_from_real_http(state, restarted, firewall)
        assert api_state["shield"] == {"error": "source unavailable"}
        shown = _shown(html, {"audit": api_state}, state)["audit"]
        assert shown["threw"] is False
        assert shown["connection"] == "pill bad"
        health, normal, upstream, _metrics = _wire(restarted, firewall)
        assert health.startswith(b"HTTP/1.1 503 Service Unavailable"), health
        assert normal.startswith(b"HTTP/1.1 200 OK"), normal
        assert len(upstream) == 1
        assert any(e.get("kind") == "audit" and e.get("would") == "block"
                   and e.get("rule") == "policy_block"
                   for e in restarted.events(30)), restarted.events(30)


def _assert_signed_policy_list(kind, endpoint, key):
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as root:
        with tempfile.TemporaryDirectory(dir=root) as state:
            shield = ND.NetShield(state_dir=state)
            firewall = FW.AppFirewall(state_dir=state)
            assert shield.set_config(enabled=True, block_page=False)["ok"]
            if kind == "bans":
                assert shield.ban("127.0.0.1", permanent=True)["ok"]
                target = shield._bans_path
            else:
                assert shield.add_signature("admin-list-probe", "private-list-probe",
                                            weight=200)["ok"]
                target = shield._sig_path
            good = _read_authenticated(state, shield, firewall, [endpoint])[endpoint]
            assert good[0] == 200 and len(json.loads(good[1])[key]) == 1, kind

            Path(target).write_bytes(b"{}")
            restarted = ND.NetShield(state_dir=state)
            assert (restarted._ban_state_untrusted if kind == "bans"
                    else restarted._sig_state_untrusted)
            bad = _read_authenticated(state, restarted, firewall,
                                      [endpoint, "/api/shield/tamper"])
            assert bad[endpoint][0] == 503, (kind, bad[endpoint])
            assert json.loads(bad[endpoint][1]) == {
                "ok": False, "error": "state unavailable"}, (kind, bad[endpoint])
            assert bad["/api/shield/tamper"][0] == 200
            assert json.loads(bad["/api/shield/tamper"][1])["summary"]["count"] >= 1
            _health, normal, upstream, _metrics = _wire(restarted, firewall)
            assert not normal.startswith(b"HTTP/1.1 200 OK") and upstream == []


def test_signed_ban_list_does_not_report_false_empty():
    _assert_signed_policy_list("bans", "/api/shield/bans", "bans")


def test_signed_signature_list_does_not_report_false_empty():
    _assert_signed_policy_list("signatures", "/api/shield/signatures", "custom")


def test_healthy_empty_policy_lists_remain_available():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as state:
        healthy = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        empty = _read_authenticated(state, healthy, firewall,
                                    ["/api/shield/bans", "/api/shield/signatures"])
        assert empty["/api/shield/bans"][0] == 200
        assert json.loads(empty["/api/shield/bans"][1])["bans"] == []
        assert empty["/api/shield/signatures"][0] == 200
        assert json.loads(empty["/api/shield/signatures"][1])["custom"] == []
