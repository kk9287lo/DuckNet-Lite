"""Signed Shield damage must remain visible while the Shield is deliberately off."""

import os
from pathlib import Path
import tempfile

import dataplane.engine.lifeform.pipeline as pipeline
from dataplane.engine.lifeform.policy import AppFirewall
from test_security_admin_integrity_status_round15 import (
    _read_authenticated, _shown, _state_from_real_http)


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-admin-off-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_disabled_shield_does_not_paint_corrupt_signed_sources_healthy():
    with _state() as root:
        for kind in ("signatures", "bans", "traffic"):
            with tempfile.TemporaryDirectory(dir=root) as state:
                shield = pipeline.NetShield(state_dir=state)
                assert shield.set_config(enabled=False)["ok"]
                firewall = AppFirewall(state_dir=state)
                if kind == "signatures":
                    assert shield.add_signature("r16-disabled-integrity", "r16marker",
                                                weight=100)["ok"]
                    target = shield._sig_path
                    endpoint = "/api/shield/signatures"
                else:
                    if kind == "bans":
                        assert shield.ban("192.0.2.8", permanent=True)["ok"]
                        target = shield._bans_path
                        endpoint = "/api/shield/bans"
                    else:
                        assert shield.set_config(quota_enabled=True,
                                                 quota_max_gb=1e-6)["ok"]
                        assert shield.flush_state()["ok"]
                        target = shield._traffic_path
                        endpoint = None
                Path(target).write_bytes(b"{}")
                restarted = pipeline.NetShield(state_dir=state)
                assert restarted.cfg["enabled"] is False
                assert (restarted._sig_state_untrusted if kind == "signatures"
                        else restarted._ban_state_untrusted if kind == "bans"
                        else restarted._traffic_state_untrusted)
                html, api = _state_from_real_http(state, restarted, firewall)
                if endpoint:
                    individual = _read_authenticated(state, restarted, firewall,
                                                      [endpoint])[endpoint]
                    assert individual[0] == 503, (kind, individual)
                # Old runtime returned healthy Shield status and green GUI
                # while this same signed source was untrusted and its API 503.
                assert api["shield"] == {"error": "source unavailable"}, (kind, api)
                shown = _shown(html, {kind: api}, state)[kind]
                assert shown["connection"] == "pill bad", shown


def test_healthy_intentionally_disabled_shield_remains_visible():
    with _state() as state:
        shield = pipeline.NetShield(state_dir=state)
        assert shield.set_config(enabled=False)["ok"]
        firewall = AppFirewall(state_dir=state)
        html, api = _state_from_real_http(state, shield, firewall)
        assert api["shield"]["cfg"]["enabled"] is False
        shown = _shown(html, {"healthy_off": api}, state)["healthy_off"]
        assert shown["connection"] == "pill ok"
        assert shown["shield"] is False
