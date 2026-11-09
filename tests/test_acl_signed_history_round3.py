"""ACL signing history must distinguish migration from a stripped sidecar."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.policy as policy_module
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall


def test_signed_acl_cannot_be_reintroduced_as_unsigned_allow_after_sidecar_removal():
    with tempfile.TemporaryDirectory() as state:
        NetShield(state_dir=state)  # Existing global marker proves only shield history.
        original = AppFirewall(state_dir=state)
        assert original.set_policy("public", "deny")["ok"]
        assert original.add_rule("8.8.8.8/32", "deny")["ok"]
        assert Path(original.path + ".hw").is_file()
        os.unlink(original.path + ".hw")
        Path(original.path).write_text(json.dumps({
            "enabled": False,
            "policy": {"public": "allow"},
            "rules": [{"net": "8.8.8.8/32", "action": "allow", "note": "legacy"}],
        }), encoding="utf-8")
        restarted = AppFirewall(state_dir=state)
        assert restarted.is_enabled() is True
        assert restarted.evaluate("8.8.8.8")["action"] == "deny"
        assert restarted.status()["load_warning"]
        again = AppFirewall(state_dir=state)
        assert again.evaluate("8.8.8.8")["action"] == "deny"


def test_genuine_unsigned_acl_migrates_even_if_shield_marker_already_exists():
    with tempfile.TemporaryDirectory() as state:
        NetShield(state_dir=state)
        acl = Path(state) / "acl.json"
        acl.write_text(json.dumps({"enabled": False,
                                   "policy": {"public": "allow"},
                                   "rules": []}), encoding="utf-8")
        migrated = AppFirewall(state_dir=state)
        assert migrated.is_enabled() is False
        assert migrated.evaluate("8.8.8.8")["action"] == "allow"
        assert (Path(state) / "acl.json.hw").is_file()
        assert AppFirewall(state_dir=state).evaluate("8.8.8.8")["action"] == "allow"


def test_history_marker_failure_never_claims_acl_disable_success():
    with tempfile.TemporaryDirectory() as state:
        firewall = AppFirewall(state_dir=state)
        with patch.object(policy_module, "atomic_write_text", return_value=False,
                          create=True):
            result = firewall.disable()
        assert result["ok"] is False, result
        assert firewall.is_enabled() is True
        assert not Path(firewall.path).exists()
        assert firewall.disable()["ok"] is True
        assert (Path(state) / ".acl_signed").is_file()
        assert AppFirewall(state_dir=state).is_enabled() is False


def test_signed_acl_without_history_marker_fails_closed_if_repair_fails():
    with tempfile.TemporaryDirectory() as state:
        original = AppFirewall(state_dir=state)
        assert original.disable()["ok"] is True
        marker = Path(state) / ".acl_signed"
        if marker.exists():
            os.unlink(marker)  # Models an older signed deployment before this marker.
        with patch.object(policy_module, "atomic_write_text", return_value=False,
                          create=True):
            restarted = AppFirewall(state_dir=state)
        assert restarted.is_enabled() is True
        assert restarted.evaluate("8.8.8.8")["action"] == "deny"
        assert restarted.status()["load_warning"]
