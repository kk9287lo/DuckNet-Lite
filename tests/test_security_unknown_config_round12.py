"""Round 12: unknown config members cannot make a security patch half succeed."""

import copy
import json
import tempfile
from pathlib import Path

from dataplane.engine.lifeform.pipeline import NetShield


def _seed(shield):
    assert shield.set_config(enabled=True, ip_mode="blacklist",
                             ip_blacklist=["192.0.2.9"])["ok"]
    assert shield.inspect("192.0.2.9", path="/safe")["action"] == "block"


def _snapshot(shield):
    return copy.deepcopy(shield.cfg), Path(shield.path).read_bytes()


def _unchanged(shield, before):
    assert shield.cfg == before[0]
    assert Path(shield.path).read_bytes() == before[1]
    assert shield.inspect("192.0.2.9", path="/safe")["action"] == "block"


def test_unknown_only_direct_config_reports_rejection_without_a_write():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        _seed(shield)
        before = _snapshot(shield)
        result = shield.set_config(ip_blacklsit=["192.0.2.9"])
        assert result["ok"] is False and "ip_blacklsit" in result["rejected"], result
        _unchanged(shield, before)


def test_unknown_mixed_direct_config_preserves_previous_protection_atomically():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        _seed(shield)
        before = _snapshot(shield)
        result = shield.set_config(ip_mode="off", ip_blacklsit=["192.0.2.9"])
        decision = shield.inspect("192.0.2.9", path="/safe")
        assert decision["action"] == "block", (result, decision)
        assert result["ok"] is False and result["changed"] == {}, result
        assert "ip_blacklsit" in result["rejected"], result
        _unchanged(shield, before)


def test_unknown_mixed_declarative_config_preserves_signed_snapshot():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        _seed(shield)
        before = _snapshot(shield)
        result = shield.apply_config({"ip_mode": "off", "ip_blacklsit": ["192.0.2.9"]})
        assert result["ok"] is False and result["applied"] == [], result
        assert "ip_blacklsit" in result["rejected"], result
        _unchanged(shield, before)


def test_unknown_config_file_is_rejected_before_disabling_blacklist():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        _seed(shield)
        before = _snapshot(shield)
        file = Path(state) / "declarative.json"
        file.write_text(json.dumps({"ip_mode": "off", "ip_blacklsit": ["192.0.2.9"]}),
                        encoding="utf-8")
        result = shield.apply_config_file(str(file))
        assert result["ok"] is False and result["applied"] == [], result
        assert "ip_blacklsit" in result["rejected"], result
        _unchanged(shield, before)


def test_known_only_direct_and_declarative_config_still_commit():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        _seed(shield)
        assert shield.set_config(rate_per_sec=23)["ok"] is True
        result = shield.apply_config({"ip_mode": "off"})
        assert result["ok"] is True and result["applied"] == ["ip_mode"]
        assert shield.inspect("192.0.2.9", path="/safe")["action"] == "allow"
        restored = NetShield(state_dir=state)
        assert restored.cfg["ip_mode"] == "off" and restored.cfg["rate_per_sec"] == 23
