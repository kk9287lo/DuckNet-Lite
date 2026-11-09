"""Round 12: an existing invalid high-water file is tampering, not first boot."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall


_ACL_CHILD = (
    "import json,sys\n"
    "from dataplane.engine.lifeform.policy import AppFirewall\n"
    "f=AppFirewall(state_dir=sys.argv[1])\n"
    "print(json.dumps({'action':f.evaluate('127.0.0.1')['action'],"
    "'warning':bool(f._load_warning)}),flush=True)\n"
)
_SHIELD_CHILD = (
    "import json,sys\n"
    "from dataplane.engine.lifeform.pipeline import NetShield\n"
    "s=NetShield(state_dir=sys.argv[1])\n"
    "print(json.dumps({'enabled':s.is_enabled(),"
    "'action':s.inspect('192.0.2.9',path='/.env')['action'],"
    "'tamper':s.tamper_report()['summary']['count']}),flush=True)\n"
)


def _fresh(code, state):
    env = os.environ.copy()
    env["DUCKNET_STATE_DIR"] = state
    child = subprocess.run([sys.executable, "-c", code, state], cwd=str(Path(__file__).parent.parent),
                           env=env, capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, (child.stdout, child.stderr)
    return json.loads(child.stdout.strip())


def test_corrupt_retained_highwater_cannot_accept_older_signed_acl_allow():
    with tempfile.TemporaryDirectory() as state:
        firewall = AppFirewall(state_dir=state)
        assert firewall.set_policy("loopback", "allow")["ok"]
        path = Path(firewall.path)
        old_allow = path.read_bytes()
        assert firewall.set_policy("loopback", "deny")["ok"]
        assert firewall.evaluate("127.0.0.1")["action"] == "deny"
        Path(str(path) + ".hw").write_bytes(b"{}")
        path.write_bytes(old_allow)
        result = _fresh(_ACL_CHILD, state)
        assert result == {"action": "deny", "warning": True}, result
        assert Path(str(path) + ".hw").read_bytes() == b"{}"


def test_corrupt_highwater_cannot_recover_stale_tmp_and_accept_old_acl():
    with tempfile.TemporaryDirectory() as state:
        firewall = AppFirewall(state_dir=state)
        assert firewall.set_policy("loopback", "allow")["ok"]
        path = Path(firewall.path)
        old_allow = path.read_bytes()
        highwater = Path(str(path) + ".hw")
        old_highwater = highwater.read_bytes()
        assert firewall.set_policy("loopback", "deny")["ok"]
        assert firewall.evaluate("127.0.0.1")["action"] == "deny"
        highwater.write_bytes(b"{}")
        Path(str(highwater) + ".tmp").write_bytes(old_highwater)
        path.write_bytes(old_allow)
        result = _fresh(_ACL_CHILD, state)
        assert result == {"action": "deny", "warning": True}, result
        assert highwater.read_bytes() == b"{}"


def test_corrupt_retained_highwater_cannot_restore_old_signed_shield_off():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=False)["ok"]
        path = Path(shield.path)
        old_off = path.read_bytes()
        assert shield.set_config(enabled=True)["ok"]
        assert shield.inspect("192.0.2.9", path="/.env")["action"] == "block"
        Path(str(path) + ".hw").write_bytes(b"{}")
        path.write_bytes(old_off)
        result = _fresh(_SHIELD_CHILD, state)
        assert result["enabled"] is True and result["action"] == "block", result
        assert result["tamper"] >= 1, result
        assert Path(str(path) + ".hw").read_bytes() == b"{}"


def test_missing_acl_with_invalid_highwater_stays_closed_without_marker():
    with tempfile.TemporaryDirectory() as state:
        firewall = AppFirewall(state_dir=state)
        assert firewall.add_rule("127.0.0.1/32", "deny")["ok"]
        path = Path(firewall.path)
        path.unlink()
        Path(firewall._history_path).unlink()
        Path(str(path) + ".hw").write_bytes(b"{}")
        result = _fresh(_ACL_CHILD, state)
        assert result == {"action": "deny", "warning": True}, result


def test_missing_shield_with_invalid_highwater_reports_tamper():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        path = Path(shield.path)
        path.unlink()
        Path(state, ".state_signed").unlink()
        Path(str(path) + ".hw").write_bytes(b"{}")
        result = _fresh(_SHIELD_CHILD, state)
        assert result["enabled"] is True and result["action"] == "block", result
        assert result["tamper"] >= 1, result


def test_valid_highwater_still_rejects_old_signed_acl():
    with tempfile.TemporaryDirectory() as state:
        firewall = AppFirewall(state_dir=state)
        assert firewall.set_policy("loopback", "allow")["ok"]
        path = Path(firewall.path)
        old_allow = path.read_bytes()
        assert firewall.set_policy("loopback", "deny")["ok"]
        path.write_bytes(old_allow)
        result = _fresh(_ACL_CHILD, state)
        assert result == {"action": "deny", "warning": True}, result


def test_pristine_first_boot_and_unsigned_legacy_acl_remain_usable():
    with tempfile.TemporaryDirectory() as state:
        result = _fresh(_ACL_CHILD, state)
        assert result == {"action": "allow", "warning": False}, result
    with tempfile.TemporaryDirectory() as state:
        legacy = {"enabled": True,
                  "policy": {"loopback": "allow", "private": "prompt",
                             "public": "deny", "special": "deny", "unknown": "prompt"},
                  "rules": []}
        Path(state, "acl.json").write_text(json.dumps(legacy), encoding="utf-8")
        result = _fresh(_ACL_CHILD, state)
        assert result == {"action": "allow", "warning": False}, result
        assert Path(state, "acl.json.hw").is_file()
