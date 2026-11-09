"""Round 12: corrupt signed rules/config must not remove live protection."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_RULE_PATH = b"/r12privatemarker"
_CFG_PATH = b"/r12vault"


def _request(path):
    return b"GET " + path + b" HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _send(shield, state, path):
    backend = _Backend()
    try:
        with patch.object(ND, "_SHIELD", shield), \
                patch.object(FW, "_FW", AppFirewall(state_dir=state)), \
                _guard(backend) as edge:
            client = _exchange(edge, [_request(path)])
        return backend.got, client
    finally:
        backend.close()


def _seed_rule(state, *, mode="enforce"):
    shield = NetShield(state_dir=state)
    assert shield.set_config(enabled=True, mode=mode, block_page=False)["ok"]
    assert shield.add_signature("r12-private-rule", "r12privatemarker", weight=200)["ok"]
    assert shield.list_signatures()["custom_active"] == 1
    assert shield.inspect("192.0.2.8", path=_RULE_PATH.decode())["action"] == (
        "allow" if mode == "audit" else "block")
    return shield


def _seed_cfg(state):
    shield = NetShield(state_dir=state)
    assert shield.set_config(enabled=True, block_page=False,
                             private_paths=[_CFG_PATH.decode()],
                             private_path_allow=[])["ok"]
    assert shield.inspect("192.0.2.8", path=_CFG_PATH.decode())["action"] == "block"
    return shield


def test_corrupt_signed_custom_rules_cannot_reopen_backend_wire():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_rule(state)
        Path(shield._sig_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted.tamper_report()["summary"]["count"] >= 1
        upstream, client = _send(restarted, state, _RULE_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)


def test_missing_signed_custom_rules_keep_denial_across_two_restarts():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_rule(state)
        rules = Path(shield._sig_path)
        assert Path(str(rules) + ".hw").is_file()
        rules.unlink()
        first = NetShield(state_dir=state)
        assert first.tamper_report()["summary"]["count"] >= 1
        second = NetShield(state_dir=state)
        upstream, client = _send(second, state, _RULE_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
        assert not rules.exists(), "missing signed rules must not be re-published empty"


def test_untrusted_custom_rules_in_audit_forward_and_record_intent():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_rule(state, mode="audit")
        Path(shield._sig_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state, _RULE_PATH)
        assert len(upstream) == 1 and upstream[0].startswith(_request(_RULE_PATH)[:-2])
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client
        assert any(e.get("kind") == "audit" and e.get("would") == "block"
                   and e.get("rule") == "policy_block"
                   for e in restarted.events(30)), restarted.events(30)


def test_corrupt_signed_config_cannot_reopen_private_route():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_cfg(state)
        Path(shield.path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted.tamper_report()["summary"]["count"] >= 1
        upstream, client = _send(restarted, state, _CFG_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)


def test_missing_signed_config_does_not_republish_defaults_across_restarts():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_cfg(state)
        path = Path(shield.path)
        assert Path(str(path) + ".hw").is_file()
        path.unlink()
        first = NetShield(state_dir=state)
        assert first.tamper_report()["summary"]["count"] >= 1
        second = NetShield(state_dir=state)
        upstream, client = _send(second, state, _CFG_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
        assert not path.exists(), "missing signed config must not be replaced by defaults"


def test_valid_signed_rule_and_private_config_still_block_but_first_boot_allows():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_rule(state)
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state, _RULE_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_cfg(state)
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state, _CFG_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
    with tempfile.TemporaryDirectory() as state:
        pristine = NetShield(state_dir=state)
        assert pristine.set_config(enabled=True, block_page=False)["ok"]
        upstream, client = _send(pristine, state, _RULE_PATH)
        assert len(upstream) == 1 and upstream[0].startswith(_request(_RULE_PATH)[:-2])
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client


def test_flush_reports_untrusted_config_or_rules_without_erasing_evidence():
    for seed, state_file, label in ((_seed_rule, "_sig_path", "signatures"),
                                    (_seed_cfg, "path", "config")):
        with tempfile.TemporaryDirectory() as state:
            shield = seed(state)
            path = Path(getattr(shield, state_file))
            path.write_bytes(b"{}")
            restarted = NetShield(state_dir=state)
            before = path.read_bytes()
            result = restarted.flush_state()
            assert result["ok"] is False and label in result["untrusted_state"], result
            assert path.read_bytes() == before


def test_untrusted_rules_refuse_new_signature_without_erasing_missing_evidence():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_rule(state)
        path = Path(shield._sig_path)
        path.unlink()
        restarted = NetShield(state_dir=state)
        result = restarted.add_signature("r12-another-rule", "r12anothermarker", weight=200)
        assert result.get("ok") is False and result.get("conflict") is True, result
        assert not path.exists(), "an ordinary edit must not re-sign an empty rule set"
        next_restart = NetShield(state_dir=state)
        upstream, client = _send(next_restart, state, _RULE_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)


def test_untrusted_config_refuses_edit_without_erasing_missing_evidence():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_cfg(state)
        path = Path(shield.path)
        path.unlink()
        restarted = NetShield(state_dir=state)
        result = restarted.set_config(rate_per_sec=17)
        assert result.get("ok") is False and result.get("conflict") is True, result
        assert not path.exists(), "an ordinary edit must not re-sign default configuration"
        next_restart = NetShield(state_dir=state)
        upstream, client = _send(next_restart, state, _CFG_PATH)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)


def test_restoring_valid_signed_snapshots_and_restarting_only_engine_recovers():
    for seed, path_attr, guarded_path in (
            (_seed_rule, "_sig_path", _RULE_PATH),
            (_seed_cfg, "path", _CFG_PATH)):
        with tempfile.TemporaryDirectory() as state:
            shield = seed(state)
            path = Path(getattr(shield, path_attr))
            valid_snapshot = path.read_bytes()
            path.write_bytes(b"{}")
            untrusted = NetShield(state_dir=state)
            blocked, client = _send(untrusted, state, guarded_path)
            assert blocked == [] and b"\r\n\r\nok" not in client
            # An operator restores an already signed snapshot; the next
            # application engine start can verify the same key and high-water.
            path.write_bytes(valid_snapshot)
            recovered = NetShield(state_dir=state)
            assert not recovered._cfg_state_untrusted and not recovered._sig_state_untrusted
            allowed, client = _send(recovered, state, b"/public-r12")
            assert len(allowed) == 1 and client.startswith(b"HTTP/1.1 200")
            blocked, client = _send(recovered, state, guarded_path)
            assert blocked == [] and b"\r\n\r\nok" not in client
