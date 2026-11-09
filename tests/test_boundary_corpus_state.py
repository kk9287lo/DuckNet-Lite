"""Bounded, inert configuration corpus: no exploit bytes or command execution."""
import copy
import json
import tempfile
from pathlib import Path
from unittest import mock

from dataplane.engine.lifeform import pipeline as P
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.core.signed_state import write_signed_json
from test_sweep_proxy_request import _Backend, _guard, _exchange, _shield


def _snapshot(shield):
    path = Path(shield.path)
    return copy.deepcopy(shield.cfg), path.read_bytes() if path.exists() else None


def _submit(shield, name, key, value):
    if name == "generic":
        return shield.set_config(**{key: value, "enabled": False})
    if name == "declarative":
        return shield.apply_config({key: value, "enabled": False})
    return (shield.set_blocked_methods(value) if key == "blocked_methods"
            else shield.set_path_limits(value))


def test_explicit_null_known_values_reject_the_entire_config_patch():
    with tempfile.TemporaryDirectory() as directory:
        shield = P.NetShield(state_dir=directory)
        assert shield.set_config(enabled=True)["ok"]
        for key in ("enabled", "dlp_enabled", "blocked_methods", "max_total_conn",
                    "optional_sigs", "private_paths", "path_limits"):
            before = _snapshot(shield)
            result = shield.set_config(**{key: None, "rate_per_sec": 17})
            assert result["ok"] is False and result["changed"] == {} and key in result["rejected"], result
            assert _snapshot(shield) == before
        # A misspelled key must not report success or rewrite signed state.
        before = _snapshot(shield)
        unknown = shield.set_config(unknown_corpus_key=None)
        assert unknown["ok"] is False and "unknown_corpus_key" in unknown["rejected"]
        assert _snapshot(shield) == before
        assert shield.set_config(rate_per_sec=17)["ok"] is True


def test_method_replacements_reject_invalid_members_before_any_publication():
    bad_lists = (["TRACE", None], ["TRACE", False], ["TRACE", 7],
                 ["TRACE", "BAD-METHOD"], ["TRACE", ""],
                 ["A" * 16, "A" * 17], ["TRACE", "MÉTHOD"])
    for name in ("generic", "declarative", "dedicated"):
        with tempfile.TemporaryDirectory() as directory:
            shield = P.NetShield(state_dir=directory)
            assert shield.set_config(enabled=True, blocked_methods=["CONNECT"])["ok"]
            for value in bad_lists:
                before = _snapshot(shield)
                result = _submit(shield, name, "blocked_methods", value)
                assert result["ok"] is False, (name, value, result)
                assert _snapshot(shield) == before
            assert shield.set_blocked_methods(["trace", "TRACE", "connect"])["ok"]
            assert shield.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
            assert shield.set_blocked_methods([])["ok"] and shield.cfg["blocked_methods"] == []


def _verb(index):
    return "M" + "".join(chr(65 + value) for value in (index // 676, index // 26 % 26, index % 26))


def test_method_replacement_has_a_bounded_input_count_and_ascii_tokens():
    values = [_verb(i) for i in range(P._CFG_LIST_MAX_ITEMS + 1)]
    with tempfile.TemporaryDirectory() as directory:
        shield = P.NetShield(state_dir=directory)
        before = _snapshot(shield)
        for name in ("generic", "declarative", "dedicated"):
            for bad in (values, "A " * (P._CFG_LIST_TOTAL_MAX_BYTES // 2 + 1),
                        [" " * P._CFG_LIST_ITEM_MAX_BYTES + "TRACE"],
                        [" " * 128 + "TRACE"] * P._CFG_LIST_MAX_ITEMS):
                result = _submit(shield, name, "blocked_methods", bad)
                assert result["ok"] is False, name
                assert _snapshot(shield) == before
        assert shield.set_blocked_methods(values[:-1])["ok"]
        assert len(shield.cfg["blocked_methods"]) == P._CFG_LIST_MAX_ITEMS


def test_path_limits_reject_duplicate_effective_prefixes_and_oversized_items():
    duplicate = [{"path": "/BOUNDARY", "rate": 100, "burst": 100},
                 {"path": "/boundary", "rate": 1, "burst": 1}]
    too_long = [{"path": "/" + "a" * P._CFG_LIST_ITEM_MAX_BYTES, "rate": 1}]
    for name in ("generic", "declarative", "dedicated"):
        with tempfile.TemporaryDirectory() as directory:
            shield = P.NetShield(state_dir=directory)
            assert shield.set_path_limits([{"path": "/keep", "rate": 1}])["ok"]
            before = _snapshot(shield)
            for value in (duplicate, too_long):
                result = _submit(shield, name, "path_limits", value)
                assert result["ok"] is False, (name, result)
                assert _snapshot(shield) == before
            assert shield.set_path_limits([{"path": "/boundary", "rate": 1}])["ok"]


def test_invalid_method_patch_keeps_enforcement_and_audit_on_real_bytes():
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBOUNDARY_OK"
    # The marker is deliberately ordinary data. The backend never executes it.
    for mode in ("enforce", "audit"):
        backend = _Backend(response)
        try:
            with _shield(mode=mode, blocked_methods=["TRACE"]) as shield:
                before = _snapshot(shield)
                rejected = shield.set_config(blocked_methods=None, enabled=False)
                with _guard(backend) as guard:
                    request = b"TRACE /boundary HTTP/1.1\r\nHost: app.example\r\n\r\n"
                    result = _exchange(guard, [request])
                    if mode == "enforce":
                        assert backend.saw() == b"" and b"BOUNDARY_OK" not in result
                    else:
                        assert request.split(b"\r\n", 1)[0] in backend.saw() and result == response
                    good = b"GET /ordinary HTTP/1.1\r\nHost: app.example\r\n\r\n"
                    assert _exchange(guard, [good]) == response
                    assert good.split(b"\r\n", 1)[0] in backend.saw()
                assert rejected["ok"] is False and _snapshot(shield) == before
        finally:
            backend.close()


def test_equivalent_acl_network_update_has_one_effective_rule_after_restart():
    with tempfile.TemporaryDirectory() as directory:
        firewall = AppFirewall(state_dir=directory)
        assert firewall.add_rule("198.51.100.9/24", "deny")["ok"]
        assert firewall.evaluate("198.51.100.40")["action"] == "deny"
        assert firewall.add_rule("198.51.100.0/24", "allow")["ok"]
        assert len(firewall.rules) == 1 and firewall.evaluate("198.51.100.40")["action"] == "allow"
        restored = AppFirewall(state_dir=directory)
        assert restored.evaluate("198.51.100.40")["action"] == "allow"
        assert firewall.add_rule("198.51.100.255/24", "deny")["ok"]
        assert len(firewall.rules) == 1 and firewall.evaluate("198.51.100.40")["action"] == "deny"


def test_equivalent_acl_network_removal_does_not_report_zero_for_an_existing_rule():
    with tempfile.TemporaryDirectory() as directory:
        firewall = AppFirewall(state_dir=directory)
        assert firewall.add_rule("2001:db8:1::9/64", "deny")["ok"]
        result = firewall.remove_rule("2001:db8:1::/64")
        assert result["ok"] and result["removed"] == 1 and firewall.rules == [], result
        assert AppFirewall(state_dir=directory).rules == []


def test_rejected_scalar_matrix_and_save_failure_keep_previous_snapshots():
    invalid = (("dlp_enabled", [0, 1, "false", [], {}]),
               ("max_total_conn", [True, 1.5, float("nan"), float("inf"), -1, 1_000_001]),
               ("optional_sigs", [[], False, {"redirect": "false"}, {"unknown": True}]),
               ("private_paths", ["/one", [None], ["/one", "/ONE"], [""]]))
    with tempfile.TemporaryDirectory() as directory:
        shield = P.NetShield(state_dir=directory)
        before = _snapshot(shield)
        for key, values in invalid:
            for value in values:
                result = shield.set_config(**{key: value, "enabled": False})
                assert result["ok"] is False and _snapshot(shield) == before
        with mock.patch.object(shield, "_commit_cfg", return_value=False):
            result = shield.set_config(dlp_enabled=True)
        assert result["ok"] is False and _snapshot(shield) == before


def test_unsigned_nested_config_shape_cannot_crash_or_disable_startup():
    for value in (["BOUNDARY_SHAPE"], [], "BOUNDARY_SHAPE", False, 0, None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "state.json")
            raw = json.dumps({"cfg": value, "rev": 3}).encode()
            path.write_bytes(raw)
            shield = P.NetShield(state_dir=directory)
            assert shield.is_enabled() is True
            warning = [e for e in shield.events() if e["kind"] == "cfg_load_rejected"]
            assert warning and "cfg" in warning[-1]["keys"]
            assert "BOUNDARY_SHAPE" not in json.dumps(warning)
            assert path.read_bytes() == raw  # corrupt evidence is not silently migrated


def test_signed_nested_config_shape_cannot_crash_or_replace_corrupt_evidence():
    for value in (["BOUNDARY_SHAPE"], [], "BOUNDARY_SHAPE", False, 0, None):
        with tempfile.TemporaryDirectory() as directory:
            seed = P.NetShield(state_dir=directory)
            assert write_signed_json(seed.path, {"cfg": value, "rev": 3}, seed._state_key)
            raw = Path(seed.path).read_bytes()
            shield = P.NetShield(state_dir=directory)
            assert shield.is_enabled() is True
            # Signed roots with an invalid cfg shape are rejected before the
            # high-water write, rather than accepted for later cfg parsing.
            assert shield._cfg_state_untrusted
            assert any(e["kind"] == "state_tamper" and e.get("what") == "config"
                       and e.get("status") == "tampered" for e in shield.events())
            result = shield.set_config(rate_per_sec=17)
            assert result["ok"] is False and result.get("conflict") is True
            assert Path(seed.path).read_bytes() == raw


def test_invalid_nested_disk_config_keeps_last_verified_memory_generation():
    with tempfile.TemporaryDirectory() as directory:
        shield = P.NetShield(state_dir=directory)
        assert shield.set_config(enabled=False, rate_per_sec=23)["ok"]
        assert write_signed_json(shield.path, {"cfg": ["BOUNDARY_SHAPE"], "rev": 3}, shield._state_key)
        shield.cfg["enabled"] = True  # inert out-of-band memory mutation
        result = shield.verify_cfg_integrity()
        assert result["restored"] and result["source"] == "memory"
        assert shield.cfg["enabled"] is False and shield.cfg["rate_per_sec"] == 23


def test_valid_legacy_mapping_off_and_mixed_list_migration_stay_compatible():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, "state.json")
        path.write_text(json.dumps({"cfg": {"enabled": False}, "rev": 3}), encoding="utf-8")
        assert P.NetShield(state_dir=directory).is_enabled() is False
    with tempfile.TemporaryDirectory() as directory:
        seed = P.NetShield(state_dir=directory)
        old = {"enabled": True, "blocked_methods": ["TRACE", 7, "BAD-METHOD"],
               "path_limits": [{"path": "/keep", "rate": 1}, {"path": "/bad", "rate": None}]}
        assert write_signed_json(seed.path, {"cfg": old, "rev": 3}, seed._state_key)
        shield = P.NetShield(state_dir=directory)
        assert shield.cfg["blocked_methods"] == ["TRACE"]
        assert [r["path"] for r in shield.cfg["path_limits"]] == ["/keep"]
        assert shield.inspect("192.0.2.65", method="TRACE")["action"] == "block"
