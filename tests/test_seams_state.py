"""Inert persisted-state and configuration seams; no operational user state."""
import copy
import json
import tempfile
from pathlib import Path
from unittest import mock

from dataplane.engine.core.signed_state import write_signed_json
from dataplane.engine.lifeform import pipeline as P
from dataplane.engine.lifeform.policy import AppFirewall


def _put(shield, kind, value):
    path = Path(getattr(shield, "_" + kind + "_path"))
    assert write_signed_json(str(path), {kind: value}, shield._state_key)
    return path, path.read_bytes()


def _assert_discarded(kind, value):
    with tempfile.TemporaryDirectory() as directory:
        seed = P.NetShield(state_dir=directory)
        path, raw = _put(seed, kind, value)
        restored = P.NetShield(state_dir=directory)
        assert getattr(restored, "_" + kind) == {}, (kind, value)
        assert path.read_bytes() == raw, "invalid state was migrated or overwritten at load"
        notices = [row for row in restored.events() if row.get("what") == kind]
        # A malformed signed root is rejected before its high-water is
        # advanced; a valid root with malformed inner rows reaches the
        # per-record validator instead.
        expected = "invalid" if isinstance(value, dict) else "tampered"
        assert notices and notices[-1].get("status") == expected, notices
        assert "BOUNDARY" not in json.dumps(notices), notices
        assert restored.quota_status("192.0.2.73")["out_gb"] == 0
        assert restored.usage_list()["rows"] == []


def test_signed_accounting_rejects_invalid_inner_containers_without_crashing():
    for kind in ("traffic", "usage"):
        for value in (None, [], ["BOUNDARY"], "BOUNDARY", False, 3):
            _assert_discarded(kind, value)


def test_signed_traffic_rejects_entire_malformed_bucket_mapping():
    day = str(P.NetShield._day())
    bad_rows = (["BOUNDARY"], None, {"BOUNDARY": [1, 0, 0]},
                {"-1": [1, 0, 0]}, {"1.0": [1, 0, 0]},
                {"9" * 100: [1, 0, 0]}, {day: []}, {day: [1, 0]},
                {day: [1, 0, 0, 0]}, {day: [True, 0, 0]},
                {day: ["BOUNDARY", 0, 0]}, {day: [-1, 0, 0]},
                {day: [float("nan"), 0, 0]}, {day: [float("inf"), 0, 0]},
                {day: [1 << 4096, 0, 0]},
                {day: [1e308, 0, 0], str(int(day) + 1): [1e308, 0, 0]})
    for row in bad_rows:
        _assert_discarded("traffic", {"192.0.2.70": {day: [4, 2, 1]},
                                      "192.0.2.73": row})
    _assert_discarded("traffic", {"BOUNDARY": {day: [1, 0, 0]}})


def _usage_row():
    return {"out": 8, "in": 4, "conns": 2, "sec": 1.5, "last": 0,
            "hosts": {"app.example": {"out": 8, "in": 4, "conns": 2}}}


def test_signed_usage_rejects_entire_malformed_record_and_nested_hosts():
    bad_rows = (["BOUNDARY"], None, {}, {**_usage_row(), "hosts": []},
                {**_usage_row(), "hosts": {"BOUNDARY": []}},
                {**_usage_row(), "hosts": {"BOUNDARY": {"out": 1, "in": 0}}})
    for row in bad_rows:
        _assert_discarded("usage", {"192.0.2.70": _usage_row(), "192.0.2.73": row})
    for key in ("out", "in", "conns", "sec", "last"):
        for value in (None, True, "BOUNDARY", -1, float("nan"), float("inf"), 1 << 4096):
            _assert_discarded("usage", {"192.0.2.73": {**_usage_row(), key: value}})
    _assert_discarded("usage", {"192.0.2.73": {**_usage_row(), "conns": 1.5}})
    for key in ("out", "in", "conns"):
        _assert_discarded("usage", {"192.0.2.73": {**_usage_row(), "hosts": {
            "app.example": {"out": 8, "in": 4, "conns": 2, key: float("nan")}}}})
    _assert_discarded("usage", {"BOUNDARY": _usage_row()})


def test_accounting_load_enforces_existing_ip_and_host_count_bounds():
    with mock.patch.object(P, "_MAX_IPS", 2):
        for kind in ("traffic", "usage"):
            value = {"192.0.2." + str(n): ({str(P.NetShield._day()): [1, 0, 0]}
                                          if kind == "traffic" else _usage_row())
                     for n in range(3)}
            _assert_discarded(kind, value)
    row = _usage_row()
    row["hosts"] = {str(n) + ".example": {"out": 1, "in": 0, "conns": 1}
                    for n in range(P._USAGE_HOSTS_CAP + 1)}
    _assert_discarded("usage", {"192.0.2.73": row})


def test_valid_signed_and_unsigned_legacy_accounting_roundtrips():
    for legacy in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            seed = P.NetShield(state_dir=directory)
            day = str(seed._day())
            values = {"traffic": {"192.0.2.73": {"0": [0, 1, 0], day: [8, 4, 1.5]}},
                      "usage": {"192.0.2.73": _usage_row()}}
            if legacy:
                Path(seed._state_marker).unlink()
            for kind, value in values.items():
                path = Path(getattr(seed, "_" + kind + "_path"))
                if legacy:
                    path.write_text(json.dumps({kind: value}), encoding="utf-8")
                else:
                    _put(seed, kind, value)
            restored = P.NetShield(state_dir=directory)
            assert restored._traffic == values["traffic"]
            assert restored._usage == values["usage"]
            assert restored.usage_list()["rows"][0]["conns"] == 2
            assert restored.quota_status("192.0.2.73")["conn_sec"] == 1.5
            assert restored.set_config(quota_enabled=True)["ok"]
            assert restored.record_traffic("192.0.2.73", out_bytes=4, host="app.example")["counted"]
            restored.flush_state()
            again = P.NetShield(state_dir=directory)
            assert again._traffic["192.0.2.73"][day][0] == 12
            assert again._usage["192.0.2.73"]["out"] == 12
            assert again._usage["192.0.2.73"]["conns"] == 3


def test_invalid_unsigned_accounting_is_not_silently_migrated():
    for kind in ("traffic", "usage"):
        with tempfile.TemporaryDirectory() as directory:
            seed = P.NetShield(state_dir=directory)
            Path(seed._state_marker).unlink()
            path = Path(getattr(seed, "_" + kind + "_path"))
            raw = json.dumps({kind: ["BOUNDARY"]}).encode()
            path.write_bytes(raw)
            restored = P.NetShield(state_dir=directory)
            assert getattr(restored, "_" + kind) == {}
            assert path.read_bytes() == raw


def test_cumulative_counters_larger_than_single_event_bound_remain_readable():
    with tempfile.TemporaryDirectory() as directory:
        seed = P.NetShield(state_dir=directory)
        assert seed.set_config(quota_enabled=True)["ok"]
        for _ in range(2):
            assert seed.record_traffic("192.0.2.73", out_bytes=1 << 63)["counted"]
        seed.flush_state()
        restored = P.NetShield(state_dir=directory)
        assert restored._traffic["192.0.2.73"][str(restored._day())][0] == float(1 << 64)
        assert restored._usage["192.0.2.73"]["out"] == float(1 << 64)
        assert restored.usage_list()["rows"][0]["conns"] == 2


def test_invalid_signed_quota_history_stays_untrusted_while_usage_telemetry_recovers():
    with tempfile.TemporaryDirectory() as directory:
        seed = P.NetShield(state_dir=directory)
        raw = {}
        for kind in ("traffic", "usage"):
            path, saved = _put(seed, kind, ["BOUNDARY"])
            raw[kind] = (path, saved)
        restored = P.NetShield(state_dir=directory)
        assert restored._traffic_state_untrusted is True
        assert restored.set_config(quota_enabled=True, quota_max_gb=1e-8)["ok"]
        assert restored.record_traffic("192.0.2.73", out_bytes=4)["counted"]
        result = restored.flush_state()
        assert result["ok"] is False and result["persisted"] is False
        assert result["traffic_saved"] is False and "traffic" in result["untrusted_state"]
        assert raw["traffic"][0].read_bytes() == raw["traffic"][1]
        again = P.NetShield(state_dir=directory)
        assert again._traffic_state_untrusted is True and again._traffic == {}
        assert again.usage_list()["rows"][0]["conns"] == 1


def test_explicit_null_acl_sections_fail_closed_and_preserve_raw_state():
    for legacy in (False, True):
        for key in ("policy", "rules"):
            with tempfile.TemporaryDirectory() as directory:
                seed = AppFirewall(state_dir=directory)
                payload = {"enabled": False, "policy": {}, "rules": [], key: None}
                if legacy:
                    Path(seed.path).write_text(json.dumps(payload), encoding="utf-8")
                else:
                    assert write_signed_json(seed.path, payload, seed._state_key)
                raw = Path(seed.path).read_bytes()
                restored = AppFirewall(state_dir=directory)
                assert restored.enabled is True
                assert restored.evaluate("192.0.2.75")["action"] == "deny"
                assert restored._load_warning
                assert Path(seed.path).read_bytes() == raw


def test_valid_acl_missing_legacy_sections_and_explicit_off_remain_compatible():
    for payload in ({"enabled": False}, {"enabled": False, "policy": {}, "rules": []}):
        with tempfile.TemporaryDirectory() as directory:
            seed = AppFirewall(state_dir=directory)
            assert write_signed_json(seed.path, payload, seed._state_key)
            restored = AppFirewall(state_dir=directory)
            assert restored.enabled is False
            assert restored.evaluate("192.0.2.75")["action"] == "allow"
            assert not restored._load_warning


def test_method_original_non_ascii_input_cannot_become_ascii_by_case_mapping():
    for route in ("generic", "declarative", "dedicated"):
        with tempfile.TemporaryDirectory() as directory:
            shield = P.NetShield(state_dir=directory)
            assert shield.set_config(blocked_methods=["CONNECT"])["ok"]
            before = copy.deepcopy(shield.cfg), Path(shield.path).read_bytes()
            for value in (["TRACE", "\u017f"], ["TRACE", "\ufb06"], "TRACE,\u017f"):
                result = (shield.set_config(blocked_methods=value) if route == "generic" else
                          shield.apply_config({"blocked_methods": value}) if route == "declarative"
                          else shield.set_blocked_methods(value))
                assert result["ok"] is False, (route, value, result)
                assert (shield.cfg, Path(shield.path).read_bytes()) == before
            assert shield.set_blocked_methods(["trace", "TRACE", "connect"])["ok"]
            assert shield.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
