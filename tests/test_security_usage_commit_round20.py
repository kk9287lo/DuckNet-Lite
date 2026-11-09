"""A stale telemetry owner must not erase newer signed usage accounting."""

import json
import tempfile
from pathlib import Path

from dataplane.engine.lifeform.pipeline import NetShield


_STATE_BASE = Path(__file__).resolve().parents[1] / ".validation-security-round20-20261108"
_STATE_BASE.mkdir(exist_ok=True)
_IP = "192.0.2.79"


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="usage-cas-", dir=_STATE_BASE)


def _out(shield):
    return shield._usage[_IP]["out"]


def _record(shield, amount):
    shield.record_traffic(_IP, out_bytes=amount, host="example.test",
                          method="GET", path="/safe")


def test_external_signed_usage_cannot_be_overwritten_or_cleared_by_stale_owner():
    with _state_dir() as directory:
        first = NetShield(state_dir=directory)
        assert first.set_config(usage_record=True, persist_bans=True)["ok"]
        _record(first, 59)
        assert _out(NetShield(state_dir=directory)) == 59

        external = NetShield(state_dir=directory)
        _record(external, 941)
        assert _out(NetShield(state_dir=directory)) == 1000

        _record(first, 1)
        saved = first._save_usage(force=True)
        # Old code acknowledged the stale save and durably rolled 1000 back
        # to 60. Check the actual signed file through a fresh loader first.
        assert _out(NetShield(state_dir=directory)) == 1000
        assert saved is False
        assert first._last_usage_write.get("conflict") is True
        assert first._usage_dirty is True
        flush = first.flush_state()
        assert flush["ok"] is False and flush["usage_conflict"] is True
        assert flush["usage_dirty"] is True
        assert _out(NetShield(state_dir=directory)) == 1000

        before_memory = _out(first)
        clear = first.usage_clear()
        assert clear["ok"] is False and clear["cleared"] is False
        assert clear["conflict"] is True
        assert _out(first) == before_memory
        assert _out(NetShield(state_dir=directory)) == 1000


def test_own_usage_save_clear_and_unsigned_legacy_migration_remain_valid():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        assert shield.set_config(usage_record=True)["ok"]
        _record(shield, 59)
        assert shield._save_usage(force=True) is True
        assert _out(NetShield(state_dir=directory)) == 59
        assert shield.usage_clear()["ok"] is True
        assert NetShield(state_dir=directory)._usage == {}

    with _state_dir() as directory:
        legacy = {"usage": {_IP: {"out": 4, "in": 0, "conns": 1,
                                  "sec": 0, "hosts": {}, "last": 0}}}
        Path(directory, "usage.json").write_text(json.dumps(legacy), encoding="utf-8")
        migrated = NetShield(state_dir=directory)
        assert _out(migrated) == 4
        assert Path(directory, "usage.json.hw").is_file()
        assert migrated._save_usage(force=True) is True
        assert _out(NetShield(state_dir=directory)) == 4


def test_unreadable_usage_state_is_not_signed_over_by_telemetry():
    with _state_dir() as directory:
        path = Path(directory, "usage.json")
        path.write_bytes(b"not-json")
        shield = NetShield(state_dir=directory)
        assert shield._state_fingerprints[shield._usage_path] is None
        assert shield.set_config(usage_record=True)["ok"]
        _record(shield, 1)
        assert shield._last_usage_write.get("conflict") is True
        assert shield._usage_dirty is True
        assert path.read_bytes() == b"not-json"


def test_verified_malformed_usage_recovers_only_at_its_original_cas_generation():
    with _state_dir() as directory:
        seed = NetShield(state_dir=directory)
        assert seed.set_config(usage_record=True)["ok"]
        malformed = {"usage": ["BOUNDARY"], "saved": 1}
        assert seed._write_state(seed._usage_path, malformed)["ok"] is True
        repaired = NetShield(state_dir=directory)
        assert repaired._usage == {}
        _record(repaired, 4)
        assert _out(NetShield(state_dir=directory)) == 4

    with _state_dir() as directory:
        seed = NetShield(state_dir=directory)
        assert seed.set_config(usage_record=True)["ok"]
        malformed = {"usage": ["BOUNDARY"], "saved": 1}
        assert seed._write_state(seed._usage_path, malformed)["ok"] is True
        stale = NetShield(state_dir=directory)
        external = NetShield(state_dir=directory)
        _record(external, 1000)
        assert _out(NetShield(state_dir=directory)) == 1000
        _record(stale, 1)
        assert stale._last_usage_write.get("conflict") is True
        assert _out(NetShield(state_dir=directory)) == 1000


def test_usage_recovery_rejects_bad_signature_rollback_and_wrong_purpose():
    for attack in ("bad_signature", "rollback", "wrong_purpose"):
        with _state_dir() as directory:
            seed = NetShield(state_dir=directory)
            assert seed.set_config(usage_record=True)["ok"]
            usage = Path(seed._usage_path)
            if attack == "wrong_purpose":
                assert seed._write_state(seed._traffic_path,
                                         {"traffic": {}, "saved": 1})["ok"]
                usage.write_bytes(Path(seed._traffic_path).read_bytes())
            else:
                malformed = {"usage": ["BOUNDARY"], "saved": 1}
                assert seed._write_state(seed._usage_path, malformed)["ok"]
                original = usage.read_bytes()
                if attack == "bad_signature":
                    envelope = json.loads(original)
                    envelope["_payload"]["saved"] = 2
                    usage.write_text(json.dumps(envelope), encoding="utf-8")
                else:
                    assert seed._write_state(seed._usage_path,
                                             {"usage": ["BOUNDARY"], "saved": 2})["ok"]
                    usage.write_bytes(original)
            before = usage.read_bytes()
            restored = NetShield(state_dir=directory)
            assert restored._state_fingerprints[restored._usage_path] is None, attack
            _record(restored, 1)
            assert restored._last_usage_write.get("conflict") is True, attack
            assert usage.read_bytes() == before, attack
