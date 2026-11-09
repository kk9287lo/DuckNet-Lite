"""A declarative file is the exact startup authority, not a recoverable state file."""

from pathlib import Path
import tempfile

from dataplane.engine.core.atomic_io import safe_read_json
from dataplane.engine.lifeform.pipeline import NetShield


def _enabled_shield(directory):
    shield = NetShield(state_dir=directory)
    assert shield.enable()["ok"] is True
    return shield


def test_duplicate_config_members_cannot_disable_a_saved_shield():
    with tempfile.TemporaryDirectory() as directory:
        shield = _enabled_shield(directory)
        config = Path(directory, "declarative.json")
        config.write_text('{"enabled": true, "enabled": false}', encoding="utf-8")
        result = shield.apply_config_file(str(config))
        assert result["ok"] is False and result["applied"] == [], result
        assert shield.cfg["enabled"] is True
        assert NetShield(state_dir=directory).cfg["enabled"] is True


def test_missing_declarative_file_never_applies_stale_tmp_copy():
    for primary in (None, "{broken"):
        with tempfile.TemporaryDirectory() as directory:
            shield = _enabled_shield(directory)
            config = Path(directory, "declarative.json")
            if primary is not None:
                config.write_text(primary, encoding="utf-8")
            Path(str(config) + ".tmp").write_text('{"enabled": false}', encoding="utf-8")
            result = shield.apply_config_file(str(config))
            assert result["ok"] is False and result["applied"] == [], (primary, result)
            assert shield.cfg["enabled"] is True
            assert NetShield(state_dir=directory).cfg["enabled"] is True


def test_nonfinite_json_cannot_hide_in_an_ignored_compatibility_key():
    with tempfile.TemporaryDirectory() as directory:
        shield = _enabled_shield(directory)
        config = Path(directory, "declarative.json")
        config.write_text('{"enabled": false, "legacy_only": NaN}', encoding="utf-8")
        result = shield.apply_config_file(str(config))
        assert result["ok"] is False and result["applied"] == [], result
        assert shield.cfg["enabled"] is True
        assert NetShield(state_dir=directory).cfg["enabled"] is True


def test_unique_declarative_file_applies_and_persists_atomically():
    with tempfile.TemporaryDirectory() as directory:
        shield = _enabled_shield(directory)
        config = Path(directory, "declarative.json")
        config.write_text('{"enabled": true, "blocked_methods": ["TRACE"]}', encoding="utf-8")
        result = shield.apply_config_file(str(config))
        assert result["ok"] is True and result["applied"] == ["blocked_methods", "enabled"], result
        assert shield.cfg["blocked_methods"] == ["TRACE"]
        assert NetShield(state_dir=directory).cfg["blocked_methods"] == ["TRACE"]


def test_legacy_state_reader_still_recovers_its_tmp_file():
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory, "state.json")
        Path(str(state) + ".tmp").write_text('{"safe": true}', encoding="utf-8")
        assert safe_read_json(str(state)) == {"safe": True}
