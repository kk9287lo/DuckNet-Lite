"""A rejected BAN-state write must never be reported as a successful edit."""

import copy
import tempfile
from pathlib import Path

from dataplane.engine.lifeform.pipeline import NetShield


def _untrusted(state):
    shield = NetShield(state_dir=state)
    assert shield.set_config(enabled=True)["ok"]
    assert shield.ban("192.0.2.1", permanent=True)["ok"]
    path = Path(shield._bans_path)
    path.write_bytes(b"{}")
    restarted = NetShield(state_dir=state)
    assert restarted._ban_state_untrusted
    return restarted, path


def test_ban_and_unban_do_not_claim_success_without_a_trusted_snapshot():
    with tempfile.TemporaryDirectory() as state:
        shield, path = _untrusted(state)
        before = path.read_bytes()
        added = shield.ban("192.0.2.2", permanent=True)
        assert added["ok"] is False and added["persisted"] is False, added
        assert added.get("applied_in_memory") is True and path.read_bytes() == before
        removed = shield.unban("192.0.2.2")
        assert removed["ok"] is False and removed["persisted"] is False, removed
        assert removed.get("applied_in_memory") is not True, removed
        assert shield.is_banned_fast("192.0.2.2") and path.read_bytes() == before
        flushed = shield.flush_state()
        assert flushed["ok"] is False and flushed["persisted"] is False, flushed
        assert "bans" in flushed["untrusted_state"] and path.read_bytes() == before


def test_restrict_rolls_back_when_untrusted_ban_file_cannot_be_saved():
    with tempfile.TemporaryDirectory() as state:
        shield, path = _untrusted(state)
        before = path.read_bytes()
        result = shield.restrict("192.0.2.3")
        assert result["ok"] is False and result.get("persisted") is not True, result
        assert shield.list_restrictions() == [] and path.read_bytes() == before


def test_review_release_keeps_ban_and_review_when_untrusted():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert shield.restrict("192.0.2.4")["ok"]
        assert shield.submit_report("192.0.2.4", "synthetic report")["ok"]
        before_review = copy.deepcopy(shield.list_restrictions())
        before_ban = shield.ban_info("192.0.2.4")
        path = Path(shield._bans_path)
        path.write_bytes(b"{}")
        shield._load_bans()  # same process still has the prior review in memory
        assert shield._ban_state_untrusted
        result = shield.admin_confirm("192.0.2.4", True)
        assert result["ok"] is False and result.get("released") is False, result
        assert shield.list_restrictions() == before_review
        assert shield.ban_info("192.0.2.4")["banned"] is before_ban["banned"]
        assert path.read_bytes() == b"{}"


def test_valid_signed_ban_edits_keep_their_success_result():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        saved = shield.ban("192.0.2.5", permanent=True)
        assert saved["ok"] is True and saved["persisted"] is True, saved
        removed = shield.unban("192.0.2.5")
        assert removed["ok"] is True and removed["persisted"] is True, removed
