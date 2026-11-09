"""A rejected manual unban must leave the live and durable deny intact."""

import os
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard
from test_atomic_pipeline import _published_without_directory_sync


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-unban-atomic-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_failed_and_conflicted_unban_keep_backend_deny_then_durable_success_allows():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 persist_bans=True)["ok"]
        assert shield.ban("127.0.0.1", permanent=True)["ok"]
        firewall = AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall), \
                    _guard(backend) as edge:
                for status in ("failed", "conflict"):
                    with patch.object(shield, "_save_bans", return_value=status):
                        result = shield.unban("127.0.0.1")
                    wire = _exchange(edge, [b"GET /failed-unban-r16 HTTP/1.1\r\n"
                                            b"Host: local.test\r\n\r\n"])
                    assert result["ok"] is False, (status, result)
                    assert not wire.startswith(b"HTTP/1.1 200"), wire
                    assert b"GET /failed-unban-r16" not in backend.saw(), backend.got
                    assert shield.is_banned_fast("127.0.0.1")
                released = shield.unban("127.0.0.1")
                assert released["ok"] is True and released["persisted"] is True, released
                good = _exchange(edge, [b"GET /after-unban-r16 HTTP/1.1\r\n"
                                        b"Host: local.test\r\n\r\n"])
                assert good.startswith(b"HTTP/1.1 200"), good
                assert b"GET /after-unban-r16" in backend.saw(), backend.got
        finally:
            backend.close()
        assert not NetShield(state_dir=state).is_banned_fast("127.0.0.1")


def test_failed_unban_keeps_signed_ban_and_restriction_review():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, persist_bans=True)["ok"]
        assert shield.restrict("192.0.2.9")["ok"]
        before = shield.list_restrictions()
        with patch.object(shield, "_save_bans", return_value="failed"):
            result = shield.unban("192.0.2.9")
        assert result["ok"] is False, result
        assert shield.is_banned_fast("192.0.2.9")
        assert shield.list_restrictions() == before
        assert NetShield(state_dir=state).is_banned_fast("192.0.2.9")


def test_published_nondurable_unban_reports_uncertainty_without_false_durable_ack():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, persist_bans=True)["ok"]
        assert shield.ban("192.0.2.10", permanent=True)["ok"]
        with _published_without_directory_sync():
            result = shield.unban("192.0.2.10")
        assert result["ok"] is False and result["published"] is True, result
        assert result["applied_in_memory"] is True and result["durable"] is False, result
        assert result["persisted"] is False
        assert not shield.is_banned_fast("192.0.2.10")
        assert not NetShield(state_dir=state).is_banned_fast("192.0.2.10")


def test_unban_save_exception_restores_ban_before_later_flush_and_restart():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, persist_bans=True)["ok"]
        assert shield.restrict("192.0.2.11")["ok"]
        prior_review = shield.list_restrictions()
        with patch.object(shield, "_save_bans", side_effect=OSError("injected")):
            result = shield.unban("192.0.2.11")
        assert result["ok"] is False and result["persisted"] is False, result
        assert result.get("applied_in_memory") is not True, result
        assert shield.is_banned_fast("192.0.2.11")
        assert shield.list_restrictions() == prior_review
        assert shield.flush_state()["ok"] is True
        reopened = NetShield(state_dir=state)
        assert reopened.is_banned_fast("192.0.2.11")
        assert reopened.list_restrictions() == prior_review
