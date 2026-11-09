"""Quota history must survive capacity pressure and BAN expiry."""

import time
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as P
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_GET = b"GET /safe HTTP/1.1\r\nHost: local.test\r\n\r\n"
_BACKEND_GET = (b"GET /safe HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n"
                b"X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\n\r\n")
_VICTIM = "127.0.0.1"


def _fill(sh):
    for i in range(2, 11):
        sh.record_traffic(f"192.0.2.{i}", out_bytes=1)
    assert len(sh._traffic) == 10


def test_expired_ban_does_not_grant_another_response_over_daily_quota():
    with patch.object(P, "_MAX_IPS", 10), _shield(
            quota_enabled=True, quota_max_gb=1e-8, ban_ttl_sec=1,
            persist_bans=False, usage_record=False) as sh:
        assert sh.record_traffic(_VICTIM, out_bytes=11).get("exceeded")
        time.sleep(1.1)
        backend = _Backend()
        try:
            with _guard(backend) as guard:
                response = _exchange(guard, [_GET])
                assert not response.startswith(b"HTTP/1.1 200"), response
                assert backend.saw() == b"" and guard.metrics["proxied"] == 0
        finally:
            backend.close()


def test_new_ip_at_capacity_cannot_erase_victim_quota_or_reach_backend():
    with patch.object(P, "_MAX_IPS", 10), _shield(
            quota_enabled=True, quota_max_gb=1e-8, ban_ttl_sec=1,
            persist_bans=False, usage_record=True) as sh:
        assert sh.record_traffic(_VICTIM, out_bytes=11).get("exceeded")
        _fill(sh)
        fresh = "192.0.2.11"
        with patch.object(sh, "_save_bans") as save_bans:
            assert sh.inspect(fresh, path="/safe", method="GET")["action"] == "block"
            blocked_before_accounting = sh._metrics.get("block", 0)
            result = sh.record_traffic(fresh, out_bytes=1, _defer_log=True)
            save_bans.assert_not_called()  # overflow must not become a disk-write flood
            assert sh._metrics.get("block", 0) == blocked_before_accounting
        assert result["counted"] is False and result.get("error") == "quota capacity exhausted"
        assert "_usage_log_work" in result
        assert _VICTIM in sh._traffic and fresh not in sh._traffic
        assert len(sh._traffic) == 10
        time.sleep(1.1)
        backend = _Backend()
        try:
            with _guard(backend) as guard:
                response = _exchange(guard, [_GET])
                assert not response.startswith(b"HTTP/1.1 200"), response
                assert backend.saw() == b"" and guard.metrics["proxied"] == 0
        finally:
            backend.close()


def test_audit_capacity_records_uncounted_ip_and_keeps_existing_wire():
    with patch.object(P, "_MAX_IPS", 10), _shield(
            quota_enabled=True, quota_max_gb=1e-8, mode="audit",
            persist_bans=False, usage_record=False) as sh:
        assert sh.record_traffic(_VICTIM, out_bytes=11).get("exceeded")
        _fill(sh)
        fresh = "192.0.2.11"
        assert sh.inspect(fresh, path="/safe", method="GET")["action"] == "allow"
        result = sh.record_traffic(fresh, out_bytes=1)
        assert result["counted"] is False and result.get("error") == "quota capacity exhausted"
        assert _VICTIM in sh._traffic and len(sh._traffic) == 10
        backend = _Backend()
        try:
            with _guard(backend) as guard:
                response = _exchange(guard, [_GET])
                assert response.startswith(b"HTTP/1.1 200") and response.endswith(b"ok")
                assert backend.saw() == _BACKEND_GET and guard.metrics["proxied"] == 1
        finally:
            backend.close()
        assert any(e.get("kind") == "audit" and e.get("rule") == "quota_capacity"
                   for e in sh.events(100))


def test_expired_quota_rows_are_reclaimed_for_new_ip():
    with patch.object(P, "_MAX_IPS", 10), _shield(
            quota_enabled=True, quota_max_gb=1e-8,
            persist_bans=False, usage_record=False) as sh:
        yesterday = str(sh._day() - 1)
        sh._traffic = {f"192.0.2.{i}": {yesterday: [1.0, 0.0, 0.0]}
                       for i in range(1, 11)}
        fresh = "192.0.2.11"
        assert sh.inspect(fresh, path="/safe", method="GET")["action"] == "allow"
        assert sh.record_traffic(fresh, out_bytes=1)["counted"] is True
        assert len(sh._traffic) <= 10 and fresh in sh._traffic


def test_saturated_quota_survives_signed_reload_and_operator_unban():
    with tempfile.TemporaryDirectory() as state_dir, patch.object(P, "_MAX_IPS", 10):
        sh = P.NetShield(state_dir=state_dir)
        assert sh.set_config(enabled=True, quota_enabled=True,
                             quota_max_gb=1e-8, usage_record=False)["ok"]
        assert sh.record_traffic(_VICTIM, out_bytes=11).get("exceeded")
        _fill(sh)
        fresh = "192.0.2.11"
        assert sh.inspect(fresh, path="/safe", method="GET")["action"] == "block"
        assert sh.record_traffic(fresh, out_bytes=1)["counted"] is False
        assert sh._save_traffic(force=True) is True

        reopened = P.NetShield(state_dir=state_dir)
        assert _VICTIM in reopened._traffic and fresh not in reopened._traffic
        assert len(reopened._traffic) == 10
        assert reopened.unban(_VICTIM)["ok"] is True
        assert reopened.inspect(_VICTIM, path="/safe", method="GET")["action"] == "block"
