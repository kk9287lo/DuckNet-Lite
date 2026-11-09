"""Round 12: a lost signed quota history must not grant fresh backend bytes."""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_REQUEST = b"GET /safe HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _send(shield, state):
    backend = _Backend()
    try:
        with patch.object(ND, "_SHIELD", shield), \
                patch.object(FW, "_FW", AppFirewall(state_dir=state)):
            with _guard(backend) as edge:
                wire = _exchange(edge, [_REQUEST])
        return backend.got, wire
    finally:
        backend.close()


def _seed_quota(state, mode="enforce"):
    shield = NetShield(state_dir=state)
    assert shield.set_config(enabled=True, mode=mode, block_page=False,
                             quota_enabled=True, quota_max_gb=1e-8,
                             ban_ttl_sec=1, usage_record=True)["ok"]
    result = shield.record_traffic("127.0.0.1", out_bytes=11)
    assert result.get("exceeded") and Path(shield._traffic_path).is_file(), result
    return shield


def _expire_short_ban():
    # The saved quota history must still block after its temporary BAN expires.
    time.sleep(1.25)


def test_tampered_signed_traffic_rejects_before_backend_after_ban_expiry():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_quota(state)
        _expire_short_ban()
        Path(shield._traffic_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted.tamper_report()["summary"]["count"] >= 1
        upstream, client = _send(restarted, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)


def test_tampered_traffic_in_audit_forwards_but_records_would_block():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_quota(state, mode="audit")
        Path(shield._traffic_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state)
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2]), upstream
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client
        # Post-response quota accounting can emit a separate audit event;
        # require the pre-backend untrusted-state policy decision specifically.
        assert any(e.get("kind") == "audit" and e.get("would") == "block"
                   and e.get("rule") == "policy_block"
                   for e in restarted.events(20)), restarted.events(20)


def test_missing_signed_traffic_is_not_republished_empty_across_two_restarts():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_quota(state)
        _expire_short_ban()
        path = Path(shield._traffic_path)
        assert Path(str(path) + ".hw").is_file()
        path.unlink()
        first = NetShield(state_dir=state)
        assert first.tamper_report()["summary"]["count"] >= 1
        second = NetShield(state_dir=state)
        upstream, client = _send(second, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
        assert second.tamper_report()["summary"]["count"] >= 1
        assert not path.exists(), "startup must preserve the missing signed quota evidence"


def test_flush_cannot_clear_untrusted_quota_history_after_missing_snapshot():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_quota(state)
        _expire_short_ban()
        path = Path(shield._traffic_path)
        path.unlink()
        first = NetShield(state_dir=state)
        assert first._traffic_state_untrusted is True and not path.exists()
        flush = first.flush_state()
        second = NetShield(state_dir=state)
        upstream, client = _send(second, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (flush, upstream, client)
        assert flush["ok"] is False and flush["persisted"] is False, flush
        assert flush["traffic_saved"] is False
        assert second._traffic_state_untrusted is True and not path.exists()


def test_valid_quota_and_pristine_history_keep_their_wire_behavior():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_quota(state)
        _expire_short_ban()
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 quota_enabled=True, quota_max_gb=1e-6)["ok"]
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state)
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2]), upstream
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client


def test_usage_telemetry_tamper_does_not_erase_valid_traffic_quota():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_quota(state)
        _expire_short_ban()
        Path(shield._usage_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
