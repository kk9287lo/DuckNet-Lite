"""Round 12: an unreadable signed BAN snapshot cannot reopen backend admission."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.core import signed_state
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
                response = _exchange(edge, [_REQUEST])
        return backend.got, response
    finally:
        backend.close()


def _seed_ban(state):
    shield = NetShield(state_dir=state)
    assert shield.set_config(enabled=True, block_page=False)["ok"]
    assert shield.ban("127.0.0.1", permanent=True)["ok"]
    assert shield.is_banned_fast("127.0.0.1")
    return shield


def test_tampered_signed_ban_file_rejects_before_backend_wire():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_ban(state)
        path = Path(shield._bans_path)
        path.write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted.tamper_report()["summary"]["count"] >= 1
        upstream, client = _send(restarted, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)


def test_older_signed_empty_bans_and_corrupt_highwater_reject_before_backend():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        assert shield._save_bans(force=True) == "saved"
        path = Path(shield._bans_path)
        old_empty = path.read_bytes()
        assert shield.ban("127.0.0.1", permanent=True)["ok"]
        Path(str(path) + ".hw").write_bytes(b"{}")
        path.write_bytes(old_empty)
        # Simulate a fresh worker without this process's in-memory high water.
        signed_state._MEM_HW.pop(str(path), None)
        signed_state._MEM_MIN_SV.pop(str(path), None)
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
        assert restarted.tamper_report()["summary"]["count"] >= 1


def test_tampered_ban_state_in_audit_forwards_but_records_would_block():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, mode="audit", block_page=False)["ok"]
        assert shield.ban("127.0.0.1", permanent=True)["ok"]
        Path(shield._bans_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        upstream, client = _send(restarted, state)
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2]), upstream
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client
        assert any(e.get("kind") == "audit" and e.get("would") == "block"
                   for e in restarted.events(20)), restarted.events(20)


def test_missing_signed_bans_do_not_publish_empty_snapshot_across_two_restarts():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_ban(state)
        path = Path(shield._bans_path)
        assert Path(str(path) + ".hw").is_file()
        path.unlink()
        first = NetShield(state_dir=state)
        assert first.tamper_report()["summary"]["count"] >= 1
        second = NetShield(state_dir=state)
        upstream, client = _send(second, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
        assert second.tamper_report()["summary"]["count"] >= 1
        assert not path.exists(), "startup must preserve the missing signed BAN evidence"


def test_flush_cannot_republish_untrusted_empty_bans_as_durable_success():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_ban(state)
        path = Path(shield._bans_path)
        path.unlink()
        first = NetShield(state_dir=state)
        assert first._ban_state_untrusted is True and not path.exists()
        flush = first.flush_state()
        second = NetShield(state_dir=state)
        upstream, client = _send(second, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (flush, upstream, client)
        assert flush["ok"] is False and flush["persisted"] is False, flush
        assert second._ban_state_untrusted is True and not path.exists()


def test_valid_signed_ban_and_pristine_first_boot_keep_their_wire_behavior():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_ban(state)
        restarted = NetShield(state_dir=state)
        assert restarted.is_banned_fast("127.0.0.1")
        upstream, client = _send(restarted, state)
        assert upstream == [] and b"\r\n\r\nok" not in client, (upstream, client)
    with tempfile.TemporaryDirectory() as state:
        pristine = NetShield(state_dir=state)
        assert pristine.set_config(enabled=True, block_page=False)["ok"]
        upstream, client = _send(pristine, state)
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2]), upstream
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client


def test_reloading_verified_bans_clears_untrusted_latch_only_after_validation():
    with tempfile.TemporaryDirectory() as state:
        shield = _seed_ban(state)
        path = Path(shield._bans_path)
        signed_snapshot = path.read_bytes()
        path.write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted._ban_state_untrusted is True
        assert restarted.reload_bans()["ok"] is False
        assert restarted._ban_state_untrusted is True
        path.write_bytes(signed_snapshot)
        result = restarted.reload_bans()
        assert result["ok"] is True and restarted._ban_state_untrusted is False, result
        assert restarted.is_banned_fast("127.0.0.1") is True
        assert restarted.inspect("192.0.2.10", path="/safe")["action"] == "allow"
        assert restarted.unban("127.0.0.1")["ok"] is True
        upstream, client = _send(restarted, state)
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2]), upstream
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok"), client
