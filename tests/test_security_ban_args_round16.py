"""Reject ambiguous direct BAN arguments before policy or signed-state mutation."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-ban-args-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_truthy_string_permanent_does_not_publish_infinite_ban_or_block_wire():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 persist_bans=True)["ok"]
        firewall = AppFirewall(state_dir=state)
        before = Path(shield._bans_path).read_bytes() if Path(shield._bans_path).exists() else None
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall), \
                    _guard(backend) as edge:
                result = shield.ban("127.0.0.1", ttl_sec=1, permanent="false")
                wire = _exchange(edge, [b"GET /invalid-ban-r16 HTTP/1.1\r\n"
                                        b"Host: local.test\r\n\r\n"])
            after = Path(shield._bans_path).read_bytes() if Path(shield._bans_path).exists() else None
            assert wire.startswith(b"HTTP/1.1 200"), wire
            assert b"GET /invalid-ban-r16" in backend.saw(), backend.got
            assert result["ok"] is False, result
            assert result.get("persisted") is not True, result
            assert not shield.is_banned_fast("127.0.0.1")
            assert after == before
        finally:
            backend.close()


def test_ban_rejects_bool_and_nonfinite_duration_without_partial_state():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, persist_bans=True)["ok"]
        before = Path(shield._bans_path).read_bytes() if Path(shield._bans_path).exists() else None
        for kwargs in ({"ttl_sec": True}, {"ttl_sec": False},
                       {"ttl_sec": "60"}, {"ttl_sec": float("nan")},
                       {"ttl_sec": float("inf")}, {"ttl_sec": -1},
                       {"permanent": 1}, {"permanent": None},
                       {"permanent": "false"},
                       {"ttl_sec": "bad", "permanent": True},
                       {"ttl_sec": 60, "permanent": True}):
            result = shield.ban("192.0.2.7", **kwargs)
            assert result["ok"] is False, (kwargs, result)
            assert not shield.is_banned_fast("192.0.2.7")
            after = Path(shield._bans_path).read_bytes() if Path(shield._bans_path).exists() else None
            assert after == before, kwargs


def test_valid_finite_and_permanent_bans_keep_signed_behavior():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, persist_bans=True)["ok"]
        short = shield.ban("192.0.2.8", ttl_sec=60.0, permanent=False)
        permanent = shield.ban("192.0.2.9", permanent=True)
        assert short["ok"] and permanent["ok"]
        assert shield.is_banned_fast("192.0.2.8")
        assert shield.is_banned_fast("192.0.2.9")
        restarted = NetShield(state_dir=state)
        assert restarted.is_banned_fast("192.0.2.8")
        assert restarted.is_banned_fast("192.0.2.9")
