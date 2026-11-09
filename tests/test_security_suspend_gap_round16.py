"""Invalid suspend compensation must not turn finite BANs into infinite BANs."""

import math
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-suspend-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_infinite_suspend_gap_cannot_make_short_ban_permanent_on_real_wire():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        firewall = AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    _guard(backend) as edge:
                control = _exchange(edge, [b"GET /suspend-before HTTP/1.1\r\n"
                                          b"Host: local.test\r\n\r\n"])
                assert control.startswith(b"HTTP/1.1 200"), control
                assert b"GET /suspend-before" in backend.saw()
                assert shield.ban("127.0.0.1", ttl_sec=0.3)["ok"]
                before_until = shield._ips["127.0.0.1"]["ban_until"]
                bans_before = Path(shield._bans_path).read_bytes()
                result = shield.absorb_suspend(float("inf"))
                time.sleep(0.4)
                after = _exchange(edge, [b"GET /suspend-after HTTP/1.1\r\n"
                                         b"Host: local.test\r\n\r\n"])
                # Old runtime made ban_until=inf and denied this real request.
                assert after.startswith(b"HTTP/1.1 200"), after
                assert b"GET /suspend-after" in backend.saw()
                assert result.get("ok") is False, result
                assert shield._ips["127.0.0.1"]["ban_until"] == before_until
                assert Path(shield._bans_path).read_bytes() == bans_before
        finally:
            backend.close()


def test_bad_suspend_gaps_reject_without_touching_ban_state():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert shield.ban("192.0.2.7", ttl_sec=60)["ok"]
        before = shield._ips["192.0.2.7"]["ban_until"]
        for gap in (None, True, "60", float("nan"), float("inf"),
                    -float("inf"), -1, 1e100):
            result = shield.absorb_suspend(gap)
            assert result.get("ok") is False, (gap, result)
            assert shield._ips["192.0.2.7"]["ban_until"] == before
        assert math.isfinite(shield._ips["192.0.2.7"]["ban_until"])


def test_finite_suspend_gap_still_restores_short_ban():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert shield.ban("192.0.2.8", ttl_sec=60)["ok"]
        before = shield._ips["192.0.2.8"]["ban_until"]
        result = shield.absorb_suspend(2.0)
        after = shield._ips["192.0.2.8"]["ban_until"]
        assert result.get("ok") is True and result["bans"] >= 1, result
        assert 1.9 <= after - before <= 2.1
        assert result.get("persisted") is True, result
        restarted = NetShield(state_dir=state)
        assert restarted._ips["192.0.2.8"]["ban_until"] >= before + 1.9


def test_failed_suspend_save_reports_memory_only_without_false_durability():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert shield.ban("192.0.2.9", ttl_sec=60)["ok"]
        before = shield._ips["192.0.2.9"]["ban_until"]
        durable = Path(shield._bans_path).read_bytes()
        with patch.object(shield, "_save_bans", return_value="failed"):
            result = shield.absorb_suspend(2.0)
        assert result.get("ok") is False, result
        assert result.get("applied_in_memory") is True, result
        assert result.get("persisted") is False, result
        assert shield._ips["192.0.2.9"]["ban_until"] >= before + 1.9
        assert Path(shield._bans_path).read_bytes() == durable
