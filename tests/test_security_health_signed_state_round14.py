"""A signed-state integrity failure cannot advertise a healthy edge."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_HEALTH = b"GET /healthz HTTP/1.1\r\nHost: local.test\r\n\r\n"
_NORMAL = b"GET /safe HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _wire(shield, firewall):
    backend = _Backend()
    try:
        with patch.object(ND, "_SHIELD", shield), \
                patch.object(FW, "_FW", firewall), \
                _guard(backend, health_path="/healthz") as edge:
            health = _exchange(edge, [_HEALTH])
            normal = _exchange(edge, [_NORMAL])
            metrics = dict(edge.metrics)
        return health, normal, list(backend.got), metrics
    finally:
        backend.close()


def _base():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=base)


def test_untrusted_signed_shield_states_do_not_advertise_health():
    for kind in ("config", "signatures", "bans", "traffic"):
        with _base() as state:
            shield = NetShield(state_dir=state)
            assert shield.set_config(enabled=True, block_page=False)["ok"]
            if kind == "config":
                target, flag = shield.path, "_cfg_state_untrusted"
            elif kind == "signatures":
                assert shield.add_signature("health-check", "health-private", weight=200)["ok"]
                target, flag = shield._sig_path, "_sig_state_untrusted"
            elif kind == "bans":
                assert shield.ban("127.0.0.1", permanent=True)["ok"]
                target, flag = shield._bans_path, "_ban_state_untrusted"
            else:
                assert shield.set_config(quota_enabled=True, quota_max_gb=1e-6)["ok"]
                assert shield.flush_state()["ok"]
                target, flag = shield._traffic_path, "_traffic_state_untrusted"
            Path(target).write_bytes(b"{}")
            restarted = NetShield(state_dir=state)
            assert getattr(restarted, flag), kind
            health, normal, upstream, metrics = _wire(restarted, AppFirewall(state_dir=state))
            assert health.startswith(b"HTTP/1.1 503 Service Unavailable"), (kind, health)
            assert not normal.startswith(b"HTTP/1.1 200 OK"), (kind, normal)
            assert upstream == [], (kind, upstream)
            assert metrics.get("health", 0) == 0, (kind, metrics)


def test_untrusted_signed_acl_does_not_advertise_health():
    with _base() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        firewall = AppFirewall(state_dir=state)
        assert firewall.enable()["ok"]
        Path(firewall.path).write_bytes(b"{}")
        restarted = AppFirewall(state_dir=state)
        assert restarted.status()["load_warning"]
        health, normal, upstream, metrics = _wire(shield, restarted)
        assert health.startswith(b"HTTP/1.1 503 Service Unavailable"), health
        assert not normal.startswith(b"HTTP/1.1 200 OK"), normal
        assert upstream == []
        assert metrics.get("health", 0) == 0


def test_untrusted_traffic_without_finite_active_quota_keeps_health():
    with _base() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, quota_enabled=False)["ok"]
        assert shield.flush_state()["ok"]
        Path(shield._traffic_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted._traffic_state_untrusted
        health, normal, upstream, metrics = _wire(restarted, AppFirewall(state_dir=state))
        assert health.startswith(b"HTTP/1.1 200 OK"), health
        assert normal.startswith(b"HTTP/1.1 200 OK"), normal
        assert len(upstream) == 1 and upstream[0].startswith(_NORMAL[:-2]), upstream
        assert metrics.get("health", 0) == 1
