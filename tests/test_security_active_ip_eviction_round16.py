"""IP capacity must not erase active token, score, or window decisions."""

import os
import tempfile
import time
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_security_ip_state_capacity_round16 import _exchange_from
from test_sweep_proxy_request import _Backend, _guard


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-active-ip-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _setup(state, *, rate, window):
    shield = pipeline.NetShield(state_dir=state)
    result = shield.set_config(enabled=True, block_page=False,
                               persist_bans=False, rate_per_sec=rate, burst=1,
                               window_sec=window, flood_threshold=1000)
    assert result["ok"], result
    return shield, policy.AppFirewall(state_dir=state), _Backend()


def test_active_ip_rate_window_survives_new_source_churn_on_real_wire():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state, rate=1e-9, window=60)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                first_a = _exchange_from(edge, "127.0.0.2", "/a-first")
                rate_a = _exchange_from(edge, "127.0.0.2", "/a-rate")
                first_b = _exchange_from(edge, "127.0.0.3", "/b-first")
                newcomer = _exchange_from(edge, "127.0.0.4", "/c-churn")
                after_a = _exchange_from(edge, "127.0.0.2", "/a-after-churn")
                assert len(shield._ips) == 2
                assert shield._metrics["ip_state_capacity"] >= 1
            upstream = backend.saw()
        finally:
            backend.close()
        assert first_a.startswith(b"HTTP/1.1 200"), first_a
        assert first_b.startswith(b"HTTP/1.1 200"), first_b
        assert not rate_a.startswith(b"HTTP/1.1 200"), rate_a
        assert not newcomer.startswith(b"HTTP/1.1 200"), newcomer
        assert not after_a.startswith(b"HTTP/1.1 200"), after_a
        assert b"GET /c-churn" not in upstream
        assert b"GET /a-after-churn" not in upstream


def test_quiescent_ip_row_is_reclaimed_for_benign_client():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state, rate=1000, window=1)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert _exchange_from(edge, "127.0.0.2", "/a").startswith(b"HTTP/1.1 200")
                assert _exchange_from(edge, "127.0.0.3", "/b").startswith(b"HTTP/1.1 200")
                time.sleep(1.1)
                newcomer = _exchange_from(edge, "127.0.0.4", "/new-after-expiry")
                assert len(shield._ips) == 2
            upstream = backend.saw()
        finally:
            backend.close()
        assert newcomer.startswith(b"HTTP/1.1 200"), newcomer
        assert b"GET /new-after-expiry" in upstream


def test_scored_ip_rows_remain_tracked_when_table_is_full():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state, rate=1000, window=1)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield.penalize("127.0.0.2", weight=1)["action"] == "penalize"
                assert shield.penalize("127.0.0.3", weight=1)["action"] == "penalize"
                newcomer = _exchange_from(edge, "127.0.0.4", "/scored-full")
                assert len(shield._ips) == 2
                assert shield._ips["127.0.0.2"]["score"] > 0
                assert shield._ips["127.0.0.3"]["score"] > 0
            upstream = backend.saw()
        finally:
            backend.close()
        assert not newcomer.startswith(b"HTTP/1.1 200"), newcomer
        assert b"GET /scored-full" not in upstream


def test_active_path_bucket_survives_after_flood_window_expires():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state, rate=1000, window=1)
        assert shield.set_path_limits([{"path": "/login", "rate": 1e-9, "burst": 1}])["ok"]
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert _exchange_from(edge, "127.0.0.2", "/login/a").startswith(b"HTTP/1.1 200")
                assert _exchange_from(edge, "127.0.0.3", "/login/b").startswith(b"HTTP/1.1 200")
                time.sleep(1.1)
                newcomer = _exchange_from(edge, "127.0.0.4", "/unrelated-c")
                still_limited = _exchange_from(edge, "127.0.0.2", "/login/a-again")
                assert len(shield._ips) == 2
            upstream = backend.saw()
        finally:
            backend.close()
        assert not newcomer.startswith(b"HTTP/1.1 200"), newcomer
        assert not still_limited.startswith(b"HTTP/1.1 200"), still_limited
        assert b"GET /unrelated-c" not in upstream
        assert b"GET /login/a-again" not in upstream


def test_nearly_all_banned_table_throttles_repeated_full_scans_on_wire():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state, rate=1e-9, window=60)
        try:
            with patch.object(pipeline, "_MAX_IPS", 100), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                now = pipeline._now()
                for index in range(98):
                    ip = f"2001:db8:1::{index:x}"
                    st = shield._state(ip)
                    st["ban_until"] = now + 3600
                    shield._ban_bloom.add(ip)
                active = _exchange_from(edge, "127.0.0.2", "/active-first")
                assert active.startswith(b"HTTP/1.1 200"), active
                shield._state("127.0.0.99")  # one quiescent row; table now full
                assert len(shield._ips) == 100
                calls = [0]
                original = shield._evict

                def counted():
                    calls[0] += 1
                    return original()

                shield._evict = counted
                first_new = _exchange_from(edge, "127.0.0.3", "/one-safe-reclaim")
                denied = [_exchange_from(edge, f"127.0.0.{index}", f"/full-{index}")
                          for index in range(4, 12)]
                still_active = _exchange_from(edge, "127.0.0.2", "/active-after")
                assert len(shield._ips) == 100
                assert calls[0] == 1, calls
            upstream = backend.saw()
        finally:
            backend.close()
        assert first_new.startswith(b"HTTP/1.1 200"), first_new
        assert all(not wire.startswith(b"HTTP/1.1 200") for wire in denied), denied
        assert not still_active.startswith(b"HTTP/1.1 200"), still_active
        assert b"GET /full-4" not in upstream and b"GET /active-after" not in upstream
