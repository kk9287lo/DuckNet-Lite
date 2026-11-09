"""Active subnet-ban aggregation must survive table and entry saturation."""

import os
import tempfile
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_security_ip_state_capacity_round16 import _exchange_from
from test_sweep_proxy_request import _Backend, _guard


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-subnet-cap-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _setup(state):
    shield = pipeline.NetShield(state_dir=state)
    result = shield.set_config(enabled=True, block_page=False, persist_bans=False,
                               rate_per_sec=1000, burst=1000,
                               subnet_defense=True, subnet_threshold=2,
                               subnet_score=100)
    assert result["ok"], result
    return shield, policy.AppFirewall(state_dir=state), _Backend()


def _auto_ban(shield, ip):
    result = shield.penalize(ip, weight=100, reason="probe")
    assert result["banned"] is True, result


def test_hot_subnet_survives_unrelated_subnet_churn_on_real_wire():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_MAX_SUBNETS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                _auto_ban(shield, "127.0.1.2")
                _auto_ban(shield, "127.0.1.3")
                _auto_ban(shield, "127.0.2.2")
                assert shield._subnet_hot_count("127.0.1.4") == 2
                _auto_ban(shield, "127.0.3.2")
                attacked = _exchange_from(edge, "127.0.1.4", "/hot-after-churn")
                benign = _exchange_from(edge, "127.0.2.4", "/tracked-benign")
                assert len(shield._subnets) <= 2
            upstream = backend.saw()
        finally:
            backend.close()
        assert not attacked.startswith(b"HTTP/1.1 200"), attacked
        assert b"GET /hot-after-churn" not in upstream
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /tracked-benign" in upstream


def test_active_hot_subnet_survives_per_subnet_entry_cap():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_SUBNET_IP_CAP", 2), \
                    patch.object(pipeline, "_SUBNET_IP_LOW", 1), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                _auto_ban(shield, "127.0.1.2")
                _auto_ban(shield, "127.0.1.3")
                _auto_ban(shield, "127.0.1.5")
                blocked = _exchange_from(edge, "127.0.1.4", "/subnet-entry-reset")
                benign = _exchange_from(edge, "127.0.2.4", "/other-subnet-benign")
            upstream = backend.saw()
        finally:
            backend.close()
        assert not blocked.startswith(b"HTTP/1.1 200"), blocked
        assert b"GET /subnet-entry-reset" not in upstream
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /other-subnet-benign" in upstream
        assert shield._subnet_entries == 2


def test_subnet_threshold_cannot_exceed_distinct_ip_tracking_cap():
    with _state_dir() as state:
        shield, _firewall, backend = _setup(state)
        backend.close()
        before = shield.cfg["subnet_threshold"]
        rejected = shield.set_config(subnet_threshold=pipeline._SUBNET_IP_CAP + 1)
        assert rejected["ok"] is False and not rejected.get("applied_in_memory"), rejected
        assert shield.cfg["subnet_threshold"] == before


def test_full_active_subnet_table_throttles_expiry_scans():
    with _state_dir() as state:
        shield, _firewall, backend = _setup(state)
        backend.close()
        with patch.object(pipeline, "_MAX_SUBNETS", 2):
            assert shield._record_subnet_ban("127.0.1.2")
            assert shield._record_subnet_ban("127.0.2.2")
            scans = [0]
            original = shield._evict_subnets

            def counted():
                scans[0] += 1
                return original()

            shield._evict_subnets = counted
            for index in range(3, 12):
                assert shield._record_subnet_ban(f"127.0.{index}.2") is False
            assert scans[0] == 1, scans
            assert len(shield._subnets) == 2 and shield._subnet_entries == 2


def test_one_expired_slot_does_not_repeat_full_subnet_scans_on_wire():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_MAX_SUBNETS", 100), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield._record_subnet_ban("127.0.1.2")
                for index in range(2, 100):
                    assert shield._record_subnet_ban(f"2001:db8:{index}::1")
                expired = "2001:db8:100::1"
                assert shield._record_subnet_ban(expired)
                key = pipeline._subnet_key(expired)
                shield._subnets[key][expired] = pipeline._now() - 3601
                assert len(shield._subnets) == 100
                scans = [0]
                original = shield._evict_subnets

                def counted():
                    scans[0] += 1
                    return original()

                shield._evict_subnets = counted
                _auto_ban(shield, "127.0.200.2")  # safely reuses the one expired slot
                _auto_ban(shield, "127.0.201.2")  # table full again: must not rescan
                unknown = _exchange_from(edge, "127.0.202.2", "/subnet-full-attack")
                benign = _exchange_from(edge, "127.0.1.4", "/subnet-known-benign")
                assert scans[0] == 1, scans
                assert len(shield._subnets) == 100
            upstream = backend.saw()
        finally:
            backend.close()
        assert not unknown.startswith(b"HTTP/1.1 200"), unknown
        assert b"GET /subnet-full-attack" not in upstream
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /subnet-known-benign" in upstream


def test_negative_subnet_window_does_not_keep_expired_hot_bans_on_wire():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        assert shield.set_config(subnet_window_sec=1)["ok"]
        attempted = shield.set_config(subnet_window_sec=-1)
        clock = [1000.0]
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(pipeline, "_now", side_effect=lambda: clock[0]), \
                    _guard(backend) as edge:
                _auto_ban(shield, "127.0.1.2")
                _auto_ban(shield, "127.0.1.3")
                clock[0] += 2.0
                benign = _exchange_from(edge, "127.0.1.4", "/expired-hot-benign")
            upstream = backend.saw()
        finally:
            backend.close()
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /expired-hot-benign" in upstream
        assert attempted["ok"] is False and shield.cfg["subnet_window_sec"] == 1


def test_legacy_signed_negative_subnet_window_is_bounded_on_load():
    with _state_dir() as state:
        shield, _firewall, backend = _setup(state)
        backend.close()
        payload = {"cfg": {**shield.cfg, "subnet_window_sec": -1},
                   "saved": pipeline._now(), "rev": 3}
        assert shield._write_state(shield.path, payload)["ok"]
        loaded = pipeline.NetShield(state_dir=state)
        assert loaded.cfg["subnet_window_sec"] == pipeline._DEFAULTS["subnet_window_sec"]
        assert any(event.get("kind") == "cfg_load_rejected"
                   and "subnet_window_sec" in event.get("bounded", ())
                   for event in loaded.events(100))
