"""Path rule buckets have a global memory budget without resetting active limits."""

import os
import tempfile
import time
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-path-budget-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _setup(state, *, mode="enforce"):
    shield = pipeline.NetShield(state_dir=state)
    rules = [{"path": f"/p{i}", "rate": 1e-9, "burst": 1}
             for i in range(3)]
    result = shield.set_config(enabled=True, mode=mode, block_page=False,
                               persist_bans=False, rate_per_sec=1000,
                               burst=1000, flood_threshold=1000,
                               path_limits=rules)
    assert result["ok"], result
    return shield, policy.AppFirewall(state_dir=state)


def _get(edge, path):
    request = (f"GET {path} HTTP/1.1\r\nHost: local.test\r\n"
               "Connection: close\r\n\r\n").encode("ascii")
    return _exchange(edge, [request])


def test_new_ruled_path_fails_closed_at_budget_without_evicting_active_bucket():
    with _state_dir() as state:
        shield, firewall = _setup(state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_PATH_BUCKET_BUDGET", 2, create=True), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                first = _get(edge, "/p0")
                second = _get(edge, "/p1")
                overflow = _get(edge, "/p2")
                ordinary = _get(edge, "/normal")
                repeat = _get(edge, "/p0")
            upstream = backend.saw()
        finally:
            backend.close()
        assert first.startswith(b"HTTP/1.1 200") and b"GET /p0" in upstream
        assert second.startswith(b"HTTP/1.1 200") and b"GET /p1" in upstream
        assert ordinary.startswith(b"HTTP/1.1 200") and b"GET /normal" in upstream
        assert not overflow.startswith(b"HTTP/1.1 200") and b"GET /p2" not in upstream
        assert not repeat.startswith(b"HTTP/1.1 200") and upstream.count(b"GET /p0") == 1
        assert shield._path_bucket_entries == 2


def test_audit_mode_reports_unallocated_path_bucket_as_would_block():
    with _state_dir() as state:
        shield, firewall = _setup(state, mode="audit")
        backend = _Backend()
        try:
            with patch.object(pipeline, "_PATH_BUCKET_BUDGET", 1, create=True), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                first = _get(edge, "/p0")
                overflow = _get(edge, "/p1")
            upstream = backend.saw()
        finally:
            backend.close()
        assert first.startswith(b"HTTP/1.1 200") and overflow.startswith(b"HTTP/1.1 200")
        assert b"GET /p0" in upstream and b"GET /p1" in upstream
        assert any(event.get("kind") == "audit"
                   and event.get("rule") == "path_bucket_capacity"
                   and event.get("would") == "block"
                   for event in shield.events(100))
        assert shield._path_bucket_entries == 1


def test_refilled_bucket_reclaims_one_slot_without_losing_active_new_rule():
    with _state_dir() as state:
        shield = pipeline.NetShield(state_dir=state)
        rules = [{"path": path, "rate": 1.0, "burst": 1.0}
                 for path in ("/p0", "/p1")]
        assert shield.set_config(enabled=True, path_limits=rules,
                                 rate_per_sec=1000, burst=1000)["ok"]
        now = [pipeline._now()]
        with patch.object(pipeline, "_PATH_BUCKET_BUDGET", 1, create=True), \
                patch.object(pipeline, "_now", side_effect=lambda: now[0]):
            assert shield.inspect("127.0.0.2", path="/p0")["action"] == "allow"
            assert shield.inspect("127.0.0.2", path="/p1")["action"] == "block"
            assert shield._path_bucket_entries == 1
            now[0] += 2.0
            time.sleep(0.3)  # let the bounded saturation sweep retry
            assert shield.inspect("127.0.0.2", path="/p1")["action"] == "allow"
            assert shield._path_bucket_entries == 1
            assert shield.inspect("127.0.0.2", path="/p0")["action"] == "block"
            assert shield._path_bucket_entries == 1


def test_removed_rule_and_evicted_ip_release_exact_bucket_count():
    with _state_dir() as state:
        shield = pipeline.NetShield(state_dir=state)
        rules = [{"path": path, "rate": 1.0, "burst": 1.0}
                 for path in ("/p0", "/p1")]
        assert shield.set_config(enabled=True, path_limits=rules,
                                 rate_per_sec=1000, burst=1000)["ok"]
        now = [pipeline._now()]
        with patch.object(pipeline, "_PATH_BUCKET_BUDGET", 1, create=True), \
                patch.object(pipeline, "_now", side_effect=lambda: now[0]):
            assert shield.inspect("127.0.0.2", path="/p0")["action"] == "allow"
            assert shield._path_bucket_entries == 1
        # Real signed config update removes /p0. Its old bucket must not pin
        # the budget merely because its prior token deficit remains active.
        assert shield.set_path_limits([rules[1]])["ok"]
        with patch.object(pipeline, "_PATH_BUCKET_BUDGET", 1, create=True), \
                patch.object(pipeline, "_MAX_IPS", 1), \
                patch.object(pipeline, "_now", side_effect=lambda: now[0]):
            assert shield.inspect("127.0.0.2", path="/p1")["action"] == "allow"
            assert shield._path_bucket_entries == 1
            assert set(shield._ips["127.0.0.2"]["path_buckets"]) == {"/p1"}
            # Two inspect calls also retain cadence intervals for up to 75s.
            now[0] += 100.0
            shield._state("127.0.0.3")
            assert shield._path_bucket_entries == 0
            assert "127.0.0.2" not in shield._ips
