"""Existing clients must not evict unrelated usage history at capacity."""

import tempfile
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline as P


def _filled_usage(state_dir):
    sh = P.NetShield(state_dir=state_dir)
    sh.cfg["usage_record"] = True
    for i in range(10):
        sh.record_traffic(f"192.0.2.{i + 1}", out_bytes=10, host="example.test")
    assert len(sh._usage) == 10
    return sh


def test_existing_usage_client_preserves_other_clients_at_capacity():
    with tempfile.TemporaryDirectory() as state_dir, patch.object(P, "_MAX_IPS", 10):
        sh = _filled_usage(state_dir)
        before = set(sh._usage)
        assert sh.record_traffic("192.0.2.10", out_bytes=5, host="example.test")["counted"] is False
        assert set(sh._usage) == before
        assert sh._usage["192.0.2.10"]["out"] == 15
        assert sh._save_usage(force=True) is True
        reopened = P.NetShield(state_dir=state_dir)
        assert set(reopened._usage) == before


def test_new_usage_client_at_capacity_still_evicts_to_bound_memory():
    with tempfile.TemporaryDirectory() as state_dir, patch.object(P, "_MAX_IPS", 10):
        sh = _filled_usage(state_dir)
        sh.record_traffic("192.0.2.11", out_bytes=7, host="example.test")
        assert "192.0.2.11" in sh._usage
        assert len(sh._usage) <= 10


def test_one_entry_capacity_stays_bounded_for_new_and_existing_clients():
    with tempfile.TemporaryDirectory() as state_dir, patch.object(P, "_MAX_IPS", 1):
        sh = P.NetShield(state_dir=state_dir)
        sh.cfg["usage_record"] = True
        sh.record_traffic("192.0.2.1", out_bytes=1)
        sh.record_traffic("192.0.2.1", out_bytes=1)
        assert list(sh._usage) == ["192.0.2.1"] and sh._usage["192.0.2.1"]["out"] == 2
        sh.record_traffic("192.0.2.2", out_bytes=1)
        assert list(sh._usage) == ["192.0.2.2"]
