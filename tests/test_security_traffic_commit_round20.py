"""Signed quota history is a single-owner CAS state under the commit barrier."""

import asyncio
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.core.commit_barrier import register_cluster, release_cluster
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_STATE_BASE = Path(__file__).resolve().parents[1] / ".validation-security-round20-20261108"
_STATE_BASE.mkdir(exist_ok=True)
_IP = "192.0.2.59"
_WIRE_IP = "127.0.0.1"
_REQUEST = b"GET /safe HTTP/1.1\r\nHost: local.test\r\n\r\n"


class _FakeServingLease:
    held = True
    path_valid = True

    def verify_path(self):
        return self.path_valid


class _ReplacingServingLease:
    held = True

    def __init__(self):
        self.calls = 0

    def verify_path(self):
        self.calls += 1
        return self.calls == 1


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="traffic-cas-", dir=_STATE_BASE)


def _total(shield):
    return shield._window_totals(_IP)[0]


def test_external_signed_quota_writer_cannot_be_overwritten_by_stale_owner():
    with _state_dir() as directory:
        first = NetShield(state_dir=directory)
        assert first.set_config(enabled=True, mode="enforce", quota_enabled=True,
                                quota_max_gb=2000 / 1e9, usage_record=False)["ok"]
        assert first.record_traffic(_IP, out_bytes=59)["counted"] is True
        assert _total(NetShield(state_dir=directory)) == 59

        # A second process with the same valid state key publishes a newer
        # signed history while the first still owns its stale in-memory 59.
        external = NetShield(state_dir=directory)
        assert external.record_traffic(_IP, out_bytes=941)["counted"] is True
        assert _total(NetShield(state_dir=directory)) == 1000

        # The old implementation wrote 60 and acknowledged success, rolling
        # durable accounting back even though an external 1000 was valid.
        assert first.record_traffic(_IP, out_bytes=1)["counted"] is True
        saved = first._save_traffic(force=True)
        restored = NetShield(state_dir=directory)
        assert _total(restored) == 1000, "a stale owner rolled durable quota history back"
        assert saved is False
        assert first._last_traffic_write.get("conflict") is True
        assert first._traffic_state_untrusted is True
        assert first.reserve_egress(_IP, object(), 1500) == 0
        assert restored.reserve_egress(_IP, object(), 1001) == 1000


def test_own_signed_quota_saves_and_legacy_unsigned_migration_stay_writable():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, quota_enabled=True,
                                 quota_max_gb=2000 / 1e9, usage_record=False)["ok"]
        assert shield.record_traffic(_IP, out_bytes=59)["counted"] is True
        assert shield._save_traffic(force=True) is True
        assert shield.verify_traffic_source() is True
        assert _total(NetShield(state_dir=directory)) == 59

    with _state_dir() as directory:
        # Pre-signature legacy state is accepted once, then CAS-advanced to a
        # signed source before the next write. No signed marker/history exists.
        Path(directory, "traffic.json").write_text(
            '{"traffic":{"192.0.2.59":{"20000":[2,0,0]}}}',
            encoding="utf-8")
        migrated = NetShield(state_dir=directory)
        assert migrated._traffic_state_untrusted is False
        assert Path(directory, "traffic.json.hw").is_file()
        assert migrated.verify_traffic_source() is True
        assert migrated._save_traffic(force=True) is True


def test_changed_traffic_source_and_unreadable_pristine_file_fail_closed():
    with _state_dir() as directory:
        first = NetShield(state_dir=directory)
        assert first.set_config(enabled=True, quota_enabled=True,
                                quota_max_gb=2000 / 1e9)["ok"]
        assert first.verify_traffic_source() is True
        external = NetShield(state_dir=directory)
        assert external.record_traffic(_IP, out_bytes=1000)["counted"] is True
        assert first.verify_traffic_source() is False
        assert first._traffic_state_untrusted is True
        assert first.reserve_egress(_IP, object(), 1) == 0

    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        Path(shield._traffic_path).write_bytes(b"not-json")
        assert shield.verify_traffic_source() is False
        assert shield._traffic_state_untrusted is True

    with _state_dir() as directory:
        malformed = Path(directory, "traffic.json")
        malformed.write_bytes(b"not-json")
        restarted = NetShield(state_dir=directory)
        assert restarted._traffic_state_untrusted is True
        assert restarted._save_traffic(force=True) is False
        assert malformed.read_bytes() == b"not-json"


def test_event_loop_quota_save_fails_fast_then_flushes_after_barrier_release():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        lock = register_cluster(shield.path)
        held = threading.Event()
        release = threading.Event()

        def hold_backend_write():
            assert lock.acquire(timeout=2)
            held.set()
            try:
                release.wait(4)
            finally:
                lock.release()

        holder = threading.Thread(target=hold_backend_write, daemon=True)
        holder.start()
        assert held.wait(2)
        path = Path(shield._traffic_path)
        before = path.read_bytes() if path.exists() else None

        async def attempt():
            started = time.monotonic()
            saved = shield._save_traffic(force=True)
            elapsed = time.monotonic() - started
            await asyncio.sleep(0)
            return saved, elapsed

        try:
            saved, elapsed = asyncio.run(attempt())
            during = path.read_bytes() if path.exists() else None
            assert elapsed < 1.0, elapsed
            assert saved is False
            assert shield._last_traffic_write.get("barrier_unavailable") is True
            assert during == before
        finally:
            release.set()
            holder.join(5)
            assert release_cluster(lock)
        assert not holder.is_alive()
        assert shield._save_traffic(force=True) is True
        assert NetShield(state_dir=directory)._traffic_state_untrusted is False


def test_quota_writer_fails_fast_while_backend_commit_barrier_is_held():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        shield._traffic[_IP] = {str(shield._day()): [1, 0, 0]}
        shield._traffic_dirty = True
        lock = register_cluster(shield.path)
        entered_write = threading.Event()
        finished = threading.Event()
        result = []
        original = shield._write_state

        def observe(path, payload):
            if path == shield._traffic_path:
                entered_write.set()
            return original(path, payload)

        def save():
            try:
                with shield._lock:
                    result.append(shield._save_traffic(force=True))
            finally:
                finished.set()

        worker = threading.Thread(target=save, daemon=True)
        assert lock.acquire(timeout=2)
        try:
            with patch.object(shield, "_write_state", side_effect=observe):
                worker.start()
                finished_while_held = finished.wait(0.4)
                published_during_write = entered_write.is_set()
        finally:
            lock.release()
        worker.join(1)
        assert release_cluster(lock)
        assert finished_while_held, "quota writer blocked while holding Shield lock"
        assert not published_during_write
        assert result == [False]
        assert shield._traffic_dirty is True
        assert shield._last_traffic_write.get("barrier_unavailable") is True
        deadline = time.monotonic() + 3
        while shield._traffic_dirty and time.monotonic() < deadline:
            time.sleep(0.02)
        assert shield._traffic_dirty is False, "deferred quota accounting did not retry"
        assert Path(shield._traffic_path).is_file()


def test_external_signed_quota_between_shield_construction_and_start_blocks_wire():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, mode="enforce", block_page=False,
                                 quota_enabled=True, quota_max_gb=100 / 1e9,
                                 usage_record=False)["ok"]
        external = NetShield(state_dir=directory)
        external._traffic[_WIRE_IP] = {str(external._day()): [1000, 0, 0]}
        external._traffic_dirty = True
        assert external._save_traffic(force=True) is True
        assert shield._window_totals(_WIRE_IP)[0] == 0

        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), \
                    patch.object(FW, "_FW", AppFirewall(state_dir=directory)):
                with _guard(backend) as edge:
                    wire = _exchange(edge, [_REQUEST])
            assert backend.got == [], backend.got
            assert b"\r\n\r\nok" not in wire, wire
            assert shield._window_totals(_WIRE_IP)[0] == 1000
        finally:
            backend.close()


def test_start_reload_preserves_local_dirty_accounting_and_active_egress_lease():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, quota_enabled=True,
                                 quota_max_gb=2000 / 1e9, usage_record=False)["ok"]
        token = object()
        assert shield.reserve_egress(_IP, token, 1) == 1
        assert shield.reload_traffic_for_start() is False
        assert shield._traffic_state_untrusted is False
        shield.finalize_egress(token)
        assert shield.reload_traffic_for_start() is True
        assert _total(shield) == 1

        assert shield.record_traffic(_IP, out_bytes=1)["counted"] is True
        assert shield.record_traffic(_IP, out_bytes=1)["counted"] is True
        assert shield._traffic_dirty is True  # debounced, not yet signed
        assert shield.reload_traffic_for_start() is False
        assert _total(shield) == 3
        assert shield._save_traffic(force=True) is True
        assert shield.reload_traffic_for_start() is True
        assert _total(shield) == 3


def test_lost_serving_lease_never_publishes_signed_ban_or_quota_state():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        lease = _FakeServingLease()
        shield._serving_lease = lease
        assert shield.ban("192.0.2.1", permanent=True)["ok"] is True
        bans = Path(shield._bans_path)
        before_bans = bans.read_bytes()
        lease.path_valid = False  # as if the named lease inode were replaced
        rejected = shield.ban("192.0.2.2", permanent=True)
        assert rejected["ok"] is False and rejected["applied_in_memory"] is True
        assert shield._ban_state_untrusted is True and shield._bans_dirty is True
        assert shield._last_bans_write.get("lease_unavailable") is True
        assert bans.read_bytes() == before_bans

    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        lease = _FakeServingLease()
        shield._serving_lease = lease
        assert shield._save_traffic(force=True) is True
        traffic = Path(shield._traffic_path)
        before_traffic = traffic.read_bytes()
        shield._traffic[_IP] = {str(shield._day()): [1, 0, 0]}
        shield._traffic_dirty = True
        lease.held = False
        assert shield._save_traffic(force=True) is False
        assert shield._traffic_state_untrusted is True and shield._traffic_dirty is True
        assert shield._last_traffic_write.get("lease_unavailable") is True
        assert traffic.read_bytes() == before_traffic

    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        shield._serving_lease = _ReplacingServingLease()
        assert shield._save_traffic(force=True) is False
        assert shield._last_traffic_write.get("lease_unavailable") is True
        assert not Path(shield._traffic_path).exists()


def test_clean_flush_preserves_verified_signed_bytes_and_pristine_absence():
    with _state_dir() as directory:
        shield = NetShield(state_dir=directory)
        sources = [Path(shield._bans_path), Path(shield._traffic_path),
                   Path(shield._usage_path)]
        assert all(not path.exists() for path in sources)
        clean = shield.flush_state()
        assert all(not path.exists() for path in sources), "clean flush published new signed files"
        assert clean["ok"] is True and clean["persisted"] is True
        assert clean["bans"] == "unchanged"
        assert set(clean["unchanged_sources"]) == {"bans", "traffic", "usage"}

        assert shield.set_config(enabled=True, quota_enabled=True,
                                 quota_max_gb=2000 / 1e9,
                                 usage_record=True)["ok"]
        assert shield.record_traffic(_IP, out_bytes=59)["counted"] is True
        assert shield.ban("192.0.2.60", permanent=True)["ok"] is True
        before = [path.read_bytes() for path in sources]
        flushed = shield.flush_state()
        assert flushed["ok"] is True and flushed["persisted"] is True
        assert set(flushed["unchanged_sources"]) == {"bans", "traffic", "usage"}
        assert [path.read_bytes() for path in sources] == before
