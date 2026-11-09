"""Signed BAN publication shares the proxy's first-write commit barrier."""

import asyncio
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.core.commit_barrier import register_cluster, release_cluster
from dataplane.engine.lifeform.pipeline import NetShield


def test_ban_writer_fails_fast_while_backend_commit_barrier_is_held():
    with tempfile.TemporaryDirectory() as directory:
        shield = NetShield(state_dir=directory)
        lock = register_cluster(shield.path)
        entered_write = threading.Event()
        finished = threading.Event()
        result = []
        original = shield._write_state

        def observe(path, payload):
            if path == shield._bans_path:
                entered_write.set()
            return original(path, payload)

        def add_ban():
            try:
                result.append(shield.ban("127.0.0.1", permanent=True))
            finally:
                finished.set()

        worker = threading.Thread(target=add_ban, daemon=True)
        assert lock.acquire(timeout=2)
        try:
            with patch.object(shield, "_write_state", side_effect=observe):
                worker.start()
                # The Shield lock must never be held while waiting for an
                # async backend drain to release the commit barrier.
                finished_while_held = finished.wait(0.4)
                published_during_write = entered_write.is_set()
        finally:
            lock.release()
        worker.join(1)
        assert release_cluster(lock)
        assert finished_while_held, "BAN writer blocked while holding Shield lock"
        assert not published_during_write, "BAN published across an in-flight backend write"
        assert result and result[0]["ok"] is False, result
        assert result[0].get("applied_in_memory") is True
        assert shield._bans_dirty is True
        assert shield.is_banned_fast("127.0.0.1")
        deadline = time.monotonic() + 3
        while shield._bans_dirty and time.monotonic() < deadline:
            time.sleep(0.02)
        assert shield._bans_dirty is False, "deferred BAN did not retry"
        restored = NetShield(state_dir=directory)
        assert restored.is_banned_fast("127.0.0.1")


def test_event_loop_ban_writer_fails_fast_then_retries_after_barrier_release():
    with tempfile.TemporaryDirectory() as directory:
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
        path = Path(shield._bans_path)
        before = path.read_bytes() if path.exists() else None

        async def attempt():
            started = time.monotonic()
            result = shield.ban("192.0.2.9", permanent=True)
            elapsed = time.monotonic() - started
            await asyncio.sleep(0)
            return result, elapsed

        try:
            result, elapsed = asyncio.run(attempt())
            during = path.read_bytes() if path.exists() else None
            assert elapsed < 1.0, elapsed  # no 5-second event-loop stall
            assert result["ok"] is False, result
            assert shield._last_bans_write.get("barrier_unavailable") is True
            assert during == before, "signed BAN appeared during protected write"
        finally:
            release.set()
            holder.join(5)
            assert release_cluster(lock)
        assert not holder.is_alive()
        # The dirty in-memory BAN remains denied and can be durably flushed
        # after the first-write owner releases the barrier.
        assert shield.is_banned_fast("192.0.2.9")
        flushed = shield.flush_state()
        assert flushed["bans"] == "saved", flushed
        assert NetShield(state_dir=directory).is_banned_fast("192.0.2.9")
