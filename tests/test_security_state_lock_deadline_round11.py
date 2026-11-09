"""A contended state-lock table must not stall a signed commit indefinitely."""

import os
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

from dataplane.engine.core import signed_state


def test_state_lock_table_contention_returns_before_its_total_deadline():
    with tempfile.TemporaryDirectory() as state:
        path = str(Path(state, "config.json"))
        key = b"state-lock-deadline-test-key-1234"
        started, done = threading.Event(), threading.Event()
        results = []

        def commit():
            status = {}
            started.set()
            results.append((signed_state.write_signed_json(
                path, {"enabled": False}, key, status=status), status))
            done.set()

        # Model a thread stopped while it owns the lock-table mutex. The
        # per-path lock's existing timeout does not help if this first gate is
        # acquired with an unbounded `with` statement.
        lock = signed_state._PATH_LOCKS_GUARD
        assert lock.acquire(timeout=1.0)
        worker = threading.Thread(target=commit, daemon=True)
        try:
            with mock.patch.object(signed_state, "_LOCK_WAIT_SEC", 0.05):
                worker.start()
                assert started.wait(3.0)
                assert done.wait(3.0), "signed state writer waited past its lock deadline"
                assert results[0][0] is False
                assert results[0][1].get("published") is False
                assert not Path(path).exists()
        finally:
            lock.release()
            worker.join(timeout=5.0)
        assert not worker.is_alive()

        # Benign control: after contention ends, the same state is writable
        # and the published bytes verify under the expected key.
        assert signed_state.write_signed_json(path, {"enabled": True}, key) is True
        assert signed_state.read_signed_json(path, key) == ("ok", {"enabled": True})


def test_delayed_lock_file_open_cannot_commit_after_total_deadline():
    with tempfile.TemporaryDirectory() as state:
        path = str(Path(state, "config.json"))
        key = b"state-lock-deadline-test-key-1234"
        real_open = os.open

        def delayed_open(name, *args, **kwargs):
            if os.fspath(name) == path + ".lock":
                time.sleep(0.15)
            return real_open(name, *args, **kwargs)

        # A slow filesystem open is outside the deadline's direct control,
        # but it must not turn a late, immediately available OS lock into a
        # successful signed commit after the budget has expired.
        status = {}
        with mock.patch.object(signed_state, "_LOCK_WAIT_SEC", 0.05), \
                mock.patch.object(signed_state.os, "open", side_effect=delayed_open):
            assert signed_state.write_signed_json(
                path, {"enabled": False}, key, status=status) is False
        assert status.get("published") is False
        assert not Path(path).exists()

        # The expired attempt leaves no live state; a subsequent valid
        # operation can commit and be verified using the same key.
        assert signed_state.write_signed_json(path, {"enabled": True}, key) is True
        assert signed_state.read_signed_json(path, key) == ("ok", {"enabled": True})


def test_slow_nonblocking_os_lock_cannot_commit_after_total_deadline():
    with tempfile.TemporaryDirectory() as state:
        path = str(Path(state, "config.json"))
        key = b"state-lock-deadline-test-key-1234"
        if os.name == "nt":
            import msvcrt as lock_module
            lock_name, exclusive = "locking", lock_module.LK_NBLCK
        else:
            import fcntl as lock_module
            lock_name, exclusive = "flock", lock_module.LOCK_EX | lock_module.LOCK_NB
        real_lock = getattr(lock_module, lock_name)
        delayed = False

        def slow_lock(*args, **kwargs):
            nonlocal delayed
            if not delayed and args[1] == exclusive:
                delayed = True
                time.sleep(0.15)
            return real_lock(*args, **kwargs)

        status = {}
        with mock.patch.object(signed_state, "_LOCK_WAIT_SEC", 0.05), \
                mock.patch.object(lock_module, lock_name, side_effect=slow_lock):
            assert signed_state.write_signed_json(
                path, {"enabled": False}, key, status=status) is False
        assert delayed is True
        assert status.get("published") is False
        assert not Path(path).exists()

        assert signed_state.write_signed_json(path, {"enabled": True}, key) is True
        assert signed_state.read_signed_json(path, key) == ("ok", {"enabled": True})
