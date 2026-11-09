"""Nonwaiting diagnostics and serialized durable audit writes."""

import json
import os
import tempfile
import threading

from dataplane.engine.core import atomic_io as aio


def _contended_append(path, lock, *, wait):
    started = threading.Event()
    done = threading.Event()
    result = []

    def append():
        started.set()
        result.append(aio.append_jsonl(path, {"row": "benign"}, wait=wait))
        done.set()

    lock.acquire()
    worker = threading.Thread(target=append)
    worker.start()
    try:
        assert started.wait(2)
        completed_while_held = done.wait(0.3)
    finally:
        lock.release()
        worker.join(3)
    assert not worker.is_alive(), "diagnostic writer leaked"
    return completed_while_held, result


def test_nonwaiting_append_does_not_wait_for_path_mutex():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "usage.jsonl")
        completed, result = _contended_append(path, aio._append_lock(path), wait=False)
        assert completed, "wait=False blocked on the path mutex"
        assert result == [False] and not os.path.exists(path)
        assert aio.append_jsonl(path, {"row": "next"}, wait=False)
        with open(path, encoding="utf-8") as handle:
            assert [json.loads(line) for line in handle] == [{"row": "next"}]


def test_nonwaiting_append_does_not_wait_for_lock_table_mutex():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "usage.jsonl")
        completed, result = _contended_append(path, aio._APPEND_LOCKS_GUARD, wait=False)
        assert completed, "wait=False blocked on the mutex table"
        assert result == [False] and not os.path.exists(path)


def test_waiting_audit_append_preserves_row_after_contention():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "audit.jsonl")
        completed, result = _contended_append(path, aio._append_lock(path), wait=True)
        assert not completed, "durable audit bypassed the path mutex"
        assert result == [True]
        with open(path, encoding="utf-8") as handle:
            assert [json.loads(line) for line in handle] == [{"row": "benign"}]


def test_nonwaiting_append_failure_releases_mutex_and_keeps_rotation_serial():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "usage.jsonl")
        assert not aio.append_jsonl(path, {"row": object()}, wait=False)
        assert aio.append_jsonl(path, {"row": "old"}, max_bytes=24, wait=False)
        assert aio.append_jsonl(path, {"row": "new"}, max_bytes=24, wait=False)
        assert aio.append_jsonl(path, {"row": "end"}, max_bytes=24, wait=True)
        with open(path + ".1", encoding="utf-8") as handle:
            assert json.load(handle) == {"row": "new"}
        with open(path, encoding="utf-8") as handle:
            assert json.load(handle) == {"row": "end"}
