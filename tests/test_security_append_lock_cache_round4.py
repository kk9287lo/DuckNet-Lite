"""Temporary append paths release mutex handles without losing log rows."""

import gc
import json
import os
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch

from dataplane.engine.core import atomic_io as aio


def _windows_handles():
    if os.name != "nt":
        return None
    import ctypes
    kernel = ctypes.windll.kernel32
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_ulong)]
    kernel.GetProcessHandleCount.restype = ctypes.c_int
    count = ctypes.c_ulong()
    assert kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(count))
    return count.value


def test_distinct_append_paths_do_not_retain_mutex_handles():
    with tempfile.TemporaryDirectory() as directory:
        warm = Path(directory) / "warm.jsonl"
        assert aio.append_jsonl(str(warm), {"n": -1}) is True
        gc.collect()
        baseline_cache = len(aio._APPEND_LOCKS)
        baseline_handles = _windows_handles()
        for index in range(64):
            path = Path(directory) / f"ephemeral-{index}.jsonl"
            row = {"n": index}
            assert aio.append_jsonl(str(path), row) is True
            assert path.read_bytes() == (json.dumps(row, ensure_ascii=False)
                                         + os.linesep).encode()
        gc.collect()
        cache_growth = len(aio._APPEND_LOCKS) - baseline_cache
        handle_growth = (_windows_handles() - baseline_handles
                         if baseline_handles is not None else 0)
        assert cache_growth <= 1 and handle_growth <= 8, (cache_growth, handle_growth)


def test_same_append_path_serializes_concurrent_exact_rows():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        workers, rounds = 8, 16
        start = threading.Barrier(workers)
        failures = []

        def append(worker):
            try:
                start.wait(timeout=3)
                for index in range(rounds):
                    if aio.append_jsonl(str(path), {"worker": worker, "index": index},
                                       max_bytes=1 << 20) is not True:
                        failures.append((worker, index))
            except BaseException as exc:
                failures.append(repr(exc))

        threads = [threading.Thread(target=append, args=(worker,))
                   for worker in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in threads)
        assert not failures, failures
        wire = path.read_bytes()
        lines = wire.splitlines(keepends=True)
        expected = {(worker, index) for worker in range(workers) for index in range(rounds)}
        assert len(lines) == len(expected) and all(line.endswith(b"\n") for line in lines)
        records = list(map(json.loads, lines))
        assert {(row["worker"], row["index"]) for row in records} == expected
        assert wire == b"".join((json.dumps(row, ensure_ascii=False) + os.linesep).encode()
                                 for row in records)


def test_failed_append_releases_lock_and_next_write_has_only_its_own_bytes():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.jsonl"
        with patch.object(aio, "_open_append_nofollow", side_effect=OSError("injected open")):
            assert aio.append_jsonl(str(path), {"row": "failed"}, wait=False) is False
        assert aio.append_jsonl(str(path), {"row": "kept"}, wait=False) is True
        assert path.read_bytes() == b'{"row": "kept"}' + os.linesep.encode()
