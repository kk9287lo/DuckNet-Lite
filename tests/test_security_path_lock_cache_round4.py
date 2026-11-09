"""Short-lived state paths must release OS lock handles after use."""

import gc
import os
from pathlib import Path
import tempfile
import threading
import time

from dataplane.engine.core import signed_state as ss


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


def test_distinct_short_lived_state_paths_do_not_retain_lock_handles():
    with tempfile.TemporaryDirectory() as directory:
        # Warm one state guard and the Windows handle-count API before the
        # baseline so one-time runtime initialization does not affect it.
        with ss._state_guard(str(Path(directory) / "warm.json")) as locked:
            assert locked
        gc.collect()
        baseline_cache = len(ss._PATH_LOCKS)
        baseline_handles = _windows_handles()
        for index in range(64):
            path = Path(directory) / f"ephemeral-{index}.json"
            with ss._state_guard(str(path)) as locked:
                assert locked
        gc.collect()
        cache_growth = len(ss._PATH_LOCKS) - baseline_cache
        handle_growth = (_windows_handles() - baseline_handles
                         if baseline_handles is not None else 0)
        assert cache_growth <= 1 and handle_growth <= 8, (cache_growth, handle_growth)


def test_same_state_path_waiters_share_one_lock_and_preserve_updates():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "counter.txt"
        path.write_text("0", encoding="ascii")
        workers, rounds = 8, 4
        start = threading.Barrier(workers)
        failures = []

        def increment():
            try:
                start.wait(timeout=3)
                for _ in range(rounds):
                    with ss._state_guard(str(path)) as locked:
                        if not locked:
                            failures.append("lock timeout")
                            return
                        old = int(path.read_text(encoding="ascii"))
                        time.sleep(0.002)
                        path.write_text(str(old + 1), encoding="ascii")
            except BaseException as exc:
                failures.append(repr(exc))

        threads = [threading.Thread(target=increment) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in threads)
        assert not failures, failures
        assert int(path.read_text(encoding="ascii")) == workers * rounds
