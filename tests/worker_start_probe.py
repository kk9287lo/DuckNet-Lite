"""Test-only child lifecycle probe for the shared diagnostic worker.

The child imports DuckNet only after the parent runner has isolated state.
READY ends the interpreter/import phase; GO starts a separate five-second
worker-operation deadline. No product code or external service is changed.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time


_READY = b"READY\n"
_STDERR_TAIL = 64 * 1024
_REAP_TIMEOUT = 2.0


def _mark(label: str) -> None:
    print("PHASE " + label, file=sys.stderr, flush=True)


def _child_main() -> None:
    _mark("python-first")
    import faulthandler
    startup_stack_after = float(os.environ.get("DUCKNET_WORKER_PROBE_STARTUP_STACK_AFTER", "4"))
    faulthandler.dump_traceback_later(startup_stack_after, file=sys.stderr)
    delay = float(os.environ.get("DUCKNET_WORKER_PROBE_STARTUP_DELAY", "0"))
    if delay > 0:
        time.sleep(delay)
    _mark("import-before")
    if os.environ.get("DUCKNET_WORKER_PROBE_IMPORT_FAIL") == "1":
        raise RuntimeError("synthetic import failure")
    import asyncio
    from unittest.mock import patch
    import dataplane.engine.services.proxy as proxy
    _mark("import-ready")
    sys.stdout.buffer.write(_READY)
    sys.stdout.buffer.flush()
    if sys.stdin.buffer.read(1) != b"G":
        raise RuntimeError("missing parent GO")
    _mark("worker-begin")
    faulthandler.cancel_dump_traceback_later()
    stack_after = float(os.environ.get("DUCKNET_WORKER_PROBE_STACK_AFTER", "4"))
    faulthandler.dump_traceback_later(stack_after, file=sys.stderr)

    class Shield:
        def write_usage_log(self, work):
            return True

    async def go():
        guard = proxy.AsyncEdgeGuard()
        mode = os.environ.get("DUCKNET_WORKER_PROBE_MODE", "normal")
        if mode == "assert_fail":
            raise AssertionError("synthetic worker assertion failure")

        def fail_start():
            if mode == "work_stall":
                time.sleep(60)
            raise RuntimeError("no thread")

        _mark("submit-before")
        with patch.object(proxy.threading.Thread, "start", side_effect=fail_start):
            assert guard._submit_usage_log(Shield(), "safe") is None
        _mark("submit-after")
        assert guard._usage_pending == 0 and not proxy._USAGE_QUEUE
        assert guard.metrics.get("usage_log_write_failed") == 1
        _mark("stop-before")
        assert guard.stop()["stopped"] is True
        _mark("stop-after")

    try:
        asyncio.run(go())
    finally:
        faulthandler.cancel_dump_traceback_later()
    _mark("complete")


def _stderr_tail(stream) -> str:
    stream.flush()
    stream.seek(0, os.SEEK_END)
    stream.seek(max(0, stream.tell() - _STDERR_TAIL))
    return stream.read(_STDERR_TAIL).decode("utf-8", "replace")


def run_probe(*, startup_delay: float = 0.0, startup_timeout: float = 8.0,
              worker_timeout: float = 5.0, mode: str = "normal",
              import_fail: bool = False) -> dict:
    """Run one owned child with independently bounded startup and work phases."""
    if (mode not in ("normal", "work_stall", "assert_fail")
            or not all(type(v) in (int, float) and math.isfinite(v) for v in
                       (startup_delay, startup_timeout, worker_timeout))
            or startup_delay < 0 or startup_timeout <= 0 or worker_timeout <= 0):
        raise ValueError("invalid worker probe options")
    env = os.environ.copy()
    env["DUCKNET_WORKER_PROBE_STARTUP_DELAY"] = str(startup_delay)
    env["DUCKNET_WORKER_PROBE_MODE"] = mode
    env["DUCKNET_WORKER_PROBE_IMPORT_FAIL"] = "1" if import_fail else "0"
    env["DUCKNET_WORKER_PROBE_STARTUP_STACK_AFTER"] = str(max(0.01, startup_timeout * 0.5))
    env["DUCKNET_WORKER_PROBE_STACK_AFTER"] = str(max(0.01, worker_timeout * 0.5))
    root = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
    started = time.monotonic()
    with tempfile.TemporaryFile(mode="w+b") as stderr:
        proc = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "--child"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                                cwd=str(root), env=env, bufsize=0)
        first = {}

        def read_ready():
            try:
                first["line"] = proc.stdout.readline(128)
            except (OSError, ValueError) as exc:
                first["error"] = repr(exc)
            finally:
                # The only stdout reader owns its close, including timeout cleanup.
                # Closing a pipe from another thread while it is reading can block.
                proc.stdout.close()

        reader = threading.Thread(target=read_ready, daemon=True,
                                  name="ducknet-test-child-ready")
        outcome = "startup_failed"
        reader_started = False
        try:
            try:
                reader.start()
                reader_started = True
            except (RuntimeError, OSError) as exc:
                first["error"] = repr(exc)
                outcome = "reader_failed"
            if reader_started:
                reader.join(timeout=startup_timeout)
            if reader_started and reader.is_alive():
                outcome = "startup_timeout"
            elif reader_started and first.get("error"):
                outcome = "reader_failed"
            elif reader_started and first.get("line") == _READY:
                try:
                    # The fixed child consumes exactly one GO byte and emits no
                    # further stdout. Avoid communicate's hidden reader threads
                    # on Windows, especially when the worker deadline expires.
                    proc.stdin.write(b"G")
                    proc.stdin.close()
                    proc.wait(timeout=worker_timeout)
                    outcome = "complete" if proc.returncode == 0 else "worker_failed"
                except subprocess.TimeoutExpired:
                    outcome = "worker_timeout"
                except (OSError, ValueError):
                    outcome = "worker_failed"
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=_REAP_TIMEOUT)
            except subprocess.TimeoutExpired:
                outcome = "reap_failed"
            if reader_started:
                reader.join(timeout=_REAP_TIMEOUT)
            if reader_started and reader.is_alive():
                outcome = "reader_failed"
            if proc.stdin is not None:
                proc.stdin.close()
            if not reader_started:
                proc.stdout.close()
        details = _stderr_tail(stderr)
    phases = [match[1] for line in details.splitlines()
              if (match := re.fullmatch(r"PHASE ([a-z-]+)", line))]
    complete = (outcome == "complete" and proc.returncode == 0
                and "submit-after" in phases and "stop-after" in phases
                and "complete" in phases)
    if outcome == "complete" and not complete:
        outcome = "worker_failed"
    return {"ok": complete, "phase": outcome, "last_phase": phases[-1] if phases else "",
            "phases": phases, "returncode": proc.returncode,
            "reaped": proc.poll() is not None and not reader.is_alive(),
            "seconds": round(time.monotonic() - started, 3),
            "stdout_tail": first.get("line", b"")[-4096:].decode("utf-8", "replace"),
            "reader_error": first.get("error", ""),
            "stderr_tail": details}


if __name__ == "__main__" and "--child" in sys.argv:
    _child_main()
