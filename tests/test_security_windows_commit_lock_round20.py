"""The cluster policy barrier must exclude a separate Windows writer."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import SkipTest

from dataplane.engine.core.commit_barrier import CommitFileLock


_CHILD = r'''
import sys
from dataplane.engine.core.commit_barrier import CommitFileLock
lock = CommitFileLock(sys.argv[1])
assert lock.verify_path()
if not lock.acquire(timeout=0.3):
    print("busy", flush=True)
    sys.exit(3)
print("held", flush=True)
if sys.argv[2] == "wait":
    sys.stdin.readline()
lock.release()
lock.close()
print("released", flush=True)
'''


def _env(state):
    env = dict(os.environ)
    env["DUCKNET_STATE_DIR"] = str(state)
    env["TEMP"] = env["TMP"] = str(state)
    root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_windows_commit_lock_excludes_other_process_and_recovers_after_crash():
    if os.name != "nt":
        raise SkipTest("Windows byte-range process lock test")
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        policy = str(state / "state.json")
        lock = CommitFileLock(policy)
        assert lock.verify_path()
        assert lock.acquire(timeout=1.0)
        try:
            busy = subprocess.run([sys.executable, "-c", _CHILD, policy, "release"],
                                  env=_env(state), capture_output=True, text=True,
                                  timeout=8)
            assert busy.returncode == 3 and busy.stdout.strip() == "busy", (
                busy.returncode, busy.stdout, busy.stderr)
        finally:
            lock.release()
            lock.close()

        free = subprocess.run([sys.executable, "-c", _CHILD, policy, "release"],
                              env=_env(state), capture_output=True, text=True,
                              timeout=8)
        assert free.returncode == 0 and free.stdout.splitlines() == ["held", "released"], (
            free.returncode, free.stdout, free.stderr)

        holder = subprocess.Popen([sys.executable, "-c", _CHILD, policy, "wait"],
                                  env=_env(state), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        try:
            assert holder.stdout.readline().strip() == "held"
            blocked = subprocess.run([sys.executable, "-c", _CHILD, policy, "release"],
                                     env=_env(state), capture_output=True, text=True,
                                     timeout=8)
            assert blocked.returncode == 3 and blocked.stdout.strip() == "busy", (
                blocked.returncode, blocked.stdout, blocked.stderr)
        finally:
            holder.kill()
            holder.wait(timeout=8)
            holder.stdin.close()
            holder.stdout.close()
            holder.stderr.close()
        recovered = subprocess.run([sys.executable, "-c", _CHILD, policy, "release"],
                                   env=_env(state), capture_output=True, text=True,
                                   timeout=8)
        assert recovered.returncode == 0 and recovered.stdout.splitlines() == ["held", "released"], (
            recovered.returncode, recovered.stdout, recovered.stderr)
