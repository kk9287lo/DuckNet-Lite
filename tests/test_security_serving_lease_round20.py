"""A state directory has one crash-released serving owner across processes."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import SkipTest

from dataplane.engine.core.serving_lease import ServingLease


ROOT = Path(__file__).resolve().parents[1]
CHILD = r'''
import json, sys
from dataplane.engine.core.serving_lease import ServingLease
lease = ServingLease(sys.argv[1])
if not lease.acquire(timeout=0.5):
    print(json.dumps({"held": False}), flush=True)
    sys.exit(3)
print(json.dumps({"held": lease.held, "verified": lease.verify_path()}), flush=True)
sys.stdin.readline()
lease.close()
'''


def _state():
    return tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"])


def _env(state):
    env = dict(os.environ)
    env["DUCKNET_STATE_DIR"] = str(state)
    env["TEMP"] = env["TMP"] = str(state)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _child(state):
    child = subprocess.Popen([sys.executable, "-B", "-c", CHILD, str(state)],
                             env=_env(state), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True)
    line = child.stdout.readline()
    if not line or json.loads(line) != {"held": True, "verified": True}:
        child.kill()
        _stdout, stderr = child.communicate(timeout=8)
        raise AssertionError((line, stderr))
    return child


def _terminate(child, *, crash=False):
    if child.poll() is None:
        if crash:
            child.kill()
        else:
            child.stdin.write("stop\n")
            child.stdin.flush()
        child.wait(timeout=8)
    child.stdin.close()
    child.stdout.close()
    child.stderr.close()


def test_serving_lease_excludes_another_process_until_clean_release():
    with _state() as directory:
        state = Path(directory)
        child = _child(state)
        try:
            contender = ServingLease(str(state))
            try:
                assert contender.acquire() is False
                assert contender.acquire(timeout=0.03) is False
            finally:
                contender.close()
        finally:
            _terminate(child)
        with ServingLease(str(state)) as recovered:
            assert recovered.held and recovered.verify_path()
            second = ServingLease(str(state))
            try:
                assert second.acquire() is False, "same-process alias cannot double-own"
            finally:
                second.close()


def test_serving_lease_recovers_after_holder_process_crash():
    with _state() as directory:
        state = Path(directory)
        child = _child(state)
        try:
            contender = ServingLease(str(state))
            try:
                assert contender.acquire() is False
            finally:
                contender.close()
        finally:
            _terminate(child, crash=True)
        with ServingLease(str(state)) as recovered:
            assert recovered.verify_path()


def test_serving_lease_refuses_reparse_lock_path():
    with _state() as directory:
        state = Path(directory)
        lock_path = state / ".ducknet-serving.lock"
        outside = state / "target"
        outside.write_bytes(b"target")
        try:
            lock_path.symlink_to(outside)
        except (OSError, NotImplementedError):
            raise SkipTest("file symlink unavailable")
        try:
            try:
                ServingLease(str(state))
            except OSError:
                pass
            else:
                assert False, "serving lock symlink was accepted"
        finally:
            lock_path.unlink()


def test_serving_lease_refuses_hardlinked_lock_file():
    with _state() as directory:
        state = Path(directory)
        target = state / "other-regular-file"
        target.write_bytes(b"keep")
        lock_path = state / ".ducknet-serving.lock"
        os.link(target, lock_path)
        try:
            try:
                ServingLease(str(state))
            except OSError:
                pass
            else:
                assert False, "hardlinked serving lock was accepted"
            assert target.read_bytes() == b"keep"
        finally:
            lock_path.unlink()


def test_serving_lease_detects_replaced_lock_path():
    with _state() as directory:
        state = Path(directory)
        lease = ServingLease(str(state))
        try:
            assert lease.acquire() is True
            old_path = state / "old-lock"
            try:
                (state / ".ducknet-serving.lock").rename(old_path)
            except PermissionError:
                raise SkipTest("open Windows lock cannot be renamed")
            (state / ".ducknet-serving.lock").write_bytes(b"replacement")
            assert lease.verify_path() is False
        finally:
            lease.close()


def test_serving_lease_refuses_reparse_state_directory():
    with _state() as directory:
        state = Path(directory)
        target = state / "target"
        target.mkdir()
        alias = state / "alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            raise SkipTest("directory symlink unavailable")
        try:
            try:
                ServingLease(str(alias))
            except OSError:
                pass
            else:
                assert False, "serving state directory alias was accepted"
        finally:
            alias.unlink()


def test_serving_lease_detects_changed_ancestor_alias():
    with _state() as directory:
        root = Path(directory)
        first = root / "first" / "state"
        second = root / "second" / "state"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        alias = root / "alias"
        try:
            alias.symlink_to(first.parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            raise SkipTest("directory symlink unavailable")
        lease = ServingLease(str(alias / "state"))
        try:
            assert lease.acquire() is True
            assert lease.verify_path()
            alias.unlink()
            alias.symlink_to(second.parent, target_is_directory=True)
            assert lease.verify_path() is False
        finally:
            lease.close()
            alias.unlink()


def test_posix_fork_child_closes_inherited_fd_without_unlocking_parent():
    if not hasattr(os, "fork"):
        raise SkipTest("POSIX fork required")
    with _state() as directory:
        state = Path(directory)
        lease = ServingLease(str(state))
        assert lease.acquire() is True
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                lease.close()  # inherited object must not unlock parent
                other = ServingLease(str(state))
                try:
                    busy = not other.acquire(timeout=0.05)
                finally:
                    other.close()
                os.write(write_fd, b"1" if busy else b"0")
            except BaseException:
                os.write(write_fd, b"E")
            finally:
                os._exit(0)
        os.close(write_fd)
        try:
            assert os.read(read_fd, 1) == b"1"
            os.waitpid(pid, 0)
            assert lease.held and lease.verify_path()
        finally:
            os.close(read_fd)
            lease.close()
