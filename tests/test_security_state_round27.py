"""Serving-owner deadlines, failed construction and fork descriptor ownership."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.core import commit_barrier, serving_lease


ROOT = Path(__file__).resolve().parents[1]


def _state():
    return tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"])


@contextmanager
def _busy_registry():
    ready, release = threading.Event(), threading.Event()

    def holder():
        with serving_lease._REGISTRY_LOCK:
            ready.set()
            assert release.wait(3), "test registry holder timed out"

    worker = threading.Thread(target=holder)
    worker.start()
    assert ready.wait(2)
    try:
        yield
    finally:
        release.set()
        worker.join(3)
        assert not worker.is_alive()


def test_nonblocking_acquire_does_not_wait_for_another_registry_thread():
    with _state() as state:
        lease = serving_lease.ServingLease(state)
        try:
            # Release automatically so a regressed implementation fails a
            # timing assertion rather than hanging the entire test runner.
            with _busy_registry():
                finished, result = threading.Event(), []

                def acquire():
                    result.append(lease.acquire(0))
                    finished.set()

                worker = threading.Thread(target=acquire)
                worker.start()
                completed_while_busy = finished.wait(.1)
            worker.join(2)
            assert completed_while_busy and result == [False], result
            assert lease.acquire(0) and lease.held
        finally:
            lease.close()


def test_positive_acquire_deadline_includes_registry_wait_and_os_busy():
    with _state() as state:
        lease = serving_lease.ServingLease(state)
        try:
            with _busy_registry():
                result, finished = [], threading.Event()

                def acquire():
                    result.append(lease.acquire(.03))
                    finished.set()

                worker = threading.Thread(target=acquire)
                worker.start()
                completed_within_budget = finished.wait(.12)
            worker.join(2)
            assert completed_within_budget and result == [False], result
            assert lease.acquire(.1)
            contender = serving_lease.ServingLease(state)
            try:
                started = time.monotonic()
                assert contender.acquire(.03) is False
                assert time.monotonic() - started < .15
            finally:
                contender.close()
        finally:
            lease.close()


def test_constructor_registry_deadline_precedes_descriptor_creation():
    with _state() as state:
        result, finished = [], threading.Event()

        def construct():
            try:
                lease = serving_lease.ServingLease(state)
                result.append(lease)
            except OSError as error:
                result.append(error)
            finally:
                finished.set()

        with patch.object(serving_lease, "_REGISTRY_WAIT_SEC", .03, create=True):
            with _busy_registry():
                worker = threading.Thread(target=construct)
                worker.start()
                completed_within_budget = finished.wait(.12)
                created_while_busy = (Path(state) / serving_lease._NAME).exists()
            worker.join(2)
        for value in result:
            if isinstance(value, serving_lease.ServingLease):
                value.close()
        assert completed_within_budget and len(result) == 1
        assert isinstance(result[0], OSError) and not created_while_busy
        with serving_lease.ServingLease(state) as lease:
            assert lease.held


def test_failed_registration_closes_the_open_descriptor():
    with _state() as state:
        opened = []
        original = serving_lease.ServingLease._open

        def remember(self):
            fd = original(self)
            opened.append(fd)
            return fd

        failing_registry = SimpleNamespace(add=lambda _lease: (_ for _ in ()).throw(
            RuntimeError("injected registration failure")))
        with patch.object(serving_lease.ServingLease, "_open", remember):
            with patch.object(serving_lease, "_INSTANCES", failing_registry):
                try:
                    serving_lease.ServingLease(state)
                except RuntimeError as error:
                    assert str(error) == "injected registration failure"
                else:
                    raise AssertionError("injected registration failure was ignored")
        assert len(opened) == 1
        try:
            os.fstat(opened[0])
        except OSError:
            pass
        else:
            os.close(opened[0])
            raise AssertionError("failed registration leaked the lease descriptor")
        with serving_lease.ServingLease(state) as lease:
            assert lease.held


def test_release_and_close_retire_without_waiting_for_registry_holder():
    with _state() as state:
        lease = serving_lease.ServingLease(state)
        assert lease.acquire()
        fd = lease._fd
        with _busy_registry():
            finished = threading.Event()

            def retire():
                lease.release()
                lease.close()
                finished.set()

            worker = threading.Thread(target=retire)
            worker.start()
            completed_while_busy = finished.wait(.12)
            logically_held = lease.held
        worker.join(2)
        assert completed_while_busy and not logically_held
        assert lease._fd is None and lease.path not in serving_lease._ACTIVE
        assert lease not in serving_lease._INSTANCES
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            raise AssertionError("deferred close was not drained at registry release")
        with serving_lease.ServingLease(state) as recovered:
            assert recovered.held


def test_failed_os_acquisition_clears_reservation_and_preserves_next_owner():
    with _state() as state:
        lease = serving_lease.ServingLease(state)
        try:
            for failure in (False, OSError("injected OS lock failure")):
                with patch.object(lease, "_try_os_lock", **(
                        {"side_effect": failure} if isinstance(failure, OSError)
                        else {"return_value": failure})):
                    try:
                        result = lease.acquire()
                    except OSError:
                        assert isinstance(failure, OSError)
                    else:
                        assert result is False and failure is False
                assert lease.path not in serving_lease._ACTIVE
            assert lease.acquire()
            lease.release()
            assert not lease.held
            assert lease.acquire(.1)
            # A delayed release from an earlier generation must not unlock
            # the newly acquired lease or drop another object's reservation.
            old_generation = lease._generation - 1
            with serving_lease._REGISTRY_LOCK:
                lease._retire(old_generation, False)
            assert lease.held and serving_lease._ACTIVE[lease.path] is lease
        finally:
            lease.close()


FORK_ACTOR = r'''
import json, os, sys, threading, time
from pathlib import Path
from types import SimpleNamespace
from dataplane.engine.core import commit_barrier, serving_lease
state = Path(sys.argv[1])
def wait_file(path, timeout=8):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(str(path))
        time.sleep(.005)
ready, release = threading.Event(), threading.Event()
leases, errors = [], []
original = serving_lease.ServingLease._open
def pause_open(self):
    fd = original(self)
    ready.set()
    if not release.wait(6):
        os.close(fd)
        raise TimeoutError("paused open not released")
    return fd
serving_lease.ServingLease._open = pause_open
def construct():
    try:
        leases.append(serving_lease.ServingLease(str(state)))
    except BaseException as error:
        errors.append(repr(error))
worker = threading.Thread(target=construct)
worker.start()
assert ready.wait(3)
shield = SimpleNamespace(_lock=threading.RLock())
firewall = SimpleNamespace(_lock=threading.RLock())
commit_barrier.WAIT_SEC = .04
blocked = False
try:
    held = commit_barrier.freeze_fork(shield, firewall)
except TimeoutError:
    blocked = True
    release.set()
    worker.join(3)
    assert len(leases) == 1 and not errors, errors
    held = commit_barrier.freeze_fork(shield, firewall)
child = os.fork()
if child == 0:
    try:
        commit_barrier.thaw_child(shield, firewall)
        wait_file(state / "parent-ready.json")
        (state / "child-ready").write_text("ready")
        wait_file(state / "release-child")
    finally:
        (state / "child-done").write_text("done")
        os._exit(0)
commit_barrier.thaw_parent(held)
release.set()
worker.join(3)
assert len(leases) == 1 and not errors, errors
result = {"window_blocked": blocked, "child": child,
          "parent_acquired": leases[0].acquire(0)}
pending = state / "parent-ready.json.tmp"
pending.write_text(json.dumps(result))
os.replace(pending, state / "parent-ready.json")
time.sleep(15)
'''


def _wait_file(path, timeout=6):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(str(path))
        time.sleep(.005)


def test_posix_fork_cannot_inherit_an_open_unregistered_serving_descriptor():
    if not hasattr(os, "fork"):
        raise SkipTest("POSIX fork required")
    with _state() as state:
        folder = Path(state)
        env = dict(os.environ, DUCKNET_STATE_DIR=state, TEMP=state, TMP=state,
                   PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
        owner = subprocess.Popen([sys.executable, "-B", "-c", FORK_ACTOR, state],
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child = None
        try:
            _wait_file(folder / "parent-ready.json")
            _wait_file(folder / "child-ready")
            result = json.loads((folder / "parent-ready.json").read_text())
            child = result["child"]
            owner.kill()
            owner.wait(timeout=3)
            contender = serving_lease.ServingLease(state)
            try:
                after_parent_death = contender.acquire(.1)
            finally:
                contender.close()
            (folder / "release-child").write_text("release")
            _wait_file(folder / "child-done")
            with serving_lease.ServingLease(state) as recovered:
                assert recovered.held
            assert result["parent_acquired"] is True
            assert result["window_blocked"] and after_parent_death, result
        finally:
            (folder / "release-child").write_text("release")
            if owner.poll() is None:
                owner.kill()
            if child is not None:
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            _stdout, errors = owner.communicate(timeout=10)
            assert not errors, errors.decode("utf-8", "replace")
