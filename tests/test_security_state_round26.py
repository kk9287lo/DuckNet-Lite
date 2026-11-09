"""Audit append targets and lock generations must retain a unique identity."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest import SkipTest, mock

from dataplane.engine.core import atomic_io
from dataplane.engine.core import commit_barrier


def _case():
    return tempfile.TemporaryDirectory(prefix="ducknet-r26-state-", dir=os.environ["DUCKNET_STATE_DIR"])


def _hardlink(source, destination):
    try:
        os.link(source, destination)
    except (OSError, NotImplementedError) as error:
        raise SkipTest("hardlinks unavailable on the test filesystem") from error


def test_hardlinked_audit_target_cannot_modify_an_unrelated_file():
    with _case() as folder:
        root = Path(folder)
        victim, log = root / "separate.jsonl", root / "admin_audit.jsonl"
        before = b'{"existing":"keep"}\n'
        victim.write_bytes(before)
        _hardlink(victim, log)
        assert atomic_io.append_jsonl(str(log), {"unexpected": "audit append"}) is False
        assert victim.read_bytes() == log.read_bytes() == before

        log.unlink()
        assert atomic_io.append_jsonl(str(log), {"accepted": "ordinary audit"}) is True
        assert json.loads(log.read_text(encoding="utf-8")) == {"accepted": "ordinary audit"}
        assert victim.read_bytes() == before


def test_hardlinked_append_lock_cannot_claim_a_safe_audit_commit():
    with _case() as folder:
        root = Path(folder)
        victim, log = root / "unrelated.lock", root / "admin_audit.jsonl"
        victim.write_bytes(b"private lock target")
        _hardlink(victim, Path(str(log) + ".append.lock"))
        assert atomic_io.append_jsonl(str(log), {"value": "must not publish"}) is False
        assert not log.exists()
        assert victim.read_bytes() == b"private lock target"


_WORKER = r'''
import json,os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from dataplane.engine.core import atomic_io
log,ready,release,label=map(Path,sys.argv[2:6])
mode=sys.argv[6] if len(sys.argv)>6 else 'check'
original=atomic_io._complete_jsonl_tail
def gate():
    ready.write_text('ready')
    deadline=time.monotonic()+10
    while not release.exists():
        if time.monotonic()>=deadline:raise TimeoutError('fixture gate expired')
        time.sleep(.005)
def checked(fd):
    valid=original(fd)
    gate()
    return valid
if mode=='check':atomic_io._complete_jsonl_tail=checked
elif mode=='write':
    original_open=atomic_io._open_append_nofollow
    class PausedWrite:
        def __init__(self,file):self.file=file
        def __getattr__(self,key):return getattr(self.file,key)
        def __enter__(self):self.file.__enter__();return self
        def __exit__(self,*args):return self.file.__exit__(*args)
        def write(self,raw):gate();return self.file.write(raw)
    atomic_io._open_append_nofollow=lambda *args,**kwargs:PausedWrite(original_open(*args,**kwargs))
result=atomic_io.append_jsonl(str(log),{'kind':str(label),'padding':'x'*20},max_bytes=64,wait=mode!='none')
print(json.dumps({'accepted':result}),flush=True)
'''


def _wait_file(path, process, *, allow_exit=False):
    deadline = time.monotonic() + 8
    while not path.exists():
        if process.poll() is not None:
            if allow_exit:
                return False
            out, error = process.communicate()
            raise AssertionError((process.returncode, out, error))
        if time.monotonic() >= deadline:
            raise AssertionError("audit worker never reached the real append gate")
        time.sleep(0.005)
    return True


def test_replaced_append_lock_cannot_split_processes_and_overrun_log_capacity():
    if os.name != "posix":
        raise SkipTest("unlinking an open lock inode requires POSIX")
    with _case() as folder:
        root = Path(folder)
        log = root / "admin_audit.jsonl"
        log.write_bytes(b"{}\n")
        project = str(Path(__file__).resolve().parents[1])
        first = subprocess.Popen([sys.executable, "-c", _WORKER, project, str(log),
                                  str(root / "ready-a"), str(root / "release-a"), "A"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        second = None
        try:
            _wait_file(root / "ready-a", first)
            Path(str(log) + ".append.lock").unlink()
            second = subprocess.Popen([sys.executable, "-c", _WORKER, project, str(log),
                                       str(root / "ready-b"), str(root / "release-b"), "B", "none"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            b_out, b_error = second.communicate(timeout=8)
            (root / "release-a").write_text("release")
            a_out, a_error = first.communicate(timeout=8)
            assert first.returncode == second.returncode == 0, (a_error, b_error)
            accepted = [json.loads(a_out)["accepted"], json.loads(b_out)["accepted"]]
            rows = [json.loads(row) for row in log.read_text(encoding="utf-8").splitlines()]
            assert accepted == [False, False], {"accepted": accepted, "bytes": log.stat().st_size,
                                               "limit": 64, "rows": rows}
            assert rows == [{}], rows
            assert atomic_io.append_jsonl(str(log), {"recovered": True}, max_bytes=64)
            assert log.stat().st_size <= 64
        finally:
            for label in ("a", "b"):
                (root / ("release-" + label)).write_text("release")
            for child in (first, second):
                if child is not None:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=8)


def test_pause_after_last_check_still_keeps_real_log_inode_locked():
    if os.name != "posix":
        raise SkipTest("unlinking an open lock inode requires POSIX")
    with _case() as folder:
        root = Path(folder)
        log = root / "admin_audit.jsonl"
        log.write_bytes(b"{}\n")
        project = str(Path(__file__).resolve().parents[1])
        first = subprocess.Popen([sys.executable, "-c", _WORKER, project, str(log),
                                  str(root / "ready-a"), str(root / "release-a"), "A", "write"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        second = None
        try:
            _wait_file(root / "ready-a", first)
            Path(str(log) + ".append.lock").unlink()
            second = subprocess.Popen([sys.executable, "-c", _WORKER, project, str(log),
                                       str(root / "unused-ready"), str(root / "unused-release"), "B", "none"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            b_out, b_error = second.communicate(timeout=8)
            (root / "release-a").write_text("release")
            a_out, a_error = first.communicate(timeout=8)
            assert first.returncode == second.returncode == 0, (a_error, b_error)
            accepted = [json.loads(a_out)["accepted"], json.loads(b_out)["accepted"]]
            assert accepted == [True, False], {"accepted": accepted, "bytes": log.stat().st_size}
            assert log.stat().st_size <= 64
            assert [json.loads(row) for row in log.read_text().splitlines()] == [
                {}, {"kind": "A", "padding": "x" * 20}]
        finally:
            (root / "release-a").write_text("release")
            for child in (first, second):
                if child is not None:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=8)


def test_special_log_and_lock_targets_fail_without_blocking():
    if os.name != "posix":
        raise SkipTest("real FIFO rejection requires POSIX")
    with _case() as folder:
        root = Path(folder)
        project = str(Path(__file__).resolve().parents[1])
        for suffix in ("", ".append.lock"):
            log = root / ("log" if not suffix else "lock")
            os.mkfifo(str(log) + suffix)
            child = subprocess.Popen([sys.executable, "-c",
                                      "import sys;sys.path.insert(0,sys.argv[1]);"
                                      "from dataplane.engine.core.atomic_io import append_jsonl;"
                                      "print(append_jsonl(sys.argv[2],{'probe':True}),flush=True)",
                                      project, str(log)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                output, error = child.communicate(timeout=3)
                assert child.returncode == 0 and output.strip() == "False", (output, error)
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=3)
        victim, log = root / "original.jsonl", root / "symlink.jsonl"
        victim.write_bytes(b'{"kept":true}\n')
        log.symlink_to(victim)
        assert atomic_io.append_jsonl(str(log), {"separate": True})
        assert not log.is_symlink() and victim.read_bytes() == b'{"kept":true}\n'


_FORK_CACHE = r'''
import json,os,sys,threading,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
from dataplane.engine.core import atomic_io,commit_barrier
root=Path(sys.argv[2]);log=str(root/'fork-cache.jsonl')
ready,release=threading.Event(),threading.Event()
def hold():
    with atomic_io._APPEND_LOCKS_GUARD:
        ready.set();release.wait(10)
thread=threading.Thread(target=hold);thread.start();assert ready.wait(2)
shield,firewall=SimpleNamespace(_lock=threading.RLock()),SimpleNamespace(_lock=threading.RLock())
held=commit_barrier.freeze_fork(shield,firewall);pid=os.fork()
if not pid:
    commit_barrier.thaw_child(shield,firewall)
    first=atomic_io.append_jsonl(log,{'child':1},wait=False);time.sleep(.05)
    second=atomic_io.append_jsonl(log,{'child':2},wait=False)
    (root/'cache-child.json').write_text(json.dumps([first,second]));os._exit(0)
commit_barrier.thaw_parent(held);release.set();thread.join(2);os.waitpid(pid,0)
print(json.dumps({'child':json.loads((root/'cache-child.json').read_text()),
                 'parent':atomic_io.append_jsonl(log,{'parent':True})}),flush=True)
'''


def test_fork_child_replaces_a_mutex_held_by_a_vanished_log_thread():
    if not hasattr(os, "fork"):
        raise SkipTest("real fork lock recovery requires POSIX")
    with _case() as folder:
        result = subprocess.run([sys.executable, "-c", _FORK_CACHE,
                                 str(Path(__file__).resolve().parents[1]), folder],
                                capture_output=True, text=True, timeout=12)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"child": [True, True], "parent": True}


_FORK_OWNER = r'''
import json,os,sys,threading,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
from dataplane.engine.core import atomic_io,commit_barrier
root=Path(sys.argv[2]);log=str(root/'fork-owner.jsonl')
def publish(name,value):
    pending=root/(name+'.tmp')
    pending.write_text(json.dumps(value))
    os.replace(pending,root/name)
gate=threading.Event();original=atomic_io._open_append_nofollow
class Paused:
    def __init__(self,file):self.file=file
    def __getattr__(self,key):return getattr(self.file,key)
    def __enter__(self):self.file.__enter__();return self
    def __exit__(self,*args):return self.file.__exit__(*args)
    def write(self,raw):gate.set();time.sleep(25);return self.file.write(raw)
atomic_io._open_append_nofollow=lambda *args,**kwargs:Paused(original(*args,**kwargs))
thread=threading.Thread(target=lambda:atomic_io.append_jsonl(log,{'parent':True}))
thread.start();assert gate.wait(3)
shield,firewall=SimpleNamespace(_lock=threading.RLock()),SimpleNamespace(_lock=threading.RLock())
held=commit_barrier.freeze_fork(shield,firewall);owner=os.getpid();pid=os.fork()
if not pid:
    commit_barrier.thaw_child(shield,firewall)
    atomic_io._open_append_nofollow=original
    first=atomic_io.append_jsonl(log,{'probe':'parent still owns lock'},wait=False)
    publish('owner-child.json',{'pid':os.getpid(),'first':first})
    deadline=time.monotonic()+12
    while not (root/'owner-reaped').exists() and time.monotonic()<deadline:time.sleep(.005)
    assert (root/'owner-reaped').exists(), 'owner was not reaped before recovery probe'
    second=atomic_io.append_jsonl(log,{'probe':'parent exited'},wait=False)
    publish('owner-result.json',{'after_exit':second})
    os._exit(0)
commit_barrier.thaw_parent(held)
time.sleep(25)
'''


def test_fork_copy_neither_unlocks_parent_nor_strands_its_lock_after_sigkill():
    if not hasattr(os, "fork"):
        raise SkipTest("real fork/SIGKILL lock recovery requires POSIX")
    with _case() as folder:
        root = Path(folder)
        owner = subprocess.Popen([sys.executable, "-c", _FORK_OWNER,
                                  str(Path(__file__).resolve().parents[1]), folder],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        child_pid = None
        try:
            _wait_file(root / "owner-child.json", owner)
            child = json.loads((root / "owner-child.json").read_text())
            child_pid = child["pid"]
            assert child["first"] is False, "fork child unlocked its live parent's OS lock"
            owner.kill()
            owner.wait(timeout=8)  # Reparenting can precede the last sibling thread's fd close.
            (root / "owner-reaped").write_text("all owner threads exited")
            deadline = time.monotonic() + 8
            while not (root / "owner-result.json").exists():
                if time.monotonic() >= deadline:
                    raise AssertionError("fork child could not recover after the log owner exited")
                time.sleep(0.005)
            assert json.loads((root / "owner-result.json").read_text()) == {"after_exit": True}
            assert [json.loads(line) for line in (root / "fork-owner.jsonl").read_text().splitlines()] == [
                {"probe": "parent exited"}]
        finally:
            if owner.poll() is None:
                owner.kill()
            if child_pid is not None:
                if not (root / "owner-result.json").exists():
                    try:
                        import signal
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.waitpid(child_pid, 0)  # PID1 test containers adopt the orphan.
                except ChildProcessError:
                    pass
            owner.communicate(timeout=8)


def test_append_fd_registry_contention_cannot_make_fork_freeze_unbounded():
    held, release = threading.Event(), threading.Event()
    guard = getattr(atomic_io, "_APPEND_FD_GUARD", threading.RLock())

    def retain():
        with guard:
            held.set()
            release.wait(3)

    owner = threading.Thread(target=retain)
    owner.start()
    assert held.wait(1)
    shield, firewall = SimpleNamespace(_lock=threading.RLock()), SimpleNamespace(_lock=threading.RLock())
    try:
        started = time.monotonic()
        rejected = False
        with mock.patch.object(commit_barrier, "WAIT_SEC", 0.05):
            try:
                locks = commit_barrier.freeze_fork(shield, firewall)
            except TimeoutError:
                rejected = True
            else:
                commit_barrier.thaw_parent(locks)
        assert rejected and time.monotonic() - started < 1
    finally:
        release.set()
        owner.join(3)
    locks = commit_barrier.freeze_fork(shield, firewall)
    commit_barrier.thaw_parent(locks)
    assert not owner.is_alive()


def test_append_registry_entry_honors_nonwaiting_and_total_wait_budget():
    with _case() as folder:
        for wait in (False, True):
            path = Path(folder, "wait-" + str(wait) + ".jsonl")
            started, done = threading.Event(), threading.Event()
            result = {}

            def append():
                started.set()
                before = time.monotonic()
                result["accepted"] = atomic_io.append_jsonl(str(path), {"record": True}, wait=wait)
                result["elapsed"] = time.monotonic() - before
                done.set()

            atomic_io._APPEND_FD_GUARD.acquire()
            worker = threading.Thread(target=append, daemon=True)
            try:
                with mock.patch.object(atomic_io, "_APPEND_FILE_WAIT_SEC", 0.05):
                    worker.start()
                    assert started.wait(1)
                    assert done.wait(0.15), "append queued behind the descriptor registry"
                    assert result["accepted"] is False and result["elapsed"] < 0.14
                    assert not path.exists()
            finally:
                atomic_io._APPEND_FD_GUARD.release()
                worker.join(3)
            assert not worker.is_alive()
            assert atomic_io.append_jsonl(str(path), {"recovered": True}, wait=wait)


def test_descriptor_retirement_defers_without_wait_and_drains_on_gate_release():
    with _case() as folder:
        for wait in (False, True):
            file = atomic_io._open_append_nofollow(str(Path(folder, "close-" + str(wait))),
                                                  "utf-8", wait=wait,
                                                  deadline=time.monotonic() + 0.05 if wait else None)
            fd, token = file.fileno(), file._owner
            held, release = threading.Event(), threading.Event()

            def hold():
                with atomic_io._APPEND_FD_GUARD:
                    held.set()
                    release.wait(3)

            gate_owner = threading.Thread(target=hold)
            gate_owner.start()
            assert held.wait(1)
            try:
                before = time.monotonic()
                file.close()
                file.close()  # duplicate retirement cannot grow the queue forever
                assert time.monotonic() - before < 0.14
                assert not file.closed and atomic_io._APPEND_OPEN_FDS.get(fd) is token
            finally:
                release.set()
                gate_owner.join(3)
            assert file.closed and token.closed and fd not in atomic_io._APPEND_OPEN_FDS
            replacement = atomic_io._open_append_nofollow(str(Path(folder, "replacement-" + str(wait))), "utf-8")
            try:
                atomic_io._APPEND_PENDING_CLOSE.put(token)
                with atomic_io._APPEND_FD_GUARD:
                    pass
                os.fstat(replacement.fileno())  # old token must not close a reused descriptor
                assert not replacement.closed
            finally:
                replacement.close()


def test_rejected_lock_identity_unlocks_before_deferred_descriptor_retirement():
    with _case() as folder:
        path = str(Path(folder, "identity.jsonl"))
        checked, held, release, done = (threading.Event() for _ in range(4))
        original = atomic_io._unique_regular_file
        visits, returned = [], []

        def inspect(fd, named):
            if named == path + ".append.lock":
                visits.append(fd)
                if len(visits) == 2:
                    checked.set()
                    assert held.wait(2)
                    return False
            return original(fd, named)

        def retain():
            assert checked.wait(2)
            with atomic_io._APPEND_FD_GUARD:
                held.set()
                release.wait(4)

        def rejected():
            returned.append(atomic_io._append_file_lock(path, wait=False, deadline=None))
            done.set()

        holder, writer = threading.Thread(target=retain), threading.Thread(target=rejected)
        try:
            with mock.patch.object(atomic_io, "_unique_regular_file", side_effect=inspect):
                holder.start()
                writer.start()
                assert done.wait(2), "identity rejection waited indefinitely during close"
                assert returned == [None]
                child = subprocess.run([sys.executable, "-c",
                                        "import sys;sys.path.insert(0,sys.argv[1]);"
                                        "from dataplane.engine.core.atomic_io import append_jsonl;"
                                        "print(append_jsonl(sys.argv[2],{'child':True},wait=False))",
                                        str(Path(__file__).resolve().parents[1]), path],
                                       capture_output=True, text=True, timeout=5)
                assert child.returncode == 0 and child.stdout.strip() == "True", child.stderr
        finally:
            release.set()
            writer.join(3)
            holder.join(3)
        assert not writer.is_alive() and not holder.is_alive()
        assert all(fd not in atomic_io._APPEND_OPEN_FDS for fd in visits)


def test_fork_drops_copied_retirement_queue_and_parent_thaw_drains_its_owners():
    if not hasattr(os, "fork"):
        raise SkipTest("copied queue and deferred close recovery requires POSIX fork")
    with _case() as folder:
        file = atomic_io._open_append_nofollow(str(Path(folder, "fork-pending.jsonl")),
                                              "utf-8", wait=False)
        fd = file.fileno()
        shield, firewall = SimpleNamespace(_lock=threading.RLock()), SimpleNamespace(_lock=threading.RLock())
        held = commit_barrier.freeze_fork(shield, firewall)
        done = threading.Event()

        def retire():
            file.close()
            done.set()

        worker = threading.Thread(target=retire)
        pid = None
        try:
            worker.start()
            assert done.wait(0.15) and not file.closed
            pid = os.fork()
            if pid == 0:
                try:
                    commit_barrier.thaw_child(shield, firewall)
                    state = {"closed": file.closed, "registry_empty": not atomic_io._APPEND_OPEN_FDS,
                             "queue_empty": atomic_io._APPEND_PENDING_CLOSE.empty()}
                    Path(folder, "fork-pending-result.json").write_text(json.dumps(state))
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            commit_barrier.thaw_parent(held)
            held = None
            _, code = os.waitpid(pid, 0)
            pid = None
            assert code == 0
            assert file.closed and fd not in atomic_io._APPEND_OPEN_FDS
            assert json.loads(Path(folder, "fork-pending-result.json").read_text()) == {
                "closed": True, "registry_empty": True, "queue_empty": True}
        finally:
            if held is not None:
                commit_barrier.thaw_parent(held)
            worker.join(3)
            file.close()
            if pid:
                os.waitpid(pid, 0)
