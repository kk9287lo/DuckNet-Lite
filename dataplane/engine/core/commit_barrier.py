"""Order fork-worker first writes against acknowledged policy commits.

Every signed policy mutation uses one stable process lock inode, including
writers in separate processes. An active fork cluster keeps its descriptor
open for request admission; a single-process request never acquires it. A
mutation holds the registry mutex, so cluster registration cannot overtake an
in-progress local commit.
"""

from contextlib import contextmanager
import errno
import os
import stat
import threading
import time


WAIT_SEC = 5.0
_REGISTRY = threading.RLock()
_ACTIVE_LOCKS = {}  # stable lock-file path -> [CommitFileLock, owner count]


def _lock_path(policy_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(policy_path)),
                        ".cluster_commit.lock")


class CommitFileLock:
    """A crash-released process lock on a private, stable state file.

    Each fork child reopens the inode as a separate file description. POSIX
    flock then excludes other processes and the kernel releases it on exit,
    including SIGKILL. A thread lock covers same-process callers. Windows
    single-worker fallback uses an OS byte-range lock across processes.
    """

    def __init__(self, policy_path: str):
        self.path = _lock_path(policy_path)
        self._thread_lock = threading.Lock()
        self._owner = None
        self._fd = self._open()

    def _open(self):
        if os.path.islink(self.path):
            raise OSError("cluster commit lock is a symlink")
        flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("cluster commit lock is not a regular file")
            if os.name == "posix" and (info.st_uid != os.geteuid()
                                       or info.st_mode & 0o077):
                raise OSError("cluster commit lock is not private")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def after_fork_child(self):
        old, self._fd = self._fd, None
        if old is not None:
            os.close(old)
        self._thread_lock = threading.Lock()
        self._owner = None
        self._fd = self._open()

    def verify_path(self) -> bool:
        """A replaced lock inode would split cooperating processes."""
        try:
            held = os.fstat(self._fd)
            named = os.lstat(self.path)
            return (stat.S_ISREG(named.st_mode) and not stat.S_ISLNK(named.st_mode)
                    and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                    and named.st_nlink == 1
                    and (os.name != "posix" or
                         (named.st_uid == os.geteuid() and not named.st_mode & 0o077)))
        except OSError:
            return False

    def _try_acquire(self):
        if self._owner == threading.get_ident():
            return False  # a nested event-loop task must fail, not bypass
        if not self._thread_lock.acquire(False):
            return False
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                # The single-process fallback still watches signed files
                # written by another process. A thread lock alone leaves a
                # stamp-check-to-backend-write gap on Windows. Use the same
                # one-byte OS lock convention as signed_state._state_guard.
                import msvcrt
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            self._owner = threading.get_ident()
            return True
        except OSError as exc:
            self._thread_lock.release()
            if exc.errno in (errno.EACCES, errno.EAGAIN,
                             getattr(errno, "EWOULDBLOCK", errno.EAGAIN)) or (
                    os.name == "nt" and getattr(exc, "winerror", None) in (32, 33)):
                return False
            raise
        except BaseException:
            self._thread_lock.release()
            raise

    def acquire(self, block=True, timeout=None):
        if not block:
            return self._try_acquire()
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while True:
            if self._try_acquire():
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.001)

    def release(self):
        if self._owner != threading.get_ident():
            raise RuntimeError("cluster commit lock released by non-owner")
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            elif os.name == "nt":
                import msvcrt
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        finally:
            self._owner = None
            self._thread_lock.release()

    def close(self):
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)


def register_cluster(policy_path: str):
    """Return one fork-inherited crash-safe lock for active local clusters."""
    path = _lock_path(policy_path)
    with _REGISTRY:
        entry = _ACTIVE_LOCKS.get(path)
        if entry is None:
            entry = [CommitFileLock(policy_path), 0]
            _ACTIVE_LOCKS[path] = entry
        entry[1] += 1
        return entry[0]


def release_cluster(lock) -> bool:
    """Discard the parent registry entry after its last child is reaped."""
    with _REGISTRY:
        entry = _ACTIVE_LOCKS.get(lock.path)
        if entry is None or entry[0] is not lock or entry[1] <= 0:
            return False
        entry[1] -= 1
        if entry[1] == 0:
            _ACTIVE_LOCKS.pop(lock.path)
            lock.close()  # retain inode: unlinking would split other processes
        return True


def freeze_fork(shield, firewall):
    """Wait until signed mutations finish, then hold their locks for fork.

    Object locks precede the registry lock, matching setter lock order. The
    caller must call thaw_parent or thaw_child immediately after os.fork.
    """
    deadline = time.monotonic() + WAIT_SEC
    held = []
    try:
        for lock in (shield._lock, firewall._lock, _REGISTRY):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not lock.acquire(timeout=remaining):
                raise TimeoutError("cluster policy locks unavailable for fork")
            held.append(lock)
        return tuple(held)
    except BaseException:
        for lock in reversed(held):
            lock.release()
        raise


def thaw_parent(held) -> None:
    for lock in reversed(held):
        lock.release()


def thaw_child(shield, firewall) -> None:
    """Remove inherited held thread locks before the child starts serving."""
    global _REGISTRY
    _REGISTRY = threading.RLock()
    shield._lock = threading.RLock()
    firewall._lock = threading.RLock()
    for lock, _owners in _ACTIVE_LOCKS.values():
        lock.after_fork_child()


@contextmanager
def policy_commit(policy_path: str, *, nonblocking: bool = False):
    """Yield False if a live cluster's first-write lock is unavailable.

    The registry mutex remains held through publication. A concurrent cluster
    cannot fork between a writer's lock lookup and its signed file update.
    """
    if not _REGISTRY.acquire(timeout=0.0 if nonblocking else WAIT_SEC):
        yield False
        return
    entry = _ACTIVE_LOCKS.get(_lock_path(policy_path))
    transient = None
    lock = entry[0] if entry is not None else None
    locked = False
    try:
        try:
            if lock is None:
                # A separate process may edit the same signed state while this
                # process serves a fork cluster. It has no local registry, but
                # must still honor the stable on-disk lock inode.
                transient = lock = CommitFileLock(policy_path)
            locked = lock.acquire(block=not nonblocking,
                                  timeout=None if nonblocking else WAIT_SEC)
            if locked and not lock.verify_path():
                lock.release()
                locked = False
        except (OSError, RuntimeError, ValueError):
            locked = False
        yield bool(locked)
    finally:
        if locked:
            lock.release()
        if transient is not None:
            transient.close()
        _REGISTRY.release()
