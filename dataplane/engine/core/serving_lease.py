"""One crash-released serving owner for a DuckNet state directory.

The lease is independent of the short policy publication barrier. Keep it
from before loading mutable traffic through the final state flush. This file
is never unlinked: replacing a locked inode would let a second owner in.
Call ``verify_path`` at admission and before state publication to fail closed
if the directory or lock pathname is replaced despite private permissions.
"""

from __future__ import annotations

import errno
import math
import os
import stat
import threading
import time
import weakref

from .signed_state import _require_private_state_dir


_NAME = ".ducknet-serving.lock"
_REGISTRY_LOCK = threading.Lock()
_ACTIVE: dict[str, ServingLease] = {}
_INSTANCES: weakref.WeakSet[ServingLease] = weakref.WeakSet()


def _is_reparse(info) -> bool:
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _directory_info(path: str):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise OSError("serving state path is not a real directory")
    return info


class ServingLease:
    """Exclusive state owner. ``acquire(timeout=0)`` is nonblocking by default.

    Busy returns False; an unsafe or changed pathname raises OSError. The
    caller owns the object and must call ``close`` after the final state flush.
    A fork child automatically closes its inherited descriptor without an
    explicit unlock, which would also unlock the parent's POSIX flock.
    """

    def __init__(self, state_dir: str):
        _require_private_state_dir(state_dir)
        # Check the caller's final path before realpath can hide a junction.
        self._requested_dir = os.path.abspath(state_dir)
        _directory_info(self._requested_dir)
        self.state_dir = os.path.normcase(os.path.realpath(self._requested_dir))
        self.path = os.path.join(self.state_dir, _NAME)
        directory = _directory_info(self.state_dir)
        self._directory_identity = (directory.st_dev, directory.st_ino)
        self._fd: int | None = None
        self._held = False
        self._pid = os.getpid()
        self._fd = self._open()
        with _REGISTRY_LOCK:
            _INSTANCES.add(self)

    def _open(self) -> int:
        if os.path.lexists(self.path):
            existing = os.lstat(self.path)
            if (not stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
                    or _is_reparse(existing) or existing.st_nlink != 1):
                raise OSError("serving lease file is not a private regular file")
        flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(self.path, flags, 0o600)
        try:
            os.set_inheritable(fd, False)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or _is_reparse(info)
                    or info.st_nlink != 1
                    or (os.name == "posix" and
                        (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
                raise OSError("serving lease file is not a private regular file")
            named = os.lstat(self.path)
            if (not stat.S_ISREG(named.st_mode) or stat.S_ISLNK(named.st_mode)
                    or _is_reparse(named)
                    or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
                raise OSError("serving lease path changed while opening")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def verify_path(self) -> bool:
        """Check both stable inodes while the server still owns the lease."""
        if self._fd is None or self._pid != os.getpid():
            return False
        try:
            requested = _directory_info(self._requested_dir)
            directory = _directory_info(self.state_dir)
            fd_info = os.fstat(self._fd)
            named = os.lstat(self.path)
            return (os.path.normcase(os.path.realpath(self._requested_dir)) == self.state_dir
                    and (requested.st_dev, requested.st_ino) ==
                    (directory.st_dev, directory.st_ino)
                    and self._directory_identity == (directory.st_dev, directory.st_ino)
                    and stat.S_ISREG(fd_info.st_mode)
                    and stat.S_ISREG(named.st_mode)
                    and not stat.S_ISLNK(named.st_mode)
                    and not _is_reparse(named)
                    and fd_info.st_nlink == named.st_nlink == 1
                    and (fd_info.st_dev, fd_info.st_ino) == (named.st_dev, named.st_ino)
                    and (os.name != "posix" or
                         (directory.st_uid == os.geteuid()
                          and not directory.st_mode & 0o022
                          and named.st_uid == os.geteuid()
                          and not named.st_mode & 0o077)))
        except OSError:
            return False

    def _try_os_lock(self) -> bool:
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            else:
                raise OSError("serving lease is unavailable on this platform")
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN,
                             getattr(errno, "EWOULDBLOCK", errno.EAGAIN)) or (
                    os.name == "nt" and getattr(exc, "winerror", None) in (32, 33)):
                return False
            raise

    def _unlock_os(self) -> None:
        if os.name == "posix":
            import fcntl
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        elif os.name == "nt":
            import msvcrt
            os.lseek(self._fd, 0, os.SEEK_SET)
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)

    def acquire(self, timeout: float = 0.0) -> bool:
        """Try within a finite deadline; False means another owner is active."""
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or timeout < 0 or timeout > 30):
            raise ValueError("serving lease timeout must be 0..30 seconds")
        if self._pid != os.getpid() or self._fd is None:
            raise OSError("serving lease cannot be reused after fork or close")
        if self._held:
            if not self.verify_path():
                raise OSError("serving lease path changed")
            return True
        deadline = time.monotonic() + timeout
        while True:
            if not self.verify_path():
                raise OSError("serving lease path changed")
            with _REGISTRY_LOCK:
                other = _ACTIVE.get(self.path)
                if other is None:
                    _ACTIVE[self.path] = self
                    reserved = True
                else:
                    reserved = other is self
            if reserved:
                try:
                    if self._try_os_lock():
                        if not self.verify_path():
                            self._unlock_os()
                            raise OSError("serving lease path changed after acquisition")
                        self._held = True
                        return True
                except BaseException:
                    with _REGISTRY_LOCK:
                        if _ACTIVE.get(self.path) is self:
                            _ACTIVE.pop(self.path, None)
                    raise
                with _REGISTRY_LOCK:
                    if _ACTIVE.get(self.path) is self:
                        _ACTIVE.pop(self.path, None)
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))

    @property
    def held(self) -> bool:
        return self._held and self._pid == os.getpid() and self.verify_path()

    def release(self) -> None:
        if self._pid != os.getpid():
            raise OSError("fork child cannot release the parent serving lease")
        if not self._held:
            return
        try:
            self._unlock_os()
        except BaseException:
            # Closing also drops the OS lock if an explicit unlock failed.
            fd, self._fd = self._fd, None
            if fd is not None:
                os.close(fd)
            raise
        finally:
            self._held = False
            with _REGISTRY_LOCK:
                if _ACTIVE.get(self.path) is self:
                    _ACTIVE.pop(self.path, None)

    def close(self) -> None:
        if self._pid != os.getpid():
            # Normally handled by the at-fork callback. Never unlock here:
            # POSIX fork copies share one flock file description with parent.
            fd, self._fd = self._fd, None
            if fd is not None:
                os.close(fd)
            self._held = False
            return
        try:
            self.release()
        finally:
            fd, self._fd = self._fd, None
            if fd is not None:
                os.close(fd)
            with _REGISTRY_LOCK:
                _INSTANCES.discard(self)

    def __enter__(self) -> ServingLease:
        if not self.acquire():
            self.close()
            raise TimeoutError("another DuckNet server owns this state directory")
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _after_fork_child() -> None:
    global _REGISTRY_LOCK, _ACTIVE, _INSTANCES
    # Never unlock a copied flock: that releases the parent's lease too.
    for lease in tuple(_INSTANCES):
        fd, lease._fd = lease._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        lease._held = False
    _REGISTRY_LOCK = threading.Lock()
    _ACTIVE = {}
    _INSTANCES = weakref.WeakSet()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)
