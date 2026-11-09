"""Win32 tray lifecycle and retry boundaries (only this process's tray windows)."""
from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from unittest import SkipTest

from dataplane.gui import ASSET_ICO
from dataplane.gui import tray


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ICON = os.path.join(_ROOT, "dataplane", "gui", "assets", ASSET_ICO)


def _win():
    if not sys.platform.startswith("win"):
        raise SkipTest("real Win32 tray window required")
    return ctypes.windll.user32


def _finish(t):
    _wait(lambda: t._hwnd is not None or t._thread is None or not t._thread.is_alive(), 1)
    t.stop()
    thread = t._thread
    if thread is not None:
        thread.join(3)
        assert not thread.is_alive(), "tray worker survived stop"


def _wait(predicate, seconds=3):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_start_reports_real_window_failure_and_valid_icon_starts():
    _win()
    good = tray.TrayIcon(_ICON, "good", [], lambda _: None)
    try:
        assert good.start() is True
        assert _wait(lambda: bool(good._hwnd)) and good._thread.is_alive()
    finally:
        _finish(good)

    bad = tray.TrayIcon(_ICON + ".missing", "bad", [], lambda _: None)
    try:
        assert bad.start() is False, "invisible tray icon reported as started"
        assert bad._hwnd is None and not bad._thread.is_alive()
    finally:
        _finish(bad)


def test_thread_start_failure_can_be_stopped_idempotently():
    _win()
    original = tray.threading.Thread.start
    tray.threading.Thread.start = lambda self: (_ for _ in ()).throw(OSError("thread unavailable"))
    t = tray.TrayIcon(_ICON, "thread", [], lambda _: None)
    try:
        assert t.start() is False
        assert t._start_error and "thread unavailable" in t._start_error
        assert t.stop() is True
        assert t.stop() is True
    finally:
        tray.threading.Thread.start = original


def test_stop_while_window_is_being_created_does_not_revive_worker():
    u32 = _win()
    original = u32.CreateWindowExW
    entered, release = threading.Event(), threading.Event()

    def delayed_create(*args):
        entered.set()
        assert release.wait(3), "test gate not released"
        return original(*args)

    u32.CreateWindowExW = delayed_create
    t = tray.TrayIcon(_ICON, "race", [], lambda _: None)
    start_result = []
    caller = threading.Thread(target=lambda: start_result.append(t.start()))
    try:
        caller.start()
        assert entered.wait(3), "worker did not enter CreateWindowExW"
        t.stop()                         # no HWND has been published yet
        release.set()
        caller.join(4)
        assert not caller.is_alive()
        worker = t._thread
        assert worker is not None
        worker.join(2)
        assert not worker.is_alive(), "pre-window stop request was overwritten"
        assert t._hwnd is None
    finally:
        release.set()
        u32.CreateWindowExW = original
        _finish(t)


def test_status_changed_during_icon_load_is_applied_after_add():
    u32 = _win()
    original = u32.LoadImageW
    entered, release = threading.Event(), threading.Event()

    def delayed_load(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)

    u32.LoadImageW = delayed_load
    t = tray.TrayIcon(_ICON, "initial", [], lambda _: None)
    caller = threading.Thread(target=t.start)
    try:
        caller.start()
        assert entered.wait(3)
        t.set_status("latest")          # first snapshot was taken, HWND is not published yet
        release.set()
        caller.join(4)
        assert not caller.is_alive()
        assert _wait(lambda: t._applied_tip == "latest"), (t._applied_tip, t._status_error)
    finally:
        release.set()
        u32.LoadImageW = original
        _finish(t)


def test_two_tray_objects_have_distinct_window_procedures_and_single_start():
    u32 = _win()
    from ctypes import wintypes
    u32.GetClassNameW.restype = ctypes.c_int
    u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    first = tray.TrayIcon(_ICON, "one", [], lambda _: None)
    second = tray.TrayIcon(_ICON, "two", [], lambda _: None)
    try:
        assert first.start() is True and second.start() is True
        assert _wait(lambda: bool(first._hwnd and second._hwnd))
        name1, name2 = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
        assert u32.GetClassNameW(first._hwnd, name1, 256)
        assert u32.GetClassNameW(second._hwnd, name2, 256)
        assert name1.value != name2.value, "second HWND inherited first tray's WNDPROC"
        worker = first._thread
        assert first.start() is True
        assert first._thread is worker, "a second start created a competing worker"
    finally:
        _finish(second)
        _finish(first)


def test_two_objects_start_concurrently_without_ctypes_type_collision():
    _win()
    for _ in range(5):
        icons = [tray.TrayIcon(_ICON, str(i), [], lambda _: None) for i in range(2)]
        barrier = threading.Barrier(3)
        results = []
        callers = [threading.Thread(target=lambda t=t: (barrier.wait(), results.append(t.start())))
                   for t in icons]
        try:
            for caller in callers:
                caller.start()
            barrier.wait()
            for caller in callers:
                caller.join(5)
                assert not caller.is_alive()
            assert results == [True, True], (results, [t._start_error for t in icons])
            assert all(t._hwnd and t._thread.is_alive() for t in icons)
        finally:
            for t in reversed(icons):
                _finish(t)


def test_restart_and_stop_from_own_action_callback():
    u32 = _win()
    t = tray.TrayIcon(_ICON, "first", [("Quit", "quit")], lambda _: t.stop())
    assert t.is_alive() is False
    try:
        assert t.start() is True
        assert t.is_alive() is True
        assert t.stop() is True
        assert t.is_alive() is False
        t.set_status("second")
        assert t.start() is True
        assert t.is_alive() is True
        assert t._applied_tip == "second"
        assert u32.PostMessageW(t._hwnd, tray.WM_COMMAND, 1, 0)
        assert _wait(lambda: not t._thread.is_alive()), "callback stop deadlocked its own worker"
        assert t.is_alive() is False
        assert t._hwnd is None
    finally:
        _finish(t)


def test_shell_start_exception_releases_own_window_class():
    u32 = _win()
    shell = ctypes.windll.shell32
    original = shell.Shell_NotifyIconW
    shell.Shell_NotifyIconW = lambda *args: (_ for _ in ()).throw(OSError("Shell down"))
    t = tray.TrayIcon(_ICON, "startup", [], lambda _: None)
    try:
        assert t.start() is False
        assert t._start_error and "Shell down" in t._start_error
        assert not t._thread.is_alive() and t._hwnd is None
        assert t._wndproc is None, "window class still owns callback after startup failure"
        from ctypes import wintypes
        u32.FindWindowW.restype = wintypes.HWND
        u32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        assert not u32.FindWindowW(t._class_name, None)
    finally:
        shell.Shell_NotifyIconW = original
        _finish(t)


def test_initial_shell_add_failure_recovers_without_explorer_broadcast():
    _win()
    shell = ctypes.windll.shell32
    original = shell.Shell_NotifyIconW
    failed = []

    def first_add_fails(op, ref):
        if op == tray.NIM_ADD and not failed:
            failed.append(True)
            return 0
        return original(op, ref)

    shell.Shell_NotifyIconW = first_add_fails
    t = tray.TrayIcon(_ICON, "retry", [], lambda _: None)
    try:
        assert t.start() is True     # live window can recover from absent Shell
        assert failed and not t._added
        shell.Shell_NotifyIconW = original
        assert _wait(lambda: t._added, 3), t._readd_error
        assert t._readd_count >= 1 and t._readd_error is None
    finally:
        shell.Shell_NotifyIconW = original
        _finish(t)


class _NID(ctypes.Structure):
    _fields_ = [("uFlags", ctypes.c_uint), ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128)]


class _FakeApi:
    def __init__(self):
        self.fail = True
        self.raise_notify = False
        self.ops = []
        self.timers = []
        self.destroyed = []

    def LoadImageW(self, *args):
        return 2

    def DestroyIcon(self, handle):
        self.destroyed.append(handle)
        return 1

    def Shell_NotifyIconW(self, op, ref):
        self.ops.append(op)
        if self.raise_notify:
            raise OSError("temporary Shell error")
        return int(not self.fail)

    def SetTimer(self, hwnd, timer_id, delay, callback):
        self.timers.append(("set", timer_id, delay))
        return timer_id

    def KillTimer(self, hwnd, timer_id):
        self.timers.append(("kill", timer_id))
        return 1


def test_transient_shell_modify_failure_retries_without_another_status_change():
    t = tray.TrayIcon(_ICON, "old", [], lambda _: None)
    api = _FakeApi()
    nid = _NID()
    nid.szTip = "old"
    nid.hIcon = 1
    t._nid, t._api, t._hwnd, t._added = nid, (api, api), 123, True
    t._applied_tip, t._applied_icon = "old", _ICON
    with t._lock:
        t.tooltip = "new"
    assert t._on_message(123, tray.WM_TRAY_STATUS, 0, 0) == 0
    assert t._applied_tip == "old" and t._status_error
    api.fail = False
    assert t._on_message(123, tray.WM_TIMER, 1, 0) == 0
    assert t._applied_tip == "new" and t._status_error is None
    assert api.ops == [tray.NIM_MODIFY, tray.NIM_MODIFY]
    assert [x[0] for x in api.timers] == ["set", "kill"]


def test_shell_exception_during_icon_swap_restores_and_destroys_new_handle():
    t = tray.TrayIcon("old.ico", "old", [], lambda _: None)
    api = _FakeApi()
    api.raise_notify = True
    nid = _NID()
    nid.szTip, nid.hIcon = "old", 1
    t._nid, t._api, t._hwnd, t._added = nid, (api, api), 123, True
    t._applied_tip, t._applied_icon = "old", "old.ico"
    with t._lock:
        t.tooltip, t.icon_path = "new", "new.ico"
    assert t._on_message(123, tray.WM_TRAY_STATUS, 0, 0) == 0
    assert nid.hIcon == 1, "failed icon was left in the live NID"
    assert api.destroyed == [2], "new HICON leaked after Shell exception"
    assert (t._applied_tip, t._applied_icon) == ("old", "old.ico")
    assert t._status_error and "Shell error" in t._status_error


def test_failed_window_post_uses_tray_thread_queue_without_cross_thread_timer():
    u32 = _win()
    original = u32.PostMessageW
    original_timer = u32.SetTimer
    t = tray.TrayIcon(_ICON, "old", [], lambda _: None)
    try:
        assert t.start() is True
        u32.PostMessageW = lambda *args: 0
        u32.SetTimer = lambda *args: (_ for _ in ()).throw(OSError("window owned by tray thread"))
        try:
            t.set_status("new")
        finally:
            u32.PostMessageW = original
            u32.SetTimer = original_timer
        assert _wait(lambda: t._applied_tip == "new"), t._status_error
        assert t._status_error is None
    finally:
        u32.PostMessageW = original
        u32.SetTimer = original_timer
        _finish(t)


def test_transient_readd_failure_retries_without_taskbar_broadcast():
    t = tray.TrayIcon(_ICON, "ready", [], lambda _: None)
    api = _FakeApi()
    nid = _NID()
    nid.szTip, nid.hIcon = "ready", 1
    t._nid, t._api, t._hwnd, t._added = nid, (api, api), 123, True
    t._applied_tip, t._applied_icon = "ready", _ICON
    t._wm_taskbar = 0xC123
    assert t._on_message(123, t._wm_taskbar, 0, 0) == 0
    assert t._readd_error and t._readd_count == 0
    api.fail = False
    assert t._on_message(123, tray.WM_TIMER, 1, 0) == 0
    assert t._readd_error is None and t._readd_count == 1
    assert api.ops == [tray.NIM_ADD, tray.NIM_MODIFY, tray.NIM_ADD]


def test_popup_api_exception_destroys_only_its_own_menu():
    u32 = _win()
    original = (u32.CreatePopupMenu, u32.AppendMenuW, u32.DestroyMenu)
    destroyed = []

    def bad_append(*args):
        raise OSError("menu unavailable")

    u32.CreatePopupMenu = lambda: 123
    u32.AppendMenuW = bad_append
    u32.DestroyMenu = lambda handle: destroyed.append(handle)
    try:
        t = tray.TrayIcon(_ICON, "menu", [("Open", "open")], lambda _: None)
        assert t._on_message(42, tray.WM_TRAY, 0, tray.WM_RBUTTONUP) == 0
        assert destroyed == [123]
    finally:
        u32.CreatePopupMenu, u32.AppendMenuW, u32.DestroyMenu = original
