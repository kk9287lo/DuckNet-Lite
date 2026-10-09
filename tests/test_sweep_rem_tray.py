"""
test_sweep_rem_tray.py — Explorer が再起動してもトレイアイコンが消えたままにならない(Lite)
====================================================================================
Explorer が再起動すると(異常終了・Windows の更新・利用者による再起動)通知領域は作り直され、
各アプリは登録メッセージ "TaskbarCreated" を受けてアイコンを追加し直す必要がある。以前のトレイは
これを扱っておらず、トレイを起動し直すまでアイコンが消えたままだった(防御 OFF の淡色表示も
見えなくなる)。ここでは
  · 窓プロシージャが TaskbarCreated を受けると、*最新の* ツールチップ/アイコンで NIM_ADD する
    (set_status の反映待ちの値も使う。起動時の値に戻さない)
  · アイコンのハンドル: 変わらなければ手元のものを使い回し、差し替えたら追加の成功後に前のものを
    破棄、追加に失敗したら新しい方を破棄して元に戻す(破棄済みのハンドルをシェルへ渡さない)
  · アイコンが残っている(通知領域は作り直されていない)なら NIM_ADD は失敗するので NIM_MODIFY で揃える
  · 起動時の追加に失敗していた(Explorer がまだ無かった)トレイも、TaskbarCreated で出てくる
  · 登録に失敗した(id=0)ときに WM_NULL(0)を TaskbarCreated と取り違えない
を Shell_NotifyIcon を差し替えて確かめ、Windows 実機では本物のトレイで「アイコンが消えた →
TaskbarCreated → 最新の状態で出し直された」を確かめる(他 OS は SkipTest)。
"""
import ctypes
import os
import sys
import time
from unittest import SkipTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIN = sys.platform.startswith("win")
TASKBAR = 0xC123                 # 登録メッセージの id の代役(登録メッセージは 0xC000〜0xFFFF)
ON_TIP = "DuckNet test — 防御 ON / Protection ON"
OFF_TIP = "DuckNet test — 防御 OFF / Protection OFF"


def _tray():
    from dataplane.gui import tray
    return tray


def _wait(pred, sec=5.0):
    end = time.monotonic() + sec
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


# ── Shell_NotifyIcon を差し替えた単体テスト(Win32 を起動しない) ─────────────
class _NID(ctypes.Structure):
    """NOTIFYICONDATAW のうち再追加が触る欄だけの代役(偽の Shell_NotifyIconW が中身を読む)。"""
    _fields_ = [("uFlags", ctypes.c_uint), ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128)]


class _FakeWin:
    """偽の user32 / shell32。LoadImageW は新しいハンドル番号を返し、Shell_NotifyIconW は
    呼ばれた時点の nid の中身を記録する。起きた順は events に残す。"""

    def __init__(self, t):
        self.t = t
        self.results = {}            # op -> 戻り値(既定は成功)/例外
        self.load_ok = True
        self.events = []
        self._next = 0x5000

    def LoadImageW(self, hinst, path, typ, cx, cy, flags):
        self.events.append(("load", path))
        if not self.load_ok:
            return None
        self._next += 1
        return self._next

    def DestroyIcon(self, h):
        self.events.append(("destroy", h))
        return 1

    def Shell_NotifyIconW(self, op, ref):
        nid = self.t._nid
        self.events.append(("notify", op, nid.uFlags, nid.szTip, nid.hIcon))
        r = self.results.get(op, True)
        if isinstance(r, BaseException):
            raise r
        return int(bool(r))

    def kinds(self, kind):
        return [e for e in self.events if e[0] == kind]


def _started(tip=ON_TIP, icon="on.ico", hicon=0x100, added=True):
    """トレイのスレッドが NIM_ADD まで済ませた後の状態を、Win32 を使わずに作る。"""
    tray = _tray()
    t = tray.TrayIcon(icon, tip, [("Open", "open"), None, ("Quit", "quit")], lambda a: None)
    nid = _NID()
    nid.uFlags = tray.NIF_MESSAGE | tray.NIF_ICON | tray.NIF_TIP
    nid.hIcon = hicon
    nid.szTip = t.tooltip
    t._nid, t._added = nid, added
    t._applied_tip, t._applied_icon = t.tooltip, icon
    t._wm_taskbar = TASKBAR
    fw = _FakeWin(t)
    t._api = (fw, fw)
    return t, fw


def _all_flags(tray):
    return tray.NIF_MESSAGE | tray.NIF_ICON | tray.NIF_TIP


def test_taskbar_created_readds_with_latest_status_not_startup():
    tray = _tray()
    t, fw = _started()
    # 防御が OFF になった直後で、set_status の WM_APP はまだ窓へ届いていない(_hwnd 無し=記録だけ)
    t.set_status(OFF_TIP, "off.ico")
    assert t._on_message(1, TASKBAR, 0, 0) == 0          # 窓プロシージャが処理した
    new = 0x5001
    assert fw.events == [("load", "off.ico"),
                         ("notify", tray.NIM_ADD, _all_flags(tray), OFF_TIP, new),
                         ("destroy", 0x100)], fw.events    # 前のハンドルは追加が成功してから破棄
    assert t._nid.hIcon == new
    assert (t._applied_tip, t._applied_icon) == (OFF_TIP, "off.ico")
    assert t._readd_count == 1 and t._readd_op == tray.NIM_ADD and t._readd_error is None
    # 後から届く WM_APP(set_status の依頼)は反映済み=シェルを呼ばない
    n = len(fw.events)
    assert t._on_message(1, tray.WM_TRAY_STATUS, 0, 0) == 0
    assert len(fw.events) == n, fw.events[n:]


def test_unchanged_icon_reuses_the_live_handle():
    tray = _tray()
    t, fw = _started(hicon=0x100)
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    assert fw.events == [("notify", tray.NIM_ADD, _all_flags(tray), ON_TIP, 0x100)], fw.events
    assert t._nid.hIcon == 0x100                          # 読み直さない・破棄しない
    t.set_status("DuckNet test — ツールチップだけ変更", None)
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    assert fw.events[-1] == ("notify", tray.NIM_ADD, _all_flags(tray),
                             "DuckNet test — ツールチップだけ変更", 0x100), fw.events
    assert not fw.kinds("load") and not fw.kinds("destroy"), fw.events
    assert t._readd_count == 2


def test_icon_still_present_falls_back_to_modify():
    """通知領域が作り直されていない TaskbarCreated(アイコンが残っている)では NIM_ADD が失敗する。"""
    tray = _tray()
    t, fw = _started()
    fw.results = {tray.NIM_ADD: False}
    t.set_status(OFF_TIP, "off.ico")
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    notes = fw.kinds("notify")
    assert [e[1] for e in notes] == [tray.NIM_ADD, tray.NIM_MODIFY], notes
    assert all(e[3] == OFF_TIP and e[4] == 0x5001 for e in notes), notes
    assert fw.kinds("destroy") == [("destroy", 0x100)], fw.events
    assert t._readd_op == tray.NIM_MODIFY and t._readd_error is None
    assert (t._applied_tip, t._applied_icon) == (OFF_TIP, "off.ico")


def test_failed_readd_keeps_the_valid_handle_and_retries_later():
    tray = _tray()
    t, fw = _started()
    fw.results = {tray.NIM_ADD: False, tray.NIM_MODIFY: False}   # 通知領域がまだ無い
    t.set_status(OFF_TIP, "off.ico")
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    assert t._nid.hIcon == 0x100                          # 手元の(破棄していない)ハンドルに戻す
    assert fw.kinds("destroy") == [("destroy", 0x5001)], fw.events   # 渡せなかった新しい方を破棄
    assert t._readd_count == 0 and t._readd_error, t._readd_error
    assert (t._applied_tip, t._applied_icon) == (ON_TIP, "on.ico")
    # 次の TaskbarCreated(通知領域ができた)で、最新の状態で出る
    fw.results = {}
    fw.events.clear()
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    assert fw.events == [("load", "off.ico"),
                         ("notify", tray.NIM_ADD, _all_flags(tray), OFF_TIP, 0x5002),
                         ("destroy", 0x100)], fw.events
    assert t._readd_count == 1 and t._readd_error is None


def test_shell_exception_does_not_escape_or_leak_the_new_handle():
    tray = _tray()
    t, fw = _started()
    fw.results = {tray.NIM_ADD: OSError("shell gone")}
    t.set_status(OFF_TIP, "off.ico")
    assert t._on_message(1, TASKBAR, 0, 0) == 0          # 窓プロシージャから例外を出さない
    assert t._nid.hIcon == 0x100
    assert fw.kinds("destroy") == [("destroy", 0x5001)], fw.events
    assert t._readd_error and "shell gone" in t._readd_error, t._readd_error


def test_icon_load_failure_still_readds_with_the_current_icon():
    """新しいアイコンが読めなくても、手元のアイコンと最新のツールチップで出し直す(消えたままにしない)。"""
    tray = _tray()
    t, fw = _started()
    fw.load_ok = False
    t.set_status(OFF_TIP, "missing.ico")
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    assert fw.kinds("notify") == [("notify", tray.NIM_ADD, _all_flags(tray), OFF_TIP, 0x100)]
    assert not fw.kinds("destroy"), fw.events
    assert t._readd_count == 1 and "missing.ico" in (t._readd_error or "")
    assert t._applied_icon == "on.ico"                    # 次の更新で読み直す


def test_tray_whose_first_add_failed_appears_on_taskbar_created():
    """ログオン直後など Explorer より先に起動して NIM_ADD に失敗したトレイは、状態の更新も
    保留していた。TaskbarCreated で最新の状態で追加され、以後の更新も反映される。"""
    tray = _tray()
    t, fw = _started(added=False)
    t.set_status("DuckNet test — 状態 1", None)
    assert t._on_message(1, tray.WM_TRAY_STATUS, 0, 0) == 0
    assert fw.events == []                                # 追加前は NIM_MODIFY しない(従来どおり)
    assert t._on_message(1, TASKBAR, 0, 0) == 0
    assert fw.events == [("notify", tray.NIM_ADD, _all_flags(tray), "DuckNet test — 状態 1",
                          0x100)], fw.events
    assert t._added is True
    t.set_status("DuckNet test — 状態 2", None)
    assert t._on_message(1, tray.WM_TRAY_STATUS, 0, 0) == 0
    assert fw.events[-1] == ("notify", tray.NIM_MODIFY, tray.NIF_TIP, "DuckNet test — 状態 2",
                             0x100), fw.events


def test_wm_null_is_not_taken_for_taskbar_created():
    """登録に失敗した(id=0)とき、メニュー後に投げる WM_NULL(0)で再追加しない。起動前も無害。"""
    t, fw = _started()
    t._wm_taskbar = 0
    assert t._on_message(1, 0, 0, 0) is None              # 既定の処理(DefWindowProcW)へ
    t._wm_taskbar = TASKBAR
    assert t._on_message(1, 0, 0, 0) is None
    assert fw.events == [] and t._readd_count == 0
    fresh = _tray().TrayIcon("on.ico", "x", [], lambda a: None)
    assert fresh._wm_taskbar == 0 and fresh._readd_count == 0
    fresh._wm_taskbar = TASKBAR                           # 窓はあるが NIM_ADD 前(_nid 無し)
    assert fresh._on_message(1, TASKBAR, 0, 0) == 0
    assert fresh._readd_count == 0


def test_existing_messages_are_still_routed():
    tray = _tray()
    seen, pops = [], []
    t, fw = _started()
    t.on_action = seen.append
    t._popup = pops.append
    assert t._on_message(7, tray.WM_COMMAND, 3, 0) == 0
    assert t._on_message(7, tray.WM_TRAY, 0, tray.WM_LBUTTONDBLCLK) == 0
    assert t._on_message(7, tray.WM_TRAY, 0, tray.WM_RBUTTONUP) == 0
    assert seen == ["quit", "open"] and pops == [7], (seen, pops)
    assert t._on_message(7, tray.WM_TRAY, 0, 0x0200) is None      # マウス移動は既定の処理へ
    assert t._on_message(7, 0x0010, 0, 0) is None                 # WM_CLOSE など
    assert fw.events == []


# ── Windows 実機: 本物のトレイで「消えた → TaskbarCreated → 最新の状態で出し直す」 ──
def _win():
    from ctypes import wintypes
    u32, shell = ctypes.WinDLL("user32"), ctypes.WinDLL("shell32")
    u32.RegisterWindowMessageW.restype = wintypes.UINT
    u32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
    u32.PostMessageW.restype = wintypes.BOOL
    u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    u32.GetIconInfo.restype = wintypes.BOOL
    shell.Shell_NotifyIconW.restype = wintypes.BOOL
    shell.Shell_NotifyIconGetRect.restype = ctypes.c_long
    return u32, shell, ctypes.WinDLL("gdi32")


def _icon_shown(hwnd) -> bool:
    """通知領域にこの窓のアイコン(uID=1)があるか(Shell_NotifyIconGetRect が S_OK)。"""
    from ctypes import wintypes
    _u32, shell, _g = _win()

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class NII(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                    ("uID", wintypes.UINT), ("guidItem", GUID)]
    n = NII()
    n.cbSize, n.hWnd, n.uID = ctypes.sizeof(NII), hwnd, 1
    r = wintypes.RECT()
    return shell.Shell_NotifyIconGetRect(ctypes.byref(n), ctypes.byref(r)) == 0


def _icon_valid(h) -> bool:
    """HICON がまだ有効か(GetIconInfo が成功する。作られたビットマップは消す)。"""
    from ctypes import wintypes
    u32, _s, gdi = _win()

    class ICONINFO(ctypes.Structure):
        _fields_ = [("fIcon", wintypes.BOOL), ("xHotspot", wintypes.DWORD),
                    ("yHotspot", wintypes.DWORD), ("hbmMask", wintypes.HBITMAP),
                    ("hbmColor", wintypes.HBITMAP)]
    ii = ICONINFO()
    u32.GetIconInfo.argtypes = [wintypes.HICON, ctypes.POINTER(ICONINFO)]
    ok = bool(u32.GetIconInfo(h, ctypes.byref(ii)))
    gdi.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    for bm in (ii.hbmMask, ii.hbmColor):
        if bm:
            gdi.DeleteObject(bm)
    return ok


def _lose_icon(t):
    """通知領域の作り直しを模す: このトレイのアイコンだけを消す(Explorer には触れない)。"""
    _u32, shell, _g = _win()
    assert shell.Shell_NotifyIconW(_tray().NIM_DELETE, ctypes.byref(t._nid))
    assert not _icon_shown(t._hwnd)


def test_real_tray_readds_icon_with_latest_status_after_taskbar_created():
    if not WIN:
        raise SkipTest("Win32 トレイの実起動テスト(Windows 専用)")
    tray = _tray()
    import dataplane.gui.__main__ as G
    from dataplane.gui import ASSET_ICO, ASSET_ICO_OFF
    assets = os.path.join(ROOT, "dataplane", "gui", "assets")
    on, off = os.path.join(assets, ASSET_ICO), os.path.join(assets, ASSET_ICO_OFF)
    tip_off, _ = G._status_view("off", "DuckNet test")
    tip_on, _ = G._status_view("on", "DuckNet test")
    tip_auth, _ = G._status_view("auth", "DuckNet test")
    u32, _shell, _g = _win()
    wm = u32.RegisterWindowMessageW("TaskbarCreated")    # Explorer が全トップレベル窓へ送る id
    assert 0xC000 <= wm <= 0xFFFF, wm
    t = tray.TrayIcon(on, "DuckNet test", [("Open", "open")], lambda a: None)
    t.set_status(tip_off, off)                           # 起動時は OFF で出る
    if not t.start():
        raise SkipTest("トレイを起動できない")
    hwnd = None
    try:
        assert _wait(lambda: t._nid is not None, 5.0), "tray window not created"
        if not t._added:
            raise SkipTest("通知領域が無いセッション(Shell_NotifyIcon NIM_ADD 失敗)")
        hwnd = t._hwnd
        assert _icon_shown(hwnd)
        t.set_status(tip_on, on)                         # 最新の状態は ON(起動時の OFF とは違う)
        assert _wait(lambda: t._applied_tip == tip_on, 5.0), t._status_error
        h_on = t._nid.hIcon
        # 1) 通知領域が作り直された → TaskbarCreated → 最新の状態(ON)で出し直す
        _lose_icon(t)
        assert u32.PostMessageW(hwnd, wm, 0, 0)
        assert _wait(lambda: _icon_shown(hwnd), 5.0), "icon not re-added after TaskbarCreated"
        assert _wait(lambda: t._readd_count == 1, 5.0)
        assert t._readd_op == tray.NIM_ADD and t._readd_error is None, t._readd_error
        assert t._nid.szTip == tip_on and t._applied_icon == on, (t._nid.szTip, t._applied_icon)
        assert t._nid.hIcon == h_on and _icon_valid(h_on)   # 手元のハンドルは有効なまま使い回す
        assert t._readd_thread == t._thread.ident         # Win32 はトレイのスレッドでだけ触る
        # 2) 状態の更新(淡色アイコンへ)と通知領域の作り直しが重なっても、最新の状態で出る
        _lose_icon(t)
        t.set_status(tip_auth, off)                      # この NIM_MODIFY はアイコンが無いので失敗する
        assert u32.PostMessageW(hwnd, wm, 0, 0)
        assert _wait(lambda: t._readd_count == 2, 5.0), t._readd_error
        assert _icon_shown(hwnd)
        assert t._nid.szTip == tip_auth and t._applied_icon == off, (t._nid.szTip,
                                                                     t._applied_icon)
        assert t._nid.hIcon != h_on and _icon_valid(t._nid.hIcon)
        assert t._readd_error is None and t._status_error is None, (t._readd_error,
                                                                    t._status_error)
        # 3) アイコンが残っているときの TaskbarCreated(作り直し無し)は NIM_MODIFY で揃える
        assert u32.PostMessageW(hwnd, wm, 0, 0)
        assert _wait(lambda: t._readd_count == 3, 5.0), t._readd_error
        assert t._readd_op == tray.NIM_MODIFY and t._readd_error is None
        # 4) 出し直したアイコンへ、以後の状態の更新も届く
        t.set_status(tip_on, on)
        assert _wait(lambda: t._applied_tip == tip_on, 5.0), t._status_error
        assert t._applied_icon == on and t._status_error is None
    finally:
        t.stop()
        if t._thread:
            t._thread.join(3.0)
    assert not t._thread.is_alive()
    assert not _icon_shown(hwnd)                         # 終了でアイコンは消える
