"""
tray.py — システムトレイ(Windows Shell_NotifyIcon・ctypes・標準ライブラリのみ)
====================================================================================
タスクトレイに DuckNet.ico を常駐させ、右クリックでプロ用メニューを出す。依存ゼロのため
pystray 等は使わず Win32 API を ctypes で直接叩く。別スレッドのメッセージループで動かし、
メニュー選択はコールバックで通知する。非 Windows / 失敗時は no-op(アプリは継続)。
set_status() でツールチップ/アイコンを後から差し替えられる(防御 ON/OFF の表示に使う)。
Explorer が再起動して通知領域が作り直されたら(登録メッセージ "TaskbarCreated")、その時点の
最新のツールチップ/アイコンでアイコンを追加し直す(トレイを起動し直さなくても消えたままにならない)。

正直な範囲: Windows 専用(他 OS は available=False)。ステルス時は呼び出し側が生成可否を選ぶ。
"""
from __future__ import annotations

import os
import threading

WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_TIMER = 0x0113
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
WM_TRAY = 0x0400 + 1            # WM_USER+1(トレイコールバック)
WM_APP = 0x8000
WM_TRAY_STATUS = WM_APP + 1     # set_status → トレイのスレッドへ「最新値を反映して」の依頼
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0x0, 0x1, 0x2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x10, 0x40
TPM_RIGHTBUTTON = 0x2
MF_STRING, MF_SEPARATOR, MF_GRAYED = 0x0, 0x800, 0x1
TIP_MAX = 127                   # szTip は WCHAR[128](127 文字+NUL)
_WND_CLASS = "DuckNetTrayWnd"
_TASKBAR_CREATED = "TaskbarCreated"   # 通知領域が作り直されたとき Explorer が全トップレベル窓へ送る
_RETRY_TIMER = 1
_RETRY_MS = 1000
MSGFLT_ALLOW = 1                # ChangeWindowMessageFilterEx: 低い整合性レベルからの受信を許す


def available() -> bool:
    import sys
    return sys.platform.startswith("win")


def _u16len(s: str) -> int:
    """szTip(WCHAR=UTF-16)で占める単位数。BMP 外の文字(絵文字など)はサロゲート対で 2。"""
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in s)


def clip_tip(text, limit: int = TIP_MAX) -> str:
    """szTip に収まるよう UTF-16 単位で切る。文字数で切ると絵文字入りの名前で 128 単位を
    超え、ctypes の代入が ValueError になる(=トレイ全体が出ない)。サロゲート対は割らない。
    NUL より後ろは Win32 側で読まれないので落とす。"""
    s = str(text or "").split("\x00", 1)[0]
    n, out = 0, []
    for ch in s:
        w = 2 if ord(ch) > 0xFFFF else 1
        if n + w > limit:
            break
        out.append(ch)
        n += w
    return "".join(out)


def fit_tip(head, tail, limit: int = TIP_MAX) -> str:
    """head+tail を limit に収める。溢れる分は head(ブランド名)を詰めて末尾を「…」にし、
    tail(状態の文言)は丸ごと残す=長い偽装名でも「防御 OFF」が切れて見えなくならない。"""
    tail = clip_tip(tail, limit)
    room = limit - _u16len(tail)
    head = str(head or "").split("\x00", 1)[0]
    if _u16len(head) <= room:
        return head + tail
    return (clip_tip(head, room - 1) + "…" if room >= 1 else "") + tail


class TrayIcon:
    """トレイ常駐アイコン。menu_items=[(label, action_id) or None(区切り)]、on_action(action_id)。"""

    def __init__(self, icon_path: str, tooltip: str, menu_items, on_action):
        self.icon_path = icon_path
        self.tooltip = clip_tip(tooltip)
        self.menu_items = list(menu_items)
        self._status_lines = ()
        self.on_action = on_action
        self._thread = None
        self._hwnd = None
        self._running = False
        self._nid = None
        self._class_name = "%s-%d-%x" % (_WND_CLASS, os.getpid(), id(self))
        self._ready = threading.Event()
        self._stop_requested = threading.Event()
        self._start_ok = False
        self._start_error = None
        self._retry_timer = False
        # set_status の受け渡し(tooltip/icon_path/_hwnd は _lock の下で読み書きする)と、
        # トレイのスレッドが実際に反映した値。反映はトレイのスレッドだけが行う。
        self._lock = threading.Lock()
        self._api = None                 # (user32, shell32)。_run が型を宣言してから入れる
        self._icon_size = 32
        self._added = False              # NIM_ADD が成功したか
        self._applied_tip = None
        self._applied_icon = None
        self._status_error = None        # 直近の反映失敗(None=成功)。診断・テスト用
        self._apply_thread = None        # 反映を行ったスレッド(=トレイのスレッドのはず)
        # Explorer の再起動(TaskbarCreated)での追加し直し。id は _run が登録する(0=未登録)
        self._wm_taskbar = 0
        self._readd_count = 0            # 追加し直しに成功した回数
        self._readd_op = None            # 直近の成功が NIM_ADD か NIM_MODIFY か
        self._readd_error = None         # 直近の追加し直しの失敗(None=成功)
        self._readd_thread = None        # 追加し直しを行ったスレッド(=トレイのスレッドのはず)

    def set_status(self, tooltip: str, icon_path=None) -> None:
        """ツールチップ(と、渡されればアイコン)を差し替える。どのスレッドから呼んでもよい。
        Shell_NotifyIcon やアイコンのハンドルは別スレッドから触らない: ここでは最新値を記録して
        専用メッセージ(WM_TRAY_STATUS)を窓へ投げ、失敗時は所有スレッドのキューへ投げる。
        どちらもトレイのスレッドが NIM_MODIFY で反映する。
        起動前・非 Windows では値を覚えるだけ(起動時の NIM_ADD がその最新値で出す)。"""
        tip = clip_tip(tooltip)
        with self._lock:
            self.tooltip = tip
            if icon_path:
                self.icon_path = str(icon_path)
            hwnd = self._hwnd
        if not hwnd or not available():
            return
        error = "PostMessageW(WM_TRAY_STATUS) failed"
        try:
            import ctypes
            from ctypes import wintypes
            if ctypes.windll.user32.PostMessageW(wintypes.HWND(hwnd), WM_TRAY_STATUS, 0, 0):
                return
        except Exception as e:
            error = repr(e)
        # SetTimer(hwnd, ...) は窓を所有するスレッドからしか呼べない。窓への
        # PostMessage が失敗した場合は、その所有スレッドのキューへ依頼する。
        try:
            import ctypes
            thread = self._thread
            if thread is not None and thread.native_id and ctypes.windll.user32.PostThreadMessageW(
                    thread.native_id, WM_TRAY_STATUS, 0, 0):
                return
        except Exception:
            pass
        self._status_error = error                         # 両経路失敗を診断可能にする

    def set_status_lines(self, lines) -> None:
        """Read-only live rows are snapshotted when the menu opens."""
        rows = tuple(clip_tip("".join(ch if ch.isprintable() else " " for ch in str(line)), 180)
                     for line in tuple(lines)[:3])
        with self._lock:
            self._status_lines = rows

    def start(self) -> bool:
        if not available():
            return False
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._ready.clear()
                self._stop_requested.clear()
                self._start_ok = False
                self._start_error = None
                self._status_error = self._readd_error = None
                self._retry_timer = False
                thread = threading.Thread(target=self._run, daemon=True, name="tray")
                self._thread = thread
                try:
                    thread.start()
                except Exception as e:
                    self._start_error = repr(e)
                    self._ready.set()
                    return False
        if not self._ready.wait(5.0):
            self.stop()
            return False
        ok = bool(self._start_ok and not self._stop_requested.is_set() and thread.is_alive())
        if not ok and thread.is_alive() and thread is not threading.current_thread():
            thread.join(3.0)           # 失敗を返す前に、この試行が作った HWND/class を回収
        return ok

    def stop(self) -> bool:
        """停止を予約し、呼出元が別スレッドなら有界で資源回収を待つ。"""
        self._stop_requested.set()
        with self._lock:
            hwnd, thread = self._hwnd, self._thread
        try:
            import ctypes
            if hwnd:
                u32 = ctypes.windll.user32
                if not u32.PostMessageW(hwnd, WM_DESTROY, 0, 0) and thread is not None:
                    u32.PostThreadMessageW(thread.native_id, 0x0012, 0, 0)  # WM_QUIT
        except Exception:
            pass
        if (thread is not None and thread is not threading.current_thread()
                and self._ready.is_set() and thread.is_alive()):
            thread.join(3.0)
        return thread is None or not thread.is_alive()

    def is_alive(self) -> bool:
        """launcher が ready 後の予期せぬ message loop 終了を検知する。"""
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    # ── 内部: 別スレッドの Win32 メッセージループ ──
    def _run(self):
        u32 = shell = hinst = hwnd = hicon = nid = None
        registered = False
        try:
            import ctypes
            from ctypes import wintypes
            u32, k32, shell = ctypes.windll.user32, ctypes.windll.kernel32, ctypes.windll.shell32

            # 64bit Windows では HWND/LPARAM/戻り値(LRESULT)はポインタ幅(8byte)。ctypes は
            # 既定で引数/戻り値を c_int(32bit)扱いにするため、明示しないと OverflowError や
            # ハンドルの切り詰めが起きる。使う API の型を必ず宣言する。
            LRESULT = ctypes.c_ssize_t
            HWND, UINT, WP, LP = wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
            HMENU, HINSTANCE, HANDLE = wintypes.HMENU, wintypes.HINSTANCE, wintypes.HANDLE
            HMODULE, DWORD, LPCWSTR = wintypes.HMODULE, wintypes.DWORD, wintypes.LPCWSTR
            LPVOID, BOOL, INT = wintypes.LPVOID, wintypes.BOOL, ctypes.c_int
            k32.GetModuleHandleW.restype = HMODULE
            k32.GetModuleHandleW.argtypes = [LPCWSTR]
            u32.DefWindowProcW.restype = LRESULT
            u32.DefWindowProcW.argtypes = [HWND, UINT, WP, LP]
            u32.CreateWindowExW.restype = HWND
            u32.CreateWindowExW.argtypes = [DWORD, LPCWSTR, LPCWSTR, DWORD, INT, INT, INT, INT,
                                            HWND, HMENU, HINSTANCE, LPVOID]
            u32.LoadImageW.restype = HANDLE
            u32.LoadImageW.argtypes = [HINSTANCE, LPCWSTR, UINT, INT, INT, UINT]
            u32.PostMessageW.restype = BOOL
            u32.PostMessageW.argtypes = [HWND, UINT, WP, LP]
            u32.PostThreadMessageW.restype = BOOL
            u32.PostThreadMessageW.argtypes = [DWORD, UINT, WP, LP]
            u32.GetMessageW.restype = BOOL
            u32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), HWND, UINT, UINT]
            u32.TranslateMessage.restype = BOOL
            u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
            u32.DispatchMessageW.restype = LRESULT
            u32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
            u32.PostQuitMessage.restype = None
            u32.PostQuitMessage.argtypes = [INT]
            u32.CreatePopupMenu.restype = HMENU
            u32.CreatePopupMenu.argtypes = []
            u32.AppendMenuW.restype = BOOL
            u32.AppendMenuW.argtypes = [HMENU, UINT, ctypes.c_size_t, LPCWSTR]
            u32.TrackPopupMenu.restype = BOOL
            u32.TrackPopupMenu.argtypes = [HMENU, UINT, INT, INT, INT, HWND, LPVOID]
            u32.SetForegroundWindow.restype = BOOL
            u32.SetForegroundWindow.argtypes = [HWND]
            u32.DestroyMenu.argtypes = [HMENU]
            u32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
            u32.GetSystemMetrics.restype = INT
            u32.GetSystemMetrics.argtypes = [INT]
            u32.DestroyIcon.restype = BOOL
            u32.DestroyIcon.argtypes = [wintypes.HICON]
            u32.DestroyWindow.restype = BOOL
            u32.DestroyWindow.argtypes = [HWND]
            u32.UnregisterClassW.restype = BOOL
            u32.UnregisterClassW.argtypes = [LPCWSTR, HINSTANCE]
            u32.RegisterWindowMessageW.restype = UINT
            u32.RegisterWindowMessageW.argtypes = [LPCWSTR]
            u32.SetTimer.restype = ctypes.c_size_t
            u32.SetTimer.argtypes = [HWND, ctypes.c_size_t, UINT, LPVOID]
            u32.KillTimer.restype = BOOL
            u32.KillTimer.argtypes = [HWND, ctypes.c_size_t]
            shell.Shell_NotifyIconW.restype = BOOL

            WNDPROC = ctypes.WINFUNCTYPE(LRESULT, HWND, UINT, WP, LP)

            def wndproc(hwnd, msg, wp, lp):
                if msg == WM_DESTROY:
                    self._stop_requested.set()
                    u32.PostQuitMessage(0)
                    return 0
                r = self._on_message(hwnd, msg, wp, lp)
                return u32.DefWindowProcW(hwnd, msg, wp, lp) if r is None else r

            self._wndproc = WNDPROC(wndproc)           # GC 防止に保持

            class WNDCLASS(ctypes.Structure):
                _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                            ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                            ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                            ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                            ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

            hinst = k32.GetModuleHandleW(None)
            wc = WNDCLASS()
            wc.lpfnWndProc = self._wndproc
            wc.hInstance = hinst
            wc.lpszClassName = self._class_name
            u32.RegisterClassW.restype = ctypes.c_ushort
            # WNDCLASS はインスタンスごとの WNDPROC 型を含む。並列 start で別の
            # POINTER(WNDCLASS) を共有 DLL 関数へ設定すると相互に型が衝突する。
            u32.RegisterClassW.argtypes = [ctypes.c_void_p]
            if not u32.RegisterClassW(ctypes.byref(wc)):
                raise OSError("RegisterClassW failed")
            registered = True
            # Explorer の再起動を知る登録メッセージ(このスレッドで登録。失敗は 0=扱わない)。
            # 窓を作る前に登録し、作った直後から届いても取りこぼさない。
            self._wm_taskbar = u32.RegisterWindowMessageW(_TASKBAR_CREATED) or 0
            # 窓はメッセージ専用(HWND_MESSAGE)にしない: TaskbarCreated はトップレベル窓への一斉送信
            hwnd = u32.CreateWindowExW(0, self._class_name, "DuckNet", 0,
                                       0, 0, 0, 0, 0, 0, hinst, 0)
            if not hwnd:
                raise OSError("CreateWindowExW failed")
            if hwnd and self._wm_taskbar:
                # 管理者として動いていると、UIPI が通常権限の Explorer からの TaskbarCreated を
                # 落とす。このメッセージだけはこの窓に届くようにする(無い OS・失敗は無視)。
                try:
                    cwmf = u32.ChangeWindowMessageFilterEx
                    cwmf.restype = BOOL
                    cwmf.argtypes = [HWND, UINT, DWORD, LPVOID]
                    cwmf(hwnd, self._wm_taskbar, MSGFLT_ALLOW, None)
                except Exception:
                    pass
            # 大アイコン(SM_CXICON=32px 既定)で読み込む。隠れインジケータ表示や高DPIで鮮明・
            # 大きく見える。トレイ内の実寸は OS のトレイセルサイズに従う。
            sz = u32.GetSystemMetrics(11) or 32          # SM_CXICON
            self._api, self._icon_size = (u32, shell), sz
            # 出す値(起動前の set_status の最新値を含む)を取る。
            with self._lock:
                tip, icon = self.tooltip, self.icon_path
            hicon = u32.LoadImageW(0, icon, IMAGE_ICON, sz, sz, LR_LOADFROMFILE)
            if not hicon:
                raise OSError("LoadImageW failed: %s" % icon)

            class GUID(ctypes.Structure):
                _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                            ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

            class NID(ctypes.Structure):
                # NOTIFYICONDATAW の完全形(Vista 以降)。以前は szTip までで切った独自サイズを
                # cbSize にしていた: どの版のサイズとも一致しない cbSize をシェルがどの版として
                # 読むかは保証されず、V1 扱いなら szTip は 64 文字(状態表示の文言が切れる)。
                _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                            ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                            ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                            ("szTip", wintypes.WCHAR * 128),
                            ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                            ("szInfo", wintypes.WCHAR * 256), ("uVersion", wintypes.UINT),
                            ("szInfoTitle", wintypes.WCHAR * 64),
                            ("dwInfoFlags", wintypes.DWORD), ("guidItem", GUID),
                            ("hBalloonIcon", wintypes.HICON)]
            nid = NID()
            nid.cbSize = ctypes.sizeof(NID)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            nid.uCallbackMessage = WM_TRAY
            nid.hIcon = hicon
            nid.szTip = tip
            shell.Shell_NotifyIconW.argtypes = [DWORD, ctypes.c_void_p]
            self._nid, self._u32 = nid, u32
            # HWND を公開する直前に停止要求を確認。公開後の stop は必ず窓へ
            # WM_DESTROY を送れるので、初期化中の stop を上書きしない。
            with self._lock:
                if self._stop_requested.is_set():
                    return
                self._hwnd = hwnd
                pending_status = self.tooltip != tip or self.icon_path != icon
            self._added = bool(shell.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))
            self._applied_tip = tip
            self._applied_icon = icon if hicon else None   # 読めなかったら次の更新で再試行
            if not self._added:
                self._readd_error = "Shell_NotifyIconW(NIM_ADD) failed"
                self._schedule_retry()
            elif pending_status:
                self._apply_status()       # 公開前の set_status はメッセージを投げていない
            self._running = not self._stop_requested.is_set()
            self._start_ok = self._running
            self._ready.set()

            msg = wintypes.MSG()
            while not self._stop_requested.is_set():
                result = u32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
                if result <= 0:
                    if result < 0:
                        self._start_error = "GetMessageW failed"
                    break
                if not msg.hWnd and msg.message == WM_TRAY_STATUS:
                    self._apply_status()
                    continue
                u32.TranslateMessage(ctypes.byref(msg))
                u32.DispatchMessageW(ctypes.byref(msg))
        except Exception as e:
            self._start_error = repr(e)
        finally:
            # 例外時も窓・クラス・アイコンを所有スレッドで回収する。
            with self._lock:
                self._hwnd = None
            self._running = self._start_ok = False
            self._ready.set()
            try:
                if u32 is not None and hwnd:
                    self._clear_retry(hwnd)
                if shell is not None and nid is not None:
                    shell.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass
            self._nid, self._added, self._api = None, False, None
            if u32 is not None:
                try:
                    icon_handle = nid.hIcon if nid is not None else hicon
                    if icon_handle:
                        u32.DestroyIcon(icon_handle)
                except Exception:
                    pass
                try:
                    if hwnd:
                        u32.DestroyWindow(hwnd)
                except Exception:
                    pass
                if registered:
                    try:
                        if u32.UnregisterClassW(self._class_name, hinst):
                            self._wndproc = None
                    except Exception:
                        pass

    def _schedule_retry(self):
        """一つの窓タイマーだけで、Shell の一時失敗を所有スレッドから再試行する。"""
        if self._retry_timer or not self._hwnd or self._api is None:
            return
        try:
            if self._api[0].SetTimer(self._hwnd, _RETRY_TIMER, _RETRY_MS, None):
                self._retry_timer = True
                return
            error = "SetTimer failed: tray retry unavailable"
        except Exception as exc:
            error = "Tray retry unavailable: " + repr(exc)
        # This runs on the owner thread. Without a retry, a missing/stale icon
        # would otherwise remain a successful, live tray indefinitely.
        self._start_error = error
        self._stop_requested.set()

    def _clear_retry(self, hwnd=None):
        if not self._retry_timer:
            return
        self._retry_timer = False
        try:
            if self._api is not None:
                self._api[0].KillTimer(hwnd or self._hwnd, _RETRY_TIMER)
        except Exception:
            pass

    def _apply_status(self):
        """set_status で記録された最新値をトレイへ反映する(NIM_MODIFY)。**トレイのスレッドの
        窓プロシージャからだけ**呼ぶ。変わった部分だけ送り、アイコンを替えたら前のハンドルは
        破棄する(シェルは自前の複製を持つ)。例外は外へ出さない(窓プロシージャで落とさない)。"""
        try:
            nid, api = self._nid, self._api
            if nid is None or api is None or not self._added:
                return
            import ctypes
            u32, shell = api
            self._apply_thread = threading.get_ident()
            with self._lock:
                tip, icon = self.tooltip, self.icon_path
            flags, new_icon, err = 0, None, None
            if tip != self._applied_tip:
                flags |= NIF_TIP
            if icon and icon != self._applied_icon:
                sz = self._icon_size
                new_icon = u32.LoadImageW(0, icon, IMAGE_ICON, sz, sz, LR_LOADFROMFILE)
                if new_icon:
                    flags |= NIF_ICON
                else:
                    err = "LoadImageW failed: %s" % icon
            if flags:
                old_icon = nid.hIcon
                try:
                    nid.uFlags = flags
                    nid.szTip = tip
                    if new_icon:
                        nid.hIcon = new_icon
                    notified = bool(shell.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid)))
                except Exception:
                    if new_icon:
                        nid.hIcon = old_icon
                        u32.DestroyIcon(new_icon)
                    raise
                if notified:
                    self._applied_tip = tip
                    if new_icon:
                        self._applied_icon = icon
                        if old_icon:
                            u32.DestroyIcon(old_icon)
                else:
                    if new_icon:
                        nid.hIcon = old_icon
                        u32.DestroyIcon(new_icon)
                    err = "Shell_NotifyIconW(NIM_MODIFY) failed"
            self._status_error = err
            if err:
                self._schedule_retry()
            elif not self._readd_error:
                self._clear_retry()
        except Exception as e:
            self._status_error = repr(e)
            self._schedule_retry()

    def _on_message(self, hwnd, msg, wp, lp):
        """窓プロシージャの本体(トレイのスレッドで呼ばれる。WM_DESTROY だけは _run の窓
        プロシージャが扱う)。処理したら 0、既定の処理(DefWindowProcW)へ回すなら None。"""
        if msg and msg == self._wm_taskbar:            # 0(未登録)を WM_NULL と取り違えない
            self._readd()                              # Explorer の再起動で通知領域が作り直された
            return 0
        if msg == WM_TRAY_STATUS:
            self._apply_status()                       # set_status の反映(このスレッドで)
            return 0
        if msg == WM_TIMER and wp == _RETRY_TIMER:
            if not self._added or self._readd_error:
                self._readd()
            else:
                self._apply_status()
            return 0
        if msg == WM_TRAY and lp in (WM_RBUTTONUP, WM_LBUTTONDBLCLK):
            if lp == WM_LBUTTONDBLCLK:
                self._dispatch(1)                      # 既定アクション(=最初の項目)
            else:
                self._popup(hwnd)
            return 0
        if msg == WM_COMMAND:
            if not (wp >> 16) and not lp:
                self._dispatch(wp & 0xFFFF)
            return 0
        return None

    def _readd(self):
        """通知領域が作り直された(TaskbarCreated)ので、アイコンを NIM_ADD で追加し直す。
        **トレイのスレッドの窓プロシージャからだけ**呼ぶ。出すのは起動時の値ではなく *最新の*
        ツールチップ/アイコン(反映待ちの set_status の値も含む)。アイコンが変わっていなければ
        手元のハンドルをそのまま渡す(シェルは自前の複製を持つ)。差し替えるなら、追加できてから
        前のハンドルを破棄し、追加できなければ新しい方を破棄して元に戻す(手元の nid.hIcon は
        常に有効な 1 個=終了時に破棄する)。アイコンが残っている(作り直されていない)と NIM_ADD は
        失敗するので NIM_MODIFY で揃える。起動時の追加に失敗していた(Explorer がまだ無かった)
        トレイもここで出る。例外は外へ出さない(窓プロシージャで落とさない)。"""
        try:
            nid, api = self._nid, self._api
            if nid is None or api is None:
                return
            import ctypes
            u32, shell = api
            self._readd_thread = threading.get_ident()
            with self._lock:
                tip, icon = self.tooltip, self.icon_path
            old_icon, new_icon, err, done = nid.hIcon, None, None, None
            if icon and (icon != self._applied_icon or not old_icon):
                sz = self._icon_size
                new_icon = u32.LoadImageW(0, icon, IMAGE_ICON, sz, sz, LR_LOADFROMFILE)
                if not new_icon:
                    err = "LoadImageW failed: %s" % icon   # 手元のアイコンで出し、次の更新で再試行
            try:
                nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
                nid.szTip = tip
                if new_icon:
                    nid.hIcon = new_icon
                for op in (NIM_ADD, NIM_MODIFY):
                    if shell.Shell_NotifyIconW(op, ctypes.byref(nid)):
                        done = op
                        break
            finally:
                if done is None and new_icon:          # 渡せなかった新しいハンドルは捨てる
                    nid.hIcon = old_icon
                    u32.DestroyIcon(new_icon)
            if done is None:
                self._readd_error = "Shell_NotifyIconW(NIM_ADD) failed"
                self._schedule_retry()
                return
            self._added = True                         # 以後の set_status は NIM_MODIFY で届く
            self._applied_tip = tip
            if new_icon:
                self._applied_icon = icon
                if old_icon:
                    u32.DestroyIcon(old_icon)
            self._status_error = err                   # 表示は最新の値になった(前の失敗は解消)
            self._readd_op, self._readd_error = done, err
            self._readd_count += 1                     # 最後に数える(テストはこれを待つ)
            if err:
                self._schedule_retry()
            else:
                self._clear_retry()
        except Exception as e:
            self._readd_error = repr(e)
            self._schedule_retry()

    def _popup(self, hwnd):
        if self._stop_requested.is_set():
            return
        import ctypes
        u32 = ctypes.windll.user32
        try:
            menu = u32.CreatePopupMenu()
        except Exception:
            return
        if not menu:
            return
        try:
            with self._lock:
                status_lines = self._status_lines
            for i, item in enumerate(self.menu_items, start=1):
                if item is None:
                    appended = u32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                else:
                    appended = u32.AppendMenuW(menu, MF_STRING, i, item[0])
                if not appended:
                    return
            if status_lines:
                if not u32.AppendMenuW(menu, MF_SEPARATOR, 0, None):
                    return
                for line in status_lines:
                    if not u32.AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, line):
                        return
            from ctypes import wintypes
            pt = wintypes.POINT()
            if not u32.GetCursorPos(ctypes.byref(pt)):
                return
            u32.SetForegroundWindow(hwnd)              # メニューが即閉じないように
            u32.TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, None)
            u32.PostMessageW(hwnd, 0, 0, 0)
        except Exception:
            pass                                        # Win32 callback へ例外を出さない
        finally:
            try:
                u32.DestroyMenu(menu)
            except Exception:
                pass

    def _dispatch(self, cmd_id):
        if self._stop_requested.is_set():
            return
        idx = cmd_id - 1
        if 0 <= idx < len(self.menu_items) and self.menu_items[idx]:
            try:
                self.on_action(self.menu_items[idx][1])
            except Exception:
                pass
