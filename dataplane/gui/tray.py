"""
tray.py — システムトレイ(Windows Shell_NotifyIcon・ctypes・標準ライブラリのみ)
====================================================================================
タスクトレイに DuckNet.ico を常駐させ、右クリックでプロ用メニューを出す。依存ゼロのため
pystray 等は使わず Win32 API を ctypes で直接叩く。別スレッドのメッセージループで動かし、
メニュー選択はコールバックで通知する。非 Windows / 失敗時は no-op(アプリは継続)。

正直な範囲: Windows 専用(他 OS は available=False)。ステルス時は呼び出し側が生成可否を選ぶ。
"""
from __future__ import annotations

import os
import threading

WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
WM_TRAY = 0x0400 + 1            # WM_USER+1(トレイコールバック)
NIM_ADD, NIM_DELETE = 0x0, 0x2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x10, 0x40
TPM_RIGHTBUTTON = 0x2
MF_STRING, MF_SEPARATOR = 0x0, 0x800


def available() -> bool:
    import sys
    return sys.platform.startswith("win")


class TrayIcon:
    """トレイ常駐アイコン。menu_items=[(label, action_id) or None(区切り)]、on_action(action_id)。"""

    def __init__(self, icon_path: str, tooltip: str, menu_items, on_action):
        self.icon_path = icon_path
        self.tooltip = tooltip[:120]
        self.menu_items = list(menu_items)
        self.on_action = on_action
        self._thread = None
        self._hwnd = None
        self._running = False
        self._nid = None

    def start(self) -> bool:
        if not available():
            return False
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="tray")
        self._thread.start()
        return True

    def stop(self):
        self._running = False
        try:
            import ctypes
            if self._hwnd:
                ctypes.windll.user32.PostMessageW(self._hwnd, WM_DESTROY, 0, 0)
        except Exception:
            pass

    # ── 内部: 別スレッドの Win32 メッセージループ ──
    def _run(self):
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
            u32.DispatchMessageW.restype = LRESULT
            u32.PostQuitMessage.argtypes = [INT]
            u32.CreatePopupMenu.restype = HMENU
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
            shell.Shell_NotifyIconW.restype = BOOL

            WNDPROC = ctypes.WINFUNCTYPE(LRESULT, HWND, UINT, WP, LP)

            def wndproc(hwnd, msg, wp, lp):
                if msg == WM_TRAY and lp in (WM_RBUTTONUP, WM_LBUTTONDBLCLK):
                    if lp == WM_LBUTTONDBLCLK:
                        self._dispatch(1)              # 既定アクション(=最初の項目)
                    else:
                        self._popup(hwnd)
                    return 0
                if msg == WM_COMMAND:
                    self._dispatch(wp & 0xFFFF)
                    return 0
                if msg == WM_DESTROY:
                    u32.PostQuitMessage(0)
                    return 0
                return u32.DefWindowProcW(hwnd, msg, wp, lp)

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
            wc.lpszClassName = "DuckNetTrayWnd"
            u32.RegisterClassW(ctypes.byref(wc))
            self._hwnd = u32.CreateWindowExW(0, "DuckNetTrayWnd", "DuckNet", 0,
                                             0, 0, 0, 0, 0, 0, hinst, 0)
            # 大アイコン(SM_CXICON=32px 既定)で読み込む。隠れインジケータ表示や高DPIで鮮明・
            # 大きく見える。トレイ内の実寸は OS のトレイセルサイズに従う。
            sz = u32.GetSystemMetrics(11) or 32          # SM_CXICON
            hicon = u32.LoadImageW(0, self.icon_path, IMAGE_ICON, sz, sz, LR_LOADFROMFILE)

            class NID(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                            ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                            ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                            ("szTip", wintypes.WCHAR * 128)]
            nid = NID()
            nid.cbSize = ctypes.sizeof(NID)
            nid.hWnd = self._hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            nid.uCallbackMessage = WM_TRAY
            nid.hIcon = hicon
            nid.szTip = self.tooltip
            shell.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
            self._nid, self._u32 = nid, u32
            self._running = True

            msg = wintypes.MSG()
            while self._running and u32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
                u32.TranslateMessage(ctypes.byref(msg))
                u32.DispatchMessageW(ctypes.byref(msg))
            try:
                shell.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass
        except Exception:
            pass                                       # トレイ失敗はアプリを止めない

    def _popup(self, hwnd):
        import ctypes
        u32 = ctypes.windll.user32
        menu = u32.CreatePopupMenu()
        for i, item in enumerate(self.menu_items, start=1):
            if item is None:
                u32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
            else:
                u32.AppendMenuW(menu, MF_STRING, i, item[0])
        pt = ctypes.wintypes.POINT() if hasattr(ctypes, "wintypes") else None
        from ctypes import wintypes
        pt = wintypes.POINT()
        u32.GetCursorPos(ctypes.byref(pt))
        u32.SetForegroundWindow(hwnd)                  # メニューが即閉じないように
        u32.TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, None)
        u32.PostMessageW(hwnd, 0, 0, 0)
        u32.DestroyMenu(menu)

    def _dispatch(self, cmd_id):
        idx = cmd_id - 1
        if 0 <= idx < len(self.menu_items) and self.menu_items[idx]:
            try:
                self.on_action(self.menu_items[idx][1])
            except Exception:
                pass
