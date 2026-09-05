"""
autostart.py — 起動時自動起動の登録(透明・OS 公認の場所のみ・標準ライブラリ)
====================================================================================
ブート/ログオン時に DuckNet を自動起動する設定を *透明な* 仕組みで登録する。

  · Windows … タスクスケジューラ(schtasks・明示名)/ 標準 Run キー
    (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)。
  · Linux  … systemd unit(`systemctl enable`)。
  · macOS  … launchd plist(LaunchDaemons/LaunchAgents)。

いずれも **管理者が標準ツールで一覧・無効化できる周知の場所**だけを使う(Task Scheduler /
Autoruns / スタートアップタブ / `systemctl` / `launchctl`)。『一般に使われない珍しいレジストリ
位置に隠す』ような *目立たなさを狙った* 永続化(MITRE ATT&CK T1547/T1112)は **行わない**:
それは防御目的でも rootkit/persistence になり、製品自身が脅威化するため(本書 §線引き参照)。

純粋ビルダ(コマンド/引数/ユニット文)とテスト可能な薄い実行(run/winreg は注入可能)に分ける。
"""
from __future__ import annotations

import os
import sys

# 標準(周知)の Run キーのみ。Image File Execution Options 等の珍しい ASEP は意図的に非対応。
_RUNKEY_SUBPATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


def python_exe() -> str:
    return sys.executable or "python"


def build_command(args) -> list:
    """登録する起動コマンド(argv リスト)。`python -m dataplane <args>`。
    クラッシュからの自動再起動は OS 側の回復設定(systemd Restart= / Windows サービス回復 /
    launchd KeepAlive)に委ねる(アプリ自身は親監督フラグを持たない)。"""
    cmd = [python_exe(), "-m", "dataplane"]
    cmd += list(args)
    return cmd


def _quote(cmd) -> str:
    """argv を1本のコマンド文字列へ(空白を含む要素は二重引用符で囲う)。"""
    out = []
    for a in cmd:
        a = str(a)
        out.append(f'"{a}"' if (" " in a or "\t" in a) else a)
    return " ".join(out)


# ── Windows: タスクスケジューラ ──────────────────────────────────────────
def schtasks_create_args(name: str, command_str: str, trigger: str = "onlogon") -> list:
    """`schtasks /create` の argv(純粋)。trigger: onlogon(ログオン時)/ onstart(ブート時)。
    /rl limited=最小権限で実行(昇格しない)。/f=既存を上書き。"""
    sc = "ONSTART" if str(trigger).lower() == "onstart" else "ONLOGON"
    return ["schtasks", "/create", "/tn", name, "/tr", command_str,
            "/sc", sc, "/rl", "limited", "/f"]


def schtasks_delete_args(name: str) -> list:
    return ["schtasks", "/delete", "/tn", name, "/f"]


def install_windows_task(name, command, *, trigger="onlogon", run=None) -> dict:
    """タスクスケジューラへ登録(明示名=Task Scheduler で可視)。run は subprocess.run を注入可能。"""
    import subprocess
    run = run or subprocess.run
    args = schtasks_create_args(name, _quote(command), trigger)
    try:
        r = run(args, capture_output=True, text=True)
        return {"ok": getattr(r, "returncode", 1) == 0, "method": "schtasks",
                "name": name, "trigger": trigger,
                "detail": (getattr(r, "stdout", "") or getattr(r, "stderr", "")).strip()}
    except Exception as e:
        return {"ok": False, "method": "schtasks", "name": name, "error": str(e)}


def uninstall_windows_task(name, *, run=None) -> dict:
    import subprocess
    run = run or subprocess.run
    try:
        r = run(schtasks_delete_args(name), capture_output=True, text=True)
        return {"ok": getattr(r, "returncode", 1) == 0, "method": "schtasks", "name": name}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Windows: 標準 Run キー(周知の場所) ─────────────────────────────────
def install_windows_runkey(name, command, *, winreg_mod=None) -> dict:
    """標準 Run キー(HKCU\\...\\CurrentVersion\\Run)へ登録。Autoruns/スタートアップタブで可視。
    winreg は注入可能(テスト)。"""
    try:
        import winreg as _wr
    except Exception:
        _wr = None
    wr = winreg_mod or _wr
    if wr is None:
        return {"ok": False, "error": "winreg unavailable (non-Windows)"}
    try:
        key = wr.CreateKey(wr.HKEY_CURRENT_USER, _RUNKEY_SUBPATH)
        try:
            wr.SetValueEx(key, name, 0, wr.REG_SZ, _quote(command))
        finally:
            wr.CloseKey(key)
        return {"ok": True, "method": "runkey",
                "location": r"HKCU\%s\%s" % (_RUNKEY_SUBPATH, name)}
    except Exception as e:
        return {"ok": False, "method": "runkey", "error": str(e)}


# ── Linux: systemd / macOS: launchd(ユニット文の生成=純粋) ───────────────
def systemd_unit_text(command, *, user: str = "ducknet",
                      description: str = "DuckNet-Lite") -> str:
    exec_start = _quote(command)
    return (
        "[Unit]\n"
        f"Description={description}\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\n"
        f"User={user}\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\nRestartSec=2\n"
        "StartLimitIntervalSec=60\nStartLimitBurst=5\n\n"
        "[Install]\nWantedBy=multi-user.target\n")


def launchd_plist_text(label, command) -> str:
    args = "".join(f"    <string>{a}</string>\n" for a in command)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f"  <key>Label</key><string>{label}</string>\n"
        "  <key>ProgramArguments</key>\n  <array>\n" + args + "  </array>\n"
        "  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "</dict></plist>\n")


def install(args, *, method: str = "auto", name: str = "DuckNet",
            trigger: str = "onlogon") -> dict:
    """プラットフォームに応じて自動起動を登録/案内する。Windows は実登録(schtasks/runkey)、
    Linux/macOS は unit/plist テキストと配置先を返す(#56 docs/hardening.md に沿って有効化)。"""
    command = build_command(args)
    plat = sys.platform
    if plat.startswith("win"):
        m = "runkey" if method == "runkey" else "schtasks"
        if m == "runkey":
            return install_windows_runkey(name, command)
        return install_windows_task(name, command, trigger=trigger)
    if plat.startswith("linux"):
        return {"ok": True, "method": "systemd", "action": "manual",
                "unit_path": f"/etc/systemd/system/{name.lower()}.service",
                "unit": systemd_unit_text(command),
                "enable": f"systemctl daemon-reload && systemctl enable --now {name.lower()}",
                "note": "ユニットを書き出して systemctl enable で有効化(docs/hardening.md §2)"}
    if plat == "darwin":
        label = f"com.ducknet.{name.lower()}"
        return {"ok": True, "method": "launchd", "action": "manual",
                "plist_path": f"/Library/LaunchDaemons/{label}.plist",
                "plist": launchd_plist_text(label, command),
                "enable": f"launchctl load -w /Library/LaunchDaemons/{label}.plist",
                "note": "plist を書き出して launchctl load で有効化(docs/hardening.md §4)"}
    return {"ok": False, "error": f"unsupported platform: {plat}"}


def uninstall(*, method: str = "auto", name: str = "DuckNet") -> dict:
    plat = sys.platform
    if plat.startswith("win"):
        if method == "runkey":
            try:
                import winreg as wr
                key = wr.OpenKey(wr.HKEY_CURRENT_USER, _RUNKEY_SUBPATH, 0, wr.KEY_SET_VALUE)
                try:
                    wr.DeleteValue(key, name)
                finally:
                    wr.CloseKey(key)
                return {"ok": True, "method": "runkey"}
            except Exception as e:
                return {"ok": False, "error": str(e)}
        return uninstall_windows_task(name)
    return {"ok": True, "action": "manual",
            "note": "systemctl disable <name> / launchctl unload <plist> で解除"}
