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


def package_root() -> str:
    """dataplane パッケージの親ディレクトリ(ソースツリー配置ならリポジトリ直下=app.env の場所)。"""
    here = os.path.abspath(__file__)                   # …/dataplane/engine/core/autostart.py
    for _ in range(4):
        here = os.path.dirname(here)
    return here


def needs_chdir(root: str = "") -> bool:
    """`python -m dataplane` を起動位置に頼らず import できない配置か。
    site-packages / dist-packages(pip install・venv・--user)は既定の sys.path に入るので
    どこから起動しても import できる。それ以外(ソースツリー・解凍しただけ・editable)は
    安全側で『要る』とみなす。区切りは \\ と / の両方を見る(テストは OS を問わず走る)。"""
    base = str(root or package_root()).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return base.lower() not in ("site-packages", "dist-packages")


def _py_str(s: str) -> str:
    """-c に埋め込む Python の文字列リテラル。repr は \\ を二重にしてコマンド行を長くするので、
    安全なら raw 文字列で書く(' を含む・末尾が \\ の場所だけ repr)。"""
    if "'" in s or "\n" in s or "\r" in s or s.endswith("\\"):
        return repr(s)
    return "r'%s'" % s


def windows_command(command, workdir: str = "") -> list:
    """Run キー用に `python -m dataplane …` を起動位置に依らない形へ置き換える。
    Run キーは『開始位置』を持たず %windir%\\System32 で起動するため、pip install 不要の
    ソースツリー配置では `-m dataplane` が import できず即死していた(登録自体は ok:true)。
    起動直後に配置先へ chdir してから同じモジュールを実行する(app.env も CWD で見つかる)。
    site-packages 配置は前置き不要なので付けない(付けるとコマンド行が 110 文字以上延びる)。
    タスクスケジューラは WorkingDirectory を持てるので task_xml を使い、この前置きは使わない。"""
    cmd = [str(a) for a in command]
    if len(cmd) >= 3 and cmd[1] == "-m" and cmd[2] == "dataplane":
        root = workdir or package_root()
        if needs_chdir(root):
            boot = ("import os,runpy;os.chdir(%s);runpy.run_module('dataplane',run_name='__main__')"
                    % _py_str(root))
            cmd = [cmd[0], "-c", boot] + cmd[3:]
    return cmd


def _quote(cmd) -> str:
    """argv を1本のコマンド行へ(Windows: CreateProcess / CommandLineToArgvW の規則)。
    以前は空白を含む要素を "" で囲むだけで、空の要素は消え、埋め込みの " は落ち、
    `C:\\x y\\` の末尾 \\ が閉じ引用符を壊して後続の引数まで飲み込んでいた。"""
    import subprocess
    return subprocess.list2cmdline([str(a) for a in cmd])


def _quote_systemd(cmd) -> str:
    """systemd の ExecStart= 用のコマンド行。C 風エスケープ(\\ と ")を施し、必要なら "" で囲む。
    % は指定子、$ は環境変数として展開されるので %% / $$ にする。空の要素も "" で残す。"""
    out = []
    for a in cmd:
        a = str(a)
        e = (a.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
             .replace("%", "%%").replace("$", "$$"))
        if not a or any(ch in a for ch in " \t\n\"'\\;"):
            e = f'"{e}"'
        out.append(e)
    return " ".join(out)


# ── Windows: タスクスケジューラ ──────────────────────────────────────────
def _xml_text(s) -> str:
    # CR はそのままだと XML の読み込みで LF に正規化されるので文字参照で残す
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\r", "&#13;"))


def task_xml(command, *, trigger: str = "onlogon", workdir: str = "") -> str:
    """タスクスケジューラのタスク定義(XML・純粋)。trigger: onlogon(ログオン時)/ onstart(ブート時)。
    `schtasks /create /tr` は値が 261 文字までで、配置先へ chdir する前置きを足すと python.org 既定の
    ユーザー単位 Python や --config 付きのふつうの指定でも超えて登録できなかった。定義なら長さの
    上限が無く、開始位置を WorkingDirectory で渡せるので前置きも要らない。
    意味は /tr 時代と同じ: 誰かのサインイン時(LogonTrigger)/起動時(BootTrigger)に、登録した
    ユーザーとしてログオン中に実行(InteractiveToken)・最小権限(LeastPrivilege=/rl limited)。
    常駐するゲートウェイなので、既定の『72 時間で停止』『バッテリーでは起動しない/止める』は外す。"""
    cmd = [str(a) for a in command]
    trig = "BootTrigger" if str(trigger).lower() == "onstart" else "LogonTrigger"
    args = _quote(cmd[1:])
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        "    <Description>DuckNet gateway (registered by --install-autostart)</Description>\n"
        "  </RegistrationInfo>\n"
        f"  <Triggers>\n    <{trig}>\n      <Enabled>true</Enabled>\n    </{trig}>\n  </Triggers>\n"
        '  <Principals>\n    <Principal id="Author">\n'
        "      <LogonType>InteractiveToken</LogonType>\n"
        "      <RunLevel>LeastPrivilege</RunLevel>\n"
        "    </Principal>\n  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        "    <Enabled>true</Enabled>\n"
        "  </Settings>\n"
        '  <Actions Context="Author">\n    <Exec>\n'
        f"      <Command>{_xml_text(cmd[0])}</Command>\n"
        + (f"      <Arguments>{_xml_text(args)}</Arguments>\n" if args else "")
        + f"      <WorkingDirectory>{_xml_text(workdir or package_root())}</WorkingDirectory>\n"
        "    </Exec>\n  </Actions>\n"
        "</Task>\n")


def schtasks_create_args(name: str, xml_path: str) -> list:
    """`schtasks /create` の argv(純粋)。定義は task_xml を書いたファイル。/f=既存を上書き。"""
    return ["schtasks", "/create", "/tn", name, "/xml", xml_path, "/f"]


def schtasks_delete_args(name: str) -> list:
    return ["schtasks", "/delete", "/tn", name, "/f"]


def install_windows_task(name, command, *, trigger="onlogon", run=None) -> dict:
    """タスクスケジューラへ登録(明示名=Task Scheduler で可視)。run は subprocess.run を注入可能。
    定義は BOM 付き UTF-16 の一時ファイルで渡し(schtasks が確実に読める形)、登録後に消す。"""
    import subprocess
    import tempfile
    run = run or subprocess.run
    path = ""
    try:
        fd, path = tempfile.mkstemp(prefix="ducknet-task-", suffix=".xml")
        with os.fdopen(fd, "w", encoding="utf-16") as f:
            f.write(task_xml(command, trigger=trigger))
        r = run(schtasks_create_args(name, path), capture_output=True,
                stdin=subprocess.DEVNULL, timeout=30, text=True)
        return {"ok": getattr(r, "returncode", 1) == 0, "method": "schtasks",
                "name": name, "trigger": trigger,
                "detail": (getattr(r, "stdout", "") or getattr(r, "stderr", "")).strip()}
    except Exception as e:
        return {"ok": False, "method": "schtasks", "name": name, "error": str(e)}
    finally:
        if path:
            try:
                os.remove(path)
            except OSError:
                pass


def uninstall_windows_task(name, *, run=None) -> dict:
    import subprocess
    run = run or subprocess.run
    try:
        r = run(schtasks_delete_args(name), capture_output=True, stdin=subprocess.DEVNULL, timeout=30, text=True)
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
            wr.SetValueEx(key, name, 0, wr.REG_SZ, _quote(windows_command(command)))
        finally:
            wr.CloseKey(key)
        return {"ok": True, "method": "runkey",
                "location": r"HKCU\%s\%s" % (_RUNKEY_SUBPATH, name)}
    except Exception as e:
        return {"ok": False, "method": "runkey", "error": str(e)}


# ── Linux: systemd / macOS: launchd(ユニット文の生成=純粋) ───────────────
def systemd_unit_text(command, *, user: str = "ducknet",
                      description: str = "DuckNet L7 Security",
                      workdir: str = "") -> str:
    """systemd unit を生成する。生成物には環境の受け渡しが無く、app.env に置いた設定が
    systemd 経由の起動でだけ効かなかった(手動起動や run.sh とは挙動が食い違う)。
    作業ディレクトリと EnvironmentFile を明示する(ファイルが無ければ '-' で無視される)。"""
    exec_start = _quote_systemd(command)
    workdir = workdir or os.getcwd()
    return (
        "[Unit]\n"
        f"Description={description}\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\n"
        f"User={user}\n"
        f"WorkingDirectory={workdir}\n"
        f"EnvironmentFile=-{workdir}/app.env\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\nRestartSec=2\n"
        "StartLimitIntervalSec=60\nStartLimitBurst=5\n\n"
        "[Install]\nWantedBy=multi-user.target\n")


def launchd_plist_text(label, command, *, workdir: str = "") -> str:
    """launchd plist を生成する。値は XML エスケープする(以前は & や < を含む引数で不正な XML に
    なり launchctl load が失敗した)。WorkingDirectory を明示しないと launchd は / で起動し、
    ソースツリー配置の `-m dataplane` が import できない。"""
    def _x(s):   # xml.sax.saxutils は import 時に urllib.request を引き込む(プラットフォーム依存)ので自前で
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    args = "".join(f"    <string>{_x(a)}</string>\n" for a in command)
    wd = workdir or package_root()
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f"  <key>Label</key><string>{_x(str(label))}</string>\n"
        f"  <key>WorkingDirectory</key><string>{_x(wd)}</string>\n"
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
