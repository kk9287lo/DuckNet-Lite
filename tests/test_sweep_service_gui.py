"""
test_sweep_service_gui.py — 起動系・トレイ・自動起動まわりの回帰(service / gui / autostart / ランチャ)。
====================================================================================
どれも「その場では成功に見えるが、実運用で黙って壊れる」種類の不具合。各テストは修正前の
コードで実際に落ちることを確認してある。OS/環境の前提が無いものは SkipTest で明示的に飛ばす。
"""
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from unittest import SkipTest


def _empty_env_path(directory):
    path = os.path.join(directory, "none.env")
    with open(path, "w", encoding="utf-8"):
        pass
    return path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIN = sys.platform.startswith("win")


@contextlib.contextmanager
def _env(**kv):
    """環境変数を一時的に差し替える(None=削除)。抜けるときに必ず元へ戻す。"""
    saved = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def _patched(obj, **attrs):
    """obj の属性を一時的に差し替える。"""
    saved = {k: getattr(obj, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(obj, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(obj, k, v)


def _tray_main():
    import dataplane.gui.__main__ as G
    return G


class _FakeSubprocess:
    """_spawn_gateway が組み立てる Popen 引数だけを捕まえる(実プロセスは起動しない)。"""
    DEVNULL = subprocess.DEVNULL
    PIPE = subprocess.PIPE

    def __init__(self):
        self.calls = []

    def Popen(self, cmd, **kw):
        self.calls.append((list(cmd), dict(kw)))
        return None


def _kill(p):
    if p is not None and p.poll() is None:
        p.kill()
        try:
            p.wait(timeout=5)
        except Exception:
            pass


# ── #21 run.ps1 が Windows PowerShell 5.1(日本語版 Windows)で構文解析できない ──
def test_c21_run_ps1_has_utf8_bom():
    """BOM 無し UTF-8 の .ps1 を Windows PowerShell 5.1 は ANSI コードページ(日本語版は cp932)
    で読む。コメント末尾のバイト列が改行を飲み込み、波括弧が閉じずに起動前に ParserError に
    なっていた。非 ASCII を含むなら BOM 付き UTF-8 で保存する。"""
    with open(os.path.join(ROOT, "run.ps1"), "rb") as f:
        raw = f.read()
    if any(b >= 0x80 for b in raw):
        assert raw.startswith(b"\xef\xbb\xbf"), "非 ASCII を含む run.ps1 に UTF-8 BOM が無い"


def test_c21_run_ps1_parses_in_windows_powershell():
    """実機の Windows PowerShell 5.1 で構文解析エラーが 0 件であること(無ければ SKIP)。"""
    exe = shutil.which("powershell.exe") or shutil.which("powershell")
    if not WIN or not exe:
        raise SkipTest("Windows PowerShell 5.1 が無い環境")
    ps = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::"
          "ParseFile($env:SWEEP_PS1,[ref]$t,[ref]$e);[Console]::Out.Write($e.Count)")
    env = dict(os.environ)
    env["SWEEP_PS1"] = os.path.join(ROOT, "run.ps1")
    r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, env=env, timeout=60)
    out = r.stdout.decode("ascii", "replace").strip()
    if not out.isdigit():
        raise SkipTest("PowerShell を実行できない: %r" % (r.stderr[-200:],))
    assert out == "0", "run.ps1 の構文エラー %s 件" % out


# ── #22 / #43 略記の --install-autostart が登録コマンドに残っていた ──
def test_c22_abbreviated_autostart_flags_are_stripped():
    """argparse は曖昧でない略記(--install / --install-auto / --autostart-n)を受理する。
    除去が完全一致だけだったので略記が登録コマンドに残り、ログオン/起動のたびに『自動起動を
    再登録して終了』するだけでゲートウェイが起動しなかった(登録は ok:true と報告される)。"""
    import dataplane.service as S
    from dataplane.engine.core import autostart as A
    seen = []
    want = ["--backend", "127.0.0.1:9000"]
    cases = (["--install", "onstart", "--backend", "127.0.0.1:9000"],
             ["--backend", "127.0.0.1:9000", "--install-auto"],
             ["--install-autos=runkey", "--autostart-n", "Svc", "--backend", "127.0.0.1:9000"],
             ["--ins", "--autostart-name=Svc", "--backend", "127.0.0.1:9000"])
    with tempfile.TemporaryDirectory() as d, \
            _env(DUCKNET_ENV_FILE=_empty_env_path(d)), \
            _patched(A, install=lambda args, **kw: (seen.append(list(args)), {"ok": True})[1]), \
            open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
        for argv in cases:
            seen.clear()
            assert S.main(list(argv)) == 0, argv
            assert seen and seen[0] == want, (argv, seen)
    assert S._strip_autostart_flags(["--uninstall-auto", "--listen", "9"]) == ["--listen", "9"]


# ── #23 / #33 Windows の自動起動コマンドが作業ディレクトリに依存していた ──
class _FakeWinreg:
    HKEY_CURRENT_USER = "HKCU"
    REG_SZ = 1

    def __init__(self):
        self.val = None

    def CreateKey(self, hive, sub):
        return "KEY"

    def SetValueEx(self, key, name, r, typ, val):
        self.val = val

    def CloseKey(self, key):
        pass


def _runkey_value(A, command):
    wr = _FakeWinreg()
    r = A.install_windows_runkey("DuckNetSweep", command, winreg_mod=wr)
    assert r["ok"], r
    return wr.val


def test_c23_windows_autostart_command_runs_outside_checkout():
    """タスクスケジューラ/Run キーは開始位置を持たず System32 で起動するため、登録された
    `python -m dataplane` は(pip install 不要のソースツリー配置では)import できず即死して
    いた。登録コマンドを作業ディレクトリ非依存にする。"""
    if not WIN:
        raise SkipTest("Windows の Run キー/タスクの起動形式(CreateProcess)の検証")
    from dataplane.engine.core import autostart as A
    val = _runkey_value(A, A.build_command(["--help"]))
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run(val, cwd=d, env=env, capture_output=True, timeout=60)
    assert r.returncode == 0 and b"usage" in r.stdout.lower(), (
        r.returncode, r.stderr[-300:])
    # タスクスケジューラ側は開始位置(WorkingDirectory)を持てるので、前置きなしの同じコマンドを
    # 配置先から起動する定義で登録する(/tr は 261 文字までで前置きを足すと超えていた)
    import xml.etree.ElementTree as ET
    seen = {}

    class _R:
        returncode = 0
        stdout = "SUCCESS"
        stderr = ""

    def _run(args, **kw):
        with open(args[args.index("/xml") + 1], "rb") as f:
            seen["xml"] = f.read()
        return _R()
    A.install_windows_task("DuckNetSweep", A.build_command(["--help"]), run=_run)
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    ex = ET.fromstring(seen["xml"]).find("t:Actions/t:Exec", ns)
    exe, argl, wd = (ex.find("t:" + k, ns).text for k in ("Command", "Arguments", "WorkingDirectory"))
    line = subprocess.list2cmdline([exe]) + " " + argl
    r = subprocess.run(line, cwd=wd, env=env, capture_output=True, timeout=60)
    assert r.returncode == 0 and b"usage" in r.stdout.lower(), (r.returncode, r.stderr[-300:])


# ── #33 / #62 引数の引用が壊れていた(空文字・埋め込み " ・末尾 \ ・XML 未エスケープ) ──
def test_c62_windows_command_line_round_trips_arguments():
    """空白のある要素を "" で囲むだけだったので、空の値は消え、埋め込みの " は落ち、
    `C:\\x y\\` の末尾 \\ が閉じ引用符を壊して後続の引数まで飲み込んでいた。"""
    if not WIN:
        raise SkipTest("CreateProcess のコマンド行解釈の検証(Windows)")
    from dataplane.engine.core import autostart as A
    probe = "import sys,json;sys.stdout.write(json.dumps(sys.argv[1:]))"
    args = ["--health-path", "", "--listen", "9000", "--config", 'My "cfg"',
            "--config", "C:\\Program Files\\duck\\", "--note", "a\\\\b c", "--x", "y"]
    val = _runkey_value(A, [sys.executable, "-c", probe] + args)
    r = subprocess.run(val, capture_output=True, timeout=30)
    assert json.loads(r.stdout.decode("utf-8")) == args, r.stdout


def test_c62_launchd_plist_is_well_formed_and_sets_workdir():
    """plist へ引数をそのまま埋め込んでいたため & や < を含む値で不正な XML になり、
    launchctl load が失敗した。WorkingDirectory も無く `-m dataplane` が import できない。"""
    import plistlib
    from dataplane.engine.core import autostart as A
    cmd = ["/usr/bin/python3", "-m", "dataplane", "--config", "/srv/R&D <cfg>.json",
           "--health-path", ""]
    d = plistlib.loads(A.launchd_plist_text("com.ducknet.r&d", cmd).encode("utf-8"))
    assert d["ProgramArguments"] == cmd
    assert d["Label"] == "com.ducknet.r&d"
    wd = d.get("WorkingDirectory", "")
    assert wd and os.path.isdir(os.path.join(wd, "dataplane")), wd


def _systemd_split(line):
    """systemd の ExecStart= の語分割(引用符・C エスケープ・%% / $$)を必要な範囲で再現する。
    単独の % / $ は systemd が指定子/環境変数として展開してしまうので印を付けて区別する。"""
    out, i, n = [], 0, len(line)

    def _unspecial(s):
        r, j = [], 0
        while j < len(s):
            ch = s[j]
            if ch in "%$":
                if j + 1 < len(s) and s[j + 1] == ch:
                    r.append(ch)
                    j += 2
                    continue
                r.append("<EXPANDED:%s>" % ch)
                j += 1
                continue
            r.append(ch)
            j += 1
        return "".join(r)

    while i < n:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n:
            break
        buf = []
        q = line[i] if line[i] in "\"'" else ""
        if q:
            i += 1
        while i < n and (line[i] != q if q else line[i] not in " \t"):
            if line[i] == "\\" and i + 1 < n:
                buf.append({"n": "\n", "t": "\t"}.get(line[i + 1], line[i + 1]))
                i += 2
                continue
            buf.append(line[i])
            i += 1
        if q:
            i += 1
        out.append(_unspecial("".join(buf)))
    return out


def test_c62_systemd_execstart_round_trips_arguments():
    """ExecStart= も同じ簡易引用で、空の値は消え、% と $ は systemd に展開されていた。"""
    from dataplane.engine.core import autostart as A
    cmd = ["/usr/bin/python3", "-m", "dataplane", "--health-path", "",
           "--config", 'My "cfg" 100% $HOME', "--config", "/srv/duck dir/", "--x", "a\\b"]
    unit = A.systemd_unit_text(cmd, workdir="/srv/duck")
    line = [ln for ln in unit.splitlines() if ln.startswith("ExecStart=")][0]
    assert _systemd_split(line[len("ExecStart="):]) == cmd, line


# ── #63(Lite も同じ構造) 起動待ちの間の Ctrl-C で本体が孤児で残った ──
def test_c63_tray_stops_spawned_gateway_on_interrupt():
    """本体を子プロセスで起動した後の待機中に Ctrl-C 等で抜けると、子が残っていた。"""
    G = _tray_main()
    kids = []

    def _spawn(*a, **k):
        kids.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                     stdin=subprocess.DEVNULL))
        return kids[-1]
    m = {"up": 0}

    def _up(h, p, timeout=0.5):
        m["up"] += 1
        if m["up"] > 1:
            raise KeyboardInterrupt
        return False
    try:
        with _patched(G, _gateway_up=_up, _spawn_gateway=_spawn):
            try:
                G._ensure_gateway("http://127.0.0.1:18089", "tok")
                raise AssertionError("KeyboardInterrupt が握り潰された")
            except KeyboardInterrupt:
                pass
        assert kids
        kids[0].wait(timeout=10)                  # 修正前は 30 秒生き続ける
    finally:
        for k in kids:
            _kill(k)


# ── #64 トレイの『終了』が本体を強制終了していた ──
def test_c64_quit_stops_spawned_gateway_gracefully():
    """_stop_child は terminate() だけだった。Windows では TerminateProcess=即死で、
    停止処理(ドレイン・BAN の flush)が一切走らない(子は CREATE_NO_WINDOW なので
    CTRL_BREAK も届かない)。トレイが握る標準入力で停止を依頼し、待ってから強制終了へ落ちる。"""
    G = _tray_main()
    fake = _FakeSubprocess()
    with _patched(G, subprocess=fake):
        G._spawn_gateway(18081, "tok")
    cmd, kw = fake.calls[0]
    assert kw.get("stdin") == subprocess.PIPE, "本体へ停止を依頼する経路が無い"
    fd, marker = tempfile.mkstemp(prefix="sweep-flush-")
    os.close(fd)
    os.unlink(marker)
    fd, ready = tempfile.mkstemp(prefix="sweep-stop-ready-")
    os.close(fd)
    os.unlink(ready)
    code = "\n".join((
        "import sys",
        "sys.path.insert(0, sys.argv[1])",
        "open(sys.argv[3], 'w').write('spawned')",
        "import dataplane.service as service",
        "open(sys.argv[3], 'w').write('imported')",
        "original = service._watch_stdin_stop",
        "def marked_watch(event):",
        "    installed = original(event)",
        "    if installed:",
        "        open(sys.argv[3], 'w').write('ready')",
        "    return installed",
        "service._watch_stdin_stop = marked_watch",
        "service._block_until_shutdown(lambda: open(sys.argv[2], 'w').write('flushed'))",
    ))
    kw = dict(kw)
    kw["stdout"] = subprocess.DEVNULL
    kw["stderr"] = subprocess.PIPE
    child = subprocess.Popen([sys.executable, "-c", code, ROOT, marker, ready], **kw)
    try:
        def ready_stage():
            if not os.path.exists(ready):
                return "missing"
            with open(ready, encoding="ascii") as observed:
                return observed.read()

        deadline = time.monotonic() + 30
        while ready_stage() != "ready" and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if ready_stage() != "ready":
            detail = (child.stderr.read().decode("utf-8", "replace")[-500:]
                      if child.poll() is not None else "still running")
            raise AssertionError(f"子の停止受け口が起動していない: stage={ready_stage()} {detail}")
        G._stop_child(child)
        assert child.poll() is not None
        assert os.path.exists(marker), "停止処理(flush 等)が走らないまま終了した"
        with open(marker) as f:
            assert f.read() == "flushed"
        assert child.returncode == 0, child.returncode
    finally:
        _kill(child)
        child.stderr.close()
        if os.path.exists(marker):
            os.unlink(marker)
        if os.path.exists(ready):
            os.unlink(ready)


def test_c64_stdin_stop_is_opt_in():
    """停止依頼の受け口はトレイが起動した子(env で明示)だけ。通常起動では標準入力を読まない。"""
    import dataplane.service as S
    ev = threading.Event()
    with _env(DUCKNET_STDIN_STOP=None):
        assert S._watch_stdin_stop(ev) is False
    assert not ev.is_set()


# ── #66 ランチャが app.env の引用符付きの値をそのまま export していた ──
_ENV_LINES = ['DUCKNET_SWEEP_A="C:/duck state"', "DUCKNET_SWEEP_B='s3cret'",
              "DUCKNET_SWEEP_C=plain value", 'DUCKNET_SWEEP_D="a!b & c"',
              "DUCKNET_SWEEP_E= 'padded' "]
_ENV_WANT = {"DUCKNET_SWEEP_A": "C:/duck state", "DUCKNET_SWEEP_B": "s3cret",
             "DUCKNET_SWEEP_C": "plain value", "DUCKNET_SWEEP_D": "a!b & c",
             "DUCKNET_SWEEP_E": "padded"}


def _launcher_dir(d, script, extra=()):
    """ランチャ+app.env+『受け取った環境変数を出すだけ』の偽 dataplane を一時dirに置く。
    偽物は load_env_file を呼ばないので、出力はシェルが export した値そのもの。"""
    shutil.copy(os.path.join(ROOT, script), os.path.join(d, script))
    with open(os.path.join(d, "app.env"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(list(_ENV_LINES) + list(extra)) + "\n")
    pkg = os.path.join(d, "dataplane")
    os.makedirs(pkg)
    open(os.path.join(pkg, "__init__.py"), "w").close()
    with open(os.path.join(pkg, "__main__.py"), "w", encoding="utf-8") as f:
        f.write("import json, os, sys\n"
                "env = {k.upper(): v for k, v in os.environ.items()\n"
                "       if k.upper().startswith('DUCKNET_SWEEP_')}\n"
                "sys.stdout.write('SWEEP' + json.dumps(env))\n")


def _launcher_env(py):
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith("DUCKNET_SWEEP_")
           and k.upper() not in ("DUCKNET_ENV_FILE", "PYTHONPATH")}
    env["DUCKNET_PYTHON"] = py
    return env


def _launcher_result(r):
    out = r.stdout.decode("utf-8", "replace")
    if "SWEEP" not in out:
        raise SkipTest("ランチャから Python を起動できない環境: rc=%s %r"
                       % (r.returncode, r.stderr[-200:]))
    return json.loads(out[out.index("SWEEP") + 5:].strip())


def test_c66_run_bat_strips_quotes_like_load_env_file():
    """run.bat は app.env の値を引用符ごと set しており、load_env_file(引用符を外す)より先に
    環境へ入るので製品側の解釈が負けた(状態dirが '"C:/duck state"' になる等)。"""
    if not WIN:
        raise SkipTest("cmd.exe が無い環境")
    # 引用符を外すようにした結果、DUCKNET_PYTHON="C:\Program Files\…\python.exe"(空白入り)を
    # 書いた app.env で起動できなくならないこと。環境変数で引用符なしに渡した場合も同様。
    for how in ("app.env", "env"):
        with tempfile.TemporaryDirectory() as d:
            extra = ['DUCKNET_PYTHON="%s"' % sys.executable] if how == "app.env" else []
            _launcher_dir(d, "run.bat", extra=extra)
            env = _launcher_env(sys.executable)
            if how == "app.env":
                env.pop("DUCKNET_PYTHON")
            r = subprocess.run(["cmd.exe", "/d", "/c", os.path.join(d, "run.bat")], cwd=d,
                               env=env, capture_output=True, timeout=60)
        out = r.stdout.decode("utf-8", "replace")
        assert "SWEEP" in out, (how, r.returncode, r.stderr[-300:])
        got = json.loads(out[out.index("SWEEP") + 5:].strip())
        assert got == _ENV_WANT, (how, got)


def test_c66_run_sh_strips_quotes_like_load_env_file():
    """run.sh も同じく引用符付きの値を export していた。"""
    bash = shutil.which("bash")
    # WSL の bash(system32 / WindowsApps の起動スタブ)では Windows の Python を呼べない。
    # WindowsApps のスタブは呼び出し後も中継プロセスが残り、一時dirを掴んで後始末を失敗させていた。
    if not bash or (WIN and any(s in bash.lower() for s in ("system32", "windowsapps"))):
        raise SkipTest("bash が無い環境(WSL の bash は対象外)")
    py = sys.executable.replace("\\", "/") if WIN else sys.executable
    d = tempfile.mkdtemp(prefix="sweep-run-sh-")
    try:
        _launcher_dir(d, "run.sh")
        r = subprocess.run([bash, os.path.join(d, "run.sh").replace("\\", "/")], cwd=d,
                           env=_launcher_env(py), capture_output=True, timeout=60)
    finally:
        shutil.rmtree(d, True)          # 残ったプロセスが掴んでいても後始末でテストを落とさない
    got = _launcher_result(r)
    assert got == _ENV_WANT, got


def test_c66_run_ps1_strips_quotes_like_load_env_file():
    """run.ps1 も同じく引用符付きの値を環境へ入れていた。Windows PowerShell 5.1 では
    Get-Content が app.env を ANSI(日本語版は cp932)で読むため、非 ASCII の値も化けていた。"""
    exes = [e for e in (shutil.which("pwsh"),
                        shutil.which("powershell.exe") or shutil.which("powershell")) if e]
    if not exes:
        raise SkipTest("PowerShell が無い環境")
    want = dict(_ENV_WANT, DUCKNET_SWEEP_F="ディスク索引")
    for exe in exes:
        with tempfile.TemporaryDirectory() as d:
            _launcher_dir(d, "run.ps1", extra=["DUCKNET_SWEEP_F=ディスク索引"])
            r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                                "Bypass", "-File", os.path.join(d, "run.ps1")], cwd=d,
                               env=_launcher_env(sys.executable), capture_output=True,
                               timeout=60)
        got = _launcher_result(r)
        assert got == want, (exe, got, r.stderr[-300:])


# ── #81 IPv6 の管理URLで起動した本体を見つけられなかった ──
def test_c81_tray_spawns_gateway_on_the_probed_admin_host():
    """DUCKNET_ADMIN_URL が http://[::1]:PORT のとき、到達確認は ::1 に行うのに本体へは
    --admin-host 127.0.0.1 を渡しており、起動した本体を永遠に見つけられなかった。
    ループバック以外/HTTPS へ別の plain HTTP 子を誤って起動しない。"""
    G = _tray_main()
    fake = _FakeSubprocess()
    with _patched(G, subprocess=fake, _gateway_up=lambda h, p, timeout=0.5: False):
        G._ensure_gateway("http://[::1]:18081", "tok")
        G._ensure_gateway("http://127.0.0.1:18081", "tok")
        G._ensure_gateway("http://192.0.2.10:18081", "tok")
        G._ensure_gateway("https://127.0.0.1:18081", "tok")
    hosts = [c[c.index("--admin-host") + 1] for c, _kw in fake.calls]
    assert hosts == ["::1", "127.0.0.1"], hosts


# ── #94 トレイが app.env の DUCKNET_ADMIN_URL / DUCKNET_COVER を無視していた ──
def test_c94_tray_reads_admin_url_and_cover_after_app_env():
    """接続先と表示名を import 時(load_env_file より前)に固めていたので、
    `python -m dataplane.gui` では app.env の値が効かず、既定の :8081 を開き、ステルス運用でも
    トレイに製品名が出ていた。"""
    G = _tray_main()
    seen = {}

    class _Tray:
        def __init__(self, icon, tip, items, cb):
            seen["brand"] = tip

        def start(self):
            return False                          # 起動失敗の経路で main() を抜ける

    def _ensure(url, tok):
        seen["url"] = url
        return "", None
    with tempfile.TemporaryDirectory() as d:
        env_file = os.path.join(d, "app.env")
        with open(env_file, "w", encoding="utf-8") as f:
            f.write("DUCKNET_ADMIN_URL=http://127.0.0.1:18099\nDUCKNET_COVER=Disk Indexer\n")
        with _env(DUCKNET_ENV_FILE=env_file, DUCKNET_ADMIN_URL=None, DUCKNET_COVER=None), \
                _patched(G.tray, available=lambda: True, TrayIcon=_Tray), \
                _patched(G, _ensure_gateway=_ensure), \
                open(os.devnull, "w") as devnull, contextlib.redirect_stderr(devnull):
            G.main([])
    assert seen.get("url") == "http://127.0.0.1:18099", seen
    assert seen.get("brand", "").startswith("Disk Indexer — "), seen
    assert "状態を確認できません" in seen["brand"], seen
