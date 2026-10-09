"""
test_sweep_rv_autostart.py — Windows の自動起動登録(タスクスケジューラ / Run キー)の回帰。
====================================================================================
総点検で入れた『配置先へ chdir してから runpy で起動する』前置き(-c ...)のせいで、
schtasks の /tr が 261 文字の上限を超え、ふつうのコマンド行(python.org 既定のユーザー単位
Python に pip install した配置など)で --install-autostart が失敗するようになっていた。

本物のタスクや Run キーは登録しない。schtasks は注入した偽物(/tr の 261 文字上限だけは本物と
同じく拒否する)、winreg も偽物で、生成されるタスク定義とコマンド行だけを確かめる。
"""
import contextlib
import functools
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from unittest import SkipTest

WIN = sys.platform.startswith("win")
# python.org の既定(ユーザー単位)インストールと、その site-packages へ pip install した配置
PER_USER_PY = r"C:\Users\Taro\AppData\Local\Programs\Python\Python312\python.exe"
PER_USER_SITE = r"C:\Users\Taro\AppData\Local\Programs\Python\Python312\Lib\site-packages"
_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
_TR_MAX = 261                     # schtasks.exe が /tr に許す最大文字数


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


@contextlib.contextmanager
def _env(**kv):
    """環境変数を一時的に差し替える(None=削除)。"""
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


class _Result:
    def __init__(self, rc, out, err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class _FakeSchtasks:
    """schtasks.exe の偽物。/tr の長さ上限は本物と同じく拒否し、/xml は渡された定義を控える。"""

    def __init__(self):
        self.calls = []
        self.xml = None
        self.xml_path = None

    def __call__(self, args, **kw):
        args = [str(a) for a in args]
        self.calls.append(args)
        if "/tr" in args and len(args[args.index("/tr") + 1]) > _TR_MAX:
            return _Result(1, "", "ERROR: Value for '/tr' option cannot be more than "
                                  "261 character(s).")
        if "/xml" in args:
            self.xml_path = args[args.index("/xml") + 1]
            with open(self.xml_path, "rb") as f:
                self.xml = f.read()
        return _Result(0, "SUCCESS: The scheduled task has successfully been created.")


def _task(xml_bytes):
    """タスク定義 XML から、確かめたい値だけを取り出す。"""
    assert xml_bytes, "schtasks にタスク定義(/xml)が渡されていない"
    assert xml_bytes[:2] in (b"\xff\xfe", b"\xfe\xff"), "BOM 付き UTF-16 で書かれていない"
    root = ET.fromstring(xml_bytes)

    def g(path):
        el = root.find(path, _NS)
        return None if el is None else (el.text or "")
    trig = root.find("t:Triggers", _NS)
    return {"command": g("t:Actions/t:Exec/t:Command"),
            "arguments": g("t:Actions/t:Exec/t:Arguments") or "",
            "workdir": g("t:Actions/t:Exec/t:WorkingDirectory"),
            "triggers": [el.tag.split("}")[-1] for el in list(trig)] if trig is not None else [],
            "run_level": g("t:Principals/t:Principal/t:RunLevel"),
            "logon_type": g("t:Principals/t:Principal/t:LogonType"),
            "time_limit": g("t:Settings/t:ExecutionTimeLimit"),
            "battery_stop": g("t:Settings/t:StopIfGoingOnBatteries"),
            "battery_start": g("t:Settings/t:DisallowStartIfOnBatteries")}


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


def _A():
    from dataplane.engine.core import autostart as A
    return A


# ── #0 pip install(ユーザー単位 Python)で /tr が 261 文字を超えて登録できなかった ──
def test_rv0_pip_install_on_per_user_python_registers_task():
    """前置き(-c "import os,runpy;os.chdir(...)...")が約 110 文字+パスを足し、引数が最小限でも
    /tr が 261 文字を超えて schtasks に拒否されていた(以前は 116 文字で登録できた)。
    タスク定義(XML)で登録し、開始位置は WorkingDirectory で渡す。"""
    A = _A()
    fake = _FakeSchtasks()
    args = ["--backend", "127.0.0.1:3000", "--listen", "8443"]
    with _patched(A, python_exe=lambda: PER_USER_PY, package_root=lambda: PER_USER_SITE):
        r = A.install_windows_task("DuckNetSweepRv", A.build_command(args), run=fake)
    assert r.get("ok"), (r, fake.calls)
    assert fake.calls and all("/tr" not in c for c in fake.calls), fake.calls
    t = _task(fake.xml)
    assert t["command"] == PER_USER_PY, t
    assert t["arguments"] == subprocess.list2cmdline(["-m", "dataplane"] + args), t   # 前置き無し
    assert t["workdir"] == PER_USER_SITE, t
    # 一時ファイルは片付ける(登録後に残さない)
    assert fake.xml_path and not os.path.exists(fake.xml_path), fake.xml_path


def test_rv0_long_ordinary_command_line_registers_task():
    """--config / --health-path などふつうの指定を足すと、ソースツリー配置でも /tr が上限を超えた。
    タスク定義には長さの上限が無いので、引数はそのまま全部届く。"""
    A = _A()
    fake = _FakeSchtasks()
    args = ["--backend", "10.0.0.15:8080", "--listen", "443", "--admin", "8081",
            "--admin-host", "127.0.0.1", "--host", "0.0.0.0", "--drain-grace", "5",
            "--config", r"C:\Users\Taro\Documents\DuckNet Gateway\production\conf\ducknet.json",
            "--health-path", "/healthz"]
    with _patched(A, python_exe=lambda: PER_USER_PY):
        r = A.install_windows_task("DuckNetSweepRv", A.build_command(args),
                                   trigger="onstart", run=fake)
    assert r.get("ok"), (r, fake.calls)
    t = _task(fake.xml)
    assert t["command"] == PER_USER_PY, t
    assert t["arguments"] == subprocess.list2cmdline(["-m", "dataplane"] + args), t
    assert len(t["arguments"]) + len(PER_USER_PY) > _TR_MAX     # 前置きが無くても /tr なら拒否される長さ
    assert t["workdir"] == A.package_root(), t
    assert t["triggers"] == ["BootTrigger"], t
    assert r.get("trigger") == "onstart", r


def test_rv0_task_definition_keeps_least_privilege_and_runs_unbounded():
    """登録の意味は /tr 時代と同じ(サインイン時/起動時・最小権限・ログオン中のユーザーで実行)。
    ゲートウェイは常駐するので、既定の『72 時間で停止』『バッテリーでは起動しない/止める』は外す。"""
    A = _A()
    for trig, want in (("onlogon", "LogonTrigger"), ("onstart", "BootTrigger"),
                       ("bogus", "LogonTrigger")):
        fake = _FakeSchtasks()
        r = A.install_windows_task("DuckNetSweepRv", ["python", "-m", "dataplane"],
                                   trigger=trig, run=fake)
        assert r.get("ok"), r
        t = _task(fake.xml)
        assert t["triggers"] == [want], (trig, t)
        assert t["run_level"] == "LeastPrivilege" and t["logon_type"] == "InteractiveToken", t
        assert t["time_limit"] == "PT0S", t
        assert t["battery_stop"] == "false" and t["battery_start"] == "false", t
    args = fake.calls[-1]
    assert args[:4] == ["schtasks", "/create", "/tn", "DuckNetSweepRv"] and "/f" in args, args


def test_rv0_task_definition_escapes_xml_and_round_trips_arguments():
    """引数に & < > " や空の値があっても、タスク定義は壊れず、そのままの argv で起動する。"""
    A = _A()
    fake = _FakeSchtasks()
    cmd = [r"C:\Program Files\Python312\python.exe", "-m", "dataplane",
           "--admin-host", 'R&D <Monitor> "Svc"', "--health-path", "", "--x", "a\\b c\\"]
    r = A.install_windows_task("R&D <Svc>", cmd, run=fake)
    assert r.get("ok"), r
    t = _task(fake.xml)
    assert t["command"] == cmd[0], t
    assert t["arguments"] == subprocess.list2cmdline(cmd[1:]), t


def test_rv0_runkey_value_for_pip_install_has_no_bootstrap():
    """site-packages に入った配置はどこから起動しても import できるので、前置き(-c)は要らない。
    付けると Run キーの値も 261 文字を超えるほど長くなっていた。"""
    A = _A()
    wr = _FakeWinreg()
    args = ["--backend", "127.0.0.1:3000", "--listen", "8443"]
    with _patched(A, python_exe=lambda: PER_USER_PY, package_root=lambda: PER_USER_SITE):
        r = A.install_windows_runkey("DuckNetSweepRv", A.build_command(args), winreg_mod=wr)
    assert r.get("ok"), r
    assert wr.val == subprocess.list2cmdline([PER_USER_PY, "-m", "dataplane"] + args), wr.val
    assert len(wr.val) <= _TR_MAX, len(wr.val)
    # venv / --user の site-packages、Linux の dist-packages も同じ扱い
    for root in (r"D:\proj\.venv\Lib\site-packages", r"C:\Users\Taro\AppData\Roaming\Python"
                 r"\Python312\site-packages", "/usr/lib/python3/dist-packages"):
        assert A.windows_command(["py", "-m", "dataplane", "--x"], root) == \
            ["py", "-m", "dataplane", "--x"], root


def test_rv0_runkey_value_for_source_checkout_keeps_short_bootstrap():
    """ソースツリー配置(pip install なし)は Run キーに開始位置が無いので前置きを残す
    (修正 #23 の意図)。パスの \\ を二重にしない短い形にする。"""
    A = _A()
    root = r"D:\Work\DuckNet"
    cmd = A.windows_command([PER_USER_PY, "-m", "dataplane", "--listen", "8443"], root)
    assert cmd[0] == PER_USER_PY and cmd[1] == "-c" and cmd[-2:] == ["--listen", "8443"], cmd
    assert "chdir(r'D:\\Work\\DuckNet')" in cmd[2], cmd[2]
    # 引用符や末尾の \ を含む場所でも Python の文字列として正しく書く
    for odd in ("D:\\", r"D:\it's here"):
        boot = A.windows_command(["py", "-m", "dataplane"], odd)[2]
        ns = {}
        exec(boot.replace("import os,runpy;os.chdir(", "_wd=(", 1).split(";runpy.")[0], ns)
        assert ns["_wd"] == odd, (odd, boot)


def test_rv0_source_checkout_task_starts_from_package_root():
    """ソースツリー配置でも、タスクは WorkingDirectory(配置先)から `-m dataplane` を起動するので
    import でき、app.env も見つかる(修正 #23 の意図を保つ)。"""
    A = _A()
    fake = _FakeSchtasks()
    r = A.install_windows_task("DuckNetSweepRv", A.build_command(["--help"]), run=fake)
    assert r.get("ok"), r
    t = _task(fake.xml)
    assert "-c" not in t["arguments"].split() and "runpy" not in t["arguments"], t
    assert t["workdir"] == A.package_root(), t
    assert os.path.isdir(os.path.join(t["workdir"], "dataplane")), t
    if not WIN:
        raise SkipTest("タスクスケジューラの起動形式(CreateProcess のコマンド行)の検証は Windows")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    line = subprocess.list2cmdline([t["command"]]) + " " + t["arguments"]
    p = subprocess.run(line, cwd=t["workdir"], env=env, capture_output=True, timeout=60)
    assert p.returncode == 0 and b"usage" in p.stdout.lower(), (p.returncode, p.stderr[-300:])


def test_rv0_install_autostart_cli_succeeds_for_long_command_line():
    """`--install-autostart` に --config / --health-path を足しただけの指定が、/tr の上限で
    『登録できませんでした』+ 見当違いの次の手順(権限)になっていた。"""
    if not WIN:
        raise SkipTest("Windows のタスクスケジューラ経路(install の分岐は sys.platform で決まる)")
    import dataplane.service as S
    A = _A()
    fake = _FakeSchtasks()

    def _no_real_schtasks(*a, **k):          # 万一注入が外れても本物の schtasks は呼ばせない
        raise AssertionError("real subprocess.run called: %r" % (a[:1],))
    serve = ["--backend", "10.0.0.15:8080", "--listen", "443", "--admin", "8081",
             "--admin-host", "127.0.0.1", "--config", r"C:\ProgramData\DuckNet\ducknet.json",
             "--health-path", "/healthz"]
    argv = ["--install-autostart"] + serve + ["--autostart-name", "DuckNetSweepRv"]
    with tempfile.TemporaryDirectory() as d, \
            _env(DUCKNET_ENV_FILE=os.path.join(d, "none.env"), DUCKNET_LANG="en"), \
            _patched(A, python_exe=lambda: PER_USER_PY,
                     install_windows_task=functools.partial(A.install_windows_task, run=fake),
                     install_windows_runkey=_no_real_schtasks), \
            _patched(subprocess, run=_no_real_schtasks), \
            open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
        rc = S.main(argv)
    assert rc == 0, fake.calls
    t = _task(fake.xml)
    assert t["command"] == PER_USER_PY, t
    assert t["arguments"] == subprocess.list2cmdline(["-m", "dataplane"] + serve), t
