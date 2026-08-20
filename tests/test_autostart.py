"""
test_autostart.py — 起動時自動起動の登録(透明・公認の場所のみ・evolution #58)。
====================================================================================
タスクスケジューラ/標準 Run キー/systemd/launchd の *純粋ビルダ* と、注入実行での登録フローを
回帰から守る。隠し永続化(珍しい ASEP)は対象にしない=標準の周知の場所だけを使うことを担保。
"""
from dataplane.engine.core import autostart as A
from dataplane.service import _strip_autostart_flags


def test_build_command_adds_supervise():
    cmd = A.build_command(["--backend", "127.0.0.1:8080", "--listen", "8443"])
    assert cmd[1:3] == ["-m", "dataplane"]
    assert "--supervise" in cmd
    assert "--backend" in cmd and "8443" in cmd
    # 既に --supervise 指定なら二重化しない
    cmd2 = A.build_command(["--supervise", "--listen", "8443"])
    assert cmd2.count("--supervise") == 1


def test_quote_handles_spaces():
    s = A._quote(["C:\\Program Files\\python.exe", "-m", "dataplane", "--stealth", "Disk Indexer"])
    assert '"C:\\Program Files\\python.exe"' in s and '"Disk Indexer"' in s
    assert " -m dataplane " in s


def test_schtasks_args_are_standard_and_named():
    args = A.schtasks_create_args("ChickenNet", 'python -m dataplane', "onstart")
    assert args[:5] == ["schtasks", "/create", "/tn", "ChickenNet", "/tr"]
    assert "/sc" in args and "ONSTART" in args and "/rl" in args and "limited" in args
    # onlogon(既定)
    assert "ONLOGON" in A.schtasks_create_args("X", "c", "onlogon")


def test_install_windows_task_uses_injected_runner():
    calls = {}

    class _R:
        returncode = 0
        stdout = "SUCCESS"
        stderr = ""

    def fake_run(args, **kw):
        calls["args"] = args
        return _R()

    r = A.install_windows_task("ChickenNet", ["python", "-m", "dataplane", "--listen", "8443"],
                               trigger="onlogon", run=fake_run)
    assert r["ok"] and r["method"] == "schtasks" and r["name"] == "ChickenNet"
    assert calls["args"][0] == "schtasks" and "/create" in calls["args"]


def test_install_windows_runkey_uses_standard_location():
    # 注入 winreg でフェイク登録 → 周知の Run キーパスのみを使うことを確認(珍しい ASEP 不使用)。
    writes = {}

    class _FakeWR:
        HKEY_CURRENT_USER = "HKCU"
        REG_SZ = 1

        def CreateKey(self, hive, sub):
            writes["hive"], writes["sub"] = hive, sub
            return "KEY"

        def SetValueEx(self, key, name, r, typ, val):
            writes["name"], writes["val"] = name, val

        def CloseKey(self, key):
            pass

    r = A.install_windows_runkey("ChickenNet", ["python", "-m", "dataplane"], winreg_mod=_FakeWR())
    assert r["ok"]
    assert writes["sub"] == r"Software\Microsoft\Windows\CurrentVersion\Run"   # 標準の場所のみ
    assert writes["name"] == "ChickenNet" and "dataplane" in writes["val"]


def test_systemd_unit_text_has_restart_and_hardening():
    u = A.systemd_unit_text(["python", "-m", "dataplane", "--listen", "8443"], user="chickennet")
    assert "Restart=on-failure" in u and "StartLimitBurst=5" in u
    assert "User=chickennet" in u and "ExecStart=" in u and "WantedBy=multi-user.target" in u


def test_launchd_plist_text_keepalive():
    p = A.launchd_plist_text("com.chickennet.x", ["python", "-m", "dataplane"])
    assert "<key>KeepAlive</key>" in p and "<key>RunAtLoad</key>" in p
    assert "<string>python</string>" in p


def test_strip_autostart_flags():
    raw = ["--install-autostart", "onstart", "--backend", "127.0.0.1:8080",
           "--autostart-name", "Svc", "--listen", "8443"]
    assert _strip_autostart_flags(raw) == ["--backend", "127.0.0.1:8080", "--listen", "8443"]
    # 値省略の --install-autostart(const)+ uninstall も除去
    raw2 = ["--install-autostart", "--uninstall-autostart", "--host", "0.0.0.0"]
    assert _strip_autostart_flags(raw2) == ["--host", "0.0.0.0"]
    # =形式
    raw3 = ["--autostart-name=Svc", "--install-autostart=runkey", "--listen", "9"]
    assert _strip_autostart_flags(raw3) == ["--listen", "9"]


def test_install_dispatch_non_windows_returns_unit(monkeypatch=None):
    # Linux/mac では unit/plist テキストを返す(手動有効化=docs/hardening.md)。
    import sys
    orig = sys.platform
    try:
        sys.platform = "linux"
        r = A.install(["--listen", "8443"], name="ChickenNet")
        assert r["method"] == "systemd" and "Restart=on-failure" in r["unit"]
        sys.platform = "darwin"
        r = A.install(["--listen", "8443"], name="ChickenNet")
        assert r["method"] == "launchd" and "KeepAlive" in r["plist"]
    finally:
        sys.platform = orig
