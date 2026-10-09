"""
test_sweep_ux_cli.py — 運用者向け CLI の結果表示(JSON の垂れ流しをやめる)の回帰。
====================================================================================
--install-autostart / --uninstall-autostart は結果の dict をそのまま JSON で出していたため、
運用者は「成功したのか」「次に何をすればよいのか」が分からなかった。

· 既定の出力は人が読む短い要約(成否の 1 行・要点・失敗時は「次の手順」)。
· --json は従来とまったく同じ JSON を出す(スクリプト互換)。
· 終了コードは従来どおり。

テスト用の継ぎ目(autostart.install / uninstall の差し替え)だけを使い、この機に実際の
自動起動エントリを登録しない。
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile

_JA_DONE = "しました"          # 日本語の完了表現(英語出力に混ざっていないことの目印)


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


def _is_json(text) -> bool:
    try:
        json.loads(text)
        return True
    except ValueError:
        return False


def _assert_readable(out):
    """人が読む出力であること: 全体が JSON でなく、JSON の行も dict の repr も含まない。"""
    assert out.strip(), "何も表示されていない"
    assert not _is_json(out), out
    for line in out.splitlines():
        s = line.strip()
        assert not (s.startswith("{") or s.startswith("[{")), ("JSON/dict の行が残っている", out)


def _main(argv, lang="ja"):
    """service.main を同一プロセスで実行し (終了コード, 標準出力+標準エラー, 標準出力) を返す。"""
    import dataplane.service as S
    tmp = tempfile.mkdtemp(prefix="ux-cli-")
    out, err = io.StringIO(), io.StringIO()
    try:
        with _env(DUCKNET_ENV_FILE=os.path.join(tmp, "none.env"), DUCKNET_LANG=lang,
                  DUCKNET_STATE_DIR=tmp), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = S.main(list(argv))
            except SystemExit as e:              # argparse の引数エラー等(ランナーごと落とさない)
                rc = e.code
    finally:
        shutil.rmtree(tmp, True)
    return rc, out.getvalue() + err.getvalue(), out.getvalue()


def _autostart(argv, result, lang="ja", plat=None, which="install"):
    """autostart.install / uninstall を差し替えて main を実行する(実登録しない)。"""
    import dataplane.service  # noqa: F401  sys.platform を差し替える前に import を済ませる
    from dataplane.engine.core import autostart as A
    seen = []

    def fake(*a, **kw):
        seen.append((a, kw))
        return dict(result)
    old_plat = sys.platform
    try:
        if plat:
            sys.platform = plat
        with _patched(A, **{which: fake}):
            rc, out, stdout = _main(argv, lang)
    finally:
        sys.platform = old_plat
    return rc, out, stdout, seen


def test_install_autostart_schtasks_ok_says_where_and_how_to_undo():
    """登録成功: 何をどこへ登録したか・確認方法・取り消し方。終了コード 0。"""
    res = {"ok": True, "method": "schtasks", "name": "DuckNet", "trigger": "onlogon",
           "detail": "SUCCESS: a'b<c"}
    rc, out, _, _ = _autostart(["--install-autostart"], res, "ja", "win32")
    assert rc == 0, out
    _assert_readable(out)
    assert out.splitlines()[0].startswith("自動起動を登録しました"), out
    assert "DuckNet" in out and "schtasks /query" in out, out
    assert "--uninstall-autostart" in out, out
    rc, out, _, _ = _autostart(["--install-autostart"], res, "en", "win32")
    assert rc == 0 and out.splitlines()[0].startswith("Autostart registered"), out
    assert "--uninstall-autostart" in out and _JA_DONE not in out, out


def test_install_autostart_failure_gives_next_step_and_exit_1():
    """登録失敗: 失敗の 1 行・OS が返した理由・次の手順(権限/ユーザー)。終了コード 1。"""
    res = {"ok": False, "method": "schtasks", "name": "DuckNet", "trigger": "onstart",
           "detail": "ERROR: Access is denied."}
    rc, out, _, _ = _autostart(["--install-autostart", "onstart"], res, "ja", "win32")
    assert rc == 1, out
    _assert_readable(out)
    assert out.splitlines()[0].startswith("自動起動を登録できませんでした"), out
    assert "Access is denied." in out and "次の手順" in out and "管理者" in out, out
    rc, out, _, _ = _autostart(["--install-autostart"], dict(res, trigger="onlogon"), "en", "win32")
    assert rc == 1 and "Next step" in out and "runkey" in out, out


def test_install_autostart_runkey_ok():
    """Run キー登録: 場所(HKCU の Run キー)と取り消しコマンド(runkey 指定付き)。"""
    res = {"ok": True, "method": "runkey",
           "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DuckNet"}
    rc, out, _, _ = _autostart(["--install-autostart", "runkey"], res, "ja", "win32")
    assert rc == 0, out
    _assert_readable(out)
    assert res["location"] in out, out
    assert "--uninstall-autostart --install-autostart runkey" in out, out


def test_install_autostart_linux_manual_steps():
    """Linux は登録せずユニット文を返す: 『まだ登録されていない』ことと保存先・有効化手順を示す。"""
    import dataplane.service  # noqa: F401
    from dataplane.engine.core import autostart as A
    old = sys.platform
    try:
        sys.platform = "linux"
        res = A.install(["--listen", "8443"], name="DuckNet")
    finally:
        sys.platform = old
    rc, out, _, _ = _autostart(["--install-autostart"], res, "ja", "linux")
    assert rc == 0, out
    _assert_readable(out)
    assert "まだ登録されていません" in out, out
    assert res["unit_path"] in out and res["enable"] in out, out
    assert "Restart=on-failure" in out and "User=ducknet" in out, out   # 保存すべき中身そのもの
    assert "systemctl disable" in out, out                             # 取り消し方
    rc, out, _, _ = _autostart(["--install-autostart"], res, "en", "linux")
    assert rc == 0 and "not registered yet" in out and res["unit_path"] in out, out


def test_install_autostart_unsupported_platform():
    res = {"ok": False, "error": "unsupported platform: a'b<c"}
    rc, out, _, _ = _autostart(["--install-autostart"], res, "en", "a'b<c")
    assert rc == 1, out
    _assert_readable(out)
    assert "Next step" in out and "docs/hardening.md" in out, out
    assert "--supervise" not in out, out                     # Lite に親監督フラグは無い


def test_install_autostart_json_is_unchanged_and_not_registered():
    """--json は従来の JSON(indent=2)をそのまま出す。--json 自体は登録コマンドに入れない。"""
    res = {"ok": True, "method": "schtasks", "name": "Svc", "trigger": "onlogon", "detail": ""}
    rc, _, out, seen = _autostart(["--install-autostart", "--json", "--autostart-name", "Svc",
                                   "--backend", "127.0.0.1:9000"], res, "ja", "win32")
    assert rc == 0
    assert out == json.dumps(res, ensure_ascii=False, indent=2) + "\n", out
    assert seen and list(seen[0][0][0]) == ["--backend", "127.0.0.1:9000"], seen
    rc, _, out, _ = _autostart(["--install-autostart", "--json"], dict(res, ok=False), "ja", "win32")
    assert rc == 1 and json.loads(out)["ok"] is False


def test_uninstall_autostart_readable_and_exit_code_unchanged():
    """解除: 成功/失敗を平文で言う。失敗時は名前・登録方式の取り違えを案内。終了コードは常に 0。"""
    ok = {"ok": True, "method": "schtasks", "name": "DuckNet"}
    rc, out, _, _ = _autostart(["--uninstall-autostart"], ok, "ja", "win32", "uninstall")
    assert rc == 0, out
    _assert_readable(out)
    assert out.splitlines()[0].startswith("自動起動を解除しました"), out
    bad = {"ok": False, "method": "schtasks", "name": "DuckNet"}
    rc, out, _, _ = _autostart(["--uninstall-autostart"], bad, "ja", "win32", "uninstall")
    assert rc == 0, out                                     # 従来どおり 0
    _assert_readable(out)
    assert out.splitlines()[0].startswith("自動起動を解除できませんでした"), out
    assert "次の手順" in out and "--autostart-name" in out and "runkey" in out, out
    rc, out, _, _ = _autostart(["--uninstall-autostart"], bad, "en", "win32", "uninstall")
    assert rc == 0 and "Next step" in out, out
    manual = {"ok": True, "action": "manual",
              "note": "systemctl disable <name> / launchctl unload <plist> で解除"}
    rc, out, _, _ = _autostart(["--uninstall-autostart"], manual, "ja", "linux", "uninstall")
    assert rc == 0, out
    _assert_readable(out)
    assert "systemctl disable --now ducknet" in out, out
    rc, _, out, _ = _autostart(["--uninstall-autostart", "--json"], bad, "ja", "win32", "uninstall")
    assert rc == 0 and out == json.dumps(bad, ensure_ascii=False) + "\n", out


def test_install_autostart_tolerates_minimal_result():
    """結果の形が想定より少なくても(テストの継ぎ目・将来の変更)表示で落ちない。"""
    rc, out, _, _ = _autostart(["--install-autostart"], {"ok": True}, "ja", "win32")
    assert rc == 0 and out.strip() and not _is_json(out), out
    rc, out, _, _ = _autostart(["--uninstall-autostart"], {}, "en", "darwin", "uninstall")
    assert rc == 0 and out.strip() and not _is_json(out), out


def test_install_autostart_survives_ascii_console():
    """非 UTF-8(ASCII しか書けない)端末でも、日本語の要約で落ちない。"""
    import dataplane.service as S
    from dataplane.engine.core import autostart as A
    raw = io.BytesIO()
    w = io.TextIOWrapper(raw, encoding="ascii", errors="strict")
    old = sys.stdout
    tmp = tempfile.mkdtemp(prefix="ux-cli-")
    res = {"ok": False, "method": "schtasks", "name": "DuckNet", "detail": "a'b<c"}
    try:
        sys.stdout = w
        with _env(DUCKNET_ENV_FILE=os.path.join(tmp, "none.env"), DUCKNET_LANG="ja",
                  DUCKNET_STATE_DIR=tmp), _patched(A, install=lambda *a, **k: dict(res)):
            rc = S.main(["--install-autostart"])
        w.flush()
    finally:
        sys.stdout = old
        shutil.rmtree(tmp, True)
    assert rc == 1
    assert "自動起動を登録できませんでした" in raw.getvalue().decode("utf-8", "replace")
