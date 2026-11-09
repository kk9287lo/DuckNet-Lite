"""
test_sweep_core.py — core 層(署名付き状態・原子 I/O・正規表現 lint・言語判定)の回帰(Lite)。
====================================================================================
各テストは「修正前のコードで落ちる」ことを確かめてある。テスト名の c<番号> は掃討時の候補番号。
"""
import errno
import json
import os
import tempfile
import threading
import time
from unittest import SkipTest


def _pop_env(*keys):
    return {k: os.environ.pop(k, None) for k in keys}


def _restore_env(old):
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── #4: 署名検証が非 ASCII / 範囲外の値で例外を投げる ────────────────────────────
def test_c4_non_ascii_signature_reads_as_tampered():
    """`_sig` を非 ASCII 文字列にすると hmac.compare_digest が TypeError を投げ、
    『例外は投げない』はずの read_signed_json から漏れて NetShield の起動自体が落ちていた。"""
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        assert ss.write_signed_json(p, {"bans": {"192.0.2.1": 1}}, b"k" * 32)
        with open(p, encoding="utf-8") as f:
            env = json.load(f)
        for bad in ("é", {"x": "é"}, ["é"]):
            env["_sig"] = bad
            with open(p, "w", encoding="utf-8") as f:
                json.dump(env, f)
            ss._MEM_HW.clear()
            st, val = ss.read_signed_json(p, b"k" * 32, {})       # 修正前: TypeError
            assert st == "tampered" and val == {}, (bad, st)
        assert ss.verify_payload({"a": 1}, "é", b"k") is False
        assert ss.verify_payload({"a": 1}, None, b"k") is False


def test_c4_poisoned_hw_sidecar_and_infinite_numbers_do_not_raise():
    """破損した .hw は例外を漏らさず改竄として拒否し、保存で証拠を洗い替えない。
    本体の _sv / _ver に Infinity を置いた場合も例外を漏らさない。"""
    from dataplane.engine.core import signed_state as ss
    key = b"k" * 32
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        assert ss.write_signed_json(p, {"bans": {}}, key)
        with open(p + ".hw", "rb") as f:
            valid_hw = f.read()
        for hw_text in ('{"_ver": 1, "_sig": "\\u00e9"}',
                        '{"_ver": Infinity, "_sig": "ab"}',
                        '{"_ver": -Infinity, "_sig": "\\u00e9"}'):
            with open(p + ".hw", "w", encoding="utf-8") as f:
                f.write(hw_text)
            ss._MEM_HW.clear()
            st, _ = ss.read_signed_json(p, key, {})                 # 修正前: TypeError/OverflowError
            assert st == "tampered", (hw_text, st)
            with open(p + ".hw", "rb") as f:
                before_hw = f.read()
            assert ss.write_signed_json(p, {"bans": {"192.0.2.9": 1}}, key) is False, hw_text
            with open(p + ".hw", "rb") as f:
                assert f.read() == before_hw
        with open(p + ".hw", "wb") as f:
            f.write(valid_hw)                 # 以後は正署名の高水位へ戻した上で本体の不正を試す
        for body in ('{"_sv": Infinity, "_sig": "ab", "_payload": {}}',
                     '{"_sv": 3, "_ver": Infinity, "_purpose": "blocklist.json", '
                     '"_sig": "ab", "_payload": {}}'):
            with open(p, "w", encoding="utf-8") as f:
                f.write(body)
            ss._MEM_HW.clear()
            st, val = ss.read_signed_json(p, key, {"d": 1})
            assert st == "tampered" and val == {"d": 1}, (body, st)
        # A present corrupt main cannot be overwritten as healthy merely
        # because its _ver is not a finite number, even with a valid .hw.
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"_ver": Infinity}')
        ss._MEM_HW.clear()
        with open(p, "rb") as f:
            corrupt_main = f.read()
        with open(p + ".hw", "rb") as f:
            trusted_hw = f.read()
        assert ss.write_signed_json(p, {"bans": {}}, key) is False
        with open(p, "rb") as f:
            assert f.read() == corrupt_main
        with open(p + ".hw", "rb") as f:
            assert f.read() == trusted_hw


def test_c4_netshield_starts_with_non_ascii_signature():
    """改竄された blocklist.json(_sig が非 ASCII)で NetShield の構築が TypeError で落ち、
    WAF が起動できなかった。改竄として既定値へ倒し、警報を上げて起動すること。"""
    from dataplane.engine.core import signed_state as ss
    from dataplane.engine.lifeform.pipeline import NetShield
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.ban("198.51.100.66", ttl_sec=3600)
        sh._save_bans(force=True)
        p = os.path.join(d, "blocklist.json")
        with open(p, encoding="utf-8") as f:
            env = json.load(f)
        env["_sig"] = "é"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(env, f)
        ss._MEM_HW.clear()
        s2 = NetShield(state_dir=d)                                 # 修正前: TypeError
        assert s2.metrics()["tamper"]["count"] >= 1


# ── #5: 空の鍵ファイルが鍵を永久に壊す ──────────────────────────────────────────
def test_c5_key_write_failure_does_not_poison_statekey():
    """鍵の新規作成直後に書込が失敗(ENOSPC)すると 0 バイトの .statekey が残り、以後の起動では
    毎回 *別の* 一時鍵が使われて、前回保存した状態がすべて『改竄』扱いで初期化されていた。"""
    from dataplane.engine.core import signed_state as ss
    old = _pop_env("DUCKNET_STATE_KEY")
    real_write = os.write

    def _enospc(fd, b):
        raise OSError(errno.ENOSPC, "No space left on device")
    try:
        with tempfile.TemporaryDirectory() as d:
            sd = os.path.join(d, "state")
            os.write = _enospc
            try:
                try:
                    ss.persistent_key(sd)
                except OSError:
                    pass                        # 永続鍵が無いなら起動を止める
                else:
                    raise AssertionError("鍵保存失敗を一時鍵で続行した")
            finally:
                os.write = real_write
            kp = os.path.join(sd, ".statekey")
            assert not os.path.exists(kp) or os.path.getsize(kp) > 0, "空の鍵ファイルが残った"
            k1 = ss.persistent_key(sd)
            k2 = ss.persistent_key(sd)
            assert k1 == k2 and len(k1) == 32
            with open(kp, "rb") as f:
                assert f.read() == k1
    finally:
        os.write = real_write
        _restore_env(old)


def test_c5_legacy_empty_key_files_are_recovered():
    """旧版のクラッシュで既に 0 バイトになった .statekey も、起動のたびに別鍵になる
    状態から回復すること(手で消すまで永久に壊れたままだった)。"""
    from dataplane.engine.core import signed_state as ss
    old = _pop_env("DUCKNET_STATE_KEY")
    try:
        with tempfile.TemporaryDirectory() as d:
            kp = os.path.join(d, ".statekey")
            open(kp, "wb").close()
            past = time.time() - 3600
            os.utime(kp, (past, past))                             # 前回起動の残骸(作成途中ではない)
            k1 = ss.persistent_key(d)
            k2 = ss.persistent_key(d)
            assert k1 == k2 and len(k1) == 32
    finally:
        _restore_env(old)


# ── #30: 孤立サロゲートで保存/追記が黙って失敗する ────────────────────────────────
def test_c30_lone_surrogate_is_persisted_not_dropped():
    """json.loads は '\\udc80' のような孤立サロゲートをそのまま作る。厳格な UTF-8 書込で
    UnicodeEncodeError になり、atomic_write_json/append_jsonl が False を返して黙って捨てていた
    (カスタム規則が保存されず再起動で全消失・監査ログ行が消える)。"""
    from dataplane.engine.core import atomic_io as aio
    from dataplane.engine.core import signed_state as ss
    marker = json.loads('"a\'b<c\\udc80"')                          # 孤立サロゲートを含む値
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "s.json")
        assert aio.atomic_write_json(p, {"pattern": marker}) is True
        assert aio.safe_read_json(p) == {"pattern": marker}
        lp = os.path.join(d, "a.jsonl")
        assert aio.append_jsonl(lp, {"e": marker}) is True
        assert aio.tail_jsonl(lp, 5) == [{"e": marker}]
        sp = os.path.join(d, "rules.json")
        assert ss.write_signed_json(sp, {"signatures": [{"pattern": marker}]}, b"k" * 32)
        ss._MEM_HW.clear()
        st, val = ss.read_signed_json(sp, b"k" * 32, {})
        assert st == "ok" and val["signatures"][0]["pattern"] == marker


# ── #31: U+0085/U+2028/U+2029 を含むログ行が末尾読みから消える ─────────────────────
def test_c31_tail_jsonl_keeps_lines_with_unicode_line_separators():
    """tail_jsonl が str.splitlines() で分割していたため、U+0085(NEL)/U+2028/U+2029 を含む
    記録が 2 つの壊れた断片に割れて捨てられ、管理画面から消えていた(ログ回避)。"""
    from dataplane.engine.core import atomic_io as aio
    with tempfile.TemporaryDirectory() as d:
        lp = os.path.join(d, "txn.jsonl")
        recs = [{"i": 0, "ua": "normal"}, {"i": 1, "ua": "x\x85y"},
                {"i": 2, "ua": "x y"}, {"i": 3, "ua": "x y"},
                {"i": 4, "ua": "normal"}]
        for r in recs:
            assert aio.append_jsonl(lp, r)
        assert [r["i"] for r in aio.tail_jsonl(lp, 10)] == [4, 3, 2, 1, 0]
        assert [r["i"] for r in aio.tail_jsonl(lp, 2)] == [4, 3]


# ── 状態 JSON のサイズ確認後にファイルが成長する競合 ──────────────────────────
def test_state_read_stays_bounded_if_file_grows_after_size_check():
    """サイズ確認後の追記でも巨大な JSON を解析せず、正常な .tmp へ回復する。"""
    from unittest.mock import patch
    from dataplane.engine.core import atomic_io as aio
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state.json")
        with open(p, "wb") as f:
            f.write(b'{"v":1}')
        with open(p + ".tmp", "wb") as f:
            f.write(b'{"v":2}')
        original_size = os.path.getsize
        grown = False

        def grow_after_check(path):
            nonlocal grown
            size = original_size(path)
            if path == p and not grown:
                grown = True
                with open(p, "ab") as f:
                    f.write(b" " * 65)       # JSON としては有効なまま上限を超える
            return size

        with patch.object(aio, "_MAX_READ_BYTES", 64), \
                patch.object(aio.os.path, "getsize", side_effect=grow_after_check):
            assert aio.safe_read_json(p, "missing") == {"v": 2}
        assert grown
        exact = os.path.join(d, "exact.json")
        with open(exact, "wb") as f:
            f.write(b'{"v":3}' + b" " * (64 - len(b'{"v":3}')))
        with patch.object(aio, "_MAX_READ_BYTES", 64):
            assert aio.safe_read_json(exact, "missing") == {"v": 3}


# ── #32: Windows の共有違反で書込/読込が黙って失敗する ─────────────────────────────
def _hold_exclusive(path: str, seconds: float):
    """path を共有なし(dwShareMode=0)で開き、seconds 後に閉じる(Windows の共有違反を再現)。"""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.CreateFileW(path, 0x80000000, 0, None, 3, 0x80, None)   # GENERIC_READ, OPEN_EXISTING
    if h is None or h == wintypes.HANDLE(-1).value:
        raise SkipTest("CreateFileW で排他ハンドルを取れない")
    t = threading.Timer(seconds, k32.CloseHandle, args=(h,))
    t.start()
    return t


def test_c32_windows_sharing_violation_is_retried():
    """Windows では他のハンドルが開いている間 os.replace/open が PermissionError になる。
    再試行が無く、読み手が 1 つ居るだけで保存が失敗し(False)、読み手は存在する状態ファイルを
    『欠損』と見て既定値を返し、追記ログは行を失っていた。"""
    if os.name != "nt":
        raise SkipTest("共有違反は Windows 固有")
    from dataplane.engine.core import atomic_io as aio
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "s.json")
        assert aio.atomic_write_json(p, {"v": 1})
        # (1) 読み手が開いたまま(FILE_SHARE_DELETE なし)でも、閉じた後に置換が通る
        f = open(p, "rb")
        t = threading.Timer(0.1, f.close)
        t.start()
        try:
            assert aio.atomic_write_json(p, {"v": 2}) is True       # 修正前: False
        finally:
            t.join()
            f.close()
        assert aio.safe_read_json(p) == {"v": 2}
        # (2) 一時的に開けない状態ファイルを『欠損』扱いしない
        t = _hold_exclusive(p, 0.1)
        try:
            assert aio.safe_read_json(p, "MISSING") == {"v": 2}     # 修正前: 'MISSING'
        finally:
            t.join()
        # (3) 追記ログも一時的な共有違反で行を落とさない
        lp = os.path.join(d, "audit.jsonl")
        assert aio.append_jsonl(lp, {"i": 0})
        t = _hold_exclusive(lp, 0.1)
        try:
            assert aio.append_jsonl(lp, {"i": 1}) is True            # 修正前: False
        finally:
            t.join()
        assert [r["i"] for r in aio.tail_jsonl(lp, 5)] == [1, 0]


def test_c32_concurrent_appends_with_rotation_lose_nothing():
    """同一プロセス内の複数スレッドが、ローテーションを跨いで追記しても行を失わないこと。"""
    from dataplane.engine.core import atomic_io as aio
    with tempfile.TemporaryDirectory() as d:
        lp = os.path.join(d, "audit.jsonl")
        n_threads, per = 6, 120
        oks = []

        def _w(tid):
            for i in range(per):
                oks.append(aio.append_jsonl(lp, {"t": tid, "i": i, "pad": "x" * 40},
                                            max_bytes=4000, backups=50))
        ts = [threading.Thread(target=_w, args=(k,)) for k in range(n_threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert all(oks), oks.count(False)
        total = 0
        for name in os.listdir(d):
            with open(os.path.join(d, name), "rb") as f:
                total += sum(1 for ln in f.read().split(b"\n") if ln.strip())
        assert total == n_threads * per, total


# ── #71: 有界反復/省略可能要素の指数的パターンが lint を通る ─────────────────────────
def test_c71_lint_flags_exponential_bounded_and_optional_repeats():
    """(a?){N}a{N} や (a|aa){24}b、(a?a?)+b は数十文字の入力で秒〜分単位を消費する
    (実測: (a|a?){18}b が 20 文字で 156 秒)のに、外側が有界 {N} だったり内側が ? だったりすると
    lint を素通りし、カスタム規則として登録できた。"""
    from dataplane.engine.core import saferegex as sr
    for bad in (r"(a?){26}a{26}", r"(a|aa){24}b", r"(a{1,2}){24}b", r"(a|a?){18}b",
                r"(a?a?)+b", r"(?:x?y?){30}z", r"((a)?){12}", r"^\s*\s*\s*\s*x$",
                r".*.*=.*", r"(a?){4,30}b"):
        assert sr.lint(bad) != "", bad
    # 実用的で安全なものは従来どおり通す
    for ok in (r"(\d{1,3}\.){3}\d{1,3}", r"(a{3}){2}b", r"([0-9a-f]{2}:){5}[0-9a-f]{2}",
               r"(?:https?://)?example\.com", r"(?i)\bunion\b\s+select\b",
               r"colou?r", r"(?P<k>ab){2}", r"\d{1,3}\.\d{1,3}", r"(abc)?def",
               r"\s*=\s*", r"a*?b", r"(?:ab){10}",
               r"\b(?:\d[ -]?){13,19}\b"):                  # カード番号検出(区切りで一意=線形)
        assert sr.lint(ok) == "", (ok, sr.lint(ok))


# ── #72: LC_ALL/LC_MESSAGES が LANG より優先されない ────────────────────────────
def test_c72_locale_precedence_and_language_code():
    """英語の変数が 1 つでもあれば英語にしていたため、LANG=en_US のサーバで LC_ALL=ja_JP を
    設定しても英語になった。また '_us' を含むだけで es_US(スペイン語)も英語扱いだった。"""
    from dataplane.engine.core import i18n
    keys = ("DUCKNET_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")
    old = _pop_env(*keys)
    try:
        for env, expect in (
                ({"LC_ALL": "ja_JP.UTF-8", "LANG": "en_US.UTF-8"}, "ja"),
                ({"LC_MESSAGES": "ja_JP.UTF-8", "LANG": "en_US.UTF-8"}, "ja"),
                ({"LANGUAGE": "ja_JP:ja", "LANG": "en_US.UTF-8"}, "ja"),    # gettext と同じく最上位
                ({"LANGUAGE": "en_US:en", "LANG": "ja_JP.UTF-8"}, "en"),
                ({"LANG": "es_US.UTF-8"}, "ja"),
                ({"LANG": "cy_GB.UTF-8"}, "ja"),
                ({"LC_ALL": "C", "LC_MESSAGES": "en_US.UTF-8", "LANG": "ja_JP.UTF-8"}, "en"),
                ({"LANG": "en_US.UTF-8"}, "en"),
                ({"LANG": "en"}, "en"),
                ({"LANGUAGE": "en_GB:ja"}, "en"),
        ):
            for k in keys:
                os.environ.pop(k, None)
            os.environ.update(env)
            assert i18n.lang() == expect, (env, i18n.lang())
    finally:
        for k in keys:
            os.environ.pop(k, None)
        _restore_env(old)


# ── #44: 状態ファイル/マーカーの削除で改竄検知を迂回できる ─────────────────────────
def test_c44_deleting_signed_state_or_marker_is_reported_as_tamper():
    """署名済みで保存した実績(署名付きサイドカー .hw)があるのに、(a) 状態ファイルを消す、
    (b) .state_signed マーカーを消して平文の state.json/blocklist.json を置く、だけで
    BAN 全消し・監査モード化が改竄警報ゼロで通っていた。"""
    from dataplane.engine.core import signed_state as ss
    from dataplane.engine.lifeform.pipeline import NetShield
    # (b) マーカー削除+平文差し替え
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.enable()
        sh.ban("203.0.113.7", permanent=True)
        sh._save_bans(force=True)
        assert os.path.exists(os.path.join(d, "blocklist.json.hw"))
        os.remove(os.path.join(d, ".state_signed"))
        with open(os.path.join(d, "state.json"), "w", encoding="utf-8") as f:
            json.dump({"cfg": {"enabled": True, "mode": "audit"}}, f)
        with open(os.path.join(d, "blocklist.json"), "w", encoding="utf-8") as f:
            json.dump({"bans": {}}, f)
        ss._MEM_HW.clear()                                           # 再起動相当
        s2 = NetShield(state_dir=d)
        assert s2.cfg.get("mode") != "audit"
        assert s2.metrics()["tamper"]["count"] >= 2, s2.metrics()["tamper"]
    # (a) 状態ファイルの削除
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.enable()
        sh.ban("203.0.113.8", permanent=True)
        sh._save_bans(force=True)
        os.remove(os.path.join(d, "blocklist.json"))
        os.remove(os.path.join(d, "state.json"))
        ss._MEM_HW.clear()
        s2 = NetShield(state_dir=d)
        tam = s2.metrics()["tamper"]
        assert tam["count"] >= 2, tam
    # 初回起動・正常な再起動は改竄扱いしない(誤警報を出さない)
    with tempfile.TemporaryDirectory() as d:
        s1 = NetShield(state_dir=d)
        assert s1.metrics()["tamper"]["count"] == 0
        s1.enable()
        s1._save_bans(force=True)
        ss._MEM_HW.clear()
        s2 = NetShield(state_dir=d)
        assert s2.metrics()["tamper"]["count"] == 0, s2.metrics()["tamper"]
