"""
test_sweep_rem_jsonesc.py — JSON 本文の短いエスケープ(\\n \\r)を値の改行として読む(sweep: rem_jsonesc・既知の限界の解消)。
====================================================================================
· 本文の crlf・rce(';' 連結)・sqli-stacked の照合は、値に符号化して入れた改行(%0D%0A・&#10;・\\u000a)を
  ';' として読む見え方を使う(det3_crlf・rv_bodynorm)。ところが JSON.stringify / json.dumps が改行を
  書く標準の形 \\r\\n(バックスラッシュ + r / n の短いエスケープ)は復号されず、同じ値を JSON で送ると
  その見え方に載らなかった(\\u000a の形だけが載った)。
· 直しても他の検知の見え方(本文の走査面)は変えない。JSON の文章の改行(複数行のコメント・住所・
  コード片)、JSON 文字列の中で二重にエスケープされた \\\\n(コード片の文字列リテラル)、JSON でない本文
  (フォーム・multipart・テキスト)に書かれた \\n は 0 点のまま。
入力は無害な文章か、既存テストにある fixture だけを使う。
"""
import json
import tempfile
from urllib.parse import unquote_plus

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield, _normalize_full
from test_sweep_dec_headfold import _FW_EVASION
from test_sweep_det2_signatures import _PROSE_BODIES
from test_sweep_det3_crlf import _CRLF_FIXTURES, _LINE_BREAK_BODIES, _multipart
from test_sweep_det_normalize import BROWSER_MULTIPART
from test_sweep_rv_bodynorm import _JA_OTHER, _JA_TITLES, _STACKED_NL

_JSON = "application/json"
_BS = chr(92)                     # バックスラッシュ(エスケープをソースに直書きしない)

# 改行を含む普通の文章(JSON の値として送る)。日本語と英語の複数行コメント・住所・コード片。
_MULTILINE_TEXTS = (
    "いつもありがとうございます。\n本日発送しました。\n到着まで少々お待ちください。",
    "〒100-0001\n東京都千代田区千代田1-1\n営業部 御中",
    "レビュー: とても良い店でした。\r\n猫用の餌も早く届きました。\r\n星5つです。",
    "宛先；To: 営業部の皆さん\n件名：来週の予定\n詳細は追って連絡します。",
    "Hi team,\nTo: everyone in sales\nPlease update the deck before Friday.",
    "Thanks for the fix!\r\nUpdate: works now.\r\nCat food arrived fast.",
    "221B Baker Street\nLondon NW1 6XE\nUnited Kingdom",
    "Steps:\n1. Select a size from the menu\n2. Create an account\n3. Delete old drafts",
    "Location: Tokyo office\nContent: quarterly report\nCc: none",
    "def add(a, b):\n    return a + b\n\nprint(add(1, 2))",
    "function greet(name) {\n\treturn 'Hello, ' + name;\n}\n",
    "SELECT は列を選ぶ構文です。\nUPDATE は行を書き換えます。\n詳細は第3章を参照。",
)


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg["body_scan_enabled"] = True
    sh.cfg.update(cfg)
    return sh


def _json_bodies(key: str, value: str):
    """同じ値を JSON で送る形(json.dumps=JSON.stringify と同じ \\r\\n の短いエスケープ・生 UTF-8 の
    JSON・整形した JSON・配列の中)。"""
    return (json.dumps({key: value}).encode("ascii"),
            json.dumps({"title": "Hello", key: value, "stars": 5}, ensure_ascii=False).encode("utf-8"),
            json.dumps({"form": {key: value}}, indent=2).encode("ascii"),
            json.dumps([{key: value}]).encode("ascii"))


def _fixture_pairs():
    """既存の crlf fixture(フォーム値の形)を (名前, 復号した値) にする。値の改行は実際の CR/LF。"""
    for f in _CRLF_FIXTURES:
        name, value = f.split(b"=", 1)
        yield name.decode("ascii"), unquote_plus(value.decode("ascii"))


# ── 検知: JSON の短いエスケープで書いた値の改行 ─────────────────────────────
def test_crlf_fixture_with_json_short_escape_is_detected():
    """既存の crlf fixture の改行を JSON の短いエスケープ(\\r\\n・\\n)で書くと crlf として数える
    (Content-Type の有無・整形・配列の中を問わない)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for name, value in _fixture_pairs():
            assert "\n" in value, value
            for b in _json_bodies(name, value):
                assert _BS + "n" in b.decode("utf-8"), b
                for kw in ({"content_type": _JSON}, {}):
                    r = sh.inspect_body("192.0.2.80", b, **kw)
                    assert r.get("signature") == "crlf", (b, kw, r)


def test_json_short_escape_matches_unicode_escape_form():
    """同じ値は JSON での書き方(短いエスケープ \\n・\\u000a)に依らず同じ結果。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for name, value in _fixture_pairs():
            short = json.dumps({name: value}).encode("ascii")
            uesc = short.replace((_BS + "r").encode("ascii"), (_BS + "u000d").encode("ascii")) \
                        .replace((_BS + "n").encode("ascii"), (_BS + "u000a").encode("ascii"))
            got = [sh.inspect_body("192.0.2.81", b).get("signature") for b in (short, uesc)]
            assert got == ["crlf", "crlf"], (short, uesc, got)


def test_json_short_escape_detected_past_first_window():
    """先頭を無害な詰め物で埋めて後ろの窓へ押し出しても数える(JSON かどうかは本文全体で決める)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for name, value in _fixture_pairs():
            b = json.dumps({"pad": "A" * (P._MAX_SCAN + 100), name: value}).encode("ascii")
            r = sh.inspect_body("192.0.2.82", b)
            assert r.get("signature") == "crlf", (b[-80:], r)


def test_json_short_escape_reaches_stacked_rule():
    """複文(sqli-stacked)の照合も同じ見え方を使う(rv_bodynorm の fixture を JSON の値に)。"""
    value = unquote_plus(_STACKED_NL.decode("ascii"))
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for b in _json_bodies("q", value):
            r = sh.inspect_body("192.0.2.83", b)
            assert r.get("signature") == "sqli-stacked", (b, r)


# ── 本文の走査面(他の検知が見る見え方)は変えない ─────────────────────────────
def test_main_body_view_is_unchanged_by_json_flag():
    """値の改行を ';' にする見え方以外(カスタムシグネチャを含む他の検知が見る本文の走査面)は、
    JSON の短いエスケープを復号しない=従来と同じ字面。"""
    for name, value in _fixture_pairs():
        s = json.dumps({name: value})
        assert _normalize_full(s, body=True, json_esc=True) == _normalize_full(s, body=True), s
        assert ";" not in _normalize_full(s, body=True, json_esc=True), s
        # 値の改行を ';' にする見え方では、JSON 本文の時だけ ';' になる
        assert ";" in _normalize_full(s, body=True, nl=True, json_esc=True), s
        assert ";" not in _normalize_full(s, body=True, nl=True), s


# ── 誤検知を戻さない ─────────────────────────────────────────────────────
def test_ordinary_multiline_json_text_scores_zero():
    """JSON の文章の改行(日本語/英語の複数行コメント・住所・コード片)は 0 点。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for t in _MULTILINE_TEXTS:
            for b in _json_bodies("comment", t):
                for kw in ({"content_type": _JSON}, {}):
                    r = sh.inspect_body("192.0.2.84", b, **kw)
                    assert r["action"] == "allow", (t, kw, r)
        assert sh._decayed_score(sh._state("192.0.2.84")) == 0
        assert not sh.is_banned_fast("192.0.2.84")


def test_existing_false_positive_fixtures_as_json_values_score_zero():
    """既存の誤検知 fixture(det2 の地の文・det3 の改行入り本文・rv_bodynorm/dec_headfold の日本語の
    題名)を、改行を復号した値として JSON に入れても 0 点。元の形のままの本文も 0 点のまま。"""
    texts = list(_JA_TITLES + _JA_OTHER)
    for b in _LINE_BREAK_BODIES + _PROSE_BODIES:
        s = b.decode("ascii")
        texts.append(s)
        texts.extend(unquote_plus(v.split("=", 1)[-1]) for v in s.split("&"))
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for t in texts:
            for b in _json_bodies("note", t):
                r = sh.inspect_body("192.0.2.85", b)
                assert r["action"] == "allow", (t, r)
        for b in (BROWSER_MULTIPART,) + _LINE_BREAK_BODIES + _PROSE_BODIES:
            assert sh.inspect_body("192.0.2.85", b)["action"] == "allow", b[:80]
        assert sh._decayed_score(sh._state("192.0.2.85")) == 0


def test_double_escaped_code_snippet_in_json_scores_zero():
    """コード片の文字列リテラルにある \\r\\n は、JSON では \\\\r\\\\n(バックスラッシュ自体のエスケープ)で
    届く=値の改行ではない。既存の crlf fixture をコード片のリテラルにして JSON で送っても 0 点。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for name, value in _fixture_pairs():
            literal = value.replace("\r", _BS + "r").replace("\n", _BS + "n")
            snippet = 'const %s = "%s";\nconsole.log(%s);' % (name, literal, name)
            for b in _json_bodies("code", snippet):
                assert (_BS * 2 + "n") in b.decode("utf-8"), b
                r = sh.inspect_body("192.0.2.86", b, content_type=_JSON)
                assert r["action"] == "allow", (b, r)
        assert sh._decayed_score(sh._state("192.0.2.86")) == 0


def test_backslash_n_in_non_json_bodies_is_not_a_line_break():
    """JSON でない本文(フォーム・multipart のテキスト欄・テキスト)に書かれた \\n は字面のまま
    (コード片の文字列リテラルの形)。JSON の短いエスケープとして読むのは JSON 本文だけ。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for name, value in _fixture_pairs():
            literal = value.replace("\r", _BS + "r").replace("\n", _BS + "n")
            snippet = 'printf("%s");' % literal
            bodies = (_multipart(name.encode("ascii"), snippet.encode("ascii")),
                      snippet.encode("ascii"),
                      ("code=" + snippet).encode("ascii"))
            for b in bodies:
                for kw in ({}, {"content_type": "text/plain"}):
                    r = sh.inspect_body("192.0.2.87", b, **kw)
                    assert r["action"] == "allow", (b, kw, r)
        assert sh._decayed_score(sh._state("192.0.2.87")) == 0


def test_other_detections_on_json_bodies_unchanged():
    """全角の互換文字による回避(dec_headfold の fixture)は、JSON の値に改行が混じっても従来どおり検知。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for s, sig in _FW_EVASION:
            for b in _json_bodies("c", "line one\n" + s):
                assert sh.inspect_body("192.0.2.88", b).get("signature") == sig, (s, b)


def test_ordinary_multiline_json_is_normalized_once():
    """要求ごとの経路を重くしない: 改行入りの普通の JSON 本文は 1 回だけ正規化する。"""
    calls = []
    orig = P._normalize_full

    def counting(*a, **kw):
        calls.append(kw.get("json_esc", False))
        return orig(*a, **kw)

    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        P._normalize_full = counting
        try:
            for t in _MULTILINE_TEXTS:
                b = json.dumps({"comment": t}).encode("ascii")
                calls.clear()
                assert sh.inspect_body("192.0.2.89", b)["action"] == "allow", t
                assert calls == [True], (t, calls)
        finally:
            P._normalize_full = orig
