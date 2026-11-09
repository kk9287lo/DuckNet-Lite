"""
test_sweep_rv_bodynorm.py — 本文の正規化の見え方の回帰(sweep: rv_bodynorm 群・独立レビューの所見)。
====================================================================================
· #3  本文を UTF-8 で読むようにした(#8)結果、日本語の地の文で普通に使う全角の ｜ ＄ （ ） ； ｀ が
      NFKC でシェル/区切りのメタ文字になり、'データ分析の基礎｜Python' のような題名の JSON 保存が
      rce(42 点=単発拒否の閾値超え)に当たって、3 回目の保存で BAN になっていた。本文ではこれらを
      畳まない(全角英字・全角の ＜＞ の畳み込みは維持=#8 の検知は落とさない)。
· #14 値に符号化して入れた改行(%0A 等)の後の文/コマンドを、本文では crlf の照合でしか ';' として
      見ていなかった(旧版は rce/sqli-stacked でも検知)。同じ見え方を本文の rce・スタック複文の照合にも
      使う。生の改行(文書の枠)は従来どおり空白で、改行入りの普通の本文は 0 点・正規化 1 回のまま。
入力は普通の日本語の文章か、既存テストにある fixture だけを使う。
"""
import json
import tempfile
from urllib.parse import urlencode

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield, _normalize_full
from test_sweep_det2_signatures import _PROSE_BODIES
from test_sweep_det3_crlf import _LINE_BREAK_BODIES
from test_sweep_det_normalize import FULLWIDTH_XSS

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/126.0 Safari/537.36")
_FORM = "application/x-www-form-urlencoded"
# ブログ/CMS の題名に普通に出る全角の区切り・記号(#3 の repro)
_JA_TITLES = (
    "データ分析の基礎｜Python",
    "初心者向け講座｜Python 入門 第1回",
    "おすすめ書籍まとめ｜Python と統計",
    "ターミナル操作メモ｜curl の使い方",
    "価格は＄（税込）で表示",
)
# 同じ全角記号の別の普通の使い方(； の後の宛先、（）の注記、｀ の括り)
_JA_OTHER = (
    "宛先；To: info@example.com",
    "注記（a=1）（b=2）",
    "｀設定｀を開いてください",
)
# test_core.test_newline_injected_separator_is_caught の複文 fixture(値に符号化した改行)
_STACKED_NL = b"q%0a%0aselect a from b"
# 同 rce の fixture(本文の走査面では /etc/passwd が先に traversal に当たるので rce の照合を直接見る)
_RCE_NL = "127.0.0.1%0acat /etc/passwd"


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg["body_scan_enabled"] = True
    sh.cfg.update(cfg)
    return sh


def _carriers(text: str):
    """同じ値を、ブラウザ/クライアントが送る本文の形それぞれで(生 UTF-8 の JSON・\\u エスケープの
    JSON・urlencoded・text/plain)。"""
    return ((json.dumps({"title": text, "status": "draft"}, ensure_ascii=False).encode("utf-8"),
             "application/json"),
            (json.dumps({"title": text, "status": "draft"}).encode("ascii"), "application/json"),
            (urlencode({"title": text, "status": "draft"}).encode("ascii"), _FORM),
            (text.encode("utf-8"), "text/plain; charset=utf-8"))


# ── #3: 全角の句読点/記号はメタ文字に畳まない ─────────────────────────────
def test_fullwidth_cjk_punctuation_in_raw_utf8_json_save_scores_zero():
    """#3 の repro: 題名に全角 ｜ や ＄（）を含む JSON の保存 3 回で、次の要求が単発拒否、
    3 回目で BAN になっていた。保存は何度でも 0 点で、次の要求も通る。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for n, t in enumerate(_JA_TITLES):
            ip = "192.0.2.%d" % (60 + n)
            body = json.dumps({"title": t, "status": "draft"}, ensure_ascii=False).encode("utf-8")
            for _ in range(3):
                r = sh.inspect_body(ip, body, content_type="application/json")
                assert r["action"] == "allow", (t, r)
            assert sh._decayed_score(sh._state(ip)) == 0, t
            nxt = sh.inspect(ip, path="/wp-json/wp/v2/posts/42", method="POST", user_agent=_UA)
            assert nxt["action"] == "allow", (t, nxt)
            assert not sh.is_banned_fast(ip), t


def test_fullwidth_punctuation_scores_zero_in_every_body_encoding():
    """同じ値は本文の送り方(生 UTF-8・\\u エスケープ・urlencoded・text/plain)に依らず同じ結果
    (#8 の趣旨)。全角の ； （） ｀ の普通の使い方も crlf/ldapi/rce に当たらない。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for t in _JA_TITLES + _JA_OTHER:
            for body, ct in _carriers(t):
                r = sh.inspect_body("192.0.2.70", body, content_type=ct)
                assert r["action"] == "allow", (t, ct, r)
        assert sh._decayed_score(sh._state("192.0.2.70")) == 0


def test_fullwidth_punctuation_is_not_folded_into_metacharacters_in_body_view():
    """本文の走査面(body=True)に、全角の ｜ ＄ （ ） ； ｀ 由来の ASCII メタ文字が現れない。"""
    for t in _JA_TITLES + _JA_OTHER:
        v = _normalize_full(t, body=True)
        for c in "|$();`":
            assert c not in v, (t, c, v)
        # 値の改行を ';' にする見え方(本文の crlf/rce/複文用)でも同じ
        v = _normalize_full(t, body=True, nl=True)
        for c in "|$();`":
            assert c not in v, (t, c, v)


def test_fullwidth_letters_and_angle_brackets_still_fold_in_body():
    """#8 の検知は落とさない: 全角の ＜＞(test_d8)と全角英字の UNION SELECT(test_core)は、
    生 UTF-8 でもエスケープでも本文で検知される。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=1000)
        for s, sig in ((FULLWIDTH_XSS, "xss"), ("1 ＵＮＩＯＮ ＳＥＬＥＣＴ a from b", "sqli")):
            for body, ct in _carriers(s):
                assert sh.inspect_body("192.0.2.71", body, content_type=ct).get("signature") == sig, \
                    (s, ct)


# ── #14: 値に符号化した改行の後の文/コマンド ───────────────────────────────
def test_encoded_line_break_statement_in_body_value_is_detected():
    """旧版は本文でも sqli-stacked として数えていた fixture。urlencoded の値・後ろの窓・JSON の値の
    どれに置いても、型の有無を問わず数える。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=1000)
        padded = b"pad=" + b"A" * (P._MAX_SCAN + 100) + b"&" + _STACKED_NL
        js = json.dumps({"q": _STACKED_NL.decode("ascii")}).encode("ascii")
        for b in (_STACKED_NL, b"title=Hello&" + _STACKED_NL + b"&stars=5", padded, js):
            for kw in ({"content_type": _FORM}, {}):
                r = sh.inspect_body("192.0.2.72", b, **kw)
                assert r.get("signature") == "sqli-stacked", (b[-60:], kw, r)


def test_encoded_line_break_command_reaches_body_rce_rule():
    """本文の rce の照合も、値に符号化した改行を ';' として見る(inspect_body と同じ本文の走査)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        rce = frozenset({"rce"})
        assert sh._scan_field(_RCE_NL, body=True, only=rce)[0] == "rce"
        assert sh._scan_field("title=Hello&host=" + _RCE_NL, body=True, only=rce)[0] == "rce"


def test_raw_line_breaks_in_body_stay_whitespace():
    """生の改行(YAML/テキスト/multipart の枠)は従来どおり空白: 同じ fixture を生の改行で書いた本文、
    改行入りの普通の本文(テキストエリア・YAML・CSV・地の文)は 0 点。"""
    raw = _STACKED_NL.replace(b"%0a", b"\n")
    assert ";" not in _normalize_full(raw.decode("ascii"), body=True)
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for b in (raw, raw.replace(b"\n", b"\r\n")) + _LINE_BREAK_BODIES + _PROSE_BODIES:
            for kw in ({}, {"content_type": _FORM}):
                r = sh.inspect_body("192.0.2.73", b, **kw)
                assert r["action"] == "allow", (b[:80], kw, r)
        assert sh._decayed_score(sh._state("192.0.2.73")) == 0


def test_line_break_view_is_built_only_when_a_value_line_break_needs_it():
    """要求ごとの経路を重くしない: 本文は(値に改行があっても)1 回だけ正規化し、改行を ';' にした
    見え方は、値の改行の後にコマンド名/SQL の動詞/ヘッダ名が続く時だけ作る(生の改行・改行の無い
    文章・'Update: …' のような普通の行では作らない)。"""
    quiet = ((b"msg=Please+select+a+size+from+the+menu&note=50%25+off",
              b"msg=Thanks%21%0D%0AWill+update+you+soon")
             + _LINE_BREAK_BODIES[:3] + _LINE_BREAK_BODIES[4:5])   # YAML 3 件 + 'Update: …' の行
    for b in quiet:
        views = []
        P._scan_windows(b.decode("ascii"), body=True, nl_views=views)
        assert views == [], (b, views)
    views = []
    P._scan_windows(_STACKED_NL.decode("ascii"), body=True, nl_views=views)
    assert views == [_normalize_full(_STACKED_NL.decode("ascii"), body=True, nl=True)], views
    calls = []
    orig = P._normalize_full

    def counting(*a, **kw):
        calls.append(kw.get("nl", False))
        return orig(*a, **kw)

    bodies = (b"msg=Please+select+a+size+from+the+menu&note=50%25+off",
              json.dumps({"title": _JA_TITLES[3], "memo": "curl https://example.com/ を参照"},
                         ensure_ascii=False).encode("utf-8")) + _LINE_BREAK_BODIES[3:]
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        P._normalize_full = counting
        try:
            for b in bodies:
                calls.clear()
                assert sh.inspect_body("192.0.2.74", b)["action"] == "allow", b
                assert len(calls) == 1, (b, calls)
        finally:
            P._normalize_full = orig
