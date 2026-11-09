"""
test_sweep_dec_headfold.py — URL/ヘッダ(head)の走査面で全角記号をメタ文字へ畳まない(sweep: dec_headfold・決定)。
====================================================================================
· 日本語の題名で普通に使う全角の ｜ ＄ （ ） ； ｀ が、head の正規化でも NFKC で | $ ( ) ; ` になり、
  ブラウザが送る '?q=データ分析の基礎｜Python'(UTF-8 の %XX)の検索 1 回が rce 等で 60 点=単発拒否の
  閾値超えになっていた(この版も前の版も)。本文(rv_bodynorm #3)と同じ表で、head でも畳まない(決定)。
  全角英字・全角の ＜＞ の畳み込みは維持=test_d8・test_core の検知は落とさない。
入力は普通の日本語の文章か、既存テストにある fixture だけを使う。
"""
import tempfile
from urllib.parse import quote, urlencode

from dataplane.engine.lifeform.pipeline import NetShield, _normalize_full
from test_sweep_det_normalize import FULLWIDTH_XSS
from test_sweep_rv_bodynorm import _JA_OTHER, _JA_TITLES

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/126.0 Safari/537.36")
# 全角の互換文字による回避の fixture(test_core.test_unicode_evasion_is_normalized・test_d8)
_FW_EVASION = ((FULLWIDTH_XSS, "xss"),
               ("＜ｓｃｒｉｐｔ＞alert(1)", "xss"),
               ("1 ＵＮＩＯＮ ＳＥＬＥＣＴ a from b", "sqli"))


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _query_forms(t: str):
    """ブラウザが送るクエリの形: フォームの GET(空白は +)と、%20 の URL。どちらも UTF-8 の %XX。"""
    return (urlencode({"q": t}), "q=" + quote(t, safe=""))


def _header_forms(t: str):
    """ヘッダ値の形: 値そのもの(独自ヘッダ等)と、検索結果のページから来た Referer(%XX)。"""
    return (t, "https://example.com/search?" + urlencode({"q": t}))


def _escaped_forms(t: str):
    """同じ値の別の送り方: %XX・\\u エスケープ・数値文字参照(非 ASCII の文字だけを符号化する)。"""
    bs = chr(92)                                        # バックスラッシュ(\u をソースに直書きしない)
    return (quote(t, safe=""),
            "".join(bs + "u%04x" % ord(c) if ord(c) > 0x7F else c for c in t),
            "".join("&#x%x;" % ord(c) if ord(c) > 0x7F else c for c in t))


def test_ja_titles_in_query_score_zero():
    """決定の repro: 題名を検索クエリに入れた GET が 1 回で拒否されていた。0 点で通る。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for n, t in enumerate(_JA_TITLES):
            for k, q in enumerate(_query_forms(t)):
                ip = "192.0.2.%d" % (10 + n * 2 + k)
                r = sh.inspect(ip, path="/search", query=q, user_agent=_UA)
                assert r["action"] == "allow", (t, q, r)
                assert sh._decayed_score(sh._state(ip)) == 0, (t, q)
                assert sh._scan_field(q) == (None, 0.0), (t, q)


def test_ja_titles_in_header_value_score_zero():
    """同じ題名がヘッダ値(値そのもの・検索ページからの Referer)に入っても 0 点で通る。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for n, t in enumerate(_JA_TITLES):
            for k, h in enumerate(_header_forms(t)):
                ip = "192.0.2.%d" % (30 + n * 2 + k)
                r = sh.inspect(ip, path="/", headers=h, user_agent=_UA)
                assert r["action"] == "allow", (t, h, r)
                assert sh._decayed_score(sh._state(ip)) == 0, (t, h)
                assert sh._scan_field(h) == (None, 0.0), (t, h)


def test_other_ordinary_uses_in_query_header_and_path_score_zero():
    """同じ全角記号の別の普通の使い方(； の後の宛先・（）の注記・｀ の括り)も、クエリ・ヘッダ・
    パス(題名の slug)のどこでも crlf/ldapi/rce に当たらない。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for t in _JA_TITLES + _JA_OTHER:
            for q in _query_forms(t):
                sh.inspect("192.0.2.50", path="/search", query=q, user_agent=_UA)
            for h in _header_forms(t):
                sh.inspect("192.0.2.50", path="/", headers=h, user_agent=_UA)
            r = sh.inspect("192.0.2.50", path="/blog/" + quote(t), user_agent=_UA)
            assert r["action"] == "allow", (t, r)
        assert sh._decayed_score(sh._state("192.0.2.50")) == 0


def test_head_view_does_not_fold_fullwidth_punctuation_into_metacharacters():
    """head の走査面に、全角の ｜ ＄ （ ） ； ｀ 由来の ASCII メタ文字が現れない。値の送り方(生・%XX・
    \\u エスケープ・数値文字参照)に依らず同じ見え方で、本文の見え方とも同じ。"""
    for t in _JA_TITLES + _JA_OTHER:
        want = _normalize_full(t)
        for c in "|$();`":
            assert c not in want, (t, c, want)
        assert want == _normalize_full(t, body=True), t
        for form in _escaped_forms(t):
            assert _normalize_full(form) == want, (t, form)


def test_fullwidth_letters_and_angle_brackets_still_fold_in_head():
    """畳み込みによる検知は落とさない: 全角の ＜＞ と全角英字は、クエリ・ヘッダ値として生でも %XX でも
    \\u エスケープでも検知され、inspect() で加点される。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=1000)
        for n, (s, sig) in enumerate(_FW_EVASION):
            for v in (s,) + _escaped_forms(s) + _query_forms(s) + _header_forms(s)[1:]:
                assert sh._scan_field(v)[0] == sig, (s, v)
            ip = "192.0.2.%d" % (80 + n)
            sh.inspect(ip, path="/search", query=urlencode({"q": s}), user_agent=_UA)
            assert sh._decayed_score(sh._state(ip)) > 0, s
            ip = "192.0.2.%d" % (90 + n)
            sh.inspect(ip, path="/", headers=s, user_agent=_UA)
            assert sh._decayed_score(sh._state(ip)) > 0, s
