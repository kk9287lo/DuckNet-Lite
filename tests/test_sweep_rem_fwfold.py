"""
test_sweep_rem_fwfold.py — 全角記号を ASCII へ畳み直す運用者の設定 fold_fullwidth_punct(sweep: rem_fwfold)。
====================================================================================
· 決定(dec_headfold・rv_bodynorm #3)で、日本語の地の文で普通に使う全角の ｜ ＄ （ ） ； ｀ は、本文でも
  URL/ヘッダでも ASCII のメタ文字へ畳まなくなった。受け入れた残余: バックエンド自身が全角を ASCII へ変換する
  構成(入力へ NFKC を掛けるアプリ・Windows の best-fit 変換)では、それらが本物のメタ文字として読まれる。
  その構成の運用者向けの設定を足す。既定は OFF で、既定の挙動は今と同じ(題名は 0 点のまま)。
· ON は本文も head も、その表の文字だけを前の版の NFKC と同じに畳む: 題名は前の版と同じ点数になる
  (検索クエリ 1 回で rce 60 点・JSON の保存 1 回で 42 点)。
· 設定は bool だけを受け付け、再起動を跨いで残り、options.md と CHANGELOG に載る。
入力は既存テストの普通の日本語の題名と fixture だけを使う。
"""
import json
import os
import tempfile
import unicodedata
from unittest import SkipTest
from urllib.parse import quote

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_dec_headfold import _escaped_forms, _header_forms, _query_forms
from test_sweep_det_normalize import FULLWIDTH_XSS
from test_sweep_rv_bodynorm import _JA_OTHER, _JA_TITLES, _carriers

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KEY = "fold_fullwidth_punct"
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/126.0 Safari/537.36")


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg["body_scan_enabled"] = True
    sh.cfg["block_score"] = 10000                 # 加点をそのまま比べる(BAN で打ち切らない)
    sh.cfg["score_halflife_sec"] = 1e9            # 比べる間の減衰で点数がずれないように
    sh.cfg.update(cfg)
    return sh


def _prefold(t: str) -> str:
    """前の版の見え方の基準: 表の全角記号だけを NFKC の ASCII 形にしておいた同じ文。"""
    return t.translate({ord(c): unicodedata.normalize("NFKC", c) for c in P._CJK_FW_PUNCT})


def _head_forms(t: str):
    """head の送り方: クエリ(+ と %20)・ヘッダ値(値そのものと Referer)・%XX/\\u/数値文字参照・生。"""
    return _query_forms(t) + _header_forms(t) + _escaped_forms(t) + (t,)


def _pair(d):
    """ON にした shield と、既定(OFF)のままの shield。"""
    on = _shield(os.path.join(d, "on"))
    r = on.set_config(**{_KEY: True})
    assert r["ok"] and r["changed"] == {_KEY: True}, r
    off = _shield(os.path.join(d, "off"))
    assert off.cfg[_KEY] is False
    return on, off


def _inspect_all(sh, ip, t):
    """同じ文をクエリ・ヘッダ値・パス(題名の slug)で送る。"""
    for q in _query_forms(t):
        sh.inspect(ip, path="/search", query=q, user_agent=_UA)
    for h in _header_forms(t):
        sh.inspect(ip, path="/", headers=h, user_agent=_UA)
    sh.inspect(ip, path="/blog/" + quote(t), user_agent=_UA)


def test_default_is_off_and_titles_still_score_zero():
    """既定は OFF。題名(dec_headfold・rv_bodynorm と同じ文)は head でも本文でも 0 点のまま。"""
    assert P._DEFAULTS[_KEY] is False
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.cfg[_KEY] is False
        for n, t in enumerate(_JA_TITLES + _JA_OTHER):
            ip = "192.0.2.%d" % (10 + n)
            _inspect_all(sh, ip, t)
            for body, ct in _carriers(t):
                assert sh.inspect_body(ip, body, content_type=ct)["action"] == "allow", (t, ct)
            for v in _head_forms(t):
                assert sh._scan_field(v) == (None, 0.0), (t, v)
            assert sh._decayed_score(sh._state(ip)) == 0, t


def test_on_folds_titles_in_head_like_the_previous_release():
    """ON: クエリ・ヘッダ値・パスの題名は、表の全角記号を ASCII にした文と同じに照合され(前の版の NFKC)、
    前の版と同じく加点される(検索 1 回で rce 60 点)。"""
    with tempfile.TemporaryDirectory() as d:
        on, off = _pair(d)
        for n, t in enumerate(_JA_TITLES + _JA_OTHER):
            for v, w in zip(_head_forms(t), _head_forms(_prefold(t))):
                got = on._scan_field(v)
                assert got[0] is not None, (t, v)
                assert got == off._scan_field(w), (t, v, got)
            ip = "192.0.2.%d" % (30 + n)
            _inspect_all(on, ip, t)
            _inspect_all(off, ip, _prefold(t))
            s_on = round(on._decayed_score(on._state(ip)), 1)
            assert s_on > 0, t
            assert s_on == round(off._decayed_score(off._state(ip)), 1), t
        on.inspect("192.0.2.60", path="/search", query=_query_forms(_JA_TITLES[0])[0], user_agent=_UA)
        assert round(on._decayed_score(on._state("192.0.2.60")), 1) == 60.0   # 前の版と同じ 60 点
        assert on._scan_field(_query_forms(_JA_TITLES[0])[0]) == ("rce", 60)
        # 主走査面(path?query UA の連結)も同じに畳む: 題名の前半(｜ まで)の検索を curl で送ると、
        # 前の版は連結した見え方だけで rce に当たっていた(各フィールド単体では当たらない)
        part = _JA_TITLES[3].split("｜")[0] + "｜"
        q = _query_forms(part)[0]
        for sh, v, ip in ((on, q, "192.0.2.61"), (off, _query_forms(_prefold(part))[0], "192.0.2.62"),
                          (off, q, "192.0.2.63")):
            sh.inspect(ip, path="/search", query=v, user_agent="curl/8.4.0")
        assert round(on._decayed_score(on._state("192.0.2.61")), 1) == 60.0
        assert round(off._decayed_score(off._state("192.0.2.62")), 1) == 60.0
        assert off._decayed_score(off._state("192.0.2.63")) == 0          # 既定(OFF)は 0 点のまま


def test_on_folds_titles_in_body_like_the_previous_release():
    """ON: 本文(生 UTF-8 の JSON・\\u エスケープの JSON・urlencoded・text/plain)の題名も同じ。JSON の保存
    1 回は前の版と同じ 42 点(rce 60 × 本文係数 0.7)。"""
    with tempfile.TemporaryDirectory() as d:
        on, off = _pair(d)
        for n, t in enumerate(_JA_TITLES + _JA_OTHER):
            for k, ((b, ct), (b_old, _ct)) in enumerate(zip(_carriers(t), _carriers(_prefold(t)))):
                ip = "192.0.2.%d" % (100 + n * 4 + k)
                r_on = on.inspect_body(ip, b, content_type=ct)
                r_off = off.inspect_body(ip, b_old, content_type=ct)
                assert r_on.get("signature") is not None, (t, ct, r_on)
                assert (r_on.get("signature"), r_on.get("score")) == \
                    (r_off.get("signature"), r_off.get("score")), (t, ct, r_on, r_off)
        body = json.dumps({"title": _JA_TITLES[0], "status": "draft"}, ensure_ascii=False)
        r = on.inspect_body("192.0.2.200", body.encode("utf-8"), content_type="application/json")
        assert (r.get("signature"), r.get("score")) == ("rce", 42.0), r


def test_on_changes_only_the_table_characters():
    """ON でも他の畳み込みは同じ: 全角英字・全角の ＜＞ は検知され、ASCII だけの値と、表の文字を含まない
    日本語の文は OFF と同じ結果。カスタム署名の試験(dry_run_signature)も live と同じ見え方を使う。"""
    with tempfile.TemporaryDirectory() as d:
        on, off = _pair(d)
        for s, sig in ((FULLWIDTH_XSS, "xss"), ("1 ＵＮＩＯＮ ＳＥＬＥＣＴ a from b", "sqli")):
            for v in _head_forms(s):
                assert on._scan_field(v)[0] == sig, (s, v)
        for t in ("データ分析の基礎 Python", "q=hello+world&page=2", "宛先: info@example.com"):
            for v in _head_forms(t):
                assert on._scan_field(v) == off._scan_field(v) == (None, 0.0), (t, v)
        assert on.dry_run_signature(r"\|python", _JA_TITLES[0])["matches"] is True
        assert off.dry_run_signature(r"\|python", _JA_TITLES[0])["matches"] is False


def test_setting_accepts_bool_only():
    """bool 以外('true'・1・'on' 等)は管理 API でも宣言的設定でも拒否して現状を保つ。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for bad in ("true", "on", "1", 1, 0, 1.0, [], {}):
            r = sh.set_config(**{_KEY: bad})
            assert r["ok"] is False and _KEY in r.get("rejected", ()), (bad, r)
            assert sh.cfg[_KEY] is False, bad
        r = sh.apply_config({_KEY: "yes"})
        assert _KEY in r.get("rejected", ()) and _KEY not in r["applied"], r
        assert sh.cfg[_KEY] is False
        r = sh.apply_config({_KEY: True})
        assert _KEY in r["applied"] and sh.cfg[_KEY] is True, r
        r = sh.set_config(**{_KEY: False})
        assert r["changed"] == {_KEY: False} and sh.cfg[_KEY] is False, r


def test_setting_survives_restart():
    """ON は保存され、再起動後も ON のまま畳み込む。OFF に戻すと再起動後も OFF。"""
    q = _query_forms(_JA_TITLES[0])[0]
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        assert sh.set_config(**{_KEY: True})["changed"] == {_KEY: True}
        sh2 = NetShield(state_dir=d)
        assert sh2.cfg[_KEY] is True
        assert sh2._scan_field(q)[0] == "rce"
        assert sh2.set_config(**{_KEY: False})["changed"] == {_KEY: False}
        sh3 = NetShield(state_dir=d)
        assert sh3.cfg[_KEY] is False
        assert sh3._scan_field(q) == (None, 0.0)


def _read(*parts):
    with open(os.path.join(_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def test_options_md_changelog_and_defenses_md_list_the_setting():
    """options.md の設定キー表に既定 False で載り、CHANGELOG の [Unreleased] と defenses.md の
    全角記号の段落にも載る(いつ ON にするかの 1 行つき)。"""
    rows = [ln for ln in _read("docs", "options.md").splitlines() if ln.startswith("| `%s`" % _KEY)]
    assert len(rows) == 1 and "`False`" in rows[0], rows
    assert "NFKC" in rows[0] and "best-fit" in rows[0], rows[0]
    log = _read("CHANGELOG.md")
    head = log.index("## [Unreleased]")
    nxt = log.find("\n## [", head + 1)
    assert _KEY in log[head:nxt if nxt > 0 else len(log)]
    assert _KEY in _read("docs", "defenses.md")


def test_gui_schema_lists_the_setting():
    """GUI の設定スキーマ(Full)は検査の詳細設定に bool として載せ、既定は False。"""
    try:
        from dataplane.gui import schema
    except ImportError as e:
        raise SkipTest(f"GUI スキーマは Full のみ: {e!r}")
    f = [x for x in schema.FIELDS if x[0] == _KEY]
    assert len(f) == 1 and f[0][1] == "bool" and f[0][2] == "advanced", f
    assert _KEY in schema.DESC
    assert schema.defaults()[_KEY] is False
    assert schema.coerce(_KEY, "true") is True and schema.coerce(_KEY, "off") is False
