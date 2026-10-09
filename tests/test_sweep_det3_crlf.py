"""
test_sweep_det3_crlf.py — 本文の値に入った改行+応答ヘッダ(crlf)の検知の回帰(sweep: det3_crlf 群)。
====================================================================================
· 本文の改行を空白として畳む修正(#0/#2)の副作用で、フォーム値に %0D%0A で入った改行の後に応答ヘッダが
  続く形(値がリダイレクト先や Cookie に反映される時の注入=head 側の crlf が対象にしている形)を、
  本文では検知できなくなっていた(改行が crlf の照合より前に空白になっていた)。
· 直しても誤検知は戻さない: 普通のブラウザ multipart(部ヘッダは正規にヘッダの形)、YAML/CSV/地の文、
  テキストエリアの改行は 0 点のまま。
入力は無害な文章か、既存テストにある fixture だけを使う。
"""
import json
import tempfile

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield, _normalize_full
from test_sweep_det2_signatures import _PROSE_BODIES
from test_sweep_det_normalize import BROWSER_MULTIPART

# test_sweep_det2_signatures / test_core / test_logio にある crlf の fixture(フォーム値の形)
_CRLF_FIXTURES = (b"next=%0d%0aSet-Cookie:%20sid=evil", b"u=%0d%0aLocation:%20http://e",
                  b"x=%0d%0aContent-Type:%20text/html", b"to=a%0aBcc:evil@x")
_FORM = "application/x-www-form-urlencoded"

# 改行を含む普通の本文(test_sweep_det_normalize.test_d2 の YAML/テキストエリア)
_LINE_BREAK_BODIES = (
    b"name: demo\nlocation: tokyo\n",
    b"kind: Job\nspec:\n  to: ops\n",
    b"retry: 3\nupdate: true\n",
    b"review=Great+store.%0D%0ACat+food+arrived+fast&stars=5",
    b"comment=Thanks+for+the+fix%21%0D%0AUpdate%3A+works+now&submit=Send",
    b"subject=Hello&message=Hi+team%2C%0D%0ATo%3A+everyone+in+sales",
)


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _multipart(name: bytes, value: bytes, extra_head: bytes = b"") -> bytes:
    """フォーム値 1 個の multipart 本文(ブラウザと同じ CRLF の枠)。"""
    b = b"----WebKitFormBoundary7MA4YWxkTrZu0gW"
    return (b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"\r\n"
            + extra_head + b"\r\n" + value + b"\r\n--" + b + b"--\r\n")


# ── 検知の復元: フォーム値に符号化された改行+応答ヘッダ ─────────────────────────
def test_crlf_fixture_in_form_body_value_is_detected():
    """既存の crlf fixture を urlencoded 本文の値に置くと crlf として数える(型の有無を問わない)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for f in _CRLF_FIXTURES:
            for b in (f, b"title=Hello&" + f + b"&stars=5"):
                for kw in ({"content_type": _FORM}, {}):
                    r = sh.inspect_body("192.0.2.50", b, **kw)
                    assert r.get("signature") == "crlf", (b, kw, r)


def test_crlf_fixture_detected_past_first_window_and_in_other_value_carriers():
    """先頭を無害な詰め物で埋めて後ろの窓へ押し出しても、JSON の値や multipart のフォーム値に
    同じ(符号化された)値を入れても crlf として数える。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for f in _CRLF_FIXTURES:
            name, value = f.split(b"=", 1)
            padded = b"pad=" + b"A" * (P._MAX_SCAN + 100) + b"&" + f
            js = json.dumps({name.decode("ascii"): value.decode("ascii")}).encode("ascii")
            for b in (padded, js, _multipart(name, value)):
                r = sh.inspect_body("192.0.2.51", b)
                assert r.get("signature") == "crlf", (b[-80:], r)


# ── 誤検知を戻さない ─────────────────────────────────────────────────────
def test_benign_bodies_with_line_breaks_still_score_zero():
    """普通のブラウザ multipart、YAML/CSV/地の文、テキストエリアの改行(urlencoded の %0D%0A でも
    multipart の生の CRLF でも)は 0 点のまま。"""
    textarea = _multipart(b"review", b"Great store.\r\nCat food arrived fast")
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for b in (BROWSER_MULTIPART, textarea) + _PROSE_BODIES + _LINE_BREAK_BODIES:
            for kw in ({}, {"content_type": _FORM}):
                r = sh.inspect_body("192.0.2.52", b, **kw)
                assert r["action"] == "allow", (b[:80], kw, r)
        assert sh._decayed_score(sh._state("192.0.2.52")) == 0
        assert not sh.is_banned_fast("192.0.2.52")


def test_raw_header_shaped_lines_are_document_structure():
    """本文の生の改行は文書の枠(YAML/テキスト/multipart の部ヘッダ)で、値の改行ではない。ヘッダの
    形の行が並ぶ設定ファイルや、部ヘッダに Content-Type がある multipart は crlf に当てない
    ('%' や '&' を含む=復号が走る本文でも)。"""
    conf = b"name: demo\nlocation: /srv/app\ncontent-type: text/plain\nnote: 50% off & free\n"
    upload = (b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"Q&A notes.yaml\"\r\n"
              b"Content-Type: text/plain\r\n\r\n" + conf + b"\r\n--b--\r\n")
    typed_value = _multipart(b"title", b"Tom & Jerry", b"Content-Type: text/plain\r\n")
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for b in (conf, conf.replace(b"\n", b"\r\n"), upload, typed_value):
            r = sh.inspect_body("192.0.2.53", b)
            assert r["action"] == "allow", (b[:80], r)
        assert sh._decayed_score(sh._state("192.0.2.53")) == 0


def test_value_line_break_view_is_used_only_by_crlf_rce_and_stacked_rules():
    """値の改行を ';' として見るのは crlf・rce(';' 連結)・sqli-stacked の照合だけ(P._BODY_NL_RULES)。
    他の署名(カスタムシグネチャを含む)が見る本文の走査面は従来どおり改行を空白に畳む(';' にすると
    '...' + 改行 が traversal の '..;' に当たる等、別の誤検知が出る)。"""
    for f in _CRLF_FIXTURES:
        assert ";" not in _normalize_full(f.decode("ascii"), body=True), f
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for b in (b"message=See+you+soon...%0D%0ALocation%3A+Tokyo+office",
                  b"message=Thanks...%0D%0ATo%3A+everyone+in+sales"):
            r = sh.inspect_body("192.0.2.54", b)
            assert r["action"] == "allow", (b, r)


def test_benign_form_body_is_normalized_once():
    """改行入りの普通のフォーム本文は 1 回だけ正規化する(crlf・rce・複文用の見え方が要る時も、同じ
    1 回の正規化の中で作る=復号をやり直さない・要求ごとの経路を重くしない)。"""
    calls = []
    orig = P._normalize_full

    def counting(*a, **kw):
        calls.append(kw.get("nl", False))
        return orig(*a, **kw)

    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        P._normalize_full = counting
        try:
            for b in _LINE_BREAK_BODIES[3:]:
                calls.clear()
                assert sh.inspect_body("192.0.2.55", b)["action"] == "allow", b
                assert len(calls) == 1, (b, calls)
        finally:
            P._normalize_full = orig
