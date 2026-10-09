"""
test_sweep_det_normalize.py — 走査前の正規化と窓分割、本文の読み方の回帰(sweep: det_normalize 群)。
====================================================================================
· #61 窓予算をチャンクごとに按分して打ち切り、16KB フィールドの一部がどの窓にも載らなかった。
· #62 登録デコーダの出力が _PRE_CUT に届くと捨てられ、生入力の半分ずつを復号し直していた。
· #63 lower() が最後の切り詰めの *後* にあり、_normalize_full が _PRE_CUT の 2 倍を返せた。
· #64 結合文字の長い連続で NFKC の並べ替えが入力長の 2 乗で重くなった。
· #65 同じ生テキストを最大 15 回正規化し直していた。
· #66 ASCII の高速パスだけ制御文字を除去せず、無関係な非 ASCII の有無で結果が変わった。
· #0  multipart 本文の改行が ';' になり、枠の Content-Disposition: が crlf 署名に当たった。
· #2  本文の改行が ';' になり、YAML/テキスト/フォームの地の文が ';' 前提の検知に当たった。
· #8  本文を latin-1 で読んでいたため、生 UTF-8 の全角/ゼロ幅が畳まれず素通りした。
入力は無害な目印か、既存テストにある fixture だけを使う。
"""
import base64
import json
import random
import tempfile
import time
import zlib

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import (
    NetShield, _MAX_SCAN_WINDOWS, _PRE_CUT, _normalize_full, _scan_windows)

FULLWIDTH_XSS = "＜script＞alert(1)"           # test_scanwindow.test_compat_char_obfuscation_still_folded
ZW_XSS = "<scr" + chr(0x200B) + "ipt>alert(1)"   # test_core.test_unicode_evasion_is_normalized(ゼロ幅)
XSS_BODY = b"comment=<script>alert(document.cookie)</script>"   # test_bodyscan.test_xss_body_detected

_B = b"----WebKitFormBoundary7MA4YWxkTrZu0gW"
# 圧縮画像の中身の代わり(固定シードの擬似乱数バイト列=実画像と同じくほぼ一様なバイト分布)。
_IMAGE_DATA = b"\x89PNG\r\n\x1a\n" + random.Random(20261009).randbytes(32768)
# ブラウザが送る普通の multipart(テキスト欄 + 末尾がアポストロフィの欄 + UTF-8 欄 + 画像ファイル)。
BROWSER_MULTIPART = (
    b"--" + _B + b"\r\n"
    b'Content-Disposition: form-data; name="title"\r\n\r\n'
    b"My holiday photo\r\n"
    b"--" + _B + b"\r\n"
    b'Content-Disposition: form-data; name="note"\r\n\r\n'
    b"Thanks to the Smiths'\r\n"
    b"--" + _B + b"\r\n"
    b'Content-Disposition: form-data; name="place"\r\n\r\n'
    + "Café in Kyōto".encode("utf-8") + b"\r\n"
    b"--" + _B + b"\r\n"
    b'Content-Disposition: form-data; name="file"; filename="photo.png"\r\n'
    b"Content-Type: image/png\r\n\r\n"
    + _IMAGE_DATA + b"\r\n"
    b"--" + _B + b"--\r\n")


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _best_ms(fn, arg, reps=7):
    fn(arg)
    best = float("inf")
    for _ in range(reps):
        t = time.perf_counter()
        fn(arg)
        best = min(best, time.perf_counter() - t)
    return best * 1000


# ── #61: 展開する文字で埋めたフィールドの全域が窓に載る ─────────────────────────
def test_d61_every_part_of_expanding_field_lands_in_a_window():
    """#61: 1→4 に展開する U+3300 で埋めた 16384 文字のフィールドで、各チャンクの窓が予算 4 で
    打ち切られ、64 個の目印のうち 28 個がどの窓にも載らなかった。"""
    blocks, tags = [], []
    for i in range(_PRE_CUT // 256):
        tag = "tag%05d" % i
        blocks.append("㌀" * (256 - len(tag)) + tag)
        tags.append(tag)
    field = "".join(blocks)
    assert len(field) == _PRE_CUT
    wins = _scan_windows(field)
    assert len(wins) <= _MAX_SCAN_WINDOWS, len(wins)
    joined = "\x1e".join(wins)
    missing = [t for t in tags if t not in joined]
    assert not missing, (len(missing), missing[:4])


# ── #62: 登録デコーダはフィールド全体を 1 回だけ見て、出力が窓に載る ────────────────
def test_d62_decoder_output_reaching_pre_cut_is_scanned():
    """#62: 復号結果が _PRE_CUT に届くと捨てられ、生入力を半分に割って各々を復号し直していた。
    全体が要る復号(圧縮+base64)は半分では失敗し、窓には生の base64 しか残らなかった。"""
    text = "".join("benign log line %05d tag%05d\n" % (i, i) for i in range(1200))
    packed = base64.b64encode(zlib.compress(text.encode("ascii"), 9)).decode("ascii")
    seen = []

    def unz(s):
        seen.append(len(s))
        return zlib.decompress(base64.b64decode(s))

    try:
        P.register_scan_decoder("sweep_unz", unz)
        wins = _scan_windows(packed)
    finally:
        P.clear_scan_decoder("sweep_unz")
    assert seen and max(seen) == len(packed), seen          # デコーダはフィールド全体を受け取る
    assert len(seen) == 1, seen                              # 1 フィールドにつき 1 回
    assert any("benign log line" in w for w in wins), [len(w) for w in wins]
    # 復号結果(上限 _PRE_CUT)の末尾近くまで、どれかの窓に載る
    shown = text[:_PRE_CUT]
    last_tag = shown[:shown.rfind("\n")].rsplit(" ", 1)[-1]
    assert any(last_tag in w for w in wins), last_tag


# ── #63: 返り値の長さは _PRE_CUT 以内 ───────────────────────────────────────
def test_d63_normalize_full_length_stays_within_pre_cut():
    """#63: lower() を最後の切り詰めの後に掛けていたため、U+0130 で埋めると 2 倍の長さが返った。"""
    assert len(_normalize_full("İ" * _PRE_CUT)) <= _PRE_CUT
    assert len(_normalize_full("a" * _PRE_CUT)) == _PRE_CUT


# ── #64: 結合文字の長い連続でも NFKC は線形 ─────────────────────────────────
def test_d64_long_combining_mark_runs_normalize_in_linear_time():
    """#64: 結合クラスが交互に変わる結合文字の長い連続で、NFKC の並べ替えが入力長の 2 乗で
    重くなった(16K で約 40ms)。U+0F73 のように分解すると非 starter が並ぶ文字も同じ。"""
    for unit in (chr(0x0301) + chr(0x0316), chr(0x0F73)):   # 結合クラス 230/220 の交互 / U+0F73
        def make(n):
            return ("a" + unit * n)[:n]
        small = _best_ms(_normalize_full, make(_PRE_CUT // 4))
        large = _best_ms(_normalize_full, make(_PRE_CUT))
        # 線形なら 4 倍前後、2 乗なら 16 倍前後。ゆとりを持って 8 倍で切る。
        assert large < max(small, 0.05) * 8, (unit.encode("unicode_escape"), small, large)


# ── #65: 1 チャンクは 1 回だけ正規化する ───────────────────────────────────
def test_d65_each_raw_chunk_is_normalized_once():
    """#65: 正規化結果が上限に届くと捨てて半分ずつ正規化し直し、16K の U+3300 で
    _normalize_full を 15 回呼んでいた(1 回なら済む量の数倍の CPU)。"""
    calls = []
    orig = P._normalize_full

    def counting(*a, **kw):
        calls.append(len(a[0]) if a else 0)
        return orig(*a, **kw)

    P._normalize_full = counting
    try:
        _scan_windows("㌀" * _PRE_CUT)
    finally:
        P._normalize_full = orig
    assert len(calls) <= 3, calls                  # 生チャンク数(8192 窓+重なりで 3 枚)以下


# ── #66: 制御文字の扱いが無関係な非 ASCII の有無で変わらない ─────────────────────
def test_d66_control_chars_handled_same_on_ascii_path():
    """#66: 制御文字の除去が非 ASCII の分岐の中にあり、'ab\\x01cd' は \\x01 を残し、
    同じ文字列に 'é' があると除去していた(同じ値が別の文字の有無で別物に見えた)。"""
    for c in ("\x01", "\x08", "\x0b", "\x0c", "\x1b", "\x1f"):
        ascii_only = _normalize_full("ab" + c + "cd")
        with_other = _normalize_full("ab" + c + "cdé")
        assert ascii_only + "é" == with_other, (repr(c), ascii_only, with_other)
    assert _normalize_full("ab\x01cd") == "abcd"
    assert _normalize_full("ab%01cd") == "abcd"


# ── #0: 普通のブラウザ multipart は 0 点 ──────────────────────────────────
def test_d0_browser_multipart_upload_scores_zero():
    """#0: 改行を ';' にしていたため、multipart の枠 CRLF + Content-Disposition: が crlf 署名に
    当たり、普通のアップロード 1 回ごとに 31.5 点、4 回目で BAN になっていた。末尾がアポストロフィ
    の値 + 枠の '--境界' は sqli に、画像の中身のランダムなバイト列は rce(`…`)にも当たっていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for _ in range(6):
            r = sh.inspect_body("192.0.2.10", BROWSER_MULTIPART)
            assert r["action"] == "allow", r
        assert sh._decayed_score(sh._state("192.0.2.10")) == 0
        assert not sh.is_banned_fast("192.0.2.10")
    # 枠と部ヘッダを外しても、部の中身と部ヘッダ(filename 等)は引き続き走査される
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        part = ("--b\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n" + FULLWIDTH_XSS
                + "\r\n--b--\r\n").encode("utf-8")
        assert sh.inspect_body("192.0.2.11", part).get("signature") == "xss"
        named = (b'--b\r\nContent-Disposition: form-data; name="f"; filename="'
                 + XSS_BODY.split(b"=", 1)[1] + b'"\r\n\r\nx\r\n--b--\r\n')
        assert sh.inspect_body("192.0.2.12", named).get("signature") == "xss"
        # filename の無い部(フォーム値)は制御文字が混じっても走査を外さない
        value = (b'--b\r\nContent-Disposition: form-data; name="c"\r\n\r\n\x01'
                 + XSS_BODY.split(b"=", 1)[1] + b"\r\n--b--\r\n")
        assert sh.inspect_body("192.0.2.13", value).get("signature") == "xss"


# ── #2: 本文の改行は空白(';' にしない) ────────────────────────────────────
def test_d2_line_breaks_in_body_text_do_not_score():
    """#2: 本文の改行(生でも %0D%0A でも)が ';' になり、YAML の 'location:' 行は crlf、
    'update:' 行は sqli-stacked、フォームの 'Cat food ...' 行は rce に当たって加点された。"""
    bodies = (b"name: demo\nlocation: tokyo\n",
              b"kind: Job\nspec:\n  to: ops\n",
              b"retry: 3\nupdate: true\n",
              b"review=Great+store.%0D%0ACat+food+arrived+fast&stars=5",
              b"comment=Thanks+for+the+fix%21%0D%0AUpdate%3A+works+now&submit=Send",
              b"subject=Hello&message=Hi+team%2C%0D%0ATo%3A+everyone+in+sales")
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for b in bodies:
            r = sh.inspect_body("192.0.2.20", b)
            assert r["action"] == "allow", (b, r)
    # head 側(path/query/ヘッダ値)の正規化は従来どおり改行を ';' にする
    assert _normalize_full("a\r\nb") == "a;b"


# ── #8: 生 UTF-8 の本文も NFKC/書式文字の畳み込みを受ける ─────────────────────
def test_d8_raw_utf8_body_is_folded_like_escaped_forms():
    """#8: 本文を latin-1 で読んでいたため、生 UTF-8 の全角/ゼロ幅入りの値は文字化けのまま
    走査され、%XX や \\u エスケープで送った同じ値だけが検知されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for s in (FULLWIDTH_XSS, ZW_XSS):
            raw = json.dumps({"c": s}, ensure_ascii=False).encode("utf-8")
            assert sh.inspect_body("192.0.2.30", raw).get("signature") == "xss", s
            esc = json.dumps({"c": s}).encode("ascii")
            assert sh.inspect_body("192.0.2.31", esc).get("signature") == "xss", s
        # UTF-8 として不正なバイトが混ざっても、ASCII 部分はそのまま走査される
        assert sh.inspect_body("192.0.2.32", b"\xff\xfe" + XSS_BODY).get("signature") == "xss"
