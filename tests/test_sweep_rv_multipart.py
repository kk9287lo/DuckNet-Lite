"""
test_sweep_rv_multipart.py — multipart の解析コストと出口 DLP のカード IIN の回帰(review: rv_multipart)。
====================================================================================
· #4  パートヘッダの逐次検査が、Content-Disposition 行が揃うたびに *それまでのヘッダ塊全体* を
      作り直して読み直していた(行数の 2 乗)。害の無い行を 1500 回繰り返しただけの小さな要求 1 本で
      イベントループが数秒止まった。1 パートのヘッダ行数にも上限が無かった。
· #38 _multipart_fields が枠でない '--境界…' 行を文字列の += で中身へ戻していた(2 乗)。
      body_scan_max_bytes を上げると要求 1 本で数秒止まった。
· #39 カード番号の IIN 絞り込み(#26)で、前版が検出していた Maestro / RuPay が抜けていた。

所要時間の試験は絶対時間ではなく *同じ量の入力を形だけ変えたときの比* で見る(遅い CI でも安定)。
カード番号は Luhn を満たすよう末尾を補った合成番号だけを使う(実在のカード番号は使わない)。
"""
import tempfile
import time

import dataplane.engine.lifeform.pipeline as ND
from dataplane.engine.lifeform.pipeline import NetShield, scan_secret_leak

_MP_CT = "multipart/form-data; boundary=b"
_LINE = b'Content-Disposition: form-data; name="a"\r\n'     # 害の無いヘッダ行(ファイル名なし)
_CONT = b' content-disposition; name="a"\r\n'                # 同じ語で始まる折り返し行


def _sh(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _body(nparts: int, hdr: bytes) -> bytes:
    return (b"--b\r\n" + hdr + b"\r\nx\r\n") * nparts + b"--b--\r\n"


def _stream_ms(body: bytes, reps: int = 3):
    """proxy と同じく 64 KiB ずつ逐次スキャナへ食わせた所要時間(最良値・ms)と最後の判定。"""
    best, hit = float("inf"), None
    for _ in range(reps):
        us = ND._UploadScan([b"b"], {"xyz"})
        t = time.perf_counter()
        for i in range(0, len(body), 65536):
            hit = us.feed(body[i:i + 65536])
        best = min(best, time.perf_counter() - t)
    return best * 1000, hit


# ── #4 パートヘッダの検査は行数に線形 ─────────────────────────────────────────
def test_rv4_part_header_scan_is_linear_in_header_lines():
    """#4: 同じ量のヘッダ行を『2 行×多パート』と『80 行×少パート』で比べる。線形なら所要時間は
    ほぼ同じ。旧実装は 80 行のパートで行が揃うたびに塊全体を読み直し、約 15 倍かかった。"""
    few = _body(1200, _LINE * 2)                  # 2400 行(1 パート 2 行)
    many = _body(30, _LINE * 80)                  # 2400 行(1 パート 80 行)
    t_few, h1 = _stream_ms(few)
    t_many, h2 = _stream_ms(many)
    assert h1 is None and h2 is None, (h1, h2)
    assert t_many < 4 * max(t_few, 1.0), (t_few, t_many)


def test_rv4_folded_disposition_lines_do_not_rescan_the_block():
    """#4: 'content-disposition' で始まる折り返し行が続くと、1 本の論理行が伸びるたびに丸ごと
    読み直していた(折り返し行の連結も bytes の + で 2 乗)。"""
    plain = _body(1200, _LINE * 2)
    folded = _body(30, _LINE + _CONT * 79)
    t_plain, h1 = _stream_ms(plain)
    t_fold, h2 = _stream_ms(folded)
    assert h1 is None and h2 is None, (h1, h2)
    assert t_fold < 4 * max(t_plain, 1.0), (t_plain, t_fold)


def test_rv4_too_many_part_header_lines_fail_closed():
    """#4: 1 パートのヘッダ行数に上限が無く、害の無い行 1500 本(64 KiB 未満)を数秒かけて全部
    読んでいた。実在のパートは数行なので、上限超えは検査できない multipart として拒否する。"""
    body = _body(1, _LINE * 1500)
    assert len(body) < ND._UPLOAD_HDR_MAX
    t = time.perf_counter()
    hit = ND._dangerous_upload_filename(body, ["xyz"], 1 << 20, _MP_CT)
    took = time.perf_counter() - t
    assert hit is not None and hit[1] == "", hit             # (理由, "")=フェイルクローズ
    assert took < 1.0, took
    _, hit = _stream_ms(body, reps=1)
    assert hit is not None and hit[1] == "", hit
    with tempfile.TemporaryDirectory() as d:
        r = _sh(d).scan_upload("192.0.2.40", body, _MP_CT)
        assert r["action"] == "block" and r["ext"] == "", r
    # 実在の形(折り返し付きの長いファイル名・Content-Type 等で十数行)は従来どおり通す
    hdr = (b'Content-Disposition: form-data; name="file";\r\n'
           + b"".join(b" filename*%d*=UTF-8''part%02d;\r\n" % (i, i) for i in range(12))
           + b"Content-Type: text/plain\r\nContent-Transfer-Encoding: binary\r\n")
    ok = _body(3, hdr)
    assert ND._dangerous_upload_filename(ok, ["xyz"], 1 << 20, _MP_CT) is None
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d)
        assert sh.scan_upload("192.0.2.41", ok, _MP_CT)["action"] == "allow"
        assert not sh.is_banned_fast("192.0.2.41")


def test_rv4_disposition_line_is_still_checked_before_the_block_ends():
    """#4 の修正後も、Content-Disposition 行が揃った時点で(ヘッダ塊の終わりを待たずに)見る。
    待つと、その行を含むチャンクが先に backend へ転送される(#33)。2 本目の行・折り返し行も同じ。"""
    first = b'--b\r\nContent-Disposition: form-data; name="f"; filename="note.xyz"\r\n'
    second = (b'--b\r\nContent-Disposition: form-data; name="f"\r\n'
              b'Content-Disposition: form-data; name="f"; filename="note.xyz"\r\n')
    folded = (b'--b\r\nContent-Disposition: form-data; name="f";\r\n'
              b' content-disposition: form-data; filename="note.xyz"\r\n')
    for head in (first, second, folded):
        us = ND._UploadScan([b"b"], {"xyz"})
        hit = us.feed(head)                           # 空行(塊の終わり)はまだ来ていない
        assert hit is not None and hit[1] == "xyz", (head, hit)
    # 折り返しで分かれたファイル名は塊の終わりで続き行込みに読む
    split = (b'--b\r\nContent-Disposition: form-data; name="f";\r\n'
             b' filename="note.xyz"\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n')
    hit = ND._dangerous_upload_filename(split, ["xyz"], 1 << 20, _MP_CT)
    assert hit is not None and hit[1] == "xyz", hit
    # 区切りを跨いで細かく届いても同じ(1 バイトずつ)
    us = ND._UploadScan([b"b"], {"xyz"})
    hits = [us.feed(split[i:i + 1]) for i in range(len(split))]
    assert any(h and h[1] == "xyz" for h in hits), hits[-1]


# ── #38 _multipart_fields は本文長に線形 ─────────────────────────────────────
def _fields_ms(text: str, reps: int = 3) -> float:
    ND._multipart_fields(text)
    best = float("inf")
    for _ in range(reps):
        t = time.perf_counter()
        ND._multipart_fields(text)
        best = min(best, time.perf_counter() - t)
    return best * 1000


def test_rv38_multipart_fields_is_linear_in_body_size():
    """#38: 枠でない '--境界…' 行(境界を接頭に持つ普通の行)を部の中身へ += で戻していた。
    8 倍の本文で 8 倍程度に収まること(旧実装は 2 乗で約 60 倍)。"""
    def text(size):
        return ("--a\n" + "\n--ax" * (size // 5 + 1))[:size]
    small, big = text(65536), text(65536 * 8)
    t_small = _fields_ms(small)
    t_big = _fields_ms(big)
    assert t_big < 24 * max(t_small, 0.5), (t_small, t_big)


def test_rv38_non_frame_boundary_lines_stay_in_the_part():
    """#38 の修正で結果は変わらない: 枠でない '--境界…' 行は元の位置のまま部の中身に残る。"""
    text = ("--a\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n"
            "line one\n--abc not a frame\n--ab also text\r\n--a\r\n"
            "Content-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--a--\r\n")
    bodies, heads = ND._multipart_fields(text)
    assert bodies == ND._MP_SEP.join(
        ["line one\n--abc not a frame\n--ab also text", "value"]), bodies
    assert heads == ND._MP_SEP.join(["a", 'Content-Disposition: form-data; name="note"',
                                     'Content-Disposition: form-data; name="x"']), heads


# ── #39 Maestro / RuPay の IIN ───────────────────────────────────────────────
def _with_luhn(prefix: str, length: int) -> str:
    """prefix + 0 埋め + Luhn の検査数字(合成番号)。"""
    base = prefix + "0" * (length - len(prefix) - 1)
    for d in "0123456789":
        if ND._luhn_ok((base + d).encode()):
            return base + d
    raise AssertionError(prefix)


def test_rv39_maestro_and_rupay_numbers_are_detected():
    """#39: #26 の IIN 絞り込みで Maestro(5018/5020/5038/5893/6304/6759/6761-6763 等)と RuPay
    (508500-508999 / 606985-607984 / 608001-608500)が抜け、前版が検出していた番号を素通りした。"""
    for prefix, n in (("5018", 16), ("5020", 19), ("5038", 16), ("5893", 16), ("6304", 16),
                      ("6759", 16), ("6761", 16), ("6762", 18), ("6763", 16),
                      ("676770", 16), ("676774", 19),
                      ("5085", 16), ("508999", 16), ("606985", 16), ("6074", 16),
                      ("607984", 16), ("608001", 16), ("608500", 16)):
        num = _with_luhn(prefix, n)
        assert scan_secret_leak("card " + num) == ["credit_card"], num
    # 範囲の外側と 13 桁(JAN/EAN と衝突)は従来どおり対象外(#26)
    for prefix, n in (("606984", 16), ("607985", 16), ("608000", 16), ("608501", 16),
                      ("508499", 16), ("5019", 16), ("6305", 16), ("6760", 16),
                      ("676771", 16), ("60", 16), ("63", 16), ("5000", 16),
                      ("5018", 13), ("6074", 13)):
        num = _with_luhn(prefix, n)
        assert scan_secret_leak("id " + num) == [], num
