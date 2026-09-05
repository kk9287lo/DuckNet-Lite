"""
test_smuggling.py — HTTP リクエストスマグリング/デシンク拒否(_framing_ambiguous)。
====================================================================================
本機はバイト透過で *再フレーミングしない*。フロントと上流で本文境界の解釈が割れ得る曖昧な
要求は受け取らず拒否する(RFC 7230 §3.3.3 の安全側)。CL.TE/TE.CL・重複CL・非数字CL・
TE.TE・非chunked TE・裸LF/裸CR・obs-fold・複数Host/Host欠落・NUL・名前空白・非origin-form・
不正リクエストラインを構造で弾く。正常な GET / CL付きPOST は通す(誤遮断しない)。
"""
from dataplane.engine.services.proxy import _framing_ambiguous


def _req(lines, body=b""):
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def test_clean_requests_pass():
    assert _framing_ambiguous(_req(["GET / HTTP/1.1", "Host: x"])) is False
    assert _framing_ambiguous(
        _req(["POST /a HTTP/1.1", "Host: x", "Content-Length: 5"], b"hello")) is False
    assert _framing_ambiguous(
        _req(["POST /a HTTP/1.1", "Host: x", "Transfer-Encoding: chunked"])) is False
    assert _framing_ambiguous(_req(["OPTIONS * HTTP/1.1", "Host: x"])) is False


def test_cl_te_desync_rejected():
    assert _framing_ambiguous(_req(
        ["POST / HTTP/1.1", "Host: x", "Content-Length: 6", "Transfer-Encoding: chunked"]))


def test_duplicate_and_malformed_content_length_rejected():
    assert _framing_ambiguous(_req(
        ["POST / HTTP/1.1", "Host: x", "Content-Length: 5", "Content-Length: 6"]))
    for bad in ("0x10", "+5", "5, 5", "0x5", "5e0"):    # 非1*DIGIT(OWS トリム後も数字でない)
        assert _framing_ambiguous(_req(
            ["POST / HTTP/1.1", "Host: x", f"Content-Length: {bad}"])), bad


def test_transfer_encoding_tricks_rejected():
    assert _framing_ambiguous(_req(
        ["POST / HTTP/1.1", "Host: x", "Transfer-Encoding: chunked",
         "Transfer-Encoding: identity"]))                     # TE.TE
    assert _framing_ambiguous(_req(
        ["POST / HTTP/1.1", "Host: x", "Transfer-Encoding: gzip"]))   # 最終が chunked でない


def test_header_name_space_obfuscation_rejected():
    assert _framing_ambiguous(_req(
        ["POST / HTTP/1.1", "Host: x", "Content-Length : 5"]))   # "名前 :" の難読化


def test_bare_lf_and_cr_rejected():
    # 裸 LF(CR 無し)を含む head=行終端の解釈が割れる
    raw = b"POST / HTTP/1.1\r\nHost: x\nContent-Length: 5\r\n\r\n"
    assert _framing_ambiguous(raw)
    raw_cr = b"POST / HTTP/1.1\rHost: x\r\n\r\n"
    assert _framing_ambiguous(raw_cr)


def test_obs_fold_rejected():
    assert _framing_ambiguous(_req(
        ["POST / HTTP/1.1", "Host: x", "X-Foo: a", "    b", "Content-Length: 0"]))


def test_host_and_requestline_rules():
    assert _framing_ambiguous(_req(["GET / HTTP/1.1", "Host: a", "Host: b"]))   # 複数 Host
    assert _framing_ambiguous(_req(["GET / HTTP/1.1"]))                          # 1.1 で Host 欠落
    assert _framing_ambiguous(_req(["GET  /  HTTP/1.1", "Host: x"]))            # 二重空白
    assert _framing_ambiguous(_req(["GET http://h/ HTTP/1.1", "Host: x"]))      # 絶対形(非origin)
    assert _framing_ambiguous(_req(["BOGUS", "Host: x"]))                        # 不正リクエストライン


def test_nul_in_header_rejected():
    assert _framing_ambiguous(b"GET / HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n")


def test_framing_never_raises_on_malformed_or_multibyte():
    import os
    import random
    for _ in range(300):                                   # ファズ: ランダム断片でも例外/フリーズ無し
        assert _framing_ambiguous(os.urandom(random.randint(0, 400))) in (True, False)
    samples = [
        ("GET /" + "漢" * 200 + " HTTP/1.1\r\nHost: x\r\n\r\n").encode("utf-8"),  # 未エンコ多byte URI
        b"GET / HTTP/1.1\r\nHost: x\r\nX-A: \xe6\xbc\xa2\r\n\r\n",               # ヘッダ値に生UTF-8
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0x0001\r\nAA\r\n0\r\n\r\n",
        b"\xff\xfe\x00\x01 not http at all",                                     # 非HTTPバイナリ
        b"GET / HTTP/1.1\r\n" + b"X-Pad: " + b"A" * 70000 + b"\r\n\r\n",         # 巨大ヘッダ
    ]
    for raw in samples:
        assert _framing_ambiguous(raw) in (True, False)   # クラッシュ/フリーズしないこと
