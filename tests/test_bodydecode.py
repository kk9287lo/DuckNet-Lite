"""
test_bodydecode.py — 圧縮ボディの解凍走査(Content-Encoding 回避封じ・evolution #74)。
====================================================================================
Content-Encoding: gzip/deflate で圧縮したボディは、生バイト走査では payload を見逃す。有界に
解凍して(zip bomb 耐性)解凍後を走査することで、gzip 化した SQLi 等の回避を塞ぐ。
"""
import gzip
import tempfile
import zlib

from dataplane.engine.services.proxy import AsyncEdgeGuard
from dataplane.engine.lifeform.pipeline import NetShield


def test_decompress_gzip_roundtrip():
    payload = b"username=admin' or 1=1-- -&x=1"
    comp = gzip.compress(payload)
    out = AsyncEdgeGuard._decompress_bounded(comp, "gzip", 65536)
    assert out == payload


def test_decompress_deflate():
    payload = b"q=login' or 1=1-- -"
    comp = zlib.compress(payload)
    assert AsyncEdgeGuard._decompress_bounded(comp, "deflate", 65536) == payload


def test_decompress_raw_deflate():
    payload = b"raw-deflate-' or 1=1--"
    co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    comp = co.compress(payload) + co.flush()
    assert AsyncEdgeGuard._decompress_bounded(comp, "deflate", 65536) == payload


def test_decompress_unknown_encoding_none():
    assert AsyncEdgeGuard._decompress_bounded(b"\x00\x01", "br", 65536) is None
    assert AsyncEdgeGuard._decompress_bounded(b"not-compressed", "gzip", 65536) is None


def test_decompress_bounded_caps_output():
    # zip bomb 耐性: 出力は max_out で頭打ち
    big = gzip.compress(b"A" * 1_000_000)
    out = AsyncEdgeGuard._decompress_bounded(big, "gzip", 1024)
    assert out is not None and len(out) <= 1024


def test_decoded_body_sqli_is_detected():
    # 解凍後の本文を inspect_body に通すと SQLi が検知される(回避が塞がれる)。
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg["block_score"] = 20
        comp = gzip.compress(b"user=admin' or 1=1-- -")
        # 生(圧縮)を走査してもヒットしない
        assert sh.inspect_body("1.1.1.1", comp)["action"] == "allow"
        # 解凍後を走査するとヒット→遮断
        dec = AsyncEdgeGuard._decompress_bounded(comp, "gzip", 65536)
        assert sh.inspect_body("9.9.9.9", dec)["action"] == "block"
