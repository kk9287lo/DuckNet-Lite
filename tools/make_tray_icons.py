"""
make_tray_icons.py — トレイの「防御 OFF / 接続不可」用の淡色アイコンを生成する(標準ライブラリのみ)
====================================================================================
トレイは防御 ON の間だけ通常の DuckNet.ico を出し、OFF・本体に接続できない・状態を確認できない
間は淡色(灰色・半透明)の DuckNet-off.ico に切り替える。その淡色版をここで作る。

元絵は **トレイが実際に出している DuckNet.ico の中の PNG(256x256・8bit RGBA)**。原画の
DuckNet.png(1408x1408)ではなくこちらを使うのは、ON と OFF で切り抜き・縮小のされ方まで同じ
(=色だけが変わる)にするためと、純 Python の復号を軽くしておくため(テストが毎回再生成する)。
外部ライブラリ(Pillow 等)は使わない: zlib で展開し、PNG のフィルタ 0〜4 を自前で戻し、
輝度で灰色にして不透明度を下げ、PNG に詰め直して ICO(ヘッダ+PNG 格納エントリ 1 個)で包む。
PNG 格納の ICO は Windows Vista 以降の LoadImageW がそのまま読む。

再生成(リポジトリ直下で。DuckNet.ico を差し替えたら必ず実行してコミットする):
    python tools/make_tray_icons.py
確認だけ(書き込まない。生成結果と既存ファイルの画素が違えば終了コード 1):
    python tools/make_tray_icons.py --check
出力: dataplane/gui/assets/DuckNet-off.ico と ico/DuckNet-off.ico(同じ内容)。
ソースツリーから起動したトレイは ico/ を、インストール版は同梱 assets/ を見るため両方に置く。

出力は決定的(タイムスタンプ等の付随チャンクを書かない・フィルタ選択も固定規則)。圧縮は
zlib.compress(level 9)なので、同じ zlib なら毎回同じバイト列になる(zlib-ng など別実装では
圧縮バイト列だけが変わり得る。--check は画素で比べるのでその差には反応しない)。
"""
from __future__ import annotations

import os
import struct
import sys
import zlib

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(_ROOT, "dataplane", "gui", "assets", "DuckNet.ico")
OUTPUTS = (os.path.join(_ROOT, "dataplane", "gui", "assets", "DuckNet-off.ico"),
           os.path.join(_ROOT, "ico", "DuckNet-off.ico"))

_PNG_SIG = b"\x89PNG\r\n\x1a\n"

# 淡色化の度合い。不透明度は元の ALPHA_NUM/ALPHA_DEN 倍、灰色は輝度を GRAY_FLOOR〜255 へ
# 寄せる(暗い部分を少し持ち上げ、暗色のタスクバー上でも輪郭が消えないようにする)。
ALPHA_NUM, ALPHA_DEN = 1, 2
GRAY_FLOOR = 72


# ── PNG の読み書き ────────────────────────────────────────────────────
def _chunks(png: bytes):
    if png[:8] != _PNG_SIG:
        raise ValueError("not a PNG")
    pos = 8
    while pos + 8 <= len(png):
        n, typ = struct.unpack(">I4s", png[pos:pos + 8])
        body = png[pos + 8:pos + 8 + n]
        if len(body) != n:
            raise ValueError("truncated PNG chunk")
        (crc,) = struct.unpack(">I", png[pos + 8 + n:pos + 12 + n])
        if zlib.crc32(typ + body) & 0xFFFFFFFF != crc:
            raise ValueError("bad CRC in %r" % typ)
        yield typ, body
        if typ == b"IEND":
            return
        pos += 12 + n
    raise ValueError("PNG without IEND")


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def read_png(png: bytes):
    """PNG を (幅, 高さ, RGBA バイト列) に復号する。元絵が使う 8bit の RGBA(色型 6)と、
    念のため 8bit RGB(色型 2)だけを受け付ける。インターレースは非対応(元絵は非インターレース)。"""
    ihdr, idat = None, []
    for typ, body in _chunks(png):
        if typ == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif typ == b"IDAT":
            idat.append(body)
    if ihdr is None:
        raise ValueError("PNG without IHDR")
    w, h, depth, ctype, comp, filt, inter = ihdr
    if depth != 8 or ctype not in (2, 6) or comp or filt or inter:
        raise ValueError("unsupported PNG (depth=%d color=%d interlace=%d)" % (depth, ctype, inter))
    bpp = 4 if ctype == 6 else 3
    stride = w * bpp
    raw = zlib.decompress(b"".join(idat))
    if len(raw) != h * (stride + 1):
        raise ValueError("PNG data size mismatch")
    out = bytearray()
    prev = bytearray(stride)
    for y in range(h):
        base = y * (stride + 1)
        f = raw[base]
        line = bytearray(raw[base + 1:base + 1 + stride])
        if f == 1:                                   # Sub
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif f == 2:                                 # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif f == 3:                                 # Average
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif f == 4:                                 # Paeth
            for i in range(stride):
                if i >= bpp:
                    line[i] = (line[i] + _paeth(line[i - bpp], prev[i], prev[i - bpp])) & 0xFF
                else:
                    line[i] = (line[i] + prev[i]) & 0xFF
        elif f != 0:
            raise ValueError("bad PNG filter type %d" % f)
        out += line
        prev = line
    if ctype == 2:                                   # RGB → RGBA(不透明)
        rgb, out = out, bytearray()
        for i in range(0, len(rgb), 3):
            out += rgb[i:i + 3] + b"\xff"
    return w, h, bytes(out)


def _chunk(typ: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + typ + body
            + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF))


def _cost(bs: bytes) -> int:
    """フィルタ後の行の「ばらつき」(符号付きに読んだ絶対値の和)。小さいほど圧縮が効く。"""
    return sum(v if v < 128 else 256 - v for v in bs)


def write_png(w: int, h: int, rgba: bytes) -> bytes:
    """8bit RGBA の PNG を作る。各行のフィルタは Sub と Up のうち差分の絶対値和が小さい方
    (固定規則=決定的)。付随チャンク(時刻・ガンマ等)は書かない。"""
    stride = w * 4
    rows = []
    prev = bytes(stride)
    for y in range(h):
        line = rgba[y * stride:(y + 1) * stride]
        sub = bytes((line[i] - (line[i - 4] if i >= 4 else 0)) & 0xFF for i in range(stride))
        up = bytes((line[i] - prev[i]) & 0xFF for i in range(stride))
        rows.append(b"\x01" + sub if _cost(sub) <= _cost(up) else b"\x02" + up)
        prev = line
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (_PNG_SIG + _chunk(b"IHDR", ihdr)
            + _chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + _chunk(b"IEND", b""))


# ── ICO の読み書き ────────────────────────────────────────────────────
def largest_png_in_ico(data: bytes) -> bytes:
    """ICO の中で最大の PNG 格納エントリを返す(DuckNet.ico は 256x256 の PNG 1 枚)。"""
    reserved, typ, count = struct.unpack("<HHH", data[:6])
    if reserved != 0 or typ != 1 or count < 1:
        raise ValueError("not an ICO")
    best = b""
    for k in range(count):
        size, off = struct.unpack("<II", data[6 + 16 * k + 8:6 + 16 * k + 16])
        img = data[off:off + size]
        if img[:8] == _PNG_SIG and len(img) > len(best):
            best = img
    if not best:
        raise ValueError("ICO has no PNG entry")
    return best


def wrap_ico(png: bytes, w: int, h: int) -> bytes:
    """PNG 1 枚を格納した ICO を作る(幅・高さの 0 は 256px の意味)。"""
    entry = struct.pack("<BBBBHHII", w % 256, h % 256, 0, 0, 1, 32, len(png), 6 + 16)
    return struct.pack("<HHH", 0, 1, 1) + entry + png


# ── 淡色化 ────────────────────────────────────────────────────────────
def dim_rgba(rgba: bytes) -> bytes:
    """灰色(BT.601 輝度を GRAY_FLOOR〜255 へ圧縮)+不透明度 ALPHA_NUM/ALPHA_DEN 倍。
    完全に透明な画素は (0,0,0,0) に揃える(見た目は同じで、出力が決定的かつ小さくなる)。"""
    out = bytearray(len(rgba))
    span = 255 - GRAY_FLOOR
    for i in range(0, len(rgba), 4):
        r, g, b, a = rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]
        na = (a * ALPHA_NUM + ALPHA_DEN // 2) // ALPHA_DEN
        if na == 0:
            continue
        y = (299 * r + 587 * g + 114 * b + 500) // 1000
        v = GRAY_FLOOR + (y * span + 127) // 255
        out[i] = out[i + 1] = out[i + 2] = v
        out[i + 3] = na
    return bytes(out)


def build(source: str = SOURCE) -> bytes:
    """source(.ico なら最大の PNG エントリ、.png ならそのもの)から淡色版の ICO バイト列を作る。"""
    with open(source, "rb") as f:
        data = f.read()
    png = data if data[:8] == _PNG_SIG else largest_png_in_ico(data)
    w, h, rgba = read_png(png)
    return wrap_ico(write_png(w, h, dim_rgba(rgba)), w, h)


def _pixels_of_ico(data: bytes):
    return read_png(largest_png_in_ico(data))


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    check = "--check" in argv
    out = build(SOURCE)
    want = _pixels_of_ico(out)
    bad = 0
    for path in OUTPUTS:
        if check:
            try:
                with open(path, "rb") as f:
                    same = _pixels_of_ico(f.read()) == want
            except (OSError, ValueError):
                same = False
            if not same:
                bad += 1
                print("outdated: " + path)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(out)
        print("wrote %s (%d bytes)" % (path, len(out)))
    if check and not bad:
        print("up to date")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
