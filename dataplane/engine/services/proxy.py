"""
proxy.py — stdlib asyncio による Fail-Fast 前衛ガード(依存ゼロのリバースプロキシ)
====================================================================================
高速な前衛シュレッダー + 非同期化 を **外部依存なし(標準ライブラリ asyncio だけ)** で実現する。
スレッド毎接続型サーバ(1接続=1スレッド)の手前に置く単一イベントループの L7ガード:

  · 接続が来たら request-line / Host / User-Agent だけを(タイムアウト付きで)読む。
  · app_firewall + net_shield(v2)に照会。block/deny は **その場で writer.close()**=
    レスポンスも返さず即TCP切断(444 相当=接続を黙って閉じる)。スレッドを1つも消費しない。
  · throttle は 429+Retry-After を返して切断。allow だけバックエンド(本体 Web サービス)へ
    非同期パイプ(双方向 splice)。

これが C10K/C100K への現実解の一枚: イベントループなら数万の I/O 待ちをシングルスレッドで
プールでき、怪しい接続は『即解放(Fail Fast)』で捨てて次へ進める=スレッド枯渇しない。

正直: これは **L7(アプリ層)** の前衛。回線/OSを飽和させる L3/L4 ボリューメトリックは依然
ネットワーク層(Anycast/eBPF/ISP)の領域で、ここでは止められない。防御専用・OS非侵襲。
"""
from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import html as html_lib
from html.parser import HTMLParser
import ipaddress
import json
import math
import mmap
import os
import re
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import weakref
from urllib.parse import unquote_to_bytes
from xml.parsers import expat

from . import banner as deception
from ..core import saferegex
from ..core import commit_barrier


def _finite_positive_timeout(value, default: float) -> float:
    """Timeout の NaN/inf/非正値を有限の安全な既定値へ戻す。"""
    if isinstance(value, bool):
        return default
    try:
        seconds = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return (seconds if math.isfinite(seconds) and 0 < seconds < threading.TIMEOUT_MAX
            else default)


class _DrainedStall(asyncio.TimeoutError):
    """drain完了後に累積stall上限へ達した時の、既送バイト数。"""

    def __init__(self, sent_bytes: int):
        self.sent_bytes = sent_bytes


class _EgressQuotaReached(Exception):
    """The current response cannot send another byte under its quota."""


# A second stream can shorten an already waiting stream's aggregate deadline.
# Finite time quotas are opt-in; recheck their read/drain waits at this bound.
_QUOTA_TIME_RECHECK_SEC = 0.05
_MAX_DRAIN_GRACE_SEC = 300.0


def _signed_source_stamp(path: str):
    """Cheap, fail-closed change detector for one fork-visible state file."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise OSError("signed state source is not a regular file")
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _jsonify(obj) -> str:
    """戻り値を JSON 文字列へ(非シリアライズ可能は str)。製品を巨大APIから独立させるため内蔵。"""
    return json.dumps(obj, ensure_ascii=False, default=lambda o: str(o))


def _http_response(status: str, body, content_type: str = "application/json; charset=utf-8",
                   server: str = "", extra=None) -> bytes:
    """HTTP応答を1本に束ねる。body は str/bytes どちらでも受け取り、Content-Length は
    必ず *UTF-8 エンコード後のバイト数* で厳密計算する。これにより将来 reason 等へ
    非ASCII(例: "期限切れ")が混ざっても、文字数とバイト数の食い違いで Content-Length が
    ズレてクライアントがハングする事故を構造的に防ぐ。Connection: close 固定(単発応答)。
    server を渡すと Server ヘッダを付与(デセプション時=偽バナーで指紋を攪乱)。extra は
    追加ヘッダ [(name, value), …](デセプションの系統整合ヘッダ等)。CR/LF はヘッダ注入防止に除去。"""
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
    if server:
        head += f"Server: {server}\r\n"
    for k, v in (extra or ()):                    # 系統整合ヘッダ等。値の CR/LF は除去(注入防止)
        k = str(k).replace("\r", "").replace("\n", "")
        v = str(v).replace("\r", "").replace("\n", "")
        head += f"{k}: {v}\r\n"
    head += f"Connection: close\r\nContent-Length: {len(body)}\r\n\r\n"
    return head.encode("ascii", "replace") + body


def _force_conn_close(buf: bytes) -> bytes:
    """転送するリクエストヘッダの Connection を close に書き換える。
    `_handle_conn` は設定値にかかわらず宣言された本文境界で転送を止め、後続の
    パイプライン要求をバックエンドへ送らない。head 不完全/body 部は保持。"""
    head, sep, rest = buf.partition(b"\r\n\r\n")
    if not sep:
        return buf                                    # head 不完全=触らない(壊さない)
    lines = head.split(b"\r\n")
    kept = lines[:1]                                  # リクエストライン
    for ln in lines[1:]:
        low = ln.lower()
        if (low.startswith(b"connection:") or low.startswith(b"keep-alive:")
                or low.startswith(b"proxy-connection:")):
            continue                                  # 既存の接続制御ヘッダは除去
        kept.append(ln)
    kept.append(b"Connection: close")
    return b"\r\n".join(kept) + b"\r\n\r\n" + rest


def _request_declares_body(buf: bytes) -> bool:
    """要求が本文を持ち得るか(Content-Length / Transfer-Encoding を宣言しているか)。
    どちらも無ければ RFC 7230 §3.3.3 により本文長はゼロ=ボディ皆無。よって head の
    CRLFCRLF 以降に来るバイトは *この要求の一部ではあり得ず*、パイプラインされた第2要求
    (inspect-once 設計では未検査でバックエンドへ届く=#31 が backend の close 尊重に
    委ねていた残余リスク)である。framing 検査通過後に呼ぶ前提なので素朴な名前一致で十分。"""
    head = buf.split(b"\r\n\r\n", 1)[0]
    for ln in head.split(b"\r\n")[1:]:
        kl = ln.split(b":", 1)[0].strip().lower()
        if kl in (b"content-length", b"transfer-encoding"):
            return True
    return False


_CONTINUE_100 = b"HTTP/1.1 100 Continue\r\n\r\n"
_GZIP_MEMBER_MAX = 256  # empty members bypass decoded-byte caps and amplify CPU work
_REQUEST_HEAD_MAX = 16384
_BACKEND_CONNECT_TIMEOUT = 5.0
_REJECT_DRAIN_SEC = 0.2
_REJECT_DRAIN_MAX = 1 << 20
_BODY_STAGE_MAX = 64 * 1024 * 1024       # hard wire-byte cap per request
_BODY_STAGE_TOTAL = 256 * 1024 * 1024   # hard aggregate across active requests/workers
_BODY_STAGE_MEMORY = 256 * 1024         # spill only larger bodies to a private temp file
_BODY_STAGE_MAX_SEC = 300.0             # even a disabled configured body timer stays bounded
_BODY_STAGE_PROBE_INTERVAL_NS = 200_000_000  # one pressure scan across all fork workers


def _expects_continue(buf: bytes) -> bool:
    """要求が 100 Continue を待ってから本文を送る形か(HTTP/1.1 以上 + Expect: 100-continue)。
    HTTP/1.0 の Expect は無視する決まり(RFC 9110 §10.1.1)=1.0 の相手に 1xx は送らない。"""
    ver = buf.split(b"\r\n", 1)[0].rsplit(b" ", 1)[-1].strip().upper()
    if not ver.startswith(b"HTTP/") or ver in (b"HTTP/1.0", b"HTTP/0.9"):
        return False
    return any(t.strip().lower() == "100-continue"
               for v in _header_values(buf, b"expect") for t in v.split(","))


_CHUNK_HEX = re.compile(rb"\A[0-9A-Fa-f]{1,16}\Z")
_CHUNK_LINE_MAX = 8192      # サイズ行/trailer 行の上限(超える行は枠の破損とみなす)
_CHUNK_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _chunk_size_line(line: bytes):
    """chunk-size / chunk-ext を有界・厳密に読む。曖昧な拡張構文は上流へ渡さない。"""
    i, n = 0, len(line)
    while i < n and line[i] in b"0123456789ABCDEFabcdef":
        i += 1
    if not 1 <= i <= 16:
        return None
    size = int(line[:i], 16)
    while i < n:
        while i < n and line[i] in b" \t":
            i += 1
        if i >= n or line[i] != ord(";"):
            return None
        i += 1
        while i < n and line[i] in b" \t":
            i += 1
        start = i
        while i < n and line[i] in _CHUNK_TCHAR:
            i += 1
        if i == start:
            return None
        while i < n and line[i] in b" \t":
            i += 1
        if i < n and line[i] == ord("="):
            i += 1
            while i < n and line[i] in b" \t":
                i += 1
            if i < n and line[i] == ord('"'):
                i += 1
                while i < n and line[i] != ord('"'):
                    ch = line[i]
                    if ch == ord("\\"):
                        i += 1
                        if i >= n:
                            return None
                        ch = line[i]
                    if ch != 9 and (ch < 32 or ch == 127):
                        return None
                    i += 1
                if i >= n:
                    return None
                i += 1
            else:
                start = i
                while i < n and line[i] in _CHUNK_TCHAR:
                    i += 1
                if i == start:
                    return None
    return size


class _ChunkedEnd:
    """chunked 本文の *終端位置* を逐次に追跡する(#18)。本文は保持しない=メモリは行バッファのみ。
    feed(data) は data のうち *この本文に属する* 先頭バイト数を返す。last-chunk + trailer + 空行に
    達したら done。枠が RFC 7230 §4.1 の厳密形でなければ bad(どこで終わるか backend と一致させ
    られない=呼び出し側はそこで転送を止める)。終端より後ろのバイトはパイプライン化された後続要求で
    あり、転送してはならない(旧実装は読取が '0\\r\\n\\r\\n' で *ちょうど終わる* ときしか完了と
    見なさず、後ろに第2要求が続くと丸ごと転送していた。逆に chunk データが偶然その並びで終わる
    パケット境界では本文の途中で転送を打ち切っていた)。"""
    __slots__ = ("_st", "_line", "_left", "consumed", "done", "bad",
                 "_response_trailers", "_trailer_bytes", "_trailer_name_checked",
                 "_forbidden_response_fields")

    def __init__(self, *, response_trailers=False, forbidden_response_fields=()):
        self._st = "size"             # size → data → crlf → size … → trailer
        self._line = bytearray()
        self._left = 0
        self.consumed = 0             # これまでに本文として受理した総バイト数
        self.done = self.bad = False
        self._response_trailers = response_trailers
        self._trailer_bytes = 0
        self._trailer_name_checked = False
        self._forbidden_response_fields = frozenset(forbidden_response_fields)

    def feed(self, data: bytes) -> int:
        i, n = 0, len(data)
        while i < n and not (self.done or self.bad):
            if self._st == "data":
                take = min(self._left, n - i)
                i += take
                self._left -= take
                if self._left == 0:
                    self._st = "crlf"
                continue
            j = data.find(b"\n", i)
            if j < 0:
                previous_line_len = len(self._line)
                self._line += data[i:]
                i = n
                if (self._st == "trailer" and self._response_trailers
                        and not self._trailer_name_checked):
                    # A previous fragment had no colon; never rescan that prefix.
                    name_end = self._line.find(b":", previous_line_len)
                    if name_end >= 0:
                        name = bytes(self._line[:name_end])
                        self._trailer_name_checked = True
                        if (not _RESPONSE_HEADER_NAME.fullmatch(name)
                                or name.lower() in _RESPONSE_TRAILER_FORBIDDEN
                                or name.lower() in self._forbidden_response_fields):
                            # Decide at the colon, before this read can release
                            # any origin-only value (even with bytewise input).
                            self.bad = True
                if len(self._line) > _CHUNK_LINE_MAX:
                    self.bad = True
                break
            self._line += data[i:j + 1]
            i = j + 1
            ln = bytes(self._line)
            self._line.clear()
            self._trailer_name_checked = False
            if len(ln) > _CHUNK_LINE_MAX or not ln.endswith(b"\r\n") or b"\r" in ln[:-2]:
                self.bad = True       # 裸 LF / 行中の裸 CR / 過大行=境界の解釈が割れる
                break
            ln = ln[:-2]
            if self._st == "crlf":
                if ln:
                    self.bad = True   # chunk データの直後は CRLF のみ
                    break
                self._st = "size"
            elif self._st == "size":
                size = _chunk_size_line(ln)
                if size is None:
                    self.bad = True   # 0x 接頭辞・符号・空 等も拒否(int(,16) は受理してしまう)
                    break
                if size == 0:
                    self._st = "trailer"
                else:
                    self._left, self._st = size, "data"
            elif not ln:              # 空 trailer 部=本文終端
                self.done = True
            elif self._response_trailers:
                # Response trailers were already carried on the wire. Keep
                # their data separate from the body and bound the whole section.
                self._trailer_bytes += len(ln) + 2
                name, sep, value = ln.partition(b":")
                if (self._trailer_bytes > 65536 or not sep
                        or not _RESPONSE_HEADER_NAME.fullmatch(name)
                        or any(c < 32 and c != 9 or c == 127 for c in value)
                        or name.lower() in _RESPONSE_TRAILER_FORBIDDEN
                        or name.lower() in self._forbidden_response_fields):
                    self.bad = True
            else:
                # Trailer は head の WAF 走査面に載らない。上流で Host/認証/CL 等に
                # 統合される実装もあるため、非空の request trailer は一律に拒否する。
                self.bad = True
                break
        if self.bad:
            return 0
        self.consumed += i
        return i


def _resp_status(line: bytes) -> int:
    """応答行(HTTP/1.x NNN ...)のステータスコード。読めなければ 0。"""
    parts = line.split(b" ")
    if len(parts) >= 2 and parts[0].startswith(b"HTTP/") and parts[1].isdigit():
        return int(parts[1])
    return 0


def _is_interim(code: int) -> bool:
    """1xx 中間応答(100 Continue / 103 Early Hints 等)か。101 はプロトコル切替=最終応答。"""
    return 100 <= code < 200 and code != 101


# ── 出口 DLP の応答本文走査(#1/#27/#42/#47/#48) ───────────────────────────────
# 窓走査で一致の開始を判定するのに要る右側の文脈長。最長の判定幅(カード番号 19 桁+区切り 19+
# 後続 1 = 39B、github_token 40+1B)より長く取る。各読取の末尾この長さは次の読取と合わせて判定する。
_DLP_LOOK = 64
class _Dechunk:
    """chunked 応答本文から *DLP の走査対象* になるバイト範囲を逐次に取り出す(#47)。
    feed(data) は data 内の範囲 [(s, e), …] を返す(chunk-size 行と data 直後の CRLF は含めない)。
    転送は呼び出し側が wire のまま行う(ここは走査面を作るだけ=枠は 1 バイトも変えない)。
    trailer は本文へ混ぜず、別の raw 走査が検査する。枠が読めなくなった以降は全バイトを範囲に含める。"""
    __slots__ = ("_st", "_line", "_left")

    def __init__(self):
        self._st = "size"             # size → data → crlf → size … → trailer → done
        self._line = bytearray()      # 読取を跨いだサイズ行の断片
        self._left = 0

    def feed(self, data: bytes) -> list:
        runs, i, n = [], 0, len(data)
        while i < n:
            st = self._st
            if st == "done":
                break
            if st == "raw":
                runs.append((i, n))
                break
            if st == "data":
                take = min(self._left, n - i)
                runs.append((i, i + take))
                i += take
                self._left -= take
                if not self._left:
                    self._st = "crlf"
                continue
            j = data.find(b"\n", i)
            if j < 0:
                self._line += data[i:]
                if len(self._line) > _CHUNK_LINE_MAX:   # 過大な行=枠ではない。以降はそのまま走査
                    self._st = "raw"
                    runs.append((i, n))
                break
            ln, ls, i = (bytes(self._line) + data[i:j]).rstrip(b"\r"), i, j + 1
            self._line.clear()
            if st == "trailer":
                if not ln:
                    self._st = "done"
                continue
            if st == "crlf":
                if ln:                                  # data 直後が CRLF でない=枠崩れ
                    self._st = "raw"
                    runs.append((ls, n))
                    break
                self._st = "size"
                continue
            sz = ln.split(b";", 1)[0].strip(b" \t")     # chunk-ext(;...)は捨てる
            if not _CHUNK_HEX.match(sz):
                self._st = "raw"
                runs.append((ls, n))
                break
            size = int(sz, 16)
            if size:
                self._left, self._st = size, "data"
            else:
                self._st = "trailer"                    # raw scan separately covers trailer metadata
        return runs


def _dlp_body_mode(head: bytes):
    """最終応答 head(CRLFCRLF 抜き)から chunked と解けない符号化を読む。
    解けない符号化=identity 以外の Content-Encoding と単一の chunked 以外の
    Transfer-Encoding(#1)。"""
    lines = head.split(b"\r\n")
    chunked, bad = False, []
    transfers = []
    for ln in lines[1:]:
        k, sep, v = ln.partition(b":")
        if not sep:
            continue
        k = k.strip().lower()
        if k == b"transfer-encoding":
            transfers.append(v.strip().lower())
        elif k == b"content-encoding":
            for c in v.lower().split(b","):
                c = c.strip()
                if c and c != b"identity":
                    bad.append(c.decode("latin-1")[:16])
    if transfers:
        if transfers == [b"chunked"]:
            chunked = True
        else:
            bad.append("transfer-encoding")
    return chunked, ",".join(bad[:4])


_RESPONSE_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_DLP_ASCII_CHARSETS = {b"utf-8", b"utf8", b"us-ascii", b"ascii",
                       b"iso-8859-1", b"latin-1", b"latin1", b"windows-1252"}
_DLP_JSON_LOOK = _DLP_LOOK * 6  # ASCII JSON \uXXXX は 1 文字につき最大 6 wire bytes
_DLP_HTML_ENTITY_MAX = 64   # includes long benign HTML5 named references
_DLP_HTML_ASCII_ENTITY_MAX = 16  # longer ASCII-producing references fail closed
_DLP_HTML_WIRE_LOOK = (_DLP_LOOK * _DLP_HTML_ASCII_ENTITY_MAX
                       + _DLP_HTML_ENTITY_MAX + 32)
_DLP_HTML_PARSE_TAIL_MAX = 8192  # bound an unfinished tag/reference in HTMLParser
_DLP_HTML_HOLD_MAX = 16 << 20  # process-wide wire held by blocking HTML DLP
_DLP_HTML_RESPONSE_SEC = 30.0
_DLP_HTML_HOLD_LOCK = threading.Lock()
_DLP_HTML_HOLD_USED = 0


def _dlp_html_reserve(size: int) -> bool:
    global _DLP_HTML_HOLD_USED
    with _DLP_HTML_HOLD_LOCK:
        if size > _DLP_HTML_HOLD_MAX - _DLP_HTML_HOLD_USED:
            return False
        _DLP_HTML_HOLD_USED += size
        return True


def _dlp_html_release(size: int) -> None:
    global _DLP_HTML_HOLD_USED
    if size:
        with _DLP_HTML_HOLD_LOCK:
            _DLP_HTML_HOLD_USED -= size


def _dlp_html_after_fork_child() -> None:
    global _DLP_HTML_HOLD_LOCK, _DLP_HTML_HOLD_USED
    _DLP_HTML_HOLD_LOCK = threading.Lock()
    _DLP_HTML_HOLD_USED = 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_dlp_html_after_fork_child)
_DLP_HTML_TAIL = re.compile(rb"&(?:\#[0-9]*|\#[xX][0-9A-Fa-f]*|[A-Za-z][A-Za-z0-9]*)?\Z")
_DLP_HTML_ENTITY_CHARS = b"#0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_DLP_MARKUP_URI_ATTRS = frozenset({
    "href", "xlink:href", "src", "srcset", "imagesrcset", "data", "action",
    "formaction", "poster", "cite", "background", "longdesc", "manifest",
    "ping", "codebase", "archive", "profile", "icon", "usemap",
})
_DLP_MARKUP_URI_LIST_ATTRS = frozenset({"srcset", "imagesrcset", "ping"})
_DLP_ARCHIVE_PROBE = 262          # tar の ustar marker は offset 257..261
_DLP_ARCHIVE_MEDIA = {
    b"application/zip", b"application/x-zip-compressed", b"application/gzip",
    b"application/x-gzip", b"application/x-bzip2", b"application/x-xz",
    b"application/x-7z-compressed", b"application/x-rar-compressed",
    b"application/vnd.rar", b"application/x-tar", b"application/tar",
    b"application/vnd.ms-cab-compressed",
}
_DLP_JS_MEDIA = frozenset({  # WHATWG MIME Sniffing: JavaScript MIME essences
    b"application/ecmascript", b"application/javascript",
    b"application/x-ecmascript", b"application/x-javascript",
    b"text/ecmascript", b"text/javascript",
    b"text/javascript1.0", b"text/javascript1.1", b"text/javascript1.2",
    b"text/javascript1.3", b"text/javascript1.4", b"text/javascript1.5",
    b"text/jscript", b"text/livescript", b"text/x-ecmascript",
    b"text/x-javascript",
})
_DLP_ARCHIVE_SUFFIXES = (
    b".zip", b".jar", b".war", b".ear", b".apk", b".ipa", b".whl",
    b".docx", b".xlsx", b".pptx", b".odt", b".ods", b".odp",
    b".tar", b".tgz", b".gz", b".bz2", b".xz", b".7z", b".rar", b".cab",
)


def _dlp_archive_filename(value: bytes) -> bool:
    """Recognize an opaque download even when its Content-Type is misleading."""
    # Split only outside quoted strings. A quoted semicolon is part of a
    # filename, not a second parameter. The complete HTTP head is capped.
    parts, start, quoted, escaped = [], 0, False, False
    for index, ch in enumerate(value):
        if escaped:
            escaped = False
        elif quoted and ch == 92:
            escaped = True
        elif ch == 34:
            quoted = not quoted
        elif ch == 59 and not quoted:
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    for part in parts[1:]:
        name, sep, raw = part.partition(b"=")
        name = name.strip().lower()
        if not sep or name not in (b"filename", b"filename*"):
            continue
        raw = raw.strip()
        if len(raw) >= 2 and raw.startswith(b'"') and raw.endswith(b'"'):
            raw = re.sub(rb"\\(.)", rb"\1", raw[1:-1])
        if name == b"filename*":
            encoded = raw.split(b"'", 2)
            if len(encoded) == 3:
                raw = encoded[2]
        raw = unquote_to_bytes(raw).rstrip(b" .\t").lower()
        if raw.endswith(_DLP_ARCHIVE_SUFFIXES):
            return True
    return False


def _dlp_media_problem(head: bytes) -> str:
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.lower() == b"content-disposition":
            if _dlp_archive_filename(value):
                return "archive-media"
        if sep and name.lower() == b"content-type":
            media = value.split(b";", 1)[0].strip().lower()
            # Executable JS and CSS escapes/concatenation can construct a
            # secret that no bounded static byte scanner can equate with the
            # runtime value. Decide before publishing even the response head.
            if media in _DLP_JS_MEDIA:
                return "js-media"
            if media == b"text/css":
                return "css-media"
            # Multipart parts can carry their own encoding, or reconstruct a
            # single entity from byte ranges. Raw scanning is not that view.
            if media.startswith(b"multipart/"):
                return "multipart-media"
            if (media in _DLP_ARCHIVE_MEDIA
                    or media.startswith(b"application/vnd.openxmlformats-officedocument.")
                    or media.startswith(b"application/vnd.oasis.opendocument.")):
                return "archive-media"
    return ""


def _dlp_archive_magic(prefix: bytes) -> bool:
    return (prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",
                               b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00",
                               b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07\x00",
                               b"Rar!\x1a\x07\x01\x00", b"MSCF"))
            or (len(prefix) >= _DLP_ARCHIVE_PROBE and prefix[257:262] == b"ustar"))


def _dlp_wide_text_prefix(prefix: bytes) -> bool:
    """Recognize unlabelled UTF-16/32 text without adding another decoder."""
    if len(prefix) < 4:
        return False
    a, b, c, d = prefix[:4]
    starters = b'{["< \t\r\n'
    return ((a in starters and b == 0 and d == 0)  # UTF-16LE or UTF-32LE
            or (a == 0 and b in starters and c == 0)  # UTF-16BE
            or (a == b == c == 0 and d in starters))


# Three printable ASCII code points in an unlabelled UTF-16/32 stream are
# enough to identify a wide view that the raw-byte secret scanner cannot read.
# Scan every body chunk, not just the first archive-probe bytes: a non-ASCII
# title or long padding can precede the credential. The longest pattern is
# 12 bytes, so an 11-byte carry covers every transport/chunk boundary.
_DLP_WIDE_RUN = re.compile(
    rb"(?:[\x20-\x7e]\x00){3}|(?:\x00[\x20-\x7e]){3}|"
    rb"(?:[\x20-\x7e]\x00\x00\x00){3}|(?:\x00\x00\x00[\x20-\x7e]){3}")


def _response_head_problem(head: bytes, *, protected_connection_fields=()) -> str:
    """Reject ambiguous HTTP response syntax independently of optional defenses."""
    lines = head.split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e\x80-\xff]*)?", lines[0]):
        return "response-head"
    content_types = []
    content_lengths, transfers, connections = [], [], []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if (not sep or not _RESPONSE_HEADER_NAME.fullmatch(name)
                or any(c < 32 and c != 9 or c in (127, 0x85, 0xA0)
                       for c in value)):
            return "response-head"
        if name.lower() == b"content-type":
            content_types.append(value)
        elif name.lower() == b"content-length":
            content_lengths.append(value.strip(b" \t"))
        elif name.lower() == b"transfer-encoding":
            transfers.append(value.strip(b" \t").lower())
        elif name.lower() in (b"connection", b"proxy-connection"):
            connections.append(value.strip(b" \t"))
    for value in connections:
        for token in value.split(b","):
            token = token.strip(b" \t").lower()
            if not _RESPONSE_HEADER_NAME.fullmatch(token):
                return "response-head"
            if token in (b"content-length", b"transfer-encoding",
                         b"content-encoding", b"content-type"):
                return "response-framing"
            if (token in _RESPONSE_CONNECTION_PROTECTED
                    or token in protected_connection_fields):
                # A downstream intermediary removes every field nominated by
                # Connection. It must not remove a cache/security field that
                # this edge stripped, inspected, or injected on the same head.
                return "response-control"
    # These statuses end at the header boundary. Advertising a different body
    # boundary is invalid even when the advertised length is zero (RFC 9110
    # 8.6 / RFC 9112 6.1), and must not change the next head into raw body data.
    status = _resp_status(lines[0])
    if (content_lengths or transfers) and (100 <= status < 200 or status == 204):
        return "response-framing"
    if len(content_lengths) > 1 or len(transfers) > 1 or (content_lengths and transfers):
        return "response-framing"
    if content_lengths:
        raw = content_lengths[0]
        if not re.fullmatch(rb"[0-9]{1,19}", raw) or int(raw) > (1 << 63) - 1:
            return "response-framing"
    if transfers and (not lines[0].startswith(b"HTTP/1.1 ")
                      or transfers[0] != b"chunked"):
        return "response-framing"
    if len(content_types) > 1:
        return "content-type"
    return ""


def _dlp_head_problem(head: bytes, *, bodyless=False) -> str:
    """DLP representation checks follow the mandatory HTTP syntax boundary."""
    problem = _response_head_problem(head)
    if problem:
        return problem
    lines = head.split(b"\r\n")
    status = _resp_status(lines[0])
    content_types, content_lengths = [], []
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"content-type":
            content_types.append(value)
        elif name.lower() == b"content-length":
            content_lengths.append(value.strip(b" \t"))
    # Only after the framing fields were validated can an empty entity (or a
    # normal informational response) ignore representation charset metadata.
    if _is_interim(status) or (content_lengths and int(content_lengths[0]) == 0):
        bodyless = True
    for value in (() if bodyless else content_types):
        charsets = []
        for param in value.split(b";")[1:]:
            name, sep, raw = param.partition(b"=")
            if name.strip().lower() == b"charset":
                if not sep:
                    return "charset"
                charset = raw.strip().strip(b'"').lower()
                if not charset:
                    return "charset"
                charsets.append(charset)
        if len(charsets) > 1 or any(c not in _DLP_ASCII_CHARSETS for c in charsets):
            return "charset"
    return ""


def _dlp_decoded_url_head_values(head: bytes) -> bytes:
    """One browser URL-decoding view of response-header URI targets.

    A Location/Refresh/Link URI may carry ``gh%70_...`` while the raw head
    has no contiguous token. The complete response head is already capped at
    64 KiB; select only URI targets and separate them before scanning so
    unrelated header syntax cannot fabricate a token.
    """
    targets = []
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        name = name.lower()
        if name in (b"location", b"content-location"):
            candidates = (value.strip(b" \t"),)
        elif name == b"refresh":
            target = _refresh_target(value.decode("latin-1"))
            candidates = (target.encode("latin-1"),) if target else ()
        elif name == b"link":
            candidates = (match.group(1) for match in re.finditer(rb"<([^<>]*)>", value))
        else:
            continue
        targets.extend(unquote_to_bytes(target) for target in candidates if b"%" in target)
    return b"\x00".join(targets)


def _dlp_filename_head_values(head: bytes) -> tuple[bytes, bool]:
    """RFC 2231 filename* and continuations as a bounded download-name view.

    All candidate bytes come from the already-capped response head. Duplicate,
    incomplete, or unsupported extended parameters have no single recipient
    interpretation; block mode must not call that a clean scan.
    """
    views, bad, seen = [], False, False
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if not sep or name.lower() != b"content-disposition":
            continue
        if seen:
            bad = True
        seen = True
        parts, start, quoted, escaped = [], 0, False, False
        for index, ch in enumerate(value):
            if escaped:
                escaped = False
            elif quoted and ch == 92:
                escaped = True
            elif ch == 34:
                quoted = not quoted
            elif ch == 59 and not quoted:
                parts.append(value[start:index])
                start = index + 1
        parts.append(value[start:])
        if quoted:
            bad = True
        segments, direct, plain = {}, False, False
        for part in parts[1:]:
            key, equal, raw = part.partition(b"=")
            key, raw = key.strip().lower(), raw.strip()
            if not equal or (key != b"filename" and not key.startswith(b"filename*")):
                continue
            if len(raw) >= 2 and raw.startswith(b'"') and raw.endswith(b'"'):
                raw = re.sub(rb"\\(.)", rb"\1", raw[1:-1])
            elif b'"' in raw:
                bad = True
                continue
            if key == b"filename":
                if plain:
                    bad = True
                plain = True
                # RFC 6266 documents recipients that unescape quoted-pairs
                # and even legacy recipients that percent-decode filename.
                # Scan that conservative recipient view as well as raw head.
                decoded = unquote_to_bytes(raw)
                if b"=?" in decoded and b"?=" in decoded:
                    # Legacy RFC 2047 encoded-word decoding is not a single
                    # byte view across recipients. Do not call it clean.
                    bad = True
                views.append(decoded)
                continue
            if key == b"filename*":
                if direct:
                    bad = True
                direct = True
                pieces = raw.split(b"'", 2)
                if len(pieces) != 3 or pieces[0].lower() not in _DLP_ASCII_CHARSETS:
                    bad = True
                else:
                    decoded = unquote_to_bytes(pieces[2])
                    if b"=?" in decoded and b"?=" in decoded:
                        bad = True
                    views.append(decoded)
                continue
            match = re.fullmatch(rb"filename\*([0-9]{1,3})(\*)?", key)
            if not match:
                bad = True
                continue
            number = int(match.group(1))
            if number >= 64 or number in segments:
                bad = True
                continue
            segments[number] = (raw, bool(match.group(2)))
        if segments:
            if direct or set(segments) != set(range(len(segments))):
                bad = True
                continue
            joined = bytearray()
            for number in range(len(segments)):
                raw, encoded = segments[number]
                if number == 0 and encoded:
                    pieces = raw.split(b"'", 2)
                    if len(pieces) != 3 or pieces[0].lower() not in _DLP_ASCII_CHARSETS:
                        bad = True
                        break
                    raw = pieces[2]
                joined.extend(unquote_to_bytes(raw) if encoded else raw)
            if b"=?" in joined and b"?=" in joined:
                bad = True
            if not bad:
                views.append(bytes(joined))
    return b"\x00".join(views), bad


class _ResponseEnd:
    """One existing HTTP response boundary, without waiting for TCP EOF."""
    __slots__ = ("remaining", "tracker", "known", "done", "bad")

    def __init__(self, head, method="", forbidden_response_fields=()):
        self.remaining, self.tracker = None, None
        self.known = self.done = self.bad = False
        lines = head.split(b"\r\n")
        status = _resp_status(lines[0])
        if status == 101:
            return
        if method == "HEAD" or status in (204, 304):
            self.remaining, self.known, self.done = 0, True, True
            return
        lengths, transfers = [], []
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep:
                continue
            if name.lower() == b"content-length":
                lengths.append(value.strip(b" \t"))
            elif name.lower() == b"transfer-encoding":
                transfers.append(value.strip(b" \t").lower())
        if transfers == [b"chunked"] and not lengths:
            self.tracker, self.known = _ChunkedEnd(
                response_trailers=True,
                forbidden_response_fields=forbidden_response_fields), True
        elif not transfers and len(lengths) == 1 and re.fullmatch(rb"[0-9]{1,19}", lengths[0]):
            self.remaining, self.known = int(lengths[0]), True
            self.done = self.remaining == 0

    def feed(self, data):
        if self.tracker is not None:
            used = self.tracker.feed(data)
            self.done, self.bad = self.tracker.done, self.tracker.bad
            return used
        if self.remaining is not None:
            used = min(len(data), self.remaining)
            self.remaining -= used
            self.done = self.remaining == 0
            return used
        return len(data)


def _dlp_json_type(head: bytes) -> bool:
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.lower() == b"content-type":
            media = value.split(b";", 1)[0].strip().lower()
            return (media == b"application/json" or media.endswith(b"+json")
                    or media in (b"application/x-ndjson", b"application/json-seq"))
    return False


def _dlp_markup_media(head: bytes) -> bytes:
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.lower() == b"content-type":
            media = value.split(b";", 1)[0].strip().lower()
            if (media in (b"text/html", b"application/xhtml+xml", b"application/xml",
                          b"text/xml") or media.endswith(b"+xml")):
                return media
            return b""
    return b""


class _HtmlDlpText:
    """One-pass HTML character-reference view with a bounded split entity."""
    __slots__ = ("pending", "bad")

    def __init__(self):
        self.pending = b""
        self.bad = False

    def feed(self, data: bytes, *, final: bool = False) -> bytes:
        raw = self.pending + data
        self.pending = b""
        # Bound a complete reference as well as a split one. Otherwise an
        # attacker could place a very long numeric reference in one packet,
        # stretch a decoded token past the held wire window, and release its
        # encoded prefix before the next packet completes the secret.
        at = raw.find(b"&")
        while at >= 0:
            end = at + 1
            while end < len(raw) and raw[end] in _DLP_HTML_ENTITY_CHARS:
                end += 1
                limit = (_DLP_HTML_ASCII_ENTITY_MAX if raw[at + 1:at + 2] == b"#"
                         else _DLP_HTML_ENTITY_MAX)
                if end - at > limit:
                    self.bad = True
                    return b""
            terminated = end < len(raw)
            if terminated and raw[end] == 59:
                end += 1
            entity = raw[at:end]
            if len(entity) > _DLP_HTML_ENTITY_MAX:
                self.bad = True
                return b""
            if (terminated and len(entity) > _DLP_HTML_ASCII_ENTITY_MAX
                    and entity[1:2] != b"#"):
                decoded = html_lib.unescape(entity.decode("ascii"))
                if decoded != entity.decode("ascii") and any(ord(ch) < 128 for ch in decoded):
                    self.bad = True
                    return b""
            at = raw.find(b"&", end)
        if not final:
            at = raw.rfind(b"&")
            if at >= 0:
                suffix = raw[at:]
                if b";" not in suffix and _DLP_HTML_TAIL.fullmatch(suffix):
                    if len(suffix) > _DLP_HTML_ENTITY_MAX:
                        self.bad = True
                        return b""
                    self.pending, raw = suffix, raw[:at]
        if b"&" not in raw:
            return raw
        try:
            return html_lib.unescape(raw.decode("latin-1")).encode("utf-8")
        except (UnicodeError, ValueError):
            self.bad = True
            return b""


def _dlp_markup_uri_target(name: str, value: str, *, refresh=False) -> str:
    if not value:
        return ""
    if name in _DLP_MARKUP_URI_ATTRS:
        return value
    if refresh and name == "content":
        return _refresh_target(value)
    return ""


def _dlp_markup_attr_unscannable(name: str, value: str, *, refresh=False) -> bool:
    local_name = name.rsplit(":", 1)[-1]
    if local_name in ("srcdoc", "style") or local_name.startswith("on"):
        return True
    target = _dlp_markup_uri_target(name, value, refresh=refresh)
    if not target:
        return False
    # URL parsers remove ASCII TAB/LF/CR and trim surrounding ASCII space.
    # Apply that view before selecting nested data documents or script URLs.
    target = target.translate({9: None, 10: None, 13: None}).strip(" \t\r\n\f\v").lower()
    candidates = (target.split(",") if name in _DLP_MARKUP_URI_LIST_ATTRS else (target,))
    if name == "ping":
        candidates = [part for group in candidates for part in group.split()]
    return any(part.lstrip(" \t\r\n\f\v").startswith(("data:", "javascript:"))
               for part in candidates)


class _HtmlDlpDom(HTMLParser):
    """Scan browser-visible textContent across tags and decoded attributes.

    HTMLParser emits data in pieces. Keep only a DLP look-behind, so a long
    document with many short tags cannot grow parser-side text state.
    """
    __slots__ = ("sh", "carry", "cst", "kinds", "bad")

    def __init__(self, sh):
        super().__init__(convert_charrefs=True)
        self.sh, self.carry, self.cst, self.kinds, self.bad = sh, b"", 0, None, False

    def handle_data(self, data):
        if self.kinds or not data:
            return
        seg = self.carry + data.encode("utf-8")
        lim = max(self.cst, len(seg) - _DLP_LOOK)
        self.kinds = self.sh.scan_leak(seg, self.cst, lim) if lim > self.cst else None
        keep = max(0, lim - 1)
        self.carry, self.cst = seg[keep:], lim - keep

    def handle_starttag(self, tag, attrs):
        if len(self.get_starttag_text()) > _DLP_HTML_PARSE_TAIL_MAX:
            self.bad = True
            return
        if tag in ("script", "style"):
            self.bad = True
            return
        if self.kinds:
            return
        refresh = (tag == "meta" and any(name == "http-equiv" and value and
                   value.strip().lower() == "refresh" for name, value in attrs))
        for name, value in attrs:
            if _dlp_markup_attr_unscannable(name, value, refresh=refresh):
                # srcdoc and data URLs create nested documents. Inline JS/CSS
                # can construct secrets after this static scan. Reject the
                # active interpretation before releasing any held body bytes.
                self.bad = True
                return
            if value:
                self.kinds = self.sh.scan_leak(value.encode("utf-8"))
                if not self.kinds:
                    target = _dlp_markup_uri_target(name, value, refresh=refresh)
                    if target and "%" in target:
                        self.kinds = self.sh.scan_leak(unquote_to_bytes(target))
                if self.kinds:
                    break

    handle_startendtag = handle_starttag

    def finish(self):
        self.close()
        if self.kinds:
            return self.kinds
        return self.sh.scan_leak(self.carry, self.cst) if self.cst < len(self.carry) else None


class _UnsafeXhtml(ValueError):
    pass


class _XhtmlDlpDom:
    """Expat's XML text/attribute view, with DTD and transforms disabled.

    HTMLParser skips XML CDATA and custom entities and therefore cannot be
    used for application/xhtml+xml. Expat's character callbacks join CDATA
    and text nodes as an XML DOM would. Doctype/PI semantics are not an
    equivalent static representation, so reject them before any expansion.
    """
    __slots__ = ("sh", "parser", "carry", "cst", "kinds", "bad", "total",
                 "active_markup")

    def __init__(self, sh, *, active_markup=False):
        self.sh, self.carry, self.cst, self.kinds = sh, b"", 0, None
        self.bad, self.total, self.active_markup = False, 0, active_markup
        parser = expat.ParserCreate()
        parser.CharacterDataHandler = self._data
        parser.StartElementHandler = self._start
        parser.StartDoctypeDeclHandler = self._reject
        parser.ProcessingInstructionHandler = self._reject
        parser.ExternalEntityRefHandler = self._reject
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        self.parser = parser

    @staticmethod
    def _reject(*_):
        raise _UnsafeXhtml("XHTML DTD, external entity, or transform")

    def _data(self, data):
        if self.kinds or not data:
            return
        seg = self.carry + data.encode("utf-8")
        lim = max(self.cst, len(seg) - _DLP_LOOK)
        self.kinds = self.sh.scan_leak(seg, self.cst, lim) if lim > self.cst else None
        keep = max(0, lim - 1)
        self.carry, self.cst = seg[keep:], lim - keep

    def _start(self, tag, attrs):
        if self.active_markup and tag.rsplit(":", 1)[-1].lower() in ("script", "style"):
            raise _UnsafeXhtml("inline script or style")
        if self.kinds:
            return
        refresh = (self.active_markup and tag.rsplit(":", 1)[-1].lower() == "meta"
                   and any(name.lower() == "http-equiv" and value.strip().lower() == "refresh"
                           for name, value in attrs.items()))
        for name, value in attrs.items():
            lower_name = name.lower()
            if self.active_markup and _dlp_markup_attr_unscannable(
                    lower_name, value, refresh=refresh):
                raise _UnsafeXhtml("nested document or inline style")
            self.kinds = self.sh.scan_leak(value.encode("utf-8"))
            if not self.kinds and self.active_markup:
                target = _dlp_markup_uri_target(lower_name, value, refresh=refresh)
                if target and "%" in target:
                    self.kinds = self.sh.scan_leak(unquote_to_bytes(target))
            if self.kinds:
                break

    def feed(self, data: bytes):
        self.total += len(data)
        self.parser.Parse(data, False)
        if self.total - self.parser.CurrentByteIndex > _DLP_HTML_PARSE_TAIL_MAX:
            self.bad = True

    def finish(self):
        self.parser.Parse(b"", True)
        if self.kinds:
            return self.kinds
        return self.sh.scan_leak(self.carry, self.cst) if self.cst < len(self.carry) else None


class _JsonDlpText:
    """JSON 文字列を 1 pass で復号した走査面。フィールド値は保存しない。"""
    __slots__ = ("in_string", "escape", "hexdigits", "bad")

    def __init__(self):
        self.in_string = False
        self.escape = False
        self.hexdigits = None
        self.bad = False

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        escapes = {34: 34, 92: 92, 47: 47, 98: 8, 102: 12,
                   110: 10, 114: 13, 116: 9}
        for c in data:
            if self.hexdigits is not None:
                if c not in b"0123456789abcdefABCDEF":
                    self.bad = True
                    break
                self.hexdigits.append(c)
                if len(self.hexdigits) == 4:
                    codepoint = int(self.hexdigits, 16)
                    out.append(codepoint if codepoint <= 0x7f else 0)
                    self.hexdigits = None
            elif self.escape:
                self.escape = False
                if c == 117:                 # JSON \uXXXX
                    self.hexdigits = bytearray()
                elif c in escapes:
                    out.append(escapes[c])
                else:
                    self.bad = True
                    break
            elif self.in_string:
                if c == 34:
                    self.in_string = False
                    out.append(0)            # 別 JSON 文字列へ token を連結しない
                elif c == 92:
                    self.escape = True
                elif c < 32:
                    self.bad = True
                    break
                else:
                    out.append(c)
            elif c == 34:
                self.in_string = True
                out.append(0)
        return bytes(out)


class _DlpStream:
    """出口 DLP の応答本文走査(1 応答ぶんの状態)。feed(chunk) は (今送ってよいバイト, 停止) を返す。
    · 走査面: chunked なら枠を外した本文(#47)、それ以外は受けたバイトそのもの。
    · 窓走査: 直前の走査の末尾(未判定 _DLP_LOOK B+左文脈 1B)を重ねて次の読取と合わせて判定する。
      読取の切れ目を語境界とみなさない=判定がパケット分割に依存しない(#48)。EOF で残りを判定。
    · 保留: block は未判定の末尾に当たる wire バイトを次の読取か EOF まで送らない。
      HTML はタグをまたぐ textContent のため応答完了まで有界に保留する。
      audit は保留しない。SSE の block でも未判定の秘密を放出しない。
    · 解けない符号化(gzip/br 等)の本文は走査できない=dlp_unscannable として dlp_action どおり(#1)。
    · budget(dlp_max_scan_bytes)を超える応答は未検査として扱う。block は切断し、audit は記録して通す。"""
    __slots__ = ("sh", "ip", "budget", "hold", "dech", "bad", "carry", "cst",
                 "raw_carry", "raw_cst", "pending", "pruns", "active", "look",
                 "json_text", "json_carry", "json_cst", "json_strict", "json_sniffed",
                 "json_probe", "body_prefix", "archive_probe_done", "zip_tail",
                 "wide_tail",
                 "html_text", "html_carry", "html_cst", "html_dom", "html_xml", "html_wire",
                 "html_reserved", "html_pid", "html_deadline")

    def __init__(self, sh, ip, budget):
        self.sh, self.ip, self.budget = sh, ip, budget
        self.hold = sh.dlp_effective_action() == "block"
        self.dech, self.bad = None, ""
        self.carry, self.cst = b"", 0     # 走査済み本文の末尾と、その中で未判定の開始位置
        self.raw_carry, self.raw_cst = b"", 0  # chunk 枠/拡張行も wire として走査
        self.pending, self.pruns = b"", []   # 保留中の wire と、その中の本文範囲
        self.active = True
        self.look = _DLP_ARCHIVE_PROBE
        self.json_text, self.json_carry, self.json_cst = None, b"", 0
        self.json_strict, self.json_sniffed = False, False
        self.json_probe = b""
        self.body_prefix = b""
        self.archive_probe_done = False
        self.zip_tail = b""
        self.wide_tail = b""
        self.html_text, self.html_carry, self.html_cst = None, b"", 0
        self.html_dom, self.html_xml, self.html_wire = None, False, None
        self.html_reserved, self.html_pid, self.html_deadline = 0, os.getpid(), None

    def head(self, head: bytes):
        chunked, self.bad = _dlp_body_mode(head)
        self.dech = _Dechunk() if chunked else None
        if _dlp_json_type(head):
            self.json_text = _JsonDlpText()
            self.look = _DLP_JSON_LOOK
            self.json_strict = self.json_sniffed = True
        markup_media = _dlp_markup_media(head)
        if markup_media:
            self.html_text = _HtmlDlpText()
            self.html_xml = markup_media != b"text/html"
            self.html_dom = (_XhtmlDlpDom(
                self.sh, active_markup=markup_media in
                (b"application/xhtml+xml", b"image/svg+xml")) if self.html_xml
                             else _HtmlDlpDom(self.sh))
            self.html_deadline = time.monotonic() + _DLP_HTML_RESPONSE_SEC
            if self.hold:
                self.html_wire = bytearray()

    def close(self):
        """Release the process-wide HTML wire reservation on every exit path."""
        reserved, self.html_reserved = self.html_reserved, 0
        if reserved and self.html_pid == os.getpid():
            _dlp_html_release(reserved)
        if self.html_wire is not None:
            self.html_wire.clear()

    def release(self) -> bytes:
        """終端で判定した後に送るため、保留分を取り出す。"""
        if self.html_wire is not None:
            # Keep the global reservation until the caller has drained the
            # client write. A bytes copy followed by early release would let
            # many slow readers retain unaccounted response bodies.
            out, self.html_wire = self.html_wire, None
            return out
        out, self.pending, self.pruns = self.pending, b"", []
        return out

    def _stop(self, action, wire):
        self.active, self.pending, self.pruns = False, b"", []
        if action == "block":
            self.close()
            return b"", True              # 保留分(秘密の頭になり得る)も送らず切断
        if self.html_wire is not None:
            wire, self.html_wire = (self.html_wire, wire), None
        if not self.html_reserved:
            self.close()
        return wire, False                # audit: 記録して走査停止。保留分も含め流す

    def feed(self, chunk: bytes):
        # A hard scan budget is a containment boundary. Do not release an unchecked
        # suffix (or scan beyond the budget) when enforcement is active.
        if self.html_deadline is not None and time.monotonic() >= self.html_deadline:
            return self._stop(self.sh.note_unscannable(self.ip, "html-timeout")
                              .get("action"), chunk)
        if len(chunk) > self.budget:
            wire = self.pending + chunk if self.pending else chunk
            return self._stop(self.sh.note_unscannable(self.ip, "scan-budget").get("action"), wire)
        if self.dech is not None:
            runs = self.dech.feed(chunk)
            pay = chunk if runs == [(0, len(chunk))] else b"".join(chunk[s:e] for s, e in runs)
        else:
            runs, pay = [(0, len(chunk))], chunk
        wire = self.pending + chunk if self.pending else chunk
        if self.dech is not None:
            # Chunk-size/extension は復号後本文には含まれないが wire には載る。
            # 生の応答を読む相手へ秘密を先に出さないよう別窓で検査する。
            rawseg = self.raw_carry + chunk
            rawlim = max(self.raw_cst, len(rawseg) - _DLP_LOOK)
            kinds = self.sh.scan_leak(rawseg, self.raw_cst, rawlim) if rawlim > self.raw_cst else None
            if kinds:
                return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
            rawk = max(0, rawlim - 1)
            self.raw_carry, self.raw_cst = rawseg[rawk:], rawlim - rawk
        if self.bad and pay:
            return self._stop(self.sh.note_unscannable(self.ip, self.bad).get("action"), wire)
        if pay:
            wide = self.wide_tail + pay
            if b"\x00" in wide and _DLP_WIDE_RUN.search(wide):
                return self._stop(self.sh.note_unscannable(self.ip, "unicode-wide")
                                  .get("action"), wire)
            self.wide_tail = wide[-11:]
        if pay:
            # ZIP readers find the central directory from the end and accept
            # arbitrary leading bytes (self-extracting ZIPs). A fixed magic
            # check at byte zero or in the first 262 bytes misses that view.
            if (b"PK\x03\x04" in pay or
                    (self.zip_tail and b"PK\x03\x04" in self.zip_tail + pay[:3])):
                return self._stop(self.sh.note_unscannable(self.ip, "archive-magic")
                                  .get("action"), wire)
            self.zip_tail = (pay[-3:] if len(pay) >= 3 else
                             (self.zip_tail + pay)[-3:])
        if pay and not self.archive_probe_done:
            self.body_prefix = (self.body_prefix + pay)[:_DLP_ARCHIVE_PROBE]
            bom = (self.body_prefix.startswith((b"\xff\xfe", b"\xfe\xff"))
                   or self.body_prefix.startswith(b"\x00\x00\xfe\xff"))
            if bom or _dlp_wide_text_prefix(self.body_prefix):
                return self._stop(self.sh.note_unscannable(
                                      self.ip, "unicode-bom" if bom else "unicode-prefix")
                                  .get("action"), wire)
            if _dlp_archive_magic(self.body_prefix):
                return self._stop(self.sh.note_unscannable(self.ip, "archive-magic")
                                  .get("action"), wire)
            if len(self.body_prefix) >= _DLP_ARCHIVE_PROBE:
                self.archive_probe_done = True
                if self.json_text is None:
                    self.look = _DLP_LOOK
        if pay and not self.json_sniffed:
            probe = (self.json_probe + pay).lstrip(b" \t\r\n")
            if b"\xef\xbb\xbf".startswith(probe) and len(probe) < 3:
                self.json_probe = probe     # split UTF-8 BOM (最大 2 B)
                probe = b""
            elif probe.startswith(b"\xef\xbb\xbf"):
                probe = probe[3:].lstrip(b" \t\r\n")
                self.json_probe = b""
            first = probe[:1]
            if first:
                self.json_sniffed = True
                self.json_probe = b""
                if first in (b"{", b"[", b'"'):
                    # Content-Type 欠落/偽装でも JSON.parse が読む形は限定的に検査する。
                    # SSE/通常の raw stream は従来の短い保留窓を保つ。
                    self.json_text = _JsonDlpText()
                    self.look = _DLP_JSON_LOOK
        if self.json_text is not None and pay:
            decoded = self.json_text.feed(pay)
            jseg = self.json_carry + decoded
            if self.json_text.bad:
                if self.json_strict:
                    return self._stop(self.sh.note_unscannable(self.ip, "json-escape")
                                      .get("action"), wire)
                # A later malformed string does not erase earlier, completely
                # decoded strings. Only inspect through a known string boundary;
                # an unfinished suffix is not an artificial token boundary.
                complete = jseg.rfind(b"\x00") + 1
                kinds = (self.sh.scan_leak(jseg, self.json_cst, complete)
                         if complete > self.json_cst else None)
                if kinds:
                    return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
                self.json_text, self.json_carry, self.json_cst = None, b"", 0
                self.look = (_DLP_LOOK if self.archive_probe_done else _DLP_ARCHIVE_PROBE)
                # sniffed non-JSON は raw stream へ戻す(archive判定中はまだ保留)
            else:
                jlim = max(self.json_cst, len(jseg) - _DLP_LOOK)
                jkinds = self.sh.scan_leak(jseg, self.json_cst, jlim) if jlim > self.json_cst else None
                if jkinds:
                    return self._stop(self.sh.note_leak(self.ip, jkinds).get("action"), wire)
                jk = max(0, jlim - 1)
                self.json_carry, self.json_cst = jseg[jk:], jlim - jk
        if self.html_text is not None and pay:
            decoded = self.html_text.feed(pay)
            if self.html_text.bad:
                return self._stop(self.sh.note_unscannable(self.ip, "html-entity")
                                  .get("action"), wire)
            hseg = self.html_carry + decoded
            hlim = max(self.html_cst, len(hseg) - _DLP_LOOK)
            hkinds = (self.sh.scan_leak(hseg, self.html_cst, hlim)
                      if hlim > self.html_cst else None)
            if hkinds:
                return self._stop(self.sh.note_leak(self.ip, hkinds).get("action"), wire)
            hk = max(0, hlim - 1)
            self.html_carry, self.html_cst = hseg[hk:], hlim - hk
            try:
                self.html_dom.feed(pay if self.html_xml else pay.decode("latin-1"))
            except (UnicodeError, ValueError, AssertionError, expat.ExpatError):
                return self._stop(self.sh.note_unscannable(self.ip, "html-parse")
                                  .get("action"), wire)
            if (self.html_dom.bad or (not self.html_xml and
                    len(self.html_dom.rawdata) > _DLP_HTML_PARSE_TAIL_MAX)):
                return self._stop(self.sh.note_unscannable(self.ip, "html-parse")
                                  .get("action"), wire)
            if self.html_dom.kinds:
                return self._stop(self.sh.note_leak(self.ip, self.html_dom.kinds)
                                  .get("action"), wire)
        self.budget -= len(chunk)
        seg = self.carry + pay
        lim = max(self.cst, len(seg) - self.look)
        kinds = self.sh.scan_leak(seg, self.cst, lim) if lim > self.cst else None
        if kinds:
            return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
        k = max(0, lim - 1)
        self.carry, self.cst = seg[k:], lim - k
        if not self.hold:
            return wire, False
        if self.html_wire is not None:
            if not _dlp_html_reserve(len(chunk)):
                return self._stop(self.sh.note_unscannable(self.ip, "html-memory")
                                  .get("action"), wire)
            self.html_reserved += len(chunk)
            self.html_wire.extend(chunk)
            return b"", False
        # 未判定の本文(seg[lim:])を含む wire の末尾を保留する(枠の中でも本文位置で切る)
        base = len(wire) - len(chunk)
        allr = self.pruns + [(s + base, e + base) for s, e in runs]
        u, cut = len(seg) - lim, len(wire)
        if u:
            cut = 0                       # 既に放出済みの未判定がある=wire 内の本文は全部保留
            for s, e in reversed(allr):
                if u <= e - s:
                    cut = e - u
                    break
                u -= e - s
        if self.dech is not None:
            cut = min(cut, max(0, len(wire) - self.look))
            if not self.archive_probe_done:
                cut = 0             # 枠の拡張行も本文形式が分かるまで先送りしない
            if self.dech._st != "raw" and self.dech._line:
                cut = 0                   # 分割された chunk 行は終端まで送らない
        if self.html_text is not None:
            # Keep the encoded wire for every decoded DLP look-behind byte.
            # Each pending reference is at most _DLP_HTML_ENTITY_MAX bytes;
            # an overlong reference is rejected before this hold can expire.
            cut = min(cut, max(0, len(wire) - _DLP_HTML_WIRE_LOOK))
        self.pending = wire[cut:]
        self.pruns = [(max(s, cut) - cut, e - cut) for s, e in allr if e > cut]
        return wire[:cut], False

    def eof(self):
        """EOF=本当の終端。未判定の末尾を、終端を境界として判定する(#48)。"""
        wire = self.release()
        if self.active and self.html_text is not None:
            decoded = self.html_text.feed(b"", final=True)
            if self.html_text.bad:
                return self._stop(self.sh.note_unscannable(self.ip, "html-entity")
                                  .get("action"), wire)
            hseg = self.html_carry + decoded
            if self.html_cst < len(hseg):
                kinds = self.sh.scan_leak(hseg, self.html_cst)
                if kinds:
                    return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
            try:
                kinds = self.html_dom.finish()
            except (UnicodeError, ValueError, AssertionError, expat.ExpatError):
                return self._stop(self.sh.note_unscannable(self.ip, "html-parse")
                                  .get("action"), wire)
            if (self.html_dom.bad or (not self.html_xml and
                    len(self.html_dom.rawdata) > _DLP_HTML_PARSE_TAIL_MAX)):
                return self._stop(self.sh.note_unscannable(self.ip, "html-parse")
                                  .get("action"), wire)
            if kinds:
                return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
        if self.active and self.json_text is not None:
            if (self.json_text.bad or self.json_text.escape or
                    self.json_text.hexdigits is not None or self.json_text.in_string):
                if self.json_strict:
                    return self._stop(self.sh.note_unscannable(self.ip, "json-escape")
                                      .get("action"), wire)
            if self.json_cst < len(self.json_carry):
                kinds = self.sh.scan_leak(self.json_carry, self.json_cst)
                if kinds:
                    return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
        if self.active and self.dech is not None and self.raw_cst < len(self.raw_carry):
            kinds = self.sh.scan_leak(self.raw_carry, self.raw_cst)
            if kinds:
                return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
        if self.active and self.cst < len(self.carry):
            kinds = self.sh.scan_leak(self.carry, self.cst)
            if kinds:
                return self._stop(self.sh.note_leak(self.ip, kinds).get("action"), wire)
        return wire, False


def _strip_request_headers(buf: bytes, names_lower) -> bytes:
    """転送リクエスト head から指定ヘッダ(小文字名の集合)を除去する(#75)。リクエストライン/
    body は保持。head 不完全は不変。キャッシュ汚染を招く unkeyed ヘッダ(X-Forwarded-Host 等)を
    信頼 proxy 経由でないときに落とす用途。"""
    head, sep, rest = buf.partition(b"\r\n\r\n")
    if not sep:
        return buf
    names = {(n.encode("latin1", "replace") if isinstance(n, str) else n)
             .lower().replace(b"_", b"-")
             for n in names_lower}                  # str/bytes 混在を bytes に正規化して比較
    lines = head.split(b"\r\n")
    kept = lines[:1]
    for ln in lines[1:]:
        k = ln.split(b":", 1)[0].strip().lower().replace(b"_", b"-")
        if k in names:
            continue
        kept.append(ln)
    return b"\r\n".join(kept) + b"\r\n\r\n" + rest


def _set_request_header(buf: bytes, name: str, value: str) -> bytes:
    """転送リクエスト head に1ヘッダを *差し替え設定* する(同名の既存は除去してから付与)。
    クライアント供給の偽装を許さず、エッジが付ける値だけを残す(#77 オリジントークン用)。"""
    head, sep, rest = buf.partition(b"\r\n\r\n")
    if not sep:
        return buf
    nl = name.strip().lower().encode("latin1", "replace").replace(b"_", b"-")
    kept = [ln for ln in head.split(b"\r\n")
            if ln.split(b":", 1)[0].strip().lower().replace(b"_", b"-") != nl]
            # CGI/WSGI が同一視する '_' と '-' の別名も除去する。
    kept.append(name.encode("latin1", "replace") + b": " + value.encode("latin1", "replace"))
    return b"\r\n".join(kept) + b"\r\n\r\n" + rest


def _header_value(buf: bytes, name_lower: bytes) -> str:
    """head から指定ヘッダ(小文字名)の値を返す(無ければ空)。

    同名ヘッダが複数回現れたら **出現順にカンマで連結** する(RFC 7230 §3.2.2:
    繰り返しヘッダは 1 本のカンマ区切りと等価)。
    以前は *最初の 1 本* しか読んでいなかった。クライアントが X-Forwarded-For を
    1 本置き、信頼 proxy が *追記* する構成(HAProxy の add-header / Apache の
    RequestHeader add / 多段 proxy)では、攻撃者が置いた側だけを読んでしまい
    **身元を完全に選べた** ―― 任意の第三者IPを BAN させることも、自分の BAN や
    レート制限を回避することもできた(実測: proxy が追記した本物の IP が無視された)。
    連結すれば _real_client_ip が右から辿るので、proxy が最後に足した本物が採れる。"""
    head = buf.split(b"\r\n\r\n", 1)[0]
    out = []
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(name_lower + b":"):
            out.append(ln[len(name_lower) + 1:].strip().decode("latin-1", "replace"))
    return ", ".join(out)


def _header_values(buf: bytes, name_lower: bytes) -> list:
    """head から指定ヘッダ(小文字名)の値を *出現ごとに* リストで返す(無ければ [])。
    _header_value の連結は XFF/XFP のようなリスト型ヘッダ用。Authorization / X-API-Key /
    メソッド override のような *単一値* フィールドを連結すると、検査するのは
    'Bearer a, Bearer b' という *どの backend も採らない値* になる(Node/Go は先頭の 1 本を採る)。
    実測: alg:none JWT を 2 本並べると JWT と認識されず素通りした(#16)。単一値フィールドは
    本関数で本数を確かめてから使う。名前は ':' 手前で切って正規化する(_strip_request_headers と同じ)。"""
    head = buf.split(b"\r\n\r\n", 1)[0]
    out = []
    for ln in head.split(b"\r\n")[1:]:
        k, sep, v = ln.partition(b":")
        if sep and k.strip().lower() == name_lower:
            out.append(v.strip().decode("latin-1", "replace"))
    return out


_MAX_XFF_HOPS = 16         # X-Forwarded-For を辿る最大ホップ数(実運用は数個)


def _real_client_ip(peer_ip: str, buf: bytes, trusted) -> str:
    """信頼 proxy 経由のときだけ X-Forwarded-For から実クライアントIPを解決する。
    peer が trusted CIDR に含まれない(=直結 or 未設定)なら **XFF を信頼しない**(偽装無効化)。
    含まれるなら XFF を右(最も近いhop)から辿り、trusted でない最初の妥当IP=実クライアント。
    採った候補は NetShield と同じ正規形(pipeline._canon_ip)で返す。"""
    if not trusted or not peer_ip:
        return peer_ip
    from ..lifeform.netutil import ip_in_any
    from ..lifeform.pipeline import _canon_ip
    if not ip_in_any(peer_ip, trusted):
        return peer_ip
    xff = _header_value(buf, b"x-forwarded-for")
    if not xff:
        return peer_ip
    # ホップ数を上限化しつつ、信頼 proxy が最後に追記した実クライアントを必ず残す。
    # 左から split して先頭を採ると、攻撃者が 16 個の値を先置きするだけで
    # 右端の実 IP が落ち、BAN/レート/転送 XFF が偽装値へ切り替わる。
    _hops = xff.rsplit(",", _MAX_XFF_HOPS)[-_MAX_XFF_HOPS:]
    for raw_cand in reversed(_hops):
        cand = raw_cand.strip()
        if not cand:
            return peer_ip
        # 妥当な単一IPのみ採用し、正規形(小文字/圧縮・IPv4-mapped は純IPv4)にしてから使う。
        # 生の綴りを返すと '2001:DB8::1' 等の別表記が BAN/リスト/状態の鍵(正規形)と一致せず、
        # BAN 済みクライアントが新顔として通った。信頼 hop の照合も正規形で行う(::ffff:10.0.0.9
        # も信頼側)。ゾーンID付き(fe80::1%eth0。任意文字を運べる)は捨てずにゾーンだけ外す:
        # 捨てて左へ進むと、信頼 proxy が付けた接続元の代わりに *クライアントが自分で書いた*
        # 値を採ってしまう(BAN 回避・なりすまし)。peer の _norm_ip と同じ扱い。
        c = _canon_ip(cand)
        if not c and "%" in cand:
            c = _canon_ip(cand.split("%", 1)[0])
        if not c:
            # Once a trusted hop is malformed, entries to its left may be
            # entirely client controlled. Do not promote one into an identity.
            return peer_ip
        if not ip_in_any(c, trusted):
            return c
    return peer_ip


def _set_forwarded_for(buf: bytes, client_ip: str) -> bytes:
    """転送リクエストの X-Forwarded-For / X-Real-IP を *解決済みの実クライアントIP* に置き換える
    (evolution #35)。クライアント申告の既存値は除去してから設定=バックエンドが偽装不能な客IPを
    得る(信頼 proxy 構成でのみ呼ぶ)。リクエストライン/body は保持。client_ip 空/head 不完全は不変。"""
    if not client_ip:
        return buf
    head, sep, rest = buf.partition(b"\r\n\r\n")
    if not sep:
        return buf
    cb = client_ip.encode("latin-1", "replace")
    lines = head.split(b"\r\n")
    kept = lines[:1]
    for ln in lines[1:]:
        # ヘッダ名を『:』手前で切って正規化してから照合(#D13)。旧 startswith(b"x-forwarded-for:")
        # は完全一致ゆえ "X-Forwarded-For : evil"(コロン前空白)が strip をすり抜け、エッジ付与の
        # XFF と並んで backend へ届いた。RFC7239 Forwarded も同時に破棄する(信頼 proxy 経路でも
        # クライアント申告を残さない)。他ヘッダハンドラ(_header_value 等)と同じ split 方式に統一。
        k = ln.split(b":", 1)[0].strip().lower()
        if k in (b"x-forwarded-for", b"x-real-ip", b"forwarded"):
            continue                                  # クライアント申告は破棄(偽装無効化)
        kept.append(ln)
    kept.append(b"X-Forwarded-For: " + cb)
    kept.append(b"X-Real-IP: " + cb)
    return b"\r\n".join(kept) + b"\r\n\r\n" + rest


def _forwarded_proto_tls(peer_ip: str, buf: bytes, trusted) -> bool:
    """X-Forwarded-Proto から『元接続が TLS だったか』を判定。*信頼 peer 経由の XFP のみ*
    信頼する(平文クライアントが https を偽装して require_tls を回避するのを封じる・#33)。
    trusted_proxies 未設定(既定)なら XFP は一切信じない=フェイルクローズ(#111。_real_client_ip
    の XFF と同じ既定方針に合わせた=trusted_proxies を設定しない限り、直結の平文クライアントが
    ヘッダ1本で「これはTLS経由」と偽装して require_tls 系ポリシーを回避できてはならない)。
    本機は TLS 終端しないため XFP が唯一の元プロトコル情報。"""
    if not trusted or not peer_ip:
        return False
    from ..lifeform.netutil import ip_in_any
    if not ip_in_any(peer_ip, trusted):
        return False
    # 実際の X-Forwarded-Proto ヘッダ *値* を解析する(head 内・ヘッダ名先頭一致)。
    # 旧実装は buf 全体の substring 照合で、body や別ヘッダ値に文字列 "x-forwarded-proto: https"
    # を仕込むだけで tls=True を偽装でき、信頼 proxy が正しく http をセットしても require_tls を
    # 回避できた(#forwarded-trust)。_real_client_ip の XFF 解析と同じく _header_value を使う。
    # **全ホップが https のときだけ** TLS とみなす。先頭だけを見ると、クライアントが
    # X-Forwarded-Proto を 1 本置き proxy が追記する構成で `https, http` となり、
    # 攻撃者の自己申告が勝って require_tls を回避できた(実測: 平文の直結クライアントが
    # 信頼 proxy 越しに TLS を騙れた)。値が食い違うとき「元は TLS だった」と決めつける
    # 根拠は無いので、フェイルクローズする(経路に平文ホップがあるなら require_tls は
    # 通すべきでない、とも言える)。proxy 側は set/replace 系のディレクティブを使い、
    # クライアント由来の値を残さない設定が正しい。
    parts = [p.strip().lower() for p in
             _header_value(buf, b"x-forwarded-proto").split(",") if p.strip()]
    return bool(parts) and all(p == "https" for p in parts)


# 解除リクエスト(異議申立)の受付パス。遮断中ユーザーでも到達できる(BAN判定の手前)。
_APPEAL_PATH = "/__ducknet_appeal__"


_CL_DIGITS = re.compile(rb"\A[0-9]+\Z")         # Content-Length は 1*DIGIT のみ(RFC 7230 §3.3.2)
_BARE_LF = re.compile(rb"(?<!\r)\n")            # CR を伴わない裸 LF(行終端の解釈が割れる)
_BARE_CR = re.compile(rb"\r(?!\n)")            # LF を伴わない裸 CR(同上・対称)
_BAD_REQUEST_LINE = re.compile(rb"[\x00-\x1f\x7f-\xff]")  # raw target は可視 ASCII のみ
_REQ_LINE = re.compile(rb"\A[A-Za-z]+ \S+ HTTP/1\.[01]\Z")  # METHOD SP target SP HTTP/1.x
_FIELD_NAME = re.compile(rb"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")  # RFC 9110 token
# Latin-1 NEL/NBSP (0x85/0xa0) become whitespace under an origin's str.strip().
# Byte-trimmed edge values otherwise split one route/credential into many views.
_BAD_FIELD_VALUE = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f\x85\xa0]")  # HTAB/他のobs-textは許容
_PROTECTED_REQUEST_OPTIONS = frozenset((
    b"host", b"content-length", b"transfer-encoding", b"content-encoding",
    b"content-type", b"content-disposition", b"authorization", b"cookie",
    b"user-agent", b"range", b"origin", b"referer", b"x-api-key",
    b"x-forwarded-for", b"x-real-ip", b"forwarded", b"x-forwarded-proto",
    b"x-forwarded-host", b"x-original-url", b"x-rewrite-url",
    # Keep every name consumed by _header_values() override policy here:
    # CGI/WSGI merges '-' and '_' before routing or method selection.
    b"x-override-url", b"x-http-method-override", b"x-method-override",
    b"x-http-method", b"accept-encoding",
    b"x-edge-token", b"connection", b"proxy-connection",
))
_HOST_REG_NAME = re.compile(rb"\A[A-Za-z0-9_.~-]+\Z")
_BOUNDARY_PARAM = re.compile(rb"(?:\A|[; \t])boundary[ \t]*=", re.I)
_BOUNDARY_EXT_PARAM = re.compile(rb"(?:\A|[; \t])boundary\*[^;= \t]*[ \t]*=", re.I)
_CHARSET_PARAM = re.compile(rb"(?:\A|[; \t])charset[ \t]*=", re.I)


def _valid_host_authority(raw: bytes) -> bool:
    """Host を単一の ASCII authority として読む。userinfo/曖昧なポートは拒否。"""
    value = raw.strip(b" \t")
    if not value or any(c < 33 or c > 126 for c in value):
        return False
    if value.startswith(b"["):
        host, close, suffix = value[1:].partition(b"]")
        if not close or b"%" in host:
            return False
        try:
            ipaddress.IPv6Address(host.decode("ascii"))
        except (ValueError, UnicodeError):
            return False
        if not suffix:
            return True
        if not suffix.startswith(b":"):
            return False
        port = suffix[1:]
    else:
        if value.count(b":") > 1:
            return False                         # IPv6 リテラルは [] が必須
        host, sep, port = value.partition(b":")
        if (not host or host.startswith(b".") or not _HOST_REG_NAME.fullmatch(host)
                or b".." in host or not host.strip(b".")):
            return False
        if not sep:
            return True
    return bool(port) and port.isdigit() and len(port) <= 5 and int(port) <= 65535


def _framing_ambiguous(buf: bytes, *, origin_header: bytes = b"",
                       protected_headers=()) -> bool:
    """HTTP リクエストスマグリング/デシンクの前提(曖昧な本文境界・行構造)を *構造* で検出。
    本機はバイト透過で再フレーミングしないため、フロントと上流で解釈が食い違う恐れのある要求は
    *受け取らない*(RFC 7230 §3.3.3 の安全側=拒否)。表層は無害な POST / の裏に隠した第2要求
    (例 GET /.env)を上流が実行してしまう desync を、難読化亜種ごと封じる。
    検出する曖昧化(いずれも二者で『どこで何が終わるか』を食い違わせ得る形):
      · 改行の不統一: 裸 LF / 裸 CR(CRLF を期待する側とズレる)
      · obs-fold(SP/HT で始まる継続行): 値の分割で片側だけ別解釈になり得る(RFC 7230 §3.2.4)
      · リクエストラインの不正(3トークン/method=英字/version=HTTP/1.[01] 以外・二重空白)
      · CL と TE の併存(CL.TE / TE.CL)・重複 Content-Length
      · Content-Length 値が有界な 1*DIGIT でない(0x10 / +5 / 桁過大 / "5, 5" 等)
      · 複数 Transfer-Encoding(TE.TE)・最終コーディングが chunked でない TE
      · 複数 Host / HTTP/1.1 で Host 欠落(RFC 7230 §5.4: 1.1 はちょうど1個=ルーティングの的)
      · 重複 User-Agent / Range(専用検査面と backend の採用値が割れる)
      · ヘッダ領域の NUL バイト(パーサにより打ち切り位置が割れる)
      · 不正なヘッダ名/行/値(片側だけを無視・別名解釈させる)
      · CGI/WSGI が '-' と '_' を同一視する保護ヘッダの別名
      · chunked 以外の転送符号化(走査面が復号できず、上流だけが復号する)
      · 重複/多段 Content-Encoding(走査側が復号しない層を上流が復号する)
    誇張しない: 『曖昧なら拒否』であって上流パーサのバグは直さない(安全側に倒すだけ)。本文
    (chunk)自体の検査は fail-fast 設計(ヘッダのみ読取)の対象外=別レイヤの責務。"""
    head = buf.split(b"\r\n\r\n", 1)[0]
    if _BARE_LF.search(head) or _BARE_CR.search(head):   # 行終端の不統一=境界解釈が割れる
        return True
    if b"\x00" in head:                          # NUL=打ち切り位置がパーサで割れる
        return True
    lines = head.split(b"\r\n")
    if _BAD_REQUEST_LINE.search(lines[0]) or not _REQ_LINE.match(lines[0]):
        # Backend parser may treat Latin-1 NEL/NBSP and 0x1c..0x1f as
        # whitespace even though the byte-oriented edge sees one path.
        # Require visible ASCII on the wire; percent-encoded UTF-8 stays valid.
        return True
    # origin-form のみ受理(evolution #34): リバプロは origin-form(/path)だけを受ける。絶対形
    #   (GET http://host/…)や authority 形は target に scheme/host が紛れ、WAF が path 規則
    #   (path_limits/sensitive_path)を本来のパスで評価できず回避され得る。OPTIONS * のみ例外。
    _rl = lines[0].split(b" ")
    _tgt = _rl[1] if len(_rl) > 1 else b""
    if not (_tgt.startswith(b"/") or (_tgt == b"*" and _rl[0].upper() == b"OPTIONS")):
        return True
    origin_header = origin_header.lower()
    origin_alias = origin_header.replace(b"_", b"-")
    configured = set()
    for name in protected_headers if isinstance(protected_headers, (list, tuple, set)) else ():
        if isinstance(name, str):
            try:
                name = name.encode("ascii")
            except UnicodeEncodeError:
                continue
        if isinstance(name, bytes) and _FIELD_NAME.fullmatch(name):
            configured.add(name.lower())
    configured_aliases = {name.replace(b"_", b"-") for name in configured}
    cls, tes, ces, cts, hosts = [], [], [], [], 0
    singleton_fields = set()
    cgi_names = {}                         # '_' と '-' の別名を二つのフィールドとして渡さない
    for ln in lines[1:]:
        if ln[:1] in (b" ", b"\t"):              # obs-fold 継続行=値の分割で解釈が割れる
            return True
        k, sep, v = ln.partition(b":")
        if not sep or not _FIELD_NAME.fullmatch(k) or _BAD_FIELD_VALUE.search(v):
            return True                          # 全フィールドで同じ厳密な名前/値を採用
        kl = k.lower()
        alias = kl.replace(b"_", b"-")
        prior = cgi_names.setdefault(alias, kl)
        if prior != kl:
            return True                      # WSGI/CGI では同じキーに連結される
        # A WSGI/CGI origin maps both spellings to the same application key.
        # Permit the exact edge-owned spelling, which is replaced later, but
        # reject another spelling that could survive inspection or removal.
        if ((origin_header and alias == origin_alias and kl != origin_header)
                or (alias in configured_aliases and kl not in configured)
                or (b"_" in kl and alias in _PROTECTED_REQUEST_OPTIONS
                    and kl != origin_header)):
            return True
        if kl in (b"connection", b"proxy-connection"):
            # HTTP intermediaries remove fields named by Connection options.
            # An origin must not discard a field the edge inspected or added.
            for raw_option in v.split(b","):
                option = raw_option.strip(b" \t").lower()
                option_alias = option.replace(b"_", b"-")
                if (not _FIELD_NAME.fullmatch(option)
                        or option_alias in _PROTECTED_REQUEST_OPTIONS
                        or option_alias in configured_aliases
                        or option_alias == origin_alias):
                    return True
        if kl in (b"user-agent", b"range"):
            # UA has one dedicated scan field and Range one range-count budget.
            # A backend choosing another copy must not see an unchecked value.
            if kl in singleton_fields:
                return True
            singleton_fields.add(kl)
        if kl == b"content-length":
            cls.append(v.strip())
        elif kl == b"transfer-encoding":
            tes.append(v.strip().lower())
        elif kl == b"content-encoding":
            ces.append(v.strip().lower())
        elif kl == b"content-type":
            cts.append(v.strip())
        elif kl == b"host":
            if not _valid_host_authority(v):
                return True                      # WAF/上流の authority 解釈を一致させる
            hosts += 1
    if hosts > 1:                                # 複数 Host(HTTP/1.1 はちょうど1個)
        return True
    if hosts == 0 and lines[0].endswith(b"HTTP/1.1"):   # 1.1 で Host 欠落(RFC 7230 §5.4 MUST)
        return True
    if cls and tes:                              # CL.TE / TE.CL
        return True
    if len(cls) > 1:                             # 重複 Content-Length
        return True
    if cls and (len(cls[0]) > 19 or not _CL_DIGITS.match(cls[0])
                or int(cls[0]) > (1 << 63) - 1):
        # A backend's signed length limit and Python's decimal-int limit must
        # not assign different message boundaries to the same wire request.
        return True
    if len(tes) > 1:                             # 複数 Transfer-Encoding(TE.TE)
        return True
    if tes and (not lines[0].endswith(b"HTTP/1.1") or tes[0] != b"chunked"):
        return True                              # 1.0 の TE/他の TE は上流と解釈が割れる
    if len(ces) > 1 or (ces and not _FIELD_NAME.fullmatch(ces[0])):
        return True                              # 単一の content-coding token だけ受ける
    if len(cts) > 1:
        return True                              # multipart 境界の検査/上流解釈差を拒否
    if cts and len(_CHARSET_PARAM.findall(cts[0])) > 1:
        return True                              # 先勝ち/後勝ち/中間採用の charset 差を拒否
    if cts and cts[0].lower().startswith(b"multipart/"):
        if (_BOUNDARY_EXT_PARAM.search(cts[0]) or
                len(_BOUNDARY_PARAM.findall(cts[0])) > 1):
            return True                          # 拡張/重複 boundary の backend 解釈差を拒否
    return False


# 訪問者向けページ(遮断ページ・案内ページ)共通の見た目。外部リソースは使わない。
_PAGE_CSS = (
    "body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;"
    "display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}"
    ".card{max-width:480px;padding:32px;background:#161b22;border:1px solid #30363d;"
    "border-radius:14px;text-align:center}.dim{color:#8b949e;font-size:13px}"
    "h2{color:#f85149}.logo{font-size:13px;color:#58a6ff;margin-bottom:8px}")


def _cover_brand(default: str) -> str:
    """案内ページの表示名(DUCKNET_COVER。空・空白だけなら default)。Server ヘッダや題名へ入るので
    制御文字は空白にして前後を落とす(CRLF の env ファイルから読むと末尾に CR が残る)。"""
    v = os.environ.get("DUCKNET_COVER", "")
    return "".join(ch if ch.isprintable() else " " for ch in v).strip() or default


def _block_page(info: dict, submitted: bool = False, msg: str = "") -> bytes:
    """アクセス遮断ページ(商用WAF風)。数分後に解除リクエスト(異議申立)フォームを出す。
    表示名は環境変数 DUCKNET_COVER で差し替え可(ステルス時=製品名を露見させない)。
    文言は DUCKNET_LANG(ja|en)で切替(end-user 向け多言語)。"""
    import html as _html
    from ..core.i18n import t, lang
    lg = lang()
    brand = _html.escape(_cover_brand("DuckNet-Lite"))
    remain = int(info.get("remain_sec", 0))
    if submitted:
        center = (f"<h2>{t('block.received.h')}</h2>"
                  f"<p>{_html.escape(msg)}</p>"
                  f"<p class='dim'>{t('block.received.p')}</p>")
    elif info.get("appealed") == "pending":
        center = (f"<h2>{t('block.pending.h')}</h2>"
                  f"<p class='dim'>{t('block.pending.p')}</p>")
    elif info.get("appeal_available"):
        center = (f"<h2>{t('block.appeal.h')}</h2>"
                  f"<p>{t('block.appeal.p')}</p>"
                  f"<form method='get' action='{_APPEAL_PATH}'>"
                  f"<input name='reason' maxlength='300' placeholder='{t('block.appeal.reason')}' "
                  "style='width:100%;padding:10px;margin:8px 0;border-radius:8px;"
                  "border:1px solid #30363d;background:#0d1117;color:#c9d1d9'>"
                  "<button type='submit' style='padding:10px 18px;border:0;border-radius:8px;"
                  f"background:#238636;color:#fff;cursor:pointer'>{t('block.appeal.submit')}</button></form>")
    else:
        after = int(info.get("appeal_after_sec", 0))
        center = (f"<h2>{t('block.blocked.h')}</h2>"
                  f"<p>{t('block.blocked.p')}</p>"
                  f"<p class='dim'>{t('block.blocked.when', after=after, remain=remain)}</p>")
    page = (
        f"<!doctype html><html lang='{lg}'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{t('block.title')} — " + brand + "</title><style>" + _PAGE_CSS +
        "</style></head><body><div class='card'>"
        "<div class='logo'>🛡 " + brand + "</div>" + center + "</div></body></html>")
    return page.encode("utf-8")


# ── 訪問者(ブラウザ)向けの案内ページ ─────────────────────────────────────────
# 拒否応答(429/502/400/413/415/431 ほか)は、ブラウザの画面遷移(HTML を優先する Accept+
# 画面遷移らしさ。_wants_html)には『何が起きたか・次に何をすればよいか』の短い HTML を返す。
# API クライアント(Accept: application/json・*/*・Accept 無し・Java の既定 Accept など)には
# 従来どおりの JSON を返す(機械が読む本文は 1 バイトも変えない)。ページは拒否経路でだけ
# 組み立てる=ホットパス無関係。文言は _block_page と同じく DUCKNET_LANG(lang())で日英を選ぶ。
# 内部の判定理由・規則名・スコア・パス・製品名(DUCKNET_COVER 設定時)は出さない。

def _wants_html(buf) -> bool:
    """要求がブラウザの画面遷移で HTML を優先しているか。次の両方を満たすときだけ True:
      · text/html の q が正で、JSON 系(application/json・text/json・…+json)の q より大きい。
        Accept 無し・*/*(curl)・JSON 優先は False。
      · 画面遷移らしい: Accept に application/xhtml+xml(主要ブラウザの画面遷移は必ず含む)、
        Sec-Fetch-Mode: navigate / Sec-Fetch-Dest: document|iframe、または UA がブラウザ
        (Mozilla/…)。Java HttpURLConnection の既定 Accept(text/html, image/gif, image/jpeg,
        *; q=.2, */*; q=.2)は text/html が先頭でもブラウザではない=JSON のまま(#33)。"""
    try:
        b = bytes(buf)
        acc = _header_value(b, b"accept").lower()
    except Exception:
        return False
    if "text/html" not in acc:
        return False
    html_q = json_q = 0.0
    for part in acc.split(","):
        mt, _, params = part.partition(";")
        mt = mt.strip()
        is_json = mt.endswith("/json") or mt.endswith("+json")
        if mt != "text/html" and not is_json:
            continue
        q = 1.0
        for p in params.split(";"):
            k, _, v = p.partition("=")
            if k.strip() == "q":
                try:
                    q = float(v.strip())
                except ValueError:
                    q = 0.0
        if is_json:
            json_q = max(json_q, q)
        else:
            html_q = max(html_q, q)
    if not html_q > max(0.0, json_q):
        return False
    if "application/xhtml+xml" in acc:
        return True
    if _header_value(b, b"sec-fetch-mode").strip().lower() == "navigate":
        return True
    if _header_value(b, b"sec-fetch-dest").strip().lower() in ("document", "iframe"):
        return True
    return _header_value(b, b"user-agent").strip().lower().startswith("mozilla/")


_PG = {
    "time": {"ja": "発生時刻: {ts}(サイトの管理者に問い合わせるときにお伝えください)",
             "en": "Time: {ts} (please mention this if you contact the site administrator)"},
    "contact": {"ja": "問題が続く場合は、サイトの管理者にお問い合わせください。",
                "en": "If this keeps happening, please contact the site administrator."},
    "reload": {"ja": "再読み込み", "en": "Reload"},
    "home": {"ja": "トップページへ", "en": "Go to the home page"},
    # 429
    "rate.h": {"ja": "アクセスが集中しています", "en": "Too many requests"},
    "rate.p": {"ja": "短い時間に多くのリクエストが届いたため、一時的に受け付けを止めています。",
               "en": "We received too many requests in a short time, so they are paused for a moment."},
    "rate.when": {"ja": "約 {n} 秒後に、また利用できるようになります。",
                  "en": "You can continue in about {n} seconds."},
    "rate.auto": {"ja": "このページは自動で再読み込みします。待てない場合は下のボタンを押してください。",
                  "en": "This page will reload automatically. You can also use the button below."},
    "rate.retry": {"ja": "今すぐ再試行", "en": "Try again now"},
    # 502
    "down.h": {"ja": "サイトに一時的に接続できません", "en": "The site is temporarily unreachable"},
    "down.p": {"ja": "このサイトのサーバーが一時的に応答していません。しばらく待ってから、"
                     "もう一度お試しください。",
               "en": "The site's server is not responding right now. Please wait a moment "
                     "and try again."},
    # 400
    "bad.h": {"ja": "リクエストを処理できませんでした", "en": "Your request could not be processed"},
    "bad.framing": {"ja": "ブラウザから届いたリクエストの形式に問題がありました。",
                    "en": "The request from your browser was not in a form this site accepts."},
    "bad.conflict": {"ja": "リクエストに、同じ情報が食い違う内容で複数含まれていました。",
                     "en": "The request contained the same information more than once, with "
                           "different values."},
    "bad.body": {"ja": "送信されたデータが途中で途切れているか、形式が正しくありませんでした。",
                 "en": "The data you sent was cut off or not in a valid format."},
    "bad.next": {"ja": "ページを再読み込みしてください。ブラウザの拡張機能やプロキシを使っている"
                       "場合は、それらを止めると解決することがあります。",
                 "en": "Please reload the page. If you use browser extensions or a proxy, "
                       "turning them off may help."},
    "bad.resend": {"ja": "もう一度送信してください。", "en": "Please send it again."},
    # 413
    "big.h": {"ja": "送信したデータが大きすぎます", "en": "The data you sent is too large"},
    "big.lim": {"ja": "このサイトが受け付けられる大きさ(最大 {limit})を超えています。",
                "en": "It is larger than this site accepts (up to {limit})."},
    "big.p": {"ja": "このサイトが受け付けられる大きさを超えています。",
              "en": "It is larger than this site accepts."},
    "big.next": {"ja": "データを小さくしてから、もう一度送信してください。",
                 "en": "Please make it smaller and send it again."},
    # 415
    "enc.h": {"ja": "送信したデータの形式に対応していません",
              "en": "The data format is not supported"},
    "enc.p": {"ja": "このサイトは、送信されたデータの圧縮形式を受け付けていません。",
              "en": "This site does not accept the compression used for the data you sent."},
    "enc.next": {"ja": "圧縮せずに送信し直してください。",
                 "en": "Please send it again without compression."},
    # 431
    "hdr.h": {"ja": "ブラウザから届いた情報が大きすぎます",
              "en": "Your browser sent too much information"},
    "hdr.p": {"ja": "Cookie などのリクエストに付く情報が大きすぎるため、処理できませんでした。",
              "en": "The information sent with the request, such as cookies, is too large "
                    "to process."},
    "hdr.next": {"ja": "ブラウザの設定から、このサイトの Cookie を削除してから、もう一度"
                       "アクセスしてください。",
                 "en": "Please delete this site's cookies in your browser settings, then "
                       "try again."},
    # 解除リクエスト経路(BAN されていない)
    "nb.h": {"ja": "このアドレスは現在ブロックされていません",
             "en": "This address is not currently blocked"},
    "nb.p": {"ja": "解除のリクエストは必要ありません。前のページに戻って再読み込みしてください。",
             "en": "There is nothing to unblock. Go back to the previous page and reload it."},
}


def _pg(key: str, lg: str, **fmt) -> str:
    """案内ページの文言(生テキスト)。"""
    m = _PG[key]
    s = m.get(lg) or m["ja"]
    return s.format(**fmt) if fmt else s


def _pgh(key: str, lg: str, **fmt) -> str:
    """案内ページの文言(HTML エスケープ済み。差し込む値ごとエスケープされる)。"""
    import html as _html
    return _html.escape(_pg(key, lg, **fmt))


def _page_lang() -> str:
    try:
        from ..core.i18n import lang
        return lang()
    except Exception:
        return "ja"


def _human_size(n: int) -> str:
    """上限バイト数を人が読める形に(切り捨て=実際より大きくは言わない)。"""
    n = int(n)
    if n >= 1 << 20:
        return f"{((n * 10) >> 20) / 10:g} MB"        # 小数 1 桁で切り捨て(1.95MB→1.9 MB)
    if n >= 1 << 10:
        return f"{n >> 10} KB"
    return f"{n} B"


_PAGE_CSS_EXTRA = (
    "p{line-height:1.6}.wait h2{color:#d29922}.ok h2{color:#3fb950}"
    "a.btn{display:inline-block;margin-top:4px;padding:10px 18px;border-radius:8px;"
    "background:#238636;color:#fff;text-decoration:none}")


def _guard_page(lg: str, head_key: str, body: str, tone: str = "",
                head: str = "", tail: str = "") -> bytes:
    """案内ページの外枠(_block_page と同じ見た目・ブランドの扱い・外部リソース無し)。
    body/head/tail は呼び出し側でエスケープ済みの HTML 断片。末尾に発生時刻(UTC)を添える
    (訪問者が管理者へ伝えられるように)。"""
    import html as _html
    brand = _html.escape(_cover_brand("DuckNet-Lite"))
    h = _pgh(head_key, lg)
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    page = (
        f"<!doctype html><html lang='{lg}'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{h} — {brand}</title>{head}<style>{_PAGE_CSS}{_PAGE_CSS_EXTRA}</style>"
        f"</head><body><div class='{('card ' + tone) if tone else 'card'}'>"
        f"<div class='logo'>🛡 {brand}</div>"
        f"<h2>{h}</h2>{body}<p class='dim'>{_pgh('time', lg, ts=ts)}</p></div>{tail}"
        "</body></html>")
    return page.encode("utf-8")


def _btn(label_key: str, lg: str, href: str = "") -> str:
    """リンクボタン。href='' は *いま表示している URL* (=元の URL をそのまま再要求)。"""
    import html as _html
    return f"<p><a class='btn' href='{_html.escape(href)}'>{_pgh(label_key, lg)}</a></p>"


# 静的な案内(見出し, 説明…, ボタン)。説明は _PG のキー。
_NOTICES = {
    "down": ("down.h", ("down.p", "contact"), ("reload", "")),
    "framing": ("bad.h", ("bad.framing", "bad.next", "contact"), ("reload", "")),
    "conflict": ("bad.h", ("bad.conflict", "bad.next", "contact"), ("reload", "")),
    "body": ("bad.h", ("bad.body", "bad.resend", "contact"), None),
    "encoding": ("enc.h", ("enc.p", "enc.next", "contact"), None),
    "headers": ("hdr.h", ("hdr.p", "hdr.next"), None),
    "not_banned": ("nb.h", ("nb.p",), ("home", "/")),
}


def _notice_page(kind: str) -> bytes:
    """静的な案内ページ(_NOTICES の kind)。"""
    lg = _page_lang()
    hk, paras, btn = _NOTICES[kind]
    body = "".join(f"<p>{_pgh(k, lg)}</p>" for k in paras)
    if btn:
        body += _btn(btn[0], lg, btn[1])
    return _guard_page(lg, hk, body)


def _too_large_page(limit=None) -> bytes:
    """413: 大きすぎる(上限が分かれば添える)。"""
    lg = _page_lang()
    why = (_pgh("big.lim", lg, limit=_human_size(limit)) if limit
           else _pgh("big.p", lg))
    return _guard_page(lg, "big.h", f"<p>{why}</p><p>{_pgh('big.next', lg)}</p>")


def _rate_page(retry_after) -> bytes:
    """429: N 秒後にまた使える。N 秒後(+揺らぎ)に元の URL を自動で再要求し、手動の再試行
    ボタンも出す。JS 無効でも meta refresh で再読み込みする。0 秒でも即時ループにしない。"""
    lg = _page_lang()
    try:
        n = max(1, int(retry_after))
    except (TypeError, ValueError):
        n = 1
    body = (f"<p>{_pgh('rate.p', lg)}</p><p>{_pgh('rate.when', lg, n=n)}</p>"
            f"<p class='dim'>{_pgh('rate.auto', lg)}</p>" + _btn("rate.retry", lg))
    head = f"<noscript><meta http-equiv='refresh' content='{n}'></noscript>"
    tail = ("<script>setTimeout(function(){location.replace(location.href)},"
            f"({n}+Math.random())*1000)</script>")
    return _guard_page(lg, "rate.h", body, tone="wait", head=head, tail=tail)


def _reject_response(status: str, json_body, page=None, extra=None) -> bytes:
    """拒否応答。page(HTML)があれば人向けページ、無ければ従来と同一の JSON 応答。
    HTML はキャッシュさせない(再読み込みで古い案内が出続けないように)。"""
    if page is None:
        return _http_response(status, json_body,
                              extra=list(extra or ()) + [("Cache-Control", "no-store")])
    return _http_response(status, page, "text/html; charset=utf-8",
                          extra=list(extra or ()) + [("Cache-Control", "no-store")])


_CONN_RATE_CAP = 50000      # 接続レート窓テーブルの上限(メモリ有界)
_CONN_RATE_LOW = 40000      # 間引き後の目標水位(上限との差=間引きの償却間隔)

# 同一 NetShield を複数 guard が共有しても、使用量行の生成→追記順が逆転しない。
# worker はプロセス内で一つ、実行中を含め最大32件。ディスク待ちでイベントループを止めない。
_USAGE_SUBMIT_LOCK = threading.Lock()
_USAGE_CV = threading.Condition()
_USAGE_QUEUE = deque()
_USAGE_OPEN = weakref.WeakSet()
_USAGE_RUNNING = None
_USAGE_WORKER = None
_USAGE_LIMIT = 32


def _usage_after_fork_child():
    """fork子は親threadのロック/待ち行列/Futureを引き継がない。"""
    global _USAGE_SUBMIT_LOCK, _USAGE_CV, _USAGE_QUEUE, _USAGE_OPEN
    global _USAGE_RUNNING, _USAGE_WORKER
    _USAGE_SUBMIT_LOCK = threading.Lock()
    _USAGE_CV = threading.Condition()
    _USAGE_QUEUE = deque()
    _USAGE_OPEN = weakref.WeakSet()
    _USAGE_RUNNING = _USAGE_WORKER = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_usage_after_fork_child)


def _complete_usage_future(fut, ok):
    if not fut.done():
        fut.set_result(ok)


def _usage_worker_loop():
    global _USAGE_RUNNING, _USAGE_WORKER
    while True:
        with _USAGE_CV:
            while not _USAGE_QUEUE and _USAGE_OPEN:
                _USAGE_CV.wait()
            if not _USAGE_QUEUE:
                _USAGE_WORKER = None
                return
            job = _USAGE_QUEUE.popleft()
            _USAGE_RUNNING = job
        guard, writer_fn, work, loop, done, kind = job
        try:
            ok = writer_fn(work) is True
        except Exception:
            ok = False
        with _USAGE_CV:
            _USAGE_RUNNING = None
            guard._log_pending -= 1
            if kind == "usage":
                guard._usage_pending -= 1
            else:
                guard._acl_pending -= 1
            if not ok:
                metric = kind + "_log_write_failed"
                guard.metrics[metric] = guard.metrics.get(metric, 0) + 1
            _USAGE_CV.notify_all()
        try:
            loop.call_soon_threadsafe(_complete_usage_future, done, ok)
        except RuntimeError:
            pass                      # loop 停止後でも pending/失敗指標は回収済み


class _BufferPool:
    """ヘッダ読取用 bytearray の再利用プール(GC断片化を抑えるリングバッファ方式)。
    イベントループは単一スレッドなのでロック不要。bytearray.extend は bytes+=bytes の
    O(n^2) コピー churn を避ける(これが実利・完全ゼロ確保は低レベルprotocol APIが要る=正直)。"""
    def __init__(self, cap: int = 128):
        self._free: list = []
        self._cap = cap

    def get(self) -> bytearray:
        if self._free:
            b = self._free.pop()
            del b[:]
            return b
        return bytearray()

    def put(self, b: bytearray):
        if len(self._free) < self._cap:
            self._free.append(b)


def _parse_head(buf: bytes):
    try:
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        lines = head.split("\r\n")
        parts = (lines[0].split(" ") + ["", ""])
        method, path = parts[0], parts[1]
        ua = host = ""
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            kl = k.strip().lower()
            if kl == "user-agent":
                ua = v.strip()
            elif kl == "host":
                host = v.strip()
        return method or "GET", path or "/", ua, host
    except Exception as exc:
        # A default GET / would inspect a different route than the raw head
        # forwarded to the origin. Parsing failure is an unavailable defense.
        raise RuntimeError("request head parsing unavailable") from exc


# 走査対象外にするヘッダ。Host/UA は inspect が *別フィールド* として走査(二重走査回避)。
# 構造系(CL/TE/Connection)はフレーミング検査/転送整形で扱う。Accept* は攻撃者制御で
# バックエンドが記録し得る(Log4Shell 等の運び手)ため #41 で走査対象へ戻した(除外しない)。
_SCAN_SKIP_HDR = frozenset((
    b"host", b"user-agent", b"content-length", b"transfer-encoding", b"connection",
))


def _header_names(buf: bytes, max_headers: int = 64) -> list:
    """head に存在するヘッダ名(小文字)の一覧。ボット整合性検知(#63)が UA とヘッダ集合の
    不整合を見るのに使う。値は見ない=軽量。framing 検査済みなので行構造は健全。"""
    try:
        head = buf.split(b"\r\n\r\n", 1)[0]
        names = []
        for ln in head.split(b"\r\n")[1:]:
            k, sep, _ = ln.partition(b":")
            if sep:
                names.append(k.strip().lower().decode("latin1", "replace"))
            if len(names) >= max_headers:
                break
        return names
    except Exception as exc:
        raise RuntimeError("request header-name inspection unavailable") from exc


_SCAN_PART_OVERLAP = 256    # ヘッダ値分割時の重なり(境界跨ぎペイロードの分断を防ぐ)
_SCAN_MAX_PARTS = 4         # 1 ヘッダ値あたりの最大分割数(走査面積を有界に保つ)


def _scan_header_values(buf: bytes, per: int = 8192, max_headers: int = 64) -> str:
    """攻撃者制御のヘッダ値(Referer/X-Forwarded-For/Cookie/独自ヘッダ等)を WAF の走査面へ。
    Log4Shell/SQLi 等は UA 以外のあらゆるヘッダから来る。構造系/高頻度・低リスク(Accept* 等)は除外。
    各値を *個別に* 上限化(per)し改行で区切って返す=inspect 側がヘッダ毎に独立走査でき(#39)、
    早いヘッダのパディングで後のヘッダ値が走査面から押し出されるのを防ぐ。本数も上限化(走査面積有界)。
    値に生改行は無い(framing 検査が裸LF/CRを既に拒否)ため改行は曖昧でない区切りになる。
    per は engine の 1 フィールド上限 _MAX_SCAN(8192)に合わせる: 旧 2048 は head バッファ
    (16384)や backend へ転送される実サイズより小さく、値の 2048〜転送サイズ間が *転送されるのに
    未走査* になる窓だった(単一ヘッダ padding で Log4Shell/SQLi を素通しできた)。
    max_headers を超える分は捨てず 1 つの結合末尾フィールドとして必ず走査面へ含める: 先頭を
    ダミーヘッダで埋めて後続の悪性ヘッダを本数上限の外へ押し出す回避(#field-count)を封じる。"""
    try:
        head = buf.split(b"\r\n\r\n", 1)[0]
        vals = []
        tail = []
        for ln in head.split(b"\r\n")[1:]:
            k, sep, v = ln.partition(b":")
            if not sep or k.strip().lower() in _SCAN_SKIP_HDR:
                continue
            v = v.strip()
            # per を超える値は *切り捨てず* 重なり付きで分割し、全量を走査面へ載せる。
            # 旧実装は v[:per] で切っていたため、per〜転送サイズの範囲が「転送されるのに
            # 未走査」の迂回窓だった(単一ヘッダを padding して Log4Shell 等を素通しできた)。
            # engine 側も 1 フィールド _MAX_SCAN で切るので、上限を上げるだけでは塞がらない。
            # 重なりは境界を跨ぐペイロードの分断を防ぐ。断片数は上限化(走査面積を有界に保つ)。
            if len(v) <= per:
                parts = [v]
            else:
                _step = max(1, per - _SCAN_PART_OVERLAP)
                parts = [v[i:i + per] for i in range(0, len(v), _step)][:_SCAN_MAX_PARTS]
            for _pv in parts:
                if len(vals) < max_headers:
                    vals.append(_pv)
                else:
                    tail.append(_pv)
        if tail:
            # 上限超ヘッダを結合して必ず走査(転送される全ヘッダ内容を走査面に残す)。
            # ここも切り捨てず重なり付き分割: 末尾バケットだけ未走査窓が残るのを防ぐ。
            _t = b" ".join(tail)
            if len(_t) <= per:
                vals.append(_t)
            else:
                _step = max(1, per - _SCAN_PART_OVERLAP)
                vals.extend(_t[i:i + per]
                            for i in range(0, len(_t), _step))
        return b"\n".join(vals).decode("latin1", "replace")
    except Exception as exc:
        # An empty scan view would make a forwarded, unexamined header look
        # clean. The caller distinguishes enforce from explicit audit mode.
        raise RuntimeError("request header-value inspection unavailable") from exc


# 応答セキュリティヘッダ(evolution #12)。保守的な既定=どのアプリでも概ね安全な
# 3つ。HSTS/CSP は配備依存(TLS終端・許可オリジン)ゆえ既定に入れず sec_headers_extra で opt-in。
_SEC_HEADERS_DEFAULT = {
    "X-Content-Type-Options": "nosniff",                  # MIME スニッフィング無効化
    "X-Frame-Options": "SAMEORIGIN",                      # クリックジャッキング緩和
    "Referrer-Policy": "strict-origin-when-cross-origin",  # リファラ漏れ抑制
}


def _harden_set_cookie(line: str, cfg, tls: bool) -> str:
    """応答 Set-Cookie 行に欠けた保護属性(SameSite/Secure/HttpOnly)を補完する(#65)。
    Set-Cookie 以外・既に属性がある場合は触らない。Secure は *TLS 接続時のみ* 付与する
    (平文接続で Secure を付けるとブラウザが Cookie を捨てる=壊す)。"""
    name, sep, val = line.partition(":")
    if not sep or name.strip().lower() != "set-cookie" or not val.strip():
        return line
    # The first segment is the cookie name/value, never an attribute. Cookie
    # parsers trim whitespace around attribute names and take the last
    # SameSite value, so a simple prefix search can both miss the attribute
    # and override an explicit Strict setting with our configured Lax value.
    attrs = [a.strip().lower() for a in val.split(";")[1:]]
    def attr_name(part):
        return part.partition("=")[0].strip()
    add = []
    ss = str(cfg.get("cookie_samesite", "Lax")).strip()
    same_site = [a.partition("=")[2].strip() for a in attrs if attr_name(a) == "samesite"]
    if ss and (not same_site or same_site[-1] not in ("strict", "lax", "none")):
        add.append(f"SameSite={ss}")
    if tls and not any(attr_name(a) == "secure" for a in attrs):
        add.append("Secure")
    if cfg.get("cookie_httponly") and not any(attr_name(a) == "httponly" for a in attrs):
        add.append("HttpOnly")
    return f"{name}:{val.rstrip()}; " + "; ".join(add) if add else line


def _neutralize_cors(lines) -> list:
    """応答ヘッダ行から危険な CORS 誤設定を無害化する(#69)。
    Access-Control-Allow-Credentials: true が Access-Control-Allow-Origin: * / null と併存する場合、
    任意/サンドボックス origin が *資格情報付き* 応答を読めてしまう=常に誤り。credentials 行を除去して
    無害化する(origin が静的な正当構成は触らない)。返り値: 加工後の行リスト。"""
    origins, credentials = [], []
    for ln in lines:
        n, _, v = ln.partition(":")
        nl = n.strip().lower()
        if nl == "access-control-allow-origin":
            origins.append(v.strip().lower())
        elif nl == "access-control-allow-credentials":
            credentials.append(v.strip().lower())
    # Duplicated/comma-joined singleton fields are interpreted differently by
    # clients. Do not leave credentials enabled if any reading is unsafe.
    credential_true = any("true" in (part.strip() for part in v.split(","))
                          for v in credentials)
    unsafe_origin = any(part.strip() in ("*", "null")
                        for v in origins for part in v.split(","))
    ambiguous = len(origins) != 1 or len(credentials) != 1 or any("," in v for v in origins)
    if credential_true and (unsafe_origin or ambiguous):
        return [ln for ln in lines
                if ln.partition(":")[0].strip().lower() != "access-control-allow-credentials"]
    return lines


_URL_SCHEME = re.compile(r"\A([A-Za-z][A-Za-z0-9+.\-]*):")
_SPECIAL_SCHEMES = ("http", "https", "ws", "wss", "ftp")
_C0_OR_SPACE = "".join(chr(c) for c in range(0x21))


def _location_host(loc: str) -> str:
    """Location 値から *絶対* リダイレクト先のホストを取り出す(小文字)。相対パス(/foo)や
    判定不能は ""(=同一サイト扱い)。ブラウザ(WHATWG URL)と同じ正規化をしてから判定する(#61):
      · 前後の C0 制御文字/空白を除き、値の中の TAB/CR/LF を取り除く
      · http(s) では '\\' は '/' と同義(/\\evil や \\\\evil は //evil=外部ホスト)
      · 特殊スキームの後ろの '/' の本数は問わない(https:evil / https:/evil も host=evil)
      · userinfo は *最後の* '@' まで(https://evil\\@site は host=evil)
    旧実装は '//' と '://' しか見ず、これらを相対/自サイト扱いして外部リダイレクトを通していた。
    逆に相対パスのクエリ中の URL(/sso?next=https://x)を外部扱いする誤検知もあった(スキームは
    先頭にしか現れない)。"""
    v = loc.strip(_C0_OR_SPACE)
    v = v.replace("\t", "").replace("\r", "").replace("\n", "").replace("\\", "/")
    m = _URL_SCHEME.match(v)
    if m:
        rest = v[m.end():]
        if m.group(1).lower() in _SPECIAL_SCHEMES:
            rest = rest.lstrip("/")
        elif rest.startswith("//"):
            rest = rest[2:]
        else:
            return ""                               # mailto:/javascript: 等=ホスト無し
    elif v.startswith("//"):
        rest = v.lstrip("/")                        # scheme 相対(/// も同じホスト)
    else:
        return ""                                   # 相対=同一サイト=対象外
    host = re.split(r"[/?#]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]   # userinfo 除去
    if host.startswith("["):                        # IPv6 リテラル [..]:port
        return host.split("]", 1)[0].lower() + "]"
    return host.split(":", 1)[0].strip().lower()    # port 除去


def _refresh_target(value: str) -> str:
    """Extract the URL that a browser reads from a bounded Refresh value.

    The shared declarative refresh grammar accepts a numeric delay, optional
    semicolon/comma/space, optional case-insensitive URL=, and quoted targets.
    It is parsed linearly so response-header size is the only work budget.
    """
    value = value.strip(" \t")
    i, n = 0, len(value)
    while i < n and "0" <= value[i] <= "9":
        i += 1
    if i == 0 and (i == n or value[i] != "."):
        return ""
    while i < n and ("0" <= value[i] <= "9" or value[i] == "."):
        i += 1
    if i == n or value[i] not in ";, \t":
        return ""
    while i < n and value[i] in " \t":
        i += 1
    if i < n and value[i] in ";,":
        i += 1
    while i < n and value[i] in " \t":
        i += 1
    prefix = i
    if value[i:i + 3].lower() == "url":
        i += 3
        while i < n and value[i] in " \t":
            i += 1
        if i < n and value[i] == "=":
            i += 1
            while i < n and value[i] in " \t":
                i += 1
        else:
            i = prefix
    if i < n and value[i] in "\"'":
        quote = value[i]
        i += 1
        end = value.find(quote, i)
        return value[i:] if end < 0 else value[i:end]
    return value[i:]


def _redirect_violation_host(status_line: str, lines, req_host: str, allow) -> str:
    """Find an external Location (3xx) or Refresh (any status), if present.

    req_host(リクエスト自身の Host)は完全一致、明示 allow のホストはサブドメインも許容。"""
    parts = status_line.split(" ", 2)
    is_redirect = len(parts) >= 2 and parts[1].startswith("3")
    # 比較は両辺とも _host_key の正規形で(#32)。旧実装は Host と allow を split(':') で切ったので
    # IPv6 リテラルが '[2001' になり、自サイトへのリダイレクトまで外部扱いしていた。
    own_host = _host_key(req_host)
    allowed = {_host_key(a) for a in (allow or [])}
    allowed.discard("")
    for ln in lines:
        n, sep, loc = ln.partition(":")
        if not sep:
            continue
        name = n.strip().lower()
        if name == "location" and is_redirect:
            target = loc
        elif name == "refresh":
            target = _refresh_target(loc)
        else:
            continue
        host = _location_host(target)
        if not host:
            continue                               # 相対リダイレクト=安全
        hk = _host_key(host)
        if hk != own_host and hk not in allowed and not any(hk.endswith("." + a) for a in allowed):
            return host
    return ""


def _host_key(h) -> str:
    """ホスト比較用の正規形: 小文字・ポート除去・IPv6 は角括弧を外して正規表記にする(#32)。
    '[2001:DB8:0::1]:8080' と '2001:db8::1' は同じ、'app.example:443' は 'app.example'。"""
    h = str(h or "").strip().lower()
    if h.startswith("["):
        h = h[1:].split("]", 1)[0]                  # [v6]:port → v6
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]                      # host:port(':' が 2 個以上=角括弧なしの v6)
    if ":" in h:
        import ipaddress
        try:
            h = str(ipaddress.ip_address(h))        # 表記揺れ(0 の省略・大文字)をそろえる
        except ValueError:
            pass
    return h


_ORIGIN_RESPONSE_FIELDS = frozenset((
    b"x-origin-ip", b"x-backend-server", b"x-upstream", b"x-original-ip",
    b"x-remote-ip", b"x-remote-addr", b"x-forwarded-server",
    b"x-rewrite-url", b"x-original-url",
))
_RESPONSE_TRAILER_FORBIDDEN = _ORIGIN_RESPONSE_FIELDS | frozenset((
    b"content-length", b"transfer-encoding", b"content-encoding", b"content-type",
    b"content-range", b"content-disposition", b"connection", b"keep-alive", b"proxy-connection",
    b"upgrade", b"te", b"trailer", b"proxy-authenticate", b"proxy-authorization",
    b"cache-control", b"pragma", b"expires", b"vary", b"surrogate-control",
    b"cdn-cache-control", b"cloudflare-cdn-cache-control", b"x-accel-expires",
    b"set-cookie", b"access-control-allow-origin", b"access-control-allow-credentials",
    b"location", b"refresh", b"x-content-type-options", b"x-frame-options",
    b"referrer-policy", b"content-security-policy", b"strict-transport-security",
))
_RESPONSE_CONNECTION_PROTECTED = _RESPONSE_TRAILER_FORBIDDEN - frozenset((
    b"connection", b"keep-alive", b"proxy-connection", b"upgrade", b"te", b"trailer",
)) | frozenset((
    b"vary", b"etag", b"last-modified", b"content-location", b"content-disposition",
    b"permissions-policy", b"clear-site-data", b"www-authenticate",
    b"authentication-info", b"content-security-policy-report-only",
    b"cross-origin-opener-policy", b"cross-origin-opener-policy-report-only",
    b"cross-origin-embedder-policy", b"cross-origin-embedder-policy-report-only",
    b"cross-origin-resource-policy", b"x-content-security-policy",
    b"x-download-options", b"x-permitted-cross-domain-policies",
    b"access-control-allow-methods", b"access-control-allow-headers",
    b"access-control-expose-headers", b"access-control-max-age",
))
_RESPONSE_EXTRA_FORBIDDEN = _ORIGIN_RESPONSE_FIELDS | frozenset((
    b"content-length", b"transfer-encoding", b"content-encoding",
    b"content-type", b"content-range", b"connection", b"trailer",
    b"upgrade", b"host", b"set-cookie", b"keep-alive",
    b"proxy-connection", b"te", b"proxy-authenticate", b"proxy-authorization",
))
_RESPONSE_EXTRA_MAX_FIELDS = 128
_RESPONSE_EXTRA_MAX_NAME = 128
_RESPONSE_EXTRA_MAX_VALUE = 16384
_RESPONSE_EXTRA_MAX_TOTAL = 32768
_RESPONSE_HEAD_MAX = 65536
_MAX_INTERIM_HEADS = 32


def _strip_origin_response_metadata(head: bytes) -> bytes:
    """Remove exact origin-only routing fields, retaining all other wire bytes."""
    lines = head.split(b"\r\n")
    kept = [lines[0]]
    for line in lines[1:]:
        if line.partition(b":")[0].lower() not in _ORIGIN_RESPONSE_FIELDS:
            kept.append(line)
    return b"\r\n".join(kept)


def inject_security_headers(head: bytes, cfg, tls: bool = False, *,
                            add_headers: bool = True, harden_cookies: bool = False,
                            harden_cors: bool = False) -> bytes:
    """応答 head(status line + ヘッダ群、末尾の CRLFCRLF は含まない)を加工する。
      · add_headers(既定True): 防御ヘッダ注入(#12)。既存は尊重・sec_headers_strip 除去・
        sec_headers_extra で上書き。
      · harden_cookies(既定False): Set-Cookie に SameSite/Secure(TLS時)/HttpOnly(opt-in)を
        補完(#65)。
      · harden_cors(既定False): ACAO:*/null + ACAC:true の危険な CORS 誤設定を無害化(#69)。
      · 各加工は独立に効く(_pipe が cfg フラグから渡す)。
      · 101 は origin 内部情報を除き handshake を保持。応答行が読めないものは触らない。"""
    try:
        text = head.decode("latin1")
    except Exception:
        return head
    lines = text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return head                                        # 応答行が読めない=非介入
    head = _strip_origin_response_metadata(head)
    lines = head.decode("latin1").split("\r\n")
    # WebSocket 等の切替(101)は触らない。切替は 101 でしか起きないので *ステータスで* 判定する
    # (#92)。旧実装は head のどこかに "upgrade" があるだけで全加工を外していた=
    # Vary: Upgrade-Insecure-Requests(一般的)・Apache の Upgrade: h2,h2c 告知・Cookie 値や
    # Location の部分一致で、防御ヘッダ/SameSite 補完/CORS 無害化がまとめて消えた。
    if _resp_status(lines[0].encode("latin1")) == 101:
        return head
    strip = ({str(h).strip().lower() for h in (cfg.get("sec_headers_strip") or [])}
             if add_headers else set())
    existing, kept = set(), []
    for ln in lines[1:]:
        name = ln.split(":", 1)[0].strip().lower() if ":" in ln else ""
        if name and name in strip:
            continue                                       # 情報漏洩ヘッダを除去
        if name:
            existing.add(name)
        kept.append(ln)
    if harden_cookies:                                     # #65: Set-Cookie の保護属性を補完
        kept = [_harden_set_cookie(ln, cfg, tls) for ln in kept]
    if harden_cors:                                        # #69: 危険な CORS 誤設定を無害化
        kept = _neutralize_cors(kept)
    out = [lines[0]] + kept
    if not add_headers:
        result = "\r\n".join(out).encode("latin1", "replace")
        if len(result) > _RESPONSE_HEAD_MAX:
            raise ValueError("configured response head exceeds limit")
        return result
    add = {name.lower(): (name, value) for name, value in _SEC_HEADERS_DEFAULT.items()}
    extra = cfg.get("sec_headers_extra") or {}
    if not isinstance(extra, dict) or len(extra) > _RESPONSE_EXTRA_MAX_FIELDS:
        raise ValueError("invalid configured response headers")
    seen, total = set(), 0
    for name, value in extra.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("invalid configured response headers")
        try:
            key, val = name.encode("ascii"), value.encode("latin1")
        except UnicodeError as exc:
            raise ValueError("invalid configured response headers") from exc
        lower = key.lower()
        if (not key or len(key) > _RESPONSE_EXTRA_MAX_NAME
                or not _RESPONSE_HEADER_NAME.fullmatch(key)
                or lower in _RESPONSE_EXTRA_FORBIDDEN or lower in seen
                or len(val) > _RESPONSE_EXTRA_MAX_VALUE
                or any(c < 32 and c != 9 or c == 127 for c in val)):
            raise ValueError("invalid configured response headers")
        total += len(key) + len(val)
        if total > _RESPONSE_EXTRA_MAX_TOTAL:
            raise ValueError("configured response headers exceed limit")
        seen.add(lower)
        add[lower] = (name, value)
    for lower, (name, value) in add.items():
        if value and lower not in existing:               # 既存は尊重・空値はスキップ
            out.append(f"{name}: {value}")
    if harden_cors:
        # Added fields have the same CORS semantics as backend fields.
        out[1:] = _neutralize_cors(out[1:])
    result = "\r\n".join(out).encode("latin1", "replace")
    if len(result) > _RESPONSE_HEAD_MAX:
        raise ValueError("configured response head exceeds limit")
    return result


_PRIVATE_CACHE_REMOVE = {b"cache-control", b"pragma", b"expires",
                         b"surrogate-control", b"cdn-cache-control",
                         b"cloudflare-cdn-cache-control", b"x-accel-expires"}


def _private_cache_head(head: bytes) -> bytes:
    """私有経路の公開/共有キャッシュ指示を消し、保存禁止を一意に設定する。"""
    lines = head.split(b"\r\n")
    kept = [lines[0]]
    for line in lines[1:]:
        name = line.partition(b":")[0].lower()
        if name not in _PRIVATE_CACHE_REMOVE:
            kept.append(line)
    kept.extend((b"Cache-Control: private, no-store", b"Pragma: no-cache", b"Expires: 0"))
    return b"\r\n".join(kept)


class AsyncEdgeGuard:
    """本体サービスの前に立つ asyncio 製 Fail-Fast L7 ガード。"""

    def __init__(self, backend_host: str = "127.0.0.1", backend_port: int = 8787,
                 listen_host: str = "127.0.0.1", listen_port: int = 8799,
                 head_timeout: float = 10.0, backend_unix: str = "",
                 health_path: str = "", write_timeout: float = 60.0):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.head_timeout = _finite_positive_timeout(head_timeout, 10.0)
        # 書込み(drain)デッドライン(#9): クライアント/バックエンドが受信を止めた(TCP zero-window)
        #   まま放置する『遅延読取』兵糧攻めを断つ。各 drain をこの秒数で打ち切り→両端を強制解放。
        #   SSE/大容量DLでも『一切受信しない状態がこの秒数』続くのは異常=安全に切る。env で調整可。
        self.write_timeout = _finite_positive_timeout(
            os.environ.get("DUCKNET_DRAIN_TIMEOUT", write_timeout), 60.0)
        self.backend_unix = backend_unix      # 同一ホストならUnixソケットでTCP越え加速(可用時)
        # ヘルスチェック用パス(opt-in)。LB/オーケストレータの死活監視を WAF/バックエンド非経由で
        # 即 200 応答するための予約パス。既定は空=無効(env DUCKNET_HEALTH_PATH で既定指定可)。
        self.health_path = (health_path or os.environ.get("DUCKNET_HEALTH_PATH", "")).strip()
        self._loop = None
        self._server = None
        self._thread = None
        self._ready = threading.Event()
        self._lifecycle_lock = threading.RLock()
        self._start_cancel = threading.Event()
        self._start_error = ""        # 待受開始に失敗した理由(start() が返す)
        self._workers = []            # --cluster で fork した子ワーカーの pid
        self._cluster_policy_sync = False  # cluster-origin listeners track signed policy before admission
        self._single_cluster_policy_sync = False  # reaped/safe-single parent may enforce stateful policy
        self._single_ban_snapshot_verified = False
        self._single_traffic_source_stamps = None
        self._serving_lease = None  # one serving owner for this signed state directory
        self._cluster_commit_lock = None  # fork-inherited ack/first-write order
        self._policy_sync_pid = os.getpid()
        self._policy_source_stamps = None  # None forces one verified load after fork
        self._cluster_quota_shield = None  # reservation owned until every fork child is reaped
        self._cluster_acl_firewall = None  # ACL audit/prompt reservation until children reap
        self._parent_guard_read = None   # fork children watch this pipe for parent death
        self._parent_guard_write = None  # only the cluster parent retains this writer
        self._worker_parent_guard = False
        self._worker_parent_dead = False
        self._parent_guard_poll_task = None
        self._listen_sock = None      # --cluster で親が使う SO_REUSEPORT ソケット
        self._defense_warned = set()  # 防御を用意できなかった理由(重複表示を避ける)
        self._stop_event = None       # ループ内 asyncio.Event(graceful drain の停止合図)
        self._active = 0              # 進行中の接続ハンドラ数(ループスレッドのみが触る=ロック不要)
        self._live = set()            # 進行中の writer(同上・停止時に確実に閉じるため)
        self._conn_per_ip: dict = {}  # ip -> 同時接続数(limit_conn 用・ループスレッドのみ=ロック不要)
        self._conn_rate: dict = {}    # ip -> [窓開始, 件数](接続レート=RST/churn フラッド対策・#10)
        self._body_stage_bytes = 0    # single-process in-flight spooled wire bytes
        self._body_stage_shm = None   # per-worker counters inherited by real fork workers
        self._body_stage_lock_path = None
        self._body_stage_lock_id = None
        self._body_stage_lock_fd = None
        self._body_stage_lock_pid = None
        self._body_stage_slot_count = 0
        self._body_stage_slot = 0
        self._body_stage_parent_pid = None
        self._body_stage_owner_paths = ()
        self._body_stage_owner_ids = ()
        self._body_stage_owner_fd = None
        self._body_stage_owner_pid = None
        self._body_stage_probe_fds = {}
        self._body_stage_probe_pid = None
        self._body_stage_executor = None
        self._body_stage_executor_pid = None
        self._pool = _BufferPool()
        self._log_pending = 0         # 共有 worker にこの guard が委託した総未完件数
        self._usage_pending = 0
        self._acl_pending = 0
        self._usage_closing = False
        self._usage_pid = os.getpid()
        self.metrics = {"accepted": 0, "dropped": 0, "proxied": 0, "backend_unreachable": 0}

    @staticmethod
    def platform_capabilities() -> dict:
        """この実行環境で使える低レベル最適化を正直に返す(各最適化案の可用性)。"""
        return {"platform": sys.platform,
                "so_reuseport": hasattr(socket, "SO_REUSEPORT"),
                "os_fork": hasattr(os, "fork"),
                "asyncio_unix": (hasattr(asyncio, "open_unix_connection")
                                 and hasattr(socket, "AF_UNIX")),
                "cpu_count": os.cpu_count() or 1,
                "note": "SO_REUSEPORT/fork/unix-socketはLinux/macOS向け。Windowsは"
                        "単一プロセス+TCPへフォールバック(誇張せず正直に降格)。"}

    # ── 接続処理(1コルーチン/接続・block は即解放) ──
    async def _read_head(self, reader) -> bytes:
        buf = self._pool.get()                # 再利用 bytearray(確保を抑える)
        # head_timeout は *総* デッドライン(#82)。per-read だけだと head_timeout 直前ごとに 1 バイト
        # 小出しする slowloris が各読取を成功させ続けて接続を保持できた。総時間で頭打ちにして塞ぐ。
        loop = asyncio.get_event_loop()
        deadline = loop.time() + self.head_timeout
        try:
            # 終端探索は *新着分だけ* を見る。ループ条件に "b'\r\n\r\n' not in buf" と
            # 書くと 1 チャンク受け取るたびにバッファ全体を再走査するため、攻撃者が 1 バイト
            # ずつ小出しすると走査量が 1+2+…+16384 = O(N^2) に膨らむ(実測: 1 バイト刻みで
            # 13ms/接続。単一イベントループなので同時接続数ぶん直撃する)。直前の 3 バイトだけ
            # 重ねて見れば境界を跨ぐ "\r\n\r\n" も取りこぼさず、総走査量は O(N) になる。
            done = False
            while not done and len(buf) < _REQUEST_HEAD_MAX:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError    # 総時間超過=slowloris(だらだら/小出し含む)
                chunk = await asyncio.wait_for(reader.read(4096), remaining)
                if not chunk:
                    break
                prev = len(buf)
                buf.extend(chunk)             # extend=償却O(1)(bytes+=のO(n^2)回避)
                done = buf.find(b"\r\n\r\n", prev - 3 if prev >= 3 else 0) >= 0
            return bytes(buf)                 # 解析/転送用の不変スナップショット
        finally:
            self._pool.put(buf)               # コンテナをプールへ返す

    async def _open_backend(self):
        """バックエンドへ接続。Unixソケット指定かつ可用ならTCPスタックを越えて加速。"""
        if self.backend_unix and hasattr(asyncio, "open_unix_connection"):
            return await asyncio.wait_for(
                asyncio.open_unix_connection(path=self.backend_unix),
                timeout=_BACKEND_CONNECT_TIMEOUT)
        return await asyncio.wait_for(
            asyncio.open_connection(self.backend_host, self.backend_port),
            timeout=_BACKEND_CONNECT_TIMEOUT)

    @staticmethod
    def _cluster_policy_sources(shield, firewall):
        """Signed control-plane files whose publication changes admission."""
        paths = (shield.path, shield.path + ".hw",
                 shield._sig_path, shield._sig_path + ".hw",
                 shield._bans_path, shield._bans_path + ".hw",
                 shield._traffic_path, shield._traffic_path + ".hw",
                 shield._state_marker,
                 firewall.path, firewall.path + ".hw",
                 firewall._history_path,
                 os.path.join(os.path.dirname(shield.path), ".statekey"),
                 os.path.join(os.path.dirname(firewall.path), ".statekey"))
        return tuple(dict.fromkeys(paths))

    @staticmethod
    def _cluster_unshared_reason(shield, firewall) -> str:
        """A fork cluster is safe only while all mutable decisions have one owner."""
        reason = shield._fork_cluster_unshared_reason(shield.cfg)
        if reason:
            return reason
        enabled = firewall.is_enabled()
        if type(enabled) is not bool or enabled:
            # Even a static allow/deny ACL maintains process-local audit log,
            # statistics and prompt IDs that the parent admin cannot see.
            return "ACL audit and prompt state"
        return ""

    @staticmethod
    def _cluster_bans_ready(shield):
        """Classify a signed BAN snapshot before workers acknowledge readiness.

        The ordinary single-process loader retains signed legacy migration
        behavior. A cluster cannot acknowledge readiness then make every
        child fail closed on its first admission for that same legacy file.
        """
        if not shield.cfg.get("persist_bans"):
            return "ready"
        from ..core.signed_state import MISSING_FINGERPRINT
        from ..lifeform.pipeline import _canon_cfg_ip, _MAX_IPS
        with shield._lock:
            was_signed = (shield._state_fingerprints.get(shield._bans_path)
                          != MISSING_FINGERPRINT)
            exists = (os.path.lexists(shield._bans_path)
                      or os.path.lexists(shield._bans_path + ".hw"))
            if not (was_signed or exists):
                return "ready"
            if shield.reload_bans().get("ok") is True:
                return "ready"
            # Only the known older signed shape (canonicalizable IP and/or
            # missing generation) may use the single-process compatibility
            # loader. A corrupt signature, missing high-water, or malformed
            # signed payload must never be served from stale local memory.
            status = []
            try:
                payload, _ = shield._read_state(shield._bans_path, {}, "bans",
                                                status_out=status)
                bans = payload.get("bans") if type(payload) is dict else None
                restrictions = payload.get("restrictions", {}) if type(payload) is dict else None
                if (status == ["ok"] and type(bans) is dict and len(bans) <= _MAX_IPS
                        and type(restrictions) is dict and not restrictions):
                    seen, legacy = set(), False
                    for ip, row in bans.items():
                        canonical = _canon_cfg_ip(ip) if type(ip) is str else ""
                        if (not canonical or canonical in seen or type(row) is not dict
                                or type(row.get("permanent")) is not bool
                                or type(row.get("count")) is not int
                                or not 0 <= row["count"] <= 1_000_000_000):
                            break
                        seen.add(canonical)
                        started = row.get("started")
                        until = row.get("until")
                        if (type(started) not in (int, float)
                                or not math.isfinite(started) or started < 0
                                or (row["permanent"] and until is not None)
                                or (not row["permanent"] and
                                    (type(until) not in (int, float)
                                     or not math.isfinite(until) or until < 0))):
                            break
                        generation = row.get("generation")
                        if generation is not None and (type(generation) is not str
                                or len(generation) != 32
                                or any(c not in "0123456789abcdef"
                                       for c in generation.lower())):
                            break
                        legacy = legacy or canonical != ip or generation is None
                    else:
                        if legacy:
                            return "legacy"
            except (OSError, TypeError, ValueError, OverflowError):
                pass
            shield._ban_state_untrusted = True
            return "untrusted"

    def _single_bans_ready(self, shield) -> bool:
        """Reload modern BANs; retain only a previously verified legacy view.

        A local BAN may be dirty between bounded durable writes. In that case
        its in-memory deny remains authoritative only while the signed file
        still has the fingerprint this process last verified or published.
        An unseen external legacy replacement must fail closed rather than
        silently discard either process's live BANs.
        """
        from ..core.signed_state import MISSING_FINGERPRINT, payload_fingerprint

        with shield._lock:
            if shield._ban_state_untrusted:
                return False
            if not shield.cfg.get("persist_bans"):
                return True
            if not shield._bans_dirty and shield.reload_bans().get("ok") is True:
                return True
            if not self._single_ban_snapshot_verified:
                return False
            expected = shield._state_fingerprints.get(shield._bans_path)
            status = []
            payload, _ = shield._read_state(shield._bans_path, {}, "bans",
                                             status_out=status)
            if status == ["missing"]:
                return expected == MISSING_FINGERPRINT
            return (status == ["ok"] and type(payload) is dict and
                    payload_fingerprint(payload) == expected)

    @staticmethod
    def _single_traffic_sources(shield):
        return (shield._traffic_path, shield._traffic_path + ".hw")

    def _check_single_traffic_source(self, shield):
        """Reject an external signed quota history the live owner has not loaded."""
        with shield._lock:
            finite = bool(shield.cfg.get("persist_bans") and
                          shield._finite_quota_active(shield.cfg))
        if not finite:
            return None
        paths = self._single_traffic_sources(shield)
        for _ in range(3):
            before = tuple(_signed_source_stamp(path) for path in paths)
            if (self._single_traffic_source_stamps != before or
                    shield._traffic_state_untrusted):
                if not shield.verify_traffic_source():
                    # Shield already latches this state: enforce rejects its
                    # quota decision, while audit records would-block and
                    # forwards by explicit mode choice. Preserve both modes.
                    if not shield._traffic_state_untrusted:
                        raise RuntimeError("signed single-worker quota history is unavailable")
            after = tuple(_signed_source_stamp(path) for path in paths)
            if before == after:
                self._single_traffic_source_stamps = after
                return after
        raise RuntimeError("signed quota history changed during admission")

    def _ensure_cluster_commit_lock(self):
        if self._cluster_commit_lock is None:
            from ..lifeform.pipeline import net_shield
            self._cluster_commit_lock = commit_barrier.register_cluster(
                net_shield().path)
        return self._cluster_commit_lock

    def _ensure_serving_lease(self) -> bool:
        """Own one state directory before refreshing quota history or binding.

        service.run may have acquired this lease before applying startup
        config. Direct AsyncEdgeGuard callers acquire it here. A second server
        must never independently spend the same persisted quota window.
        """
        from ..core.serving_lease import ServingLease
        from ..lifeform.pipeline import net_shield

        shield = net_shield()
        state_dir = os.path.dirname(os.path.abspath(shield.path))
        lease = self._serving_lease
        if lease is None:
            lease = ServingLease(state_dir)
            self._serving_lease = lease
        elif os.path.normcase(os.path.realpath(state_dir)) != lease.state_dir:
            raise RuntimeError("serving lease and Shield state directories differ")
        if not lease.held:
            if not lease.acquire(timeout=0.0):
                raise RuntimeError("another DuckNet server owns this state directory")
        shield._serving_lease = lease
        # The singleton may have been constructed before the lease. Adopt the
        # latest verified quota snapshot now, with no in-flight reservations.
        # A preexisting corrupt snapshot follows Shield's established
        # enforce/audit semantics; it is never replaced by an empty history.
        if not shield._traffic_state_untrusted and not shield.reload_traffic_for_start():
            raise RuntimeError("signed traffic history changed before serving")
        return True

    def _close_serving_lease(self) -> None:
        lease, self._serving_lease = self._serving_lease, None
        if lease is None:
            return
        try:
            from ..lifeform.pipeline import net_shield
            shield = net_shield()
            if getattr(shield, "_serving_lease", None) is lease:
                shield._serving_lease = None
        finally:
            lease.close()

    def _prepare_shared_body_stage(self, shield, slots: int = 2) -> None:
        """Create per-worker spool counters before true fork workers start.

        A paired dirty marker journals every mutation. The common path reads
        the cached aggregate in O(1); after a killed writer, the marker forces
        a full slot scan before any new admission. Each slot also stores its
        complement, so a torn slot cannot silently lose reserved bytes.
        """
        if self._body_stage_shm is not None:
            return
        if type(slots) is not int or not 2 <= slots <= 1024:
            raise ValueError("body staging needs 2..1024 worker slots")
        state_dir = os.path.dirname(os.path.abspath(shield.path))
        if self._serving_lease is None or not self._serving_lease.held:
            raise OSError("serving lease is unavailable for body staging")
        path = os.path.join(state_dir, ".body_stage.lock")
        if os.path.islink(path):
            raise OSError("body staging lock is a symlink")
        flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(path, flags, 0o600)
        shared = None
        owner_paths = [None]
        owner_ids = [None]
        try:
            info = os.fstat(fd)
            named = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                    or not stat.S_ISREG(named.st_mode)
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise OSError("body staging lock is not private or stable")
            # Creation descriptors are closed here. Just before each fork the
            # parent claims only that child's owner lock, then closes its own
            # copy before forking a sibling. No sibling can keep that lock
            # alive after the owner child is killed.
            for slot in range(1, slots):
                owner_path = os.path.join(state_dir, f".body_stage.owner.{slot}")
                owner_fd = os.open(owner_path, flags, 0o600)
                try:
                    owner = os.fstat(owner_fd)
                    owner_named = os.lstat(owner_path)
                    if (not stat.S_ISREG(owner.st_mode) or owner.st_nlink != 1
                            or (owner.st_dev, owner.st_ino) !=
                            (owner_named.st_dev, owner_named.st_ino)
                            or not stat.S_ISREG(owner_named.st_mode)
                            or owner.st_uid != os.geteuid() or owner.st_mode & 0o077):
                        raise OSError("body staging owner lock is not private or stable")
                    owner_paths.append(owner_path)
                    owner_ids.append((owner.st_dev, owner.st_ino))
                finally:
                    os.close(owner_fd)
            # The final pair is one cross-worker pressure-scan deadline.
            # A process-local cooldown lets every worker scan all slots in
            # parallel under a full body budget.
            shared = mmap.mmap(-1, 48 + 16 * slots, flags=mmap.MAP_SHARED,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE)
            shared[:] = b"\0" * len(shared)
            struct.pack_into("!Q", shared, 8, (1 << 64) - 1)
            struct.pack_into("!Q", shared, 24, (1 << 64) - 1)
            for slot in range(slots):
                struct.pack_into("!Q", shared, 40 + 16 * slot,
                                 (1 << 64) - 1)
            struct.pack_into("!Q", shared, 40 + 16 * slots,
                             (1 << 64) - 1)
        except BaseException:
            if shared is not None:
                shared.close()
            os.close(fd)
            raise
        self._body_stage_shm = shared
        self._body_stage_lock_path = path
        self._body_stage_lock_id = (info.st_dev, info.st_ino)
        self._body_stage_lock_fd = fd
        self._body_stage_lock_pid = os.getpid()
        self._body_stage_slot_count = slots
        self._body_stage_slot = 0
        self._body_stage_parent_pid = os.getpid()
        self._body_stage_owner_paths = tuple(owner_paths)
        self._body_stage_owner_ids = tuple(owner_ids)
        self._body_stage_probe_fds = {}
        self._body_stage_probe_pid = os.getpid()

    def _close_shared_body_stage(self) -> None:
        if self._body_stage_owner_fd is not None:
            try:
                os.close(self._body_stage_owner_fd)
            except OSError:
                pass
        self._body_stage_owner_fd = self._body_stage_owner_pid = None
        for probe_fd in self._body_stage_probe_fds.values():
            try:
                os.close(probe_fd)
            except OSError:
                pass
        self._body_stage_probe_fds = {}
        self._body_stage_probe_pid = None
        if self._body_stage_lock_fd is not None:
            try:
                os.close(self._body_stage_lock_fd)
            except OSError:
                pass
        self._body_stage_lock_fd = self._body_stage_lock_pid = None
        self._body_stage_lock_path = None
        self._body_stage_lock_id = None
        shared, self._body_stage_shm = self._body_stage_shm, None
        if shared is not None:
            try:
                shared.close()
            except OSError:
                pass
        self._body_stage_bytes = 0
        self._body_stage_slot_count = 0
        self._body_stage_slot = 0
        self._body_stage_parent_pid = None
        self._body_stage_owner_paths = ()
        self._body_stage_owner_ids = ()

    def _close_body_stage_executor(self) -> None:
        pool, self._body_stage_executor = self._body_stage_executor, None
        pid, self._body_stage_executor_pid = self._body_stage_executor_pid, None
        if pool is not None and pid == os.getpid():
            # All handler tasks have finished before full stop reaches here.
            pool.shutdown(wait=True, cancel_futures=False)

    def _body_stage_fd(self):
        """A child must not flock an inherited parent file description."""
        pid = os.getpid()
        opened_here = False
        if self._body_stage_lock_pid != pid:
            old, self._body_stage_lock_fd = self._body_stage_lock_fd, None
            if old is not None:
                os.close(old)
            path = self._body_stage_lock_path
            if not path or os.path.islink(path):
                raise OSError("body staging lock path changed")
            self._body_stage_lock_fd = os.open(
                path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0))
            self._body_stage_lock_pid = pid
            opened_here = True
        fd, path = self._body_stage_lock_fd, self._body_stage_lock_path
        try:
            info, named = os.fstat(fd), os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(named.st_mode)
                    or info.st_nlink != named.st_nlink or named.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                    or (info.st_dev, info.st_ino) != self._body_stage_lock_id
                    or (named.st_dev, named.st_ino) != self._body_stage_lock_id
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise OSError("body staging lock inode changed")
        except BaseException:
            if opened_here:
                # A first post-fork reopen may have raced a pathname swap.
                # It has not acquired the flock yet, so discard that wrong
                # inode and allow a later request to retry after repair.
                self._body_stage_lock_fd = self._body_stage_lock_pid = None
                os.close(fd)
            raise
        return fd

    def _check_body_stage_owner_file(self, slot: int, fd: int) -> None:
        """Pin each lifetime lock to the inode created before fork."""
        path = self._body_stage_owner_paths[slot]
        expected = self._body_stage_owner_ids[slot]
        info, named = os.fstat(fd), os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(named.st_mode)
                or info.st_nlink != 1 or named.st_nlink != 1
                or (info.st_dev, info.st_ino) != expected
                or (named.st_dev, named.st_ino) != expected
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise OSError("body staging owner lock inode changed")

    def _open_body_stage_owner(self, slot: int) -> int:
        """Claim one child's lifetime lock before forking that child."""
        if not 1 <= slot < self._body_stage_slot_count:
            raise ValueError("invalid body staging owner slot")
        import fcntl
        path = self._body_stage_owner_paths[slot]
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        try:
            self._check_body_stage_owner_file(slot, fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check_body_stage_owner_file(slot, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _adopt_body_stage_owner(self, slot: int, fd: int) -> None:
        """The fork child alone retains the already-claimed owner lock."""
        if os.getpid() == self._body_stage_parent_pid:
            raise RuntimeError("parent cannot adopt a child staging slot")
        self._check_body_stage_owner_file(slot, fd)
        self._body_stage_slot = slot
        self._body_stage_owner_fd = fd
        self._body_stage_owner_pid = os.getpid()

    def _claim_body_stage_owner(self, slot: int) -> None:
        """Direct-fork test seam; production claims before fork instead."""
        fd = self._open_body_stage_owner(slot)
        try:
            self._adopt_body_stage_owner(slot, fd)
        except BaseException:
            os.close(fd)
            raise

    def _body_stage_owner_is_gone(self, slot: int) -> bool:
        """A free lifetime flock proves that no child owns this slot now."""
        import fcntl
        pid = os.getpid()
        if self._body_stage_probe_pid != pid:
            # A probe FD inherited through fork shares its open-file
            # description with the parent. Never reuse it in a child.
            for old in self._body_stage_probe_fds.values():
                os.close(old)
            self._body_stage_probe_fds = {}
            self._body_stage_probe_pid = pid
        fd = self._body_stage_probe_fds.get(slot)
        if fd is None:
            path = self._body_stage_owner_paths[slot]
            fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0))
            try:
                self._check_body_stage_owner_file(slot, fd)
            except BaseException:
                os.close(fd)
                raise
            self._body_stage_probe_fds[slot] = fd
        self._check_body_stage_owner_file(slot, fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        try:
            self._check_body_stage_owner_file(slot, fd)
            return True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)

    def _body_stage_dirty(self, marker: int) -> None:
        mask = (1 << 64) - 1
        struct.pack_into("!Q", self._body_stage_shm, 16, marker)
        struct.pack_into("!Q", self._body_stage_shm, 24, marker ^ mask)

    def _body_stage_cached_total(self, total: int) -> None:
        mask = (1 << 64) - 1
        struct.pack_into("!Q", self._body_stage_shm, 0, total)
        struct.pack_into("!Q", self._body_stage_shm, 8, total ^ mask)

    def _body_stage_pressure_probe_due(self, now_ns: int) -> bool:
        """Authorize one dead-owner scan for the whole fork generation.

        Called only with the global stage flock held. A killed writer may
        leave one half of the deadline pair changed; repair it conservatively
        and retry after one short interval instead of scanning in every child.
        """
        offset = 32 + 16 * self._body_stage_slot_count
        deadline, complement = struct.unpack_from("!QQ", self._body_stage_shm,
                                                 offset)
        interval = _BODY_STAGE_PROBE_INTERVAL_NS
        mask = (1 << 64) - 1
        if (complement != (deadline ^ mask)
                or deadline > now_ns + interval):
            self._body_stage_set_probe_deadline(offset, now_ns + interval)
            return False
        if now_ns < deadline:
            return False
        self._body_stage_set_probe_deadline(offset, now_ns + interval)
        return True

    def _body_stage_set_probe_deadline(self, offset: int, deadline: int) -> None:
        mask = (1 << 64) - 1
        struct.pack_into("!Q", self._body_stage_shm, offset, deadline)
        struct.pack_into("!Q", self._body_stage_shm, offset + 8,
                         deadline ^ mask)

    def _rebuild_body_stage_total(self, own_slot: int):
        """Repair a killed writer's journal, reclaiming only unlocked slots.

        Called with the global body-stage flock held. A live owner's torn
        count is never guessed; an orphaned owner's count can be discarded
        because its process cannot still hold or replay the staged body.
        """
        mask = (1 << 64) - 1
        counts = []
        dead = []
        total = 0
        for slot in range(self._body_stage_slot_count):
            count, complement = struct.unpack_from("!QQ", self._body_stage_shm,
                                                   32 + 16 * slot)
            valid = count <= _BODY_STAGE_TOTAL and complement == (count ^ mask)
            if slot and (count or not valid):
                if self._body_stage_owner_is_gone(slot):
                    if slot == own_slot:
                        raise OSError("current worker lost its staging owner")
                    dead.append(slot)
                    count, valid = 0, True
            if not valid:
                raise OSError("body staging slot is torn or untrusted")
            total += count
            if total > _BODY_STAGE_TOTAL:
                raise OSError("body staging aggregate is untrusted")
            counts.append(count)
        cached, cached_complement, marker, marker_complement = struct.unpack_from(
            "!QQQQ", self._body_stage_shm, 0)
        needs_repair = (bool(dead) or cached != total
                        or cached_complement != (cached ^ mask)
                        or marker != 0 or marker_complement != mask)
        if needs_repair:
            self._body_stage_dirty(self._body_stage_slot_count + 1)
            for slot in dead:
                struct.pack_into("!QQ", self._body_stage_shm,
                                 32 + 16 * slot, 0, mask)
            self._body_stage_cached_total(total)
            self._body_stage_dirty(0)
        return total, counts[own_slot], bool(dead)

    def _adjust_body_stage(self, delta: int) -> bool:
        """Reserve/release actual wire bytes with a hard cross-worker bound."""
        if not delta:
            return True
        if self._body_stage_shm is None:
            new = self._body_stage_bytes + delta
            if not 0 <= new <= _BODY_STAGE_TOTAL:
                return False
            self._body_stage_bytes = new
            return True
        import fcntl  # only true POSIX fork workers use the shared counters
        pid = os.getpid()
        slot = self._body_stage_slot
        if not 0 <= slot < self._body_stage_slot_count:
            raise OSError("body staging slot is unavailable")
        if slot == 0:
            if pid != self._body_stage_parent_pid:
                raise OSError("fork child has not claimed a body staging slot")
        elif (self._body_stage_owner_fd is None
              or self._body_stage_owner_pid != pid):
            raise OSError("body staging owner lock is unavailable")
        fd = self._body_stage_fd()
        # Never sleep on the sole asyncio loop while another worker owns the
        # lock. A contended reservation is a temporary 503, not an unbounded
        # wait or an unaccounted spool write.
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        try:
            self._body_stage_fd()  # reject a replaced inode while holding it
            if slot:
                self._check_body_stage_owner_file(slot, self._body_stage_owner_fd)
            mask = (1 << 64) - 1
            total, total_complement, marker, marker_complement = struct.unpack_from(
                "!QQQQ", self._body_stage_shm, 0)
            own_count, own_complement = struct.unpack_from(
                "!QQ", self._body_stage_shm, 32 + 16 * slot)
            if (total > _BODY_STAGE_TOTAL or total_complement != (total ^ mask)
                    or marker != 0 or marker_complement != mask
                    or own_count > _BODY_STAGE_TOTAL
                    or own_complement != (own_count ^ mask)):
                total, own_count, _ = self._rebuild_body_stage_total(slot)
            if delta > 0 and total + delta > _BODY_STAGE_TOTAL:
                if self._body_stage_pressure_probe_due(time.monotonic_ns()):
                    total, own_count, _ = self._rebuild_body_stage_total(slot)
            new_total = total + delta
            new_owner = own_count + delta
            if not 0 <= new_total <= _BODY_STAGE_TOTAL or not 0 <= new_owner <= _BODY_STAGE_TOTAL:
                return False
            self._body_stage_dirty(slot + 1)
            offset = 32 + 16 * slot
            struct.pack_into("!Q", self._body_stage_shm, offset, new_owner)
            struct.pack_into("!Q", self._body_stage_shm, offset + 8,
                             new_owner ^ mask)
            self._body_stage_cached_total(new_total)
            # A same-UID state writer could replace the pathname between the
            # pre-write check and this update. Leave any uncertain count
            # charged and deny this reservation if the inode changed.
            self._body_stage_fd()
            if slot:
                self._check_body_stage_owner_file(slot, self._body_stage_owner_fd)
            self._body_stage_dirty(0)
            return True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)

    def _finish_serving_lease(self) -> bool:
        """Flush security state before making the directory available again."""
        lease = self._serving_lease
        if lease is None:
            return True
        if not lease.held:
            return False
        try:
            from ..lifeform.pipeline import net_shield
            shield = net_shield()
            saved = shield.flush_state()
            complete = isinstance(saved, dict) and saved.get("ok") is True

            def disk_untrusted(path, kind):
                status = []
                shield._read_state(path, {}, kind, status_out=status)
                return bool(status and status[0] in
                            ("tampered", "rolled_back", "invalid"))

            # Usage telemetry failure is reported, but cannot let a second
            # server spend a stale finite quota. Keep the lease only while a
            # live BAN or quota counter is still unflushed against *valid*
            # on-disk evidence. Corrupt signed evidence stays fail-safe for
            # the next owner, even after audit-mode requests made it dirty.
            enabled = bool(shield.cfg.get("persist_bans"))
            traffic_safe = (not enabled or
                            (isinstance(saved, dict) and saved.get("traffic_saved") is True)
                            or not shield._traffic_dirty
                            or disk_untrusted(shield._traffic_path, "traffic"))
            bans_safe = (not enabled or
                         (isinstance(saved, dict) and saved.get("bans") == "saved")
                         or not shield._bans_dirty
                         or disk_untrusted(shield._bans_path, "bans"))
            release_safe = bool(traffic_safe and bans_safe)
        except Exception:
            complete = release_safe = False
        if release_safe:
            self._close_serving_lease()
        return complete

    def _dispose_failed_start_lease(self) -> None:
        """Do not discard dirty state from an unsuccessful listener start."""
        lease = self._serving_lease
        if lease is None:
            return
        if getattr(lease, "_held", False):
            self._finish_serving_lease()
        else:
            # Busy contender acquired no ownership; close its file handle.
            self._close_serving_lease()

    def _release_cluster_commit_lock(self):
        if (self._workers or self._active or self.is_alive()
                or self._cluster_commit_lock is None):
            return False
        lock, self._cluster_commit_lock = self._cluster_commit_lock, None
        return commit_barrier.release_cluster(lock)

    def _close_parent_guard(self, *, read=True, write=True):
        """Close only this process's copies of the parent-liveness pipe."""
        for enabled, name in ((read, "_parent_guard_read"),
                              (write, "_parent_guard_write")):
            if not enabled:
                continue
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _open_parent_guard(self):
        """Install a fork-inherited, nonblocking pipe before any worker forks."""
        self._close_parent_guard()
        read_fd, write_fd = os.pipe()
        try:
            os.set_blocking(read_fd, False)
            os.set_inheritable(read_fd, False)
            os.set_inheritable(write_fd, False)
        except BaseException:
            os.close(read_fd)
            os.close(write_fd)
            raise
        self._parent_guard_read = read_fd
        self._parent_guard_write = write_fd
        self._worker_parent_guard = False
        self._worker_parent_dead = False

    def _parent_guard_alive(self) -> bool:
        """An EOF means the only writer (the parent) died without reaping us."""
        if not self._worker_parent_guard:
            return True
        if self._worker_parent_dead:
            return False
        fd = self._parent_guard_read
        if fd is None:
            self._worker_parent_dead = True
            return False
        try:
            marker = os.read(fd, 1)
        except BlockingIOError:
            return True
        except OSError:
            marker = b""
        # The parent never sends data. A byte or EOF is equally untrustworthy.
        self._worker_parent_dead = True
        return False

    def _worker_on_parent_dead(self):
        if self._parent_guard_alive():
            return
        fd = self._parent_guard_read
        if fd is not None and self._loop is not None:
            try:
                self._loop.remove_reader(fd)
            except Exception:
                pass
        self._close_parent_guard(read=True, write=False)
        self._worker_draining = True
        if self._server is not None:
            self._server.close()
        for writer in list(self._live):
            self._close(writer)
        self._live.clear()
        if self._stop_event is not None:
            self._stop_event.set()

    def _sync_cluster_policy(self):
        """Verify published policy in each fork worker before admission.

        Parent-side direct Python setters publish signed files after fork but
        cannot mutate children's copy-on-write objects. Stat is bounded per
        request; full signed reads and compilation happen only on a changed
        source. A first request always verifies the inherited snapshot so a
        parent commit between fork and child startup cannot be missed.
        """
        if (not self._worker_parent_guard and self._serving_lease is not None
                and not self._serving_lease.held):
            raise RuntimeError("serving state lease is unavailable")
        if not self._cluster_policy_sync:
            return None
        pid = os.getpid()
        if self._policy_sync_pid != pid:
            self._policy_sync_pid = pid
            self._policy_source_stamps = None
            self._single_traffic_source_stamps = None
        from ..lifeform.pipeline import net_shield
        from ..lifeform.policy import app_firewall
        shield, firewall = net_shield(), app_firewall()
        single_owner = (self._single_cluster_policy_sync
                        and not self._worker_parent_guard and not self._workers)
        paths = self._cluster_policy_sources(shield, firewall)
        for _ in range(3):
            before = tuple(_signed_source_stamp(path) for path in paths)
            if self._policy_source_stamps == before:
                reason = self._cluster_unshared_reason(shield, firewall)
                if reason and not single_owner:
                    raise RuntimeError(f"{reason} cannot run across fork workers")
                if single_owner and (shield._cfg_state_untrusted or
                                     shield._sig_state_untrusted or
                                     shield._ban_state_untrusted or
                                     firewall._load_warning):
                    raise RuntimeError("single-worker signed policy is untrusted")
                if single_owner:
                    self._check_single_traffic_source(shield)
                return before
            if (not shield.reload_config_verified()
                    or not shield.reload_signatures_verified()
                    or not firewall.reload_verified()):
                raise RuntimeError("signed cluster policy is unavailable")
            if single_owner:
                if not self._single_bans_ready(shield):
                    raise RuntimeError("signed single-worker BAN state is unavailable")
                self._check_single_traffic_source(shield)
            elif self._cluster_bans_ready(shield) != "ready":
                raise RuntimeError("signed cluster BAN state is unavailable")
            after = tuple(_signed_source_stamp(path) for path in paths)
            if before == after:
                self._policy_source_stamps = after
                reason = self._cluster_unshared_reason(shield, firewall)
                if reason and not single_owner:
                    raise RuntimeError(f"{reason} cannot run across fork workers")
                return after
        raise RuntimeError("signed cluster policy changed during admission")

    async def _checked_backend_write(self, bwr, data: bytes, admission_stamp,
                                     deadline: float = None):
        """Order each checked request write against policy acknowledgements.

        Parent setters take the same fork-inherited lock while publishing.
        Poll without blocking the event loop if a setter is syncing disk. A
        worker that cannot obtain the lock denies this request instead of
        forwarding head or streaming body bytes under an old decision.
        """
        def check_deadline():
            if deadline is not None and (not math.isfinite(deadline)
                                         or asyncio.get_running_loop().time() >= deadline):
                self.metrics["backend_write_timeout"] = (
                    self.metrics.get("backend_write_timeout", 0) + 1)
                try:
                    bwr.transport.abort()
                except Exception:
                    self._close(bwr)
                raise asyncio.TimeoutError()

        if admission_stamp is None:
            if not self._parent_guard_alive():
                self.metrics["dropped"] += 1
                raise RuntimeError("cluster parent is unavailable before backend write")
            check_deadline()
            bwr.write(data)
            await self._drain_backend(bwr, deadline)
            return
        try:
            lock = self._ensure_cluster_commit_lock()
        except Exception as exc:
            self._defense_unavailable("cluster_policy", exc)
            self.metrics["dropped"] += 1
            raise
        if lock is None:
            exc = RuntimeError("cluster policy commit barrier is unavailable")
            self._defense_unavailable("cluster_policy", exc)
            self.metrics["dropped"] += 1
            raise exc
        # A verified reload may take Shield/ACL object locks. Do it before
        # taking the cross-process commit lock: setters use object-lock then
        # commit-lock order, and the parent is itself a serving worker.
        try:
            current_stamp = self._sync_cluster_policy()
        except Exception as exc:
            self._defense_unavailable("cluster_policy", exc)
            self.metrics["dropped"] += 1
            raise
        if current_stamp != admission_stamp:
            self.metrics["dropped"] += 1
            raise RuntimeError("cluster policy changed before backend write")
        from ..lifeform.pipeline import net_shield
        from ..lifeform.policy import app_firewall
        paths = self._cluster_policy_sources(net_shield(), app_firewall())
        lock_deadline = time.monotonic() + commit_barrier.WAIT_SEC
        while True:
            try:
                acquired = lock.acquire(False)
            except Exception as exc:
                self._defense_unavailable("cluster_policy", exc)
                self.metrics["dropped"] += 1
                raise
            if acquired:
                break
            if time.monotonic() >= lock_deadline:
                exc = RuntimeError("cluster policy commit barrier timed out")
                self._defense_unavailable("cluster_policy", exc)
                self.metrics["dropped"] += 1
                raise exc
            await asyncio.sleep(0.001)
        try:
            try:
                if not lock.verify_path():
                    raise RuntimeError("cluster policy lock inode changed")
                # Re-stat under the commit lock with no object-lock acquisition.
                # Any cooperating setter that published while we waited must
                # invalidate this old decision before a byte is queued.
                stable_stamp = tuple(_signed_source_stamp(path) for path in paths)
            except Exception as exc:
                self._defense_unavailable("cluster_policy", exc)
                self.metrics["dropped"] += 1
                raise
            if stable_stamp != current_stamp:
                self.metrics["dropped"] += 1
                raise RuntimeError("cluster policy changed before backend write")
            if not self._parent_guard_alive():
                self.metrics["dropped"] += 1
                raise RuntimeError("cluster parent is unavailable before backend write")
            check_deadline()
            bwr.write(data)
            # Keep the commit barrier through bounded transport drain. This
            # orders the local write and backpressure wait before setter ack;
            # drain does not prove when the backend application reads bytes.
            await self._drain_backend(bwr, deadline)
        finally:
            lock.release()

    async def _handle(self, reader, writer):
        """接続ごとの入口。進行中数を計上して本体へ委譲(graceful drain が枯渇を待てるように)。
        計上は単一スレッド(イベントループ)内のみ=ロック不要。本体の多数の早期 return を
        包むため薄いラッパに分離(全 return 経路で必ずデクリメント)。
        さらに per-IP 同時接続上限(limit_conn・evolution #30): cfg max_conn_per_ip>0 のとき、
        同一IPが既に上限本数を保持していれば head 解析前に即切断(接続枯渇/slowloris 増幅対策)。"""
        if not self._parent_guard_alive():
            self.metrics["dropped"] += 1
            return self._close(writer)
        self._active += 1
        # 進行中の writer を握っておく。stop(grace) の猶予を過ぎて残った接続を
        # *明示的に閉じる* ために要る。以前は放置しており、stop() から戻った時点でも
        # ソケットが開いたまま GC 待ちになっていた(実測: 高負荷停止の直後に 25 本)。
        # 長寿命プロセスの restart(watchdog)では再起動のたびにこれが積み上がる。
        self._live.add(writer)
        ip = ""
        try:
            peer = writer.get_extra_info("peername")
            ip = self._norm_ip(peer[0] if peer else "")   # #14: IPv4-mapped を正規化
        except Exception:
            ip = ""
        cap = gcap = crate = 0
        cfg_error = None
        admission_stamp = None
        try:
            admission_stamp = self._sync_cluster_policy()
            from ..lifeform.pipeline import net_shield
            _scfg = net_shield().cfg
            cap = int(_scfg.get("max_conn_per_ip", 0) or 0)
            gcap = int(_scfg.get("max_total_conn", 0) or 0)
            crate = int(_scfg.get("conn_rate_per_ip", 0) or 0)
        except Exception as exc:
            cfg_error = exc
        counted = False
        acl_jobs = []
        try:
            if cfg_error is not None:
                # 上限を取得できないまま header_timeout まで無制限に待たせない。
                self._defense_unavailable("connection_limits", cfg_error)
                self.metrics["dropped"] += 1
                if self._cluster_policy_sync:
                    # Closing a TCP socket with the unread request head sends
                    # RST on some POSIX stacks, discarding the queued 503.
                    # Consume only a bounded small head; incomplete/slow
                    # clients are simply closed, still before backend bytes.
                    try:
                        head = bytearray()
                        loop = asyncio.get_running_loop()
                        deadline = loop.time() + 0.05
                        while b"\r\n\r\n" not in head and len(head) < _REQUEST_HEAD_MAX:
                            remaining = deadline - loop.time()
                            if remaining <= 0:
                                break
                            chunk = await asyncio.wait_for(
                                reader.read(min(4096, _REQUEST_HEAD_MAX - len(head))),
                                timeout=remaining)
                            if not chunk:
                                break
                            head.extend(chunk)
                        if b"\r\n\r\n" in head:
                            writer.write(_http_response("503 Service Unavailable",
                                                        '{"status":"unavailable"}'))
                            await asyncio.wait_for(writer.drain(), timeout=0.5)
                    except Exception:
                        pass
                return self._close(writer)
            # #79: グローバル同時接続上限(FD/ソケット/メモリ枯渇のロードシェッド)。per-IP(#30)の
            #   上に、全体の総数でも頭打ち=接続フラッドで OS を巻き込む前に新規受理を即切断する。
            if gcap > 0 and self._active > gcap:
                self.metrics["conn_rejected_global"] = self.metrics.get("conn_rejected_global", 0) + 1
                return self._close(writer)
            # #10: per-IP 接続レート上限(接続→即RST/即切断を高速反復する churn フラッド対策)。
            #   head 解析や backend 接続より *手前* で安価に shed する。既定 0=無効(NAT 巻添え回避)。
            if crate > 0 and ip and self._conn_rate_exceeded(ip, crate):
                self.metrics["conn_rate_rejected"] = self.metrics.get("conn_rate_rejected", 0) + 1
                return self._close(writer)
            if cap > 0 and ip:
                n = self._conn_per_ip.get(ip, 0)
                if n >= cap:                              # 同時接続上限超過=即切断(本体に通さない)
                    self.metrics["conn_rejected"] = self.metrics.get("conn_rejected", 0) + 1
                    return self._close(writer)
                self._conn_per_ip[ip] = n + 1
                counted = True
            if admission_stamp is None:
                await self._handle_conn(reader, writer, acl_jobs)
            else:
                await self._handle_conn(reader, writer, acl_jobs, admission_stamp)
        finally:
            try:
                for done in acl_jobs:
                    await done     # deny/early return を含め所有workerの結果を回収
            finally:
                if counted:
                    v = self._conn_per_ip.get(ip, 1) - 1
                    if v <= 0:
                        self._conn_per_ip.pop(ip, None)   # 0本になったIPは破棄
                    else:
                        self._conn_per_ip[ip] = v
                self._live.discard(writer)
                self._active -= 1

    def _defense_unavailable(self, what: str, exc) -> None:
        """防御機構を用意できなかったことを記録する(同じ原因は 1 度だけ表示)。
        黙って素通しすると『動いているのに守っていない』最悪の状態になるため、
        呼び出し側は必ず接続を落とすこと。"""
        self.metrics["defense_unavailable"] = self.metrics.get("defense_unavailable", 0) + 1
        key = f"{what}:{type(exc).__name__}"
        if key in self._defense_warned:
            return
        self._defense_warned.add(key)
        try:
            print(f"[重大] {what} を初期化できないため接続を遮断しています: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        except Exception:
            pass

    def _submit_log_job(self, writer_fn, work, kind: str):
        """ACL/使用量の共有単一workerへ非ブロック投入。"""
        global _USAGE_WORKER
        self._usage_process_local()
        loop = asyncio.get_running_loop()
        with _USAGE_CV:
            if (self._usage_closing or
                    len(_USAGE_QUEUE) + int(_USAGE_RUNNING is not None) >= _USAGE_LIMIT):
                metric = kind + "_log_dropped"
                self.metrics[metric] = self.metrics.get(metric, 0) + 1
                return None
            done = loop.create_future()
            job = (self, writer_fn, work, loop, done, kind)
            _USAGE_QUEUE.append(job)
            self._log_pending += 1
            if kind == "usage":
                self._usage_pending += 1
            else:
                self._acl_pending += 1
            _USAGE_OPEN.add(self)
            if _USAGE_WORKER is None or not _USAGE_WORKER.is_alive():
                worker = threading.Thread(target=_usage_worker_loop, daemon=True,
                                          name="ducknet-usage-log")
                _USAGE_WORKER = worker
                try:
                    worker.start()
                except Exception:
                    _USAGE_WORKER = None
                    _USAGE_QUEUE.pop()
                    self._log_pending -= 1
                    if kind == "usage":
                        self._usage_pending -= 1
                    else:
                        self._acl_pending -= 1
                    _USAGE_OPEN.discard(self)
                    metric = kind + "_log_write_failed"
                    self.metrics[metric] = self.metrics.get(metric, 0) + 1
                    return None
            _USAGE_CV.notify()
            return done

    def _submit_usage_log(self, shield, work):
        """旧テスト/内部呼出し向け互換ラッパ。"""
        return self._submit_log_job(shield.write_usage_log, work, "usage")

    def _close_usage_jobs(self):
        """停止時はこのguardの未開始行を破棄。実行中はpendingとして停止結果へ残す。"""
        self._usage_process_local()
        with _USAGE_CV:
            self._usage_closing = True
            _USAGE_OPEN.discard(self)
            removed = [job for job in _USAGE_QUEUE if job[0] is self]
            if removed:
                kept = [job for job in _USAGE_QUEUE if job[0] is not self]
                _USAGE_QUEUE.clear()
                _USAGE_QUEUE.extend(kept)
                self._log_pending -= len(removed)
                for job in removed:
                    kind = job[5]
                    if kind == "usage":
                        self._usage_pending -= 1
                    else:
                        self._acl_pending -= 1
                    metric = kind + "_log_dropped"
                    self.metrics[metric] = self.metrics.get(metric, 0) + 1
            _USAGE_CV.notify_all()
        for _guard, _writer_fn, _work, loop, done, _kind in removed:
            try:
                loop.call_soon_threadsafe(_complete_usage_future, done, False)
            except RuntimeError:
                pass

    async def _record_traffic_deferred(self, shield, ip, outbound, inbound, started,
                                       host, method, path, quota=None):
        """使用量判定の後、JSONLだけを有界workerへ渡して非同期に待つ。"""
        self._usage_process_local()
        try:
            with _USAGE_SUBMIT_LOCK:
                result = shield.record_traffic(
                    ip, out_bytes=outbound, in_bytes=inbound,
                    conn_sec=max(0.0, time.monotonic() - started), host=(host or "")[:255],
                    method=(method or "")[:32], path=path, _defer_log=True,
                    _egress_token=quota[1] if quota is not None else None,
                    _quota_hit=quota[2]["hit"] if quota is not None else False)
                work = result.get("_usage_log_work") if isinstance(result, dict) else None
                done = self._submit_usage_log(shield, work) if work is not None else None
        except Exception:
            self.metrics["usage_record_failed"] = self.metrics.get("usage_record_failed", 0) + 1
            return
        if done is not None:
            await done

    def _usage_process_local(self):
        """forkで継承したguardの未完件数を、子の空worker状態へ揃える。"""
        pid = os.getpid()
        if self._usage_pid != pid:
            self._usage_pid = pid
            self._log_pending = 0
            self._usage_pending = 0
            self._acl_pending = 0
            self._usage_closing = False

    async def _handle_conn(self, reader, writer, acl_jobs=None, admission_stamp=None):
        self.metrics["accepted"] += 1
        ip = ""
        try:
            peer = writer.get_extra_info("peername")
            if peer:
                ip = self._norm_ip(peer[0])      # #14: IPv4-mapped(::ffff:)を純IPv4へ
        except Exception:
            pass
        if not ip:
            self.metrics["dropped"] += 1
            return self._close(writer)             # peer 不明を loopback として許可しない
        # Slowloris等: ヘッダをだらだら送る接続はタイムアウトで即切断(Fail Fast)。
        # さらに反復犯はスコア加点→自動BAN(単発の低速回線は誤遮断しない)。
        try:
            buf = await self._read_head(reader)
        except asyncio.TimeoutError:
            self.metrics["dropped"] += 1
            self.metrics["slowloris"] = self.metrics.get("slowloris", 0) + 1
            try:
                from ..lifeform.pipeline import net_shield
                net_shield().penalize(ip, reason="slowloris: ヘッダ未完(だらだら送信)")
            except Exception:
                pass
            return self._close(writer)
        except Exception:
            self.metrics["dropped"] += 1
            return self._close(writer)
        if not buf:
            return self._close(writer)
        head_end = buf.find(b"\r\n\r\n")
        if head_end < 0 or head_end + 4 > _REQUEST_HEAD_MAX:
            # ヘッダ終端が未到達か、最後の read で上限の先に現れた。このまま進むと『検査面に載らないのに
            # backend へは転送される』ヘッダが生まれ(走査面 < 転送面)、WAF を素通りできる。
            # 転送せず 431 で拒否する(fail-closed)。framing 検査の死角も同時に塞ぐ。
            self.metrics["dropped"] += 1
            self.metrics["head_too_large"] = self.metrics.get("head_too_large", 0) + 1
            try:
                from ..lifeform.pipeline import net_shield
                net_shield().penalize(ip, reason="ヘッダ過大(終端未観測)=走査面外への押し出し",
                                      kind="head_too_large")
            except Exception:
                pass
            try:
                writer.write(_reject_response(
                    "431 Request Header Fields Too Large",
                    '{"ok":false,"error":"header too large"}',
                    _notice_page("headers") if _wants_html(buf) else None))
            except Exception:
                pass
            return self._close(writer)
        try:
            method, path, ua, host = _parse_head(buf)
        except Exception as exc:
            self.metrics["dropped"] += 1
            self._defense_unavailable("request_head", RuntimeError(type(exc).__name__))
            return self._close(writer)

        # 0y) 実クライアントIP解決(#32): 信頼 proxy 背後なら XFF から実IPを採る(rate-limit/ban/subnet が
        #     proxyIP に潰れない)。既定 trusted_proxies=[] は peer のまま=XFF を一切信頼しない(偽装無効)。
        peer_ip, _tp = ip, None
        origin_header_name = "X-Edge-Token"
        protected_headers_at_head = ()
        try:
            from ..lifeform.pipeline import net_shield as _ns
            _cfg_at_head = _ns().cfg
            _tp = _cfg_at_head.get("trusted_proxies")
            if _cfg_at_head.get("strip_cache_poison_headers", True):
                protected_headers_at_head = _cfg_at_head.get("cache_poison_headers") or ()
            _name_at_head = _cfg_at_head.get("origin_header", origin_header_name)
            if (isinstance(_name_at_head, str) and 0 < len(_name_at_head) <= 128
                    and _name_at_head.isascii()
                    and _FIELD_NAME.fullmatch(_name_at_head.encode("ascii"))):
                origin_header_name = _name_at_head
            if _tp:
                ip = self._norm_ip(_real_client_ip(ip, buf, _tp))   # #14: XFF 由来も正規化
        except Exception:
            _tp = None
        # 元接続が TLS だったか(#33)。ここで一度確定=shield 無効のパススルー時も定義される
        # (#65 の Set-Cookie Secure 付与判定で参照。後段で再計算しない)。
        tls = _forwarded_proto_tls(peer_ip, buf, _tp)

        # 0a) HTTP リクエストスマグリング: 曖昧な境界(CL.TE/重複CL)は上流へ流さず即拒否。
        #     バイト透過プロキシで『WAF 素通り→上流が隠し要求を実行』を構造的に封じる。
        if _framing_ambiguous(buf, origin_header=origin_header_name.lower().encode("ascii"),
                              protected_headers=protected_headers_at_head):
            self.metrics["dropped"] += 1
            writer.write(_reject_response("400 Bad Request",
                                          '{"error":"ambiguous message framing"}',
                                          _notice_page("framing") if _wants_html(buf) else None,
                                          extra=deception.headers_for(ip)))
            try:
                await writer.drain()
            except Exception:
                pass
            try:
                from ..lifeform.pipeline import net_shield
                net_shield().penalize(ip, reason="HTTP smuggling framing(CL/TE)",
                                      kind="smuggling")
            except Exception:
                pass
            return self._close(writer)

        # 0z) ヘルスチェック(opt-in): 正しい HTTP head だけに応答する。
        #     ここより前に 200 を返すと CL+TE/重複 Host でも「正常」を広告する。
        #     構造を確認した後は WAF/バックエンド非経由で最小ボディを返す。
        if self.health_path and path.split("?", 1)[0] == self.health_path:
            # Normal traffic cannot pass an unavailable firewall or shield.
            # Do not tell an orchestrator this instance is ready while those
            # same mandatory sources would fail its request gate.
            try:
                from ..lifeform.policy import app_firewall
                from ..lifeform.pipeline import net_shield
                firewall = app_firewall()
                shield = net_shield()
                fw_ready = firewall.is_enabled()
                sh_ready = shield.is_enabled()
                if type(fw_ready) is not bool or type(sh_ready) is not bool:
                    raise ValueError("invalid defense readiness")
                # A signed-state integrity latch intentionally denies normal
                # enforce traffic. A successful health response must not hide
                # that condition behind the still-boolean enabled switch.
                with firewall._lock:
                    if firewall._load_warning:
                        raise ValueError("firewall state is untrusted")
                with shield._lock:
                    if sh_ready and any((shield._cfg_state_untrusted,
                                         shield._sig_state_untrusted,
                                         shield._ban_state_untrusted)):
                        raise ValueError("shield state is untrusted")
                    if (sh_ready and shield._traffic_state_untrusted
                            and shield.cfg.get("quota_enabled") is True):
                        max_gb = float(shield.cfg.get("quota_max_gb", 0) or 0)
                        max_sec = float(shield.cfg.get("quota_max_conn_sec", 0) or 0)
                        if not math.isfinite(max_gb) or not math.isfinite(max_sec):
                            raise ValueError("quota state is invalid")
                        if max_gb > 0 or max_sec > 0:
                            raise ValueError("quota history is untrusted")
            except Exception as exc:
                self._defense_unavailable("health_readiness", exc)
                self.metrics["dropped"] += 1
                writer.write(_http_response("503 Service Unavailable",
                                            '{"status":"unavailable"}'))
                try:
                    await writer.drain()
                except Exception:
                    pass
                return self._close(writer)
            self.metrics["health"] = self.metrics.get("health", 0) + 1
            writer.write(_http_response("200 OK", '{"status":"ok"}'))
            try:
                await writer.drain()
            except Exception:
                pass
            return self._close(writer)

        # 1) アプリ層ファイアウォール(deny/pending は即TCP切断=444相当)
        zone = ""
        try:
            from ..lifeform.policy import app_firewall, _zone_of
            fw = app_firewall()
            fw_enabled = fw.is_enabled()
        except Exception as e:
            # 取得に失敗した=判定できない。すぐ下の evaluate() は fail-closed なのに
            # ここだけ素通しだった。防御を張れないまま通すくらいなら落とす。
            self._defense_unavailable("app_firewall", e)
            self.metrics["dropped"] += 1
            return self._close(writer)
        if fw_enabled:
            try:
                if acl_jobs is None:
                    decision = fw.evaluate(ip)   # 直接呼出しの従来同期契約
                else:
                    with _USAGE_SUBMIT_LOCK:
                        decision = fw.evaluate(ip, _defer_log=True)
                        work = (decision.get("_acl_log_work")
                                if isinstance(decision, dict) else None)
                        if work is not None:
                            try:
                                done = self._submit_log_job(fw.write_acl_log, work, "acl")
                            except Exception:
                                self.metrics["acl_log_dropped"] = (
                                    self.metrics.get("acl_log_dropped", 0) + 1)
                                done = None
                            if done is not None:
                                acl_jobs.append(done)
                fw_allowed = decision.get("action") == "allow"
            except Exception:
                fw_allowed = False    # フェイルクローズ: 判定不能を「許可」にしない(#111)
            if not fw_allowed:
                self.metrics["dropped"] += 1
                return self._close(writer)
        if fw is not None:
            try:
                zone = _zone_of(ip)
            except Exception:
                zone = ""
        # 2) L7 DDoS/侵入防御(v2): block/throttle は即解放
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            shield_enabled = sh.is_enabled()
        except Exception as e:
            # WAF 本体を用意できない(state dir が書けない/ENOSPC 等)。シングルトンは
            # 成功時にしか確定しないので、以後プロセスの寿命いっぱい無防備なまま通り続ける。
            # 検知ゲートと同じく fail-closed にし、原因を 1 度だけ表に出す。
            self._defense_unavailable("net_shield", e)
            self.metrics["dropped"] += 1
            return self._close(writer)
        # 判定を要求時にラッチする。応答までの間に設定から私有経路が消えても、
        # この応答の no-store を外さない。backend が採り得る path override も含める。
        private_paths = (path,) + tuple(
            value for name in (b"x-original-url", b"x-rewrite-url", b"x-override-url")
            for value in _header_values(buf, name))
        try:
            private_response = (bool(sh.cfg.get("private_paths"))
                                and any(sh.private_path_matches(value) for value in private_paths))
        except Exception as exc:
            self._defense_unavailable("private_path", exc)
            self.metrics["dropped"] += 1
            return self._close(writer)
        if shield_enabled and not host and sh.cfg.get("site_mode") in ("whitelist", "blacklist"):
            # HTTP/1.0 は Host 省略が合法だが、サイト制御では宛先を評価できない。
            # backend の既定 vhost だけが黒/白リスト対象になる差を作らない。
            self.metrics["dropped"] += 1
            writer.write(_reject_response("400 Bad Request",
                                          '{"error":"host required for site policy"}'))
            try:
                await writer.drain()
            except Exception:
                pass
            return self._close(writer)
        if shield_enabled:
            _p = path.split("?")[0]
            # 解除リクエスト(異議申立)経路はBAN判定の手前=遮断中のユーザーでも到達できる。
            if _p == _APPEAL_PATH:
                try:
                    return await self._handle_appeal(ip, path, sh, writer,
                                                      html=_wants_html(buf))
                except Exception:
                    # _handle は try/finally のみ(except無し)で、ここで漏らすと接続が
                    # 誰にも close されないまま残る(#111 の副作用で新たに生じた握り漏れ)。
                    return self._close(writer)
            # 0) 既知BANの瞬殺プリスキャン(ブルーム・ロックなしほぼO(1))。重い inspect
            #    (ロック/正規表現/state)へ行く手前で、執拗な再攻撃Botをビット演算で即落とす。
            #    失敗時はフェイルオープン=下の inspect() がロック下で BAN 状態を再判定する。
            try:
                _banned_fast = sh.is_banned_fast(ip)
            except Exception:
                _banned_fast = False
            if _banned_fast:
                self.metrics["dropped"] += 1
                if sh.cfg.get("block_page"):
                    return await self._serve_block_page(ip, sh, writer)
                return self._close(writer)        # 444相当・inspectを呼ぶことすら贅沢
            q = path.split("?", 1)[1] if "?" in path else ""
            # 単一値ヘッダの重複/食い違い(#16 #17 #57): Authorization / X-API-Key が複数本、または
            #   メソッド override の値が複数(同名の重複・別名の併用・カンマ列挙)だと、検査した値と
            #   backend が採る値が一致する保証が無い(Node/Go は先頭の 1 本、Express の
            #   method-override は先頭トークン、別名は backend の設定次第)。連結値を検査していた
            #   ため alg:none JWT・遮断メソッド・クレデンシャル単位レートを全て素通りできた。
            #   どれを採っても安全と言えないので 400 で拒否する(正規クライアントは送らない形)。
            #   ただし mode=audit(記録のみ・遮断しない)では拒否せず『遮断するはずだった』を記録して
            #   先へ進む(#34。_enforce_or_audit と同じ audit イベント+転送。検査には先頭の値を渡す)。
            _auths = _header_values(buf, b"authorization")
            _keys = _header_values(buf, b"x-api-key")
            _ovrs = list(dict.fromkeys(
                t.strip().upper()
                for _n in (b"x-http-method-override", b"x-method-override", b"x-http-method")
                for v in _header_values(buf, _n) for t in v.split(",") if t.strip()))
            _dup = len(_auths) > 1 or len(_keys) > 1 or len(_ovrs) > 1
            if _dup and sh.cfg.get("mode") == "audit":
                self.metrics["dup_header"] = self.metrics.get("dup_header", 0) + 1
                try:
                    sh._event(ip, "audit", {"would": "block", "rule": "dup_header",
                                            "reason": "conflicting header values"})
                    sh._forward(ip, "dup_header", "suspicious",
                                ["would block: conflicting header values"])
                except Exception:
                    pass
            elif _dup:
                self.metrics["dropped"] += 1
                self.metrics["dup_header"] = self.metrics.get("dup_header", 0) + 1
                writer.write(_reject_response(
                    "400 Bad Request", '{"error":"conflicting header values"}',
                    _notice_page("conflict") if _wants_html(buf) else None,
                    extra=deception.headers_for(ip)))
                try:
                    await writer.drain()
                except Exception:
                    pass
                return self._close(writer)
            _auth = _auths[0] if _auths else ""
            # #70: クレデンシャル識別子は *載っている全部* を渡す(Bearer と X-API-Key の両方)。
            #   Bearer があると X-API-Key を数えていなかったため、毎回ランダムな Bearer を添えて
            #   盗んだ API キーで認証させると識別子が毎回変わり、キー単位の上限が発動しなかった。
            _creds = ((_auth[7:].strip() if _auth[:7].lower() == "bearer " else ""),
                      (_keys[0] if _keys else ""))
            _ovr = _ovrs[0] if _ovrs else ""             # #72: メソッド override
            # backend ごとに採る別名/重複行が違うので、全候補を入口policyへ渡す。
            # 先頭の良性値だけだと後続の私有経路 rewrite を見落とす。
            _opath = private_paths[1:]                              # #73: パス override
            # 判定不能(例外)を「許可」にしない=フェイルクローズ(#111)。ここは唯一の
            # 実質的な検知ゲートなので、握りつぶして通すと WAF/DDoS 防御が丸ごとバイパスされる。
            try:
                header_view = _scan_header_values(buf)
                header_names = _header_names(buf)
            except Exception as exc:
                if sh.cfg.get("mode") != "audit":
                    self.metrics["dropped"] += 1
                    self._defense_unavailable("header_scan",
                                              RuntimeError(type(exc).__name__))
                    return self._close(writer)
                # Audit intentionally forwards but must not record this as
                # a clean inspection. If even the audit event cannot be
                # recorded, do not silently release the unknown header.
                try:
                    sh._event(ip, "audit", {"would": "block",
                                            "rule": "header_scan_unavailable"})
                except Exception:
                    self.metrics["dropped"] += 1
                    return self._close(writer)
                header_view, header_names = "", []
            try:
                d = sh.inspect(ip, path=path.split("?")[0], method=method,
                               user_agent=ua, query=q, zone=zone, tls=tls, host=host,
                               headers=header_view,
                               header_names=header_names,
                               auth=_auth, cred=_creds, override_method=_ovr,
                               override_path=_opath,
                               range_header=_header_value(buf, b"range"))   # #76
            except Exception:
                self.metrics["dropped"] += 1
                return self._close(writer)
            act = d.get("action")
            if act == "block":
                self.metrics["dropped"] += 1
                if sh.cfg.get("block_page"):
                    return await self._serve_block_page(ip, sh, writer)
                return self._close(writer)
            if act == "throttle":
                self.metrics["dropped"] += 1
                # レート超過: 標準的な 429 + Retry-After を返してまっとうなクライアント/SDK に
                # バックオフを促す(従来は無言TCP切断=正規クライアントは理由不明で困る)。
                # opt-out(throttle_response=False)で従来挙動へ。応答後は即 close=Fail Fast。
                if sh.cfg.get("throttle_response", True):
                    ra = max(0, int(sh.cfg.get("throttle_retry_after", 1) or 0))
                    writer.write(_reject_response("429 Too Many Requests", _jsonify(
                        {"ok": False, "defense": "rate-limit", "retry_after": ra}),
                        _rate_page(ra) if _wants_html(buf) else None,
                        extra=list(deception.headers_for(ip)) + [("Retry-After", ra)]))
                    try:
                        await writer.drain()
                    except Exception:
                        pass
                return self._close(writer)        # Fail Fast=スレッド非消費
            if act != "allow":
                # 既知アクション(block/throttle/allow)以外へ来た=判定不能。
                # フェイルクローズ(#111): 未知アクションを backend 素通し(=許可)にしない。
                self.metrics["dropped"] += 1
                return self._close(writer)
        # 本文を検査し終わるまで backend ソケットを確保しない。遅い/悪性 POST が
        # backend の接続枠だけを大量に占有することを防ぐ。
        bodyless = not _request_declares_body(buf)
        _bctx, extra = {}, b""
        if not bodyless:
            _bctx["stage_start"] = asyncio.get_running_loop().time()
            _bctx["deadline"] = self._body_deadline()
        if bodyless and "?" in path:
            try:
                _gq = sh.inspect_graphql(ip, path, b"").get("action")
            except Exception:
                _gq = "block"
            if _gq in ("block", "reject"):
                self.metrics["dropped"] += 1
                return self._close(writer)
        if not bodyless:
            try:
                extra, blocked = await self._scan_request_body(buf, reader, ip, path, _bctx,
                                                               writer=writer)
            except Exception as exc:
                self._defense_unavailable("request_body", exc)
                self.metrics["dropped"] += 1
                return self._close(writer)
            if blocked:
                self.metrics["dropped"] += 1
                _rej = {"unscannable": ("415 Unsupported Media Type",
                                        '{"ok":false,"error":"unsupported content-encoding"}'),
                        "too_large": ("413 Payload Too Large",
                                      '{"ok":false,"error":"graphql request too large"}'),
                        "body_too_large": ("413 Payload Too Large",
                                           '{"ok":false,"error":"request body exceeds scan limit"}'),
                        "malformed_chunked": ("400 Bad Request",
                                              '{"error":"malformed chunked body"}')
                        }.get(blocked) if isinstance(blocked, str) else None
                if _rej:
                    try:
                        if blocked in ("unscannable", "too_large", "body_too_large"):
                            await self._drain_rejected_body(reader, buf, extra)
                        _page = None
                        if _wants_html(buf):
                            if blocked in ("too_large", "body_too_large"):
                                try:
                                    _lim = (sh.graphql_max_bytes(path) if blocked == "too_large" else
                                            int(sh.cfg.get("body_scan_max_bytes", 65536)))
                                except Exception:
                                    _lim = None
                                _page = _too_large_page(_lim)
                            elif blocked == "malformed_chunked":
                                _page = _notice_page("body")
                            else:
                                _page = _notice_page("encoding")
                        writer.write(_reject_response(_rej[0], _rej[1], _page,
                                                      extra=deception.headers_for(ip)))
                        await writer.drain()
                    except Exception:
                        pass
                return self._close(writer)
        # 3) allow → 検査済み要求だけをバックエンドへ非同期パイプ
        if admission_stamp is not None:
            # A parent publication during header/body inspection invalidates
            # this request's earlier policy decision. Drop it before opening
            # the backend; the next admission will inspect with the new policy.
            try:
                current_stamp = self._sync_cluster_policy()
                if current_stamp != admission_stamp:
                    self.metrics["dropped"] += 1
                    return self._close(writer)
            except Exception as exc:
                self._defense_unavailable("cluster_policy", exc)
                self.metrics["dropped"] += 1
                return self._close(writer)
        start = time.monotonic()            # 経過秒は壁時計の巻戻し/ジャンプに左右されない
        quota = (sh, object(), {"hit": False, "policy_stamp": admission_stamp})
        try:
            quota[2]["time_ok"] = sh.begin_egress_time(ip, quota[1], start)
            quota[2]["time_watch"] = sh.has_egress_time_lease(quota[1])
        except Exception as exc:
            self._defense_unavailable("egress_quota", exc)
            self.metrics["dropped"] += 1
            try:
                sh.finalize_egress(quota[1])
            except Exception as settle_exc:
                self._defense_unavailable("egress_quota_accounting", settle_exc)
            return self._close(writer)
        if not quota[2]["time_ok"]:
            self.metrics["dropped"] += 1
            try:
                sh.note_egress_quota_block(ip)
            finally:
                try:
                    sh.finalize_egress(quota[1])
                except Exception as settle_exc:
                    self._defense_unavailable("egress_quota_accounting", settle_exc)
                self._close(writer)
            return
        stage, stage_size = None, 0
        if not bodyless:
            try:
                stage, stage_size, stage_error = await self._stage_request_body(
                    buf, extra, reader, writer, _bctx, sh, ip)
            except asyncio.CancelledError:
                try:
                    sh.finalize_egress(quota[1])
                except Exception as settle_exc:
                    self._defense_unavailable("egress_quota_accounting", settle_exc)
                raise
            except Exception as exc:
                self._defense_unavailable("request_body_stage", exc)
                stage_error = "unavailable"
            if stage_error is not None:
                self.metrics["dropped"] += 1
                try:
                    sh.finalize_egress(quota[1])
                except Exception as settle_exc:
                    self._defense_unavailable("egress_quota_accounting", settle_exc)
                if stage_error in ("too_large", "busy", "unavailable",
                                   "malformed_chunked", "malformed"):
                    status, body = {
                        "too_large": ("413 Payload Too Large", '{"ok":false,"error":"request body too large"}'),
                        "busy": ("503 Service Unavailable", '{"ok":false,"error":"body staging busy"}'),
                        "unavailable": ("503 Service Unavailable", '{"ok":false,"error":"body staging unavailable"}'),
                        "malformed_chunked": ("400 Bad Request", '{"error":"malformed chunked body"}'),
                        "malformed": ("400 Bad Request", '{"ok":false,"error":"malformed request body"}'),
                    }[stage_error]
                    try:
                        writer.write(_reject_response(status, body,
                                                     _notice_page("body") if _wants_html(buf) else None,
                                                     extra=deception.headers_for(ip)))
                        await writer.drain()
                    except Exception:
                        pass
                return self._close(writer)
        try:
            bre, bwr = await self._open_backend()
        except asyncio.CancelledError:
            await self._release_staged_body(stage, stage_size)
            try:
                sh.finalize_egress(quota[1])
            except Exception as settle_exc:
                self._defense_unavailable("egress_quota_accounting", settle_exc)
            raise
        except Exception:
            cleanup_cancelled = await self._release_staged_body(stage, stage_size)
            try:
                sh.finalize_egress(quota[1])
            except Exception as settle_exc:
                self._defense_unavailable("egress_quota_accounting", settle_exc)
            if cleanup_cancelled:
                raise asyncio.CancelledError()
            # バックエンド不達: 従来は無言TCP切断で運用者に何も見えなかった(accepted 以外の
            # 指標が動かず=停止に気付けない)。正規クライアントには標準的な 502 を返し、
            # 指標にも構造的に残す(このLite版は txnlog を持たないため metrics のみ)。
            self.metrics["backend_unreachable"] = (
                self.metrics.get("backend_unreachable", 0) + 1)
            writer.write(_reject_response("502 Bad Gateway", _jsonify(
                {"ok": False, "error": "backend unreachable"}),
                _notice_page("down") if _wants_html(buf) else None,
                extra=deception.headers_for(ip)))
            try:
                await writer.drain()
            except Exception:
                pass
            return self._close(writer)
        inbound = len(buf)                            # client→backend(ヘッダ分)
        outbound = 0                                  # backend→client(=持ち出し量)
        try:
            time_left = sh.egress_time_remaining(ip, quota[1])
            if time_left is not None and time_left <= 0:
                # A slow backend connect may consume the remaining budget.
                # Never send request bytes once that is known.
                quota[2]["hit"] = True
                self.metrics["dropped"] += 1
                sh.note_egress_quota_block(ip)
                raise _EgressQuotaReached()
            # 転送ヘッダの整形: keep-alive 検査回避封じ(#31)+ 信頼proxy時の XFF 上書き(#35)。
            try:
                from ..lifeform.pipeline import net_shield as _ns
                _fcc = bool(_ns().cfg.get("force_conn_close", True))
            except Exception:
                _fcc = True                           # 取得失敗時も安全側(close)
            fwd = _force_conn_close(buf) if _fcc else buf   # #31: 既定で Connection: close
            # クライアント供給の実IP/プロトコル系ヘッダの扱い(#spoof + #35):
            #   信頼proxy経由 → 解決済み実クライアントIPで X-Forwarded-For/X-Real-IP を上書き。
            #   直結/非信頼   → 真の TCP peer で XFF/X-Real-IP を上書きし、偽装され得る
            #     X-Forwarded-Proto / Forwarded は除去する。旧実装は trusted_proxies 未設定の
            #     既定でこれらを *無改変* に backend へ流し、直結の攻撃者が XFF/X-Real-IP で内部IP
            #     偽装(IP allowlist/レート回避・ログ汚染)、XFP: https で TLS 偽装(HTTP→HTTPS
            #     リダイレクト無効化・平文経由の Secure Cookie 送出)を backend に信じ込ませ得た。
            try:
                from ..lifeform.netutil import ip_in_any as _ipin
                _trusted_peer = bool(_tp) and _ipin(peer_ip, _tp)
            except Exception:
                _trusted_peer = False
            if _trusted_peer:
                fwd = _set_forwarded_for(fwd, ip)     # backendが偽装不能な実クライアントIPを得る
            else:
                fwd = _strip_request_headers(fwd, (b"x-forwarded-proto", b"forwarded"))
                fwd = _set_forwarded_for(fwd, peer_ip)   # 真の peer で XFF/X-Real-IP を上書き
            # #75: 信頼 proxy 経由でないクライアント供給のキャッシュ汚染ヘッダ(X-Forwarded-Host 等)を
            #   除去。バックエンドが反映してのキャッシュ汚染/パスワードリセット・ポイズニングを防ぐ。
            try:
                from ..lifeform.pipeline import net_shield as _ns2
                _scfg = _ns2().cfg
                if _scfg.get("strip_cache_poison_headers", True):
                    from ..lifeform.netutil import ip_in_any
                    if not (_tp and ip_in_any(peer_ip, _tp)):   # 直結 or 非信頼 peer のみ除去
                        fwd = _strip_request_headers(fwd, _scfg.get("cache_poison_headers") or [])
                # #77: バックエンド・バイパス防止。エッジ経由を証明する時間有界トークンを付与
                #   (バックエンドが検証し迂回直叩きを拒否)。鍵は env で共有。クライアント供給の
                #   同名ヘッダは _set_request_header が除去するので偽装できない。
                if _scfg.get("origin_cloaking_enabled"):
                    _okey = os.environ.get("DUCKNET_ORIGIN_KEY", "")
                    if not _okey:
                        raise ValueError("configured origin key is unavailable")
                    from ..core.origin import origin_token
                    fwd = _set_request_header(
                        fwd, origin_header_name,
                        origin_token(_okey, window=float(_scfg.get("origin_window_sec", 30))))
            except Exception as exc:
                # A failed cache-header strip or origin-token generation must
                # not turn an enabled request defense into raw backend traffic.
                self.metrics["dropped"] += 1
                self._defense_unavailable("request_forwarding",
                                          RuntimeError(type(exc).__name__))
                raise
            # #1: 出口 DLP が有効なら backend に *無圧縮* で返させる(Accept-Encoding: identity)。
            #   ブラウザは常に gzip/br を広告するので、素通しすると圧縮された応答本文を DLP が
            #   読めず、block でも秘密がそのまま届いていた。それでも圧縮で返ってきた本文は _pipe が
            #   dlp_unscannable として dlp_action どおりに扱う(応答を検査する WAF の通例)。
            try:
                from ..lifeform.pipeline import net_shield as _ns3
                if _ns3().dlp_active():
                    fwd = _set_request_header(fwd, "Accept-Encoding", "identity")
            except Exception:
                pass
            # #46: 本文皆無(CL/TE 無し)の要求は head 以降のバイトがパイプライン第2要求=
            #   未検査でバックエンドへ届く。head のみに切り詰め、client→backend パイプも張らない。
            #   この backend 接続へ追加の要求バイトを書かないので、backend が Connection: close を
            #   尊重するかに依存せず第2要求は届かない。TCP write_eof は送らない。Nginx 等は
            #   正しい HTTP 本文境界の後でも早い FIN を「client closed」として応答を捨てる。
            if _bctx.get("continued"):
                # DuckNet が返した 100 Continue を backend に重複させない。
                fwd = _strip_request_headers(fwd, (b"expect",))
            if bodyless:
                _h, _sep, _ = fwd.partition(b"\r\n\r\n")
                if _sep:
                    fwd = _h + b"\r\n\r\n"            # パイプライン第2要求を投棄
                await self._checked_backend_write(bwr, fwd, admission_stamp)
                # Count a proxied request only after its inspected head has
                # crossed the backend write barrier. A successful TCP connect
                # alone does not mean a forwarding defense allowed any bytes.
                self.metrics["proxied"] += 1
                outbound += await self._pipe(bre, writer, scan=True, ip=ip, tls=tls, req_host=host,
                                             req_paths=private_paths,
                                             private_response=private_response, req_method=method,
                                             strict_http=True, quota=quota)
            else:
                # The whole bounded wire body was validated before this backend
                # connection existed. Replay only its declared CL/chunked bytes.
                replay_deadline = asyncio.get_running_loop().time() + _BODY_STAGE_MAX_SEC
                head = fwd.partition(b"\r\n\r\n")[0] + b"\r\n\r\n"
                await self._checked_backend_write(bwr, head, admission_stamp, replay_deadline)
                self.metrics["proxied"] += 1
                inbound = len(buf.partition(b"\r\n\r\n")[0]) + 4 + stage_size
                # An origin may send a final 4xx/5xx after the request head
                # and stop reading. Do not hold 64 MiB of staged quota until
                # the upstream zero-window write timeout. Only a complete,
                # strictly framed early error can stop replay; its untrusted
                # bytes are never copied to the client.
                early_heads = bytearray()

                async def watch_early_response():
                    for _ in range(_MAX_INTERIM_HEADS + 1):
                        try:
                            response = await bre.readuntil(b"\r\n\r\n")
                        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                                OSError):
                            return "invalid", 0
                        if len(early_heads) + len(response) > _RESPONSE_HEAD_MAX:
                            return "invalid", 0
                        early_heads.extend(response)
                        response_head = response[:-4]
                        if _response_head_problem(response_head):
                            return "invalid", 0
                        code = _resp_status(response_head.split(b"\r\n", 1)[0])
                        if _is_interim(code):
                            continue
                        if code == 101:
                            return "invalid", 0
                        return ("reject" if 400 <= code <= 599 else "other"), code
                    return "invalid", 0

                watcher = asyncio.create_task(watch_early_response())
                early_result = None

                async def write_or_reject(part):
                    nonlocal early_result
                    if early_result is None and watcher.done():
                        early_result = watcher.result()
                    if early_result is not None and early_result[0] in ("reject", "invalid"):
                        return False
                    sending = asyncio.create_task(self._checked_backend_write(
                        bwr, part, admission_stamp, replay_deadline))
                    try:
                        if early_result is None:
                            done, _ = await asyncio.wait((sending, watcher),
                                                         return_when=asyncio.FIRST_COMPLETED)
                            if watcher in done:
                                early_result = watcher.result()
                                if early_result[0] in ("reject", "invalid"):
                                    if not sending.done():
                                        sending.cancel()
                                    await asyncio.gather(sending, return_exceptions=True)
                                    return False
                        await sending
                        return True
                    except BaseException:
                        if not sending.done():
                            sending.cancel()
                            await asyncio.gather(sending, return_exceptions=True)
                        raise

                stopped_early = False
                try:
                    if isinstance(stage, list):
                        for part in stage:
                            if not await write_or_reject(bytes(part)):
                                stopped_early = True
                                break
                    else:
                        while True:
                            if stage_size > _BODY_STAGE_MEMORY:
                                part = await self._stage_file_call(stage.read, 65536)
                            else:
                                part = stage.read(65536)
                            if not part:
                                break
                            if not await write_or_reject(part):
                                stopped_early = True
                                break
                finally:
                    if not watcher.done():
                        watcher.cancel()
                    await asyncio.gather(watcher, return_exceptions=True)
                if stopped_early:
                    try:
                        bwr.transport.abort()  # discard any queued request tail
                    except Exception:
                        self._close(bwr)
                    if early_result is None or early_result[0] != "reject":
                        self.metrics["backend_invalid_response"] = (
                            self.metrics.get("backend_invalid_response", 0) + 1)
                        try:
                            if sh.dlp_active():
                                sh.note_unscannable(ip, "response-head")
                        except Exception as exc:
                            self._defense_unavailable("response_shield", exc)
                        raise RuntimeError("invalid early backend response")
                    finished_stage, finished_size = stage, stage_size
                    stage, stage_size = None, 0
                    if await self._release_staged_body(finished_stage, finished_size):
                        raise asyncio.CancelledError()
                    origin_code = early_result[1]
                    # Keep the numeric 4xx for response-aware enumeration and
                    # credential-abuse scoring. The reason/body are generated
                    # locally; no untrusted origin header is copied.
                    status = (f"{origin_code} Rejected" if origin_code < 500
                              else "502 Bad Gateway")
                    if origin_code == 413:
                        status = "413 Payload Too Large"
                    body = '{"ok":false,"error":"backend rejected request before complete body"}'
                    local = asyncio.StreamReader()
                    local.feed_data(_reject_response(
                        status, body, _notice_page("body" if early_result[1] == 413 else "down")
                        if _wants_html(buf) else None, extra=deception.headers_for(ip)))
                    local.feed_eof()
                    outbound += await self._pipe(
                        local, writer, scan=True, ip=ip, tls=tls, req_host=host,
                        req_paths=private_paths, private_response=private_response,
                        req_method=method, strict_http=True, quota=quota)
                else:
                    # Staging already removed pipelined suffixes. Let the
                    # origin answer the complete framed message; half-close
                    # here aborts buffered requests in Nginx.
                    finished_stage, finished_size = stage, stage_size
                    stage, stage_size = None, 0
                    if await self._release_staged_body(finished_stage, finished_size):
                        raise asyncio.CancelledError()
                    outbound += await self._pipe(
                        bre, writer, scan=True, ip=ip, tls=tls, req_host=host,
                        req_paths=private_paths, private_response=private_response,
                        req_method=method, strict_http=True, quota=quota,
                        prefetched=bytes(early_heads))
        except Exception:
            pass
        finally:
            self._close(writer)
            self._close(bwr)
            release_cancelled = False
            # データ漏洩防止: 送出量/接続時間を集計(上限超過時はNetShieldが当該IPを遮断)
            # host/method/path も渡す(渡さないと使用量の宛先サイト内訳と usage_log の
            # host/method/path が常に空)。Host/method は攻撃者が任意長で送れるので、宛先キー/
            # ログ行が青天井にならないよう DNS 名の上限程度に切る(path は記録側で切る)。
            try:
                release_cancelled = await self._release_staged_body(stage, stage_size)
                try:
                    await self._record_traffic_deferred(sh, ip, outbound, inbound, start,
                                                        host, method, path, quota=quota)
                except Exception:
                    pass
            finally:
                # If usage logging/accounting failed, keep possibly delivered
                # reserved bytes charged instead of reopening the quota.
                sh.finalize_egress(quota[1])
            if release_cancelled:
                raise asyncio.CancelledError()

    def _apply_redirect_policy(self, head: bytes, req_host: str, ip: str = "") -> bytes:
        """Enforce the same host policy for 3xx Location and Refresh navigation."""
        sh = None
        mode = "enforce"                 # unknown policy state must not release an unchecked head
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            mode = sh.cfg.get("open_redirect_mode", "enforce")
            if mode not in ("enforce", "audit"):
                raise ValueError("unknown redirect policy mode")
            text = head.decode("latin1")
            lines = text.split("\r\n")
            if not lines or not lines[0].startswith("HTTP/"):
                return head
            vhost = _redirect_violation_host(lines[0], lines[1:], req_host,
                                             sh.cfg.get("open_redirect_allow"))
            if not vhost:
                return head
            self.metrics["open_redirect"] = self.metrics.get("open_redirect", 0) + 1
            try:
                sh._event(ip, "open_redirect",
                          {"to": vhost[:80], "mode": mode})
                sh._forward(ip, "open_redirect", "suspicious", signals=[vhost])
            except Exception:
                pass
            if mode != "enforce":
                return head                          # audit=記録のみ・応答は不変
            safe = str(sh.cfg.get("open_redirect_safe_path", "/")) or "/"
            out = [lines[0]]
            for ln in lines[1:]:
                name = ln.partition(":")[0].strip().lower()
                if name == "location" and _redirect_violation_host(
                        lines[0], [ln], req_host, sh.cfg.get("open_redirect_allow")):
                    out.append("Location: " + safe)  # 外部許可外→安全パスへ書換(無害化)
                elif name == "refresh" and _redirect_violation_host(
                        lines[0], [ln], req_host, sh.cfg.get("open_redirect_allow")):
                    out.append("Refresh: 0; URL=" + safe)
                else:
                    out.append(ln)
            return "\r\n".join(out).encode("latin1", "replace")
        except Exception as exc:
            self.metrics["redirect_policy_failed"] = (
                self.metrics.get("redirect_policy_failed", 0) + 1)
            if mode == "audit" and sh is not None:
                # Audit keeps the origin wire, but an unexamined response must
                # be visible as such instead of looking like a clean redirect.
                sh._event(ip, "audit", {"would": "block",
                                         "rule": "redirect_policy_unavailable"})
                return head
            # The response head has not been sent yet. Let _pipe close rather
            # than publishing an external Location after an enforce failure.
            self._defense_unavailable("redirect_policy",
                                      RuntimeError(type(exc).__name__))
            raise

    def _on_slow_body(self, ip):
        """要求ボディの総受信が body_max_sec を超えた(R-U-Dead-Yet 系)時の処理(#64):
        メトリクス計上 + 当該IPへ slow_body 加点(反復で BAN・単発の遅い回線は誤遮断しない)。"""
        self.metrics["slow_body"] = self.metrics.get("slow_body", 0) + 1
        try:
            from ..lifeform.pipeline import net_shield
            net_shield().penalize(ip, reason="slow request body(R-U-Dead-Yet)",
                                  kind="slow_body")
        except Exception:
            pass

    def _body_deadline(self):
        """要求ボディの総受信デッドライン(loop 時刻)。無効なら None(従来=無制限)。"""
        loop = asyncio.get_event_loop()
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            if not sh.cfg.get("body_timeout_enabled"):
                return None
            seconds = float(sh.cfg.get("body_max_sec", 60))
            if math.isfinite(seconds) and seconds > 0:
                return loop.time() + seconds
        except Exception:
            pass
        return loop.time()         # 有効期限を読めない場合は無期限へ降格しない

    async def _drain_rejected_body(self, reader, buf: bytes, extra: bytes = b""):
        """Read a small rejected POST to its boundary so a 413/415 is deliverable.

        On Windows, closing a socket with unread request bytes can reset it before
        the client receives the response. Never wait for a large or slow body.
        """
        received = buf.partition(b"\r\n\r\n")[2] + extra
        content_length = _header_value(buf, b"content-length")
        loop = asyncio.get_event_loop()
        deadline = loop.time() + _REJECT_DRAIN_SEC
        if content_length.isdigit():
            size = int(content_length)
            if size > _REJECT_DRAIN_MAX:
                return
            remaining = max(0, size - len(received))
            while remaining and loop.time() < deadline:
                try:
                    part = await asyncio.wait_for(reader.read(min(65536, remaining)),
                                                  deadline - loop.time())
                except (asyncio.TimeoutError, OSError):
                    return
                if not part:
                    return
                remaining -= len(part)
            return
        if _header_value(buf, b"transfer-encoding").lower() != "chunked":
            return
        tracker = _ChunkedEnd()
        tracker.feed(received)
        count = len(received)
        while not (tracker.done or tracker.bad) and count < _REJECT_DRAIN_MAX:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            try:
                part = await asyncio.wait_for(reader.read(min(65536, _REJECT_DRAIN_MAX - count)),
                                              remaining)
            except (asyncio.TimeoutError, OSError):
                return
            if not part:
                return
            count += len(part)
            tracker.feed(part)

    @staticmethod
    def _raw_deflate_stored_head(data: bytes) -> bool:
        """Whether the same bytes begin a syntactically valid raw stored block."""
        if len(data) < 5 or data[0] & 0x06:  # BTYPE must be 00
            return False
        length = data[1] | data[2] << 8
        complement = data[3] | data[4] << 8
        return length ^ complement == 0xffff

    @staticmethod
    def _deflate_views(data: bytes, max_out: int):
        """Bound both zlib-wrapped and raw readings of one deflate entity."""
        import zlib
        views = []
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                d = zlib.decompressobj(wbits)
                out = d.decompress(data, max_out)
            except (ValueError, zlib.error):
                views.append(None)
                continue
            # A backend may stop at EOF and ignore unused_data. Preserve that
            # reading for ambiguity checks, even though DuckNet requires a
            # strict boundary before accepting it as the canonical entity.
            views.append((out, d.eof, not d.unused_data and not d.unconsumed_tail))
        return views

    @staticmethod
    def _decompress_bounded(data: bytes, encoding: str, max_out: int = 262144):
        """要求ボディを有界に解凍する(#74)。gzip/deflate を decompressobj の max_length で
        *出力上限つき* に展開=zip bomb 耐性。解凍後を署名走査することで Content-Encoding による
        WAF 回避(gzip 化した SQLi 等)を塞ぐ。非対応(br 等)/破損は None。"""
        import zlib
        enc = (encoding or "").strip().lower()
        try:
            if enc in ("gzip", "x-gzip"):
                # 連結 gzip(multi-member)は *全メンバ* を展開する(#58)。decompressobj は 1 メンバの
                # 終端で止まり残りを unused_data に残すため、旧実装は先頭メンバしか走査しなかった
                # (Python gzip / Go gzip.Reader / Node zlib は後続メンバも展開する=2 個目以降に
                # 置いた payload が走査を素通りした)。出力上限はメンバ合計で守る。解けない後続
                # データは例外→None(=走査不能として扱う)。
                out = bytearray()
                rest = data
                members = 0
                while rest and len(out) < max_out:
                    members += 1
                    if members > _GZIP_MEMBER_MAX:
                        return None
                    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    out += d.decompress(rest, max_out - len(out))
                    if not d.eof:
                        break                    # 出力上限 or 走査 prefix の打ち切り=読めた分まで
                    rest = d.unused_data.lstrip(b"\x00")   # メンバ間のゼロ詰めは gzip の慣行
                return bytes(out)
            if enc == "deflate":
                wrapped, raw = AsyncEdgeGuard._deflate_views(data, max_out)
                if (wrapped is not None and wrapped[1] and wrapped[2] and raw is None
                        and AsyncEdgeGuard._raw_deflate_stored_head(data)):
                    # The raw decoder can emit one or more stored-block bytes
                    # before a later error. A streaming backend may have used
                    # that prefix even though one-shot decoding raises.
                    return None
                if wrapped is not None and raw is not None:
                    # A streaming backend can use a different decoded prefix
                    # even if its decoder never reaches EOF. A capped view
                    # may conceal later bytes, so do not select one reading.
                    if wrapped[0] and raw[0] and wrapped[0] != raw[0]:
                        return None
                    if (wrapped[1] and raw[1]
                            and (wrapped[0] != raw[0] or not wrapped[2] or not raw[2])):
                        return None
                    if (wrapped[0] != raw[0]
                            and (len(wrapped[0]) >= max_out or len(raw[0]) >= max_out)):
                        return None
                view = wrapped if wrapped is not None else raw
                return view[0] if view is not None else None
        except Exception:
            return None
        return None

    @staticmethod
    def _decompress_complete_bounded(data: bytes, encoding: str, max_out: int):
        """圧縮本文の終端と出力上限を確かめてから返す。"""
        import zlib
        enc = (encoding or "").strip().lower()
        try:
            if enc in ("gzip", "x-gzip"):
                out = bytearray()
                rest = data
                if not rest:
                    return None
                members = 0
                while rest:
                    members += 1
                    if members > _GZIP_MEMBER_MAX:
                        return None
                    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    out += d.decompress(rest, max_out + 1 - len(out))
                    if len(out) > max_out or not d.eof:
                        return None
                    rest = d.unused_data.lstrip(b"\x00")
                return bytes(out)
            if enc == "deflate":
                views = AsyncEdgeGuard._deflate_views(data, max_out + 1)
                if (views[0] is not None and views[0][1] and views[0][2]
                        and views[1] is None
                        and AsyncEdgeGuard._raw_deflate_stored_head(data)):
                    return None
                for i, view in enumerate(views):
                    if view is None or not view[1] or not view[2] or len(view[0]) > max_out:
                        continue
                    alternate = views[1 - i]
                    if alternate is not None:
                        # The other decoder may accept an EOF with extra wire
                        # bytes (zlib.decompress(raw) does), or stream a
                        # different prefix without reaching EOF. If it has
                        # filled the output budget, its full reading is also
                        # unknowable without exceeding the scan limit.
                        if ((alternate[1] and (not alternate[2]
                                               or alternate[0] != view[0]))
                                or (alternate[0] and alternate[0] != view[0])
                                or len(alternate[0]) > max_out):
                            return None
                    return view[0]
        except (ValueError, zlib.error):
            return None
        return None

    @staticmethod
    def _dechunk_bounded(data: bytes, max_out: int):
        """Transfer-Encoding: chunked の本文を *走査用に* 有界復号する(#D5)。返り値=復号バイト、
        サイズ行が不正(非hex)なら None(=破損→呼び出し側で fail closed)。
        走査面のみ復号し、backend へは raw のまま転送する(#61 と同じ方針)。旧実装はチャンク
        符号化のまま走査していたため、境界分割(3\\r\\nUNI\\r\\n9\\r\\nON SELECT)で UNION SELECT が
        非連続になり body-scan(SQLi/XSS/RCE/upload/GraphQL)を確定的に回避できた。
        prefix が cap で途中打ち切りされた場合は『読めた分だけ』採用する(不完全≠破損=誤検知回避)。"""
        out = bytearray()
        i, n = 0, len(data)
        while i < n and len(out) < max_out:
            j = data.find(b"\r\n", i)
            if j < 0:
                break                              # サイズ行が途中(prefix 打ち切り)=ここまで
            size = _chunk_size_line(data[i:j])
            if size is None:
                return None                        # 不正なサイズ行=破損 → fail closed
            if size == 0:
                break                              # 終端チャンク(0\r\n\r\n)
            start = j + 2
            end = start + size
            if end > n:
                out += data[start:n]               # 最終チャンクが途中で切れている=読めた分
                break
            out += data[start:end]
            i = end + 2                            # チャンク末尾 CRLF を飛ばす
        return bytes(out[:max_out])

    async def _stage_file_call(self, fn, *args):
        """Run disk I/O off-loop; retain its Future through loop-wide cancel."""
        pid = os.getpid()
        if self._body_stage_executor is None or self._body_stage_executor_pid != pid:
            # A fork child cannot use the parent's inherited executor state.
            self._body_stage_executor = ThreadPoolExecutor(
                max_workers=8, thread_name_prefix="ducknet-stage")
            self._body_stage_executor_pid = pid
        future = self._body_stage_executor.submit(fn, *args)
        pending = asyncio.wrap_future(future)
        try:
            return await asyncio.shield(pending)
        except asyncio.CancelledError:
            # _run cancels every asyncio Task during stop(), including tasks
            # created by to_thread. This independent concurrent Future cannot
            # be canceled by that sweep; wait for its real disk operation.
            while not future.done():
                try:
                    # The asyncio wrapper itself may have been canceled. A
                    # second shield on it would throw immediately and spin.
                    await asyncio.sleep(0.01)
                except asyncio.CancelledError:
                    continue
            try:
                future.result()
            except Exception:
                pass
            raise

    async def _change_body_stage(self, delta: int) -> bool:
        """Try a contended cross-worker reservation without blocking the loop."""
        end = asyncio.get_running_loop().time() + (1.0 if delta < 0 else 0.05)
        while True:
            try:
                if self._adjust_body_stage(delta):
                    return True
            except Exception as exc:
                self._defense_unavailable("body_stage_quota", exc)
                return False
            if asyncio.get_running_loop().time() >= end:
                return False
            await asyncio.sleep(0.002)

    async def _release_staged_body(self, stage, reserved: int) -> bool:
        if stage is None:
            return False
        closed = False
        cancelled = False
        try:
            if isinstance(stage, list):
                stage.clear()
            elif reserved > _BODY_STAGE_MEMORY:
                await self._stage_file_call(stage.close)
            else:
                stage.close()
            closed = True
        except asyncio.CancelledError:
            # _stage_file_call joined the executor operation before raising.
            cancelled = True
            if not getattr(stage, "closed", False):
                # A queued executor close may have been canceled before it
                # ran. No previous I/O remains after _stage_file_call joins.
                try:
                    stage.close()
                except Exception as exc:
                    self._defense_unavailable("body_stage_close", exc)
            closed = bool(getattr(stage, "closed", False))
        except Exception as exc:
            self._defense_unavailable("body_stage_close", exc)
            closed = bool(getattr(stage, "closed", False))
        finally:
            if closed and reserved:
                end = asyncio.get_running_loop().time() + 1.0
                while True:
                    try:
                        released = self._adjust_body_stage(-reserved)
                    except Exception as exc:
                        self._defense_unavailable("body_stage_release", exc)
                        break
                    if released:
                        break
                    if asyncio.get_running_loop().time() >= end:
                        self._defense_unavailable("body_stage_release",
                                                  RuntimeError("staged bytes not released"))
                        break
                    try:
                        await asyncio.sleep(0.002)
                    except asyncio.CancelledError:
                        cancelled = True
        return cancelled

    @staticmethod
    def _append_memory_stage(stage: list, piece: bytes) -> None:
        """Coalesce arbitrary tiny Windows reads into bounded 64 KiB pages."""
        view = memoryview(piece)
        while view:
            if not stage or len(stage[-1]) == 65536:
                stage.append(bytearray())
            take = min(len(view), 65536 - len(stage[-1]))
            stage[-1].extend(view[:take])
            view = view[take:]

    async def _stage_request_body(self, buf, extra, reader, writer, ctx, sh, ip):
        """Validate the entire declared wire body before any backend connect.

        Returns (spool, wire bytes, error). The caller owns a successful spool
        and its aggregate reservation; every failure closes/releases here.
        """
        loop = asyncio.get_running_loop()
        deadline = ctx.get("deadline")
        hard = ctx.get("stage_start", loop.time()) + _BODY_STAGE_MAX_SEC
        deadline = min(deadline, hard) if deadline is not None else hard
        ctx["deadline"] = deadline
        if loop.time() >= deadline:
            self._on_slow_body(ip)
            return None, 0, "timeout"
        data = buf.partition(b"\r\n\r\n")[2] + extra
        transfer = _header_value(buf, b"transfer-encoding").lower()
        clh = _header_value(buf, b"content-length")
        chunked = _ChunkedEnd() if "chunked" in transfer else None
        # int() rejects huge decimal strings on recent Python versions. A
        # literal CL can be classified before conversion without an exception
        # that escapes egress-lease cleanup.
        digits = (clh.lstrip("0") or "0") if clh.isdigit() else ""
        if digits and len(digits) > len(str(_BODY_STAGE_MAX)):
            return None, 0, "too_large"
        content_len = int(digits) if digits else None
        if chunked is None and content_len is None:
            return None, 0, "malformed"
        if content_len is not None and content_len > _BODY_STAGE_MAX:
            return None, 0, "too_large"
        if self._worker_parent_guard:
            if not self._parent_guard_alive():
                return None, 0, "unavailable"
        elif self._serving_lease is None or not self._serving_lease.held:
            return None, 0, "unavailable"
        stage = None
        reserved = 0
        complete = False
        success = False
        result = "unavailable"
        memory = _BODY_STAGE_MEMORY
        try:
            from ..core.signed_state import _require_private_state_dir
            state_dir = os.path.dirname(os.path.abspath(sh.path))
            _require_private_state_dir(state_dir, create=False)
            stage = ([] if os.name == "nt" else
                     tempfile.SpooledTemporaryFile(max_size=memory, mode="w+b",
                                                   dir=state_dir))
            remaining = content_len
            initial = True
            while True:
                if chunked is not None:
                    used = chunked.feed(data)
                    if chunked.bad:
                        result = "malformed_chunked"
                        break
                    piece = data[:used]
                else:
                    piece = data[:remaining]
                if len(piece) > _BODY_STAGE_MAX - reserved:
                    result = "too_large"
                    break
                if piece:
                    if not await self._change_body_stage(len(piece)):
                        result = "busy"
                        break
                    reserved += len(piece)
                    if ctx.get("on_body") is not None and not initial:
                        if ctx["on_body"](piece):
                            result = "blocked"
                            break
                    if isinstance(stage, list):
                        self._append_memory_stage(stage, piece)
                    elif reserved <= memory:
                        stage.write(piece)
                    else:
                        await self._stage_file_call(stage.write, piece)
                if chunked is not None:
                    if chunked.done:
                        complete = True
                        break
                else:
                    remaining -= len(piece)
                    if remaining == 0:
                        complete = True
                        break
                initial = False
                left = deadline - loop.time()
                if not math.isfinite(left) or left <= 0:
                    self._on_slow_body(ip)
                    result = "timeout"
                    break
                if not ctx.get("continued") and _expects_continue(buf):
                    await self._send(writer, _CONTINUE_100, ip)
                    ctx["continued"] = True
                try:
                    data = await asyncio.wait_for(reader.read(min(65536, _BODY_STAGE_MAX - reserved + 1)),
                                                  min(self.head_timeout, left))
                except asyncio.TimeoutError:
                    self._on_slow_body(ip)
                    result = "timeout"
                    break
                except Exception:
                    result = "incomplete"
                    break
                if not data:
                    result = "incomplete"
                    break
            if complete:
                if loop.time() >= deadline:
                    self._on_slow_body(ip)
                    result = "timeout"
                    complete = False
                else:
                    if not isinstance(stage, list):
                        if reserved > memory:
                            await self._stage_file_call(stage.seek, 0)
                        else:
                            stage.seek(0)
                    success = True
                    return stage, reserved, None
        except Exception as exc:
            self._defense_unavailable("request_body_stage", exc)
            result = "unavailable"
        finally:
            if not success and stage is not None:
                if await self._release_staged_body(stage, reserved):
                    raise asyncio.CancelledError()
        return None, 0, result

    async def _pipe_body_bounded(self, reader, bwr, remaining, chunked, deadline,
                                 on_body=None, ip="", admission_stamp=None,
                                 completion=None):
        """直接呼び出しとの互換用。通常の ingress は事前検証 staging を使用する。
        宣言された本文長ぶんだけ client→backend へ転送し、それ以降(パイプライン化された後続
        要求)は流さない(#D3)。remaining=残り本文バイト数(Content-Length 時)。chunked=それまでの
        本文を食わせた _ChunkedEnd(終端=last-chunk+trailer の *ちょうど末尾* まで転送。#18)。
        True なら新しい追跡器で始める。総受信デッドライン(#64 body_max_sec)も尊重する。返り値=
        転送バイト数。本文完了後に write_eof=半クローズ(#46 の bodyless 保証を body 有り要求へ拡張)。
        on_body(chunk) が True を返したら(#33: 走査 prefix より後ろに危険なパート)そのチャンクから
        先を流さず backend 接続を閉じる=backend は本文の途中で切れた要求として捨てる。"""
        total = 0
        # Only a verified body boundary may gracefully half-close the backend.
        # Timeout, premature EOF and malformed chunks must discard its connection.
        aborted = True
        loop = asyncio.get_event_loop()
        if isinstance(chunked, bool):
            chunked = _ChunkedEnd() if chunked else None
        try:
            while True:
                if chunked is not None:
                    want = 65536
                else:
                    if remaining <= 0:
                        aborted = False
                        break
                    want = min(65536, remaining)
                rem_t = self.head_timeout if deadline is None else (deadline - loop.time())
                if not math.isfinite(rem_t) or rem_t <= 0:
                    if ip:
                        self._on_slow_body(ip)
                    break                              # 総受信デッドライン超過=接続を中断
                try:
                    chunk = await asyncio.wait_for(reader.read(want),
                                                   min(self.head_timeout, rem_t))
                except asyncio.TimeoutError:
                    if ip:
                        self._on_slow_body(ip)
                    break
                except Exception:
                    break
                if not chunk:
                    break
                if chunked is not None:
                    # 本文に属する分だけを流す。終端より後ろ=パイプライン第2要求は捨てる。
                    # 枠の破損はどこで終わるか backend と一致させられない=以降を流さない。
                    chunk = chunk[:chunked.feed(chunk)]
                    if chunked.bad:
                        break
                if chunk:
                    if on_body is not None and on_body(chunk):
                        break
                    try:
                        await self._checked_backend_write(
                            bwr, chunk, admission_stamp, deadline)
                    except Exception:
                        break
                    total += len(chunk)
                if chunked is not None:
                    if chunked.done:
                        aborted = False
                        break
                else:
                    remaining -= len(chunk)
                    if remaining <= 0:
                        aborted = False
                        break
        finally:
            if completion is not None:
                completion["complete"] = not aborted
            if aborted:
                # A normal close can flush a partial request and look like a
                # graceful EOF to the backend. Abort the transport when possible.
                try:
                    bwr.transport.abort()
                except Exception:
                    self._close(bwr)
            else:
                try:
                    if bwr.can_write_eof():
                        bwr.write_eof()
                except Exception:
                    pass
        return total

    @staticmethod
    def _empty_stream_ok(data: bytes, encoding: str) -> bool:
        """data が *中身が空のまま正しく終端した* gzip/deflate ストリームか(#35)。途中で切れた
        ストリーム(_decompress_bounded はこれも b"" を返す)と区別する。"""
        import zlib
        enc = (encoding or "").strip().lower()
        try:
            if enc in ("gzip", "x-gzip"):
                rest = data
                members = 0
                while rest:                            # 連結 gzip(#58)は全メンバが空で終端すること
                    members += 1
                    if members > _GZIP_MEMBER_MAX:
                        return False
                    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    if d.decompress(rest, 1) or not d.eof:
                        return False
                    rest = d.unused_data.lstrip(b"\x00")
                return bool(data)
            if enc == "deflate":
                for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                    try:
                        d = zlib.decompressobj(wbits)
                        if not d.decompress(data, 1) and d.eof and not d.unused_data:
                            return True
                    except zlib.error:
                        continue
        except zlib.error:
            pass
        return False

    def _upload_stream_check(self, us, sh, ip):
        """staging 中のアップロード検査(#33)。未読部分の on_body コールバックを返す。
        危険なパートを見つけたら upload_violation(加点/BAN)し、遮断なら True=backend に渡さない。
        監査モード(遮断しない)は 1 回記録したら以後は見ない。検査中の例外は止める側(#111)。"""
        fired = []

        def on_body(chunk):
            if fired:
                return False
            try:
                hit = us.feed(chunk)
                if not hit:
                    return False
                fired.append(1)
                act = sh.upload_violation(ip, *hit).get("action")
            except Exception:
                act = "block"
            if act != "block":
                return False
            self.metrics["dropped"] = self.metrics.get("dropped", 0) + 1
            return True
        return on_body

    async def _scan_request_body(self, buf, reader, ip, path="", ctx=None, writer=None):
        """要求ボディを有界に読んで検査する(#61 署名・#66 アップロード・#67 GraphQL)。
        返り値 (extra, blocked):
          · extra … buf を *超えて* 読んだ本文先頭バイト(クリーン時に backend へ転送する分)。
          · blocked … 本文を上流へ流さず接続を切るべきか。True=悪性。"unscannable"=走査できない
            Content-Encoding(呼び出し側が 415・#93)。"too_large"=graphql_max_bytes を超える GraphQL
            本文(413・#4)。"timeout"=走査中に総受信時間(body_max_sec)を超えた(黙って切断・#13)。
        ctx(dict)を渡すと、本文が prefix の先へ続く multipart のために逐次アップロード検査
        ctx["on_body"](chunk)->bool(True=そこで転送を止める・#33)を入れて返す。
        要求ヘッダ Content-Disposition のファイル名(生本文アップロード・T2)は本文を読む前に見る。
        署名走査・アップロード検査(本文は multipart のみ)・GraphQL ガード(graphql_paths のみ)はそれぞれ
        自分のキーで効く(#12)。どれも効かない要求は走査を省き、後段で全本文を有界 staging する。
        署名走査 ON の遮断モードでは復号後の全本文が body_scan_max_bytes 以下の要求だけを転送する。
        監査モードは超過を記録し、先頭だけを走査する。転送は後段の構造検証後に行う。GraphQL
        パスの本文は graphql_max_bytes まで読み切って解析する。chunked 本文は走査面では有界復号して
        から走査する(#D5。backend へは raw 転送)。Content-Encoding 付きの multipart は全量を
        上限内で復号できる場合だけアップロード検査後に転送する。
        writer(クライアント側)を渡すと、Expect: 100-continue で本文を待っている要求へ、本文を
        読む前に 100 Continue を返して ctx["continued"]=True を入れる(#10。呼び出し側は backend へ
        Expect を外して渡す)。"""
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            if not sh.is_enabled():
                return b"", False               # OFF は本文検査を止める(構造検査は後段で継続)
            body_scan_enabled = sh.cfg.get("body_scan_enabled")
            # #12: アップロード検査(本文を読むのは multipart/* の要求だけ・#10)と GraphQL ガード
            #   (graphql_paths だけ)は body_scan_enabled と独立に効く。本文を読むのはどれかが効くときだけ。
            #   Content-Type の重複はどれかが multipart なら multipart とみなす(backend 依存を残さない)。
            cts = _header_values(buf, b"content-type")
            mp_ct = next((v for v in cts if v.strip().lower().startswith("multipart/")), "")
            # 署名走査へ渡す本文の型。重複 Content-Type は前段の構造検査で拒否する。
            body_ct = cts[0] if len(cts) == 1 else ""
            upload_on = bool(mp_ct) and sh.is_enabled() and bool(sh.cfg.get("upload_scan_enabled"))
            gql_lim = sh.graphql_max_bytes(path)
            # T2: 生本文アップロード(WordPress REST の /wp/v2/media 等)は要求ヘッダの
            #   Content-Disposition の filename / filename* が保存名になる。multipart のパートと同じ
            #   拡張子ポリシーで本文を読む前に見て、拒否なら backend へ何も送らない。
            req_cd = _header_values(buf, b"content-disposition")
            if req_cd and sh.scan_upload(ip, b"", disposition=req_cd).get("action") == "block":
                return b"", True
        except Exception:
            return b"", True   # フェイルクローズ: net_shield 到達不能を「スキャンなし」にしない(#111)。
                                # 下の走査例外ハンドラと同じ方針(素通しは本文検査の丸ごとバイパスになる)。
        if not (body_scan_enabled or upload_on or gql_lim):
            return b"", False
        try:
            cap = max(1, min(int(sh.cfg.get("body_scan_max_bytes", 65536)), 262144))
        except Exception:
            cap = 65536
        scan_on = bool(body_scan_enabled)
        audit_mode = sh.cfg.get("mode") == "audit"
        full_scan = scan_on and not audit_mode
        limit_recorded = False

        def scan_limit():
            nonlocal limit_recorded
            if not limit_recorded:
                sh._event(ip, "audit" if audit_mode else "body_scan_limit",
                          {"would": "reject", "rule": "body_scan_limit", "limit": cap})
                limit_recorded = True
            return False if audit_mode else "body_too_large"

        def reject_unscannable(read_bytes=b""):
            self.metrics["body_unscannable"] = self.metrics.get("body_unscannable", 0) + 1
            return read_bytes, "unscannable"

        body_in_buf = buf.partition(b"\r\n\r\n")[2]
        # Content-Length を尊重して読み取りを *正確に* 上限化する。これが無いと本文完了後も
        # cap まで read() がブロック=全 POST に head_timeout 分の遅延が乗る(性能バグ)。
        _cl = _header_value(buf, b"content-length")
        content_len = int(_cl) if _cl.isdigit() else None
        chunked_te = "chunked" in _header_value(buf, b"transfer-encoding").lower()
        enc = _header_value(buf, b"content-encoding").strip().lower()
        encoded = enc not in ("identity", "")
        decode_on = bool(sh.cfg.get("body_decode_enabled", True))
        if (scan_on or gql_lim) and body_ct and saferegex.unsupported_charset(body_ct):
            if not audit_mode:
                return reject_unscannable()
            if gql_lim:
                sh._event(ip, "audit", {"would": "reject", "rule": "graphql_unscannable",
                                        "encoding": "charset"})
                gql_lim = 0
        if scan_on and not decode_on and (chunked_te or encoded):
            if full_scan:
                return reject_unscannable()
            sh._event(ip, "audit", {"would": "reject", "rule": "body_unscannable",
                                    "encoding": enc or "chunked"})
        if gql_lim and (chunked_te or encoded) and not decode_on:
            if not audit_mode:
                return reject_unscannable()          # GraphQL ガードは復号を要する
            sh._event(ip, "audit", {"would": "reject", "rule": "graphql_unscannable",
                                    "encoding": enc or "chunked"})
            gql_lim = 0                             # 監査は生バイトを JSON と誤読しない
        if upload_on and encoded and not decode_on:
            if not audit_mode:
                return reject_unscannable()
            sh._event(ip, "audit", {"would": "reject", "rule": "upload_unscannable",
                                    "encoding": enc})
            upload_on = False
        if not (scan_on or upload_on or gql_lim):
            return b"", False
        if scan_on and not encoded and not chunked_te and content_len is not None and content_len > cap:
            result = scan_limit()
            if result:
                return b"", result                  # CL で確定: backend 接続前に 413
        dmax = cap + (1 if scan_on else 0)
        if gql_lim and not full_scan:
            dmax = max(dmax, gql_lim + 1)
        # #4: GraphQL パスの本文は graphql_max_bytes まで読み切って *全体* を解析する(prefix で切ると
        #   JSON が読めず深さ/バッチ上限を素通りした)。宣言長が上限を超える本文は読み足さない
        #   (inspect_graphql が complete=False で拒否=413)。chunked は枠の分だけ余裕を持って読む。
        #   multipart は先頭の operations 欄だけが GraphQL なので上限ぶんの先頭を読む。
        want = cap
        if gql_lim and not full_scan and (mp_ct or content_len is None or content_len <= gql_lim):
            want = max(cap, gql_lim + 1 + (65536 if chunked_te else 0))
        target = want if content_len is None else min(want, content_len)
        # 走査対象は復号後 dmax bytes。chunk 枠や gzip ヘッダだけで raw cap を
        # 食い切っても、復号後に未走査の余地があるなら読取を続ける。raw は最大 8 倍
        # (かつ追加 4MiB)で頭打ちにし、そこでも dmax に届かない場合は転送しない。
        # 遮断モードは cap 超で backend に接続せず、監査だけは従来の転送を続ける。
        need_decoded_cap = decode_on and (chunked_te or encoded)
        raw_budget = max(want, min(want * 8, want + 4 * 1024 * 1024))
        prefix = bytearray(body_in_buf)
        extra = bytearray()
        # #82: 走査読取にも *総* デッドラインを課す。per-read だけだと走査フェーズでボディを小出しして
        #   接続を保持できた(#64 の body_max_sec は走査 *後* の pipe にしか効かない)。
        loop = asyncio.get_event_loop()
        deadline = ctx.get("deadline") if ctx is not None else self._body_deadline()
        stage_start = (ctx.get("stage_start", loop.time()) if ctx is not None
                       else loop.time())
        hard_deadline = stage_start + _BODY_STAGE_MAX_SEC
        deadline = min(deadline, hard_deadline) if deadline is not None else hard_deadline
        if ctx is not None:
            ctx["deadline"] = deadline                 # 残りの転送も同じ総デッドラインで(#13)
        timed_out = False
        # chunked は枠を逐次解析し、本文の終端(trailer 込み)に達したら読み止める(#18)。旧実装は
        # 読取が '0\r\n\r\n' で *ちょうど終わる* ときしか完了と見なさず、終端の後ろにパイプライン
        # 第2要求が続くと head_timeout まで待って正規の送信者を slow_body 加点までしていた。
        trk = None
        if content_len is None and chunked_te:
            trk = _ChunkedEnd()
            trk.feed(body_in_buf)
        # #10: Expect: 100-continue の送信者(aiohttp・Node・JDK 等)は 100 を受け取るまで本文を送らない。
        #   本文を読むのは DuckNet なので 100 も DuckNet が返す(nginx と同じ)。返さないと本文が来ない
        #   まま走査の待ちが切れ、要求は黙って切断されて backend に何も届かなかった。
        if (writer is not None and len(prefix) < target
                and (trk is None or not (trk.done or trk.bad))
                and _expects_continue(buf)):
            try:
                writer.write(_CONTINUE_100)
                if ctx is not None:
                    ctx["continued"] = True
            except Exception:
                pass
        read_stopped = False
        while True:
            while len(prefix) < target and not (trk is not None and (trk.done or trk.bad)):
                remaining = self.head_timeout if deadline is None else (deadline - loop.time())
                if not math.isfinite(remaining) or remaining <= 0:
                    timed_out = True
                    break
                try:
                    # 総デッドラインの運用中は 1 回の読取もその残りまで待つ(#10)。
                    chunk = await asyncio.wait_for(reader.read(min(65536, target - len(prefix))),
                                                   remaining)
                except asyncio.TimeoutError:
                    timed_out = deadline is not None
                    read_stopped = True
                    break
                except Exception:
                    read_stopped = True
                    break
                if not chunk:
                    read_stopped = True
                    break
                prefix += chunk
                extra += chunk                         # buf を超えた分=後で転送が要る
                if trk is not None:
                    trk.feed(chunk)
            if (timed_out or read_stopped or not need_decoded_cap
                    or (trk is not None and (trk.done or trk.bad))
                    or (content_len is not None and len(prefix) >= content_len)):
                break
            # チェックポイントだけで復号する。1-byte dribble ごとに全 prefix を再復号
            # すると O(n^2) になるので、次のチェックポイントは倍増させる。
            scan_prefix = bytes(prefix)
            if chunked_te:
                scan_prefix = self._dechunk_bounded(scan_prefix, raw_budget)
            if scan_prefix is None:
                return bytes(extra), True
            if encoded:
                scan_prefix = self._decompress_bounded(scan_prefix, enc, dmax)
            if scan_prefix is None or len(scan_prefix) >= dmax:
                break                              # 復号不能は下の既存ポリシーで扱う
            if target >= raw_budget:
                return bytes(extra), True          # 枠/圧縮ヘッダの過大パディング=fail closed
            target = min(raw_budget, max(target + 1, target * 2))
            if content_len is not None:
                target = min(target, content_len)   # 宣言済み本文の後ろを待たない
        if timed_out:
            # 総時間超過=切断+加点(R-U-Dead-Yet 走査版)。旧実装は加点だけして部分本文を backend へ
            # 転送し、続きを新しい body_max_sec で待っていた(#13)。ここで切る(backend は受信せず)。
            self._on_slow_body(ip)
            return bytes(extra), "timeout"
        if trk is not None and trk.bad:
            return bytes(extra), "malformed_chunked"
        if read_stopped and (
                (content_len is not None and len(prefix) < content_len)
                or (trk is not None and not trk.done)):
            return bytes(extra), True              # 不完全/破損本文で backend に接続しない
        blocked = False
        try:
            pb = bytes(prefix)
            # 走査面は *この要求の本文* に限る(転送するのもそこまで=#18)。本文の後ろに乗った
            # パイプライン後続要求のバイトを本文として採点しない。
            if content_len is not None:
                pb = pb[:content_len]
            elif trk is not None and trk.done:
                pb = pb[:trk.consumed]
            raw = pb                                   # 転送する生の本文(逐次アップロード検査の起点)
            complete = (len(prefix) >= content_len if content_len is not None
                        else (trk.done if trk is not None else True))
            # 圧縮 multipart は後続パートを逐次アップロード検査できない。宣言された
            # 本文を全て復号して拡張子検査できる場合に限り通す(body_scan_enabled と独立)。
            if upload_on and encoded and not complete:
                if not audit_mode:
                    return bytes(extra), True
                sh._event(ip, "audit", {"would": "reject", "rule": "upload_unscannable",
                                        "encoding": enc, "reason": "incomplete"})
                upload_on = False
            # GraphQL は上限+1 まで復号して超過を知る(dmax は読取前に確定)。
            # #D5: chunked 本文は *復号後* を走査する(境界分割による body-scan 回避封じ)。
            #   Content-Encoding 解凍より前に行う(ワイヤ上は chunk 枠の内側に gzip 等が入る)。
            #   原本(extra)は backend へ raw のまま転送。破損チャンクは fail closed。
            if decode_on and chunked_te:
                dec = self._dechunk_bounded(pb, len(pb) if encoded else dmax)
                if dec is None:
                    return bytes(extra), True      # 破損チャンクストリーム=フェイルクローズ(#111)
                pb = dec
            # #74: Content-Encoding で圧縮された本文は解凍後を走査する(gzip 化 payload の回避封じ)。
            #   解凍は有界(max_length)=zip bomb 耐性。原本(pb)は backend へそのまま転送する。
            if decode_on:
                if encoded:
                    if upload_on or full_scan:
                        dec = self._decompress_complete_bounded(pb, enc, cap)
                        if dec is None:
                            if full_scan:
                                probe = self._decompress_bounded(pb, enc, cap + 1)
                                if probe is not None and len(probe) > cap:
                                    return bytes(extra), scan_limit()
                                return reject_unscannable(bytes(extra))
                            # Upload scanning is independent of body signatures.
                            # A partial decoded prefix cannot prove that later
                            # multipart parts lack a forbidden filename.
                            if not audit_mode:
                                return reject_unscannable(bytes(extra))
                            sh._event(ip, "audit", {"would": "reject", "rule": "upload_unscannable",
                                                    "encoding": enc, "reason": "decode"})
                            upload_on = False
                            dec = self._decompress_bounded(pb, enc, dmax)
                            decoded_ok = bool(dec) or (dec == b"" and complete
                                                       and self._empty_stream_ok(pb, enc))
                        else:
                            pb = dec
                    else:
                        # A complete HTTP entity needs a complete coding stream
                        # even in audit mode. Prefix decoding can yield safe
                        # plaintext before a missing checksum or later member.
                        # An incomplete read prefix still uses bounded decoding
                        # and must not be mistaken for a broken coding stream.
                        dec = (self._decompress_complete_bounded(pb, enc, dmax)
                               if complete and (gql_lim or scan_on) else
                               self._decompress_bounded(pb, enc, dmax))
                        if dec is None and complete:
                            # A complete decoder returns None for both an
                            # ambiguous tail and excess output. Preserve a
                            # proven size-limit reason and the audit prefix;
                            # otherwise record the coding as unscannable.
                            probe = self._decompress_bounded(pb, enc, dmax)
                            if probe is not None:
                                if gql_lim and len(probe) > gql_lim:
                                    action = sh.inspect_graphql(
                                        ip, path, b"", body_ct, complete=False).get("action")
                                    if action == "reject":
                                        return bytes(extra), "too_large"
                                    gql_lim = 0
                                    dec = probe
                                if scan_on and len(probe) > cap:
                                    dec = probe
                        decoded_ok = bool(dec) or (dec == b"" and complete
                                                   and self._empty_stream_ok(pb, enc))
                    # 解凍結果 b"" は『正しく終端した空の本文』のときだけ走査可能(#35)。途中で切れた/
                    # 巨大な gzip ヘッダで prefix 内に中身が出ない本文まで空とみなすと素通りになる。
                    if not (upload_on or full_scan) and decoded_ok:
                        pb = dec                       # 解凍できたら解凍後を走査面に
                    elif not (upload_on or full_scan) and (
                            scan_on or gql_lim or sh.cfg.get("body_reject_unscannable_encoding", True)):
                        # 解けない符号化(br 等)のボディを *圧縮バイトのまま* 走査しても
                        # 署名は当たらない。バックエンドがその符号化に対応していれば
                        # 実質バイパスになるので、検査できない本文は通さない。
                        # 415 は writer を持つ呼び出し側(_handle_conn)が返し、dropped もそこで
                        # 1 回だけ数える。ここで writer を参照していたため NameError → 外側の
                        # except で「黙って切断」に化け、dropped も二重計上されていた(#93)。
                        if not audit_mode:
                            return reject_unscannable(bytes(extra))
                        self.metrics["body_unscannable"] = self.metrics.get(
                            "body_unscannable", 0) + 1
                        sh._event(ip, "audit", {"would": "reject", "rule": "body_unscannable",
                                                "encoding": enc})
                        gql_lim = 0                     # 不可視の JSON を検査済みと見なさない
            if scan_on and len(pb) > cap:
                result = scan_limit()
                if result:
                    return bytes(extra), result
            kw = {"content_type": body_ct} if body_ct else {}   # 型の無い要求は従来どおりの呼び方
            if len(cts) > 1:
                # 重複した Content-Type は型を渡さない(上の T1)が、宣言された charset はどれを
                # backend が採っても読めるように全部を渡す(どれかで読み直して走査する)。
                kw["charsets"] = ", ".join(cts)
            blocked = sh.inspect_body(ip, pb[:cap], **kw).get("action") == "block"   # 無効なら allow
            if not blocked and upload_on:              # #66: 危険なアップロード拡張子も拒否
                us = None if encoded else sh.upload_scanner(mp_ct, pb, chunked_te)
                if us is None:
                    # 圧縮 multipart は全量が cap 以内で復号済みの場合に限る。
                    blocked = sh.scan_upload(ip, pb, mp_ct).get("action") == "block"
                else:
                    hit = us.feed(raw)                 # 生の本文(chunked は枠を解いて)のパートヘッダ
                    if hit:
                        blocked = sh.upload_violation(ip, *hit).get("action") == "block"
                    elif not complete and ctx is not None:
                        ctx["on_body"] = self._upload_stream_check(us, sh, ip)
            if not blocked and gql_lim:                # #67: GraphQL の深さ/複雑度/イントロスペクション
                g = sh.inspect_graphql(ip, path, pb, mp_ct or _header_value(buf, b"content-type"),
                                       complete=complete).get("action")
                if g == "reject":
                    return bytes(extra), "too_large"   # #4: 上限超=読み切れない=検査できない(413)
                blocked = g == "block"
        except Exception:
            # フェイルクローズ: 走査中の例外を「非悪性」にしない(#111)。素通しすると
            # 本文スキャン(SQLi/アップロード/GraphQL検査)が丸ごとバイパスされる。
            blocked = True
        return bytes(extra), blocked

    def _write_html(self, writer, code: str, body, server: str = "", extra=None):
        # body は str/bytes どちらでも可。Content-Length は _http_response が
        # UTF-8 バイト数で厳密計算する(日本語の遮断ページ/申立メッセージでもズレない)。
        writer.write(_http_response(code, body, "text/html; charset=utf-8",
                                    server=server, extra=extra))

    async def _serve_block_page(self, ip, sh, writer):
        """遮断中ユーザーへ『アクセス遮断ページ』を返す(静かな切断の代わり・商用WAF風)。"""
        try:
            self._write_html(writer, "403 Forbidden", _block_page(sh.ban_info(ip)),
                             extra=deception.headers_for(ip))
            await writer.drain()
        except Exception:
            pass
        return self._close(writer)

    async def _handle_appeal(self, ip, path, sh, writer, html: bool = False):
        """解除リクエスト(異議申立)を受け付ける。?reason=... を submit_appeal へ。
        判定の手前にある経路ゆえ、CPU枯渇フラッド対策として **BAN されていないIPには
        重い遮断ページ(_block_page)を生成せず**、bloom O(1) で軽量拒否する。
        html=True(ブラウザ)には『ブロックされていない・戻って再読み込み』の短い案内
        (state を読まない静的な文言のみ=軽量のまま)。"""
        if not sh.is_banned_fast(ip):            # bloom: 確実に未BAN→state も作らず即軽量応答
            writer.write(_reject_response("403 Forbidden",
                                          '{"error":"no active ban for this address"}',
                                          _notice_page("not_banned") if html else None))
            try:
                await writer.drain()
            except Exception:
                pass
            return self._close(writer)
        from urllib.parse import parse_qs
        reason = ""
        if "?" in path:
            reason = (parse_qs(path.split("?", 1)[1]).get("reason") or [""])[0]
        try:
            if reason or sh.ban_info(ip).get("appeal_available"):
                r = sh.submit_appeal(ip, reason)
                body = _block_page(sh.ban_info(ip), submitted=r.get("ok", False),
                                   msg=r.get("note") or r.get("error", ""))
            else:
                body = _block_page(sh.ban_info(ip))   # フォーム表示
            self._write_html(writer, "200 OK", body)
            await writer.drain()
        except Exception:
            pass
        return self._close(writer)

    async def _drain_backend(self, bwr, deadline: float = None):
        """要求方向の背圧待ちを有限にし、総本文期限も越えない。"""
        def abort():
            try:
                bwr.transport.abort()    # 部分要求を graceful EOF として backend に渡さない
            except Exception:
                self._close(bwr)

        limit = self.write_timeout
        if deadline is not None:
            remaining = deadline - asyncio.get_event_loop().time()
            if not math.isfinite(remaining) or remaining <= 0:
                limit = 0
            else:
                limit = min(limit, remaining)
        try:
            if limit <= 0:
                raise asyncio.TimeoutError()
            await asyncio.wait_for(bwr.drain(), limit)
        except asyncio.TimeoutError:
            self.metrics["backend_write_timeout"] = self.metrics.get("backend_write_timeout", 0) + 1
            abort()
            raise
        except BaseException:
            abort()                       # stop() による cancel も半端な要求を残さない
            raise

    async def _send(self, dst, data: bytes, ip: str = ""):
        """write + 期限付き drain(#9)。受信側が止まって drain が write_timeout 超でサスペンドし続け
        たら『遅延読取(zero-window)』とみなして例外で中断する。中断は _pipe の except→finally で
        dst.close() を起こし、相方 pipe の EOF を誘発して両端(クライアント/バックエンド)を解放する。"""
        if data:
            dst.write(data)
        _cap = getattr(dst, "_dn_stall_cap", 0.0)   # #D2: 応答方向のみ >0(_pipe が装填)
        _t0 = asyncio.get_event_loop().time() if _cap else 0.0
        try:
            await asyncio.wait_for(dst.drain(), self.write_timeout)
        except asyncio.TimeoutError:
            self._on_slow_read(ip)
            raise                                 # _pipe へ伝播=ストリーム中断→両端カスケード切断
        if _cap:
            # drain を待った累積時間が上限超=slow-read 兵糧攻め(小出し受信で無期限保持)とみなし切断。
            # 高速 client / idle SSE は drain 待ち≒0 ゆえ加算されず誤切断しない(#D2)。
            acc = getattr(dst, "_dn_stall", 0.0) + (asyncio.get_event_loop().time() - _t0)
            dst._dn_stall = acc
            if acc > _cap:
                self._on_slow_read(ip)
                raise _DrainedStall(len(data))  # 送信完了分を数えてからカスケード切断
        return len(data)                   # writerへ送信完了したbytes。TCP先の受領保証ではない

    async def _checked_client_write(self, dst, data: bytes, ip: str, shield,
                                    approved_stamp):
        """Fence a response write against signed policy/accounting commits.

        Quota reservation and signed verification take the Shield object lock
        before the process lock. Only the synchronous write is inside the
        process lock; drain and slow-read penalties may reacquire Shield.
        """
        if self._single_cluster_policy_sync:
            self._check_single_traffic_source(shield)
            with shield._lock:
                if (shield._traffic_state_untrusted and shield.is_enabled() and
                        shield.cfg.get("persist_bans") and
                        shield._finite_quota_active(shield.cfg) and
                        shield.cfg.get("mode") != "audit"):
                    raise RuntimeError("signed quota history is untrusted before response write")
        from ..lifeform.policy import app_firewall
        paths = self._cluster_policy_sources(shield, app_firewall())
        lock = self._ensure_cluster_commit_lock()
        deadline = time.monotonic() + commit_barrier.WAIT_SEC
        while True:
            if lock.acquire(False):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("quota history commit barrier timed out")
            await asyncio.sleep(0.001)
        try:
            if not lock.verify_path():
                raise RuntimeError("quota history commit lock inode changed")
            if tuple(_signed_source_stamp(path) for path in paths) != approved_stamp:
                raise RuntimeError("signed policy changed before response write")
            if not self._parent_guard_alive():
                raise RuntimeError("cluster parent is unavailable before response write")
            dst.write(data)
        finally:
            lock.release()
        try:
            await self._send(dst, b"", ip)
        except _DrainedStall:
            raise _DrainedStall(len(data)) from None
        return len(data)

    def _on_slow_read(self, ip):
        """応答の受信を止めたまま放置する遅延読取(TCP zero-window 兵糧攻め・#9)の検知。
        メトリクス計上 + 当該IPへ加点(反復で BAN・単発の遅い回線は誤遮断しない)。"""
        self.metrics["slow_read"] = self.metrics.get("slow_read", 0) + 1
        try:
            from ..lifeform.pipeline import net_shield
            net_shield().penalize(ip, reason="slow response read(TCP zero-window)",
                                  kind="slow_read")
        except Exception:
            pass

    async def _pipe(self, src, dst, scan: bool = False, ip: str = "",
                    deadline: float = None, tls: bool = False, req_host: str = "",
                    req_paths=(), private_response: bool = False, req_method: str = "",
                    strict_http: bool = False, quota=None, prefetched: bytes = b"") -> int:
        total = 0
        own_ban_fp = None  # BAN published by this response's backend status
        def mark_quota_hit():
            if quota is not None and not quota[2]["hit"]:
                quota[2]["hit"] = True
                quota[0].note_egress_quota_block(ip)

        if quota is not None and not quota[2].get("time_ok", True):
            mark_quota_hit()
            self._close(dst)
            return 0

        async def send_response(data, *, whole=False):
            nonlocal total
            if not data:
                return
            current = None
            if quota is not None and self._cluster_policy_sync:
                current = self._sync_cluster_policy()
                admitted = quota[2].get("policy_stamp")
                if admitted is None or len(current) != len(admitted):
                    raise RuntimeError("signed response policy is unavailable")
                from ..lifeform.policy import app_firewall
                paths = self._cluster_policy_sources(quota[0], app_firewall())
                traffic = set(self._single_traffic_sources(quota[0]))
                bans = {quota[0]._bans_path, quota[0]._bans_path + ".hw"}
                if any(now != old for path, now, old in
                       zip(paths, current, admitted)
                       if path not in traffic and path not in bans):
                    raise RuntimeError("signed policy changed before response write")
                if any(now != old for path, now, old in
                       zip(paths, current, admitted) if path in bans):
                    with quota[0]._lock:
                        if (own_ban_fp is None or
                                quota[0]._state_fingerprints.get(quota[0]._bans_path)
                                != own_ban_fp):
                            raise RuntimeError("external BAN changed before response write")
            permitted = (quota[0].reserve_egress(ip, quota[1], len(data), whole=whole)
                         if quota is not None else len(data))
            clipped = permitted < len(data)
            if clipped and quota is not None:
                mark_quota_hit()
            if permitted:
                time_budget = (quota[0].egress_time_remaining(ip, quota[1])
                               if quota is not None else None)
                if time_budget is not None and time_budget <= 0:
                    mark_quota_hit()
                    raise _EgressQuotaReached()
                async def send_wire():
                    if quota is not None and self._cluster_policy_sync:
                        return await self._checked_client_write(
                            dst, data[:permitted], ip, quota[0], current)
                    return await self._send(dst, data[:permitted], ip)

                if quota is None or (time_budget is None and not quota[2].get("time_watch", False)):
                    total += await send_wire()
                else:
                    # Keep one write/drain task. Cancelling and retrying _send
                    # at each quota recheck would write the same bytes twice.
                    sending = asyncio.create_task(send_wire())
                    try:
                        while True:
                            if sending.done():
                                # The write may have completed just as the
                                # shared deadline changed. Observe its result
                                # and count confirmed bytes before cutoff.
                                total += sending.result()
                                time_budget = quota[0].egress_time_remaining(ip, quota[1])
                                if time_budget is not None and time_budget <= 0:
                                    mark_quota_hit()
                                    raise _EgressQuotaReached()
                                break
                            time_budget = quota[0].egress_time_remaining(ip, quota[1])
                            if time_budget is not None and time_budget <= 0:
                                mark_quota_hit()
                                raise _EgressQuotaReached()
                            wait = (_QUOTA_TIME_RECHECK_SEC if time_budget is None
                                    else min(time_budget, _QUOTA_TIME_RECHECK_SEC))
                            await asyncio.wait((sending,), timeout=wait)
                    finally:
                        if not sending.done():
                            sending.cancel()
                            await asyncio.gather(sending, return_exceptions=True)
            if clipped:
                raise _EgressQuotaReached()

        async def send_dlp(out):
            for part in out if isinstance(out, tuple) else (out,):
                if part:
                    await send_response(part)
        # 出口DLP(evolution #6): 応答方向のみ、先頭を有界走査して秘密情報漏洩を検出。
        # 本文の走査・保留・符号化の扱いは _DlpStream(#1/#27/#42/#47/#48)。head は CRLFCRLF で
        # 閉じるので丸ごと走査して即送る(#59)。dlp=None は本文の内容検査を行わない。
        dlp = None
        sec_cfg = None                            # 応答 head 加工(#12/#65/#69)の cfg
        private = bool(private_response)
        add_sec, harden_ck, harden_cors, harden_redir = False, False, False, False
        if scan:
            try:
                from ..lifeform.pipeline import net_shield
                s = net_shield()
                if not private and req_paths and s.cfg.get("private_paths"):
                    private = any(s.private_path_matches(value) for value in req_paths)
                if s.dlp_active():
                    budget = int(s.cfg.get("dlp_max_scan_bytes", 262144))
                    if budget <= 0:
                        raise ValueError("invalid DLP scan budget")
                    dlp = _DlpStream(s, ip, budget)
                add_sec = bool(s.cfg.get("sec_headers_enabled"))
                harden_ck = bool(s.cfg.get("cookie_harden_enabled"))
                harden_cors = bool(s.cfg.get("cors_harden_enabled"))
                harden_redir = bool(s.cfg.get("open_redirect_enabled"))
                if add_sec or harden_ck or harden_cors or harden_redir:   # いずれかで head 処理起動
                    sec_cfg = s.cfg
                # #D2: 応答方向(scan=True=backend→client)にのみ slow-read 累積 drain 待ち上限を装填。
                #   >0 のときだけ _send が累積計上して超過で切断する(0=従来どおり無制限=SSE 非破壊)。
                try:
                    dst._dn_stall_cap = float(s.cfg.get("resp_stall_sec", 0) or 0)
                    dst._dn_stall = 0.0
                except Exception:
                    pass
            except Exception as exc:
                # The response has already crossed the request gate. Losing the
                # shield here must not turn configured egress checks into raw pass-through.
                self._defense_unavailable("response_shield", exc)
                self._close(dst)
                return 0
        # HTTP framing and origin-only metadata are transport boundaries, including
        # when optional defenses or the shield switch are off. Valid opaque bodies
        # retain their bytes; charset/media restrictions remain exclusive to DLP.
        # The actual HTTP gateway cannot fall back to an arbitrary raw stream;
        # direct internal callers retain their existing non-HTTP helper contract.
        head_done = not (scan or private or strict_http)
        hbuf = bytearray()
        hsearch = 0
        response_end = None
        # Score only a complete, strictly framed final response head. A status
        # line from an invalid backend head must not BAN a legitimate client.
        report_status = bool(scan and ip)
        interim_count = 0
        loop = asyncio.get_event_loop()
        head_deadline = loop.time() + self.head_timeout if not head_done else None
        try:
            while True:
                remaining = None
                quota_remaining = None
                if deadline is not None:          # #64: 要求ボディの総受信時間に上限(slow-body)
                    remaining = deadline - loop.time()
                    if not math.isfinite(remaining) or remaining <= 0:
                        self._on_slow_body(ip)
                        break
                if dlp is not None and dlp.html_deadline is not None:
                    html_remaining = dlp.html_deadline - loop.time()
                    if html_remaining <= 0:
                        action = dlp.sh.note_unscannable(ip, "html-timeout").get("action")
                        out, _ = dlp._stop(action, b"")
                        if action == "block":
                            break
                        await send_dlp(out)
                        dlp.close()
                        dlp = None                # audit: resume raw forwarding
                        continue
                    remaining = (min(remaining, html_remaining)
                                 if remaining is not None else html_remaining)
                if not head_done and head_deadline is not None:
                    head_remaining = head_deadline - loop.time()
                    if head_remaining <= 0:
                        self.metrics["response_head_timeout"] = (
                            self.metrics.get("response_head_timeout", 0) + 1)
                        break
                    remaining = (min(remaining, head_remaining)
                                 if remaining is not None else head_remaining)
                quota_recheck = False
                if quota is not None:
                    quota_remaining = quota[0].egress_time_remaining(ip, quota[1])
                    if quota_remaining is not None:
                        if quota_remaining <= 0:
                            mark_quota_hit()
                            break
                        remaining = (min(remaining, quota_remaining)
                                     if remaining is not None else quota_remaining)
                    if quota_remaining is not None or quota[2].get("time_watch", False):
                        if remaining is None or remaining > _QUOTA_TIME_RECHECK_SEC:
                            remaining = _QUOTA_TIME_RECHECK_SEC
                            quota_recheck = True
                if prefetched:
                    chunk, prefetched = prefetched, b""
                elif remaining is not None:
                    try:
                        chunk = await asyncio.wait_for(src.read(65536), remaining)
                    except asyncio.TimeoutError:
                        current_quota = (quota[0].egress_time_remaining(ip, quota[1])
                                         if quota_remaining is not None else None)
                        if current_quota is not None and current_quota <= 0:
                            mark_quota_hit()
                        elif quota_recheck:
                            # Another same-IP stream may have shortened the
                            # shared deadline while this read was waiting.
                            continue
                        elif (quota_remaining is not None and
                              remaining == quota_remaining):
                            # Another same-IP stream may have settled, making
                            # the aggregate deadline later; recalculate it.
                            continue
                        elif not head_done and head_deadline is not None and loop.time() >= head_deadline:
                            self.metrics["response_head_timeout"] = (
                                self.metrics.get("response_head_timeout", 0) + 1)
                        elif dlp is not None and dlp.html_deadline is not None and loop.time() >= dlp.html_deadline:
                            action = dlp.sh.note_unscannable(ip, "html-timeout").get("action")
                            out, _ = dlp._stop(action, b"")
                            if action != "block":
                                await send_dlp(out)
                                dlp.close()
                                dlp = None
                                continue          # audit still forwards later backend bytes
                        elif deadline is not None and loop.time() >= deadline:
                            self._on_slow_body(ip)
                        else:
                            # wait_for can wake a few clock ticks before the
                            # selected deadline. Recompute it instead of
                            # mislabeling an HTML/body timeout as a response
                            # head timeout and dropping the DLP audit record.
                            continue
                        break
                else:
                    chunk = await src.read(65536) # 64KiB=syscall/await 往復を削減(I/O律速)
                if not chunk:
                    if hbuf:
                        if (strict_http or private or (scan and (
                                hbuf.startswith(b"HTTP/") or b"HTTP/".startswith(hbuf)))):
                            self.metrics["backend_invalid_response"] = (
                                self.metrics.get("backend_invalid_response", 0) + 1)
                            if dlp is not None:
                                dlp.sh.note_unscannable(ip, "response-head-incomplete")
                            break
                        if private:
                            break               # cache 保護用 head を安全に作れない
                        if dlp is not None:
                            if hbuf.startswith(b"HTTP/") or b"HTTP/".startswith(hbuf):
                                if (dlp.sh.note_unscannable(ip, "response-head-incomplete")
                                        .get("action") == "block"):
                                    break
                            else:                 # 既存の raw 非HTTPストリーム走査を保つ
                                kinds = dlp.sh.scan_leak(hbuf)
                                if kinds and dlp.sh.note_leak(ip, kinds).get("action") == "block":
                                    break
                        await send_response(bytes(hbuf))
                        hbuf.clear()
                    elif response_end is not None and response_end.known and not response_end.done:
                        # A transport EOF is not a complete declared entity.
                        if dlp is not None:
                            action = dlp.sh.note_unscannable(ip, "response-framing").get("action")
                            out, stop = dlp._stop(action, dlp.release())
                            if out and not stop:
                                await send_dlp(out)
                    elif dlp is not None:         # Close-delimited entity: EOF is its boundary.
                        out, stop = dlp.eof()
                        if out and not stop:
                            await send_dlp(out)
                    break
                if not head_done:                 # 応答 head を蓄積→注入→以降は body として通常処理
                    hbuf.extend(chunk)
                    chunk = b""
                    leak_stop = False
                    while not head_done:
                        if not hbuf.startswith(b"HTTP/"):
                            if len(hbuf) >= 5:
                                # 応答行が HTTP でない(非HTTPストリーム等)=head 加工対象外。諦めて
                                # 既存の raw DLP stream へ回す。私有経路は cache head が作れない。
                                if private or strict_http:
                                    self.metrics["backend_invalid_response"] = (
                                        self.metrics.get("backend_invalid_response", 0) + 1)
                                    if dlp is not None:
                                        dlp.sh.note_unscannable(ip, "response-head")
                                    leak_stop = True
                                    break
                                chunk, hbuf, head_done = bytes(hbuf), bytearray(), True
                            break
                        idx = hbuf.find(b"\r\n\r\n", hsearch)
                        if idx < 0 or idx > 65536:
                            if idx < 0:
                                hsearch = max(0, len(hbuf) - 3)
                            if len(hbuf) > 65536:
                                self.metrics["backend_invalid_response"] = (
                                    self.metrics.get("backend_invalid_response", 0) + 1)
                                if dlp is not None:
                                    dlp.sh.note_unscannable(ip, "response-head-too-large")
                                leak_stop = True
                                break
                            break                 # head 未完=次の chunk を待つ
                        response_head = bytes(hbuf[:idx])
                        configured_response_fields = set()
                        if add_sec and sec_cfg is not None:
                            names = list(sec_cfg.get("sec_headers_strip") or [])
                            extra = sec_cfg.get("sec_headers_extra") or {}
                            if isinstance(extra, dict):
                                names.extend(extra)
                            configured_response_fields = {
                                str(name).strip().lower().encode("latin1", "replace")
                                for name in names}
                        framing_problem = _response_head_problem(
                            response_head,
                            protected_connection_fields=configured_response_fields)
                        if framing_problem:
                            self.metrics["backend_invalid_response"] = (
                                self.metrics.get("backend_invalid_response", 0) + 1)
                            if dlp is not None:
                                dlp.sh.note_unscannable(ip, framing_problem)
                            leak_stop = True
                            break
                        status = _resp_status(response_head.split(b"\r\n", 1)[0])
                        if report_status and not _is_interim(status):
                            # The mandatory HTTP syntax check above has seen
                            # the entire final head. Keep this before optional
                            # DLP/media rejection so a valid 401 still scores,
                            # but an invalid 401 never mutates BAN state.
                            try:
                                from ..lifeform.pipeline import net_shield
                                sh = net_shield()
                                with sh._lock:
                                    before_ban = sh._state_fingerprints.get(sh._bans_path)
                                    sh.note_response(ip, status)
                                    after_ban = sh._state_fingerprints.get(sh._bans_path)
                                    if (after_ban != before_ban and
                                            sh._last_bans_write.get("ok") is True):
                                        own_ban_fp = after_ban
                            except Exception:
                                pass
                        no_body = req_method == "HEAD" or status in (204, 304)
                        problem = (_dlp_head_problem(response_head, bodyless=no_body)
                                   if (dlp is not None or private) else "")
                        if problem:
                            action = (dlp.sh.note_unscannable(ip, problem).get("action")
                                      if dlp is not None else None)
                            if private or action == "block":
                                leak_stop = True
                                break
                            dlp = None             # audit: 不定な応答を記録して raw 転送
                        if _is_interim(status):
                            interim_count += 1
                            if interim_count > _MAX_INTERIM_HEADS:
                                self.metrics["backend_invalid_response"] = (
                                    self.metrics.get("backend_invalid_response", 0) + 1)
                                if dlp is not None:
                                    dlp.sh.note_unscannable(ip, "response-interim-limit")
                                leak_stop = True
                                break
                            # 1xx 中間応答は無加工で即送り、*次の* head を最終応答として加工する(#60)。
                            # 旧実装は中間応答を『その応答』として加工し、本物の最終 head を body と
                            # して素通ししていた=Set-Cookie 補完/CORS 無害化/防御ヘッダ/オープン
                            # リダイレクト無害化がまとめて外れた。
                            out_head = _strip_origin_response_metadata(response_head) + b"\r\n\r\n"
                            hbuf = hbuf[idx + 4:]
                            hsearch = 0             # 残りは次の interim/final head
                            upgraded = False
                        else:
                            new_head = response_head
                            upgraded = _resp_status(new_head.split(b"\r\n", 1)[0]) == 101
                            # A configured response-header removal or override
                            # also applies to late fields; a trailer must not
                            # reintroduce a value after the edited head.
                            response_end = _ResponseEnd(
                                new_head, req_method, configured_response_fields)
                            media_problem = (
                                ("partial-content" if status == 206 else
                                 "instance-manipulation" if status == 226 else
                                 _dlp_media_problem(new_head))
                                if dlp is not None and not response_end.done else "")
                            if media_problem:
                                # Archives, multipart, range and delta-coded
                                # responses are not equivalent to the raw
                                # stream being scanned. A client can assemble
                                # 206 parts or reverse 226 IM transformations.
                                # MIME が既知なら head 公開前に遮断または監査する。
                                if (dlp.sh.note_unscannable(ip, media_problem)
                                        .get("action") == "block"):
                                    leak_stop = True
                                    break
                                dlp = None
                            if dlp is not None and not response_end.done:
                                # A valid HEAD/204/304 or CL:0 has no entity
                                # to parse. In particular, an empty XML body
                                # must not be reported as malformed XML.
                                dlp.head(new_head)
                            if sec_cfg is not None:
                                try:
                                    new_head = inject_security_headers(new_head, sec_cfg, tls=tls,
                                                                       add_headers=add_sec,
                                                                       harden_cookies=harden_ck,
                                                                       harden_cors=harden_cors)
                                except (TypeError, ValueError, UnicodeError) as exc:
                                    self.metrics["response_config_invalid"] = (
                                        self.metrics.get("response_config_invalid", 0) + 1)
                                    self._defense_unavailable("response_headers", exc)
                                    leak_stop = True
                                    break
                            else:
                                new_head = _strip_origin_response_metadata(new_head)
                            if harden_redir:          # #71: オープンリダイレクト無害化
                                new_head = self._apply_redirect_policy(new_head, req_host, ip)
                            if private:
                                new_head = _private_cache_head(new_head)
                            out_head, chunk = new_head + b"\r\n\r\n", bytes(hbuf[idx + 4:])
                            hbuf, head_done = bytearray(), True   # head 以降=body として今回処理へ続行
                        # head も DLP を通してから送る(#59)。旧実装は加工した head を走査せずに
                        # 送っていたため、head 加工が有効(cookie/CORS 加工は既定 ON)だと応答
                        # ヘッダの秘密(X-Debug-Key・Set-Cookie のトークン等)が素通りした。
                        # head は CRLFCRLF で閉じるので body 側の保留窓は要らない=従来どおり即送る。
                        if dlp is not None:
                            kinds = dlp.sh.scan_leak(out_head)
                            if not kinds:
                                urls = _dlp_decoded_url_head_values(out_head)
                                if urls:
                                    kinds = dlp.sh.scan_leak(urls)
                            if not kinds:
                                filenames, ambiguous = _dlp_filename_head_values(out_head)
                                if ambiguous:
                                    if (dlp.sh.note_unscannable(ip, "response-disposition")
                                            .get("action") == "block"):
                                        leak_stop = True
                                        break
                                    dlp = None       # audit: preserve the exact original head
                                elif filenames:
                                    kinds = dlp.sh.scan_leak(filenames)
                            if dlp is not None and kinds:
                                if dlp.sh.note_leak(ip, kinds).get("action") == "block":
                                    leak_stop = True
                                    break
                                dlp = None        # audit: 記録したら走査停止(body 経路と同じ)
                            elif dlp is not None and upgraded:
                                # The framing and encoding after 101 are unknown to HTTP DLP.
                                if dlp.sh.note_unscannable(ip, "protocol-upgrade").get("action") == "block":
                                    leak_stop = True
                                    break
                                dlp = None
                        await send_response(out_head, whole=True)
                    if leak_stop:
                        break
                    if not chunk and not (response_end is not None and response_end.done):
                        continue
                finished = False
                if response_end is not None and response_end.known:
                    used = response_end.feed(chunk)
                    if response_end.bad:
                        self.metrics["backend_invalid_response"] = (
                            self.metrics.get("backend_invalid_response", 0) + 1)
                        if dlp is not None:
                            dlp.sh.note_unscannable(ip, "response-framing")
                        break                   # structural errors never become audit pass-through
                    else:
                        chunk, finished = chunk[:used], response_end.done
                if dlp is not None:
                    # 本文: 走査して送ってよい分だけ送る(block の漏洩=保留分も含め送らず切断)。
                    out, stop = dlp.feed(chunk)
                    if stop:
                        break
                    if out:
                        await send_dlp(out)
                    if not dlp.active:            # audit で記録済み / 走査不能=以降は素通し
                        dlp.close()
                        dlp = None
                    if finished:
                        if dlp is not None:
                            out, stop = dlp.eof()
                            if out and not stop:
                                await send_dlp(out)
                        break
                    continue
                if chunk:
                    await send_response(chunk)
                if finished:
                    break
        except _EgressQuotaReached:
            pass
        except _DrainedStall as exc:
            total += exc.sent_bytes
        except Exception:
            if (dlp is not None and response_end is not None
                    and response_end.known and not response_end.done):
                dlp.sh.note_unscannable(ip, "response-framing")
        finally:
            if dlp is not None:
                dlp.close()
            try:
                dst.close()
            except Exception:
                pass
        return total

    def _conn_rate_exceeded(self, ip: str, limit: int) -> bool:
        """同一 IP の新規接続が 1 秒窓内で limit を超えたか(#10・RST/churn フラッド対策)。
        イベントループスレッドのみが触る=ロック不要。活動中の別IPを退避して
        窓をリセットしない。満杯時は最古の期限切れだけ再利用し、全件活動中なら
        新規IPを拒否する。超過で True(=即切断)。"""
        if type(limit) is not int or limit <= 0:
            return True
        now = self._loop.time() if self._loop else time.monotonic()
        ent = self._conn_rate.get(ip)
        if ent is not None:
            if now - ent[0] < 1.0:
                ent[1] = min(limit + 1, ent[1] + 1)
                return ent[1] > limit
            # Refreshing a window moves it to the insertion-order tail. The
            # first key is thus the oldest window when the table is full.
            self._conn_rate.pop(ip)
        if len(self._conn_rate) >= _CONN_RATE_CAP:
            if not self._conn_rate:
                return True
            oldest_ip, oldest = next(iter(self._conn_rate.items()))
            if now - oldest[0] < 1.0:
                return True  # every later window is also active
            self._conn_rate.pop(oldest_ip)
        self._conn_rate[ip] = [now, 1]
        return False

    @staticmethod
    def _norm_ip(ip: str) -> str:
        """peer/XFF 由来の IPv6 を NetShield と同じ正規形(pipeline._canon_ip)へ(#14)。dual-stack
        束縛時の射影アドレス(::ffff:192.0.2.1)は純IPv4へ、別表記は小文字/圧縮へ揃える(生の綴り
        だと BAN/状態の鍵と一致しない)。純IPv4(":"無し)は即返し=ゼロ負荷。"""
        if not ip or ":" not in ip:
            return ip
        try:
            from ..lifeform.pipeline import _canon_ip
            c = _canon_ip(ip)
            if not c and "%" in ip:
                # リンクローカル peer(fe80::1%eth0)のゾーンIDはカーネルが付けた受信 IF 名。
                # NetShield はゾーンID付きを鍵にしない(BAN できない)ので外して正規形にする。
                c = _canon_ip(ip.split("%", 1)[0])
            return c or ip
        except Exception:
            return ip

    @staticmethod
    def _close(writer):
        try:
            writer.close()
        except Exception:
            pass

    # ── 起動/停止(別スレッドのイベントループで常駐) ──
    async def _serve(self):
        if self._listen_sock is not None:
            # --cluster: 親も SO_REUSEPORT のソケットで待受ける。素の
            # start_server(host, port) だと、先に fork した子が SO_REUSEPORT で
            # 掴んだポートに対して EADDRINUSE になる。
            self._server = await asyncio.start_server(self._handle,
                                                      sock=self._listen_sock, start_serving=False)
        else:
            self._server = await asyncio.start_server(
                self._handle, self.listen_host, self.listen_port, start_serving=False)
        srv = self._server
        if self._start_cancel.is_set():
            srv.close()
            await srv.wait_closed()
            return
        await srv.start_serving()
        if self._start_cancel.is_set():
            srv.close()
            await srv.wait_closed()
            return
        self.listen_port = srv.sockets[0].getsockname()[1]
        self._stop_event = asyncio.Event()
        self._ready.set()
        # 受理は start_server の時点で始まっている(start_serving=True)ので serve_forever は
        # 使わない。コルーチンの寿命は stop_event に委ね、受理停止は Server.close()(listener
        # だけを閉じる)で行う=進行中の _handle タスクは生かしたまま drain を待てる。
        # serve_forever を走らせていると、Server.close() がそれをキャンセルし、3.15 以降は
        # そのキャンセル処理が close_clients() まで呼ぶ=drain の最初に進行中の接続を切る(#54)。
        check_task = asyncio.ensure_future(self._periodic_checks_loop())
        try:
            await self._stop_event.wait()
        finally:
            check_task.cancel()
            try:
                await check_task
            except (asyncio.CancelledError, Exception):
                pass
            # drain を経ずに抜けた(例外・停止合図の直接送付)ときも listener は必ず閉じる
            # (以前は serve_forever のキャンセルが担っていた)。次の start() が bind できる。
            try:
                srv.close()
            except Exception:
                pass

    async def _periodic_checks_loop(self, interval: float = 30.0):
        """トラフィック非依存の定期セキュリティチェックを回す独立ループ(自己再起動/生存監視とは
        無関係): 迂回検知(#78 traffic_stall_check)と in-memory cfg 改竄検知(#85
        verify_cfg_integrity)。以前は watchdog の周期タスクに便乗していたが、どちらも
        自動復旧(watchdog)とは別物のセキュリティ機能なのでここへ独立させてある。"""
        try:
            while True:
                await asyncio.sleep(interval)
                try:
                    from ..lifeform.pipeline import net_shield
                    net_shield().traffic_stall_check()   # #78: 迂回検知(busy→突然ゼロ=バイパスの疑い)
                    net_shield().verify_cfg_integrity()  # #85: in-memory cfg すり替え検知+復元
                except Exception:
                    pass
        except asyncio.CancelledError:
            pass

    # ── 生存/再起動アクセサ(基本のスレッド状態操作。自動復旧の配線はしない) ──
    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def restart(self) -> dict:
        """強制再起動: 既存スレッド/ループを止めて新しい serving スレッドを起こす(手動/管理操作
        向けユーティリティ)。listener を握ったままの完全ハングは同ポート再 bind が確実でない
        (正直な限界)。"""
        with self._lifecycle_lock:
            try:
                stopped = self.stop(grace=0.0)
            except Exception as exc:
                return {"ok": False, "error": f"停止に失敗しました: {exc}"}
            if stopped.get("ok") is not True:
                return {"ok": False, "error": "停止が完了していないため再起動できません"}
            return self.start()

    async def _drain(self, grace: float):
        """graceful shutdown: ① 新規受理を止め ② 進行中の接続が捌けるのを最大 `grace` 秒待ち
        ③ 停止合図。`grace<=0`(既定)は待たず即時=従来挙動。残接続数を返す。
        新規受理の停止は Server.close() で行う。close() 自体が閉じるのは listener だけで、
        進行中の接続には触らない(3.10〜3.15 共通)。ただし serve_forever を走らせていると
        close() がそれをキャンセルし、3.15 ではその後始末が close_clients() まで呼ぶので、
        _serve は serve_forever を使わない。"""
        if self._server is not None:
            # 以前は Server.sockets の各要素を close() していたが、3.11+ のそれは close() を
            # 持たない TransportSocket で、例外は握り潰されて listener は開いたままだった
            # (猶予中も新規接続を受理・中継し、絶え間ない負荷では drain が終わらない・#54)。
            try:
                self._server.close()
            except Exception:
                pass
        deadline = self._loop.time() + self._clamp_grace(grace)
        while self._active > 0 and self._loop.time() < deadline:
            await asyncio.sleep(0.05)
        remaining = self._active
        if remaining:
            # 猶予を過ぎても捌けなかった接続は、ここで確実に閉じる。graceful shutdown の
            # 約束は「grace 秒までは待つ」であって「いつまでも放置する」ではない。
            for _w in list(self._live):
                try:
                    _w.close()
                except Exception:
                    pass
            self._live.clear()
            await asyncio.sleep(0)                # close を1度まわしてから後片付けへ
        # 猶予を使い切った待ち行列は見送り、実行中の行は pending として保持。
        self._close_usage_jobs()
        if self._server is not None:
            try:
                self._server.close()              # 冪等(既に閉じていれば何もしない)
            except Exception:
                pass
            try:
                # ループが生きているうちに後片付けを終わらせる。ここを待たずにループを
                # 閉じると、残ったトランスポートが Server より後に GC され、asyncio 内部で
                # `Exception ignored in _SelectorTransport.__del__` → Server._wakeup が
                # 二度呼ばれて TypeError、というトレースが大量に出る(実測: 高負荷時の停止
                # 5 回に 1 回、1 回あたり 30 本)。製品としては「停止のたびにログが
                # クラッシュしたように見える」ので、ここで確実に畳む。
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except Exception:
                pass
        if self._stop_event is not None:
            self._stop_event.set()                # _serve を解放=ループ終了
        return remaining

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        # 停止時の CancelledError / pending task 警告(デーモンループ終了の正常ノイズ)を黙らせる
        self._loop.set_exception_handler(lambda loop, ctx: None)
        try:
            self._loop.run_until_complete(self._serve())
        except asyncio.CancelledError:
            pass
        except Exception as e:
            # 起動失敗(ポート使用中・権限不足・名前解決不能 等)の理由を捨てていたため、
            # 呼び出し側には 5 秒後に「起動タイムアウト」としか見えなかった。理由を残し、
            # _ready を立てて即座に返せるようにする(待たせない・原因が分かる)。
            self._start_error = f"{type(e).__name__}: {e}"
        finally:
            self._ready.set()             # 成功・失敗どちらでも待機側を解放する
            if self._server is not None:
                self._server.close()
            # Close transports and consume task cancellation while their loop exists.
            for writer in list(self._live):
                self._close(writer)
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                try:
                    self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except (Exception, asyncio.CancelledError):
                    pass
            self._close_usage_jobs()
            try:
                self._loop.close()
            except Exception:
                pass

    @staticmethod
    def _raise_fd_limit():
        """開ける FD のソフト上限をハード上限まで引き上げる(#79・Unix のみ・best-effort)。
        接続枯渇攻撃に対する頭打ち(max_total_conn)を実効化する余裕を確保。非対応は no-op。"""
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft < hard:
                resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        except Exception:
            pass

    def start(self, timeout: float = 5.0) -> dict:
        with self._lifecycle_lock:
            new_listener = (not (self._thread is not None and self._thread.is_alive())
                            and not self._workers)
            if new_listener:
                try:
                    self._ensure_serving_lease()
                except Exception as exc:
                    self._dispose_failed_start_lease()
                    return {"ok": False, "error": f"serving state lease unavailable: {exc}"}
            # A direct single listener also accepts signed policy edits from
            # another process. Verify the same snapshot/fence used by a
            # cluster-origin fallback before opening any socket.
            prepared = False
            if (not self._cluster_policy_sync and
                    not (self._thread is not None and self._thread.is_alive()) and
                    not self._workers):
                if not self._prepare_single_cluster_policy_sync():
                    self._release_cluster_commit_lock()
                    # Startup may have already latched a corrupt signed state.
                    # Existing Shield/ACL enforce and audit decisions must be
                    # observable on the wire, including audit's would-block.
                    # This exception is only for a known untrusted snapshot;
                    # an ordinary race or missing commit fence still refuses
                    # to open a listener.
                    from ..lifeform.pipeline import net_shield
                    from ..lifeform.policy import app_firewall
                    shield, firewall = net_shield(), app_firewall()
                    if (shield._cfg_state_untrusted or shield._sig_state_untrusted or
                            shield._ban_state_untrusted or
                            shield._traffic_state_untrusted or firewall._load_warning):
                        info = self._start(timeout)
                        if not info.get("ok") and not self.is_alive():
                            self._dispose_failed_start_lease()
                        return info
                    self._dispose_failed_start_lease()
                    return {"ok": False,
                            "error": "signed single-worker policy is unavailable"}
                prepared = True
            info = self._start(timeout)
            if prepared and not info.get("ok"):
                self._single_cluster_policy_sync = False
                self._single_ban_snapshot_verified = False
                self._single_traffic_source_stamps = None
                self._cluster_policy_sync = False
                self._policy_source_stamps = None
                self._release_cluster_commit_lock()
            if not info.get("ok") and not self.is_alive() and not self._workers:
                self._dispose_failed_start_lease()
            return info

    def _start(self, timeout: float) -> dict:
        self._usage_process_local()
        if self._thread is not None and self._thread.is_alive():
            return {"ok": False, "error": "前衛は起動中または停止処理中です"}
        if self._workers and self._listen_sock is None:
            return {"ok": False, "error": "既存ワーカーの停止が完了していません"}
        with _USAGE_CV:
            if self._log_pending:
                return {"ok": False, "error": "診断ログ書込が未完了のため再起動できません"}
            self._usage_closing = False
        import math
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= threading.TIMEOUT_MAX):
            return {"ok": False, "error": "起動待機時間は有限の正数で指定してください"}
        self._start_error = ""
        self._ready.clear()
        self._start_cancel.clear()
        self._server = self._stop_event = None
        self._raise_fd_limit()                        # #79: FD ソフト上限を引き上げ(可能なら)
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="ducknet-edge")
        try:
            self._thread.start()
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if not self._ready.wait(timeout):
            self._start_cancel.set()
            self._stop(0.0)
            return {"ok": False, "error": "起動タイムアウト"}
        if self._start_error:                         # 待受に失敗した実際の理由を返す
            self._thread.join(timeout=1.0)
            return {"ok": False, "error": self._start_error}
        if self._start_cancel.is_set() or not self.is_alive() or self._server is None:
            return {"ok": False, "error": "前衛の待受が開始されませんでした"}
        from ..core.netaddr import hostport as _hp      # IPv6 リテラルは [] で囲う
        return {"ok": True, "listen": _hp(self.listen_host, self.listen_port),
                "backend": _hp(self.backend_host, self.backend_port),
                "note": "asyncio Fail-Fastガード。block/denyは即TCP切断(スレッド非消費)。"}

    def url(self) -> str:
        from ..core.netaddr import url as _url          # IPv6 リテラルは [] で囲う
        return _url(self.listen_host, self.listen_port)

    _grace_shm = None             # --cluster: 停止時の drain 猶予をワーカーへ渡す共有メモリ(#56)
    _worker_draining = False      # --cluster のワーカー側: SIGTERM を受けて drain 中
    _MAX_DRAIN_GRACE_SEC = _MAX_DRAIN_GRACE_SEC  # 停止を無期限に保持しない

    @staticmethod
    def _clamp_grace(grace) -> float:
        """drain 猶予を有限の非負秒へ正規化する(#55)。`--drain-grace inf` や 1e7
        (「捌けるまで待つ」のつもり)をそのまま待機 API へ渡すと threading の上限
        (Windows で約 49 日)を超えて OverflowError になり、stop() がワーカー刈り取り・
        listener の後始末の手前で例外脱出していた。
        API から直接呼ばれた場合も 300 秒に制限する。NaN・負・数値でない値は
        0(即時停止)。CLI/env の入力は起動前に別途拒否または既定へ戻す。"""
        try:
            g = float(grace)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if not g > 0.0:                           # NaN も負もここで落ちる
            return 0.0
        return min(g, AsyncEdgeGuard._MAX_DRAIN_GRACE_SEC)

    def stop(self, grace: float = 0.0) -> dict:
        """停止。`grace>0` なら進行中リクエストを最大 grace 秒ドレイン(受理停止→捌けるまで待機)。
        既定 grace=0 は従来どおり即時停止(後方互換)。別スレッドのループへ drain を投入して待つ。
        --cluster のワーカーにも先に合図して、親と同時に drain させる(#56)。"""
        with self._lifecycle_lock:
            return self._stop(grace)

    def _stop(self, grace: float = 0.0) -> dict:
        self._start_cancel.set()
        grace = self._clamp_grace(grace)
        since = time.monotonic()
        self._signal_workers(grace)
        remaining = None
        loop = self._loop
        # ループが走っている時だけ drain を投入する。停止済み(例: restart() 呼び出し直後)へ
        # run_coroutine_threadsafe すると _drain コルーチンが await されず警告+無駄な5s待機になる。
        if loop is not None and loop.is_running():
            try:
                fut = asyncio.run_coroutine_threadsafe(self._drain(grace), loop)
                try:
                    remaining = fut.result(timeout=grace + 5.0)
                except Exception:
                    fut.cancel()
                    if self._stop_event is not None:
                        loop.call_soon_threadsafe(self._stop_event.set)
            except Exception:               # 競合で停止した=ベストエフォート
                if self._stop_event is not None:
                    try:
                        loop.call_soon_threadsafe(self._stop_event.set)
                    except Exception:
                        pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=grace + 5.0)
        self._close_usage_jobs()        # loop未起動/異常終了時にも待ち行列を所有して回収
        # --cluster 用の listener は *持ち越さない*。ループ側で既に閉じられているため、
        # 残しておくと次の start()(watchdog の restart など)が **閉じたソケット** を
        # asyncio へ渡して二度と起動できなくなる。次回は素の bind でやり直す
        # (ワーカーは下で刈り取るので SO_REUSEPORT を共有する相手はもう居ない)。
        ls, self._listen_sock = self._listen_sock, None
        if ls is not None:
            try:
                ls.close()
            except Exception:
                pass
        reaped = self._stop_workers(grace, since=since)
        # Keep the parent writer through normal SIGTERM drain, then release it.
        # If an unreaped worker remains, EOF makes it stop serving as well.
        self._close_parent_guard()
        if not self._workers:
            self._release_cluster_quota_guard()
            self._release_cluster_commit_lock()
            self._cluster_policy_sync = False
            self._single_cluster_policy_sync = False
            self._single_ban_snapshot_verified = False
            self._single_traffic_source_stamps = None
            self._policy_source_stamps = None
        # asyncio のトランスポート/プロトコルは循環参照を作るため、参照カウントだけでは
        # 解放されない。stop() から戻った時点でソケットの FD が世代別 GC 任せで開いたまま
        # 残り(実測: 高負荷停止の直後に 31 本。gc.collect() で 5 本まで落ちる)、
        # 遅れて回収されるときに asyncio 内部が停止済みの Server を触って
        # `Exception ignored in _SelectorTransport.__del__` を撒き散らす。
        # stop() は毎秒走る経路ではない(停止/再起動時のみ)ので、ここで確実に回収する。
        # CPython の asyncio.Server._wakeup は *再入不可* (2 回目は self._waiters が None の
        # まま反復して TypeError)。一方 Server._clients は WeakSet なので、放置された
        # トランスポートが GC でまとめて回収されると、_detach が「残り 0 件」を何度も観測して
        # _wakeup を連打する ―― 結果 `Exception ignored in _SelectorTransport.__del__` の
        # トレースが 1 回の停止で数十本、ログへ流れる(実測 10 回に 3 回)。
        # ここまで来た Server は閉じ済みで、もう誰も wait_closed() で待っていないので、
        # このインスタンスの wakeup だけ無効化して黙らせる(挙動には影響しない)。
        srv = self._server
        if srv is not None:
            try:
                srv._wakeup = lambda: None
            except Exception:
                pass
        import gc
        gc.collect()
        with _USAGE_CV:
            last_worker = (_USAGE_WORKER if not _USAGE_OPEN and not _USAGE_QUEUE
                           and _USAGE_RUNNING is None else None)
        if last_worker is not None and last_worker is not threading.current_thread():
            last_worker.join(timeout=0.1)  # 最後の idle worker の終了通知を回収
        with _USAGE_CV:
            log_pending = self._log_pending
            usage_pending = self._usage_pending
            acl_pending = self._acl_pending
        stopped = (not (self._thread is not None and self._thread.is_alive())
                   and not self._workers and log_pending == 0)
        flush_ok = True
        if stopped:
            # No worker or loop task can still own staged bytes. A later
            # cluster start must create a fresh generation of the counter.
            self._close_body_stage_executor()
            self._close_shared_body_stage()
        if stopped and self._serving_lease is not None:
            # Keep the exclusive state owner through the final signed BAN and
            # quota flush. A new listener must not load the previous quota
            # while this process still has unsaved response accounting.
            flush_ok = self._finish_serving_lease()
        return {"ok": stopped and flush_ok, "stopped": stopped, "drained": remaining,
                "workers_stopped": reaped, "log_pending": log_pending,
                "usage_log_pending": usage_pending, "acl_log_pending": acl_pending,
                "metrics": dict(self.metrics)}

    def _signal_workers(self, grace: float = 0.0, pids=None) -> None:
        """--cluster のワーカーへ drain 開始を合図する(待たない・#56)。猶予は共有メモリ経由で
        渡す ―― ワーカーは SIGTERM を受けたらそれを読み、親と同じ drain(受理停止→最大
        grace 秒待機→残りを閉じる)をしてから抜ける。"""
        pids = list(self._workers) if pids is None else pids
        if not pids or not hasattr(os, "kill"):
            return
        shm = self._grace_shm
        if shm is not None:
            try:
                import struct
                shm[:8] = struct.pack("d", self._clamp_grace(grace))
            except Exception:
                pass
        import signal as _sig
        for pid in pids:
            try:
                # A separately reaped child may have had its PID reused. Never
                # signal a PID unless waitpid still confirms it is our live child.
                if os.waitpid(pid, os.WNOHANG)[0]:
                    continue
                os.kill(pid, _sig.SIGTERM)
            except OSError:
                pass

    def _stop_workers(self, grace: float = 0.0, since: float = None) -> int:
        """--cluster で fork したワーカーを確実に終わらせる。
        旧実装は子 pid を集めるだけで誰も止めておらず、親へ SIGTERM を送ると
        *親だけが死んで子が待受ポートを握ったまま生き残った*(実測: 13 ワーカー全残存・
        前衛ポートも管理ポートも開いたまま)。SIGTERM → 猶予 → SIGKILL で刈り取る。
        ワーカーは SIGTERM で自分の drain をしてから抜ける(#56)。stop() は先に合図済み
        なので、待つ期限はその時刻(since)から数える(親の drain と同時進行)。"""
        pids = list(self._workers)
        if not pids or not hasattr(os, "kill"):
            shm, self._grace_shm = self._grace_shm, None
            if shm is not None:
                try:
                    shm.close()
                except Exception:
                    pass
            return 0
        import signal as _sig
        grace = self._clamp_grace(grace)
        self._signal_workers(grace, pids)     # 合図済みでも再送は無害(ワーカー側で一度きり)
        start = time.monotonic() if since is None else since
        deadline = start + max(1.0, grace + 2.0)
        alive = list(pids)
        while alive and time.monotonic() < deadline:
            for pid in list(alive):
                try:
                    done, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    done = pid                # 既に回収済み
                except OSError:
                    done = 0                  # 確認できない PID の所有権は残す
                if done:
                    alive.remove(pid)
            if alive:
                time.sleep(0.05)
        for pid in list(alive):               # 猶予を過ぎても残るものは強制終了
            try:
                os.kill(pid, getattr(_sig, "SIGKILL", _sig.SIGTERM))
            except OSError:
                continue
            kill_deadline = time.monotonic() + 2.0
            while time.monotonic() < kill_deadline:
                try:
                    done, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    done = pid
                except OSError:
                    break
                if done:
                    alive.remove(pid)
                    break
                time.sleep(0.01)
        self._workers = alive
        if alive:
            return len(pids) - len(alive)
        shm, self._grace_shm = self._grace_shm, None
        if shm is not None:
            try:
                shm.close()
            except Exception:
                pass
        return len(pids)

    def serve_forever(self) -> None:
        info = self.start()
        if not info.get("ok"):
            raise RuntimeError(info.get("error"))
        print(f"DuckNet async edge guard: "
              f"{info['listen']} -> {info['backend']}")
        try:
            while True:
                time.sleep(0.5)
                if not self.is_alive():
                    break                         # serving スレッドが死ねば終了(自動再起動はしない)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ── マルチコア(SO_REUSEPORT + fork)。可用OSのみ・Windowsは正直に単一へ降格 ──
    def _reuseport_socket(self):
        # AF_INET 固定だと --host に IPv6(:: 等)を指定したクラスタ起動が必ず失敗する。
        # 単一プロセス経路は asyncio が解決してくれるので、ここだけ取り残されていた。
        fam = socket.AF_INET
        try:
            infos = socket.getaddrinfo(self.listen_host or None, self.listen_port,
                                       type=socket.SOCK_STREAM)
            if infos:
                fam = infos[0][0]
        except OSError:
            pass
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind((self.listen_host, self.listen_port))
            s.listen(1024)
            s.setblocking(False)
            return s
        except BaseException:
            s.close()
            raise

    def _worker_blocking(self):
        # A parent may die between fork and the child's first listener bind.
        if not self._parent_guard_alive():
            return
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(lambda l, c: None)
        self._loop = loop
        self._server = self._stop_event = None     # fork 元(親)の値を引き継がない
        if self._worker_parent_guard:
            try:
                loop.add_reader(self._parent_guard_read, self._worker_on_parent_dead)
            except (NotImplementedError, RuntimeError, ValueError, OSError):
                # Some POSIX event loops omit add_reader. Direct admission and
                # backend-write checks still fail closed; polling exits idle
                # workers without waiting for a new connection.
                async def poll_parent():
                    while self._parent_guard_alive():
                        await asyncio.sleep(0.02)
                    self._worker_on_parent_dead()
                self._parent_guard_poll_task = loop.create_task(poll_parent())
        sock = self._reuseport_socket()       # 各ワーカーが同ポートを共有listen
        if not self._parent_guard_alive():
            sock.close()
            self._worker_on_parent_dead()
            return

        async def _s():
            # 受理は start_server の時点で始まる。serve_forever を使わない理由は _serve と同じ。
            if not self._parent_guard_alive():
                sock.close()
                return
            srv = self._server = await asyncio.start_server(self._handle, sock=sock)
            self._stop_event = asyncio.Event()
            if not self._parent_guard_alive():
                self._worker_on_parent_dead()
            if self._worker_draining and not self._worker_parent_dead:  # 待受前に SIGTERM
                self._worker_drain_task = asyncio.ensure_future(
                    self._drain(self._worker_grace()))
            try:
                await self._stop_event.wait()     # drain が立てる
            finally:
                try:
                    srv.close()
                except Exception:
                    pass
        # SIGTERM で即死させず、親と同じ drain(受理停止→最大 grace 秒待機→残りを閉じる)を
        # してから抜ける(#56)。以前は SIG_DFL のままで、親が自分の drain をしている間も
        # 新規受理を続け、その後の SIGTERM で進行中のリクエストごと切られていた。
        # 張れなければ従来どおり SIG_DFL(即終了)。抜けた後は呼び出し側が os._exit する。
        try:
            import signal as _sig
            loop.add_signal_handler(_sig.SIGTERM, self._worker_on_term)
        except Exception:
            pass
        try:
            loop.run_until_complete(_s())
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            # Unlike the threaded _run path, this process exits through
            # os._exit: pending handler finalizers will never run unless we
            # cancel and join them while this loop is still alive. In
            # particular, staged-body quota must be released after spool I/O.
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                try:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except (Exception, asyncio.CancelledError):
                    pass
            self._close_body_stage_executor()
            self._close_shared_body_stage()
            self._close_parent_guard(read=True, write=False)
            # CPython 3.12's UnixSelectorEventLoop.close() closes its
            # self-pipe before it removes signal handlers. A concurrent
            # second SIGTERM can write to that dead wakeup fd. Remove our
            # handler first; any later SIGTERM may terminate this already
            # drained child immediately before os._exit.
            try:
                import signal as _sig
                loop.remove_signal_handler(_sig.SIGTERM)
            except Exception:
                pass
            loop.close()

    def _worker_grace(self) -> float:
        """親が stop(grace) で共有メモリへ書いた猶予。親を経ない SIGTERM(未記入)は 0=即時。"""
        shm = self._grace_shm
        if shm is None:
            return 0.0
        try:
            import struct
            return self._clamp_grace(struct.unpack("d", shm[:8])[0])
        except Exception:
            return 0.0

    def _worker_on_term(self):
        """ワーカーの SIGTERM(ループ内で呼ばれる): 親と同じ drain を始める(一度きり)。"""
        if self._worker_draining:
            return
        self._worker_draining = True
        if self._stop_event is not None:          # 待受前なら _s() が待受直後に始める
            # 参照を保持する(ループはタスクを弱参照でしか持たない=途中で回収され得る)
            self._worker_drain_task = self._loop.create_task(
                self._drain(self._worker_grace()))

    def serve_cluster(self, workers: int = 0) -> dict:
        """CPUコア数ぶんの asyncio ループで同一ポートを SO_REUSEPORT 共有待受(全コア解放)。
        SO_REUSEPORT/fork 非対応OS(Windows等)では **正直に単一プロセスへフォールバック**。"""
        with self._lifecycle_lock:
            if self.is_alive() or self._workers:
                return {"ok": False, "mode": "cluster", "error": "前衛は既に起動中です"}
            if type(workers) is not int or not 0 <= workers <= 1024:
                return {"ok": False, "mode": "cluster", "error": "workers は0〜1024の整数で指定してください"}
            try:
                self._ensure_serving_lease()
            except Exception as exc:
                self._dispose_failed_start_lease()
                return {"ok": False, "mode": "cluster", "workers": 0,
                        "error": f"serving state lease unavailable: {exc}"}
            try:
                result = self._serve_cluster(workers)
            except BaseException:
                if (not self.is_alive() and not self._workers
                        and self._listen_sock is None and self._server is None):
                    self._close_shared_body_stage()
                    self._dispose_failed_start_lease()
                raise
            if (not result.get("ok") and not self.is_alive() and not self._workers
                    and self._listen_sock is None and self._server is None):
                self._close_shared_body_stage()
                self._dispose_failed_start_lease()
            return result

    @staticmethod
    def _finite_quota_requires_single_worker() -> bool:
        """An in-flight IP quota cannot be multiplied across forked memories."""
        try:
            from ..lifeform.pipeline import net_shield
            shield = net_shield()
            with shield._lock:
                return shield._finite_quota_active(shield.cfg)
        except Exception:
            return True

    @staticmethod
    def _same_cluster_policy_dir(shield, firewall) -> bool:
        """One file lock must cover both signed Shield and ACL writers."""
        try:
            return (os.path.realpath(os.path.dirname(shield.path)) ==
                    os.path.realpath(os.path.dirname(firewall.path)))
        except Exception:
            return False

    def _release_cluster_quota_guard(self) -> None:
        if self._workers:
            return
        shield = self._cluster_quota_shield
        self._cluster_quota_shield = None
        if shield is not None:
            shield._release_fork_cluster()
        firewall = self._cluster_acl_firewall
        self._cluster_acl_firewall = None
        if firewall is not None:
            firewall._release_fork_cluster()

    def quiesce_cluster_for_mutation(self) -> dict:
        """Reap fork copies before acknowledging a parent-only defense edit.

        The parent listener continues to serve as a single worker.  Returning
        failure with live child ownership leaves the old policy unchanged.
        """
        with self._lifecycle_lock:
            children = list(self._workers)
            if not children:
                return {"ok": True, "cluster_downgraded": False}
            if not self.is_alive() or self._server is None:
                return {"ok": False, "error": "cluster parent listener is unavailable"}
            try:
                reaped = self._stop_workers(0.0)
            except Exception:
                return {"ok": False, "error": "cluster workers could not be stopped"}
            if self._workers or reaped != len(children) or not self.is_alive():
                return {"ok": False, "error": "cluster workers remain active"}
            self._close_parent_guard()
            self._release_cluster_quota_guard()
            # This parent now serves alone, but an external signed writer can
            # still publish a newer policy before the admin setter commits.
            # Keep verified source sync and first-write fencing active; an
            # otherwise failed compare-and-swap must not reopen the old policy.
            self._single_cluster_policy_sync = True
            self._single_ban_snapshot_verified = True
            self._single_traffic_source_stamps = None
            self._policy_source_stamps = None
            return {"ok": True, "cluster_downgraded": True,
                    "cluster_mode": "single", "workers_stopped": reaped}

    def _prepare_single_cluster_policy_sync(self) -> bool:
        """Verify signed sources before advertising a cluster-origin single."""
        from ..core.signed_state import payload_fingerprint
        from ..lifeform.pipeline import net_shield
        from ..lifeform.policy import app_firewall

        try:
            shield, firewall = net_shield(), app_firewall()
            if not self._same_cluster_policy_dir(shield, firewall):
                return False
            paths = self._cluster_policy_sources(shield, firewall)
            for _ in range(3):
                before = tuple(_signed_source_stamp(path) for path in paths)
                if (not shield.reload_config_verified()
                        or not shield.reload_signatures_verified()
                        or not firewall.reload_verified()):
                    return False
                ban_status = self._cluster_bans_ready(shield)
                if ban_status not in ("ready", "legacy"):
                    return False
                if ban_status == "legacy":
                    # The startup compatibility loader already applied this
                    # exact verified payload. A newer external legacy file
                    # cannot be silently served from that older memory.
                    status = []
                    payload, _ = shield._read_state(shield._bans_path, {}, "bans",
                                                     status_out=status)
                    if (status != ["ok"] or
                            payload_fingerprint(payload) !=
                            shield._state_fingerprints.get(shield._bans_path)):
                        return False
                self._check_single_traffic_source(shield)
                after = tuple(_signed_source_stamp(path) for path in paths)
                if before != after:
                    continue
                lock = self._ensure_cluster_commit_lock()
                if not lock.acquire(timeout=commit_barrier.WAIT_SEC):
                    return False
                try:
                    if not lock.verify_path():
                        return False
                finally:
                    lock.release()
                self._single_ban_snapshot_verified = True
                self._single_cluster_policy_sync = True
                self._cluster_policy_sync = True
                self._policy_source_stamps = after
                self._policy_sync_pid = os.getpid()
                return True
        except Exception:
            return False
        return False

    def _start_single_cluster_fallback(self, reason: str, caps: dict) -> dict:
        if not self._prepare_single_cluster_policy_sync():
            self._release_cluster_commit_lock()
            return {"ok": False, "mode": "single", "workers": 0,
                    "cluster_downgraded": False, "reason": reason,
                    "error": "signed single-worker policy is unavailable",
                    "child_pids": [], "capabilities": caps}
        info = self.start()
        ok = bool(info.get("ok"))
        if not ok:
            self._single_cluster_policy_sync = False
            self._single_ban_snapshot_verified = False
            self._single_traffic_source_stamps = None
            self._cluster_policy_sync = False
            self._policy_source_stamps = None
            self._release_cluster_commit_lock()
        return {"ok": ok, "mode": "single", "workers": 1 if ok else 0,
                "cluster_downgraded": ok, "reason": reason,
                "child_pids": [], "capabilities": caps,
                "listen": info.get("listen"), "error": info.get("error", ""),
                "telemetry_scope": "single", "telemetry_complete": ok}

    def _serve_cluster(self, workers: int) -> dict:
        caps = self.platform_capabilities()
        if not (caps["so_reuseport"] and caps["os_fork"]):
            return self._start_single_cluster_fallback(
                "SO_REUSEPORT/fork非対応のOS→単一プロセス(正直な降格)", caps)
        n = workers or caps["cpu_count"]
        if n <= 1:
            return self._start_single_cluster_fallback(
                "one worker requested or available", caps)
        if n > 1:
            try:
                from ..lifeform.pipeline import net_shield
                from ..lifeform.policy import app_firewall
                shield = net_shield()
                firewall = app_firewall()
                same_policy_dir = self._same_cluster_policy_dir(shield, firewall)
                verified = (shield.reload_config_verified()
                            and shield.reload_signatures_verified()
                            and firewall.reload_verified())
            except Exception:
                same_policy_dir = False
                verified = False
            if not verified:
                return {"ok": False, "mode": "cluster", "workers": 0,
                        "error": "signed cluster policy is unavailable",
                        "child_pids": []}
            if not same_policy_dir:
                return self._start_single_cluster_fallback(
                    "Shield and ACL policy state directories differ", caps)
        if n > 1:
            ban_status = self._cluster_bans_ready(shield)
            if ban_status != "ready":
                if ban_status == "untrusted":
                    return {"ok": False, "mode": "cluster",
                            "error": "signed BAN state is untrusted; cluster not started",
                            "child_pids": []}
                return self._start_single_cluster_fallback(
                    "signed legacy BAN snapshot requires one worker", caps)
            reason = self._cluster_unshared_reason(shield, firewall)
            if reason:
                return self._start_single_cluster_fallback(
                    f"{reason} is process-local; using one worker", caps)
            try:
                reserved = shield._reserve_fork_cluster()
                if reserved:
                    self._cluster_quota_shield = shield
                    reserved = firewall._reserve_fork_cluster()
                    if reserved:
                        self._cluster_acl_firewall = firewall
                    else:
                        self._release_cluster_quota_guard()
            except Exception:
                self._release_cluster_quota_guard()
                reserved = False
            if not reserved:
                return self._start_single_cluster_fallback(
                    "cluster state reservation failed during policy mutation", caps)
        if n > 1:
            try:
                self._ensure_cluster_commit_lock()
            except Exception as exc:
                self._release_cluster_quota_guard()
                self._cluster_policy_sync = False
                self._policy_source_stamps = None
                # Serving without this cross-process fence would let a signed
                # external policy change race past the last checked decision.
                # Do not advertise an available single worker in that state.
                return {"ok": False, "mode": "cluster", "workers": 0,
                        "reason": "cluster policy commit barrier is unavailable",
                        "capabilities": caps, "child_pids": [],
                        "error": f"cluster policy commit barrier unavailable: {type(exc).__name__}"}
            # This flag is inherited by fork children. Each child verifies
            # signed parent policy on first admission and after publication.
            self._cluster_policy_sync = True
            self._policy_source_stamps = None
            self._policy_sync_pid = os.getpid()
            # All process-local security decisions are disabled in this path.
            # Per-process proxy/ACL telemetry remains incomplete until an
            # authoritative shared owner is integrated and must be labelled.
            # 停止時の drain 猶予をワーカーへ渡す共有メモリ(#56)。匿名 mmap は fork 後も
            # 親子で同じ領域を指すので、親が stop(grace) で書いた値をワーカーが読める。
            try:
                import mmap
                self._grace_shm = mmap.mmap(-1, 8)
            except Exception:
                self._grace_shm = None
            try:
                self._open_parent_guard()
            except Exception as exc:
                self._stop_workers(0.0)
                self._release_cluster_quota_guard()
                self._release_cluster_commit_lock()
                self._cluster_policy_sync = False
                return {"ok": False, "mode": "cluster",
                        "error": f"parent liveness pipe unavailable: {type(exc).__name__}",
                        "child_pids": []}
            try:
                self._prepare_shared_body_stage(shield, n)
            except Exception as exc:
                self._close_parent_guard()
                self._release_cluster_quota_guard()
                self._release_cluster_commit_lock()
                self._cluster_policy_sync = False
                return {"ok": False, "mode": "cluster", "workers": 0,
                        "error": f"body staging budget unavailable: {type(exc).__name__}",
                        "child_pids": []}
        else:
            self._cluster_policy_sync = False
            self._policy_source_stamps = None
        pids = []
        for worker_slot in range(1, n):
            # Fork may otherwise copy an object RLock held by a parent setter
            # into a child with no owning thread. Wait for signed mutations to
            # finish, then freeze the singleton locks for this fork only.
            try:
                from ..lifeform.policy import app_firewall
                fork_firewall = app_firewall()
                held_policy_locks = commit_barrier.freeze_fork(shield, fork_firewall)
            except Exception as exc:
                self._stop_workers(0.0)
                self._close_parent_guard()
                self._release_cluster_quota_guard()
                self._release_cluster_commit_lock()
                return {"ok": False, "mode": "cluster",
                        "error": f"policy fork freeze failed: {type(exc).__name__}",
                        "child_pids": list(self._workers)}
            try:
                owner_fd = self._open_body_stage_owner(worker_slot)
            except Exception as exc:
                commit_barrier.thaw_parent(held_policy_locks)
                self._stop_workers(0.0)
                self._close_parent_guard()
                self._release_cluster_quota_guard()
                self._release_cluster_commit_lock()
                return {"ok": False, "mode": "cluster", "workers": 0,
                        "error": f"body staging owner unavailable: {type(exc).__name__}",
                        "child_pids": list(self._workers)}
            try:
                pid = os.fork()
            except OSError as exc:
                os.close(owner_fd)
                commit_barrier.thaw_parent(held_policy_locks)
                self._stop_workers(0.0)
                self._close_parent_guard()
                self._release_cluster_quota_guard()
                self._release_cluster_commit_lock()
                return {"ok": False, "mode": "cluster", "error": f"fork failed: {exc}",
                        "child_pids": list(self._workers)}
            if pid == 0:                      # 子ワーカー: 自分のループで待受(戻らない)
                try:
                    self._adopt_body_stage_owner(worker_slot, owner_fd)
                except BaseException:
                    os._exit(1)          # owner 不明の子は待受も転送もしない
                self._worker_parent_guard = True
                self._close_parent_guard(read=False, write=True)
                if self._parent_guard_read is None:
                    os._exit(1)
                try:
                    commit_barrier.thaw_child(shield, fork_firewall)
                except BaseException:
                    os._exit(1)           # lock を復元できない子は待受しない
                self._lifecycle_lock = threading.RLock()
                held_policy_locks = None
                # 親から継承したシグナル配線を既定へ戻す。親のハンドラは親の
                # threading.Event を叩くだけで子には効かず、SIGTERM を無視する
                # ワーカーが残る原因になる。SIGTERM は _worker_blocking が drain 用に張り直す。
                try:
                    import signal as _sig
                    for _s in ("SIGTERM", "SIGINT", "SIGBREAK"):
                        _h = getattr(_sig, _s, None)
                        if _h is not None:
                            _sig.signal(_h, _sig.SIG_DFL)
                except Exception:
                    pass
                self._workers = []            # 子は孫を持たない
                try:
                    self._worker_blocking()
                finally:
                    os._exit(0)
            os.close(owner_fd)             # 次の子には先の子の owner FD を継承させない
            commit_barrier.thaw_parent(held_policy_locks)
            pids.append(pid)
            self._workers = list(pids)
        self._workers = pids
        self._close_parent_guard(read=True, write=False)
        # 親も 1 ワーカーを担うが、*ブロックせずに戻る*。旧実装はここで
        # _worker_blocking() を呼んで戻らなかったため、呼び出し側の停止処理
        # (SIGTERM ハンドラ・ドレイン・状態 flush)へ一度も到達しなかった。
        try:
            self._listen_sock = self._reuseport_socket()   # 子と同じ条件で待受ける
        except OSError as e:
            self._stop_workers(0.0)
            self._close_parent_guard()
            self._release_cluster_quota_guard()
            self._release_cluster_commit_lock()
            return {"ok": False, "mode": "cluster", "workers": n,
                    "child_pids": [], "capabilities": caps,
                    "error": f"{type(e).__name__}: {e}"}
        info = self.start()
        if not info.get("ok"):
            try:
                self._listen_sock.close()
            except Exception:
                pass
            self._listen_sock = None
            self._stop_workers(0.0)
            self._close_parent_guard()
            self._release_cluster_quota_guard()
            self._release_cluster_commit_lock()
        return {"ok": bool(info.get("ok")), "mode": "cluster", "workers": n,
                "child_pids": list(self._workers), "capabilities": caps,
                "error": info.get("error", ""),
                "rate_limit_scope": "disabled",
                "telemetry_scope": "per-worker", "telemetry_complete": False,
                "note": "aggregate proxy and ACL telemetry is unavailable across workers"}
