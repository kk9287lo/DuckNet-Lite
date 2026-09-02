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
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time

from . import banner as deception


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
    """転送するリクエストヘッダの Connection を close に書き換える(keep-alive/pipelining による
    *検査回避* を封じる)。本機は接続の先頭リクエスト1本だけを検査して以降を生パイプするため、
    close を強制しないと keep-alive の2本目以降が未検査でバックエンドへ素通りする(WAFバイパス)。
    1接続=1リクエストにすることで毎リクエストが必ず検査経路を通る。head 不完全/body 部は保持。
    正直な限界: バックエンドが Connection: close を尊重する前提(準拠サーバはほぼ全て尊重する)。"""
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


def _strip_request_headers(buf: bytes, names_lower) -> bytes:
    """転送リクエスト head から指定ヘッダ(小文字名の集合)を除去する(#75)。リクエストライン/
    body は保持。head 不完全は不変。キャッシュ汚染を招く unkeyed ヘッダ(X-Forwarded-Host 等)を
    信頼 proxy 経由でないときに落とす用途。"""
    head, sep, rest = buf.partition(b"\r\n\r\n")
    if not sep:
        return buf
    names = {(n.encode("latin1", "replace") if isinstance(n, str) else n).lower()
             for n in names_lower}                  # str/bytes 混在を bytes に正規化して比較
    lines = head.split(b"\r\n")
    kept = lines[:1]
    for ln in lines[1:]:
        k = ln.split(b":", 1)[0].strip().lower()
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
    nl = name.strip().lower().encode("latin1", "replace")
    kept = [ln for ln in head.split(b"\r\n")
            if ln.split(b":", 1)[0].strip().lower() != nl]   # リクエストラインは ':' 無しで残る
    kept.append(name.encode("latin1", "replace") + b": " + value.encode("latin1", "replace"))
    return b"\r\n".join(kept) + b"\r\n\r\n" + rest


def _header_value(buf: bytes, name_lower: bytes) -> str:
    """head から指定ヘッダ(小文字名)の値を返す(無ければ空)。最初の1本のみ。"""
    head = buf.split(b"\r\n\r\n", 1)[0]
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(name_lower + b":"):
            return ln[len(name_lower) + 1:].strip().decode("latin-1", "replace")
    return ""


def _real_client_ip(peer_ip: str, buf: bytes, trusted) -> str:
    """信頼 proxy 経由のときだけ X-Forwarded-For から実クライアントIPを解決する。
    peer が trusted CIDR に含まれない(=直結 or 未設定)なら **XFF を信頼しない**(偽装無効化)。
    含まれるなら XFF を右(最も近いhop)から辿り、trusted でない最初の妥当IP=実クライアント。"""
    if not trusted or not peer_ip:
        return peer_ip
    from ..lifeform.netutil import ip_in_any
    if not ip_in_any(peer_ip, trusted):
        return peer_ip
    xff = _header_value(buf, b"x-forwarded-for")
    if not xff:
        return peer_ip
    for cand in reversed([p.strip() for p in xff.split(",") if p.strip()]):
        try:
            ipaddress.ip_address(cand)                # 妥当なIPのみ採用
        except ValueError:
            continue
        if not ip_in_any(cand, trusted):
            return cand
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
    # プロキシ連鎖("https, http")では先頭=元クライアントのプロトコルを採る。
    xfp = _header_value(buf, b"x-forwarded-proto").split(",", 1)[0].strip().lower()
    return xfp == "https"


# 解除リクエスト(異議申立)の受付パス。遮断中ユーザーでも到達できる(BAN判定の手前)。
_APPEAL_PATH = "/__ducknet_appeal__"


_CL_DIGITS = re.compile(rb"\A[0-9]+\Z")         # Content-Length は 1*DIGIT のみ(RFC 7230 §3.3.2)
_BARE_LF = re.compile(rb"(?<!\r)\n")            # CR を伴わない裸 LF(行終端の解釈が割れる)
_BARE_CR = re.compile(rb"\r(?!\n)")            # LF を伴わない裸 CR(同上・対称)
_REQ_LINE = re.compile(rb"\A[A-Za-z]+ \S+ HTTP/1\.[01]\Z")  # METHOD SP target SP HTTP/1.x


def _framing_ambiguous(buf: bytes) -> bool:
    """HTTP リクエストスマグリング/デシンクの前提(曖昧な本文境界・行構造)を *構造* で検出。
    本機はバイト透過で再フレーミングしないため、フロントと上流で解釈が食い違う恐れのある要求は
    *受け取らない*(RFC 7230 §3.3.3 の安全側=拒否)。表層は無害な POST / の裏に隠した第2要求
    (例 GET /.env)を上流が実行してしまう desync を、難読化亜種ごと封じる。
    検出する曖昧化(いずれも二者で『どこで何が終わるか』を食い違わせ得る形):
      · 改行の不統一: 裸 LF / 裸 CR(CRLF を期待する側とズレる)
      · obs-fold(SP/HT で始まる継続行): 値の分割で片側だけ別解釈になり得る(RFC 7230 §3.2.4)
      · リクエストラインの不正(3トークン/method=英字/version=HTTP/1.[01] 以外・二重空白)
      · CL と TE の併存(CL.TE / TE.CL)・重複 Content-Length
      · Content-Length 値が 1*DIGIT でない(0x10 / +5 / "5, 5" のカンマ畳み 等)
      · 複数 Transfer-Encoding(TE.TE)・最終コーディングが chunked でない TE
      · 複数 Host / HTTP/1.1 で Host 欠落(RFC 7230 §5.4: 1.1 はちょうど1個=ルーティングの的)
      · ヘッダ領域の NUL バイト(パーサにより打ち切り位置が割れる)
      · CL/TE のフィールド名とコロンの間の空白(名前を曲げ片側だけに無視させる)
    誇張しない: 『曖昧なら拒否』であって上流パーサのバグは直さない(安全側に倒すだけ)。本文
    (chunk)自体の検査は fail-fast 設計(ヘッダのみ読取)の対象外=別レイヤの責務。"""
    head = buf.split(b"\r\n\r\n", 1)[0]
    if _BARE_LF.search(head) or _BARE_CR.search(head):   # 行終端の不統一=境界解釈が割れる
        return True
    if b"\x00" in head:                          # NUL=打ち切り位置がパーサで割れる
        return True
    lines = head.split(b"\r\n")
    if not _REQ_LINE.match(lines[0]):            # リクエストラインが厳密形でない(二重空白等)
        return True
    # origin-form のみ受理(evolution #34): リバプロは origin-form(/path)だけを受ける。絶対形
    #   (GET http://host/…)や authority 形は target に scheme/host が紛れ、WAF が path 規則
    #   (path_limits/sensitive_path)を本来のパスで評価できず回避され得る。OPTIONS * のみ例外。
    _rl = lines[0].split(b" ")
    _tgt = _rl[1] if len(_rl) > 1 else b""
    if not (_tgt.startswith(b"/") or (_tgt == b"*" and _rl[0].upper() == b"OPTIONS")):
        return True
    cls, tes, hosts, name_spaced = [], [], 0, False
    for ln in lines[1:]:
        if not ln:
            continue
        if ln[:1] in (b" ", b"\t"):              # obs-fold 継続行=値の分割で解釈が割れる
            return True
        k, sep, v = ln.partition(b":")
        if not sep:
            continue
        kl = k.strip().lower()
        if kl in (b"content-length", b"transfer-encoding") and k != k.strip():
            name_spaced = True                   # 例: "Content-Length :"=名前を曲げる難読化
        if kl == b"content-length":
            cls.append(v.strip())
        elif kl == b"transfer-encoding":
            tes.append(v.strip().lower())
        elif kl == b"host":
            hosts += 1
    if name_spaced:
        return True
    if hosts > 1:                                # 複数 Host(HTTP/1.1 はちょうど1個)
        return True
    if hosts == 0 and lines[0].endswith(b"HTTP/1.1"):   # 1.1 で Host 欠落(RFC 7230 §5.4 MUST)
        return True
    if cls and tes:                              # CL.TE / TE.CL
        return True
    if len(cls) > 1:                             # 重複 Content-Length
        return True
    if cls and not _CL_DIGITS.match(cls[0]):     # CL が 1*DIGIT でない(難読化・カンマ畳み)
        return True
    if len(tes) > 1:                             # 複数 Transfer-Encoding(TE.TE)
        return True
    if tes and tes[0].split(b",")[-1].strip() != b"chunked":
        return True                              # 最終コーディングが chunked でない=本文長が曖昧
    return False


def _block_page(info: dict, submitted: bool = False, msg: str = "") -> bytes:
    """アクセス遮断ページ(商用WAF風)。数分後に解除リクエスト(異議申立)フォームを出す。
    表示名は環境変数 DUCKNET_COVER で差し替え可(ステルス時=製品名を露見させない)。
    文言は DUCKNET_LANG(ja|en)で切替(end-user 向け多言語)。"""
    import html as _html
    from ..core.i18n import t, lang
    lg = lang()
    brand = _html.escape(os.environ.get("DUCKNET_COVER", "DuckNet L7 Security"))
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
        f"<title>{t('block.title')} — " + brand + "</title><style>"
        "body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;"
        "display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}"
        ".card{max-width:480px;padding:32px;background:#161b22;border:1px solid #30363d;"
        "border-radius:14px;text-align:center}.dim{color:#8b949e;font-size:13px}"
        "h2{color:#f85149}.logo{font-size:13px;color:#58a6ff;margin-bottom:8px}"
        "</style></head><body><div class='card'>"
        "<div class='logo'>🛡 " + brand + "</div>" + center + "</div></body></html>")
    return page.encode("utf-8")


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
    except Exception:
        return "GET", "/", "", ""


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
    except Exception:
        return []


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
            v = v.strip()[:per]
            if len(vals) < max_headers:
                vals.append(v)
            else:
                tail.append(v)
        if tail:
            # 上限超ヘッダを 1 フィールドに結合して必ず走査(転送される全ヘッダ内容を走査面に残す)
            vals.append(b" ".join(tail)[:per])
        return b"\n".join(vals).decode("latin1", "replace")
    except Exception:
        return ""


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
    attrs = [a.strip().lower() for a in val.split(";")]
    add = []
    ss = str(cfg.get("cookie_samesite", "Lax")).strip()
    if ss and not any(a.startswith("samesite=") for a in attrs):
        add.append(f"SameSite={ss}")
    if tls and "secure" not in attrs:
        add.append("Secure")
    if cfg.get("cookie_httponly") and "httponly" not in attrs:
        add.append("HttpOnly")
    return f"{name}:{val.rstrip()}; " + "; ".join(add) if add else line


def _neutralize_cors(lines) -> list:
    """応答ヘッダ行から危険な CORS 誤設定を無害化する(#69)。
    Access-Control-Allow-Credentials: true が Access-Control-Allow-Origin: * / null と併存する場合、
    任意/サンドボックス origin が *資格情報付き* 応答を読めてしまう=常に誤り。credentials 行を除去して
    無害化する(origin が静的な正当構成は触らない)。返り値: 加工後の行リスト。"""
    acao = acac = None
    for ln in lines:
        n, _, v = ln.partition(":")
        nl = n.strip().lower()
        if nl == "access-control-allow-origin":
            acao = v.strip().lower()
        elif nl == "access-control-allow-credentials":
            acac = v.strip().lower()
    if acac == "true" and acao in ("*", "null"):
        return [ln for ln in lines
                if ln.partition(":")[0].strip().lower() != "access-control-allow-credentials"]
    return lines


def _location_host(loc: str) -> str:
    """Location 値から *絶対* リダイレクト先のホストを取り出す(小文字)。相対パス(/foo)や
    判定不能は ""(=同一サイト扱い)。scheme://host/.. と scheme 相対 //host/.. の両方に対応。"""
    v = loc.strip()
    low = v.lower()
    if low.startswith("//"):
        rest = v[2:]
    elif "://" in low:
        rest = v.split("://", 1)[1]
    else:
        return ""                                   # 相対=同一サイト=対象外
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return host.split("@", 1)[-1].split(":", 1)[0].strip().lower()   # userinfo/port 除去


def _redirect_violation_host(status_line: str, lines, req_host: str, allow) -> str:
    """3xx 応答の Location が外部の許可外ホストを指すなら、その違反ホストを返す(無ければ "")。
    req_host(リクエスト自身の Host)と allow のホストは常に許容。"""
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].startswith("3"):
        return ""                                   # 3xx でない
    loc = ""
    for ln in lines:
        n, sep, v = ln.partition(":")
        if sep and n.strip().lower() == "location":
            loc = v
            break
    if not loc:
        return ""
    host = _location_host(loc)
    if not host:
        return ""                                   # 相対リダイレクト=安全
    rh = (req_host or "").split(":", 1)[0].strip().lower()
    allowed = {rh} | {str(a).split(":", 1)[0].strip().lower() for a in (allow or [])}
    allowed.discard("")
    if host in allowed or any(host == a or host.endswith("." + a) for a in allowed if a):
        return ""                                   # 自サイト or 許可ホスト(サブドメイン含む)
    return host


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
      · WS/プロトコル切替(101/Upgrade)や応答行が読めないものは触らない(壊さない)。"""
    try:
        text = head.decode("latin1")
    except Exception:
        return head
    lines = text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return head                                        # 応答行が読めない=非介入
    low = text.lower()
    if " 101 " in lines[0] or "upgrade" in low:            # WebSocket 等の切替は触らない
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
        return "\r\n".join(out).encode("latin1", "replace")
    add = dict(_SEC_HEADERS_DEFAULT)
    extra = cfg.get("sec_headers_extra") or {}
    if isinstance(extra, dict):
        add.update({str(k): str(v) for k, v in extra.items()})
    for k, v in add.items():
        if v and k.lower() not in existing:                # 既存は尊重・空値はスキップ
            out.append(f"{k}: {v}")
    return "\r\n".join(out).encode("latin1", "replace")


class AsyncEdgeGuard:
    """本体サービスの前に立つ asyncio 製 Fail-Fast L7 ガード。"""

    def __init__(self, backend_host: str = "127.0.0.1", backend_port: int = 8787,
                 listen_host: str = "127.0.0.1", listen_port: int = 8799,
                 head_timeout: float = 10.0, backend_unix: str = "",
                 license_check=None, health_path: str = "", write_timeout: float = 60.0):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.head_timeout = head_timeout
        # 書込み(drain)デッドライン(#9): クライアント/バックエンドが受信を止めた(TCP zero-window)
        #   まま放置する『遅延読取』兵糧攻めを断つ。各 drain をこの秒数で打ち切り→両端を強制解放。
        #   SSE/大容量DLでも『一切受信しない状態がこの秒数』続くのは異常=安全に切る。env で調整可。
        try:
            self.write_timeout = float(os.environ.get("DUCKNET_DRAIN_TIMEOUT", write_timeout))
        except (TypeError, ValueError):
            self.write_timeout = write_timeout
        self.backend_unix = backend_unix      # 同一ホストならUnixソケットでTCP越え加速(可用時)
        # ヘルスチェック用パス(opt-in)。LB/オーケストレータの死活監視を WAF/バックエンド非経由で
        # 即 200 応答するための予約パス。既定は空=無効(env DUCKNET_HEALTH_PATH で既定指定可)。
        self.health_path = (health_path or os.environ.get("DUCKNET_HEALTH_PATH", "")).strip()
        # ライセンス検証はホットパスでは **メモリBooleanを返す callable** だけ(外部I/Oなし)。
        # 未設定(None)なら無効化=評価/OSS運用はそのまま。商用は gateway が LicenseManager を渡す。
        self.license_check = license_check
        self._loop = None
        self._server = None
        self._thread = None
        self._ready = threading.Event()
        self._stop_event = None       # ループ内 asyncio.Event(graceful drain の停止合図)
        self._active = 0              # 進行中の接続ハンドラ数(ループスレッドのみが触る=ロック不要)
        self._conn_per_ip: dict = {}  # ip -> 同時接続数(limit_conn 用・ループスレッドのみ=ロック不要)
        self._conn_rate: dict = {}    # ip -> [窓開始, 件数](接続レート=RST/churn フラッド対策・#10)
        self._pool = _BufferPool()
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
            while b"\r\n\r\n" not in buf and len(buf) < 16384:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError    # 総時間超過=slowloris(だらだら/小出し含む)
                chunk = await asyncio.wait_for(reader.read(4096), remaining)
                if not chunk:
                    break
                buf.extend(chunk)             # extend=償却O(1)(bytes+=のO(n^2)回避)
            return bytes(buf)                 # 解析/転送用の不変スナップショット
        finally:
            self._pool.put(buf)               # コンテナをプールへ返す

    async def _open_backend(self):
        """バックエンドへ接続。Unixソケット指定かつ可用ならTCPスタックを越えて加速。"""
        if self.backend_unix and hasattr(asyncio, "open_unix_connection"):
            return await asyncio.open_unix_connection(path=self.backend_unix)
        return await asyncio.open_connection(self.backend_host, self.backend_port)

    async def _handle(self, reader, writer):
        """接続ごとの入口。進行中数を計上して本体へ委譲(graceful drain が枯渇を待てるように)。
        計上は単一スレッド(イベントループ)内のみ=ロック不要。本体の多数の早期 return を
        包むため薄いラッパに分離(全 return 経路で必ずデクリメント)。
        さらに per-IP 同時接続上限(limit_conn・evolution #30): cfg max_conn_per_ip>0 のとき、
        同一IPが既に上限本数を保持していれば head 解析前に即切断(接続枯渇/slowloris 増幅対策)。"""
        self._active += 1
        ip = ""
        try:
            peer = writer.get_extra_info("peername")
            ip = self._norm_ip(peer[0] if peer else "")   # #14: IPv4-mapped を正規化
        except Exception:
            ip = ""
        cap = gcap = 0
        try:
            from ..lifeform.pipeline import net_shield
            _scfg = net_shield().cfg
            cap = int(_scfg.get("max_conn_per_ip", 0) or 0)
            gcap = int(_scfg.get("max_total_conn", 0) or 0)
            crate = int(_scfg.get("conn_rate_per_ip", 0) or 0)
        except Exception:
            cap = gcap = crate = 0
        counted = False
        try:
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
            await self._handle_conn(reader, writer)
        finally:
            if counted:
                v = self._conn_per_ip.get(ip, 1) - 1
                if v <= 0:
                    self._conn_per_ip.pop(ip, None)       # 0本になったIPは破棄(辞書を有界に保つ)
                else:
                    self._conn_per_ip[ip] = v
            self._active -= 1

    async def _handle_conn(self, reader, writer):
        self.metrics["accepted"] += 1
        ip = "127.0.0.1"
        try:
            peer = writer.get_extra_info("peername")
            if peer:
                ip = self._norm_ip(peer[0])      # #14: IPv4-mapped(::ffff:)を純IPv4へ
        except Exception:
            pass
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
        method, path, ua, host = _parse_head(buf)

        # 0y) 実クライアントIP解決(#32): 信頼 proxy 背後なら XFF から実IPを採る(rate-limit/ban/subnet が
        #     proxyIP に潰れない)。既定 trusted_proxies=[] は peer のまま=XFF を一切信頼しない(偽装無効)。
        peer_ip, _tp = ip, None
        try:
            from ..lifeform.pipeline import net_shield as _ns
            _tp = _ns().cfg.get("trusted_proxies")
            if _tp:
                ip = self._norm_ip(_real_client_ip(ip, buf, _tp))   # #14: XFF 由来も正規化
        except Exception:
            _tp = None
        # 元接続が TLS だったか(#33)。ここで一度確定=shield 無効のパススルー時も定義される
        # (#65 の Set-Cookie Secure 付与判定で参照。後段で再計算しない)。
        tls = _forwarded_proto_tls(peer_ip, buf, _tp)

        # 0z) ヘルスチェック(opt-in): 設定パス一致なら WAF/バックエンド非経由で即 200 を返す。
        #     LB/オーケストレータの死活監視用。最小ボディのみ=内部状態を漏らさない。
        if self.health_path and path.split("?", 1)[0] == self.health_path:
            self.metrics["health"] = self.metrics.get("health", 0) + 1
            writer.write(_http_response("200 OK", '{"status":"ok"}'))
            try:
                await writer.drain()
            except Exception:
                pass
            return self._close(writer)

        # 0a) HTTP リクエストスマグリング: 曖昧な境界(CL.TE/重複CL)は上流へ流さず即拒否。
        #     バイト透過プロキシで『WAF 素通り→上流が隠し要求を実行』を構造的に封じる。
        if _framing_ambiguous(buf):
            self.metrics["dropped"] += 1
            writer.write(_http_response("400 Bad Request",
                                        '{"error":"ambiguous message framing"}',
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

        # 0) ライセンス(商用): ホットパスは Boolean 1個だけ(外部I/Oなし=詰まらない)。
        #    無効/期限切れなら 402 を即返して切断(防御性能は1ミリも落とさない)。
        if self.license_check is not None and not self.license_check():
            self.metrics["dropped"] += 1
            writer.write(_http_response(
                "402 Payment Required", '{"error":"license invalid or expired"}',
                extra=deception.headers_for(ip)))
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
        except Exception:
            fw = None
            fw_enabled = False
        if fw_enabled:
            try:
                fw_allowed = fw.evaluate(ip).get("action") == "allow"
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
        except Exception:
            shield_enabled = False
        if shield_enabled:
            _p = path.split("?")[0]
            # 解除リクエスト(異議申立)経路はBAN判定の手前=遮断中のユーザーでも到達できる。
            if _p == _APPEAL_PATH:
                try:
                    return await self._handle_appeal(ip, path, sh, writer)
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
            _auth = _header_value(buf, b"authorization")
            _cred = (_auth[7:].strip() if _auth[:7].lower() == "bearer "
                     else _header_value(buf, b"x-api-key"))   # #70: クレデンシャル識別子
            _ovr = (_header_value(buf, b"x-http-method-override")     # #72: メソッド override
                    or _header_value(buf, b"x-method-override")
                    or _header_value(buf, b"x-http-method"))
            _opath = (_header_value(buf, b"x-original-url")           # #73: パス override
                      or _header_value(buf, b"x-rewrite-url")
                      or _header_value(buf, b"x-override-url"))
            # 判定不能(例外)を「許可」にしない=フェイルクローズ(#111)。ここは唯一の
            # 実質的な検知ゲートなので、握りつぶして通すと WAF/DDoS 防御が丸ごとバイパスされる。
            try:
                d = sh.inspect(ip, path=path.split("?")[0], method=method,
                               user_agent=ua, query=q, zone=zone, tls=tls, host=host,
                               headers=_scan_header_values(buf),
                               header_names=_header_names(buf),
                               auth=_auth, cred=_cred, override_method=_ovr,
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
                    writer.write(_http_response("429 Too Many Requests", _jsonify(
                        {"ok": False, "defense": "rate-limit", "retry_after": ra}),
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
        # 3) allow → バックエンドへ非同期パイプ(綺麗なアクセスだけ本体に通す)
        try:
            bre, bwr = await self._open_backend()
        except Exception:
            # バックエンド不達: 従来は無言TCP切断で運用者に何も見えなかった(accepted 以外の
            # 指標が動かず=停止に気付けない)。正規クライアントには標準的な 502 を返し、
            # 指標にも構造的に残す(このLite版は txnlog を持たないため metrics のみ)。
            self.metrics["backend_unreachable"] = (
                self.metrics.get("backend_unreachable", 0) + 1)
            writer.write(_http_response("502 Bad Gateway", _jsonify(
                {"ok": False, "error": "backend unreachable"}),
                extra=deception.headers_for(ip)))
            try:
                await writer.drain()
            except Exception:
                pass
            return self._close(writer)
        self.metrics["proxied"] += 1
        start = time.time()
        inbound = len(buf)                            # client→backend(ヘッダ分)
        outbound = 0                                  # backend→client(=持ち出し量)
        try:
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
                    if _okey:
                        from ..core.origin import origin_token
                        fwd = _set_request_header(
                            fwd, _scfg.get("origin_header", "X-Edge-Token"),
                            origin_token(_okey, window=float(_scfg.get("origin_window_sec", 30))))
            except Exception:
                pass
            # #46: 本文皆無(CL/TE 無し)の要求は head 以降のバイトがパイプライン第2要求=
            #   未検査でバックエンドへ届く。head のみに切り詰め、client→backend パイプも張らず
            #   write_eof で『要求完了』を半クローズで通知する。これで *backend が
            #   Connection: close を尊重するか否かに依存せず* smuggle 第2要求が上流に到達しない
            #   (#31 が「準拠サーバ前提」と明記していた残余リスクを DuckNet 側で能動的に塞ぐ)。
            bodyless = not _request_declares_body(buf)
            if bodyless:
                _h, _sep, _ = fwd.partition(b"\r\n\r\n")
                if _sep:
                    fwd = _h + b"\r\n\r\n"            # パイプライン第2要求を投棄
                bwr.write(fwd)
                await bwr.drain()
                try:
                    if bwr.can_write_eof():
                        bwr.write_eof()               # 半クローズ=以降 client→backend を流さない
                except Exception:
                    pass
                outbound += await self._pipe(bre, writer, scan=True, ip=ip, tls=tls, req_host=host)
            else:
                # #61: 要求ボディ検査。本文先頭を有界に読み、署名走査してから転送する
                #   (head-only の死角=POST/JSON/GraphQL 本文の SQLi/XSS/RCE/SSTI を塞ぐ)。
                extra, blocked = await self._scan_request_body(buf, reader, ip, path)
                if blocked:
                    self.metrics["dropped"] += 1
                    return self._close(writer)        # 悪性本文は上流へ流さない(backend は受信せず)
                bwr.write(fwd)
                if extra:
                    bwr.write(extra)                  # buf を超えて読んだ本文先頭も転送
                await bwr.drain()
                # #D3: 宣言された本文長ぶんだけを backend へ渡し、それ以降(パイプライン化された
                #   後続要求)を流さない=#46(bodyless)の半クローズ保証を body 有り要求へ拡張し、
                #   backend の Connection:close 尊重に依存した smuggling を封じる。走査で本文を
                #   読み切っている(cap 以下=大多数)なら即 write_eof し client→backend パイプを
                #   張らない(後続要求は reader に残したまま=転送されず接続 close で破棄)。
                body_in_buf = buf.partition(b"\r\n\r\n")[2]
                prefix_len = len(body_in_buf) + len(extra)
                _te = _header_value(buf, b"transfer-encoding").lower()
                _clh = _header_value(buf, b"content-length")
                _cl = int(_clh) if _clh.isdigit() else None
                if "chunked" in _te:
                    body_done = (body_in_buf + extra).endswith(b"0\r\n\r\n")
                    remaining = None
                elif _cl is not None:
                    body_done = prefix_len >= _cl
                    remaining = max(0, _cl - prefix_len)
                else:
                    body_done, remaining = True, 0
                if body_done:
                    try:
                        if bwr.can_write_eof():
                            bwr.write_eof()          # 本文完了=以降 client→backend を流さない
                    except Exception:
                        pass
                    outbound += await self._pipe(bre, writer, scan=True, ip=ip,
                                                 tls=tls, req_host=host)
                    inbound += len(extra)
                else:
                    # 本文が cap 超で未読=宣言長ぶんだけ有界転送(#64 の総受信デッドライン尊重)。
                    res = await asyncio.gather(
                        self._pipe_body_bounded(reader, bwr, remaining, "chunked" in _te,
                                                self._body_deadline()),
                        self._pipe(bre, writer, scan=True, ip=ip, tls=tls, req_host=host))
                    inbound += len(extra) + res[0]
                    outbound += res[1]
        except Exception:
            pass
        finally:
            self._close(writer)
            self._close(bwr)
            # データ漏洩防止: 送出量/接続時間を集計(上限超過時はNetShieldが当該IPを遮断)
            try:
                from ..lifeform.pipeline import net_shield
                net_shield().record_traffic(ip, out_bytes=outbound,
                                            in_bytes=inbound, conn_sec=time.time() - start)
            except Exception:
                pass

    def _apply_redirect_policy(self, head: bytes, req_host: str, ip: str = "") -> bytes:
        """応答 head に対しオープンリダイレクト無害化を適用する(#71)。外部の許可外ホストへの
        3xx Location を、enforce では安全パスへ書換え、audit では記録のみ。違反は metrics/event 計上。"""
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            text = head.decode("latin1")
            lines = text.split("\r\n")
            if not lines or not lines[0].startswith("HTTP/"):
                return head
            vhost = _redirect_violation_host(lines[0], lines[1:], req_host,
                                             sh.cfg.get("open_redirect_allow"))
            if not vhost:
                return head
            self.metrics["open_redirect"] = self.metrics.get("open_redirect", 0) + 1
            mode = sh.cfg.get("open_redirect_mode", "enforce")
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
                if ln.partition(":")[0].strip().lower() == "location":
                    out.append("Location: " + safe)  # 外部許可外→安全パスへ書換(無害化)
                else:
                    out.append(ln)
            return "\r\n".join(out).encode("latin1", "replace")
        except Exception:
            return head

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
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            if sh.cfg.get("body_timeout_enabled"):
                return asyncio.get_event_loop().time() + float(sh.cfg.get("body_max_sec", 60))
        except Exception:
            pass
        return None

    @staticmethod
    def _decompress_bounded(data: bytes, encoding: str, max_out: int = 262144):
        """要求ボディを有界に解凍する(#74)。gzip/deflate を decompressobj の max_length で
        *出力上限つき* に展開=zip bomb 耐性。解凍後を署名走査することで Content-Encoding による
        WAF 回避(gzip 化した SQLi 等)を塞ぐ。非対応(br 等)/破損は None。"""
        import zlib
        enc = (encoding or "").strip().lower()
        try:
            if enc in ("gzip", "x-gzip"):
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                return d.decompress(data, max_out)
            if enc == "deflate":
                try:
                    return zlib.decompressobj().decompress(data, max_out)
                except Exception:
                    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(data, max_out)  # raw
        except Exception:
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
            size_line = data[i:j].split(b";", 1)[0].strip()   # chunk-ext(;...)は捨てる
            if not size_line:
                break
            try:
                size = int(size_line, 16)
            except ValueError:
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

    async def _pipe_body_bounded(self, reader, bwr, remaining, chunked, deadline):
        """宣言された本文長ぶんだけ client→backend へ転送し、それ以降(パイプライン化された後続
        要求)は流さない(#D3)。remaining=残り本文バイト数(Content-Length 時)。chunked=終端
        0\\r\\n\\r\\n まで転送。総受信デッドライン(#64 body_max_sec)も尊重する。返り値=転送バイト数。
        本文完了後に write_eof=半クローズ(#46 の bodyless 保証を body 有り要求へ拡張)。"""
        total = 0
        loop = asyncio.get_event_loop()
        tail = b""
        try:
            while True:
                if chunked:
                    want = 65536
                else:
                    if remaining <= 0:
                        break
                    want = min(65536, remaining)
                rem_t = self.head_timeout if deadline is None else (deadline - loop.time())
                if rem_t <= 0:
                    break                              # 総受信デッドライン超過=打ち切り(→半クローズ)
                try:
                    chunk = await asyncio.wait_for(reader.read(want),
                                                   min(self.head_timeout, rem_t))
                except Exception:
                    break
                if not chunk:
                    break
                bwr.write(chunk)
                await bwr.drain()
                total += len(chunk)
                if chunked:
                    tail = (tail + chunk)[-8:]
                    if tail.endswith(b"0\r\n\r\n"):
                        break
                else:
                    remaining -= len(chunk)
                    if remaining <= 0:
                        break
        finally:
            try:
                if bwr.can_write_eof():
                    bwr.write_eof()
            except Exception:
                pass
        return total

    async def _scan_request_body(self, buf, reader, ip, path=""):
        """要求ボディの先頭を有界に読んで署名走査する(#61)。返り値 (extra, blocked):
          · extra … buf を *超えて* 読んだ本文先頭バイト(クリーン時に backend へ転送する分)。
          · blocked … 悪性(block)と判定=本文を上流へ流さず接続を切るべきか。
        body_scan 無効なら即 (b"", False)=従来のストリーミングと同一(extra を読まない)。
        正直な限界: 走査は先頭 cap バイトのみ(巨大本文を全バッファしない)。chunked 本文は走査面
        では有界復号してから走査する(#D5。backend へは raw 転送)。本文を極端に小出しする回避は
        slowloris 同様の残余(per-read timeout)。"""
        try:
            from ..lifeform.pipeline import net_shield
            sh = net_shield()
            body_scan_enabled = sh.cfg.get("body_scan_enabled")
        except Exception:
            return b"", True   # フェイルクローズ: net_shield 到達不能を「スキャンなし」にしない(#111)。
                                # 下の走査例外ハンドラと同じ方針(素通しは本文検査の丸ごとバイパスになる)。
        if not body_scan_enabled:
            return b"", False
        try:
            cap = int(sh.cfg.get("body_scan_max_bytes", 65536))
        except Exception:
            cap = 65536
        body_in_buf = buf.partition(b"\r\n\r\n")[2]
        # Content-Length を尊重して読み取りを *正確に* 上限化する。これが無いと本文完了後も
        # cap まで read() がブロック=全 POST に head_timeout 分の遅延が乗る(性能バグ)。
        _cl = _header_value(buf, b"content-length")
        content_len = int(_cl) if _cl.isdigit() else None
        target = cap if content_len is None else min(cap, content_len)
        prefix = bytearray(body_in_buf)
        extra = bytearray()
        # #82: 走査読取にも *総* デッドラインを課す。per-read だけだと走査フェーズでボディを小出しして
        #   接続を保持できた(#64 の body_max_sec は走査 *後* の pipe にしか効かない)。
        loop = asyncio.get_event_loop()
        deadline = (loop.time() + float(sh.cfg.get("body_max_sec", 60))
                    if sh.cfg.get("body_timeout_enabled", True) else None)
        timed_out = False
        while len(prefix) < target:
            remaining = self.head_timeout if deadline is None else (deadline - loop.time())
            if remaining <= 0:
                timed_out = True
                break
            try:
                chunk = await asyncio.wait_for(reader.read(min(65536, target - len(prefix))),
                                               min(self.head_timeout, remaining))
            except asyncio.TimeoutError:
                timed_out = deadline is not None       # デッドライン運用中の read 停止=slow-body
                break
            except Exception:
                break
            if not chunk:
                break                                  # 本文終端
            prefix += chunk
            extra += chunk                             # buf を超えた分=後で転送が要る
            if content_len is None and prefix.endswith(b"0\r\n\r\n"):
                break                                  # chunked 終端=完了
        if timed_out:
            self._on_slow_body(ip)                     # 総時間超過=切断+加点(R-U-Dead-Yet 走査版)
        blocked = False
        try:
            pb = bytes(prefix)
            # #D5: chunked 本文は *復号後* を走査する(境界分割による body-scan 回避封じ)。
            #   Content-Encoding 解凍より前に行う(ワイヤ上は chunk 枠の内側に gzip 等が入る)。
            #   原本(extra)は backend へ raw のまま転送。破損チャンクは fail closed。
            if sh.cfg.get("body_decode_enabled", True) \
                    and "chunked" in _header_value(buf, b"transfer-encoding").lower():
                dec = self._dechunk_bounded(pb, cap)
                if dec is None:
                    return bytes(extra), True      # 破損チャンクストリーム=フェイルクローズ(#111)
                pb = dec
            # #74: Content-Encoding で圧縮された本文は解凍後を走査する(gzip 化 payload の回避封じ)。
            #   解凍は有界(max_length)=zip bomb 耐性。原本(pb)は backend へそのまま転送する。
            if sh.cfg.get("body_decode_enabled", True):
                enc = _header_value(buf, b"content-encoding")
                if enc and enc.strip().lower() not in ("identity", ""):
                    dec = self._decompress_bounded(pb, enc,
                                                   int(sh.cfg.get("body_scan_max_bytes", 65536)))
                    if dec:
                        pb = dec                       # 解凍できたら解凍後を走査面に
            blocked = sh.inspect_body(ip, pb).get("action") == "block"
            if not blocked:                            # #66: 危険なアップロード拡張子も拒否
                blocked = sh.scan_upload(ip, pb).get("action") == "block"
            if not blocked:                            # #67: GraphQL の深さ/複雑度/イントロスペクション
                blocked = sh.inspect_graphql(ip, path, pb).get("action") == "block"
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

    async def _handle_appeal(self, ip, path, sh, writer):
        """解除リクエスト(異議申立)を受け付ける。?reason=... を submit_appeal へ。
        判定の手前にある経路ゆえ、CPU枯渇フラッド対策として **BAN されていないIPには
        重い遮断ページ(_block_page)を生成せず**、bloom O(1) で軽量拒否する。"""
        if not sh.is_banned_fast(ip):            # bloom: 確実に未BAN→state も作らず即軽量応答
            writer.write(_http_response("403 Forbidden",
                                        '{"error":"no active ban for this address"}'))
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
                raise asyncio.TimeoutError()       # 累積 drain 待ち超過=zero-window 同様にカスケード切断

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
                    deadline: float = None, tls: bool = False, req_host: str = "") -> int:
        total = 0
        # 出口DLP(evolution #6): 応答方向のみ、先頭を有界走査して秘密情報漏洩を検出。
        # pending = 走査済みだが *まだ送っていない* 末尾窓(#42)。境界を跨ぐ秘密の頭を先に
        # 送ってしまわないため、末尾64Bは次チャンクで安全確認できるまで保留する(block で確実に止める)。
        sh, budget, pending = None, 0, b""
        sec_cfg = None                            # 応答 head 加工(#12/#65/#69)の cfg
        add_sec, harden_ck, harden_cors, harden_redir = False, False, False, False
        if scan:
            try:
                from ..lifeform.pipeline import net_shield
                s = net_shield()
                if s.dlp_active():
                    sh, budget = s, int(s.cfg.get("dlp_max_scan_bytes", 262144))
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
            except Exception:
                sh, sec_cfg = None, None
        head_done = sec_cfg is None               # 無効なら head 処理を飛ばし従来とバイト完全同一
        hbuf = b""
        # 応答アウェア脅威スコア(#60): 応答ステータス行を *覗き見* して NetShield へ還元する。
        # sec_headers/DLP の有無に依らず動く軽量ピーク(先頭行のみ・バイトは一切改変しない)。
        report_status = bool(scan and ip)
        st_buf, st_done = b"", False
        loop = asyncio.get_event_loop()
        try:
            while True:
                if deadline is not None:          # #64: 要求ボディの総受信時間に上限(slow-body)
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        self._on_slow_body(ip)
                        break
                    try:
                        chunk = await asyncio.wait_for(src.read(65536), remaining)
                    except asyncio.TimeoutError:
                        self._on_slow_body(ip)
                        break
                else:
                    chunk = await src.read(65536) # 64KiB=syscall/await 往復を削減(I/O律速)
                if not chunk:
                    if hbuf:                      # head 未完のまま EOF=残りを取りこぼさず放出
                        await self._send(dst, hbuf, ip)
                        hbuf = b""
                    break
                total += len(chunk)               # 転送バイトを計上(漏洩量算定)
                if report_status and not st_done:   # 応答ステータス行を覗き見て #60 へ
                    st_buf += chunk[:64]
                    nl = st_buf.find(b"\r\n")
                    if nl >= 0 or len(st_buf) >= 64:
                        st_done = True
                        line = st_buf[:nl] if nl >= 0 else st_buf[:64]
                        parts = line.split(b" ")
                        if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
                            try:
                                from ..lifeform.pipeline import net_shield
                                net_shield().note_response(ip, int(parts[1]))
                            except Exception:
                                pass
                if not head_done:                 # 応答 head を蓄積→注入→以降は body として通常処理
                    hbuf += chunk
                    if not hbuf.startswith(b"HTTP/") and len(hbuf) >= 5:
                        # 応答行が HTTP でない(非HTTPストリーム等)=head 加工対象外。諦めて
                        # 溜めた分を body 経路(DLP)へ回す=非HTTPでもバイト透過を維持。
                        chunk, hbuf, head_done = hbuf, b"", True
                    else:
                        idx = hbuf.find(b"\r\n\r\n")
                        if idx < 0:
                            if len(hbuf) > 65536: # head 過大=書換を諦め素通し(壊さない)
                                await self._send(dst, hbuf, ip)
                                hbuf, head_done = b"", True
                            continue              # head 未完 or 諦め=この chunk は処理済み
                        new_head = inject_security_headers(hbuf[:idx], sec_cfg, tls=tls,
                                                           add_headers=add_sec,
                                                           harden_cookies=harden_ck,
                                                           harden_cors=harden_cors)
                        if harden_redir:              # #71: オープンリダイレクト無害化
                            new_head = self._apply_redirect_policy(new_head, req_host, ip)
                        await self._send(dst, new_head + b"\r\n\r\n", ip)
                        chunk = hbuf[idx + 4:]    # head 以降=body として今回処理へ続行
                        hbuf, head_done = b"", True
                        if not chunk:
                            continue
                if sh is not None and budget > 0:
                    seg = pending + chunk         # 保留(未送信)末尾窓 + 今回 を一括走査
                    kinds = sh.scan_leak(seg)
                    if kinds:
                        # block: 保留分(=境界跨ぎ秘密の頭になり得る)も送らず切断=秘密を一切出さない。
                        if sh.note_leak(ip, kinds).get("action") == "block":
                            pending = b""
                            break
                        sh = None                 # audit: 記録したら走査停止。保留含め流す。
                        await self._send(dst, seg, ip)
                        pending = b""
                        continue
                    # clean: 末尾64B(次チャンクと跨ぐ秘密の頭になり得る)を保留、それ以外を送出。
                    budget -= len(chunk)
                    out, pending = seg[:-64], seg[-64:]
                    if out:
                        await self._send(dst, out, ip)
                    if budget <= 0:               # 走査終了=保留を放出し以降は素通し
                        if pending:
                            await self._send(dst, pending, ip)
                        pending = b""; sh = None
                    continue
                await self._send(dst, chunk, ip)
            if pending:                           # EOF: 保留していた末尾窓を最後に放出
                await self._send(dst, pending, ip)
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass
        return total

    def _conn_rate_exceeded(self, ip: str, limit: int) -> bool:
        """同一 IP の新規接続が 1 秒窓内で limit を超えたか(#10・RST/churn フラッド対策)。
        イベントループスレッドのみが触る=ロック不要。辞書は有界化する。超過で True(=即切断)。"""
        now = self._loop.time() if self._loop else time.monotonic()
        ent = self._conn_rate.get(ip)
        if ent is None or now - ent[0] >= 1.0:
            self._conn_rate[ip] = [now, 1]
            if len(self._conn_rate) > 50000:               # 有界化(古い窓を間引く)
                for k in [k for k, v in self._conn_rate.items() if now - v[0] >= 1.0][:5000]:
                    self._conn_rate.pop(k, None)
            return False
        ent[1] += 1
        return ent[1] > limit

    @staticmethod
    def _norm_ip(ip: str) -> str:
        """IPv4-mapped IPv6(::ffff:192.0.2.1)を純IPv4へ正規化(#14)。dual-stack 束縛時、peername が
        射影アドレス文字列で返ると BAN リストの完全一致を素通りする。純IPv4(":"無し)は即返し=ゼロ負荷。"""
        if not ip or ":" not in ip:
            return ip
        try:
            import ipaddress
            mapped = getattr(ipaddress.ip_address(ip), "ipv4_mapped", None)
            return str(mapped) if mapped else ip
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
        self._server = await asyncio.start_server(
            self._handle, self.listen_host, self.listen_port)
        self.listen_port = self._server.sockets[0].getsockname()[1]
        self._stop_event = asyncio.Event()
        self._ready.set()
        # serve_forever は『新規受理』専任のキャンセル可能タスク。コルーチンの寿命は stop_event に
        # 委ねる=停止時に listener だけ閉じて(受理停止)、進行中の _handle タスクは生かしたまま
        # drain を待てる(per-connection タスクは serve_forever とは独立に走り続ける)。
        serve_task = asyncio.ensure_future(self._server.serve_forever())
        check_task = asyncio.ensure_future(self._periodic_checks_loop())
        try:
            await self._stop_event.wait()
        finally:
            for _t in (serve_task, check_task):
                _t.cancel()
                try:
                    await _t
                except (asyncio.CancelledError, Exception):
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
        try:
            self.stop(grace=0.0)
        except Exception:
            pass
        self._ready = threading.Event()
        self._stop_event = None
        return self.start()

    async def _drain(self, grace: float):
        """graceful shutdown: ① 新規受理を止め(listener close)② 進行中の接続が捌けるのを最大
        `grace` 秒待ち ③ 停止合図。`grace<=0`(既定)は待たず即時=従来挙動。残接続数を返す。"""
        if self._server is not None:
            self._server.close()                  # 新規受理のみ停止(進行中タスクは非キャンセル)
        deadline = self._loop.time() + max(0.0, float(grace))
        while self._active > 0 and self._loop.time() < deadline:
            await asyncio.sleep(0.05)
        remaining = self._active
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
        except (Exception, asyncio.CancelledError):
            pass
        finally:
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
        self._raise_fd_limit()                        # #79: FD ソフト上限を引き上げ(可能なら)
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="ducknet-edge")
        self._thread.start()
        if not self._ready.wait(timeout):
            return {"ok": False, "error": "起動タイムアウト"}
        return {"ok": True, "listen": f"{self.listen_host}:{self.listen_port}",
                "backend": f"{self.backend_host}:{self.backend_port}",
                "note": "asyncio Fail-Fastガード。block/denyは即TCP切断(スレッド非消費)。"}

    def url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}"

    def stop(self, grace: float = 0.0) -> dict:
        """停止。`grace>0` なら進行中リクエストを最大 grace 秒ドレイン(受理停止→捌けるまで待機)。
        既定 grace=0 は従来どおり即時停止(後方互換)。別スレッドのループへ drain を投入して待つ。"""
        remaining = None
        loop = self._loop
        # ループが走っている時だけ drain を投入する。停止済み(例: restart() 呼び出し直後)へ
        # run_coroutine_threadsafe すると _drain コルーチンが await されず警告+無駄な5s待機になる。
        if loop is not None and loop.is_running():
            try:
                fut = asyncio.run_coroutine_threadsafe(self._drain(grace), loop)
                try:
                    remaining = fut.result(timeout=max(0.0, float(grace)) + 5.0)
                except Exception:
                    pass
            except Exception:               # 競合で停止した=ベストエフォート
                if self._stop_event is not None:
                    try:
                        loop.call_soon_threadsafe(self._stop_event.set)
                    except Exception:
                        pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=max(0.0, float(grace)) + 5.0)
        return {"ok": True, "stopped": True, "drained": remaining,
                "metrics": dict(self.metrics)}

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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(1024)
        s.setblocking(False)
        return s

    def _worker_blocking(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(lambda l, c: None)
        sock = self._reuseport_socket()       # 各ワーカーが同ポートを共有listen

        async def _s():
            server = await asyncio.start_server(self._handle, sock=sock)
            async with server:
                await server.serve_forever()
        try:
            loop.run_until_complete(_s())
        except (Exception, asyncio.CancelledError):
            pass

    def serve_cluster(self, workers: int = 0) -> dict:
        """CPUコア数ぶんの asyncio ループで同一ポートを SO_REUSEPORT 共有待受(全コア解放)。
        SO_REUSEPORT/fork 非対応OS(Windows等)では **正直に単一プロセスへフォールバック**。"""
        caps = self.platform_capabilities()
        if not (caps["so_reuseport"] and caps["os_fork"]):
            info = self.start()               # 単一プロセス(バックグラウンド)
            return {"ok": info.get("ok"), "mode": "single",
                    "reason": "SO_REUSEPORT/fork非対応のOS→単一プロセス(正直な降格)",
                    "capabilities": caps, "listen": info.get("listen")}
        n = workers or caps["cpu_count"]
        if n > 1:
            # 正直な注意(G review): fork ワーカーはレート状態(_ips トークンバケット)を
            # 共有しない=各自が独立カウンタ。よって IP 単位の上限は実効で最大 約「設定値×n」
            # まで通り得る。厳密なグローバル制限が要るなら単一プロセス、または共有KVS継ぎ目へ。
            print(f" [note] クラスタ {n} ワーカー: レート状態はワーカー間で共有しません"
                  f"(fork=独立メモリ)。IP単位の上限は実効で最大 約(設定値×{n})。"
                  " 厳密なグローバル制限は単一プロセスか共有KVS層で。")
        pids = []
        for _ in range(max(0, n - 1)):
            pid = os.fork()
            if pid == 0:                      # 子ワーカー: 自分のループで待受(戻らない)
                self._worker_blocking()
                os._exit(0)
            pids.append(pid)
        # 親も1ワーカーを担う(ブロッキング=常駐)
        return_info = {"ok": True, "mode": "cluster", "workers": n,
                       "child_pids": pids, "capabilities": caps,
                       "rate_limit_scope": "per-worker",
                       "note": "各ワーカーは独立レートカウンタ=IP単位上限は実効で約"
                               " threshold×workers。厳密なグローバル制限は共有KVS継ぎ目へ委譲。"}
        self._worker_blocking()
        return return_info
