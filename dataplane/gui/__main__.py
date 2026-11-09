"""
__main__.py — DuckNet-Lite: システムトレイ常駐(トレイのみ・依存ゼロ)
====================================================================================
`python -m dataplane tray` / `python -m dataplane.gui` で起動。タスクトレイに DuckNet.ico を
常駐させ、右クリックメニューから最小操作を提供する:
  · ダッシュボードを開く … 既定ブラウザで管理ダッシュボード(DUCKNET_ADMIN_URL)を開く
  · About              … 製品/版の情報(Win32 MessageBox)
  · 無料版でできること   … このエディションで使える機能一覧(上位版との差は README/❓ヘルプ参照)
  · 終了               … 本launcher が起動した本体を停止し、トレイを外してプロセス終了
防御の状態は 5 秒ごとに管理APIから読み、アイコン(ON=通常 / それ以外=淡色)とツールチップで示す
(「防御 ON」「防御 ON(監査モード: 記録のみ)」「防御 OFF」「ゲートウェイに接続できません」
「状態を確認できません(本体未確認)」)。所有する子の HMAC proof、または管理トークンを送らない
署名要求と応答 MAC で状態を検証する。右クリックには確認済みの状態と確認できる BAN 件数を表示する。
ON/OFF の切替そのものはダッシュボードで行う(トレイには持たせない)。
起動時、本体(ゲートウェイ)が未起動なら子プロセスとして一緒に立ち上げる(既に稼働中なら起動しない)。
backend/listen は env DUCKNET_BACKEND / DUCKNET_LISTEN で上書き可(既定 127.0.0.1:8080 / 8443)。
上位版のようなコントロールパネルは持たない(Lite=最小構成)。Windows 専用(他 OS はトレイ非対応の旨を表示)。
"""
from __future__ import annotations

import os
import re
import http.client
import io
import math
import hashlib
import hmac
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import webbrowser
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit
from types import SimpleNamespace

from . import tray, ASSET_ICO, ASSET_ICO_OFF

# 接続先・表示名は main() の中で(app.env の取り込み後に)読む。import 時に固めていた頃は
# `python -m dataplane.gui` で app.env の DUCKNET_ADMIN_URL / DUCKNET_COVER が効かなかった。
def _admin_url() -> str:
    return os.environ.get("DUCKNET_ADMIN_URL", "http://127.0.0.1:8081")


def _admin_parts(base_url: str):
    """Use one validated HTTP(S) authority for probes and the browser."""
    if (not isinstance(base_url, str) or not base_url
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in base_url)):
        raise ValueError("DUCKNET_ADMIN_URL must be a valid HTTP(S) URL")
    try:
        parts = urlsplit(base_url if "://" in base_url else "http://" + base_url)
        host, port = parts.hostname, parts.port
        if (parts.scheme not in ("http", "https") or not host or "%" in host
                or parts.username is not None or parts.password is not None
                or parts.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535)):
            raise ValueError
        return parts
    except ValueError:
        raise ValueError("DUCKNET_ADMIN_URL must be a valid HTTP(S) URL") from None


def _dashboard_url(base_url: str) -> str:
    """Open the dashboard without carrying legacy credentials into browser history."""
    parts = _admin_parts(base_url)
    def legacy_key(name: str) -> bool:
        # parse_qsl decodes one layer. Older URLs may have nested percent
        # encodings; after a bounded number of layers, drop still-encoded
        # keys rather than retaining a recoverable credential in history.
        key = name
        marker = (r"(?:^|[?&#/])(?:token|access[_-]?token|admin[_-]?token|"
                  r"ducknet-admin-token)(?:[ \t]*[=:/]|$)")
        for _ in range(4):
            if re.search(marker, key, re.I):
                return True
            decoded = unquote(key)
            if decoded == key:
                break
            key = decoded
        return bool(re.search(marker, key, re.I)
                    or re.search(r"%[0-9a-f]{2}", key, re.I))

    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if not legacy_key(k)]
    # Preserve ordinary anchors, but an old #token=... value is browser-visible
    # even though it never reaches the HTTP server.
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/",
                       urlencode(query),
                       "" if legacy_key(parts.fragment) else parts.fragment))


def _brand() -> str:
    return os.environ.get("DUCKNET_COVER", "").strip() or "DuckNet-Lite"


_ABOUT_TEXT = (
    "{brand}\n\n"
    "軽量 L7 WAF / DDoS セキュリティゲートウェイ(無償エディション・AGPL)。\n"
    "外部依存ゼロ(Python 標準ライブラリのみ)・OS 非侵襲・防御専用。\n\n"
    "コアの L7 WAF/DDoS リバースプロキシと Web 管理ダッシュボードを提供します。\n"
    "詳細は README.md / docs、ダッシュボード右上の ❓ ヘルプを参照してください。"
)                                                  # {brand} は表示時に埋める

_CAPS_TEXT = (
    "無料版(DuckNet-Lite)でできること:\n\n"
    "・WAF: SQLi / XSS / RCE / パストラバーサル / XXE / SSRF / JNDI / スキャナー等の\n"
    "  シグネチャ照合、カスタムシグネチャ追加\n"
    "・L7 DDoS 防御: レート制限・脅威スコアリング・自動BAN(拒否/BAN の2段階)\n"
    "・双方向検査: リクエストボディ(POST/JSON/GraphQL・gzip/chunked 復号)+ 応答の\n"
    "  DLP・セキュリティヘッダ付与\n"
    "・認証/濫用対策: JWT 検査・クレデンシャル単位のレート制限\n"
    "・状態の整合性: BAN/設定の HMAC 署名による改竄耐性\n\n"
    "PoW チャレンジ・DNS フィルタ・SIEM 転送・自己完全性監視・watchdog・GeoIP・\n"
    "横展開デコイ・脅威インテリジェンス・分散BAN同期・ハニーポット等は上位版(DuckNet)で。"
)


def _asset_path(name: str) -> str:
    """アイコンの場所を解決: env DUCKNET_ICON_DIR → リポジトリ/カレントの ico/ → 同梱 assets/。"""
    here = os.path.dirname(__file__)
    repo_root = os.path.dirname(os.path.dirname(here))     # …/dataplane/gui → リポジトリ直下
    cands = []
    env = os.environ.get("DUCKNET_ICON_DIR", "").strip()
    if env:
        cands.append(os.path.join(env, name))
    for root in (repo_root, os.getcwd()):
        cands.append(os.path.join(root, "ico", name))
    bundled = os.path.join(here, "assets", name)
    cands.append(bundled)
    for p in cands:
        try:
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
    return bundled


def _status_icons():
    """(通常, 淡色) アイコンのパス。淡色版は通常版と *同じ場所* から探す: DUCKNET_ICON_DIR で
    独自のアイコン(偽装名運用など)に差し替えているのに、OFF の時だけ同梱の鴨が出ると製品が
    露見する。同じ場所に淡色版が無ければ通常アイコンのまま(状態はツールチップで分かる)。"""
    on = _asset_path(ASSET_ICO)
    off = os.path.join(os.path.dirname(on), ASSET_ICO_OFF)
    try:
        return on, (off if os.path.isfile(off) else on)
    except Exception:
        return on, on


# ── 防御状態の表示(トレイのアイコン/ツールチップ) ──────────────────────
STATE_ON, STATE_OFF, STATE_DOWN, STATE_AUTH = "on", "off", "unreachable", "auth"
STATE_AUDIT = "audit"              # 検知は記録のみ。HTTP の構造異常は引き続き拒否する
_POLL_SEC = 5.0                    # 状態の再取得間隔(秒)。初回は起動直後に即時
_FETCH_TIMEOUT = 2.0
_ADMIN_401_MARK = b"token required"   # 本製品の管理APIが返す 401 本文の指紋(_admin_is_ours と共通)
_STATUS_TEXT = {
    STATE_ON: "防御 ON / Protection ON",
    STATE_AUDIT: "防御 ON(監査モード: 検知は記録のみ)/ Protection ON (audit: record only)",
    STATE_OFF: "防御 OFF(ダッシュボードで ON にできます)/ Protection OFF",
    STATE_DOWN: "ゲートウェイに接続できません / Gateway unreachable",
    STATE_AUTH: "状態を確認できません(管理トークン未確認)/ Status unknown (admin token unverified)",
}


def _status_view(state: str, brand=None):
    """防御状態 → (ツールチップ, アイコン名)。ON だけ通常アイコン、それ以外(OFF・監査モード・
    接続不可・トークン不一致)は淡色=「守られていない/守られているか分からない」を同じ見た目に
    まとめる。監査モードは検知による遮断をしない=切り替えたまま戻し忘れても気づけるよう淡色。
    想定外の値は接続不可と同じ扱い(ON と誤表示しない)。ブランド名は DUCKNET_COVER に従い、
    長すぎる名前はブランド側を詰めて状態の文言を残す(szTip は 127 文字)。"""
    if state not in _STATUS_TEXT:
        state = STATE_DOWN
    b = _brand() if brand is None else brand
    return (tray.fit_tip(b, " — " + _STATUS_TEXT[state]),
            ASSET_ICO if state == STATE_ON else ASSET_ICO_OFF)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """管理面の確認でリダイレクトに従わない。3xx は別の待受として扱う。"""

    def redirect_request(self, *a, **kw):
        return None


def _is_admin_401(e) -> bool:
    """HTTPError が本製品の管理APIの 401(本文 {"ok": false, "error": "token required"})か。
    自前の認証で 401 を返すプログラムは多いので、状態コードだけでは本製品と決められない。"""
    if getattr(e, "code", None) != 401:
        return False
    try:
        return _ADMIN_401_MARK in e.read(256)
    except Exception:
        return False


def _owned_child_active(child, base_url: str) -> bool:
    """自分が起動した子が生存し、認証先が数値 loopback の場合だけ True。"""
    if child is None:
        return False
    try:
        if child.poll() is not None:
            return False
        return _is_loopback(_admin_addr(base_url)[0])
    except Exception:
        return False


class _DeadlineRead(io.RawIOBase):
    """Keep the standard HTTP parser while bounding each underlying read."""
    def __init__(self, sock, deadline):
        super().__init__()
        self.sock, self.deadline = sock, deadline
        self.head_budget, self.body_budget = 16384, None

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("admin response deadline")
        budget = self.head_budget if self.body_budget is None else self.body_budget
        if budget <= 0:
            if self.body_budget is not None:
                return 0
            raise ValueError("admin response headers too large")
        self.sock.settimeout(remaining)
        count = self.sock.recv_into(buffer, min(len(buffer), budget))
        if self.body_budget is None:
            self.head_budget -= count
        else:
            self.body_budget -= count
        return count


def _read_admin_reply(base_url: str, timeout: float, body_limit: int = 0,
                      *, path="/api/state", headers=None, read_status=401):
    """Own a single loopback connection with one deadline and bounded headers."""
    if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("invalid admin timeout")
    deadline = time.monotonic() + timeout

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("admin response deadline")
        return value

    host, port = _admin_addr(base_url)
    if not _is_loopback(host):
        raise ValueError("admin probe requires numeric loopback")
    sock = socket.create_connection((host, port), timeout=remaining())
    connection = None
    try:
        if _admin_parts(base_url).scheme == "https":
            sock = ssl.create_default_context().wrap_socket(
                sock, server_hostname=host, do_handshake_on_connect=False)
            sock.settimeout(remaining())
            sock.do_handshake()
        nonce = secrets.token_hex(16)
        connection = http.client.HTTPConnection(host, port)
        connection.sock = sock
        sock.settimeout(remaining())
        request_headers = {"X-DuckNet-Tray-Nonce": nonce, "Connection": "close"}
        request_headers.update(headers or {})
        connection.request("GET", path, headers=request_headers)
        raw = _DeadlineRead(sock, deadline)
        reader = io.BufferedReader(raw, buffer_size=1024)
        response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda _mode: reader))
        try:
            response.begin()
            headers = response.headers
            raw.body_budget = body_limit + (1 if read_status is None else 0)
            body = (response.read(raw.body_budget) if body_limit and
                    (read_status is None or response.status == read_status) else b"")
            if len(body) > body_limit:
                raise ValueError("admin response body too large")
            remaining()  # never accept a reply completed after its total deadline
            return response.status, headers, body, nonce
        finally:
            response.close()
    finally:
        if connection is not None:
            connection.close()
        else:
            sock.close()


def _verify_admin_proof(base_url: str, child, timeout: float = 1.0) -> str | None:
    """子だけが知る鍵で、同じ 401 に結び付いた shield 状態を得る。"""
    if not _owned_child_active(child, base_url):
        return None
    try:
        key = bytes.fromhex(getattr(child, "_ducknet_tray_proof_key", ""))
        if len(key) != 32:
            return None
        status, headers, _body, nonce = _read_admin_reply(base_url, timeout)
        proofs = headers.get_all("X-DuckNet-Tray-Proof", [])
        if status != 401 or len(proofs) != 1:
            return None
        for state in (STATE_ON, STATE_OFF, STATE_AUDIT):
            expected = hmac.new(key, (nonce + ":" + state).encode("ascii"),
                                hashlib.sha256).hexdigest()
            if (hmac.compare_digest(proofs[0], expected)
                    and _owned_child_active(child, base_url)):
                return state
        return None
    except Exception:
        return None


class _TrayState(str):
    """A verified mode with an optional complete BAN count; still a state string."""
    def __new__(cls, state, bans=None):
        result = super().__new__(cls, state)
        result.bans = bans
        return result


def _signed_admin_state(base_url: str, token: str, timeout: float = _FETCH_TIMEOUT):
    """Authenticate an existing local service without ever sending its token."""
    if not isinstance(token, str) or not token or len(token) > 4096:
        return None
    try:
        if not _is_loopback(_admin_addr(base_url)[0]):
            return None
        deadline = time.monotonic() + timeout
        def left():
            return max(0.0, deadline - time.monotonic())
        status, _headers, page, _nonce = _read_admin_reply(
            base_url, left(), 1024 * 1024, path="/", read_status=None)
        instances = re.findall(rb'\b(?:const|let) AUTH_INSTANCE="([0-9a-f]{32})";', page)
        if status != 200 or len(instances) != 1:
            return None
        instance = instances[0].decode("ascii")
        stamp, nonce = str(int(time.time() * 1000)), secrets.token_hex(16)
        body_sha = hashlib.sha256(b"").hexdigest()
        message = "\n".join((instance, "GET", "/api/state", stamp, nonce, body_sha))
        key = token.encode("utf-8")
        headers = {"X-Admin-Auth-Instance": instance, "X-Admin-Auth-Time": stamp,
                   "X-Admin-Auth-Nonce": nonce, "X-Admin-Auth-Body": body_sha,
                   "X-Admin-Auth-Mac": hmac.new(key, message.encode("ascii"),
                                                hashlib.sha256).hexdigest()}
        status, response_headers, body, _ = _read_admin_reply(
            base_url, left(), 1024 * 1024, headers=headers, read_status=None)
        proofs = response_headers.get_all("X-Admin-Response-Mac", [])
        response_message = "\n".join((instance, nonce, str(status), hashlib.sha256(body).hexdigest()))
        expected = hmac.new(key, response_message.encode("ascii"), hashlib.sha256).hexdigest()
        if status != 200 or len(proofs) != 1 or not hmac.compare_digest(proofs[0], expected):
            return None
        from ..engine.core.saferegex import safe_json_loads
        data = safe_json_loads(body.decode("utf-8"), max_len=1024 * 1024,
                               default=None, reject_duplicates=True)
        if not isinstance(data, dict):
            return None
        shield = data.get("shield")
        cfg = shield.get("cfg") if isinstance(shield, dict) and not shield.get("error") else None
        if not isinstance(cfg, dict) or type(cfg.get("enabled")) is not bool:
            return None
        mode = cfg.get("mode")
        if mode not in ("enforce", "audit"):
            return None
        state = STATE_OFF if not cfg["enabled"] else STATE_AUDIT if mode == "audit" else STATE_ON
        bans = shield.get("bans")
        count = (len(bans) if data.get("telemetry_complete") is True and isinstance(bans, list)
                 and all(isinstance(row, dict) for row in bans) else None)
        return _TrayState(state, count)
    except Exception:
        return None


def _fetch_shield_state(base_url: str, token: str, timeout: float = _FETCH_TIMEOUT,
                        *, owned_child=None) -> str:
    """Preserve owned-child proof; existing services require a signed response."""
    if owned_child is not None:
        state = _verify_admin_proof(base_url, owned_child, timeout)
        return state or STATE_DOWN
    return _signed_admin_state(base_url, token, timeout) or STATE_AUTH


def _status_lines(state):
    label = _STATUS_TEXT.get(state, _STATUS_TEXT[STATE_DOWN])
    bans = getattr(state, "bans", None)
    return (label, f"BAN: {bans}" if type(bans) is int and bans >= 0
            else "BAN件数: 未確認 / BAN count unconfirmed")


def _poll_status(fetch, show, stop, interval: float = _POLL_SEC) -> None:
    """fetch() で防御状態を取り、*変わった時だけ* show(state) を呼ぶ。初回は即時、以後 interval
    秒ごと、stop(threading.Event)が立ったら抜ける。fetch/show の例外ではループを止めない
    (fetch の例外は接続不可として表示し、show が失敗した状態は次の周回でもう一度表示する)。"""
    last = None
    while not stop.is_set():
        try:
            state = fetch()
        except Exception:
            state = STATE_DOWN
        if state not in _STATUS_TEXT:
            state = STATE_DOWN
        current = (str(state), getattr(state, "bans", None))
        if current != last and not stop.is_set():  # 終了後に消えかけのトレイを触らない
            try:
                show(state)
                last = current
            except Exception:
                pass
        stop.wait(interval)


def _msgbox(text: str, title: str) -> None:
    """Win32 MessageBox(情報アイコン)。tkinter 非依存。失敗は無害。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x40)   # MB_ICONINFORMATION
    except Exception:
        pass


def _confirm_token_copy(title):
    """No secret appears in the prompt, window title, or console."""
    try:
        import ctypes
        return ctypes.windll.user32.MessageBoxW(
            0, "管理トークンをクリップボードへコピーしますか？\n"
            "管理画面のパスワード欄に貼り付けてください。\n"
            "クリップボードは他のアプリからも読めます。内容が変わっていなければ、"
            "約30秒後またはトレイ終了時に消去を試みます。",
            title, 0x24 | 0x100) == 6  # YES/NO, default NO
    except Exception:
        return False


def _clipboard_api():
    import ctypes
    from ctypes import wintypes
    u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
    signatures = (
        (u32.OpenClipboard, wintypes.BOOL, [wintypes.HWND]),
        (u32.CloseClipboard, wintypes.BOOL, []),
        (u32.EmptyClipboard, wintypes.BOOL, []),
        (u32.SetClipboardData, wintypes.HANDLE, [wintypes.UINT, wintypes.HANDLE]),
        (u32.GetClipboardData, wintypes.HANDLE, [wintypes.UINT]),
        (u32.GetClipboardSequenceNumber, wintypes.DWORD, []),
        (k32.GlobalAlloc, wintypes.HANDLE, [wintypes.UINT, ctypes.c_size_t]),
        (k32.GlobalLock, ctypes.c_void_p, [wintypes.HANDLE]),
        (k32.GlobalUnlock, wintypes.BOOL, [wintypes.HANDLE]),
        (k32.GlobalFree, wintypes.HANDLE, [wintypes.HANDLE]),
        (k32.GlobalSize, ctypes.c_size_t, [wintypes.HANDLE]),
    )
    for function, result, args in signatures:
        function.restype, function.argtypes = result, args
    return u32, k32


def _clipboard_write(token, allowed, owner):
    """Only called after explicit consent. Ownership transfers only on success."""
    import ctypes
    u32, k32 = _clipboard_api()
    if not owner or not allowed() or not u32.OpenClipboard(owner):
        return None
    handle = None
    try:
        raw = (token + "\0").encode("utf-16-le")
        handle = k32.GlobalAlloc(0x2, len(raw))  # GMEM_MOVEABLE
        if not handle:
            return None
        memory = k32.GlobalLock(handle)
        if not memory:
            return None
        try:
            ctypes.memmove(memory, raw, len(raw))
        finally:
            k32.GlobalUnlock(handle)
        if not allowed() or not u32.EmptyClipboard() or not u32.SetClipboardData(13, handle):
            return None
        handle = None
        sequence = u32.GetClipboardSequenceNumber()
        return sequence or None
    finally:
        if handle:
            k32.GlobalFree(handle)
        u32.CloseClipboard()


def _clipboard_clear_if_ours(token, sequence):
    """Never erase a later clipboard write, even one containing the same text."""
    import ctypes
    u32, k32 = _clipboard_api()
    if u32.GetClipboardSequenceNumber() != sequence or not u32.OpenClipboard(None):
        return False
    try:
        if u32.GetClipboardSequenceNumber() != sequence:
            return False
        handle = u32.GetClipboardData(13)
        raw = (token + "\0").encode("utf-16-le")
        if not handle or not len(raw) <= k32.GlobalSize(handle) <= 65536:
            return False
        memory = k32.GlobalLock(handle)
        if not memory:
            return False
        try:
            matches = ctypes.string_at(memory, len(raw)) == raw
        finally:
            k32.GlobalUnlock(handle)
        return bool(matches and u32.EmptyClipboard())
    finally:
        u32.CloseClipboard()


def _offer_token_copy(token, title, stop, verify, *, owner=None, seconds=30.0):
    """Owned-child handoff only; no URL, raw-token dialog, or automatic copy."""
    if (stop.is_set() or not isinstance(token, str) or not token or len(token) > 4096
            or "\0" in token or not _confirm_token_copy(title) or stop.is_set()):
        return False
    try:
        if not verify() or stop.is_set():
            return False
        sequence = _clipboard_write(token, lambda: not stop.is_set(), owner)
        if sequence is None:
            if not stop.is_set():
                _msgbox("クリップボードへコピーできませんでした。", title)
            return False
        if stop.is_set():
            _clipboard_clear_if_ours(token, sequence)
            return False
        def clear():
            stop.wait(seconds)
            for _ in range(20):
                try:
                    if _clipboard_clear_if_ours(token, sequence):
                        return
                except Exception:
                    pass
                time.sleep(0.025)
        worker = threading.Thread(target=clear, daemon=True, name="tray-clipboard-clear")
        try:
            worker.start()
        except Exception:
            _clipboard_clear_if_ours(token, sequence)
            return False
        return worker
    except Exception:
        return False


# ── 本体(ゲートウェイ)の自動起動 ──────────────────────────────────────
def _admin_addr(base_url: str):
    """管理APIの (host, port) を DUCKNET_ADMIN_URL から解く。"""
    parts = _admin_parts(base_url)
    return parts.hostname, (parts.port if parts.port is not None
                            else 443 if parts.scheme == "https" else 80)


def _gateway_up(host: str, port: int, timeout: float = 0.5) -> bool:
    """本体(前衛+管理API)が既にそのポートで待受けているか。"""
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def _spawn_gateway(admin_port: int, token: str, admin_host: str = "127.0.0.1"):
    """本体(ゲートウェイ)を子プロセスで起動する。コンソール窓は出さない。ローカル(127.0.0.1)
    の管理 API を内部 HMAC proof で確認する。失敗時は None。"""
    backend = os.environ.get("DUCKNET_BACKEND", "127.0.0.1:8080")
    listen = os.environ.get("DUCKNET_LISTEN", "8443")
    cmd = [sys.executable, "-m", "dataplane",
           "--backend", backend, "--listen", str(listen),
           "--admin", str(admin_port), "--admin-host", admin_host or "127.0.0.1"]
    # トークンは argv ではなく env で渡す: コマンドラインは他ユーザーから読める
    # (Linux の /proc/<pid>/cmdline は world-readable、Windows は WMI で取得可)。
    # env(/proc/<pid>/environ)は同一UID/root 限定=露出面が小さい。
    child_env = dict(os.environ)
    child_env["DUCKNET_ADMIN_TOKEN"] = token
    proof_key = secrets.token_hex(32)
    child_env["DUCKNET_TRAY_PROOF_KEY"] = proof_key
    # 終了時は標準入力の 'stop' で graceful 停止を依頼する(_stop_child)。terminate() は
    # Windows では即死で、ドレインも BAN の flush も走らない。
    child_env["DUCKNET_STDIN_STOP"] = "1"
    kw = {"stdin": subprocess.PIPE, "env": child_env,
          "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform.startswith("win"):
        kw["creationflags"] = 0x08000000 | 0x00000200   # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    try:
        child = subprocess.Popen(cmd, **kw)
        child._ducknet_tray_proof_key = proof_key
        return child
    except Exception:
        return None


def _admin_is_ours(host: str, port: int, timeout: float = 1.0) -> bool:
    """待受けの識別用ヒューリスティック。本人証明には使わない。無認証の
    GET /api/state は 401 + {"ok": false, "error": "token required"} を返すので、これを指紋にする。
    別プロセスでもこの応答を模倣できる。状態には所有子proofか署名応答の検証が必要。"""
    from ..engine.core.netaddr import url as _url
    try:
        status, _headers, body, _nonce = _read_admin_reply(_url(host, port), timeout, 256)
        return status == 401 and _ADMIN_401_MARK in body
    except Exception:
        return False


def _ensure_gateway(base_url: str, token: str):
    """本体が起動していなければ起動する。戻り値 (token, child)。child は本launcher が起動した
    子プロセス(既に稼働中なら None=触らない)。起動時は管理APIが上がるまで最大 ~6 秒待つ。"""
    host, port = _admin_addr(base_url)
    if _admin_parts(base_url).scheme != "http" or not _is_loopback(host):
        # The spawned service provides plain HTTP on a numeric loopback address.
        # A remote/HTTPS setting must never silently start a different local target.
        print("[警告] この管理 URL の本体はトレイから自動起動しません。"
              "本体を別に起動して管理 URL を確認してください。", file=sys.stderr)
        return token, None
    if _gateway_up(host, port):
        if not _admin_is_ours(host, port):        # 別プロセスのポート占有を稼働中と誤認しない
            print("[警告] %s:%d は本製品以外のプロセスが使用しています。ゲートウェイを起動できず、"
                  "保護は動作していません。" % (host, port), file=sys.stderr)
            return "", None                       # 占有プロセスへトークンを渡さない
        return token, None
    # A tray-spawned child has hidden stderr on Windows. Surface the required
    # legacy-state choice here instead of silently losing the service's error.
    from ..engine.core.atomic_io import LegacyStateSelectionRequired, default_state_dir
    try:
        default_state_dir()
    except LegacyStateSelectionRequired as exc:
        print(f"[警告] {exc}", file=sys.stderr)
        _msgbox(str(exc), "DuckNet-Lite 保存先の選択")
        return "", None
    tok = token or secrets.token_urlsafe(24)
    child = _spawn_gateway(port, tok, host)
    if child is not None:
        try:
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                up = _gateway_up(host, port, timeout=min(0.2, remaining))
                remaining = deadline - time.monotonic()
                if (up and remaining > 0
                        and _verify_admin_proof(base_url, child, timeout=min(1.0, remaining))):
                    return tok, child
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        except BaseException:                     # 待機中の Ctrl-C 等でも子を孤児にしない
            if _stop_child(child) is not True:
                print("[警告] 起動した本体の停止を確認できません。プロセスの状態を確認してください。",
                      file=sys.stderr)
            raise
        if _stop_child(child) is not True:
            # Retain ownership so final cleanup can retry this child.
            print("[警告] 起動した本体の停止を確認できません。終了時に停止を再試行します。",
                  file=sys.stderr)
            return "", child
    print("[警告] ゲートウェイの起動を確認できませんでした。設定と起動ログを確認してください。",
          file=sys.stderr)
    return "", None


def _is_loopback(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address((host or "").strip("[]")).is_loopback
    except ValueError:
        return False


def _stop_wait() -> float:
    """graceful 停止を待つ上限秒数: 本体のドレイン猶予(DUCKNET_DRAIN_GRACE、既定 5)+後始末の余裕。"""
    try:
        grace = float(os.environ.get("DUCKNET_DRAIN_GRACE", "") or 5.0)
    except ValueError:
        grace = 5.0
    return max(0.0, min(grace, 120.0)) + 5.0


def _stop_child(child) -> bool:
    """本launcher が起動した子プロセス(本体)を穏当に停止する。None/停止済みは無視。
    まず標準入力の 'stop' で graceful 停止(ドレイン→BAN の flush)を依頼し、上限時間内に
    終わらなければ terminate → kill へ落とし、実際の終了を確認できた時だけ True。"""
    if child is None:
        return True
    pipe = getattr(child, "stdin", None)

    def finished():
        try:
            return child.poll() is not None
        except (Exception, KeyboardInterrupt):
            return False

    try:
        if finished():
            return True
        asked = False
        if pipe is not None:
            try:
                pipe.write(b"stop\n")
                pipe.flush()
                asked = True
            except (Exception, KeyboardInterrupt):
                pass
            try:
                pipe.close()
            except (Exception, KeyboardInterrupt):
                pass
        if asked:
            try:
                child.wait(timeout=_stop_wait())
            except (Exception, KeyboardInterrupt):
                pass
            if finished():
                return True
        for action in ("terminate", "kill"):
            if finished():
                return True
            try:
                getattr(child, action)()
                child.wait(timeout=3)
            except (Exception, KeyboardInterrupt):
                pass
            if finished():
                return True
        return False
    finally:
        if pipe is not None:
            try:
                pipe.close()
            except (Exception, KeyboardInterrupt):
                pass


def main(argv=None) -> int:
    # GUI から起動したときも app.env を効かせる(以前はシェルのランチャだけが
    # 読んでおり、ダブルクリック起動では DUCKNET_BACKEND 等が黙って無視された)。
    from ..service import load_env_file, _force_utf8_stdio
    # `python -m dataplane.gui` は service.main() を通らないため、ここでも標準出力を
    # UTF-8 に寄せる。以前はこれが無く、非 UTF-8 コンソール(英語版 Windows の cp1252 等)
    # では下の日本語警告を出そうとした瞬間に UnicodeEncodeError で落ちていた ――
    # よりによって「別プロセスがポートを占有しており保護が動作していない」と
    # 伝えようとしている、いちばん落ちてはいけない場面で。
    _force_utf8_stdio()
    load_env_file()
    if not tray.available():
        print("トレイ常駐は Windows 専用です(他 OS では非対応)。"
              "Lite は CLI + Web ダッシュボードで運用してください。", file=sys.stderr)
        return 0

    admin_url, brand = _admin_url(), _brand()      # app.env の取り込み後に読む
    try:
        _admin_addr(admin_url)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        _msgbox("DUCKNET_ADMIN_URL が不正です。HTTP(S) の管理 URL とポートを確認してください。", brand)
        return 1

    # 本体(ゲートウェイ)も一緒に起動: 管理APIが未待受なら子プロセスで起動する
    # (既に稼働中なら起動しない)。gw は終了時に停止する。
    _tok, gw = _ensure_gateway(admin_url, os.environ.get("DUCKNET_ADMIN_TOKEN", ""))

    stop = threading.Event()

    items = [("ダッシュボードを開く", "dash"), None,
             ("About", "about"),
             ("無料版でできること", "caps"), None,
             ("終了", "quit")]

    ti = None
    poller = None
    clipboard_worker = None
    rc = 0

    def _notice(message, title):
        if not stop.is_set():
            _msgbox(message, title)

    def _on_action(aid):
        nonlocal clipboard_worker
        if stop.is_set():
            return
        if aid == "dash":
            if gw is None:
                if not _signed_admin_state(admin_url, _tok):
                    _notice("管理画面の真正性を確認できません。管理 URL と管理トークンを確認してください。"
                            "未確認の相手へトークンは送信しません。", brand)
                    return
            elif not _owned_child_active(gw, admin_url):
                _notice("トレイが起動した本体が停止したか、管理 URL が数値 loopback ではありません。"
                        "管理画面へトークンを送らず、本体と DUCKNET_ADMIN_URL を確認してください。", brand)
                return
            if not _tok:
                _notice("管理トークンが不明です。起動時に表示されたトークンで "
                        "管理 URL を開くか、app.env の DUCKNET_ADMIN_TOKEN を "
                        "本体とトレイに共通設定して再起動してください。", brand)
                return
            if gw is not None:
                host, port = _admin_addr(admin_url)
                if not _admin_is_ours(host, port) or not _verify_admin_proof(admin_url, gw):
                    _notice("管理ポートの応答をトレイが起動した本体と確認できません。"
                            "管理画面へトークンを送らず、本体を再起動してください。", brand)
                    return
            if stop.is_set():
                return
            try:
                opened = webbrowser.open(_dashboard_url(admin_url))
            except Exception:
                opened = False
            if stop.is_set():
                return
            if opened is not True:
                _notice("ブラウザを開けませんでした。管理 URL をブラウザで直接開いてください。", brand)
                return
            if _owned_child_active(gw, admin_url):
                if clipboard_worker is None or not clipboard_worker.is_alive():
                    clipboard_worker = _offer_token_copy(
                        _tok, brand, stop,
                        lambda: _verify_admin_proof(admin_url, gw) and _owned_child_active(gw, admin_url),
                        owner=getattr(ti, "_hwnd", None)) or None
            elif gw is None:
                _notice("管理画面を確認しました。本体の管理トークンをパスワード欄へ入力してください。"
                        "別に起動した本体のトークンはトレイからコピーしません。", brand)
        elif aid == "about":
            _notice(_ABOUT_TEXT.format(brand=brand), "About — " + brand)
        elif aid == "caps":
            _notice(_CAPS_TEXT, brand)
        elif aid == "quit":
            stop.set()
            try:
                if ti is not None:
                    ti.stop()
            except Exception:
                pass

    try:
        on_ico, off_ico = _status_icons()
        initial_tip, _ = _status_view(STATE_AUTH, brand)
        ti = tray.TrayIcon(off_ico, initial_tip, items, _on_action)
        menu_status = getattr(ti, "set_status_lines", None)
        if callable(menu_status):
            menu_status(_status_lines(STATE_AUTH))
        if not ti.start():
            print("トレイの起動に失敗しました。", file=sys.stderr)
            return 1

        # 暗号学的に検証した状態だけ表示する。トークン自体は poll 要求へ送らない。
        # 表示の失敗でトレイや本体を巻き込まない。
        def _show(state):
            if not stop.is_set():
                tip, name = _status_view(state, brand)
                ti.set_status(tip, on_ico if name == ASSET_ICO else off_ico)
                if callable(menu_status):
                    menu_status(_status_lines(state))
                if getattr(ti, "_status_error", None):
                    # Keep poller's last state unchanged so failed delivery is
                    # retried even when the actual defense state stays stable.
                    raise RuntimeError("tray status notification failed")

        def _fetch_owned_state():
            started = time.monotonic()
            state = _fetch_shield_state(admin_url, _tok, owned_child=gw)
            if gw is not None and state in (STATE_ON, STATE_OFF, STATE_AUDIT) and not stop.is_set():
                left = _FETCH_TIMEOUT - (time.monotonic() - started)
                signed = _signed_admin_state(admin_url, _tok, left) if left > 0 else None
                if signed == state and _owned_child_active(gw, admin_url):
                    return signed
            return state

        if not stop.is_set():
            try:
                poller = threading.Thread(target=_poll_status,
                                          args=(_fetch_owned_state, _show, stop),
                                          kwargs={"interval": _POLL_SEC},
                                          daemon=True, name="tray-status")
                poller.start()
            except Exception:
                print("[警告] 防御状態の監視を開始できません。状態は未確認です。", file=sys.stderr)
        while not stop.wait(0.25):
            alive = getattr(ti, "is_alive", None)
            if callable(alive):
                try:
                    running = alive()
                except Exception:
                    running = False
                if not running:
                    print("[警告] トレイが予期せず停止しました。本体を停止して終了します。", file=sys.stderr)
                    rc = 1
                    break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()                       # Ctrl-C で抜けた時も状態ポーラを止める
        join_clipboard = getattr(clipboard_worker, "join", None)
        if callable(join_clipboard):
            try:
                join_clipboard(timeout=0.8)
            except (Exception, KeyboardInterrupt):
                pass  # Clipboard cleanup must not skip owned gateway shutdown.
        if ti is not None:
            try:
                if ti.stop() is False:
                    print("[警告] トレイの停止を確認できませんでした。", file=sys.stderr)
                    rc = 1
            except Exception:
                print("[警告] トレイの停止に失敗しました。", file=sys.stderr)
                rc = 1
        join = getattr(poller, "join", None)
        if callable(join):
            try:
                join(timeout=_FETCH_TIMEOUT + 0.2)
            except Exception:
                pass
        if _stop_child(gw) is not True:
            print("[警告] 本体の停止を確認できませんでした。", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
