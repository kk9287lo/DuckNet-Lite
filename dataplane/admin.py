"""
admin.py — DuckNet L7 Security 管理ダッシュボード(Web GUI・stdlib http.server)
====================================================================================
中小企業のWeb担当者が『管理画面で攻撃をグラフ化・ON/OFFをクリック』できる製品UI。
外部依存ゼロ(標準ライブラリのみ)。app_firewall + net_shield を1画面で操作・監視する。

  · GET  /                  … ダッシュボード(HTML・localでtoken同梱)
  · GET  /api/state         … 現在の全状態(firewall/shield/指標/capabilities)
  · POST /api/firewall/*    … ON/OFF・ゾーンポリシー・IPルール
  · POST /api/shield/*      … ON/OFF・config・unban
  · GET  /api/shield/events|top|bans
  · GET  /api/edge          … エッジ前衛(リバースプロキシ)設定(444 Drop)テキストを取得

localhost限定 + ランダム Bearer トークン(他プロセス遮断)。商用配布可。
"""
from __future__ import annotations

import hmac
import http.cookies
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 管理トークンを焼く Cookie 名。HttpOnly + SameSite=Strict で配るため、XSS では読めず
# (HttpOnly)・クロスサイトからは送られない(SameSite=Strict=CSRF 緩和)。HTTP(localhost)
# 運用のため Secure は付けない(HTTPS 終端を挟む場合は Secure も付与すること)。
_COOKIE_NAME = "ducknet_admin"

from dataplane.engine.lifeform.policy import app_firewall, ZONES, ACTIONS
from dataplane.engine.lifeform.pipeline import net_shield
from dataplane.engine.services import edge_config
from dataplane.engine.core.atomic_io import (default_state_dir, tail_jsonl,
                                                      append_jsonl)

# 管理APIのリクエストボディ上限(Content-Length 詐称・巨大ボディのメモリ枯渇防止)。
_MAX_BODY = 1 << 20


def _j(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, default=lambda o: str(o)).encode("utf-8")


def _metrics_exposition(sh) -> str:
    """NetShield の指標を plain-text 露出形式で出す(監視系のスクレイプ用・依存ゼロ)。
    `# HELP`/`# TYPE` + `ducknet_<name>{label="v"} <int>`。ラベル値はサニタイズ(改行/引用符除去)。"""
    m = sh.metrics()
    out = []

    def scalar(name, val, typ, help_):
        out.append(f"# HELP ducknet_{name} {help_}")
        out.append(f"# TYPE ducknet_{name} {typ}")
        out.append(f"ducknet_{name} {val}")

    for key, name, h in (("requests", "requests_total", "Requests inspected"),
                         ("allow", "allow_total", "Allowed requests"),
                         ("block", "block_total", "Blocked requests"),
                         ("throttle", "throttle_total", "Throttled requests"),
                         ("dlp_leak", "dlp_leak_total", "Egress secret leaks"),
                         ("subnet_flag", "subnet_flag_total", "Subnet-aggregation soft flags")):
        scalar(name, int(m.get(key, 0)), "counter", h)
    scalar("shield_enabled", 1 if sh.is_enabled() else 0, "gauge", "Shield enabled (1/0)")
    scalar("tracked_ips", int(m.get("tracked_ips", 0)), "gauge", "Tracked source IPs")
    scalar("active_bans", int(m.get("active_bans", 0)), "gauge", "Active bans")
    scalar("paranoia_level", int(sh.cfg.get("paranoia", 1) or 1), "gauge", "Detection paranoia level")
    _sn = sh.subnet_status()
    scalar("hot_subnets", int(_sn.get("hot_subnets", 0)), "gauge", "Hot subnets (distributed-attack)")
    scalar("tracked_subnets", int(_sn.get("tracked_subnets", 0)), "gauge", "Tracked subnets")

    def labeled(name, d, label, help_):
        if not isinstance(d, dict) or not d:
            return
        out.append(f"# HELP ducknet_{name} {help_}")
        out.append(f"# TYPE ducknet_{name} counter")
        for k, v in d.items():
            lv = str(k).replace("\\", "").replace('"', "").replace("\n", "")[:64]
            out.append(f'ducknet_{name}{{{label}="{lv}"}} {int(v)}')

    labeled("sig_hits_total", m.get("sig_hits"), "signature", "Signature hits by category")
    labeled("zone_hits_total", m.get("zone_hits"), "zone", "Requests by zone")
    return "\n".join(out) + "\n"


def _audit_entry(path: str, b: dict, r: dict, pre_cfg: dict, pre_fw: dict):
    """成功した mutating POST 1件から監査ログ行を組み立てる。
    (summary, before, after, revert) を返す。ログに残す価値が無ければ None
    (例: /api/shield/config で実際には何も変わらなかった呼び出し)。

    このフォークのルート一覧に合わせて絞ってある(honeypot/intel_reload/posmodel/
    under_attack は Lite に存在しないため対象外)。revert は「単純なスカラー設定値」を
    1回だけ元に戻すための {endpoint, body} のみ持たせる。add/remove系(シグネチャ・
    ルール・BAN等)は一覧操作で戻せるためここでは revert を付けない。"""
    def cfgrevert(key, before):
        return {"endpoint": "/api/shield/config", "body": {key: before}}

    if path == "/api/firewall/toggle":
        on = bool(b.get("on"))
        return (f"firewall {'enabled' if on else 'disabled'}", pre_fw["enabled"], on,
                {"endpoint": path, "body": {"on": pre_fw["enabled"]}})
    if path == "/api/firewall/policy":
        zone, action = b.get("zone", ""), b.get("action", "")
        before = pre_fw["policy"].get(zone)
        return (f"firewall zone '{zone}' policy -> {action}", before, action, None)
    if path == "/api/firewall/rule":
        net = b.get("net", "")
        if b.get("op") == "remove":
            prev = next((x for x in pre_fw["rules"] if x.get("net") == net), None)
            return (f"firewall rule {net} removed", prev, None, None)
        return (f"firewall rule {net} -> {b.get('action', 'deny')}", None,
                {"net": net, "action": b.get("action", "deny")}, None)
    if path == "/api/firewall/resolve":
        approve = bool(b.get("approve"))
        remember = bool(b.get("remember"))
        ip = r.get("ip", "")
        suffix = "(記憶=常時許可)" if approve and remember else "(一時)" if approve else ""
        return (f"pending connection {ip or b.get('id', '')} "
                f"{'approved' if approve else 'denied'}{suffix}",
                None, {"id": b.get("id", ""), "approve": approve,
                       "remember": remember, "ip": ip}, None)
    if path == "/api/shield/toggle":
        on = bool(b.get("on"))
        return (f"shield {'enabled' if on else 'disabled'}", pre_cfg.get("enabled"), on,
                {"endpoint": path, "body": {"on": pre_cfg.get("enabled")}})
    if path == "/api/shield/config":
        changed = r.get("changed") or {}
        if not changed:
            return None
        before = {k: pre_cfg.get(k) for k in changed}
        parts = [f"{k}: {before[k]} -> {v}" for k, v in changed.items()]
        revert = None
        if len(changed) == 1:
            (k, v), = changed.items()
            revert = cfgrevert(k, before[k])
        return ("config: " + "; ".join(parts), before, changed, revert)
    if path == "/api/shield/optional_sig":
        name, on = b.get("name", ""), bool(b.get("on"))
        before = bool((pre_cfg.get("optional_sigs") or {}).get(name))
        return (f"optional signature '{name}' -> {'on' if on else 'off'}", before, on,
                {"endpoint": path, "body": {"name": name, "on": before}})
    if path == "/api/shield/paranoia":
        before = pre_cfg.get("paranoia")
        after = r.get("paranoia")
        return (f"paranoia level {before} -> {after}", before, after,
                (cfgrevert("paranoia", before) if before is None else
                 {"endpoint": "/api/shield/paranoia", "body": {"level": before}}))
    if path == "/api/shield/path_limits":
        after = r.get("path_limits", [])
        before = pre_cfg.get("path_limits")
        return (f"path limits updated ({len(after)} rules)", before, after, None)
    if path == "/api/shield/blocked_methods":
        after = r.get("blocked_methods", [])
        before = pre_cfg.get("blocked_methods")
        return (f"blocked methods -> {', '.join(after) or '(none)'}", before, after, None)
    if path == "/api/shield/sig_add":
        return (f"signature '{b.get('name', '')}' added", None,
                {"name": b.get("name", ""), "pattern": b.get("pattern", "")}, None)
    if path == "/api/shield/sig_remove":
        return (f"signature '{b.get('name', '')}' removed", {"name": b.get("name", "")}, None, None)
    if path == "/api/shield/unban":
        return (f"IP {b.get('ip', '')} unbanned", {"ip": b.get("ip", "")}, None, None)
    if path == "/api/shield/ban":
        return (f"IP {b.get('ip', '')} banned manually", None, {"ip": b.get("ip", "")}, None)
    if path == "/api/appeal/resolve":
        ip, approve = b.get("ip", ""), bool(b.get("approve"))
        return (f"appeal {ip} {'approved' if approve else 'denied'}", None,
                {"ip": ip, "approve": approve}, None)
    if path == "/api/global_block":
        on = bool(b.get("on"))
        before = pre_fw["policy"].get("public")
        return (f"global block -> {'on' if on else 'off'}", before, "deny" if on else "allow", None)
    return None


class AdminDashboard:
    def __init__(self, host: str = "127.0.0.1", port: int = 8081, token: str = "",
                 state_dir: str = "",
                 brand: str = "", logo: str = "🦅",
                 subtitle: str = "L7 防御 — 管理ダッシュボード",
                 edge_guard=None):
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(24)
        # 前衛ガード(AsyncEdgeGuard)への参照(任意)。渡されれば接続受理/バックエンド
        # 不達等の生指標(self.metrics)を state() 経由でダッシュボードへ可視化する。
        # 未指定(単体テスト等)なら空 dict で degrade=既存呼び出し元は変更不要。
        self.edge_guard = edge_guard
        # 画面の表示名/アイコン。ステルス運用では汎用名(例 "System Health Monitor")に
        # 差し替えて、管理画面のタイトル/ヘッダ/Server ヘッダから製品を伏せる。明示が無ければ
        # DUCKNET_COVER env を尊重し(遮断ページと同じ秘匿源=適用漏れを防ぐ)、無ければ製品名。
        self.brand = brand or os.environ.get("DUCKNET_COVER", "DuckNet L7 Security")
        self.logo = logo
        self.subtitle = subtitle
        # 検知ログの所在(別プロセスが書く)。DUCKNET_STATE_DIR で移設可。テストは上書き可。
        self._state_dir = state_dir or default_state_dir()
        self._server = None
        self._thread = None

    # ── 監査ログ ──
    @property
    def _audit_path(self) -> str:
        # self._state_dir は construction 後にテストが直接差し替える運用なので、ここも
        # __init__ でキャッシュせず毎回その場で組み立てる(キャッシュすると差し替えが効かず
        # 別テスト間で監査ログが混線する)。
        return os.path.join(self._state_dir, "admin_audit.jsonl")

    def record_audit(self, path: str, b: dict, r: dict, pre_cfg: dict, pre_fw: dict) -> None:
        """成功した mutating POST 1件を admin_audit.jsonl へ追記する。失敗しても本処理は
        止めない(監査は付随機能・可用性を落とさない)。他の JSONL ログと同じ既定ローテーション
        (5MB・世代1)を append_jsonl の既定値で踏襲する。"""
        try:
            built = _audit_entry(path, b, r, pre_cfg, pre_fw)
            if not built:
                return
            summary, before, after, revert = built
            append_jsonl(self._audit_path, {"ts": time.time(), "endpoint": path,
                                            "summary": summary, "before": before,
                                            "after": after, "revert": revert})
        except Exception:
            pass

    def audit_log(self, n: int = 200) -> dict:
        """直近の監査ログ(新しい順)。GET /api/admin_audit が返す。"""
        return {"entries": tail_jsonl(self._audit_path, n)}

    # ── 状態取得 ──
    @staticmethod
    def _safe_dict(fn, *a, **kw) -> dict:
        """1データソースの取得を他から独立して保護する。辞書を返す想定のソース向け:
        失敗してもそのキーだけ {"error": ...} に degrade し、/api/state 全体を
        巻き込まない(1箇所のバグで管理画面が丸ごと落ちるのを防ぐ)。"""
        try:
            return fn(*a, **kw)
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _safe_list(fn, *a, **kw) -> list:
        """一覧を返す想定のソース向け: 失敗時は空リストへ degrade する。ダッシュボードJS
        側は `(s.xxx||[]).map(...)` 前提なので、型を空リストに揃えて後続パネルの
        描画まで巻き込む例外(存在しないキーへの .map 呼び出し等)を避ける。"""
        try:
            return fn(*a, **kw)
        except Exception:
            return []

    def state(self) -> dict:
        fw = app_firewall()
        sh = net_shield()
        from dataplane.engine.services.proxy import AsyncEdgeGuard
        # 以下のサブ状態はそれぞれ独立に取得する: 1つが例外を投げても、その
        # キーだけが degrade し、他のパネルは正常なデータで描画され続ける。
        return {"firewall": self._safe_dict(fw.status),
                "shield": self._safe_dict(sh.status),
                "shield_metrics": self._safe_dict(sh.metrics),
                "top": self._safe_list(sh.top_talkers, 12),
                "events": self._safe_list(sh.events, 40),
                "zones": ZONES, "actions": ACTIONS,
                "capabilities": self._safe_dict(AsyncEdgeGuard.platform_capabilities),
                # 前衛ガード(接続受理/バックエンド不達等)の生指標。edge_guard 未配線
                # (単体テスト・旧呼び出し元)なら空 dict=既存の見た目を壊さない。
                "edge_metrics": (self._safe_dict(lambda: dict(self.edge_guard.metrics))
                                 if self.edge_guard else {})}

    def deception_status(self) -> dict:
        """動的デセプション(MTD)の状態。env 駆動・状態レスのため本プロセスの env を反映し、
        サンプル攻撃者から見える偽バナー+随伴ヘッダのローテーションをプレビューする(可視化のみ)。"""
        from dataplane.engine.services import banner as dc
        enabled = dc.is_enabled()
        preview = []
        if enabled:
            now = time.time()
            for i in range(4):           # 直近4窓: 同一攻撃者には時間で *矛盾* して見える
                hs = dc.headers_for("203.0.113.1", now=now + 30 * i)
                banner = next((v for k, v in hs if k == "Server"), "")
                comp = [f"{k}: {v}" for k, v in hs if k != "Server"]
                preview.append({"window": i, "family": dc._family(banner),
                                "server": banner, "companions": comp})
        return {"enabled": enabled, "families": list(dc._FAMILIES),
                "family_count": len(dc._FAMILIES), "sample_seed": "203.0.113.1",
                "preview": preview,
                "note": "既定OFF。DUCKNET_DECEPTION で有効化(本プロセスの env を反映)。"}

    def start(self) -> dict:
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True, name="shield-admin")
        self._thread.start()
        return {"ok": True, "url": f"http://{self.host}:{self.port}",
                "token": self.token}

    def stop(self) -> dict:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        return {"ok": True}


def _make_handler(app: AdminDashboard):
    class H(BaseHTTPRequestHandler):
        timeout = 20
        server_version = app.brand
        sys_version = ""

        def version_string(self):
            # Server ヘッダはブランド名のみ(Python/BaseHTTP のバージョンや余分な空白を
            # 晒さない=指紋低減)。ステルス時は cover 名になり製品が露見しない。
            return app.brand

        def log_message(self, *a):
            pass

        def _auth(self) -> bool:
            # 認証元(いずれか): X-Token / Authorization: Bearer(プログラム/テスト用)
            # または HttpOnly Cookie(ブラウザ=トークンを JS に晒さない硬派経路)。
            tok = self.headers.get("X-Token") or ""
            a = self.headers.get("Authorization") or ""
            if a.lower().startswith("bearer "):
                tok = a[7:].strip()
            if not tok:
                raw = self.headers.get("Cookie") or ""
                if raw:
                    try:
                        m = http.cookies.SimpleCookie(raw).get(_COOKIE_NAME)
                        if m:
                            tok = m.value
                    except Exception:
                        pass
            # 定数時間 + bytes 比較(非ASCIIトークンでの TypeError と長さ依存の漏れを排除)。
            return hmac.compare_digest(str(tok).encode("utf-8", "ignore"),
                                       str(app.token).encode("utf-8", "ignore"))

        def _send(self, code, body, ctype="application/json; charset=utf-8",
                  set_cookie=None):
            # 全体を1つの try で囲む: send_response/send_header/end_headers 自体も
            # (クライアント切断後の broken pipe 等で)例外を投げ得る。ここで漏らすと、
            # 呼び出し元の「例外→_send(500,...) でフォールバック応答」という型の処理
            # (do_GET/do_POST の外側ハンドラ)が、既に壊れた接続へ二重に _send を試みて
            # 二重に例外を出すことになる。_send は常に無害に失敗できる=決して例外を
            # 外へ漏らさない、という契約にする。
            try:
                data = body if isinstance(body, bytes) else body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                if set_cookie:
                    self.send_header("Set-Cookie", set_cookie)
                # セキュリティヘッダ(深層防御): クリックジャッキング/MIME詮索/外部読込/参照漏れの抑止。
                # 本体は依存ゼロの単一HTML(全インライン)なので script/style は 'unsafe-inline' を許可、
                # 通信先は同一オリジンのみ(connect-src 'self')に縛る。
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                 "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                 "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                pass

        def _body(self) -> dict:
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if n <= 0:
                    return {}
                # 読み込み量を上限で頭打ち(Content-Length 詐称/巨大ボディのメモリ枯渇防止)。
                raw = self.rfile.read(min(n, _MAX_BODY))
                if not raw:
                    return {}
                # JSON 再帰爆弾([[[[…]]]])はパース前に深さで弾く(graphql と統一・自己DoS回避)。
                from .engine.core import saferegex
                d = saferegex.safe_json_loads(raw.decode("utf-8", "replace"),
                                              max_len=_MAX_BODY, default=None)
                return d if isinstance(d, dict) else {}
            except Exception:
                return {}

        def _hostname_allowed(self, hostname) -> bool:
            """hostname(port/[]除去済み・小文字)が管理面の正規ホストとして許可されるか。
            DNSリバインディング対策の核心: 攻撃者ページは *ドメイン名*(evil.com)でしか
            ゲートウェイの loopback へ到達させられない(rebind 後も URL のホストは evil.com)。
            そこで **IPリテラル or localhost or 自身の bind host or 運用者許可リスト** のみ許可し、
            それ以外のホスト名は拒否する=rebinding(Host: evil.com)と、管理面を外部ドメインで
            前段公開する構成(全 peer が loopback に見えトークンが誰にでも渡る)を同時に塞ぐ。"""
            if not hostname:
                return True     # Host 無し(HTTP/1.0/生クライアント)は rebinding 経路になり得ない
            if hostname in ("localhost", str(app.host).lower()):
                return True
            try:
                import ipaddress
                ipaddress.ip_address(hostname)   # IPリテラル(loopback/LAN/直IP アクセス)は許可
                return True
            except ValueError:
                pass
            allowed = os.environ.get("DUCKNET_ADMIN_ALLOWED_HOSTS", "")
            allow = {h.strip().lower() for h in allowed.split(",") if h.strip()}
            return hostname in allow

        @staticmethod
        def _host_of(raw: str) -> str:
            """Host/Origin 由来の権威値から hostname 部(port/[]除去・小文字)を取り出す。"""
            raw = (raw or "").strip().lower()
            if not raw:
                return ""
            if raw.startswith("//"):
                raw = raw[2:]
            if "://" in raw:                     # Origin: scheme://host:port
                raw = raw.split("://", 1)[1]
            raw = raw.split("/", 1)[0]
            if raw.startswith("["):              # [ipv6]:port
                end = raw.find("]")
                return raw[1:end] if end != -1 else raw
            return raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw

        def _host_ok(self) -> bool:
            """Host ヘッダの検証(全リクエスト・認証やトークン配布より手前)。"""
            return self._hostname_allowed(self._host_of(self.headers.get("Host")))

        def _origin_ok(self) -> bool:
            """状態変更 POST の Origin/Referer 同一オリジン検査(CSRF/rebinding の多層防御)。
            Origin(無ければ Referer)が提示されていて、その host が許可外なら拒否する。
            プログラム的クライアント(Origin/Referer 無し)はトークン必須で別途守られる。"""
            src = self.headers.get("Origin") or self.headers.get("Referer") or ""
            if not src:
                return True
            return self._hostname_allowed(self._host_of(src))

        @staticmethod
        def _may_set_token_cookie(peer_ip, authed, query_token, real_token) -> bool:
            """`/` 訪問時にトークン Cookie を配ってよいか。**無認証の第三者へは配らない**
            (admin を非localhostへ公開してもトークン窃取で乗っ取られない)。許可条件:
            localhost 経由 / 既に有効トークン提示(header・cookie)/ ?token=<起動時トークン>
            (リモートブラウザの初回ブートストラップ)。"""
            if peer_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                return True
            if authed:
                return True
            return bool(query_token) and hmac.compare_digest(
                str(query_token).encode("utf-8", "ignore"),
                str(real_token).encode("utf-8", "ignore"))

        def do_GET(self):
            # Host 検証は `/`(トークンCookie配布)より手前。rebinding/前段公開でトークンを
            # 無認証の第三者へ渡さない(#auth)。421=Misdirected Request。
            if not self._host_ok():
                self._send(421, _j({"ok": False, "error": "host not allowed"}))
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                html = (_HTML.replace("__BRAND__", app.brand)
                        .replace("__LOGO__", app.logo)
                        .replace("__SUBTITLE__", app.subtitle))
                # トークンは HTML/JS に埋め込まず HttpOnly Cookie で配る(XSS で抜けない)。ただし
                # 配布は localhost or 認証済みのみ=無認証のリモートへトークンを渡さない(乗っ取り防止)。
                from urllib.parse import urlparse, parse_qs
                qtok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
                peer = (self.client_address or ("",))[0]
                set_cookie = None
                if self._may_set_token_cookie(peer, self._auth(), qtok, app.token):
                    ck = http.cookies.SimpleCookie()
                    ck[_COOKIE_NAME] = app.token
                    ck[_COOKIE_NAME]["httponly"] = True
                    ck[_COOKIE_NAME]["samesite"] = "Strict"
                    ck[_COOKIE_NAME]["path"] = "/"
                    set_cookie = ck[_COOKIE_NAME].OutputString()
                self._send(200, html, "text/html; charset=utf-8", set_cookie=set_cookie)
                return
            if not self._auth():
                self._send(401, _j({"ok": False, "error": "token required"}))
                return
            try:
                self._dispatch_get(path)
            except Exception as e:
                # do_POST と同じ思想: 個々の GET ルート(state() 等、複数のサブ状態を
                # 無防備に連結)のどこか1箇所が例外を投げても、ベースHTTPサーバの既定
                # 処理(無言で接続を切る)に落とさず、ダッシュボード全体を道連れにしない。
                self._send(500, _j({"ok": False, "error": str(e)}))

        def _dispatch_get(self, path):
            sh = net_shield()
            if path == "/api/state":
                self._send(200, _j(app.state()))
            elif path == "/api/deception":
                self._send(200, _j(app.deception_status()))
            elif path == "/api/series":
                # チャートの時間範囲ズームがクライアント側の既存retained分をフルに切り出せる
                # よう、サーバ側の返却上限を _series の実容量(maxlen=600・約10分)まで返す。
                # 新たな長期保存は追加しない(既にメモリ上にある分をそのまま返すだけ)。
                self._send(200, _j({"series": sh.series(600)}))
            elif path == "/api/admin_audit":
                self._send(200, _j(app.audit_log()))
            elif path == "/api/analysis":
                self._send(200, _j(sh.analysis()))
            elif path == "/api/appeals":
                self._send(200, _j({"appeals": sh.list_appeals()}))
            elif path == "/api/nodes":
                self._send(200, _j(sh.nodes()))
            elif path == "/api/apt":
                self._send(200, _j(sh.apt_report()))
            elif path == "/api/shield/events":
                self._send(200, _j({"events": sh.events(100)}))
            elif path == "/api/shield/top":
                self._send(200, _j({"top": sh.top_talkers(20)}))
            elif path == "/api/shield/bans":
                self._send(200, _j({"bans": sh.bans()}))
            elif path == "/api/shield/signatures":
                self._send(200, _j(sh.list_signatures()))
            elif path == "/api/shield/subnet":
                self._send(200, _j(sh.subnet_status()))
            elif path == "/api/shield/tamper":          # 改竄検知の可視化(#55)
                self._send(200, _j(sh.tamper_report()))
            elif path == "/api/edge":
                self._send(200, edge_config.edge_proxy_config(),
                           "text/plain; charset=utf-8")
            elif path == "/api/metrics":
                self._send(200, _metrics_exposition(sh),
                           "text/plain; version=0.0.4; charset=utf-8")
            else:
                self._send(404, _j({"ok": False, "error": "not found"}))

        def do_POST(self):
            # Host + Origin 検証を認証より手前に置く(rebinding/CSRF の多層防御)。
            if not self._host_ok():
                self._send(421, _j({"ok": False, "error": "host not allowed"}))
                return
            if not self._origin_ok():
                self._send(403, _j({"ok": False, "error": "bad origin"}))
                return
            if not self._auth():
                self._send(401, _j({"ok": False, "error": "token required"}))
                return
            path = self.path.split("?")[0]
            b = self._body()
            fw, sh = app_firewall(), net_shield()
            # 監査ログ用の変更前スナップショット。個々の分岐へ計装せず、ここ1箇所で変更前を
            # 取り、成功後にもう1箇所(下の record_audit 呼び出し)でログする ―― 唯一のフック
            # 2点(取得/記録)だけで全 mutating ルートを横断カバーする。
            pre_cfg = dict(sh.cfg)
            pre_fw = {"enabled": fw.enabled, "policy": dict(fw.policy), "rules": list(fw.rules)}
            try:
                if path == "/api/firewall/toggle":
                    r = fw.enable() if b.get("on") else fw.disable()
                elif path == "/api/firewall/policy":
                    r = fw.set_policy(b.get("zone", ""), b.get("action", ""))
                elif path == "/api/firewall/rule":
                    r = (fw.add_rule(b.get("net", ""), b.get("action", "deny"))
                         if b.get("op") != "remove"
                         else fw.remove_rule(b.get("net", "")))
                elif path == "/api/firewall/resolve":
                    # ゾーン policy が "prompt" の未知接続(保留)を承認(allow)/拒否(deny)する。
                    # これが無いと prompt は deny と等価な行き止まりになる(#2)。
                    # remember 未指定は既定 False=この接続だけの一時許可/拒否(#D6/#111: 「承認」
                    # 1クリックで恒久 allow ルールが黙って acl.json に積まれるのを避ける。恒久化は
                    # 明示チェックボックス経由)。Full 版へ移植済みの挙動を Lite にも反映。
                    remember = bool(b.get("remember"))
                    r = (fw.approve(b.get("id", ""), remember=remember)
                         if b.get("approve")
                         else fw.deny_pending(b.get("id", ""), remember=remember))
                elif path == "/api/shield/toggle":
                    r = sh.enable() if b.get("on") else sh.disable()
                elif path == "/api/shield/config":
                    r = sh.set_config(**{k: v for k, v in b.items()})
                elif path == "/api/shield/optional_sig":
                    r = sh.set_optional_signature(b.get("name", ""), bool(b.get("on")))
                elif path == "/api/shield/paranoia":
                    r = sh.set_paranoia(b.get("level", 1))
                elif path == "/api/shield/path_limits":
                    r = sh.set_path_limits(b.get("rules"))
                elif path == "/api/shield/blocked_methods":
                    r = sh.set_blocked_methods(b.get("methods"))
                elif path == "/api/shield/sig_add":
                    r = sh.add_signature(b.get("name", ""), b.get("pattern", ""),
                                         weight=float(b.get("weight", 40)))
                elif path == "/api/shield/sig_remove":
                    r = sh.remove_signature(b.get("name", ""))
                elif path == "/api/shield/unban":
                    r = sh.unban(b.get("ip", ""))
                elif path == "/api/shield/ban":
                    r = sh.ban(b.get("ip", ""))
                elif path == "/api/appeal/resolve":
                    r = sh.resolve_appeal(b.get("ip", ""), bool(b.get("approve")),
                                          b.get("note", ""))
                elif path == "/api/global_block":
                    fw.enable()
                    r = fw.set_policy("public", "deny" if b.get("on") else "allow")
                elif path == "/api/shield/sig_test":
                    # カスタムシグネチャの試験(状態は一切変更しない・読み取り専用)。まず既存の
                    # validate_pattern(ReDoS/安全性検査)へ通し、危険なパターンは
                    # コンパイル/マッチすら試みない(危険パターンを試験名目で実行させない)。
                    pattern, sample = b.get("pattern", ""), str(b.get("sample", ""))[:4096]
                    err = sh.validate_pattern(pattern)
                    if err:
                        r = {"ok": True, "matches": False, "error": err}
                    else:
                        try:
                            r = {"ok": True, "matches": bool(re.search(pattern, sample)), "error": None}
                        except re.error as e:
                            r = {"ok": True, "matches": False, "error": str(e)}
                else:
                    self._send(404, _j({"ok": False, "error": "not found"}))
                    return
                self._send(200, _j(r))
                # set_paranoia() は paranoia_status() をそのまま返すため "ok" キーを持たない
                # (エラー系は明示的に "ok": False を返す) — 単純に r.get("ok") だけで判定すると
                # paranoia 変更が監査ログに一切残らない。「"ok" が明示的に False でなければ成功」
                # として扱う(sig_test は _audit_entry が None を返すため二重に安全)。
                if isinstance(r, dict) and r.get("ok", True) is not False:
                    app.record_audit(path, b, r, pre_cfg, pre_fw)
            except Exception as e:
                self._send(200, _j({"ok": False, "error": str(e)}))
    return H


_HTML = r"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__BRAND__</title><style>
:root{
 /* タイポグラフィ(型スケール) */
 --f-sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Hiragino Kaku Gothic ProN","Noto Sans JP",Meiryo,sans-serif;
 --f-mono:ui-monospace,"SF Mono","Cascadia Code","JetBrains Mono",Consolas,monospace;
 --fs-2xl:30px;--fs-xl:19px;--fs-lg:15px;--fs-md:13px;--fs-sm:12px;--fs-xs:10.5px;
 --lh:1.5;--tracking:.04em;
 /* 余白・角丸 */
 --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:22px;--s6:32px;--r:14px;--r2:9px;
 /* ダークテーマ(既定) */
 --bg:#0a0d13;--panel:#10141d;--panel2:#161b27;--line:#222b3b;--line2:#1a2130;
 --fg:#e7edf6;--dim:#98a6bb;--faint:#5f6c80;
 --brand:#ff5d4d;--blue:#56a6ff;--green:#41d27f;--amber:#f4b740;--red:#ff5b5b;--purple:#b78cff;
 --accentbg:rgba(86,166,255,.12);
 --shadow:0 1px 0 rgba(255,255,255,.03) inset,0 10px 30px -16px rgba(0,0,0,.7);
}
html[data-theme="light"]{
 --bg:#eef1f7;--panel:#ffffff;--panel2:#f5f7fc;--line:#e0e6f0;--line2:#eef1f7;
 --fg:#141b27;--dim:#566175;--faint:#8a97a9;
 --brand:#e8443a;--blue:#2f74d8;--green:#1f9d54;--amber:#c98209;--red:#d83a3a;--purple:#7c4dd0;
 --accentbg:rgba(47,116,216,.10);
 --shadow:0 1px 2px rgba(16,24,40,.05),0 14px 32px -18px rgba(16,24,40,.22);
}
*{box-sizing:border-box}
html,body{margin:0}
body{font-family:var(--f-sans);font-size:var(--fs-md);line-height:var(--lh);
 background:radial-gradient(1200px 600px at 80% -10%,var(--accentbg),transparent 60%),var(--bg);
 color:var(--fg);-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
a{color:var(--blue)}
.num{font-family:var(--f-mono);font-variant-numeric:tabular-nums}
/* アプリバー */
.bar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:var(--s4);
 padding:12px clamp(14px,3vw,28px);background:color-mix(in srgb,var(--panel) 86%,transparent);
 backdrop-filter:saturate(160%) blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-size:var(--fs-xl);font-weight:700;letter-spacing:-.01em}
.brand .logo{font-size:22px;filter:drop-shadow(0 2px 6px rgba(255,93,77,.5))}
.brand small{display:block;font-size:var(--fs-xs);font-weight:500;color:var(--dim);letter-spacing:var(--tracking);text-transform:uppercase}
.spacer{flex:1}
.pill{display:inline-flex;align-items:center;gap:7px;font-size:var(--fs-sm);font-weight:600;
 padding:5px 11px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--dim)}
.pill .dot{width:8px;height:8px;border-radius:50%;background:var(--faint)}
.pill.ok{color:var(--green);border-color:color-mix(in srgb,var(--green) 40%,var(--line))}
.pill.ok .dot{background:var(--green);box-shadow:0 0 0 0 var(--green);animation:pulse 2s infinite}
.pill.bad{color:var(--red)}.pill.bad .dot{background:var(--red)}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 70%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
.iconbtn{font-size:16px;line-height:1;min-width:36px;height:36px;padding:0 8px;border-radius:var(--r2);
 cursor:pointer;background:var(--panel2);border:1px solid var(--line);color:var(--fg);display:inline-flex;
 align-items:center;justify-content:center;white-space:nowrap}
.iconbtn:hover{border-color:var(--blue)}
.wrap{max-width:1280px;margin:0 auto;padding:clamp(14px,2.5vw,26px)}
/* 操作行 */
.controls{display:flex;flex-wrap:wrap;gap:var(--s3);align-items:center;margin-bottom:var(--s5)}
.sw{display:inline-flex;align-items:center;gap:10px;font-size:var(--fs-md);font-weight:600;
 padding:9px 14px;border-radius:var(--r2);background:var(--panel);border:1px solid var(--line);cursor:pointer}
.toggle{appearance:none;width:42px;height:23px;border-radius:999px;background:var(--line);position:relative;cursor:pointer;transition:background .18s;flex:none}
.toggle::after{content:"";position:absolute;top:2px;left:2px;width:19px;height:19px;border-radius:50%;background:#fff;transition:.18s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.toggle:checked{background:var(--green)}.toggle:checked.red{background:var(--brand)}
.toggle:checked::after{left:21px}
.toggle:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
/* KPI */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:var(--s3);margin-bottom:var(--s5)}
.kpi{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
 padding:14px 16px;box-shadow:var(--shadow);overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--blue)}
.kpi.i-green::before{background:var(--green)}.kpi.i-amber::before{background:var(--amber)}
.kpi.i-red::before{background:var(--brand)}.kpi.i-blue::before{background:var(--blue)}
.kpi .kn{font-family:var(--f-mono);font-size:var(--fs-2xl);font-weight:700;letter-spacing:-.02em;line-height:1.1}
.kpi .kl{font-size:var(--fs-xs);color:var(--faint);text-transform:uppercase;letter-spacing:var(--tracking);margin-top:4px}
/* グリッド/パネル */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:var(--s4)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);
 display:flex;flex-direction:column;min-width:0;transition:border-color .15s}
.panel:hover{border-color:color-mix(in srgb,var(--blue) 30%,var(--line))}
.panel.wide{grid-column:1/-1}
.sect{grid-column:1/-1;display:flex;align-items:center;gap:10px;margin:14px 0 -4px;
 font-size:var(--fs-xs);font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:var(--tracking)}
.sect:first-child{margin-top:0}
.sect .ic{font-size:13px;filter:saturate(140%)}
.sect::after{content:"";flex:1;height:1px;background:var(--line2)}
.sbar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:var(--fs-sm)}
.sbl{width:118px;flex:0 0 118px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sbt{flex:1;height:8px;background:var(--panel2);border-radius:6px;overflow:hidden}
.sbf{display:block;height:100%;background:linear-gradient(90deg,var(--amber),var(--red));border-radius:6px;transition:width .3s}
.sbn{width:46px;text-align:right;color:var(--faint)}
.phead{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--line2)}
.phead h2{margin:0;font-size:var(--fs-sm);font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:var(--tracking)}
.phead .meta{margin-left:auto;font-size:var(--fs-xs);color:var(--faint)}
.pbody{padding:14px 16px;min-width:0}
.pbody.tight{padding:8px}
/* ボタン/入力 */
button{font-family:inherit;font-size:var(--fs-sm);font-weight:600;border:1px solid transparent;border-radius:8px;
 padding:7px 13px;cursor:pointer;background:var(--green);color:#fff;transition:.12s}
button:hover{filter:brightness(1.08)}button:active{transform:translateY(1px)}
button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
button.red{background:var(--brand)}
button.ghost{background:var(--panel2);color:var(--fg);border-color:var(--line)}
input,select{font-family:inherit;font-size:var(--fs-sm);background:var(--bg);color:var(--fg);
 border:1px solid var(--line);border-radius:8px;padding:8px 10px;min-width:0}
input:focus,select:focus{outline:2px solid var(--blue);outline-offset:-1px;border-color:var(--blue)}
input::placeholder{color:var(--faint)}
.row{display:flex;gap:var(--s2);flex-wrap:wrap;align-items:center;margin-top:var(--s3)}
.row input{flex:1}
/* テーブル */
table{width:100%;border-collapse:collapse;font-size:var(--fs-sm)}
th,td{padding:8px 6px;text-align:left;border-bottom:1px solid var(--line2)}
th{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:var(--tracking);color:var(--faint);font-weight:600}
tbody tr:hover{background:var(--panel2)}
td .num{font-size:var(--fs-sm)}
/* バッジ/タグ */
.badge{display:inline-block;font-size:var(--fs-xs);font-weight:700;padding:2px 8px;border-radius:999px;
 text-transform:uppercase;letter-spacing:.03em;border:1px solid transparent}
.badge.danger{color:var(--red);background:color-mix(in srgb,var(--red) 16%,transparent);border-color:color-mix(in srgb,var(--red) 35%,transparent)}
.badge.warn{color:var(--amber);background:color-mix(in srgb,var(--amber) 16%,transparent);border-color:color-mix(in srgb,var(--amber) 35%,transparent)}
.badge.info{color:var(--purple);background:color-mix(in srgb,var(--purple) 16%,transparent);border-color:color-mix(in srgb,var(--purple) 35%,transparent)}
.badge.muted{color:var(--dim);background:var(--panel2);border-color:var(--line)}
/* 行リスト(検知/イベント) */
.feed{max-height:280px;overflow:auto;margin:0;display:flex;flex-direction:column}
.frow{display:flex;align-items:center;gap:10px;padding:7px 4px;border-bottom:1px solid var(--line2);font-size:var(--fs-sm)}
.frow:last-child{border-bottom:0}
.frow .time{font-family:var(--f-mono);font-size:var(--fs-xs);color:var(--faint);flex:none;width:64px}
.frow .desc{color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
.frow .cnt{font-family:var(--f-mono);font-size:var(--fs-xs);color:var(--dim);flex:none}
.code{font-family:var(--f-mono);font-size:var(--fs-xs);line-height:1.55;white-space:pre;overflow:auto;
 max-height:240px;margin:0;color:var(--dim)}
.empty{color:var(--faint);font-size:var(--fs-sm);padding:14px 2px;text-align:center}
.note{color:var(--faint);font-size:var(--fs-xs);margin-top:10px}
canvas,svg{display:block;width:100%}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:var(--line);border-radius:9px}
/* トースト通知 */
.toastwrap{position:fixed;right:16px;bottom:16px;z-index:300;display:flex;flex-direction:column-reverse;
 gap:8px;max-width:min(360px,calc(100vw - 32px));pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--r2);background:var(--panel);
 border:1px solid var(--line);box-shadow:var(--shadow);font-size:var(--fs-sm);color:var(--fg);
 opacity:0;transform:translateY(8px);transition:opacity .18s,transform .18s;pointer-events:auto}
.toast.show{opacity:1;transform:translateY(0)}
.toast.ok{border-color:color-mix(in srgb,var(--green) 45%,var(--line))}
.toast.ok::before{content:"✓";color:var(--green);font-weight:700}
.toast.err{border-color:color-mix(in srgb,var(--red) 45%,var(--line))}
.toast.err::before{content:"✕";color:var(--red);font-weight:700}
.toast.info::before{content:"ℹ";color:var(--blue);font-weight:700}
.toast .ttext{flex:1;min-width:0;overflow-wrap:anywhere}
.toast .tclose{background:transparent;border:0;color:var(--faint);padding:0 2px;font-size:14px;
 line-height:1;cursor:pointer}
.toast .tclose:hover{color:var(--fg)}
/* 確認ダイアログ */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;
 justify-content:center;z-index:250;padding:16px}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);
 padding:20px;max-width:420px;width:100%}
.modal.wide{max-width:640px}
.modal-msg{font-size:var(--fs-md);color:var(--fg);margin-bottom:16px;line-height:1.5;white-space:pre-line}
.modal-body{max-height:min(60vh,520px);overflow-y:auto;margin-bottom:16px;font-size:var(--fs-sm)}
.modal-body h3{margin:16px 0 8px;font-size:var(--fs-md)}
.modal-body h3:first-child{margin-top:0}
.modal-body ol,.modal-body ul{margin:0 0 4px;padding-left:20px;line-height:1.7}
.modal-body p{margin:0 0 4px;color:var(--dim)}
.modal-body .upsell{margin-top:16px;padding:12px 14px;border-radius:var(--r2);
 background:color-mix(in srgb,var(--amber) 10%,transparent);
 border:1px solid color-mix(in srgb,var(--amber) 30%,var(--line))}
.modal-body .upsell h3{margin-top:0}
.modal-body .upsell ul{margin-bottom:0}
.modal-body .upsell li{margin-bottom:6px}
.modal-body .upsell li b{color:var(--fg)}
.modal-actions{display:flex;justify-content:flex-end;gap:8px}
/* 初回ロードのスケルトン: 『本当にゼロ』ではなく『まだ届いていない』と分かるように */
.skel-bar{display:inline-block;height:.85em;min-width:24px;border-radius:4px;vertical-align:middle;
 background:linear-gradient(90deg,var(--panel2) 25%,var(--line2) 37%,var(--panel2) 63%);
 background-size:400% 100%;animation:skel 1.4s ease-in-out infinite}
@keyframes skel{0%{background-position:100% 50%}100%{background-position:0 50%}}
.kpi.skel .kn{margin-bottom:2px}
/* ボタンのビジー状態: 二重送信防止 + 進行中フィードバック */
button.busy{color:transparent!important;pointer-events:none;position:relative}
button.busy::after{content:"";position:absolute;left:50%;top:50%;width:13px;height:13px;
 margin:-6.5px 0 0 -6.5px;border-radius:50%;border:2px solid rgba(255,255,255,.55);
 border-top-color:#fff;animation:spin .6s linear infinite}
button.ghost.busy::after,button.red.busy::after{border-color:var(--line);border-top-color:var(--fg)}
@keyframes spin{to{transform:rotate(360deg)}}
/* チャート時間範囲ズーム */
.chartzoom{display:inline-flex;gap:4px;margin-left:10px}
.chartzoom button{padding:3px 9px;font-size:var(--fs-xs)}
.chartzoom button.active{background:var(--blue);color:#fff;border-color:var(--blue)}
/* テーブル検索/ソート */
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--fg)}
th.sortable .sortarrow{display:inline-block;width:9px;font-size:9px;color:var(--blue)}
.searchrow{margin-top:0}
.searchrow input{flex:1;min-width:120px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:560px){.brand small{display:none}.wrap{padding:14px}}
</style></head><body>
<div class="toastwrap" id="toastwrap"></div>
<div class="modal-overlay" id="confirmOverlay" style="display:none">
  <div class="modal">
    <div class="modal-msg" id="confirmMsg"></div>
    <div class="modal-actions">
      <button class="ghost" id="confirmCancel">キャンセル</button>
      <button class="red" id="confirmOk">実行</button>
    </div>
  </div>
</div>
<div class="modal-overlay" id="helpOverlay" style="display:none">
  <div class="modal wide">
    <h2 style="margin:0 0 12px">__BRAND__</h2>
    <div class="modal-body" id="helpBody">
      <h3>使い方</h3>
      <pre class="code" style="margin:0 0 10px">python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081</pre>
      <ol>
        <li>起動すると --listen 宛の通信を検査し、問題なければ --backend(あなたのWebサーバ)へ転送します。</li>
        <li>本ダッシュボードは --admin ポートで待受け、起動時にコンソールへ表示されるトークンで認証します。</li>
        <li>上部の「ファイアウォール」「DDoS / 侵入防御」トグルで防御レイヤーをON/OFFできます。</li>
        <li>「攻撃イベント」「BAN中のIP」でリアルタイム監視。手動でのBAN/解除も可能です。</li>
        <li>「WAF / 検知設定」パネルでしきい値・機能ごとのON/OFFを調整できます(保存は即時反映)。</li>
      </ol>
      <h3>できること(Lite版)</h3>
      <ul>
        <li>WAF: SQLi・XSS・RCE・パストラバーサル・XXE・SSRF・JNDI・スキャナー等のシグネチャ照合、カスタムシグネチャ追加</li>
        <li>L7 DDoS防御: レート制限・脅威スコアリング・自動BAN(拒否スコア/BANスコアの2段階)</li>
        <li>双方向の検査: リクエストボディ(POST/JSON/GraphQL・gzip解凍を含む)+ 応答のDLP・セキュリティヘッダ付与</li>
        <li>認証・濫用対策: JWT検査・クレデンシャル単位のレート制限</li>
        <li>状態の整合性: BAN/設定のHMAC署名による改竄耐性</li>
      </ul>
      <p>より詳しい説明は README.md および docs/ 配下のドキュメントを参照してください。</p>
      <div class="upsell">
        <h3>フル版でできること</h3>
        <p>Lite は WAF / DDoS 対策の中核機能を無償で提供します。次のような領域は上位版(フル版)で加わります。</p>
        <ul>
          <li><b>可用性:</b> ファイルの改竄を自己完全性監視で検知・自動修復し、プロセスが落ちても watchdog が自動再起動します。無人運用でも稼働を維持できます。</li>
          <li><b>ボットとの選別:</b> 動的PoWチャレンジで、正規ユーザーを通しながら自動化された攻撃だけを絞り込みます(Liteは拒否/BANの二値判定のみ)。GeoIP・許可リスト(allowlist)・ステルス運用によるアクセス制御も加わります。</li>
          <li><b>侵入後の検知:</b> LDAP/SMB/Kerberosデコイ、囮ファイル、カナリアトークン、ハニーポットで、境界を突破された後の不審な動きも捕捉します。DNSフィルタはC2通信やトンネリングを見つけます。</li>
          <li><b>運用への統合:</b> 検知結果をSIEMやSlackへリアルタイム転送(Webhook/Syslog)。脅威インテリジェンス(IoC)照合とMITRE ATT&CK対応のルールで、既知の攻撃手口を継続的にカバーします。</li>
          <li><b>複数拠点・大規模環境:</b> LDAP 列挙検知プロキシと、ノード間でBAN情報を同期する分散ゴシップにより、組織全体で一貫した防御になります(商用ライセンス管理つき)。</li>
        </ul>
      </div>
    </div>
    <div class="modal-actions"><button class="ghost" id="helpClose">閉じる</button></div>
  </div>
</div>
<div class="bar">
  <div class="brand"><span class="logo">__LOGO__</span><div>__BRAND__<small>__SUBTITLE__</small></div></div>
  <div class="spacer"></div>
  <span class="pill" id="conn"><span class="dot"></span><span id="connt">接続中</span></span>
  <button class="iconbtn" id="help" title="使い方 / できること" aria-label="ヘルプ">❓</button>
  <button class="iconbtn" id="lang" title="Language / 言語" aria-label="Language">EN</button>
  <button class="iconbtn" id="theme" title="テーマ切替" aria-label="テーマ切替">☀️</button>
</div>
<div class="wrap">
  <div class="controls">
    <label class="sw"><input type="checkbox" id="fw" class="toggle"> ファイアウォール</label>
    <label class="sw"><input type="checkbox" id="sh" class="toggle"> DDoS / 侵入防御</label>
    <div class="spacer"></div>
    <button class="red" onclick="globalBlock(true,this)">🌍 グローバル遮断</button>
    <button class="ghost" onclick="globalBlock(false,this)">解除</button>
  </div>
  <div class="kpis" id="cards"></div>
  <div class="grid">
    <div class="sect"><span class="ic">📈</span>概況</div>
    <section class="panel wide">
      <div class="phead"><h2>リアルタイム通信</h2><span class="meta" id="chartleg">req/s · block/s</span>
        <div class="chartzoom" id="chartzoom">
          <button class="ghost" data-sec="300" onclick="setChartWindow(300)">5m</button>
          <button class="ghost" data-sec="1800" onclick="setChartWindow(1800)">30m</button>
          <button class="ghost active" data-sec="all" onclick="setChartWindow(Infinity)">全期間</button>
        </div></div>
      <div class="pbody"><canvas id="chart" height="180" style="height:180px"></canvas></div>
    </section>
    <section class="panel wide">
      <div class="phead"><h2>ネットワーク図</h2><span class="meta">中心=本機 / 内→外=loopback·private·public / ノードclickで遮断·解除</span></div>
      <div class="pbody"><svg id="netmap" height="300" viewBox="0 0 1040 300" preserveAspectRatio="xMidYMid meet" style="height:300px"></svg></div>
    </section>

    <div class="sect"><span class="ic">🛡</span>脅威モニタリング</div>
    <section class="panel">
      <div class="phead"><h2>攻撃イベント</h2><span class="meta" id="eventsmeta">—</span></div>
      <div class="pbody tight">
        <div class="row searchrow" style="margin:8px 8px 0"><input id="eventsearch" placeholder="IP/種別で絞り込み" oninput="renderEvents()">
        <button class="ghost" onclick="exportData('events','csv')">CSV</button>
        <button class="ghost" onclick="exportData('events','json')">JSON</button></div>
        <div class="feed" id="events"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>BAN中のIP</h2><span class="meta" id="bansmeta">—</span></div>
      <div class="pbody">
        <div class="row searchrow"><input id="bansearch" placeholder="IPで絞り込み" oninput="renderBans()">
        <button class="ghost" onclick="exportData('bans','csv')">CSV</button>
        <button class="ghost" onclick="exportData('bans','json')">JSON</button></div>
        <table id="bans"><thead><tr>
          <th style="width:22px"><input type="checkbox" id="banall" onchange="toggleAllBans(this.checked)" title="表示中の全行を選択"></th>
          <th>IP</th><th class="sortable" data-sort="remain">残り時間<span class="sortarrow"></span></th>
          <th class="sortable" data-sort="score">スコア<span class="sortarrow"></span></th><th></th>
        </tr></thead><tbody></tbody></table>
        <div class="row"><button class="ghost" onclick="unbanSelected(this)">選択解除</button>
        <button class="red ghost" onclick="unbanAll(this)">全解除</button></div>
        <div class="row"><input id="banip" placeholder="手動BANするIP">
        <button class="red" onclick="ban(this)">BAN</button></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>上位送信元(脅威スコア順)</h2></div>
      <div class="pbody"><pre class="code" id="top"></pre></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>APT級の兆候</h2><span class="meta">低速持続 · 規則的ビーコン · 累積</span></div>
      <div class="pbody"><pre class="code" id="apt"></pre></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>シグネチャ別ヒット</h2><span class="meta" id="sigmetatop">—</span></div>
      <div class="pbody">
        <svg id="sigtrend" height="30" viewBox="0 0 300 30" preserveAspectRatio="none" style="width:100%;height:30px;margin:0 0 8px"></svg>
        <div id="sigbars"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>トラフィック構成(ゾーン / アクション)</h2><span class="meta">外部(public)推移 · 内訳</span></div>
      <div class="pbody">
        <svg id="pubtrend" height="30" viewBox="0 0 300 30" preserveAspectRatio="none" style="width:100%;height:30px;margin:0 0 8px"></svg>
        <div class="meta" style="margin:2px 0 4px">ゾーン別</div><div id="zonebars"></div>
        <div class="meta" style="margin:8px 0 4px">アクション別</div><div id="actbars"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>HTTPメソッド別</h2></div>
      <div class="pbody">
        <div id="methbars"></div>
      </div>
    </section>

    <div class="sect"><span class="ic">⚙️</span>WAF / 検知設定</div>
    <section class="panel">
      <div class="phead"><h2>WAF 追加シグネチャ(任意・高FP)</h2><span class="meta">既定OFF · 誤検知許容な環境のみ点灯</span></div>
      <div class="pbody tight"><div id="optsigs"></div></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>カスタムシグネチャ</h2><span class="meta" id="sigmeta">—</span></div>
      <div class="pbody">
        <div class="row" style="margin-top:0"><button class="ghost" onclick="exportData('sigs','csv')">CSV</button>
        <button class="ghost" onclick="exportData('sigs','json')">JSON</button></div>
        <table id="customsigs"><tbody></tbody></table>
        <div class="row"><input id="signame" placeholder="名前 例:my-rule">
        <input id="sigpat" placeholder="正規表現 例:evil-?bot"></div>
        <div class="row"><button onclick="addSig(this)">追加</button>
        <span class="meta" id="sigerr"></span></div>
        <div class="row"><input id="sigtestsample" placeholder="テスト対象の文字列(パス/UA/ヘッダ値など)" title="実際に追加する前に、このパターンがサンプル文字列にマッチするかを試せます(状態は変更されません)。">
        <button class="ghost" onclick="testSig(this)">テスト</button>
        <span class="meta" id="sigtestresult"></span></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>パス別レート制限</h2><span class="meta" id="prlmeta">—</span></div>
      <div class="pbody">
        <table id="pathlimits"><tbody></tbody></table>
        <div class="row"><input id="prpath" placeholder="パス前方一致 例:/login">
        <input id="prrate" type="number" step="0.1" placeholder="毎秒 例:0.5" style="max-width:130px">
        <input id="prburst" type="number" step="1" placeholder="バースト 例:5" style="max-width:130px"></div>
        <div class="row"><button onclick="addPathLimit(this)">追加</button>
        <span class="meta" id="prerr"></span></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>レート/メソッド/分散(運用)</h2><span class="meta" id="opsstat">—</span></div>
      <div class="pbody tight">
        <div class="row"><label class="sw"><input type="checkbox" id="throttle" class="toggle"> レート超過に429応答</label>
          <input id="retryaft" type="number" step="1" min="0" placeholder="Retry-After 秒" style="max-width:150px"></div>
        <div class="row"><label class="sw"><input type="checkbox" id="subnetdef" class="toggle"> サブネット集約防御</label>
          <input id="subthr" type="number" step="1" min="1" placeholder="しきい値(別IP数)" style="max-width:170px"
          title="同一サブネット(IPv4は/24・IPv6は/64)内でこの数の別IPがBANされると分散攻撃(ボットネット等)とみなし、そのサブネットの新規IPに事前スコアを加点します(即BANはしません・共有NAT巻き添え回避のため既定OFF)。"></div>
        <div class="row"><span class="meta" id="subnetmeta">—</span></div>
        <div class="row"><input id="blockmeth" placeholder="遮断メソッド(カンマ区切) 例:TRACE,TRACK,CONNECT">
          <button onclick="saveBlockedMethods(this)">適用</button>
          <span class="meta" id="methoderr"></span></div>
        <div class="row"><input id="maxconnip" type="number" step="1" min="0" placeholder="上限接続数/IP(0=無制限)" style="max-width:180px"
          title="1つのIPが同時に保持できる接続数の上限。0=無制限。超過分は即切断し、接続保持型のflood(スロットループ等)を防ぎます。">
          <input id="connrateip" type="number" step="1" min="0" placeholder="新規接続/秒/IP(0=無制限)" style="max-width:190px"
          title="1つのIPからの新規接続を1秒あたりこの数までに制限。0=無制限。接続→即RST/即切断を高速反復するRSTフラッド/churnフラッドを、リクエスト解析より手前の安価な段階で遮断します。">
          <input id="maxtotalconn" type="number" step="1" min="0" placeholder="全体同時接続上限(0=無制限)" style="max-width:200px"
          title="サーバ全体の同時接続数の上限。0=無制限。超過分は即切断し、大量接続によるFD/メモリ枯渇でサーバごと落ちるのを防ぎます。"></div>
        <div class="row"><label class="sw" title="転送するリクエストのConnectionをcloseへ書き換え、1接続=1リクエストに強制します。OFFにするとkeep-alive越しの2本目以降のリクエストが検査されずに素通りする恐れがあります(検査回避対策・既定ON推奨)。"><input type="checkbox" id="forceclose" class="toggle"> keep-alive を強制切断</label></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>出口DLP(秘密漏洩)</h2><span class="meta" id="dlpstat">—</span></div>
      <div class="pbody tight">
        <div class="row">
          <label class="sw"><input type="checkbox" id="dlp" class="toggle"> 秘密漏洩検知</label>
          <select id="dlpact" title="応答本文にAPIキー等の秘密が含まれていた場合の挙動。監査=記録のみで送出は止めません。遮断=漏洩を検知した応答を送出せず遮断します。" style="background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--r2);padding:6px 9px;font:inherit">
            <option value="audit">監査(記録のみ)</option>
            <option value="block">遮断(漏洩を送出しない)</option>
          </select>
        </div>
        <svg id="leaktrend" height="30" viewBox="0 0 300 30" preserveAspectRatio="none" style="width:100%;height:30px;margin:6px 0"></svg>
        <div id="leakkinds" style="margin-bottom:6px"></div>
        <div class="feed" id="leaks"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>詳細防御(評価)</h2><span class="meta" id="advstat">—</span></div>
      <div class="pbody tight">
        <div class="row"><label class="sw"><input type="checkbox" id="sech" class="toggle"> 応答セキュリティヘッダ</label></div>
        <div class="row"><span class="meta">検知の厳格度(paranoia)</span>
          <select id="paranoia" title="検知の段階的な厳格度。レベルを上げるほど誤検知が起きやすい任意シグネチャを段階的に有効化します(2:オープンリダイレクト → 3:+内部SSRF → 4:+テンプレート注入)。既定は1(常時ONの低誤検知ルールのみ)。" style="background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--r2);padding:6px 9px;font:inherit">
            <option value="1">1 · 保守(誤検知最小)</option>
            <option value="2">2 · やや積極</option>
            <option value="3">3 · 積極</option>
            <option value="4">4 · 最大(高FP許容)</option>
          </select></div>
        <div class="row"><span class="meta" id="tamperstat">—</span></div>
      </div>
    </section>

    <div class="sect"><span class="ic">🚦</span>アクセス制御・申立</div>
    <section class="panel">
      <div class="phead"><h2>アクセスルール</h2></div>
      <div class="pbody">
        <div class="row"><input id="ruleip" placeholder="IP/CIDR 例:203.0.113.0/24">
        <button onclick="rule('allow',this)">許可</button>
        <button class="red" onclick="rule('deny',this)">拒否</button>
        <button class="ghost" onclick="edge()">エッジ前衛設定DL</button></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>解除リクエスト(異議申立)</h2></div>
      <div class="pbody"><table id="appeals"><tbody></tbody></table></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>承認待ち接続(ファイアウォール)</h2><span class="meta" id="pendingmeta">—</span></div>
      <div class="pbody">
        <div class="row" style="margin-top:0"><button onclick="approveAllPending(this)">すべて承認</button>
        <button class="red ghost" onclick="denyAllPending(this)">すべて拒否</button></div>
        <table id="fwpending"><tbody></tbody></table>
      </div>
    </section>

    <div class="sect"><span class="ic">🌐</span>欺瞞</div>
    <section class="panel">
      <div class="phead"><h2>デセプション(MTD)</h2><span class="meta" id="decepstat">—</span></div>
      <div class="pbody"><pre class="code" id="deception"></pre></div>
    </section>

    <div class="sect"><span class="ic">🔬</span>詳細分析</div>
    <section class="panel wide">
      <div class="phead"><h2>詳細分析</h2></div>
      <div class="pbody"><pre class="code" id="analysis"></pre></div>
    </section>
    <section class="panel wide">
      <div class="phead"><h2>変更履歴(監査ログ)</h2><span class="meta" id="auditmeta">—</span></div>
      <div class="pbody tight"><div class="feed" id="auditlog"></div></div>
    </section>
  </div>
</div>
<script>
// 認証は HttpOnly Cookie(同一オリジンの fetch が自動送信)。トークンは JS に持たない。
const H={"Content-Type":"application/json"};
const $=id=>document.getElementById(id);
const cssv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const esc=s=>(s==null?"":String(s)).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const tm=ts=>new Date((ts||0)*1000).toLocaleTimeString();
const nf=n=>(n||0).toLocaleString();
function sev(s){s=(s||"").toLowerCase();
 if(["malicious","block","blocked","deny"].includes(s))return"danger";
 if(["suspicious","alert","throttle"].includes(s))return"warn";
 if(["recon","info"].includes(s))return"info";return"muted";}
/* 言語(i18n): 既定は日本語=サーバHTMLそのまま。EN はクライアントで適用。 */
const JA2EN={
 "使い方":"Usage","できること(Lite版)":"What it can do (Lite)","フル版でできること":"What the full edition adds",
 "閉じる":"Close",
 "起動すると --listen 宛の通信を検査し、問題なければ --backend(あなたのWebサーバ)へ転送します。":
  "Once started, traffic to --listen is inspected and, if clean, forwarded to --backend (your web server).",
 "本ダッシュボードは --admin ポートで待受け、起動時にコンソールへ表示されるトークンで認証します。":
  "This dashboard listens on --admin and authenticates with the token printed to the console at startup.",
 "上部の「ファイアウォール」「DDoS / 侵入防御」トグルで防御レイヤーをON/OFFできます。":
  "Use the \"Firewall\" / \"DDoS / Intrusion\" toggles above to turn each defense layer on/off.",
 "「攻撃イベント」「BAN中のIP」でリアルタイム監視。手動でのBAN/解除も可能です。":
  "Monitor live via \"Attack events\" / \"Banned IPs\"; manual ban/unban is also available.",
 "「WAF / 検知設定」パネルでしきい値・機能ごとのON/OFFを調整できます(保存は即時反映)。":
  "Tune thresholds and per-feature on/off in the \"WAF / detection\" panel (changes apply immediately).",
 "WAF: SQLi・XSS・RCE・パストラバーサル・XXE・SSRF・JNDI・スキャナー等のシグネチャ照合、カスタムシグネチャ追加":
  "WAF: signature matching for SQLi, XSS, RCE, path traversal, XXE, SSRF, JNDI, scanners, etc., plus custom signatures",
 "L7 DDoS防御: レート制限・脅威スコアリング・自動BAN(拒否スコア/BANスコアの2段階)":
  "L7 DDoS defense: rate limiting, threat scoring, auto-ban (2-tier: deny score / ban score)",
 "双方向の検査: リクエストボディ(POST/JSON/GraphQL・gzip解凍を含む)+ 応答のDLP・セキュリティヘッダ付与":
  "Bidirectional inspection: request body (POST/JSON/GraphQL, incl. gzip decompression) + response DLP and security headers",
 "認証・濫用対策: JWT検査・クレデンシャル単位のレート制限":
  "Auth & abuse controls: JWT inspection, per-credential rate limiting",
 "状態の整合性: BAN/設定のHMAC署名による改竄耐性":
  "State integrity: HMAC-signed ban/config state resists tampering",
 "より詳しい説明は README.md および docs/ 配下のドキュメントを参照してください。":
  "See README.md and the docs under docs/ for more detail.",
 "Lite は WAF / DDoS 対策の中核機能を無償で提供します。次のような領域は上位版(フル版)で加わります。":
  "Lite provides the core WAF / DDoS defenses at no cost. The full edition adds the following.",
 "可用性:":"Availability:",
 "ファイルの改竄を自己完全性監視で検知・自動修復し、プロセスが落ちても watchdog が自動再起動します。無人運用でも稼働を維持できます。":
  "Self-integrity monitoring detects and repairs file tampering, and a watchdog restarts the process if it goes down — it keeps running with nobody watching.",
 "ボットとの選別:":"Telling bots from people:",
 "動的PoWチャレンジで、正規ユーザーを通しながら自動化された攻撃だけを絞り込みます(Liteは拒否/BANの二値判定のみ)。GeoIP・許可リスト(allowlist)・ステルス運用によるアクセス制御も加わります。":
  "A dynamic proof-of-work challenge lets real users through while filtering out automated traffic (Lite only makes a binary deny/ban call). GeoIP, an allowlist, and stealth operation round out access control.",
 "侵入後の検知:":"Detecting what happens after a breach:",
 "LDAP/SMB/Kerberosデコイ、囮ファイル、カナリアトークン、ハニーポットで、境界を突破された後の不審な動きも捕捉します。DNSフィルタはC2通信やトンネリングを見つけます。":
  "LDAP/SMB/Kerberos decoys, decoy files, canary tokens, and a honeypot catch suspicious activity once someone is already past the perimeter. A DNS filter picks up C2 traffic and tunneling.",
 "運用への統合:":"Fitting into existing operations:",
 "検知結果をSIEMやSlackへリアルタイム転送(Webhook/Syslog)。脅威インテリジェンス(IoC)照合とMITRE ATT&CK対応のルールで、既知の攻撃手口を継続的にカバーします。":
  "Detections forward to a SIEM or Slack in real time (Webhook/Syslog), and threat-intel (IoC) matching plus MITRE ATT&CK-mapped rules keep coverage current against known techniques.",
 "複数拠点・大規模環境:":"Multi-site and larger deployments:",
 "LDAP 列挙検知プロキシと、ノード間でBAN情報を同期する分散ゴシップにより、組織全体で一貫した防御になります(商用ライセンス管理つき)。":
  "An LDAP enumeration-detection proxy and gossip-based ban-state sync across nodes keep enforcement consistent across the whole organization (with commercial license management).",
 "ファイアウォール":"Firewall","DDoS / 侵入防御":"DDoS / Intrusion","🌍 グローバル遮断":"🌍 Global block",
 "解除":"Release","接続中":"Connected","接続不可":"Disconnected","認証エラー・再読込":"Auth error — reload",
 "概況":"Overview","脅威モニタリング":"Threat monitoring","WAF / 検知設定":"WAF / detection",
 "アクセス制御・申立":"Access control & appeals","欺瞞":"Deception","詳細分析":"Analysis",
 "リアルタイム通信":"Live traffic","ネットワーク図":"Network map",
 "攻撃イベント":"Attack events","BAN中のIP":"Banned IPs","上位送信元(脅威スコア順)":"Top sources (by score)",
 "APT級の兆候":"APT-grade indicators","シグネチャ別ヒット":"Hits by signature",
 "トラフィック構成(ゾーン / アクション)":"Traffic mix (zone / action)",
 "WAF 追加シグネチャ(任意・高FP)":"WAF optional signatures (high-FP)","カスタムシグネチャ":"Custom signatures",
 "出口DLP(秘密漏洩)":"Egress DLP (secret leak)","アクセスルール":"Access rules",
 "詳細防御(評価)":"Advanced defenses (eval)",
 "応答セキュリティヘッダ":"Response security headers",
 "検知の厳格度(paranoia)":"Detection strictness (paranoia)","ヘッダ":"headers",
 "1 · 保守(誤検知最小)":"1 · conservative (min FP)","2 · やや積極":"2 · moderate",
 "3 · 積極":"3 · aggressive","4 · 最大(高FP許容)":"4 · maximum (high FP ok)",
 "解除リクエスト(異議申立)":"Unban requests (appeals)",
 "承認待ち接続(ファイアウォール)":"Pending connections (firewall)","zone policy=prompt の未知接続":"Unknown connections under zone policy=prompt",
 "承認待ちなし":"No pending connections","常時許可として記憶":"Remember as always-allow",
 "デセプション(MTD)":"Deception (MTD)",
 "低速持続 · 規則的ビーコン · 累積":"Low-and-slow · beacon · cumulative",
 "外部(public)推移 · 内訳":"External (public) trend · breakdown","既定OFF · 誤検知許容な環境のみ点灯":"Off by default · enable where FPs OK",
 "中心=本機 / 内→外=loopback·private·public / ノードclickで遮断·解除":"Center=node / in→out=loopback·private·public / click to block·unblock",
 "ゾーン別":"By zone","アクション別":"By action","HTTPメソッド別":"By HTTP method",
 "許可":"Allow","拒否":"Deny","追加":"Add","エッジ前衛設定DL":"Download edge proxy config",
 "秘密漏洩検知":"Secret leak detection","監査(記録のみ)":"Audit (log only)","遮断(漏洩を送出しない)":"Block (withhold leak)",
 "手動BANするIP":"IP to ban manually","IP/CIDR 例:203.0.113.0/24":"IP/CIDR e.g. 203.0.113.0/24",
 "名前 例:my-rule":"Name e.g. my-rule",
 "正規表現 例:evil-?bot":"Regex e.g. evil-?bot",
 "パス別レート制限":"Per-path rate limits","パス前方一致 例:/login":"Path prefix e.g. /login",
 "毎秒 例:0.5":"Per sec e.g. 0.5","バースト 例:5":"Burst e.g. 5","ルール":"rules","ルールなし":"No rules",
 "パスと毎秒(>0)を入力":"Enter path and rate (>0)",
 "レート/メソッド/分散(運用)":"Rate / method / subnet (ops)","レート超過に429応答":"429 on rate-limit",
 "サブネット集約防御":"Subnet aggregation defense","適用":"Apply","分散":"subnet","メソッド":"methods",
 "追跡":"tracked","遮断メソッド":"Blocked methods","Retry-After 秒":"Retry-After sec",
 "しきい値(別IP数)":"threshold (distinct IPs)",
 "遮断メソッド(カンマ区切) 例:TRACE,TRACK,CONNECT":"Blocked methods (comma) e.g. TRACE,TRACK,CONNECT",
 "無視":"Ignored",
 "BAN なし":"No bans","(なし)":"(none)","イベントなし":"No events","なし":"none","ヒットなし":"No hits",
 "カスタムなし":"No custom signatures",
 "削除":"Remove","DLP 無効":"DLP off","漏洩なし":"No leaks",
 "申立なし":"No appeals","承認":"Approve","却下":"Reject","名前とパターンを入力":"Enter name and pattern",
 "SSTI(テンプレート注入 {{…}})":"SSTI (template injection {{…}})","内部SSRF(localhost/内部IP)":"Internal SSRF (localhost/internal IP)",
 "オープンリダイレクト(=//)":"Open redirect (=//)",
 "要求":"Requests","スロットル":"Throttle","ブロック":"Block","BAN中":"Banned","漏洩":"Leaks",
 "バックエンド不通":"Backend unreachable",
 "有効":"on","無効":"off","計":"total","種別":"types","系統":"families","前":"ago",
 "インターネット(public)を一括遮断します。よろしいですか?":"Block all public (internet) traffic. Are you sure?",
 "(DUCKNET_DECEPTION 未設定 = 偽装なし)":"(DUCKNET_DECEPTION unset = no deception)",
 "サンプル攻撃者":"Sample attacker","から見える偽装(隣接窓で必ず別系統):":"sees this deception (adjacent windows always differ):",
 "残":"remaining ","組込":"built-in","カスタム":"custom","危険除外":"unsafe-excluded",
 "(兆候なし)":"(no indicators)","本機":"This host","失敗":"failed",
 "改竄検知":"Tamper detection","直近":"Last",
 /* トースト/確認ダイアログ/汎用保存文言 */
 "キャンセル":"Cancel","実行":"Confirm","保存しました":"Saved",
 "ファイアウォールを更新しました":"Firewall updated","シールドを更新しました":"Shield updated",
 "DLP設定を保存しました":"DLP settings saved","設定を保存しました":"Settings saved",
 "検知の厳格度を変更しました":"Detection strictness changed",
 "このシグネチャを削除しますか?":"Delete this signature?","追加に失敗":"Add failed","削除に失敗":"Delete failed",
 "シグネチャを追加しました":"Signature added","シグネチャを削除しました":"Signature deleted",
 "このレート制限ルールを削除しますか?":"Delete this rate-limit rule?",
 "ルールを削除しました":"Rule deleted","レート制限を追加しました":"Rate limit added",
 "遮断メソッドを保存しました":"Blocked methods saved","保存に失敗":"Save failed",
 "この申立を却下しますか?":"Reject this appeal?","申立を承認しました":"Appeal approved",
 "申立を却下しました":"Appeal rejected","処理に失敗":"Action failed",
 "この接続を拒否しますか?":"Deny this connection?","接続を承認しました":"Connection approved",
 "接続を拒否しました":"Connection denied","BANを解除しました":"IP unbanned","解除に失敗":"Unban failed",
 "このIPをBANしますか?":"Ban this IP?","IPをBANしました":"IP banned","BANに失敗":"Ban failed",
 "このIP/CIDRを拒否ルールに追加しますか?":"Add this IP/CIDR as a deny rule?","ルールを追加しました":"Rule added",
 "拒否ルールを追加しました":"Deny rule added","グローバル遮断を有効にしました":"Global block enabled",
 "グローバル遮断を解除しました":"Global block released",
 /* テーブル検索/ソート */
 "IPで絞り込み":"Filter by IP","IP/種別で絞り込み":"Filter by IP/kind","該当なし":"No matches",
 "残り時間":"Remaining","スコア":"Score",
 /* より実用的な空状態 */
 "カスタムシグネチャなし — 下のフォームから追加できます(組込シグネチャで拾えないパターン用)":
  "No custom signatures yet — add one below to catch patterns the built-in signatures don't cover",
 "承認待ちなし — ゾーンポリシーが「承認待ち」のゾーンで新規接続があるとここに表示されます":
  "No pending connections — new connections appear here when a zone's policy is \"prompt\"",
 "申立なし — BANされた利用者が異議申立を送るとここに表示されます":
  "No appeals yet — requests appear here when a banned user submits one",
 /* 変更履歴(監査ログ) */
 "変更履歴(監査ログ)":"Change history (audit log)","元に戻す":"Revert","変更履歴なし":"No changes yet",
 "元に戻しました":"Reverted","復元に失敗":"Revert failed",
 /* チャートのズーム */
 "全期間":"All",
 /* シグネチャの試験(ドライラン) */
 "テスト":"Test","テスト対象の文字列(パス/UA/ヘッダ値など)":"Sample to test (path/UA/header value…)",
 "パターンを入力":"Enter a pattern","エラー":"Error","無効なパターン":"Invalid pattern",
 "一致":"Match","不一致":"No match",
 /* エクスポート */
 "エクスポートしました":"Exported",
 /* 一括操作 */
 "選択なし":"Nothing selected","選択したIPを解除しました":"Unbanned selected IPs",
 "BAN中の全IPを解除します。よろしいですか?":"Unban all currently banned IPs. Are you sure?",
 "すべてのBANを解除しました":"Unbanned all IPs","選択解除":"Unban selected","全解除":"Unban all",
 "すべて承認":"Approve all","すべて拒否":"Deny all",
 "すべての承認待ち接続を承認します。よろしいですか?":"Approve all pending connections. Are you sure?",
 "すべて承認しました":"Approved all","すべて拒否しました":"Denied all",
 "上限接続数/IP(0=無制限)":"Max conns/IP (0=unlimited)","新規接続/秒/IP(0=無制限)":"New conns/sec/IP (0=unlimited)",
 "全体同時接続上限(0=無制限)":"Total conn limit (0=unlimited)","keep-alive を強制切断":"Force keep-alive close"};
let LANG="ja";try{LANG=localStorage.getItem("fn-lang")||"ja"}catch(e){}
function tr(s){if(LANG!=="en"||s==null)return s;const k=String(s).trim();return JA2EN[k]!==undefined?JA2EN[k]:s;}
function applyStatic(){
 document.documentElement.lang=LANG;
 document.querySelectorAll(".phead h2,.phead .meta:not([id]),.pbody .meta:not([id]),button:not(.iconbtn),#dlpact option,#paranoia option,#helpBody h3,#helpBody li,#helpBody p").forEach(el=>{
  if(el.children.length)return;
  if(el.dataset.o===undefined)el.dataset.o=el.textContent.trim();
  el.textContent=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 const labels=[...document.querySelectorAll(".controls label.sw")];
 ["dlp","sech","throttle","subnetdef","forceclose"].forEach(id=>{const e=$(id)&&$(id).closest("label");if(e)labels.push(e);});
 labels.forEach(el=>{const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=" "+(LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o);});
 // アップセル項目(<b>見出し:</b> 本文)。子要素を持つため上の汎用ループはスキップする=個別に訳す。
 document.querySelectorAll(".upsell li").forEach(el=>{
  const b=el.querySelector("b");if(!b)return;
  if(b.dataset.o===undefined)b.dataset.o=b.textContent.trim();
  b.textContent=LANG==="en"?(JA2EN[b.dataset.o]||b.dataset.o):b.dataset.o;
  const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=" "+(LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o);});
 document.querySelectorAll(".sect").forEach(el=>{const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 // ソート可能な列見出し(先頭テキストノード + 矢印用span)。.sect と対称(こちらは先頭側)。
 document.querySelectorAll("th.sortable").forEach(el=>{const tn=el.firstChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 document.querySelectorAll("input[placeholder]").forEach(el=>{
  if(el.dataset.o===undefined)el.dataset.o=el.placeholder;
  el.placeholder=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
}
function setLang(l){LANG=l;try{localStorage.setItem("fn-lang",l)}catch(e){}
 $("lang").textContent=l==="en"?"日本語":"EN";
 $("help").title=l==="en"?"Usage / capabilities":"使い方 / できること";
 $("help").setAttribute("aria-label",l==="en"?"Help":"ヘルプ");applyStatic();
 try{refresh()}catch(e){}try{refreshPro()}catch(e){}}
$("lang").onclick=()=>setLang(LANG==="en"?"ja":"en");
/* テーマ */
function setTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem("fn-theme",t)}catch(e){}
 $("theme").textContent=t==="light"?"🌙":"☀️";
 $("theme").title=t==="light"?"ダークに切替":"ライトに切替";try{refreshPro()}catch(e){}}
(function(){let t;try{t=localStorage.getItem("fn-theme")}catch(e){}
 if(!t)t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";setTheme(t);})();
$("theme").onclick=()=>setTheme(document.documentElement.dataset.theme==="light"?"dark":"light");
/* ヘルプ(使い方/できること) */
$("help").onclick=()=>{$("helpOverlay").style.display="flex";applyStatic();};
$("helpClose").onclick=()=>{$("helpOverlay").style.display="none";};
$("helpOverlay").onclick=e=>{if(e.target===$("helpOverlay"))$("helpOverlay").style.display="none";};
$("lang").textContent=LANG==="en"?"日本語":"EN";
$("help").title=LANG==="en"?"Usage / capabilities":"使い方 / できること";
$("help").setAttribute("aria-label",LANG==="en"?"Help":"ヘルプ");applyStatic();
async function post(p,b){return (await fetch(p,{method:"POST",headers:H,body:JSON.stringify(b)})).json()}
// 認証エラー(401 / {ok:false})はネットワーク断とは別物として扱う: cookie失効・トークン不一致等
// (例: サーバ再起動でトークンが再生成された)で接続断ではなくデータが"正常"に見えてしまうのを防ぐ。
function isAuthFail(e){return !!(e&&e.authFail)}
function markAuthError(){$("conn").className="pill bad";$("connt").textContent=tr("認証エラー・再読込");}
async function guardedFetch(path){
 const resp=await fetch(path,{headers:H});
 let data=null;try{data=await resp.json()}catch(e){}
 if(resp.status===401||(data&&data.ok===false)){const err=new Error("auth");err.authFail=true;throw err;}
 return data;
}
/* トースト通知: kind は ok/err/info。~3秒で自動消去・手動での×閉じにも対応。 */
function toast(message,kind){
 const wrap=$("toastwrap");if(!wrap)return;
 const el=document.createElement("div");el.className="toast "+(kind||"info");
 const t=document.createElement("span");t.className="ttext";t.textContent=message;
 const x=document.createElement("button");x.className="tclose";x.setAttribute("aria-label","close");x.textContent="×";
 el.appendChild(t);el.appendChild(x);wrap.appendChild(el);
 requestAnimationFrame(()=>el.classList.add("show"));
 const hide=()=>{el.classList.remove("show");setTimeout(()=>el.remove(),220);};
 const timer=setTimeout(hide,3000);
 x.onclick=()=>{clearTimeout(timer);hide();};
}
/* ボタンのビジー状態: 二重送信防止 + 進行中フィードバック(disabled+スピナー)。 */
function busy(btn,on){
 if(!btn)return;
 if(on){if(btn.dataset.obusy===undefined)btn.dataset.obusy="1";btn.disabled=true;btn.classList.add("busy");}
 else{btn.disabled=false;btn.classList.remove("busy");delete btn.dataset.obusy;}
}
/* post + トースト: 成否をトーストで知らせ、btn があれば送信中ビジー表示する。既存の post()
   はそのまま(内部/連続呼び出し用)に残し、ユーザー操作の起点はこちらへ寄せる。post() 自体は
   例外を投げても(このダッシュボードの post() は sibling と違い try/catch していない)ここで
   捕まえてトースト表示に落とす。 */
async function postT(p,b,btn,okMsg,errPrefix){
 busy(btn,true);
 let r;try{r=await post(p,b);}catch(e){r={ok:false,error:String(e)};}
 busy(btn,false);
 if(r&&r.ok)toast(okMsg||tr("保存しました"),"ok");
 else toast((errPrefix?errPrefix+": ":"")+(r&&r.error?r.error:tr("失敗")),"err");
 return r;
}
/* 確認ダイアログ: 破壊的操作向けのスタイル付きモーダル。confirm() の置き換え。 */
function confirmDialog(message){
 return new Promise(resolve=>{
  const ov=$("confirmOverlay"),ok=$("confirmOk"),cancel=$("confirmCancel");
  $("confirmMsg").textContent=message;
  ov.style.display="flex";
  const done=v=>{ov.style.display="none";ok.onclick=null;cancel.onclick=null;ov.onclick=null;
   document.removeEventListener("keydown",onKey);resolve(v);};
  const onKey=e=>{if(e.key==="Escape")done(false);if(e.key==="Enter")done(true);};
  ok.onclick=()=>done(true);cancel.onclick=()=>done(false);
  ov.onclick=e=>{if(e.target===ov)done(false);};
  document.addEventListener("keydown",onKey);
  ok.focus();
 });
}
/* 初回ロードのスケルトン: /api/state 到着前は『0』ではなく『未取得』と分かる表示にする。 */
function showSkeleton(){
 const bar=w=>`<span class="skel-bar" style="width:${w}"></span>`;
 $("cards").innerHTML=Array.from({length:7}).map(()=>
  `<div class="kpi skel"><div class="kn">${bar("44%")}</div><div class="kl">${bar("72%")}</div></div>`).join("");
 $("top").textContent="…";$("apt").textContent="…";
 $("events").innerHTML=`<div class="frow skel"><span class="time">${bar("40px")}</span><span class="desc">${bar("60%")}</span></div>`.repeat(4);
 $("bans").querySelector("tbody").innerHTML=`<tr class="skel"><td colspan="5">${bar("90%")}</td></tr>`.repeat(3);
}
async function refresh(){
 let s;try{s=await guardedFetch("/api/state")}catch(e){
  if(isAuthFail(e)){markAuthError();}else{$("conn").className="pill bad";$("connt").textContent=tr("接続不可");}
  return}
 $("conn").className="pill ok";$("connt").textContent=tr("接続中");
 $("fw").checked=s.firewall.enabled;$("sh").checked=s.shield.cfg.enabled;
 const m=s.shield_metrics;
 const em=s.edge_metrics||{};
 $("cards").innerHTML=[["要求",m.requests,"i-blue"],["許可",m.allow,"i-green"],["スロットル",m.throttle,"i-amber"],
   ["ブロック",m.block,"i-red"],["BAN中",m.active_bans,"i-red"],
   ["漏洩",m.dlp_leak,"i-red"],["バックエンド不通",em.backend_unreachable||0,"i-red"]]
   .map(([l,n,a])=>`<div class="kpi ${a}"><div class="kn">${nf(n)}</div><div class="kl">${esc(tr(l))}</div></div>`).join("");
 // 出口DLP: 設定の反映 + 漏洩イベントの抽出表示
 // dlp_enabled はサブフラグに過ぎず、実際の稼働は本体(dc.enabled)とのAND(pipeline.py dlp_active()と同一条件) —
 // 本体OFF中に「有効」と表示して安心させない(#5)。
 const dc=s.shield.cfg;$("dlp").checked=!!dc.dlp_enabled;$("dlpact").value=dc.dlp_action||"audit";
 const dlpOn=!!dc.enabled&&!!dc.dlp_enabled;
 $("dlpstat").textContent=tr(dlpOn?"有効":"無効")+" · "+(dc.dlp_action||"audit")+" · "+tr("漏洩")+" "+nf(m.dlp_leak||0);
 // 詳細防御(評価): 応答ヘッダ / paranoia
 $("sech").checked=!!dc.sec_headers_enabled;
 $("paranoia").value=String(dc.paranoia||1);
 $("advstat").textContent=[dc.sec_headers_enabled&&tr("ヘッダ"),"P"+(dc.paranoia||1)].filter(Boolean).join(" · ");
 // 改竄検知の可視化(#55): 件数+直近イベントをダッシュボードに要約表示(READMEの記載どおり実物を出す)
 const tp=m.tamper||{};
 const tpCount=nf(tp.count||0)+(LANG==="en"?"":"件");
 const tpLast=tp.last?((tp.last.kind||"")+" "+tm(tp.last.ts)):tr("(なし)");
 $("tamperstat").textContent=tr("改竄検知")+": "+tpCount+" · "+tr("直近")+": "+tpLast;
 // WAF 任意(高FP)シグネチャのトグル一覧
 const OPTL={ssti:"SSTI(テンプレート注入 {{…}})",ssrf_internal:"内部SSRF(localhost/内部IP)",redirect:"オープンリダイレクト(=//)"};
 const oset=dc.optional_sigs||{};
 $("optsigs").innerHTML=(s.shield.optional_signatures||[]).map(n=>
   `<div class="row"><label class="sw"><input type="checkbox" class="toggle" ${oset[n]?"checked":""}`
   +` onchange="postT('/api/shield/optional_sig',{name:'${esc(n)}',on:this.checked},null,tr('設定を保存しました')).then(refresh)">`
   +` ${esc(tr(OPTL[n]||n))}</label></div>`).join("")||'<div class="empty">'+tr("なし")+'</div>';
 // パス別レート制限(per-path token bucket): 現在のルール一覧 + 削除
 curPathLimits=dc.path_limits||[];
 $("prlmeta").textContent=curPathLimits.length?(curPathLimits.length+" "+tr("ルール")):tr("無効");
 $("pathlimits").querySelector("tbody").innerHTML=curPathLimits.map((r,i)=>
   `<tr><td><span class="num">${esc(r.path)}</span></td><td class="num">${r.rate}/s</td>`
   +`<td class="num">burst ${r.burst}</td>`
   +`<td><button class="ghost" onclick="removePathLimit(${i},this)">${tr("削除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("ルールなし")+'</td></tr>';
 // レート/メソッド/分散(運用): #24/#25/#26 のトグルと値。free-text は編集中クロバー回避。
 $("throttle").checked=dc.throttle_response!==false;
 $("subnetdef").checked=!!dc.subnet_defense;
 setIfBlur("retryaft",String(dc.throttle_retry_after!=null?dc.throttle_retry_after:1));
 setIfBlur("subthr",String(dc.subnet_threshold!=null?dc.subnet_threshold:8));
 setIfBlur("blockmeth",(dc.blocked_methods||[]).join(","));
 // 上限接続数/IP・新規接続レート/IP・全体同時接続上限・keep-alive強制切断: pipeline.py の
 // _DEFAULTS には存在するが元々ダッシュボードUIが無かった4項目(#4)。汎用 /api/shield/config
 // を再利用する。conn_rate_per_ip 等は int 既定値のため set_config() の型チェックが float を
 // 黙って弾く — parseFloat ではなく parseInt を使うこと。
 setIfBlur("maxconnip",String(dc.max_conn_per_ip!=null?dc.max_conn_per_ip:0));
 setIfBlur("connrateip",String(dc.conn_rate_per_ip!=null?dc.conn_rate_per_ip:0));
 setIfBlur("maxtotalconn",String(dc.max_total_conn!=null?dc.max_total_conn:20000));
 $("forceclose").checked=dc.force_conn_close!==false;
 $("opsstat").textContent=[dc.throttle_response!==false&&"429",dc.subnet_defense&&tr("分散"),
   (dc.blocked_methods||[]).length+tr("メソッド")].filter(Boolean).join(" · ");
 try{const sn=await guardedFetch("/api/shield/subnet");
  $("subnetmeta").textContent=tr("追跡")+" "+nf(sn.tracked_subnets||0)+" · hot "+nf(sn.hot_subnets||0)
   +" · "+tr("遮断メソッド")+": "+((dc.blocked_methods||[]).join(", ")||tr("なし"));}catch(e){if(isAuthFail(e))markAuthError();}
 // シグネチャ別ヒット / トラフィック構成(累積・テレメトリ)= 横棒グラフ(共通ヘルパ)
 const si=Object.entries(m.sig_hits||{});
 $("sigmetatop").textContent=tr("計")+" "+nf(si.reduce((a,x)=>a+x[1],0))+" · "+tr("種別")+" "+si.length;
 $("sigbars").innerHTML=barHTML(si,10);
 $("zonebars").innerHTML=barHTML(Object.entries(m.zone_hits||{}),6);
 $("actbars").innerHTML=barHTML([["allow",m.allow],["throttle",m.throttle],
   ["block",m.block]],5);
 $("methbars").innerHTML=barHTML(Object.entries(m.method_hits||{}),8);
 // 漏洩した秘密種別の内訳(累積・テレメトリ)
 const lkm=m.dlp_kinds||{},lki=Object.entries(lkm).sort((a,b)=>b[1]-a[1]).slice(0,6);
 $("leakkinds").innerHTML=lki.map(([k,v])=>`<span class="badge danger">${esc(k)} ${v}</span>`).join(" ");
 const lk=(s.events||[]).filter(e=>e.kind==="dlp_leak");
 $("leaks").innerHTML=lk.slice(-30).reverse().map(e=>
   `<div class="frow"><span class="time">${tm(e.ts)}</span><span class="badge danger">leak</span>`
   +`<span class="desc num">${esc(e.ip||"")}</span>`
   +`<span class="desc">${esc((e.kinds||[]).join(", "))}</span></div>`).join("")
   ||'<div class="empty">'+tr(dlpOn?"漏洩なし":"DLP 無効")+'</div>';
 curBans=s.shield.bans||[];renderBans();
 $("top").textContent=(s.top||[]).map(t=>`${(t.ip+"").padStart(15)}  score ${String(t.score).padStart(4)}  win ${t.reqs_window}  hits ${t.hits} ${t.banned?"BAN":""}`).join("\n")||tr("(なし)");
 curEvents=s.events||[];renderEvents();
 // ゾーン policy=prompt の保留接続(#2): アピール一覧と同じ承認/拒否UXで、行き止まりを解消
 const pend=(s.firewall||{}).pending||[];curPending=pend;
 $("pendingmeta").textContent=pend.length?String(pend.length):"—";
 $("fwpending").querySelector("tbody").innerHTML=pend.map(p=>
   `<tr><td class="num">${esc(p.ip)}</td><td><span class="badge info">${esc(p.zone)}</span></td>
   <td class="num">${tm(p.ts)}</td>
   <td><label class="meta" style="font-weight:normal;cursor:pointer"><input type="checkbox" id="rem_${esc(p.id)}"> ${tr("常時許可として記憶")}</label>
   <button onclick="resolvePending('${esc(p.id)}',true,this)">${tr("承認")}</button>
   <button class="red" onclick="resolvePending('${esc(p.id)}',false,this)">${tr("却下")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("承認待ちなし — ゾーンポリシーが「承認待ち」のゾーンで新規接続があるとここに表示されます")+'</td></tr>';
}
/* BAN中IPテーブル: 検索/ソート/一括選択。curBans はサーバから取得した最新配列。 */
let curBans=[],banSort={key:null,dir:1},banSel=new Set(),lastBanRows=[];
function renderBans(){
 const q=($("bansearch").value||"").toLowerCase();
 let rows=curBans.filter(b=>!q||String(b.ip).toLowerCase().includes(q));
 if(banSort.key){
  rows=rows.slice().sort((a,b)=>{
   const av=banSort.key==="score"?a.score:a.remain_sec,bv=banSort.key==="score"?b.score:b.remain_sec;
   return ((av||0)-(bv||0))*banSort.dir;
  });
 }
 lastBanRows=rows;
 $("bansmeta").textContent=curBans.length?(rows.length+"/"+curBans.length):"—";
 $("bans").querySelector("tbody").innerHTML=rows.map(b=>
   `<tr><td><input type="checkbox" class="bansel" data-ip="${esc(b.ip)}" ${banSel.has(b.ip)?"checked":""}></td>`
   +`<td class="num">${esc(b.ip)}</td><td class="num">${esc(tr("残"))}${Math.round(b.remain_sec)}s</td>`
   +`<td><span class="badge ${b.score>40?"danger":"warn"}">score ${b.score}</span></td>`
   +`<td><button class="ghost" onclick="unban('${esc(b.ip)}',this)">${tr("解除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="5" class="empty">'+tr(curBans.length?"該当なし":"BAN なし")+'</td></tr>';
 document.querySelectorAll(".bansel").forEach(cb=>cb.onchange=()=>{
  if(cb.checked)banSel.add(cb.dataset.ip);else banSel.delete(cb.dataset.ip);
  $("banall").checked=rows.length>0&&rows.every(b=>banSel.has(b.ip));
 });
 $("banall").checked=rows.length>0&&rows.every(b=>banSel.has(b.ip));
}
$("bans").querySelector("thead").addEventListener("click",e=>{
 const th=e.target.closest("th.sortable");if(!th)return;
 const k=th.dataset.sort;
 banSort.dir=(banSort.key===k)?-banSort.dir:-1;
 banSort.key=k;
 document.querySelectorAll("#bans th.sortable .sortarrow").forEach(s=>s.textContent="");
 th.querySelector(".sortarrow").textContent=banSort.dir<0?"▼":"▲";
 renderBans();
});
function toggleAllBans(checked){
 lastBanRows.forEach(b=>{if(checked)banSel.add(b.ip);else banSel.delete(b.ip);});
 renderBans();
}
async function unbanSelected(btn){
 const ips=[...banSel];
 if(!ips.length){toast(tr("選択なし"),"info");return;}
 busy(btn,true);
 for(const ip of ips)await post("/api/shield/unban",{ip});
 busy(btn,false);
 banSel.clear();
 toast(tr("選択したIPを解除しました"),"ok");
 refresh();
}
async function unbanAll(btn){
 if(!curBans.length)return;
 if(!(await confirmDialog(tr("BAN中の全IPを解除します。よろしいですか?"))))return;
 busy(btn,true);
 for(const b of curBans)await post("/api/shield/unban",{ip:b.ip});
 busy(btn,false);
 banSel.clear();
 toast(tr("すべてのBANを解除しました"),"ok");
 refresh();
}
/* 攻撃イベント: 検索フィルタ。curEvents はサーバから取得した最新配列。 */
let curEvents=[];
function renderEvents(){
 const q=($("eventsearch").value||"").toLowerCase();
 const rows=curEvents.filter(e=>!q||String(e.ip||"").toLowerCase().includes(q)||String(e.kind||"").toLowerCase().includes(q));
 $("eventsmeta").textContent=curEvents.length?(rows.length+"/"+curEvents.length):"—";
 $("events").innerHTML=rows.slice(-300).slice().reverse().map(e=>
   `<div class="frow"><span class="time">${tm(e.ts)}</span><span class="badge ${sev(e.kind)}">${esc(e.kind)}</span>`
   +`<span class="desc num">${esc(e.ip||"")}</span></div>`).join("")
   ||'<div class="empty">'+tr(curEvents.length?"該当なし":"イベントなし")+'</div>';
}
/* 承認待ち接続の一括操作: 承認は影響が大きいため確認、拒否は安全側なので確認なし。 */
let curPending=[];
async function approveAllPending(btn){
 if(!curPending.length)return;
 if(!(await confirmDialog(tr("すべての承認待ち接続を承認します。よろしいですか?"))))return;
 busy(btn,true);
 for(const p of curPending)await post("/api/firewall/resolve",{id:p.id,approve:true});
 busy(btn,false);
 toast(tr("すべて承認しました"),"ok");
 refresh();
}
async function denyAllPending(btn){
 if(!curPending.length)return;
 busy(btn,true);
 for(const p of curPending)await post("/api/firewall/resolve",{id:p.id,approve:false});
 busy(btn,false);
 toast(tr("すべて拒否しました"),"ok");
 refresh();
}
$("fw").onchange=e=>postT("/api/firewall/toggle",{on:e.target.checked},null,tr("ファイアウォールを更新しました")).then(refresh);
$("sh").onchange=e=>postT("/api/shield/toggle",{on:e.target.checked},null,tr("シールドを更新しました")).then(refresh);
$("dlp").onchange=e=>postT("/api/shield/config",{dlp_enabled:e.target.checked},null,tr("DLP設定を保存しました")).then(refresh);
$("dlpact").onchange=e=>postT("/api/shield/config",{dlp_action:e.target.value},null,tr("DLP設定を保存しました")).then(refresh);
$("sech").onchange=e=>postT("/api/shield/config",{sec_headers_enabled:e.target.checked},null,tr("設定を保存しました")).then(refresh);
$("paranoia").onchange=e=>postT("/api/shield/paranoia",{level:parseInt(e.target.value)},null,tr("検知の厳格度を変更しました")).then(refresh);
$("throttle").onchange=e=>postT("/api/shield/config",{throttle_response:e.target.checked},null,tr("設定を保存しました")).then(refresh);
$("retryaft").onchange=e=>postT("/api/shield/config",{throttle_retry_after:parseInt(e.target.value)||0},null,tr("設定を保存しました")).then(refresh);
$("subnetdef").onchange=e=>postT("/api/shield/config",{subnet_defense:e.target.checked},null,tr("設定を保存しました")).then(refresh);
$("subthr").onchange=e=>postT("/api/shield/config",{subnet_threshold:parseInt(e.target.value)||1},null,tr("設定を保存しました")).then(refresh);
$("maxconnip").onchange=e=>postT("/api/shield/config",{max_conn_per_ip:parseInt(e.target.value)||0},null,tr("設定を保存しました")).then(refresh);
$("connrateip").onchange=e=>postT("/api/shield/config",{conn_rate_per_ip:parseInt(e.target.value)||0},null,tr("設定を保存しました")).then(refresh);
$("maxtotalconn").onchange=e=>postT("/api/shield/config",{max_total_conn:parseInt(e.target.value)||0},null,tr("設定を保存しました")).then(refresh);
$("forceclose").onchange=e=>postT("/api/shield/config",{force_conn_close:e.target.checked},null,tr("設定を保存しました")).then(refresh);
/* チャートの時間範囲ズーム: 既にクライアントが取得済みの /api/series 配列を切り出すだけ。
   サーバ側の保持期間(pipeline._series・約10分)より長い範囲を要求することはしない。 */
let chartWindow=Infinity;
function setChartWindow(sec){
 chartWindow=sec;
 document.querySelectorAll("#chartzoom button").forEach(b=>
  b.classList.toggle("active",(sec===Infinity&&b.dataset.sec==="all")||Number(b.dataset.sec)===sec));
 try{refreshPro()}catch(e){}
}
async function refreshPro(){
 try{let s=(await guardedFetch("/api/series")).series||[];
  if(chartWindow!==Infinity&&s.length){const cutoff=s[s.length-1].t-chartWindow;s=s.filter(x=>x.t>=cutoff);}
  drawChart(s);
  drawSpark("leaktrend",s.map(x=>x.dlp_leak||0));
  drawSpark("sigtrend",s.map(x=>x.sig_total||0));
  drawSpark("pubtrend",s.map(x=>x.pub||0));}catch(e){if(isAuthFail(e))markAuthError();}
 try{const ap=(await guardedFetch("/api/appeals")).appeals||[];
  $("appeals").querySelector("tbody").innerHTML=ap.map(a=>
   `<tr><td class="num">${esc(a.ip)}</td><td><span class="badge ${a.status==="pending"?"warn":"muted"}">${esc(a.status)}</span></td>
   <td>${esc((a.reason||"").slice(0,40))}</td>
   <td>${a.status==="pending"?`<button onclick="resolveAppeal('${esc(a.ip)}',true,this)">${tr("承認")}</button>
   <button class="red" onclick="resolveAppeal('${esc(a.ip)}',false,this)">${tr("却下")}</button>`:""}</td></tr>`
  ).join("")||'<tr><td colspan="4" class="empty">'+tr("申立なし — BANされた利用者が異議申立を送るとここに表示されます")+'</td></tr>';}catch(e){if(isAuthFail(e))markAuthError();}
 try{const an=await guardedFetch("/api/analysis");
  $("analysis").textContent=JSON.stringify({actions:an.actions,by_zone:an.by_zone,
   top_signatures:an.top_signatures,event_kinds:an.event_kinds,active_bans:an.active_bans},null,2);}catch(e){if(isAuthFail(e))markAuthError();}
 try{const ap=await guardedFetch("/api/apt");
  $("apt").textContent=(ap.suspects||[]).map(s=>
   `${(s.ip+"").padStart(15)}  apt ${String(s.apt_score).padStart(3)}  ${s.regular_beacon?"beacon ":""}${s.low_and_slow?"low&slow ":""}${s.banned?"BAN":""}`
  ).join("\n")||tr("(兆候なし)");}catch(e){if(isAuthFail(e))markAuthError();}
 try{drawMap(await guardedFetch("/api/nodes"));}catch(e){if(isAuthFail(e))markAuthError();}
 try{refreshSigs();}catch(e){}
 try{refreshDeception();}catch(e){}
 try{refreshAudit();}catch(e){}
}
/* 変更履歴(監査ログ) */
let curAudit=[];
async function refreshAudit(){
 let d;try{d=await guardedFetch("/api/admin_audit")}catch(e){if(isAuthFail(e))markAuthError();return}
 const rows=(d&&d.entries)||[];curAudit=rows;
 $("auditmeta").textContent=rows.length?String(rows.length):"—";
 $("auditlog").innerHTML=rows.map((e,i)=>{
   const rv=e.revert?`<button class="ghost" data-auditidx="${i}">${tr("元に戻す")}</button>`:"";
   return `<div class="frow"><span class="time">${tm(e.ts)}</span>`
    +`<span class="desc">${esc(e.summary||e.endpoint||"")}</span>${rv}</div>`;
 }).join("")||'<div class="empty">'+tr("変更履歴なし")+'</div>';
}
$("auditlog").addEventListener("click",e=>{
 const b=e.target.closest("button[data-auditidx]");if(!b)return;
 const entry=curAudit[parseInt(b.dataset.auditidx)];
 if(entry&&entry.revert)revertAudit(entry.revert,b);
});
function revertAudit(revert,btn){
 postT(revert.endpoint,revert.body,btn,tr("元に戻しました"),tr("復元に失敗")).then(()=>{refresh();refreshAudit();});
}
async function refreshDeception(){
 let d;try{d=await guardedFetch("/api/deception")}catch(e){if(isAuthFail(e))markAuthError();return}
 $("decepstat").innerHTML=`<span class="badge ${d.enabled?"info":"muted"}">${tr(d.enabled?"有効":"無効")}</span>`
   +` ${tr("系統")} ${d.family_count||0}`;
 if(!d.enabled){$("deception").textContent=tr("(DUCKNET_DECEPTION 未設定 = 偽装なし)")+"\n"+tr("系統")+": "
   +(d.families||[]).join(", ");return}
 const rows=(d.preview||[]).map(p=>
   `${LANG==="en"?"win":"窓"}+${p.window}: ${(p.server||"").padEnd(24)} [${p.family}]`+(p.companions.length?"  "+p.companions.join("  "):""));
 $("deception").textContent=tr("サンプル攻撃者")+" "+d.sample_seed+" "+tr("から見える偽装(隣接窓で必ず別系統):")+"\n"
   +rows.join("\n");
}
let curCustomSigs=[];
async function refreshSigs(){
 let d;try{d=await guardedFetch("/api/shield/signatures")}catch(e){if(isAuthFail(e))markAuthError();return}
 curCustomSigs=d.custom||[];
 $("sigmeta").textContent=`${tr("組込")} ${(d.builtin||[]).length} · ${tr("カスタム")} ${d.custom_active||0}`
   +(d.custom_blocked?` · ${tr("危険除外")} ${d.custom_blocked}`:"");
 $("customsigs").querySelector("tbody").innerHTML=curCustomSigs.map(c=>
   `<tr><td class="num">${esc(c.name)}</td><td><span class="num">${esc((c.pattern||"").slice(0,48))}</span></td>`
   +`<td><button class="ghost" data-signame="${esc(c.name)}">${tr("削除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="3" class="empty">'+tr("カスタムシグネチャなし — 下のフォームから追加できます(組込シグネチャで拾えないパターン用)")+'</td></tr>';
}
$("customsigs").addEventListener("click",e=>{
 const b=e.target.closest("button[data-signame]");
 if(b)removeSig(b.dataset.signame,b);
});
async function addSig(btn){
 const name=$("signame").value.trim(),pattern=$("sigpat").value;
 if(!name||!pattern){$("sigerr").textContent=tr("名前とパターンを入力");return;}
 const r=await postT("/api/shield/sig_add",{name,pattern},btn,tr("シグネチャを追加しました"),tr("追加に失敗"));
 $("sigerr").textContent=r.ok?"":("✗ "+(r.error||tr("失敗")));
 if(r.ok){$("signame").value="";$("sigpat").value="";$("sigtestresult").textContent="";}
 refreshSigs();
}
async function removeSig(name,btn){
 if(!(await confirmDialog(tr("このシグネチャを削除しますか?")+" "+name)))return;
 postT("/api/shield/sig_remove",{name},btn,tr("シグネチャを削除しました"),tr("削除に失敗")).then(refreshSigs);
}
/* シグネチャのドライラン試験: 追加前にサーバ側の validate_pattern(ReDoS検査)を通した上で
   マッチ確認のみ行う読み取り専用API。状態は一切変更しない。 */
async function testSig(btn){
 const pattern=$("sigpat").value,sample=$("sigtestsample").value;
 if(!pattern){$("sigtestresult").innerHTML='<span class="badge muted">'+tr("パターンを入力")+'</span>';return;}
 busy(btn,true);
 let r;try{r=await post("/api/shield/sig_test",{pattern,sample});}finally{busy(btn,false);}
 if(!r||!r.ok){$("sigtestresult").innerHTML='<span class="badge danger">'+tr("エラー")+'</span>';return;}
 if(r.error){$("sigtestresult").innerHTML='<span class="badge danger">'+tr("無効なパターン")+': '+esc(r.error)+'</span>';}
 else{$("sigtestresult").innerHTML=r.matches?'<span class="badge warn">'+tr("一致")+'</span>':'<span class="badge muted">'+tr("不一致")+'</span>';}
}
let curPathLimits=[];
async function addPathLimit(btn){
 const path=$("prpath").value.trim(),rate=parseFloat($("prrate").value),burst=parseFloat($("prburst").value);
 if(!path||!(rate>0)){$("prerr").textContent=tr("パスと毎秒(>0)を入力");return;}
 const rule={path,rate};if(burst>0)rule.burst=burst;
 const r=await postT("/api/shield/path_limits",{rules:curPathLimits.concat([rule])},btn,tr("レート制限を追加しました"),tr("追加に失敗"));
 $("prerr").textContent=r.ok?"":("✗ "+(r.error||tr("失敗")));
 if(r.ok){$("prpath").value="";$("prrate").value="";$("prburst").value="";}
 refresh();
}
async function removePathLimit(i,btn){
 if(!(await confirmDialog(tr("このレート制限ルールを削除しますか?"))))return;
 postT("/api/shield/path_limits",{rules:curPathLimits.filter((_,j)=>j!==i)},btn,tr("ルールを削除しました"),tr("削除に失敗")).then(refresh);
}
function setIfBlur(id,val){const e=$(id);if(e&&document.activeElement!==e)e.value=val;}  // 編集中は上書きしない
async function saveBlockedMethods(btn){
 const m=$("blockmeth").value.split(",").map(s=>s.trim()).filter(Boolean);
 postT("/api/shield/blocked_methods",{methods:m},btn,tr("遮断メソッドを保存しました"),tr("保存に失敗")).then(r=>{
  // バックエンドは英字以外・重複を黙って除外するため、送った物と実際に保存された物を突き合わせて
  // ドロップされたトークンをその場で表示する。
  const kept=new Set((r.blocked_methods||[]).map(x=>String(x).toUpperCase()));
  const dropped=m.filter(x=>!kept.has(x.toUpperCase()));
  $("methoderr").textContent=dropped.length?(tr("無視")+": "+dropped.join(", ")):"";
  refresh();
 });
}
const _ZR={loopback:55,private:105,public:150,special:150,unknown:150};
function drawMap(d){
 const W=1040,Hh=300,cx=W/2,cy=Hh/2;
 const line=cssv("--line"),fg=cssv("--fg"),blue=cssv("--blue"),green=cssv("--green"),amber=cssv("--amber"),red=cssv("--brand");
 let g=`<circle cx="${cx}" cy="${cy}" r="24" fill="${blue}"/>`
   +`<text x="${cx}" y="${cy+4}" fill="#fff" font-size="11" font-weight="700" text-anchor="middle">${esc(tr("本機"))}</text>`;
 const byz={};(d.nodes||[]).forEach(n=>{(byz[n.zone]=byz[n.zone]||[]).push(n)});
 Object.keys(byz).forEach(z=>{const arr=byz[z],r=_ZR[z]||150;
  arr.forEach((n,i)=>{const a=(i/Math.max(1,arr.length))*Math.PI*2;
   const x=cx+Math.cos(a)*r,y=cy+Math.sin(a)*r;
   const col=n.banned?red:(n.score>40?amber:green);
   g+=`<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${line}" stroke-width="1"/>`
    +`<circle cx="${x}" cy="${y}" r="7" fill="${col}" style="cursor:pointer"`
    +` onclick="toggleNode('${esc(n.ip)}',${!!n.banned})"><title>${esc(n.ip)} [${esc(z)}] score${n.score}${n.mac?" "+esc(n.mac):""}</title></circle>`;});});
 $("netmap").innerHTML=g;
}
function toggleNode(ip,banned){
 if(banned){postT("/api/shield/unban",{ip},null,tr("BANを解除しました")).then(refreshPro);}
 else{postT("/api/firewall/rule",{net:ip,action:"deny"},null,tr("拒否ルールを追加しました")).then(refreshPro);}
}
async function globalBlock(on,btn){
 if(on&&!(await confirmDialog(tr("インターネット(public)を一括遮断します。よろしいですか?"))))return;
 postT("/api/global_block",{on},btn,on?tr("グローバル遮断を有効にしました"):tr("グローバル遮断を解除しました"),tr("処理に失敗"))
  .then(()=>{refresh();refreshPro();});
}
function barHTML(entries,limit){
 const e=entries.filter(x=>x[1]).sort((a,b)=>b[1]-a[1]),mx=Math.max(1,...e.map(x=>x[1]));
 return e.slice(0,limit||10).map(([k,v])=>
   `<div class="sbar"><span class="sbl">${esc(k)}</span><span class="sbt">`
   +`<span class="sbf" style="width:${Math.round(v/mx*100)}%"></span></span>`
   +`<span class="sbn num">${nf(v)}</span></div>`).join("")||'<div class="empty">'+tr("なし")+'</div>';
}
function drawSpark(id,cum){
 const el=$(id);if(!el)return;
 const d=[];for(let i=1;i<cum.length;i++)d.push(Math.max(0,(cum[i]||0)-(cum[i-1]||0)));  // 累積→毎秒の漏洩数
 const W=300,Hh=30,n=d.length,mx=Math.max(1,...d),red=cssv("--red");
 if(!n){el.innerHTML="";return;}
 const xy=i=>[(i/(n-1||1))*W,Hh-2-(d[i]/mx)*(Hh-5)];
 const pts=d.map((_,i)=>xy(i).join(",")).join(" ");
 const [x0]=xy(0),[xN]=xy(n-1);
 el.innerHTML=`<polyline points="${x0},${Hh} ${pts} ${xN},${Hh}" fill="${red}" fill-opacity=".12" stroke="none"/>`
   +`<polyline points="${pts}" fill="none" stroke="${red}" stroke-width="1.5"/>`;
}
function drawChart(s){
 const c=$("chart"),x=c.getContext("2d"),dpr=devicePixelRatio||1,cw=c.clientWidth||1000,ch=180;
 if(c.width!==Math.round(cw*dpr)){c.width=Math.round(cw*dpr);c.height=Math.round(ch*dpr);}
 x.setTransform(dpr,0,0,dpr,0,0);const W=cw,Hh=ch;
 x.clearRect(0,0,W,Hh);
 const line=cssv("--line2"),faint=cssv("--faint"),blue=cssv("--blue"),red=cssv("--brand");
 for(let i=0;i<=4;i++){const y=5+(Hh-15)*i/4;x.strokeStyle=line;x.lineWidth=1;x.beginPath();x.moveTo(0,y);x.lineTo(W,y);x.stroke();}
 if(s.length<2){return;}
 const d=[];for(let i=1;i<s.length;i++){const dt=Math.max(0.001,s[i].t-s[i-1].t);
  d.push({r:(s[i].requests-s[i-1].requests)/dt,b:(s[i].block-s[i-1].block)/dt});}
 const mx=Math.max(1,...d.map(p=>Math.max(p.r,p.b)));
 const px=i=>i/(d.length-1)*W,py=v=>Hh-(v/mx)*(Hh-15)-5;
 // req は塗り
 x.beginPath();x.moveTo(0,Hh);d.forEach((p,i)=>x.lineTo(px(i),py(p.r)));x.lineTo(W,Hh);x.closePath();
 const grad=x.createLinearGradient(0,0,0,Hh);grad.addColorStop(0,blue+"55");grad.addColorStop(1,blue+"00");
 x.fillStyle=grad;x.fill();
 const ln=(k,col)=>{x.strokeStyle=col;x.lineWidth=2;x.lineJoin="round";x.beginPath();
  d.forEach((p,i)=>{i?x.lineTo(px(i),py(p[k])):x.moveTo(px(i),py(p[k]));});x.stroke();};
 ln("r",blue);ln("b",red);
 $("chartleg").innerHTML=`<span style="color:${blue}">●</span> req/s &nbsp;<span style="color:${red}">●</span> block/s &nbsp;· peak ${mx.toFixed(1)}/s`;
}
async function resolveAppeal(ip,ok,btn){
 if(!ok&&!(await confirmDialog(tr("この申立を却下しますか?")+" "+ip)))return;
 postT("/api/appeal/resolve",{ip,approve:ok},btn,ok?tr("申立を承認しました"):tr("申立を却下しました"),tr("処理に失敗"))
  .then(()=>{refresh();refreshPro();});
}
async function resolvePending(id,ok,btn){
 if(!ok&&!(await confirmDialog(tr("この接続を拒否しますか?"))))return;
 const remCk=ok?document.getElementById("rem_"+id):null;
 const remember=!!(remCk&&remCk.checked);
 postT("/api/firewall/resolve",{id,approve:ok,remember},btn,ok?tr("接続を承認しました"):tr("接続を拒否しました"),tr("処理に失敗")).then(refresh);
}
function unban(ip,btn){postT("/api/shield/unban",{ip},btn,tr("BANを解除しました"),tr("解除に失敗")).then(refresh)}
async function ban(btn){
 const ip=$("banip").value;if(!ip)return;
 if(!(await confirmDialog(tr("このIPをBANしますか?")+" "+ip)))return;
 postT("/api/shield/ban",{ip},btn,tr("IPをBANしました"),tr("BANに失敗")).then(refresh);
}
async function rule(a,btn){
 const net=$("ruleip").value;if(!net)return;
 if(a==="deny"&&!(await confirmDialog(tr("このIP/CIDRを拒否ルールに追加しますか?")+" "+net)))return;
 postT("/api/firewall/rule",{net,action:a},btn,tr("ルールを追加しました"),tr("追加に失敗")).then(refresh);
}
async function edge(){const t=await (await fetch("/api/edge",{headers:H})).text();
 const u=URL.createObjectURL(new Blob([t]));const a=document.createElement("a");a.href=u;a.download="ducknet_edge.conf";a.click()}
/* CSV/JSON エクスポート: 既に取得済みの配列をそのままファイル化するだけ(追加取得なし)。 */
function toCSV(rows,cols){
 const q=v=>{const s=v==null?"":String(v);return /[",\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;};
 return [cols.join(",")].concat(rows.map(r=>cols.map(c=>q(r[c])).join(","))).join("\r\n");
}
function downloadFile(filename,text,mime){
 const blob=new Blob([text],{type:mime||"text/plain"});
 const u=URL.createObjectURL(blob);
 const a=document.createElement("a");a.href=u;a.download=filename;document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(u),1000);
}
function exportData(which,fmt){
 let rows=[],cols=[],name="";
 if(which==="bans"){rows=curBans;cols=["ip","score","remain_sec"];name="banned_ips";}
 else if(which==="events"){rows=curEvents;cols=["ts","kind","ip"];name="attack_events";}
 else if(which==="sigs"){rows=curCustomSigs;cols=["name","category","pattern","weight"];name="custom_signatures";}
 else return;
 if(fmt==="json")downloadFile(name+".json",JSON.stringify(rows,null,2),"application/json");
 else downloadFile(name+".csv",toCSV(rows,cols),"text/csv");
 toast(tr("エクスポートしました"),"ok");
}
addEventListener("resize",()=>{try{refreshPro()}catch(e){}});
showSkeleton();refresh();refreshPro();setInterval(refresh,2000);setInterval(refreshPro,2000);
</script></body></html>"""
