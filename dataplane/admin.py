"""
admin.py — ChickenNet L7 Security 管理ダッシュボード(Web GUI・stdlib http.server)
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
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 管理トークンを焼く Cookie 名。HttpOnly + SameSite=Strict で配るため、XSS では読めず
# (HttpOnly)・クロスサイトからは送られない(SameSite=Strict=CSRF 緩和)。HTTP(localhost)
# 運用のため Secure は付けない(HTTPS 終端を挟む場合は Secure も付与すること)。
_COOKIE_NAME = "chickennet_admin"

from dataplane.engine.lifeform.policy import app_firewall, ZONES, ACTIONS
from dataplane.engine.lifeform.pipeline import net_shield
from dataplane.engine.services import edge_config
from dataplane.engine.core.atomic_io import default_state_dir

# 管理APIのリクエストボディ上限(Content-Length 詐称・巨大ボディのメモリ枯渇防止)。
_MAX_BODY = 1 << 20


def _j(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, default=lambda o: str(o)).encode("utf-8")


def _metrics_exposition(sh) -> str:
    """NetShield の指標を plain-text 露出形式で出す(監視系のスクレイプ用・依存ゼロ)。
    `# HELP`/`# TYPE` + `chickennet_<name>{label="v"} <int>`。ラベル値はサニタイズ(改行/引用符除去)。"""
    m = sh.metrics()
    out = []

    def scalar(name, val, typ, help_):
        out.append(f"# HELP chickennet_{name} {help_}")
        out.append(f"# TYPE chickennet_{name} {typ}")
        out.append(f"chickennet_{name} {val}")

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
        out.append(f"# HELP chickennet_{name} {help_}")
        out.append(f"# TYPE chickennet_{name} counter")
        for k, v in d.items():
            lv = str(k).replace("\\", "").replace('"', "").replace("\n", "")[:64]
            out.append(f'chickennet_{name}{{{label}="{lv}"}} {int(v)}')

    labeled("sig_hits_total", m.get("sig_hits"), "signature", "Signature hits by category")
    labeled("zone_hits_total", m.get("zone_hits"), "zone", "Requests by zone")
    return "\n".join(out) + "\n"


class AdminDashboard:
    def __init__(self, host: str = "127.0.0.1", port: int = 8081, token: str = "",
                 state_dir: str = "",
                 brand: str = "", logo: str = "🦅",
                 subtitle: str = "L7 防御 — 管理ダッシュボード"):
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(24)
        # 画面の表示名/アイコン。ステルス運用では汎用名(例 "System Health Monitor")に
        # 差し替えて、管理画面のタイトル/ヘッダ/Server ヘッダから製品を伏せる。明示が無ければ
        # CHICKENNET_COVER env を尊重し(遮断ページと同じ秘匿源=適用漏れを防ぐ)、無ければ製品名。
        self.brand = brand or os.environ.get("CHICKENNET_COVER", "ChickenNet L7 Security")
        self.logo = logo
        self.subtitle = subtitle
        # 検知ログの所在(別プロセスが書く)。CHICKENNET_STATE_DIR で移設可。テストは上書き可。
        self._state_dir = state_dir or default_state_dir()
        self._server = None
        self._thread = None

    # ── 状態取得 ──
    def state(self) -> dict:
        fw = app_firewall()
        sh = net_shield()
        from dataplane.engine.services.proxy import AsyncEdgeGuard
        return {"firewall": fw.status(), "shield": sh.status(),
                "shield_metrics": sh.metrics(), "top": sh.top_talkers(12),
                "events": sh.events(40), "zones": ZONES, "actions": ACTIONS,
                "capabilities": AsyncEdgeGuard.platform_capabilities()}

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
                "note": "既定OFF。CHICKENNET_DECEPTION で有効化(本プロセスの env を反映)。"}

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
            try:
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
            sh = net_shield()
            if path == "/api/state":
                self._send(200, _j(app.state()))
            elif path == "/api/deception":
                self._send(200, _j(app.deception_status()))
            elif path == "/api/series":
                self._send(200, _j({"series": sh.series(180)}))
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
            if not self._auth():
                self._send(401, _j({"ok": False, "error": "token required"}))
                return
            path = self.path.split("?")[0]
            b = self._body()
            fw, sh = app_firewall(), net_shield()
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
                    remember = bool(b.get("remember", True))
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
                else:
                    self._send(404, _j({"ok": False, "error": "not found"}))
                    return
                self._send(200, _j(r))
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
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:560px){.brand small{display:none}.wrap{padding:14px}}
</style></head><body>
<div class="bar">
  <div class="brand"><span class="logo">__LOGO__</span><div>__BRAND__<small>__SUBTITLE__</small></div></div>
  <div class="spacer"></div>
  <span class="pill" id="conn"><span class="dot"></span><span id="connt">接続中</span></span>
  <button class="iconbtn" id="lang" title="Language / 言語" aria-label="Language">EN</button>
  <button class="iconbtn" id="theme" title="テーマ切替" aria-label="テーマ切替">☀️</button>
</div>
<div class="wrap">
  <div class="controls">
    <label class="sw"><input type="checkbox" id="fw" class="toggle"> ファイアウォール</label>
    <label class="sw"><input type="checkbox" id="sh" class="toggle"> DDoS / 侵入防御</label>
    <div class="spacer"></div>
    <button class="red" onclick="globalBlock(true)">🌍 グローバル遮断</button>
    <button class="ghost" onclick="globalBlock(false)">解除</button>
  </div>
  <div class="kpis" id="cards"></div>
  <div class="grid">
    <div class="sect"><span class="ic">📈</span>概況</div>
    <section class="panel wide">
      <div class="phead"><h2>リアルタイム通信</h2><span class="meta" id="chartleg">req/s · block/s</span></div>
      <div class="pbody"><canvas id="chart" height="180" style="height:180px"></canvas></div>
    </section>
    <section class="panel wide">
      <div class="phead"><h2>ネットワーク図</h2><span class="meta">中心=本機 / 内→外=loopback·private·public / ノードclickで遮断·解除</span></div>
      <div class="pbody"><svg id="netmap" height="300" viewBox="0 0 1040 300" preserveAspectRatio="xMidYMid meet" style="height:300px"></svg></div>
    </section>

    <div class="sect"><span class="ic">🛡</span>脅威モニタリング</div>
    <section class="panel">
      <div class="phead"><h2>攻撃イベント</h2></div>
      <div class="pbody tight"><div class="feed" id="events"></div></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>BAN中のIP</h2></div>
      <div class="pbody"><table id="bans"><tbody></tbody></table>
        <div class="row"><input id="banip" placeholder="手動BANするIP">
        <button class="red" onclick="ban()">BAN</button></div></div>
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
        <table id="customsigs"><tbody></tbody></table>
        <div class="row"><input id="signame" placeholder="名前 例:my-rule">
        <input id="sigpat" placeholder="正規表現 例:evil-?bot"></div>
        <div class="row"><button onclick="addSig()">追加</button>
        <span class="meta" id="sigerr"></span></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>パス別レート制限</h2><span class="meta" id="prlmeta">—</span></div>
      <div class="pbody">
        <table id="pathlimits"><tbody></tbody></table>
        <div class="row"><input id="prpath" placeholder="パス前方一致 例:/login">
        <input id="prrate" type="number" step="0.1" placeholder="毎秒 例:0.5" style="max-width:130px">
        <input id="prburst" type="number" step="1" placeholder="バースト 例:5" style="max-width:130px"></div>
        <div class="row"><button onclick="addPathLimit()">追加</button>
        <span class="meta" id="prerr"></span></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>レート/メソッド/分散(運用)</h2><span class="meta" id="opsstat">—</span></div>
      <div class="pbody tight">
        <div class="row"><label class="sw"><input type="checkbox" id="throttle" class="toggle"> レート超過に429応答</label>
          <input id="retryaft" type="number" step="1" min="0" placeholder="Retry-After 秒" style="max-width:150px"></div>
        <div class="row"><label class="sw"><input type="checkbox" id="subnetdef" class="toggle"> サブネット集約防御</label>
          <input id="subthr" type="number" step="1" min="1" placeholder="しきい値(別IP数)" style="max-width:170px"></div>
        <div class="row"><span class="meta" id="subnetmeta">—</span></div>
        <div class="row"><input id="blockmeth" placeholder="遮断メソッド(カンマ区切) 例:TRACE,TRACK,CONNECT">
          <button onclick="saveBlockedMethods()">適用</button></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>出口DLP(秘密漏洩)</h2><span class="meta" id="dlpstat">—</span></div>
      <div class="pbody tight">
        <div class="row">
          <label class="sw"><input type="checkbox" id="dlp" class="toggle"> 秘密漏洩検知</label>
          <select id="dlpact" style="background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--r2);padding:6px 9px;font:inherit">
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
          <select id="paranoia" style="background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--r2);padding:6px 9px;font:inherit">
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
        <button onclick="rule('allow')">許可</button>
        <button class="red" onclick="rule('deny')">拒否</button>
        <button class="ghost" onclick="edge()">エッジ前衛設定DL</button></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>解除リクエスト(異議申立)</h2></div>
      <div class="pbody"><table id="appeals"><tbody></tbody></table></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>承認待ち接続(ファイアウォール)</h2><span class="meta">zone policy=prompt の未知接続</span></div>
      <div class="pbody"><table id="fwpending"><tbody></tbody></table></div>
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
 "承認待ちなし":"No pending connections",
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
 "BAN なし":"No bans","(なし)":"(none)","イベントなし":"No events","なし":"none","ヒットなし":"No hits",
 "カスタムなし":"No custom signatures",
 "削除":"Remove","DLP 無効":"DLP off","漏洩なし":"No leaks",
 "申立なし":"No appeals","承認":"Approve","却下":"Reject","名前とパターンを入力":"Enter name and pattern",
 "SSTI(テンプレート注入 {{…}})":"SSTI (template injection {{…}})","内部SSRF(localhost/内部IP)":"Internal SSRF (localhost/internal IP)",
 "オープンリダイレクト(=//)":"Open redirect (=//)",
 "要求":"Requests","スロットル":"Throttle","ブロック":"Block","BAN中":"Banned","漏洩":"Leaks",
 "有効":"on","無効":"off","計":"total","種別":"types","系統":"families","前":"ago",
 "インターネット(public)を一括遮断します。よろしいですか?":"Block all public (internet) traffic. Are you sure?",
 "(CHICKENNET_DECEPTION 未設定 = 偽装なし)":"(CHICKENNET_DECEPTION unset = no deception)",
 "サンプル攻撃者":"Sample attacker","から見える偽装(隣接窓で必ず別系統):":"sees this deception (adjacent windows always differ):",
 "残":"remaining ","組込":"built-in","カスタム":"custom","危険除外":"unsafe-excluded",
 "(兆候なし)":"(no indicators)","本機":"This host","失敗":"failed",
 "改竄検知":"Tamper detection","直近":"Last"};
let LANG="ja";try{LANG=localStorage.getItem("fn-lang")||"ja"}catch(e){}
function tr(s){if(LANG!=="en"||s==null)return s;const k=String(s).trim();return JA2EN[k]!==undefined?JA2EN[k]:s;}
function applyStatic(){
 document.documentElement.lang=LANG;
 document.querySelectorAll(".phead h2,.phead .meta:not([id]),.pbody .meta:not([id]),button:not(.iconbtn),#dlpact option,#paranoia option").forEach(el=>{
  if(el.children.length)return;
  if(el.dataset.o===undefined)el.dataset.o=el.textContent.trim();
  el.textContent=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 const labels=[...document.querySelectorAll(".controls label.sw")];
 ["dlp","sech","throttle","subnetdef"].forEach(id=>{const e=$(id)&&$(id).closest("label");if(e)labels.push(e);});
 labels.forEach(el=>{const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=" "+(LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o);});
 document.querySelectorAll(".sect").forEach(el=>{const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 document.querySelectorAll("input[placeholder]").forEach(el=>{
  if(el.dataset.o===undefined)el.dataset.o=el.placeholder;
  el.placeholder=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
}
function setLang(l){LANG=l;try{localStorage.setItem("fn-lang",l)}catch(e){}
 $("lang").textContent=l==="en"?"日本語":"EN";applyStatic();
 try{refresh()}catch(e){}try{refreshPro()}catch(e){}}
$("lang").onclick=()=>setLang(LANG==="en"?"ja":"en");
/* テーマ */
function setTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem("fn-theme",t)}catch(e){}
 $("theme").textContent=t==="light"?"🌙":"☀️";
 $("theme").title=t==="light"?"ダークに切替":"ライトに切替";try{refreshPro()}catch(e){}}
(function(){let t;try{t=localStorage.getItem("fn-theme")}catch(e){}
 if(!t)t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";setTheme(t);})();
$("theme").onclick=()=>setTheme(document.documentElement.dataset.theme==="light"?"dark":"light");
$("lang").textContent=LANG==="en"?"日本語":"EN";applyStatic();
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
async function refresh(){
 let s;try{s=await guardedFetch("/api/state")}catch(e){
  if(isAuthFail(e)){markAuthError();}else{$("conn").className="pill bad";$("connt").textContent=tr("接続不可");}
  return}
 $("conn").className="pill ok";$("connt").textContent=tr("接続中");
 $("fw").checked=s.firewall.enabled;$("sh").checked=s.shield.cfg.enabled;
 const m=s.shield_metrics;
 $("cards").innerHTML=[["要求",m.requests,"i-blue"],["許可",m.allow,"i-green"],["スロットル",m.throttle,"i-amber"],
   ["ブロック",m.block,"i-red"],["BAN中",m.active_bans,"i-red"],
   ["漏洩",m.dlp_leak,"i-red"]]
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
   +` onchange="post('/api/shield/optional_sig',{name:'${esc(n)}',on:this.checked}).then(refresh)">`
   +` ${esc(tr(OPTL[n]||n))}</label></div>`).join("")||'<div class="empty">'+tr("なし")+'</div>';
 // パス別レート制限(per-path token bucket): 現在のルール一覧 + 削除
 curPathLimits=dc.path_limits||[];
 $("prlmeta").textContent=curPathLimits.length?(curPathLimits.length+" "+tr("ルール")):tr("無効");
 $("pathlimits").querySelector("tbody").innerHTML=curPathLimits.map((r,i)=>
   `<tr><td><span class="num">${esc(r.path)}</span></td><td class="num">${r.rate}/s</td>`
   +`<td class="num">burst ${r.burst}</td>`
   +`<td><button class="ghost" onclick="removePathLimit(${i})">${tr("削除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("ルールなし")+'</td></tr>';
 // レート/メソッド/分散(運用): #24/#25/#26 のトグルと値。free-text は編集中クロバー回避。
 $("throttle").checked=dc.throttle_response!==false;
 $("subnetdef").checked=!!dc.subnet_defense;
 setIfBlur("retryaft",String(dc.throttle_retry_after!=null?dc.throttle_retry_after:1));
 setIfBlur("subthr",String(dc.subnet_threshold!=null?dc.subnet_threshold:8));
 setIfBlur("blockmeth",(dc.blocked_methods||[]).join(","));
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
 $("bans").querySelector("tbody").innerHTML=(s.shield.bans||[]).map(b=>
   `<tr><td class="num">${esc(b.ip)}</td><td class="num">${esc(tr("残"))}${Math.round(b.remain_sec)}s</td>
   <td><span class="badge ${b.score>40?"danger":"warn"}">score ${b.score}</span></td>
   <td><button class="ghost" onclick="unban('${esc(b.ip)}')">${tr("解除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("BAN なし")+'</td></tr>';
 $("top").textContent=(s.top||[]).map(t=>`${(t.ip+"").padStart(15)}  score ${String(t.score).padStart(4)}  win ${t.reqs_window}  hits ${t.hits} ${t.banned?"BAN":""}`).join("\n")||tr("(なし)");
 $("events").innerHTML=(s.events||[]).slice(-60).reverse().map(e=>
   `<div class="frow"><span class="time">${tm(e.ts)}</span><span class="badge ${sev(e.kind)}">${esc(e.kind)}</span>`
   +`<span class="desc num">${esc(e.ip||"")}</span></div>`).join("")||'<div class="empty">'+tr("イベントなし")+'</div>';
 // ゾーン policy=prompt の保留接続(#2): アピール一覧と同じ承認/拒否UXで、行き止まりを解消
 $("fwpending").querySelector("tbody").innerHTML=((s.firewall||{}).pending||[]).map(p=>
   `<tr><td class="num">${esc(p.ip)}</td><td><span class="badge info">${esc(p.zone)}</span></td>
   <td class="num">${tm(p.ts)}</td>
   <td><button onclick="resolvePending('${esc(p.id)}',true)">${tr("承認")}</button>
   <button class="red" onclick="resolvePending('${esc(p.id)}',false)">${tr("却下")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("承認待ちなし")+'</td></tr>';
}
$("fw").onchange=e=>post("/api/firewall/toggle",{on:e.target.checked}).then(refresh);
$("sh").onchange=e=>post("/api/shield/toggle",{on:e.target.checked}).then(refresh);
$("dlp").onchange=e=>post("/api/shield/config",{dlp_enabled:e.target.checked}).then(refresh);
$("dlpact").onchange=e=>post("/api/shield/config",{dlp_action:e.target.value}).then(refresh);
$("sech").onchange=e=>post("/api/shield/config",{sec_headers_enabled:e.target.checked}).then(refresh);
$("paranoia").onchange=e=>post("/api/shield/paranoia",{level:parseInt(e.target.value)}).then(refresh);
$("throttle").onchange=e=>post("/api/shield/config",{throttle_response:e.target.checked}).then(refresh);
$("retryaft").onchange=e=>post("/api/shield/config",{throttle_retry_after:parseInt(e.target.value)||0}).then(refresh);
$("subnetdef").onchange=e=>post("/api/shield/config",{subnet_defense:e.target.checked}).then(refresh);
$("subthr").onchange=e=>post("/api/shield/config",{subnet_threshold:parseInt(e.target.value)||1}).then(refresh);
async function refreshPro(){
 try{const s=(await guardedFetch("/api/series")).series||[];drawChart(s);
  drawSpark("leaktrend",s.map(x=>x.dlp_leak||0));
  drawSpark("sigtrend",s.map(x=>x.sig_total||0));
  drawSpark("pubtrend",s.map(x=>x.pub||0));}catch(e){if(isAuthFail(e))markAuthError();}
 try{const ap=(await guardedFetch("/api/appeals")).appeals||[];
  $("appeals").querySelector("tbody").innerHTML=ap.map(a=>
   `<tr><td class="num">${esc(a.ip)}</td><td><span class="badge ${a.status==="pending"?"warn":"muted"}">${esc(a.status)}</span></td>
   <td>${esc((a.reason||"").slice(0,40))}</td>
   <td>${a.status==="pending"?`<button onclick="resolveAppeal('${esc(a.ip)}',true)">${tr("承認")}</button>
   <button class="red" onclick="resolveAppeal('${esc(a.ip)}',false)">${tr("却下")}</button>`:""}</td></tr>`
  ).join("")||'<tr><td colspan="4" class="empty">'+tr("申立なし")+'</td></tr>';}catch(e){if(isAuthFail(e))markAuthError();}
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
}
async function refreshDeception(){
 let d;try{d=await guardedFetch("/api/deception")}catch(e){if(isAuthFail(e))markAuthError();return}
 $("decepstat").innerHTML=`<span class="badge ${d.enabled?"info":"muted"}">${tr(d.enabled?"有効":"無効")}</span>`
   +` ${tr("系統")} ${d.family_count||0}`;
 if(!d.enabled){$("deception").textContent=tr("(CHICKENNET_DECEPTION 未設定 = 偽装なし)")+"\n"+tr("系統")+": "
   +(d.families||[]).join(", ");return}
 const rows=(d.preview||[]).map(p=>
   `${LANG==="en"?"win":"窓"}+${p.window}: ${(p.server||"").padEnd(24)} [${p.family}]`+(p.companions.length?"  "+p.companions.join("  "):""));
 $("deception").textContent=tr("サンプル攻撃者")+" "+d.sample_seed+" "+tr("から見える偽装(隣接窓で必ず別系統):")+"\n"
   +rows.join("\n");
}
async function refreshSigs(){
 let d;try{d=await guardedFetch("/api/shield/signatures")}catch(e){if(isAuthFail(e))markAuthError();return}
 $("sigmeta").textContent=`${tr("組込")} ${(d.builtin||[]).length} · ${tr("カスタム")} ${d.custom_active||0}`
   +(d.custom_blocked?` · ${tr("危険除外")} ${d.custom_blocked}`:"");
 $("customsigs").querySelector("tbody").innerHTML=(d.custom||[]).map(c=>
   `<tr><td class="num">${esc(c.name)}</td><td><span class="num">${esc((c.pattern||"").slice(0,48))}</span></td>`
   +`<td><button class="ghost" data-signame="${esc(c.name)}">${tr("削除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="3" class="empty">'+tr("カスタムなし")+'</td></tr>';
}
$("customsigs").addEventListener("click",e=>{
 const b=e.target.closest("button[data-signame]");
 if(b)removeSig(b.dataset.signame);
});
async function addSig(){
 const name=$("signame").value.trim(),pattern=$("sigpat").value;
 if(!name||!pattern){$("sigerr").textContent=tr("名前とパターンを入力");return;}
 const r=await post("/api/shield/sig_add",{name,pattern});
 $("sigerr").textContent=r.ok?"":("✗ "+(r.error||tr("失敗")));
 if(r.ok){$("signame").value="";$("sigpat").value="";}
 refreshSigs();
}
function removeSig(name){post("/api/shield/sig_remove",{name}).then(refreshSigs);}
let curPathLimits=[];
async function addPathLimit(){
 const path=$("prpath").value.trim(),rate=parseFloat($("prrate").value),burst=parseFloat($("prburst").value);
 if(!path||!(rate>0)){$("prerr").textContent=tr("パスと毎秒(>0)を入力");return;}
 const rule={path,rate};if(burst>0)rule.burst=burst;
 const r=await post("/api/shield/path_limits",{rules:curPathLimits.concat([rule])});
 $("prerr").textContent=r.ok?"":("✗ "+(r.error||tr("失敗")));
 if(r.ok){$("prpath").value="";$("prrate").value="";$("prburst").value="";}
 refresh();
}
function removePathLimit(i){
 post("/api/shield/path_limits",{rules:curPathLimits.filter((_,j)=>j!==i)}).then(refresh);
}
function setIfBlur(id,val){const e=$(id);if(e&&document.activeElement!==e)e.value=val;}  // 編集中は上書きしない
function saveBlockedMethods(){
 const m=$("blockmeth").value.split(",").map(s=>s.trim()).filter(Boolean);
 post("/api/shield/blocked_methods",{methods:m}).then(refresh);
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
 if(banned){post("/api/shield/unban",{ip}).then(refreshPro);}
 else{post("/api/firewall/rule",{net:ip,action:"deny"}).then(refreshPro);}
}
function globalBlock(on){if(on&&!confirm(tr("インターネット(public)を一括遮断します。よろしいですか?")))return;
 post("/api/global_block",{on}).then(()=>{refresh();refreshPro();});}
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
function resolveAppeal(ip,ok){post("/api/appeal/resolve",{ip,approve:ok}).then(()=>{refresh();refreshPro();})}
function resolvePending(id,ok){post("/api/firewall/resolve",{id,approve:ok}).then(()=>{refresh();refreshPro();})}
function unban(ip){post("/api/shield/unban",{ip}).then(refresh)}
function ban(){post("/api/shield/ban",{ip:$("banip").value}).then(refresh)}
function rule(a){post("/api/firewall/rule",{net:$("ruleip").value,action:a}).then(refresh)}
async function edge(){const t=await (await fetch("/api/edge",{headers:H})).text();
 const u=URL.createObjectURL(new Blob([t]));const a=document.createElement("a");a.href=u;a.download="chickennet_edge.conf";a.click()}
addEventListener("resize",()=>{try{refreshPro()}catch(e){}});
refresh();refreshPro();setInterval(refresh,2000);setInterval(refreshPro,2000);
</script></body></html>"""
