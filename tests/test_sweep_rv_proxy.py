"""
test_sweep_rv_proxy.py — 前衛プロキシの見直し(独立レビュー)で見つかった退行の回帰(sweep: rv_proxy 群・Lite)。
====================================================================================
· #10 Expect: 100-continue を付けて 100 を待つクライアント(aiohttp・Node 等)は、本文走査の読取が
      head_timeout(既定 10 秒)で切れて黙って切断され、backend に何も届かなかった(前版は 100 が
      返って転送された)。本文を 64KiB 読み切る前に 10 秒の間が 1 度空くだけでも同じく切れた。
· #32 オープンリダイレクト判定が IPv6 リテラルの Host を '[2001' に切り詰めて比べ、自サイトへの
      リダイレクトを外部扱いした。open_redirect_allow の IPv6 も一致しなかった。
· #33 Java HttpURLConnection の既定 Accept(text/html, image/gif, … */*; q=.2)をブラウザ扱いし、
      API クライアントへ JSON ではなく HTML の拒否ページを返した。
· #34 単一値ヘッダの重複(400)が mode=audit(記録のみ)でも遮断していた。
(#11 確認ページのループはフル版のみ=Lite に PoW チャレンジは無い。)
実通信(127.0.0.1・ポート 0)と _scan_request_body / _handle の直接駆動で確かめる。
"""
import asyncio
import contextlib
import json
import socket
import tempfile
import threading
import time

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import (AsyncEdgeGuard, _redirect_violation_host,
                                             _wants_html)
from guard_support import stop_guard_owned


# ── 共通ヘルパ ──────────────────────────────────────────────────────────────
@contextlib.contextmanager
def _shield(**cfg):
    """隔離した NetShield(既定で有効)/ AppFirewall をプロセス共有シングルトンへ差し込む。"""
    osh, ofw = ND._SHIELD, FW._FW
    with tempfile.TemporaryDirectory() as d:
        sh = ND.NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg.update(cfg)
        ND._SHIELD = sh
        FW._FW = FW.AppFirewall(state_dir=d)
        try:
            yield sh
        finally:
            ND._SHIELD, FW._FW = osh, ofw


_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class _Backend:
    """検査済み HTTP head と宣言済み CL 本文を読み切ってから固定応答を返す。"""

    def __init__(self):
        self.got = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self._srv.settimeout(0.1)
        self.port = self._srv.getsockname()[1]
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        c.settimeout(2.0)
        data = bytearray()
        try:
            while b"\r\n\r\n" not in data and len(data) < 262144:
                ch = c.recv(65536)
                if not ch:
                    break
                data.extend(ch)
            head, sep, rest = bytes(data).partition(b"\r\n\r\n")
            if sep:
                lengths = [line.split(b":", 1)[1].strip()
                           for line in head.split(b"\r\n")[1:]
                           if line.lower().startswith(b"content-length:")]
                count = int(lengths[0]) if lengths else 0
                body = bytearray(rest[:count])
                while len(body) < count:
                    ch = c.recv(min(65536, count - len(body)))
                    if not ch:
                        break
                    body.extend(ch)
                data = bytearray(head + sep + body)
        except OSError:
            pass
        self.got.append(bytes(data))
        try:
            c.sendall(_OK)
        except OSError:
            pass
        finally:
            c.close()

    def saw(self) -> bytes:
        return b"".join(self.got)

    def close(self):
        self._stop.set()
        self._t.join(2)
        self._srv.close()


@contextlib.contextmanager
def _guard(backend, **kw):
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                       listen_host="127.0.0.1", listen_port=0, **kw)
    r = g.start()
    assert r.get("ok"), r
    try:
        yield g
    finally:
        stop_guard_owned(g)


def _read_all(c) -> bytes:
    out = b""
    try:
        while True:
            ch = c.recv(65536)
            if not ch:
                break
            out += ch
    except OSError:
        pass
    return out


class _R:
    """固定のチャンクを順に返す reader(delay 秒待ってから最初のチャンクを返せる)。"""

    def __init__(self, *chunks, delay=0.0):
        self._q = [c for c in chunks if c]
        self._delay = delay

    async def read(self, n=65536):
        if self._delay:
            d, self._delay = self._delay, 0.0
            await asyncio.sleep(d)
        if not self._q:
            return b""
        c = self._q.pop(0)
        if len(c) > n:
            self._q.insert(0, c[n:])
            c = c[:n]
        return c


class _W:
    def __init__(self, ip="198.51.100.70"):
        self.buf, self.closed, self._ip = b"", False, ip

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def get_extra_info(self, k, default=None):
        return (self._ip, 5555) if k == "peername" else default


def _drive(req: bytes, ip="198.51.100.71", port=1, **guard_kw) -> bytes:
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=port, **guard_kw)
    w = _W(ip)
    asyncio.run(g._handle(_R(req), w))
    assert w.closed
    return w.buf


def _split(raw: bytes):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs.setdefault(k.strip().lower().decode("latin-1"), []).append(
            v.strip().decode("latin-1"))
    return lines[0].decode("latin-1"), hdrs, body


def _req(acc: bytes, path=b"/page", extra=b"", method=b"GET", body=b"",
         ua=b"Mozilla/5.0") -> bytes:
    return (method + b" " + path + b" HTTP/1.1\r\nHost: h\r\nUser-Agent: " + ua + b"\r\n"
            + acc + extra + b"\r\n" + body)


# ── #10: Expect: 100-continue ───────────────────────────────────────────────
_EXPECT_HEAD = (b"POST /api HTTP/1.1\r\nHost: app.example\r\nUser-Agent: rv-client/1\r\n"
                b"Content-Type: application/json\r\nExpect: 100-continue\r\n"
                b"Content-Length: 9\r\n\r\n")
_EXPECT_BODY = b'{"k":"v"}'


def test_r10_expect_100_continue_client_gets_interim_and_request_completes():
    """100 を待つクライアントへ DuckNet が 100 Continue を返し、本文を走査して転送する。
    backend へは Expect を外して渡す(100 を二重に返させない)。待ちは head_timeout より長くする。"""
    be = _Backend()
    try:
        with _shield(), _guard(be, head_timeout=1.0) as g:
            c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=5)
            try:
                c.sendall(_EXPECT_HEAD)
                c.settimeout(3.0)                     # head_timeout(1 秒)より長く 100 を待つ
                t0 = time.time()
                first = b""
                try:
                    first = c.recv(65536)
                except OSError:
                    pass
                waited = time.time() - t0
                c.settimeout(5.0)
                try:
                    c.sendall(_EXPECT_BODY)
                except OSError:
                    pass
                resp = first + _read_all(c)
            finally:
                c.close()
        time.sleep(0.1)
        saw = be.saw()
    finally:
        be.close()
    assert first.startswith(b"HTTP/1.1 100 Continue\r\n\r\n"), (first[:60], waited)
    assert waited < 2.5, waited                       # クライアントが待ちを諦める前に届いた
    assert resp.count(b"100 Continue") == 1, resp
    assert b"HTTP/1.1 200 OK" in resp and resp.endswith(b"ok"), resp
    head, _, body = saw.partition(b"\r\n\r\n")
    assert body == _EXPECT_BODY, saw
    assert b"expect:" not in head.lower(), head


def _scan(buf, reader, writer=None, ctx=None, guard_kw=None, **cfg):
    with _shield(**cfg):
        g = AsyncEdgeGuard(**(guard_kw or {}))

        async def go():
            kw = {} if writer is None else {"writer": writer}
            return await g._scan_request_body(buf, reader, "198.51.100.73", "/api", ctx, **kw)

        return asyncio.run(go()), g


def test_r10_interim_100_only_when_the_client_is_waiting_for_it():
    """100 を返すのは HTTP/1.1 以上で Expect: 100-continue があり、本文が未完了のときだけ。
    HTTP/1.0 の Expect は無視する。走査が本文を読まない場合は上位の転送器が 100 を返す。"""
    w, ctx = _W(), {}
    (extra, blocked), _ = _scan(_EXPECT_HEAD, _R(_EXPECT_BODY), w, ctx)
    assert w.buf == b"HTTP/1.1 100 Continue\r\n\r\n" and ctx.get("continued"), (w.buf, ctx)
    assert extra == _EXPECT_BODY and blocked is False, (extra, blocked)
    w, ctx = _W(), {}
    (extra, blocked), _ = _scan(_EXPECT_HEAD + _EXPECT_BODY, _R(), w, ctx)
    assert w.buf == b"" and not ctx.get("continued") and blocked is False, (w.buf, ctx)
    w, ctx = _W(), {}
    (extra, blocked), _ = _scan(_EXPECT_HEAD.replace(b"HTTP/1.1", b"HTTP/1.0"),
                                _R(_EXPECT_BODY), w, ctx)
    assert w.buf == b"" and not ctx.get("continued"), (w.buf, ctx)
    w, ctx = _W(), {}
    (extra, blocked), _ = _scan(_EXPECT_HEAD, _R(_EXPECT_BODY), w, ctx,
                                body_scan_enabled=False, upload_scan_enabled=False,
                                graphql_enabled=False)
    assert w.buf == b"" and (extra, blocked) == (b"", False), (w.buf, extra, blocked)


def test_r10_scan_waits_through_a_gap_shorter_than_body_max_sec():
    """本文の途中で head_timeout より長い間が 1 度空いても、総受信時間(body_max_sec)内なら
    切断せずに読み続ける(以前は 1 回の間で『総時間超過』扱いになり、黙って切断+加点した)。"""
    buf = (b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n"
           b"Content-Length: 5\r\n\r\n")
    (extra, blocked), g = _scan(buf, _R(b"hello", delay=0.6), guard_kw={"head_timeout": 0.2},
                                body_scan_enabled=True, body_timeout_enabled=True, body_max_sec=5)
    assert (extra, blocked) == (b"hello", False), (extra, blocked)
    assert g.metrics.get("slow_body", 0) == 0, g.metrics
    t0 = time.time()
    (extra, blocked), g = _scan(buf, _R(b"hello", delay=3.0), guard_kw={"head_timeout": 10.0},
                                body_scan_enabled=True, body_timeout_enabled=True,
                                body_max_sec=0.3)
    assert blocked == "timeout" and g.metrics.get("slow_body", 0) == 1, (blocked, g.metrics)
    assert time.time() - t0 < 2.5


# ── #32: IPv6 リテラルのホスト比較 ─────────────────────────────────────────────
def _viol(req_host, loc, allow=None):
    return _redirect_violation_host("HTTP/1.1 302 Found", ["Location: " + loc], req_host, allow)


def test_r32_ipv6_literal_same_site_redirect_is_not_flagged():
    """Host が IPv6 リテラル([..]:port)のとき、自サイトへのリダイレクトを外部扱いしない。"""
    assert _viol("[2001:db8::1]:8080", "http://[2001:db8::1]:8080/next") == ""
    assert _viol("[2001:db8::1]", "http://[2001:db8::1]/next") == ""
    assert _viol("[2001:DB8::1]:8080", "https://[2001:db8:0::1]/next") == ""
    assert _viol("[2001:db8::1]:8080", "http://[2001:db8::2]/next") == "[2001:db8::2]"
    assert _viol("app.example:8443", "https://app.example:8443/next") == ""
    assert _viol("app.example", "https://other.example/") == "other.example"
    assert _viol("app.example", "/sso?next=https://other.example/") == ""


def test_r32_ipv6_allow_entries_match():
    """open_redirect_allow の IPv6 は角括弧つき・無し・ポートつきのどれで書いても一致する。"""
    for entry in ("[2001:db8::2]", "2001:db8::2", "[2001:db8::2]:443", "2001:DB8:0::2"):
        assert _viol("app.example", "http://[2001:db8::2]/next", [entry]) == "", entry
    assert _viol("app.example", "http://[2001:db8::3]/next", ["[2001:db8::2]"]) == "[2001:db8::3]"
    assert _viol("app.example", "https://login.example/x", ["login.example:443"]) == ""


# ── #33: ブラウザの画面遷移だけを HTML 扱い ───────────────────────────────────
_JAVA_ACCEPT = "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"


def _h(accept=None, ua=None, *extra):
    lines = [b"GET / HTTP/1.1", b"Host: h"]
    if ua is not None:
        lines.append(b"User-Agent: " + ua.encode())
    if accept is not None:
        lines.append(b"Accept: " + accept.encode())
    lines += [e.encode() for e in extra]
    return b"\r\n".join(lines) + b"\r\n\r\n"


def test_r33_java_default_accept_is_not_a_browser():
    """Java HttpURLConnection の既定 Accept は API クライアント=JSON のまま。"""
    assert _wants_html(_h(_JAVA_ACCEPT, "Java/17.0.2")) is False
    assert _wants_html(_h(_JAVA_ACCEPT)) is False
    assert _wants_html(_h("text/html", "curl/8.4.0")) is False
    assert _wants_html(_h("text/html", "python-requests/2.31")) is False
    assert _wants_html(_h("application/problem+json, text/html;q=0.1", "Mozilla/5.0")) is False
    assert _wants_html(_h("application/vnd.api+json, text/html;q=0.5", "Mozilla/5.0")) is False


def test_r33_browser_navigation_still_gets_html():
    """ブラウザの画面遷移(xhtml を含む Accept・Sec-Fetch の navigate/document・ブラウザの UA +
    text/html)は HTML。"""
    nav = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    assert _wants_html(_h(nav)) is True
    assert _wants_html(_h(nav, "Java/17.0.2")) is True
    assert _wants_html(_h("text/html", None, "Sec-Fetch-Mode: navigate")) is True
    assert _wants_html(_h("text/html", None, "Sec-Fetch-Dest: document")) is True
    assert _wants_html(_h("text/html", "Mozilla/5.0 (X11; Linux x86_64)")) is True
    assert _wants_html(_h("application/json, text/html;q=0.5", "Mozilla/5.0")) is False
    assert _wants_html(_h("text/html;q=0", "Mozilla/5.0")) is False
    assert _wants_html(_h("*/*", "Mozilla/5.0")) is False
    assert _wants_html(_h(None, "Mozilla/5.0")) is False


def test_r33_java_client_gets_rate_limit_json_end_to_end():
    """429 も、Java の既定 Accept には従来どおりの JSON を返す。"""
    req = _req(b"Accept: " + _JAVA_ACCEPT.encode() + b"\r\n", path=b"/api/items",
               ua=b"Java/17.0.2")
    with _shield() as sh:
        # _drive の模擬 peer は public IP。既定 ON の ACL をこの IP だけ通し、
        # 429 の本文形式まで到達させる。
        assert FW._FW.add_rule("198.51.100.71/32", "allow")["ok"]
        sh.set_path_limits([{"path": "/api/items", "rate": 0.001, "burst": 1}])
        _drive(req)
        status, hdrs, body = _split(_drive(req))
    assert status.startswith("HTTP/1.1 429"), status
    assert hdrs["content-type"][0].startswith("application/json"), hdrs
    assert json.loads(body)["retry_after"] == 1, body


# ── #34: mode=audit では重複した単一値ヘッダを記録だけする ───────────────────────
_DUP = (b"GET /api/items HTTP/1.1\r\nHost: app.example\r\nUser-Agent: curl/8\r\n"
        b"X-API-Key: k1\r\nX-API-Key: k1\r\n\r\n")


def test_r34_audit_mode_records_duplicate_headers_and_forwards():
    """mode=audit(記録のみ)では 400 にせず backend へ転送し、『遮断するはずだった』を記録する。"""
    be = _Backend()
    try:
        with _shield(mode="audit") as sh, _guard(be) as g:
            c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=5)
            try:
                c.sendall(_DUP)
                resp = _read_all(c)
            finally:
                c.close()
            evs = sh.events(200)
            m = dict(g.metrics)
        saw = be.saw()
    finally:
        be.close()
    assert resp.startswith(b"HTTP/1.1 200 OK"), resp[:80]
    assert saw.count(b"X-API-Key: k1") == 2, saw
    assert any(e.get("kind") == "audit" and e.get("rule") == "dup_header"
               and e.get("would") == "block" for e in evs), evs
    assert m.get("dup_header") == 1 and m.get("dropped", 0) == 0, m


def test_r34_enforce_mode_still_rejects_duplicate_headers():
    """enforce(既定)では従来どおり 400 で拒否し backend へ流さない。"""
    with _shield():
        assert FW._FW.add_rule("198.51.100.71/32", "allow")["ok"]
        status, _, body = _split(_drive(_DUP))
    assert status.startswith("HTTP/1.1 400"), status
    assert body == b'{"error":"conflicting header values"}', body
