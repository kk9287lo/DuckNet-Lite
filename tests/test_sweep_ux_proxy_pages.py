"""
test_sweep_ux_proxy_pages.py — 訪問者のブラウザへ返す拒否応答を『読める案内ページ』にする回帰
(sweep: ux_proxy_pages 群・Lite 版)。
====================================================================================
ゲートウェイは 429 / 502 / 400 / 413 / 415 / 431 / 解除リクエスト(BAN 無し)を、ブラウザにも
生の JSON で返していた。人には何が起きたのかも次に何をすればよいのかも分からなかった。

· ブラウザの画面遷移(Accept に text/html)には、何が起きたか・次に何をすればよいかを書いた
  自己完結の HTML を返す(状態コードとデセプション等のヘッダは従来どおり)。
· API クライアント(Accept: application/json・*/*・Accept 無し)には従来と同一の JSON を返す。
(Lite 版には PoW チャレンジとライセンス確認が無いので、その 2 つは対象外。)
"""
import asyncio
import contextlib
import os
import re
import socket
import tempfile

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services import proxy as P
from dataplane.engine.services.proxy import AsyncEdgeGuard

# ブラウザが画面遷移で送る Accept(Chrome/Firefox と同形)。
_BROWSER = b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
_JSONACC = b"Accept: application/json\r\n"
_ANY = b"Accept: */*\r\n"                      # curl の既定
_NONE = b""                                    # Accept 無し


# ── 共通ヘルパ ──────────────────────────────────────────────────────────────
class _R:
    def __init__(self, *chunks):
        self._q = [c for c in chunks if c]

    async def read(self, n=65536):
        if not self._q:
            return b""
        c = self._q.pop(0)
        if len(c) > n:
            self._q.insert(0, c[n:])
            c = c[:n]
        return c


class _W:
    def __init__(self, ip):
        self.buf, self.closed, self._ip = b"", False, ip

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def get_extra_info(self, k, default=None):
        return (self._ip, 5555) if k == "peername" else default


@contextlib.contextmanager
def _env(**kv):
    """環境変数を一時的に差し替える(None=削除)。"""
    old = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def _shield(enabled=True, **cfg):
    """隔離した NetShield / AppFirewall をプロセス共有シングルトンへ差し込む。"""
    osh, ofw = ND._SHIELD, FW._FW
    with tempfile.TemporaryDirectory() as d:
        sh = ND.NetShield(state_dir=d)
        FW._FW = FW.AppFirewall(state_dir=d)
        try:
            assert FW._FW.add_rule("198.51.100.61/32", "allow")["ok"]
            assert sh.set_config(enabled=bool(enabled), **cfg)["ok"]
            ND._SHIELD = sh
            yield sh
        finally:
            ND._SHIELD, FW._FW = osh, ofw


@contextlib.contextmanager
def _listening():
    """接続だけ受ける backend(本文検査で拒否される要求は何も届かない)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    try:
        yield s.getsockname()[1]
    finally:
        s.close()


def _drive(req: bytes, ip="198.51.100.61", port=1, **guard_kw) -> bytes:
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=port, **guard_kw)
    w = _W(ip)
    # Directly driving _handle skips start(), which normally owns the signed
    # state directory before request-body staging can use it. Keep this test
    # seam under the same serving lease as a real listener.
    try:
        g._ensure_serving_lease()
        asyncio.run(g._handle(_R(req), w))
    finally:
        lease = g._serving_lease
        if lease is not None:
            if lease.held:
                flushed = g._finish_serving_lease()
                if not flushed:
                    g._close_serving_lease()  # isolated fixture teardown only
                assert flushed, "direct guard fixture failed to flush serving state"
            else:
                g._close_serving_lease()
    assert w.closed
    return w.buf


def _req(acc: bytes, path=b"/page", extra=b"", method=b"GET", body=b"") -> bytes:
    return (method + b" " + path + b" HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0\r\n"
            + acc + extra + b"\r\n" + body)


def _split(raw: bytes):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs.setdefault(k.strip().lower().decode("latin-1"), []).append(
            v.strip().decode("latin-1"))
    return lines[0].decode("latin-1"), hdrs, body


def _visible(html: str) -> str:
    """script/style を除いた、人が読む部分。"""
    return re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.S | re.I)


def _page(raw: bytes, code: str, *needles) -> str:
    """ブラウザ向け HTML 案内ページであること(生 JSON を見せない)を確かめて本文を返す。"""
    status, hdrs, body = _split(raw)
    assert status.startswith("HTTP/1.1 " + code), status
    assert hdrs["content-type"][0].startswith("text/html"), hdrs
    assert int(hdrs["content-length"][0]) == len(body)
    text = body.decode("utf-8")
    assert text.lower().startswith("<!doctype html>"), text[:60]
    vis = _visible(text)
    for bad in ('{"', '"ok"', '"error"', "defense", "retry_after"):
        assert bad not in vis, (bad, vis)
    for n in needles:
        assert n in vis, (n, vis)
    assert "UTC" in vis, vis                    # 管理者へ伝えられる発生時刻
    return text


def _json(raw: bytes, code: str) -> bytes:
    status, hdrs, body = _split(raw)
    assert status.startswith("HTTP/1.1 " + code), status
    assert hdrs["content-type"][0].startswith("application/json"), hdrs
    return body


# ── 各応答のシナリオ(acc = Accept 行) ───────────────────────────────────────
def _s431(acc):
    with _shield(enabled=False):
        return _drive(b"GET / HTTP/1.1\r\nHost: h\r\n" + acc + b"X-Pad: " + b"a" * 20000)


def _s400_framing(acc):
    with _shield(enabled=False):
        return _drive(_req(acc, extra=b"Host: h2\r\n"))


def _s400_conflict(acc):
    with _shield():
        return _drive(_req(acc, extra=b"Authorization: Bearer a\r\nAuthorization: Bearer b\r\n"))


def _s429(acc, ra=None):
    cfg = {} if ra is None else {"throttle_retry_after": ra}
    with _shield(**cfg) as sh:
        sh.set_path_limits([{"path": "/x", "rate": 0.001, "burst": 1}])
        _drive(_req(acc, path=b"/x"))                    # 1発目=バケツ消費(allow→502)
        return _drive(_req(acc, path=b"/x"))             # 2発目=throttle


def _s502(acc):
    with _shield(enabled=False):
        return _drive(_req(acc))


def _s413(acc):
    body = b'{"query":"{ me { id } }","variables":{"note":"' + b"x" * 1500 + b'"}}'
    extra = (b"Content-Type: application/json\r\nContent-Length: "
             + str(len(body)).encode() + b"\r\n")
    with _listening() as port, _shield(graphql_enabled=True, graphql_max_bytes=1024):
        return _drive(_req(acc, path=b"/graphql", method=b"POST", extra=extra, body=body),
                      port=port)


def _s415(acc):
    extra = b"Content-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: 3\r\n"
    with _listening() as port, _shield(body_scan_enabled=True):
        return _drive(_req(acc, method=b"POST", extra=extra, body=b"abc"), port=port)


def _s400_chunked(acc):
    extra = b"Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n"
    with _listening() as port, _shield(enabled=False, body_scan_enabled=False):
        return _drive(_req(acc, method=b"POST", extra=extra, body=b"zz\r\nabc\r\n0\r\n\r\n"),
                      port=port)


def _s_appeal(acc):
    with _shield():
        return _drive(_req(acc, path=b"/__ducknet_appeal__"))


# 従来(この変更の前)と 1 バイトも違わない JSON 本文。
_OLD = [
    ("431", _s431, b'{"ok":false,"error":"header too large"}'),
    ("400", _s400_framing, b'{"error":"ambiguous message framing"}'),
    ("400", _s400_conflict, b'{"error":"conflicting header values"}'),
    ("429", _s429, b'{"ok": false, "defense": "rate-limit", "retry_after": 1}'),
    ("502", _s502, b'{"ok": false, "error": "backend unreachable"}'),
    ("413", _s413, b'{"ok":false,"error":"graphql request too large"}'),
    ("415", _s415, b'{"ok":false,"error":"unsupported content-encoding"}'),
    ("400", _s400_chunked, b'{"error":"malformed chunked body"}'),
    ("403", _s_appeal, b'{"error":"no active ban for this address"}'),
]


# ── API クライアントには従来どおりの JSON ─────────────────────────────────────
def test_api_clients_still_get_the_identical_json():
    """Accept: application/json・*/*・Accept 無し・JSON 優先の混在は、従来と同一の JSON 本文。"""
    accs = (_JSONACC, _ANY, _NONE, b"Accept: application/json, text/html;q=0.5\r\n",
            b"Accept: text/html;q=0\r\n")
    with _env(DUCKNET_LANG="ja"):
        for code, fn, old in _OLD:
            for acc in accs:
                body = _json(fn(acc), code)
                assert body == old, (fn.__name__, acc, body)


# ── ブラウザには読める案内ページ ────────────────────────────────────────────
def test_browser_gets_plain_language_pages_ja():
    """各拒否応答で、ブラウザには『何が起きたか・次に何をすればよいか』の HTML(日本語)。"""
    with _env(DUCKNET_LANG="ja", DUCKNET_COVER=None):
        t = _page(_s431(_BROWSER), "431", "Cookie", "削除")
        assert "大きすぎ" in t
        _page(_s400_framing(_BROWSER), "400", "処理できません", "再読み込み")
        _page(_s400_conflict(_BROWSER), "400", "処理できません", "再読み込み")
        _page(_s502(_BROWSER), "502", "接続できません", "しばらく", "管理者")
        t = _page(_s413(_BROWSER), "413", "大きすぎ", "1 KB")             # 上限も添える
        assert "graphql" not in _visible(t).lower()
        _page(_s415(_BROWSER), "415", "形式", "圧縮")
        _page(_s400_chunked(_BROWSER), "400", "処理できません", "もう一度")
        _page(_s_appeal(_BROWSER), "403", "ブロックされていません", "再読み込み")


def test_browser_gets_plain_language_pages_en():
    """DUCKNET_LANG=en では英語(_block_page と同じ言語の選び方)。"""
    with _env(DUCKNET_LANG="en", DUCKNET_COVER=None):
        _page(_s502(_BROWSER), "502", "temporarily", "site administrator")
        _page(_s431(_BROWSER), "431", "cookies")
        t = _page(_s429(_BROWSER), "429", "Too many requests", "seconds")
        assert "lang='en'" in t
        _page(_s_appeal(_BROWSER), "403", "not currently blocked")


def test_rate_limit_page_retries_automatically():
    """429: N 秒後に再び使えること・自動で元の URL を再試行すること・手動の再試行リンク。"""
    with _env(DUCKNET_LANG="ja"):
        raw = _s429(_BROWSER, ra=7)
    t = _page(raw, "429", "7 秒", "自動")
    _, hdrs, _ = _split(raw)
    assert hdrs["retry-after"] == ["7"], hdrs                     # 既存ヘッダは保つ
    assert "http-equiv='refresh' content='7'" in t, t             # JS 無しでも 7 秒後に再読み込み
    assert "<script>" in t and "location.replace(location.href)" in t
    assert "href=''" in t                                         # 今すぐ再試行(同じ URL)


def test_size_limit_is_shown_in_plain_units_rounded_down():
    """413 に添える上限は人が読める単位で、実際より大きくは言わない(切り捨て)。"""
    assert P._human_size(500) == "500 B"
    assert P._human_size(1024) == "1 KB" and P._human_size(1500) == "1 KB"
    assert P._human_size(262144) == "256 KB"
    assert P._human_size(1 << 20) == "1 MB" and P._human_size(2044723) == "1.9 MB"


def test_deception_headers_and_status_are_kept_on_html_pages():
    """HTML にしても状態コードとデセプションの偽 Server ヘッダは従来どおり付く。"""
    with _env(DUCKNET_DECEPTION="1", DUCKNET_LANG="ja"):
        for fn, code in ((_s502, "502"), (_s400_framing, "400"), (_s429, "429")):
            raw = fn(_BROWSER)
            _page(raw, code)
            _, hdrs, _ = _split(raw)
            assert hdrs.get("server"), (fn.__name__, hdrs)
            assert hdrs.get("cache-control") == ["no-store"], hdrs


def test_cover_brand_hides_product_and_is_escaped():
    """DUCKNET_COVER は製品名を隠し、値は HTML エスケープして埋め込む。"""
    with _env(DUCKNET_COVER="a'b<c", DUCKNET_LANG="ja"):
        t = _page(_s502(_BROWSER), "502")
        assert "a&#x27;b&lt;c" in t and "a'b<c" not in t, t
        assert "DuckNet" not in t
