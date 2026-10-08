"""
test_sweep_proxy_request.py — 前衛プロキシの要求解析/応答加工の回帰(sweep: proxy_request 群)。
====================================================================================
· #16/#17/#57 同名ヘッダの連結(f3e5bd0)で単一値フィールドが壊れた退行
  (Authorization / X-API-Key / メソッド override)。
· #18 本文付き要求の後ろにパイプラインした第2要求が未検査で backend へ届いた。
· #58 連結 gzip(multi-member)の 2 個目以降が走査されなかった。
· #59 応答 head 加工が有効だと出口 DLP が応答ヘッダを走査しなかった。
· #60 1xx 中間応答(100/103)を『その応答』とみなし、最終応答の加工/採点が外れた。
· #61 '\\' やスラッシュ数の揺れを含む Location で外部リダイレクト判定をすり抜けた。
· #92 head のどこかに "upgrade" があるだけで応答の防御加工が全部外れた。
· #93 解けない Content-Encoding の 415 が NameError で送られず、dropped が二重計上された。
実通信(127.0.0.1・ポート 0)と _pipe の直接駆動で確かめる。
"""
import asyncio
import contextlib
import gzip
import socket
import tempfile
import threading
import time

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import (AsyncEdgeGuard, _location_host,
                                             _redirect_violation_host,
                                             inject_security_headers)
from test_jwt import _jwt


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
    """接続ごとに受信バイトを記録して固定応答を返す backend。Connection: close を *尊重しない*
    近似として、EOF か 1 秒無通信まで読み続ける(パイプライン第2要求が届いたかを観測できる)。"""

    def __init__(self, resp: bytes = _OK):
        self.resp = resp
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
        c.settimeout(1.0)
        data = b""
        try:
            while len(data) < 262144:
                ch = c.recv(65536)
                if not ch:
                    break
                data += ch
        except OSError:
            pass
        self.got.append(data)
        try:
            c.sendall(self.resp)
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
        g.stop()


def _exchange(g, parts, delay=0.05, timeout=5.0) -> bytes:
    """parts を順に送り、ガードが閉じるまで応答を読む。"""
    c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=timeout)
    try:
        for i, p in enumerate(parts):
            if i:
                time.sleep(delay)
            try:
                c.sendall(p)
            except OSError:
                break
        resp = b""
        try:
            while True:
                ch = c.recv(65536)
                if not ch:
                    break
                resp += ch
        except OSError:
            pass
        return resp
    finally:
        c.close()


def _through(parts, *, guard_kw=None, backend_resp=_OK, **cfg):
    """parts を 1 接続でガードへ流し、(backend が受け取った全バイト, 応答, metrics) を返す。"""
    be = _Backend(backend_resp)
    try:
        with _shield(**cfg), _guard(be, **(guard_kw or {})) as g:
            resp = _exchange(g, parts)
            m = dict(g.metrics)
        return be.saw(), resp, m
    finally:
        be.close()


class _Sink:
    """_pipe の送出先(client 側 writer)の代役。送られたバイトを貯める。"""

    def __init__(self):
        self.buf = bytearray()

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass

    def close(self):
        pass


def _run_pipe(chunks, *, setup=None, req_host="app.example", **cfg):
    """backend 応答 chunks を _pipe(scan=True)へ流し、client へ出たバイトと shield を返す。"""
    with _shield(**cfg) as sh:
        if setup:
            setup(sh)
        g = AsyncEdgeGuard()
        out = _Sink()

        async def go():
            r = asyncio.StreamReader()
            for c in chunks:
                r.feed_data(c)
            r.feed_eof()
            await g._pipe(r, out, scan=True, ip="203.0.113.70", tls=False,
                          req_host=req_host)

        asyncio.run(go())
        return bytes(out.buf), sh


# ── #16 / #17 / #57: 単一値ヘッダの重複 ──────────────────────────────────────
def test_c16_duplicate_authorization_alg_none_not_forwarded():
    """#16: Authorization を 2 本並べると連結値が JWT と認識されず、alg:none(無署名)
    トークンが backend へ素通りしていた(f3e5bd0 の退行)。"""
    tok = _jwt("none")
    req = (f"GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok}\r\n"
           f"Authorization: Bearer {tok}\r\n\r\n").encode()
    saw, resp, m = _through([req])
    assert b"/api" not in saw, "duplicated alg:none JWT reached the backend"
    assert resp.startswith(b"HTTP/1.1 400"), resp[:60]


def test_c16_single_authorization_behaviour_unchanged():
    # 1 本なら従来どおり: alg:none は遮断、正規の JWT は通す(誤遮断しない)。
    saw, _, _ = _through([(f"GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "
                           f"{_jwt('none')}\r\n\r\n").encode()])
    assert b"/api" not in saw
    saw, _, _ = _through([(f"GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "
                           f"{_jwt('RS256')}\r\n\r\n").encode()])
    assert b"/api" in saw


def test_c17_duplicate_or_mixed_method_override_not_forwarded():
    """#17: override 値が複数あると(同名重複・別名併用・カンマ列挙)、連結値や先頭の別名だけが
    検査され、backend が採る DELETE が blocked_methods をすり抜けていた。"""
    base = "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n"
    for v in ("X-HTTP-Method-Override: DELETE\r\nX-HTTP-Method-Override: DELETE\r\n",
              "X-HTTP-Method-Override: GET\r\nX-Method-Override: DELETE\r\n",
              "X-HTTP-Method-Override: DELETE, GET\r\n"):
        saw, _, _ = _through([(base + v + "\r\n").encode()],
                             blocked_methods=["TRACE", "DELETE"])
        assert b"/api" not in saw, v


def test_c17_single_method_override_behaviour_unchanged():
    base = "POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n"
    saw, _, _ = _through([(base + "X-HTTP-Method-Override: PUT\r\n\r\n").encode()],
                         blocked_methods=["TRACE", "DELETE"])
    assert b"/api" in saw                                   # 許可メソッドは通す
    saw, _, _ = _through([(base + "X-Method-Override: DELETE\r\n\r\n").encode()],
                         blocked_methods=["TRACE", "DELETE"])
    assert b"/api" not in saw                               # 単独の遮断メソッドは従来どおり


def test_c57_duplicate_authorization_does_not_rotate_cred_rate_key():
    """#57: 2 本目の Authorization を毎回変えると連結値のハッシュが変わり、同じ盗用キーの
    クレデンシャル単位レートが一度も発動しなかった(上限 3 に対し 6/6 通過)。"""
    be = _Backend()
    try:
        with _shield(cred_rate_enabled=True, cred_rate_limit=3), _guard(be) as g:
            for i in range(6):
                _exchange(g, [(f"GET /api HTTP/1.1\r\nHost: x\r\n"
                               f"Authorization: Bearer stolen-key\r\n"
                               f"Authorization: Bearer junk{i}\r\n\r\n").encode()])
        passed = sum(1 for d in be.got if b"/api" in d)
        assert passed <= 2, passed
    finally:
        be.close()


# ── #18: 本文付き要求の後ろのパイプライン第2要求 ─────────────────────────────
_SMUGGLE = b"GET /admin-secret HTTP/1.1\r\nHost: x\r\n\r\n"


def test_c18_pipelined_after_content_length_body_not_forwarded():
    """#18: 本文付き要求は buf 全体(本文の後ろの第2要求まで)を転送してから本文完了を
    判定していた。Content-Length: 0 を付けるだけで #46 の切り詰めも外れた。"""
    for scan in (True, False):
        saw, _, _ = _through([b"GET /benign HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
                              + _SMUGGLE], body_scan_enabled=scan)
        assert b"/benign" in saw and b"/admin-secret" not in saw, (scan, saw)
        saw, _, _ = _through([b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
                              + _SMUGGLE], body_scan_enabled=scan)
        assert saw.endswith(b"\r\n\r\nhello"), (scan, saw)  # 本文はちょうど宣言長で終わる


def test_c18_pipelined_after_chunked_body_not_forwarded():
    """#18: chunked は読取が終端 0\\r\\n\\r\\n で *ちょうど終わる* 時しか完了と見なさず、
    終端の後ろに第2要求が続くと全部を転送し、正規の送信者を slow_body 扱いまでしていた。"""
    req = (b"POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\n0\r\n\r\n" + _SMUGGLE)
    for scan in (True, False):
        saw, _, m = _through([req], guard_kw={"head_timeout": 2.0}, body_scan_enabled=scan)
        assert b"/admin-secret" not in saw, (scan, saw)
        assert saw.endswith(b"5\r\nhello\r\n0\r\n\r\n"), (scan, saw)
        assert m.get("slow_body", 0) == 0, (scan, m)


def test_c18_pipelined_after_streamed_chunked_body_not_forwarded():
    # 本文が複数パケットに分かれ、終端と第2要求が同じパケットで来る(有界転送の経路)。
    head = b"POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    for scan in (True, False):
        saw, _, _ = _through([head + b"5\r\nhello\r\n", b"3\r\nabc\r\n0\r\n\r\n" + _SMUGGLE],
                             guard_kw={"head_timeout": 2.0}, body_scan_enabled=scan)
        assert b"/admin-secret" not in saw, (scan, saw)
        assert saw.endswith(b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n"), (scan, saw)


def test_c18_chunk_data_resembling_terminator_is_forwarded_intact():
    # chunk データが偶然 '0\r\n\r\n' で終わるパケット境界を、本文終端と取り違えない
    # (旧実装はここで backend への転送を打ち切り、本文が欠けていた)。
    head = b"POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    saw, _, _ = _through([head + b"7\r\nab0\r\n\r\n", b"\r\n2\r\nzz\r\n0\r\n\r\n"],
                         guard_kw={"head_timeout": 2.0}, body_scan_enabled=False)
    assert saw.endswith(b"7\r\nab0\r\n\r\n\r\n2\r\nzz\r\n0\r\n\r\n"), saw


def test_c18_malformed_chunk_framing_not_forwarded():
    # 枠が壊れた chunked(サイズ行が 16 進でない)は、どこで終わるか backend と一致させられない。
    # 後続を未検査で流さない(本文走査が無効でも)。
    req = (b"POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\nzz\r\n" + _SMUGGLE)
    saw, _, _ = _through([req], guard_kw={"head_timeout": 2.0}, body_scan_enabled=False)
    assert b"/admin-secret" not in saw, saw


# ── #58: 連結 gzip ─────────────────────────────────────────────────────────
def test_c58_multi_member_gzip_fully_decompressed():
    """#58: decompressobj は 1 メンバの終端で止まるため、2 個目以降のメンバが走査されなかった
    (backend の gzip 実装は後続メンバも展開する)。"""
    a, b = b"a=1&", b"note=a'b<c"
    assert AsyncEdgeGuard._decompress_bounded(gzip.compress(a) + gzip.compress(b),
                                              "gzip", 65536) == a + b
    # 出力上限はメンバ合計で守る(zip bomb 耐性は維持)
    big = gzip.compress(b"A" * 5000) + gzip.compress(b"B" * 5000)
    out = AsyncEdgeGuard._decompress_bounded(big, "gzip", 6000)
    assert out is not None and len(out) <= 6000 and out.startswith(b"A" * 5000)
    # メンバ間のゼロ詰めは許容、解けない後続データは「走査不能」(None)
    assert AsyncEdgeGuard._decompress_bounded(gzip.compress(a) + b"\x00\x00",
                                              "gzip", 65536) == a
    assert AsyncEdgeGuard._decompress_bounded(gzip.compress(a) + b"junk",
                                              "gzip", 65536) is None


def test_c58_second_gzip_member_reaches_body_scan():
    seen = []
    body = gzip.compress(b"a=1&") + gzip.compress(b"marker=a'b<c")
    head = (b"POST /f HTTP/1.1\r\nHost: x\r\nContent-Encoding: gzip\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    with _shield() as sh:
        sh.inspect_body = lambda ip, pb: (seen.append(pb), {"action": "allow"})[1]
        g = AsyncEdgeGuard()

        async def go():
            r = asyncio.StreamReader()
            r.feed_eof()
            return await g._scan_request_body(head + body, r, "203.0.113.71", "/f")

        _, blocked = asyncio.run(go())
    assert not blocked
    assert seen and b"marker=a'b<c" in seen[0], seen


# ── #59: 応答 head の DLP ─────────────────────────────────────────────────
_LEAK = b"AKIAIOSFODNN7EXAMPLE"      # AWS 公式ドキュメントの例示キー(無効な値)


def test_c59_dlp_scans_response_head_when_head_processing_on():
    """#59: cookie/CORS 加工(既定 ON)で head を書き換える経路は、加工後の head を DLP に
    通さず送っていた=応答ヘッダの秘密が漏れ、dlp_leak も記録されなかった。"""
    resp = (b"HTTP/1.1 200 OK\r\nX-Debug-Key: " + _LEAK + b"\r\n"
            b"Content-Length: 2\r\n\r\nok")
    out, sh = _run_pipe([resp], dlp_enabled=True, dlp_action="block",
                        cookie_harden_enabled=True, cors_harden_enabled=True)
    assert _LEAK not in out, out
    assert sh.metrics().get("dlp_leak", 0) >= 1


def test_c59_dlp_scans_oversized_response_head():
    # 64KiB 超の head(加工を諦める経路)も DLP は通す。
    resp = (b"HTTP/1.1 200 OK\r\nX-Debug-Key: " + _LEAK + b"\r\nX-Pad: " + b"p" * 70000
            + b"\r\n\r\nok")
    out, sh = _run_pipe([resp[:40000], resp[40000:]], dlp_enabled=True, dlp_action="block",
                        cookie_harden_enabled=True)
    assert _LEAK not in out
    assert sh.metrics().get("dlp_leak", 0) >= 1


# ── #60: 1xx 中間応答 ─────────────────────────────────────────────────────
def test_c60_interim_100_continue_does_not_hide_final_status():
    """#60: 先頭の応答行しか見ていなかったため、Expect: 100-continue を付けるだけで 401/404 の
    連射が応答アウェア採点(#60)に一切数えられなかった。"""
    resp = (b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
    for harden in (True, False):                        # head 加工の有無どちらでも
        codes = []

        def setup(sh):
            sh.note_response = lambda ip, code: codes.append(int(code)) or {}

        _run_pipe([resp], setup=setup, cookie_harden_enabled=harden,
                  cors_harden_enabled=harden)
        assert codes == [401], (harden, codes)
        codes.clear()
        _run_pipe([resp[:10], resp[10:30], resp[30:]], setup=setup,
                  cookie_harden_enabled=harden, cors_harden_enabled=harden)
        assert codes == [401], (harden, codes)          # パケット分割でも同じ


def test_c60_interim_103_does_not_skip_final_head_processing():
    """#60: 103 Early Hints を『その応答』として加工し、最終応答の head を body として素通し
    していた=外部リダイレクトも Set-Cookie 補完も防御ヘッダも外れた。"""
    interim = b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"
    final = (b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/p\r\n"
             b"Set-Cookie: s=1\r\nContent-Length: 0\r\n\r\n")
    out, _ = _run_pipe([interim + final], open_redirect_enabled=True,
                       open_redirect_mode="enforce", open_redirect_allow=[],
                       sec_headers_enabled=True, cookie_harden_enabled=True)
    assert out.startswith(interim), out                 # 中間応答は無加工で先に届く
    head2 = out[len(interim):].split(b"\r\n\r\n", 1)[0]
    assert head2.startswith(b"HTTP/1.1 302"), out
    assert b"elsewhere.example" not in head2, out       # 外部リダイレクトは無害化
    assert b"SameSite=" in head2 and b"nosniff" in head2, out


# ── #61: Location の正規化 ────────────────────────────────────────────────
def test_c61_backslash_and_slash_variants_are_external():
    """#61: ブラウザは http(s) の '\\' を '/' と同一視し TAB/改行を捨てる。'//' と '://' しか
    見ていなかったため、これらの外部リダイレクトを相対/自サイト扱いで通していた。"""
    for loc in ("/\\elsewhere.example/p", "\\\\elsewhere.example",
                "https://elsewhere.example\\@app.example/", "/\t/elsewhere.example",
                "https:elsewhere.example", "https:/elsewhere.example",
                "///elsewhere.example", " //elsewhere.example"):
        assert _location_host(loc) == "elsewhere.example", loc
        assert _redirect_violation_host("HTTP/1.1 302 Found", ["Location: " + loc],
                                        "app.example", []) == "elsewhere.example", loc


def test_c61_relative_locations_stay_same_site():
    for loc in ("/dashboard", "next?a=1", "#top", "/sso?next=https://elsewhere.example/x",
                "mailto:a@b.example"):
        assert _location_host(loc) == "", loc
    assert _location_host("https://u:p@a@elsewhere.example:8443/x") == "elsewhere.example"


# ── #92: "upgrade" の部分一致 ─────────────────────────────────────────────
def test_c92_upgrade_substring_does_not_disable_hardening():
    """#92: head 全体に "upgrade" が含まれるだけ(Vary: Upgrade-Insecure-Requests 等)で、
    防御ヘッダ・SameSite 補完・CORS 無害化が全て外れていた。"""
    for extra in (b"Vary: Upgrade-Insecure-Requests", b"Upgrade: h2,h2c\r\nConnection: Upgrade",
                  b"Location: /upgrade"):
        head = (b"HTTP/1.1 200 OK\r\n" + extra + b"\r\nSet-Cookie: s=1\r\n"
                b"Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true")
        out = inject_security_headers(head, {}, add_headers=True, harden_cookies=True,
                                      harden_cors=True).decode()
        assert "SameSite=" in out and "nosniff" in out, (extra, out)
        assert "allow-credentials" not in out.lower(), (extra, out)
    ws = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade"
    assert inject_security_headers(ws, {}, add_headers=True, harden_cookies=True,
                                   harden_cors=True) == ws    # 実際の切替(101)は触らない


# ── #93: 解けない Content-Encoding ────────────────────────────────────────
def test_c93_unscannable_encoding_gets_415_and_counted_once():
    """#93: _scan_request_body が持たない writer を参照して NameError になり、意図した 415 が
    送られず(無言切断)、dropped も二重計上されていた。"""
    req = (b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Encoding: br\r\n"
           b"Content-Length: 4\r\n\r\n\x0b\x01\x80\x00")
    saw, resp, m = _through([req])
    assert resp.startswith(b"HTTP/1.1 415"), resp[:60]
    assert m.get("dropped") == 1, m
    assert m.get("body_unscannable") == 1, m
    assert b"/up" not in saw
