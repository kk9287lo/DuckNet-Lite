"""
test_secheaders.py — 応答セキュリティヘッダ注入(evolution #12)。
====================================================================================
バックエンド応答 head への防御ヘッダ注入 / 情報漏洩ヘッダ除去 / 既存尊重 / WS非介入と、
proxy._pipe への配線(既定OFFはバイト完全同一・有効時は head 注入で body 不変)を回帰から守る。
"""
import asyncio

from dataplane.engine.services.proxy import inject_security_headers as inj
from dataplane.engine.services.proxy import AsyncEdgeGuard
from dataplane.engine.lifeform.pipeline import net_shield


# ── 純粋関数 inject_security_headers ─────────────────────────────────────
def test_inject_basic_defaults():
    out = inj(b"HTTP/1.1 200 OK\r\nContent-Type: text/html", {}).decode()
    assert out.startswith("HTTP/1.1 200 OK")
    assert "X-Content-Type-Options: nosniff" in out
    assert "X-Frame-Options: SAMEORIGIN" in out
    assert "Referrer-Policy: strict-origin-when-cross-origin" in out
    assert "Content-Type: text/html" in out                  # 既存は保持


def test_inject_respects_existing():
    out = inj(b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY", {}).decode()
    assert out.count("X-Frame-Options") == 1                  # 二重化しない
    assert "X-Frame-Options: DENY" in out                    # アプリ設定を尊重


def test_inject_strip_and_extra():
    cfg = {"sec_headers_strip": ["Server", "X-Powered-By"],
           "sec_headers_extra": {"Strict-Transport-Security": "max-age=31536000",
                                 "X-Frame-Options": "DENY"}}    # extra は上書き
    out = inj(b"HTTP/1.1 200 OK\r\nServer: nginx/1.0\r\nX-Powered-By: PHP/8", cfg).decode()
    assert "Server:" not in out and "X-Powered-By" not in out  # 指紋/情報漏洩を除去
    assert "Strict-Transport-Security: max-age=31536000" in out
    assert "X-Frame-Options: DENY" in out


def test_inject_skips_websocket_and_nonhttp():
    ws = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade"
    assert inj(ws, {}) == ws                                  # 切替は触らない
    junk = b"garbage not http\r\nfoo: bar"
    assert inj(junk, {}) == junk                              # 応答行不明=非介入


# ── proxy._pipe への配線(fake async stream) ──────────────────────────────
class _R:
    def __init__(self, chunks):
        self.q = list(chunks)

    async def read(self, n=65536):
        return self.q.pop(0) if self.q else b""


class _W:
    def __init__(self):
        self.buf = b""
        self.closed = False

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def _with_cfg(**over):
    sh = net_shield()
    prev = dict(sh.cfg)
    sh.cfg["dlp_enabled"] = False            # DLP は本テストの対象外=干渉させない
    sh.cfg.update(over)
    return sh, prev


def test_pipe_injects_headers_when_enabled():
    sh, prev = _with_cfg(sec_headers_enabled=True, sec_headers_strip=["Server"],
                         sec_headers_extra={"Content-Security-Policy": "default-src 'self'"})
    try:
        resp = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 5\r\n"
                b"X-Frame-Options: DENY\r\n\r\nhello")
        r = _R([resp[:20], resp[20:]])       # head/body をチャンク跨ぎで分割=蓄積経路を通す
        w = _W()
        asyncio.run(AsyncEdgeGuard()._pipe(r, w, scan=True, ip="1.2.3.4"))
        head, _, body = w.buf.partition(b"\r\n\r\n")
        assert body == b"hello"                              # body は不変
        assert b"Content-Length: 5" in head                 # CL 不変(ヘッダ追加は body 長に無影響)
        assert b"Server: nginx" not in head                 # strip された
        assert b"X-Content-Type-Options: nosniff" in head   # 既定注入
        assert b"Content-Security-Policy: default-src 'self'" in head   # extra
        assert head.count(b"X-Frame-Options") == 1          # 既存尊重=二重化しない
        assert b"X-Frame-Options: DENY" in head
    finally:
        sh.cfg.clear(); sh.cfg.update(prev)


def test_pipe_passthrough_byte_identical_when_disabled():
    sh, prev = _with_cfg(sec_headers_enabled=False)
    try:
        resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 9\r\n\r\nbody-data"
        r = _R([resp])
        w = _W()
        asyncio.run(AsyncEdgeGuard()._pipe(r, w, scan=True, ip="1.2.3.4"))
        assert w.buf == resp                                 # 既定OFF=バイト完全同一
    finally:
        sh.cfg.clear(); sh.cfg.update(prev)


def test_pipe_dlp_block_withholds_boundary_spanning_secret():
    # 脆弱性修正(#42): DLP block で、チャンク境界を跨ぐ秘密はその *前半*(既に送った前チャンク末尾)が
    # 漏れていた。末尾窓を保留(未送信)し次チャンクで安全確認するまで送らない=block を完遂する。
    sh = net_shield(); prev = dict(sh.cfg)
    sh.cfg["enabled"] = True; sh.cfg["dlp_enabled"] = True; sh.cfg["dlp_action"] = "block"
    try:
        KEY = b"AKIA1234567890123456"                        # AKIA + 16 = 正規 AWS access key
        c1 = b"data key=" + KEY[:12]                          # 'key=AKIA12345678'(頭) が chunk1 末尾
        c2 = KEY[12:] + b" end"                               # 残り → 境界跨ぎで完全キー成立
        w = _W()
        asyncio.run(AsyncEdgeGuard()._pipe(_R([c1, c2]), w, scan=True, ip="203.0.113.61"))
        assert b"AKIA12345678" not in w.buf                  # 秘密の頭も漏れない(完全に止まる)
        assert KEY[12:] not in w.buf
    finally:
        sh.cfg.clear(); sh.cfg.update(prev)


def test_pipe_dlp_clean_stream_is_byte_complete():
    # 回帰: 秘密を含まない応答は分割しても全バイト欠落なく到達する(保留した末尾窓は最後に放出)。
    sh = net_shield(); prev = dict(sh.cfg)
    sh.cfg["enabled"] = True; sh.cfg["dlp_enabled"] = True; sh.cfg["dlp_action"] = "block"
    try:
        body = b"".join(b"row-%05d-xyz\n" % i for i in range(400))
        w = _W()
        asyncio.run(AsyncEdgeGuard()._pipe(_R([body[:3000], body[3000:7000], body[7000:]]),
                                           w, scan=True, ip="203.0.113.62"))
        assert w.buf == body                                 # 完全一致=欠落/重複なし
    finally:
        sh.cfg.clear(); sh.cfg.update(prev)
