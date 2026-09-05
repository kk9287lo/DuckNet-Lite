"""
test_throttle.py — レート超過(throttle)応答(evolution #24)。
====================================================================================
レート制限(#21 のパス別 or グローバル)で throttle 評定になったとき、proxy が標準的な
HTTP 429 + Retry-After を返す(従来は無言TCP切断=正規クライアントは理由不明で困る)。
Retry-After が設定可能なこと・opt-out(throttle_response=False)で従来挙動へ戻せることを回帰から守る。
実ソケットは使わず fake async stream で _handle を直接駆動(クロスプラットフォーム・決定論)。
"""
import asyncio
import tempfile

import dataplane.engine.lifeform.pipeline as ND
from dataplane.engine.services.proxy import AsyncEdgeGuard


class _R:
    def __init__(self, data): self._q = [data]
    async def read(self, n=4096): return self._q.pop(0) if self._q else b""


class _W:
    def __init__(self): self.buf, self.closed = b"", False
    def write(self, b): self.buf += b
    async def drain(self): pass
    def close(self): self.closed = True
    def get_extra_info(self, k, default=None):
        return ("203.0.113.50", 5555) if k == "peername" else default


def _drive(req: bytes) -> _W:
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=1)   # backend port 1=届かない
    w = _W()
    asyncio.run(g._handle(_R(req), w))
    return w


def _throttling_shield(tmp, **cfg):
    """/x を burst=1 で絞るシールド。1発目=allow(バケツ消費)、2発目=throttle。"""
    sh = ND.NetShield(state_dir=tmp); sh.enable()
    sh.set_path_limits([{"path": "/x", "rate": 0.001, "burst": 1}])
    sh.cfg.update(cfg)
    return sh


def test_throttle_returns_429_with_retry_after():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        ND._SHIELD = _throttling_shield(tmp)
        try:
            _drive(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")            # 1発目=バケツ消費(allow)
            w = _drive(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")        # 2発目=throttle
            assert b"429 Too Many Requests" in w.buf
            assert b"Retry-After: 1" in w.buf
            assert b'rate-limit' in w.buf and w.closed       # 防御種別=rate-limit を明示
        finally:
            ND._SHIELD = osh


def test_throttle_retry_after_configurable():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        ND._SHIELD = _throttling_shield(tmp, throttle_retry_after=7)
        try:
            _drive(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
            w = _drive(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
            assert b"Retry-After: 7" in w.buf
        finally:
            ND._SHIELD = osh


def test_throttle_response_opt_out_bare_close():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        ND._SHIELD = _throttling_shield(tmp, throttle_response=False)
        try:
            _drive(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
            w = _drive(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
            assert b"429" not in w.buf and w.buf == b"" and w.closed   # 従来の無言切断
        finally:
            ND._SHIELD = osh


def test_allowed_request_is_not_throttled():
    # 制限外パスは 429 にならない(allow→backend へ。backend 不達でも 429 は出ない)。
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        ND._SHIELD = _throttling_shield(tmp)
        try:
            w = _drive(b"GET /other HTTP/1.1\r\nHost: h\r\n\r\n")
            assert b"429" not in w.buf
        finally:
            ND._SHIELD = osh
