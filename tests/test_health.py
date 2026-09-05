"""
test_health.py — データプレーンのヘルスチェック(evolution #17)。
====================================================================================
opt-in の死活監視パスが WAF/バックエンド非経由で即 200 を返すこと、既定OFF、env 既定、
クエリ無視を回帰から守る。LB/オーケストレータの liveness 用。
"""
import asyncio
import os

from dataplane.engine.services.proxy import AsyncEdgeGuard


class _R:
    def __init__(self, data):
        self._q = [data]

    async def read(self, n=4096):
        return self._q.pop(0) if self._q else b""


class _W:
    def __init__(self):
        self.buf, self.closed = b"", False

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def get_extra_info(self, k, default=None):
        return ("127.0.0.1", 5555) if k == "peername" else default


def _drive(req: bytes, **kw):
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=1, **kw)
    w = _W()
    asyncio.run(g._handle(_R(req), w))
    return g, w


def test_health_constructor_and_env():
    assert AsyncEdgeGuard(health_path="/healthz").health_path == "/healthz"
    assert AsyncEdgeGuard(health_path="  /hz  ").health_path == "/hz"      # strip
    assert AsyncEdgeGuard().health_path == ""                              # 既定OFF
    os.environ["DUCKNET_HEALTH_PATH"] = "/envhz"
    try:
        assert AsyncEdgeGuard().health_path == "/envhz"                    # env 既定
        assert AsyncEdgeGuard(health_path="/explicit").health_path == "/explicit"  # 引数優先
    finally:
        del os.environ["DUCKNET_HEALTH_PATH"]


def test_health_path_answers_200_without_backend():
    g, w = _drive(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", health_path="/healthz")
    assert b"200 OK" in w.buf and b'"status":"ok"' in w.buf
    assert w.closed and g.metrics.get("health", 0) == 1


def test_health_path_ignores_query():
    _, w = _drive(b"GET /healthz?probe=1 HTTP/1.1\r\nHost: x\r\n\r\n", health_path="/healthz")
    assert b'"status":"ok"' in w.buf                                       # クエリは無視して一致


def test_health_path_disabled_does_not_answer():
    _, w = _drive(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", health_path="")
    assert b'"status":"ok"' not in w.buf                                   # 既定OFF=応答しない
