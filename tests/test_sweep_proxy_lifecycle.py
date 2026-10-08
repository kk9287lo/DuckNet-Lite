"""
test_sweep_proxy_lifecycle.py — 前衛ガードの停止(graceful drain)まわりの回帰。
====================================================================================
graceful drain が新規受理を止めていなかった(#54)、巨大/無限の grace で stop() が例外脱出した(#55)、
--cluster のワーカーが drain されずに即死した(#56)。
--cluster の 1 件は fork/SO_REUSEPORT を持つ OS でのみ走る(Windows では SKIP)。
"""
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import SkipTest

from dataplane.engine.services.proxy import AsyncEdgeGuard


def _guard(backend_port: int = 9, port: int = 0) -> AsyncEdgeGuard:
    return AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                          listen_host="127.0.0.1", listen_port=port)


def _get(port: int, path: str, timeout: float = 3.0) -> bytes:
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        c.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while len(data) < 65536:
            ch = c.recv(4096)
            if not ch:
                break
            data += ch
        return data
    finally:
        c.close()


class _Backend:
    """/slow は release されるまで応答を保留する(=進行中リクエストを作る)。他は即 200。"""

    def __init__(self):
        self.received = threading.Event()
        self.release = threading.Event()
        outer = self

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/slow"):
                    outer.received.set()
                    outer.release.wait(5.0)
                    body = b"slow"
                else:
                    body = b"fast"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.srv.shutdown()
        self.srv.server_close()


# ── #54 ──────────────────────────────────────────────────────────────────────
def test_c54_drain_stops_accepting_new_connections():
    """#54: graceful drain は最初に新規受理を止めるはずが、Server.sockets が返す
    TransportSocket には close() が無く(3.11+)、例外は握り潰されて listener は開いたまま
    だった。猶予中に来た新規接続まで受理・中継されていた。"""
    be = _Backend()
    g = _guard(backend_port=be.port)
    assert g.start().get("ok") is True
    port = g.listen_port
    out = {}

    def inflight():
        try:
            out["a"] = _get(port, "/slow", timeout=5.0)
        except Exception as e:                       # noqa: BLE001
            out["a_err"] = repr(e)

    def stopper():
        out["stop"] = g.stop(grace=5.0)

    ta = threading.Thread(target=inflight)
    ts = threading.Thread(target=stopper)
    try:
        ta.start()
        assert be.received.wait(3.0), "バックエンドに届かない(前提が崩れている)"
        ts.start()
        time.sleep(0.3)                              # drain が始まるのを待つ
        try:
            late = _get(port, "/fast", timeout=1.0)
        except OSError:
            late = b""                               # 拒否/タイムアウト=受理されていない
        assert b"200" not in late, "drain 中に来た新規接続が受理・中継された: %r" % late[:40]
    finally:
        be.release.set()
        ta.join(5.0)
        ts.join(10.0)
        be.close()
        g.stop()
    assert b"200" in out.get("a", b""), out          # 進行中のリクエストは捌き切る
    assert out.get("stop", {}).get("drained") == 0, out


# ── #55 ──────────────────────────────────────────────────────────────────────
def test_c55_stop_with_unbounded_grace_does_not_raise():
    """#55: `--drain-grace inf` や 1e12 を stop() がそのまま待機 API に渡し、OverflowError で
    例外脱出していた(ワーカー刈り取り・listener の後始末を飛ばす)。"""
    for grace in (float("inf"), 1e12, float("nan"), -3.0, "bogus"):
        g = _guard()
        assert g.start().get("ok") is True
        try:
            res = g.stop(grace=grace)
        except Exception as e:                       # noqa: BLE001
            g._thread.join(1.0)
            raise AssertionError("stop(grace=%r) が例外を投げた: %r" % (grace, e))
        assert res.get("stopped") is True, (grace, res)
        assert not g.is_alive(), grace


# ── #56(--cluster: fork + SO_REUSEPORT のある OS のみ)───────────────────────
def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_c56_cluster_workers_drain_instead_of_dying_on_stop():
    """#56: --cluster のワーカーは SIGTERM で即死(SIG_DFL)していた。親が自分の drain を
    している間もワーカーは新規受理を続け、その後 SIGTERM で進行中のリクエストごと切られた。
    進行中のリクエストはどのプロセスが受けても捌き切り、drain 中の新規接続は受けないこと。"""
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT 非対応の OS(単一プロセスへ降格する経路)")
    be = _Backend()
    port = _free_port()
    g = _guard(backend_port=be.port, port=port)
    info = g.serve_cluster(workers=3)
    out = {}

    def inflight():
        try:
            out["a"] = _get(port, "/slow", timeout=8.0)
        except Exception as e:                       # noqa: BLE001
            out["a_err"] = repr(e)

    def stopper():
        out["stop"] = g.stop(grace=5.0)

    ta = threading.Thread(target=inflight)
    ts = threading.Thread(target=stopper)
    try:
        assert info.get("ok") is True and info.get("mode") == "cluster", info
        ta.start()
        assert be.received.wait(3.0), "バックエンドに届かない(前提が崩れている)"
        ts.start()
        time.sleep(0.5)                              # 全プロセスの drain が始まるのを待つ
        served = []
        for _ in range(6):                           # どのプロセスに振られても受理されないこと
            try:
                r = _get(port, "/fast", timeout=1.0)
            except OSError:
                r = b""
            served.append(b"200" in r)
        assert not any(served), "drain 中に新規接続を受理したプロセスがある: %r" % served
    finally:
        be.release.set()
        ta.join(10.0)
        ts.join(15.0)
        be.close()
        g.stop()
    assert b"200" in out.get("a", b""), out          # 進行中はどのプロセスでも捌き切る
