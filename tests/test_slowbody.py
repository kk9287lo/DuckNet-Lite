"""
test_slowbody.py — スロー POST(R-U-Dead-Yet)対策(evolution #64)。
====================================================================================
要求ボディの *総受信時間* に上限を課し、ボディを小出しして接続を保持する攻撃を切断+加点する。
client→backend 方向のみに効く(応答の長時間ストリームは縛らない)。
"""
import asyncio
import tempfile

from dataplane.engine.services.proxy import AsyncEdgeGuard
from guard_support import stop_guard_owned


class _HangReader:
    """read() が永遠に返らない(ボディを送らず接続を保持する slow-body 攻撃の模擬)。"""
    async def read(self, n):
        await asyncio.sleep(30)
        return b""


class _ListReader:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, n):
        return self._chunks.pop(0) if self._chunks else b""


class _NullWriter:
    def write(self, d):
        pass

    async def drain(self):
        pass

    def close(self):
        pass


class _BoundaryWriter(_NullWriter):
    def __init__(self):
        self.data = b""
        self.closed = self.finished = self.aborted = False
        self.transport = self

    def write(self, data):
        self.data += data

    def write_eof(self):
        self.finished = True

    def can_write_eof(self):
        return True

    def close(self):
        self.closed = True

    def abort(self):
        self.aborted = self.closed = True


def test_incomplete_or_malformed_body_aborts_backend_connection():
    """Only a completely framed body may receive graceful write_eof."""
    guard = AsyncEdgeGuard()
    penalties = []
    guard._on_slow_body = penalties.append

    async def run(parts, remaining, chunked=False, expired=False, ip=""):
        writer = _BoundaryWriter()
        deadline = asyncio.get_running_loop().time() - 1 if expired else None
        await guard._pipe_body_bounded(_ListReader(parts), writer, remaining,
                                       chunked, deadline, ip=ip)
        return writer

    valid = asyncio.run(run([b"abc"], 3))
    assert valid.data == b"abc" and valid.finished and not valid.closed
    short = asyncio.run(run([b"ab"], 3))
    assert short.data == b"ab" and short.aborted and not short.finished
    expired = asyncio.run(run([], 3, expired=True, ip="198.51.100.5"))
    assert expired.aborted and not expired.finished
    assert penalties == ["198.51.100.5"]
    valid_chunk = asyncio.run(run([b"1\r\na\r\n0\r\n\r\n"], None, chunked=True))
    assert valid_chunk.finished and not valid_chunk.closed
    bad_chunk = asyncio.run(run([b"1\r\na\r\n0\r\nHost: x\r\n\r\n"], None,
                                chunked=True))
    assert bad_chunk.data == b"" and bad_chunk.aborted and not bad_chunk.finished


def test_pipe_deadline_drops_stalled_body():
    from dataplane.engine.lifeform.pipeline import net_shield
    g = AsyncEdgeGuard()
    loop = asyncio.new_event_loop()
    try:
        before = g.metrics.get("slow_body", 0)
        deadline = loop.time() + 0.15
        total = loop.run_until_complete(
            g._pipe(_HangReader(), _NullWriter(), ip="203.0.113.50", deadline=deadline))
        assert total == 0                              # 何も受信せず切断
        assert g.metrics["slow_body"] == before + 1    # slow_body 計上
    finally:
        loop.close()
        with net_shield()._lock:                       # 共有シングルトンの加点を掃除
            net_shield()._ips.pop("203.0.113.50", None)


def test_pipe_without_deadline_streams_normally():
    g = AsyncEdgeGuard()
    loop = asyncio.new_event_loop()
    try:
        n = loop.run_until_complete(
            g._pipe(_ListReader([b"hello ", b"world"]), _NullWriter()))
        assert n == 11                                 # 全バイト透過(従来挙動)
    finally:
        loop.close()


def test_pipe_deadline_allows_prompt_body():
    # デッドライン内に完了する正常ボディは切断されない(誤遮断しない)。
    g = AsyncEdgeGuard()
    loop = asyncio.new_event_loop()
    try:
        before = g.metrics.get("slow_body", 0)
        deadline = loop.time() + 5.0
        n = loop.run_until_complete(
            g._pipe(_ListReader([b"username=alice&pw=x"]), _NullWriter(),
                    ip="1.1.1.1", deadline=deadline))
        assert n == 19 and g.metrics.get("slow_body", 0) == before
    finally:
        loop.close()


def test_body_deadline_respects_config():
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    saved = {k: sh.cfg.get(k) for k in ("body_timeout_enabled", "body_max_sec")}
    try:
        sh.cfg["body_timeout_enabled"] = False
        g = AsyncEdgeGuard()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            assert g._body_deadline() is None          # 無効=デッドライン無し
            sh.cfg["body_timeout_enabled"] = True
            sh.cfg["body_max_sec"] = 30
            dl = g._body_deadline()
            assert dl is not None and dl > loop.time()  # 有効=未来の時刻
        finally:
            loop.close()
    finally:
        sh.cfg.update(saved)


class _Dribbler:
    """head_timeout 直前ごとに 1 バイトずつ送る small-drip 攻撃の模擬(\\r\\n\\r\\n を完成させない)。"""
    async def read(self, n):
        await asyncio.sleep(0.03)
        return b"x"


def test_read_head_total_deadline_stops_dribble():
    # #82: head_timeout を *総* デッドラインに。小出しでも総時間で頭打ち→TimeoutError(=slowloris)。
    g = AsyncEdgeGuard(head_timeout=0.25)
    loop = asyncio.new_event_loop()
    try:
        t0 = loop.time()
        raised = False
        try:
            loop.run_until_complete(g._read_head(_Dribbler()))
        except asyncio.TimeoutError:
            raised = True
        elapsed = loop.time() - t0
        assert raised                                  # 総時間超過で TimeoutError
        assert elapsed < 2.0                           # 永久に保持されない(~0.25s で打切り)
    finally:
        loop.close()


def test_scan_body_total_deadline_stops_dribble():
    # #82: 走査読取にも総デッドライン。小出しでボディ走査フェーズを保持できない。
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    saved = {k: sh.cfg.get(k) for k in ("enabled", "body_scan_enabled",
                                        "body_timeout_enabled", "body_max_sec",
                                        "body_scan_max_bytes")}
    sh.cfg["enabled"] = True
    sh.cfg["body_scan_enabled"] = True
    sh.cfg["body_timeout_enabled"] = True
    sh.cfg["body_max_sec"] = 0.25
    sh.cfg["body_scan_max_bytes"] = 65536
    try:
        g = AsyncEdgeGuard(head_timeout=10.0)
        # 宣言長が scan 上限を超えると、現在は本文を待たず 413 で拒否される。
        # dribble の総期限を測るため、上限内だが期限内には届かない長さにする。
        buf = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\n"
        loop = asyncio.new_event_loop()
        try:
            before = g.metrics.get("slow_body", 0)
            t0 = loop.time()
            _, reason = loop.run_until_complete(
                g._scan_request_body(buf, _Dribbler(), "203.0.113.51"))
            assert loop.time() - t0 < 2.0              # 総時間で打切り(保持されない)
            assert reason == "timeout"
            assert g.metrics.get("slow_body", 0) == before + 1
        finally:
            loop.close()
            with net_shield()._lock:
                net_shield()._ips.pop("203.0.113.51", None)
    finally:
        sh.cfg.update(saved)


def test_scan_body_deadline_allows_prompt_body():
    """A complete body received before the same scan deadline passes unchanged."""
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    saved = {k: sh.cfg.get(k) for k in ("enabled", "body_scan_enabled",
                                        "body_timeout_enabled", "body_max_sec")}
    sh.cfg.update({"enabled": True, "body_scan_enabled": True,
                   "body_timeout_enabled": True, "body_max_sec": 0.25})
    try:
        g = AsyncEdgeGuard(head_timeout=10.0)
        buf = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n"
        before = g.metrics.get("slow_body", 0)
        extra, reason = asyncio.run(g._scan_request_body(buf, _ListReader([b"abc"]),
                                                         "203.0.113.52"))
        assert extra == b"abc" and reason is False
        assert g.metrics.get("slow_body", 0) == before
    finally:
        sh.cfg.update(saved)


def test_on_slow_body_penalizes():
    from dataplane.engine.lifeform.pipeline import net_shield
    g = AsyncEdgeGuard()
    sh = net_shield()
    prev = sh.cfg.get("enabled")
    sh.cfg["enabled"] = True                 # 加点はシールド ON のときだけ(OFF=完全パススルー・#28)
    try:
        g._on_slow_body("198.51.100.77")
        assert sh._decayed_score(sh._state("198.51.100.77")) > 0   # 加点された
    finally:
        sh.cfg["enabled"] = prev
        with sh._lock:
            sh._ips.pop("198.51.100.77", None)


# ── 遅延読取(TCP zero-window)兵糧攻め(#9): 応答 drain を期限付きにし backend を道連れにしない ──
def test_send_aborts_on_zero_window_reader():
    g = AsyncEdgeGuard()
    g.write_timeout = 0.2

    class _Stall:
        def write(self, _d):
            pass

        async def drain(self):
            await asyncio.sleep(30)            # 受信側ゼロ窓=drain が永久に完了しない

    async def run():
        try:
            await g._send(_Stall(), b"x" * 16, "9.9.9.9")
            return False
        except asyncio.TimeoutError:
            return True
    assert asyncio.run(run()) is True          # write_timeout で中断する(永久サスペンドしない)
    assert g.metrics.get("slow_read", 0) >= 1  # 遅延読取として検知・加点


def test_slow_read_releases_backend_within_timeout():
    import socket
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    BIG = 4 * 1024 * 1024
    backend_released = threading.Event()

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                self.send_response(200)
                self.send_header("Content-Length", str(BIG))
                self.end_headers()
                self.wfile.write(b"A" * BIG)   # 大容量=プロキシが読むのを止めると送信ブロック
            except Exception:
                pass                           # プロキシが切断→write が壊れる=backend 解放
            finally:
                backend_released.set()

        def log_message(self, *_a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    bport = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport,
                       listen_host="127.0.0.1", listen_port=0)
    g.write_timeout = 0.5                       # 兵糧攻めをこの秒数で断つ
    assert g.start().get("ok") is True
    c = None
    try:
        c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=5)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)   # 受信窓を絞る
        c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        # クライアントは一切 recv しない(zero-window)。プロキシは drain を打ち切り両端を解放するはず。
        assert backend_released.wait(8.0), "backend was held hostage (proxy hung on slow read)"
    finally:
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
        try:
            stop_guard_owned(g)
        finally:
            srv.shutdown()
            srv.server_close()
