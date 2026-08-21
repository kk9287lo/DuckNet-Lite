"""
test_shutdown.py — SIGTERM graceful shutdown(evolution #20)。
====================================================================================
コンテナ/k8s は停止に **SIGTERM** を送る。これを拾わないと終了処理(接続クローズ・
WAF 状態の永続化)が走らずプロセスが即死する。SIGTERM/SIGINT のハンドラ配線、停止時の
stop_fn 一括実行(片方失敗でももう片方を走らせる)、そして停止時 flush が累犯回数=ban_count を
取りこぼさないことを回帰から守る。実シグナルは送らず(クロスプラットフォーム・決定論)、
ハンドラ配線とイベント駆動の停止経路を直接検証する。
"""
import asyncio
import signal
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dataplane.service import _install_shutdown_handlers, _block_until_shutdown
from dataplane.engine.lifeform.pipeline import NetShield, _now
from dataplane.engine.services.proxy import AsyncEdgeGuard


def test_install_handlers_cover_sigterm_and_sigint():
    # SIGTERM/SIGINT は POSIX/Windows 双方に存在=必ず張れる。グローバル変更は復元する。
    orig = {s: signal.getsignal(getattr(signal, s))
            for s in ("SIGTERM", "SIGINT")}
    try:
        ev = threading.Event()
        installed = _install_shutdown_handlers(ev)
        assert "SIGTERM" in installed and "SIGINT" in installed
    finally:
        for s, h in orig.items():
            signal.signal(getattr(signal, s), h)


def test_installed_handler_sets_event():
    # 受信ハンドラ(=実シグナルが配送する callable)を直接呼ぶと Event がセットされる。
    orig = {s: signal.getsignal(getattr(signal, s))
            for s in ("SIGTERM", "SIGINT")}
    try:
        ev = threading.Event()
        _install_shutdown_handlers(ev)
        assert not ev.is_set()
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)   # SIGTERM 受信を模す
        assert ev.is_set()
    finally:
        for s, h in orig.items():
            signal.signal(getattr(signal, s), h)


def test_block_dispatches_all_stop_fns_even_on_error():
    # 既セットの Event を注入=即 graceful 停止経路へ。片方の stop_fn が例外でも全部走る。
    calls = []

    def boom():
        calls.append("boom"); raise RuntimeError("stop failed")

    ev = threading.Event(); ev.set()
    _block_until_shutdown(boom, lambda: calls.append("flush"), _event=ev)
    assert calls == ["boom", "flush"]    # boom が落ちても flush(状態保存)は必ず実行


def _restart(tmp):
    sh = NetShield(state_dir=tmp); sh.cfg["persist_bans"] = True; sh.enable()
    sh.cfg["ban_ttl_sec"] = 100.0
    sh._load_bans()
    return sh


def test_flush_state_persists_ban_count():
    # graceful shutdown の flush_state が累犯回数まで書き出し、再起動で復元できる。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _restart(tmp); ip = "203.0.113.70"
        sh.inspect(ip, path="/.env")                 # ハニーポット命中=即BAN(count=1)
        sh._ips[ip]["ban_until"] = 0.0; sh.inspect(ip, path="/.env")   # count=2(active)
        res = sh.flush_state()
        assert res["persisted"] is True
        sh2 = _restart(tmp); st = sh2._ips.get(ip)
        assert st and st["ban_count"] == 2 and st["ban_until"] > _now()


def test_flush_state_noop_without_persist():
    # 永続化OFFなら flush は安全に何もしない(persisted=False・例外なし)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.cfg["persist_bans"] = False
        assert sh.flush_state()["persisted"] is False


# ── 接続ドレイン(evolution #23): stop(grace) で進行中リクエストを取りこぼさない ──
class _FakeServer:
    def __init__(self): self.closed = False
    def close(self): self.closed = True


def test_stop_on_dead_loop_is_clean():
    # #57 review fix: ループが既に停止している(restart() 直後など)時の stop() は
    #   _drain を投入せず=コルーチン未await 警告も無駄な待機も無く、例外なく返る。
    g = AsyncEdgeGuard()
    loop = asyncio.new_event_loop()        # 走っていないループ(is_running()=False)
    g._loop = loop
    try:
        r = g.stop(grace=0.0)              # 走っていない→drain を投入しない
        assert r["ok"] and r["drained"] is None
    finally:
        loop.close()


def test_drain_grace_zero_returns_immediately():
    # 既定 grace=0: 進行中があっても待たず即時(従来挙動)。残接続数を返し listener は閉じる。
    g = AsyncEdgeGuard(); g._server = _FakeServer()
    loop = asyncio.new_event_loop()
    try:
        g._loop = loop; g._active = 3
        t0 = time.time()
        remaining = loop.run_until_complete(g._drain(0.0))
        assert remaining == 3 and g._server.closed and (time.time() - t0) < 0.5
    finally:
        loop.close()


def test_drain_waits_until_connections_finish():
    # grace 内に進行中が捌ければ待って 0 を返す(デッドライン未到達)。
    g = AsyncEdgeGuard(); g._server = _FakeServer()
    loop = asyncio.new_event_loop()
    try:
        g._loop = loop; g._active = 1
        async def runner():
            async def finish():
                await asyncio.sleep(0.15); g._active = 0
            asyncio.ensure_future(finish())
            return await g._drain(3.0)
        t0 = time.time()
        remaining = loop.run_until_complete(runner())
        assert remaining == 0 and 0.1 < (time.time() - t0) < 1.5
    finally:
        loop.close()


def test_drain_respects_deadline():
    # 進行中が捌けなければ grace で打ち切り、残数を返す(無限待ちしない)。
    g = AsyncEdgeGuard(); g._server = _FakeServer()
    loop = asyncio.new_event_loop()
    try:
        g._loop = loop; g._active = 2          # 捌けないまま
        t0 = time.time()
        remaining = loop.run_until_complete(g._drain(0.2))
        assert remaining == 2 and 0.15 < (time.time() - t0) < 1.5
    finally:
        loop.close()


def test_handle_brackets_active_counter():
    # _handle ラッパが本体の前後で進行中数を増減(全 return 経路で必ずデクリメント)。
    g = AsyncEdgeGuard(); seen = []
    async def fake_conn(reader, writer):
        seen.append(g._active)
    g._handle_conn = fake_conn
    asyncio.run(g._handle(None, None))
    assert seen == [1] and g._active == 0


def test_inflight_request_completes_within_grace():
    # 実バックエンド(応答前に遅延)+ 実ガード。リクエスト進行中に stop(grace) を呼ぶと、
    # ドレインで完了まで待ち、クライアントは正常応答(200)を受け取り drained==0。
    received = threading.Event()

    class _SlowH(BaseHTTPRequestHandler):
        def do_GET(self):
            received.set()
            time.sleep(0.3)
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *_a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SlowH)
    bport = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport,
                           listen_host="127.0.0.1", listen_port=0)
    guard.start()
    out = {}

    def client():
        try:
            c = socket.create_connection(("127.0.0.1", guard.listen_port), timeout=5)
            c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            data = b""
            while b"ok" not in data and len(data) < 65536:
                ch = c.recv(4096)
                if not ch:
                    break
                data += ch
            out["data"] = data; c.close()
        except Exception as e:                  # noqa: BLE001
            out["err"] = repr(e)

    ct = threading.Thread(target=client); ct.start()
    try:
        assert received.wait(3.0), "backend never received request (no in-flight conn)"
        res = guard.stop(grace=3.0)             # ドレイン: 進行中が捌けるまで待つ
        ct.join(5.0)
        assert b"200" in out.get("data", b"") and b"ok" in out.get("data", b""), out
        assert res.get("drained") == 0          # 完全に捌けた
    finally:
        srv.shutdown(); srv.server_close()
