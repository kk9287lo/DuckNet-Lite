"""
test_sweep_r3_proxy.py — 前衛プロキシまわりの追補(sweep 第3回: r3_proxy 群)。
====================================================================================
· T1 使用量の記録(record_traffic)へ host/method/path を渡しておらず、使用量ビューの宛先サイト
  内訳(top_hosts)と usage_log.jsonl の host/method/path が本番では常に空だった。
実通信(127.0.0.1・ポート 0)で確かめる。
"""
import contextlib
import socket
import tempfile
import threading
import time

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import AsyncEdgeGuard


# ── 共通ヘルパ ──────────────────────────────────────────────────────────────
def _wait(cond, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return bool(cond())


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
    """要求 head を受け取ったら固定の 200 を返して閉じる backend。"""

    def __init__(self):
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
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                ch = c.recv(65536)
                if not ch:
                    break
                data += ch
            c.sendall(_OK)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self._stop.set()
        self._t.join(2)
        self._srv.close()


def _exchange(port: int, req: bytes, timeout: float = 5.0) -> bytes:
    c = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        c.sendall(req)
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


def _proxy_once(req: bytes):
    """req を 1 接続でガード経由の backend へ流し、使用量が記録されるまで待って
    (応答, usage_list の rows, usage_log) を返す。記録は接続の後始末で行われる。"""
    be = _Backend()
    try:
        with _shield() as sh:
            g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=be.port,
                               listen_host="127.0.0.1", listen_port=0)
            r = g.start()
            assert r.get("ok"), r
            try:
                resp = _exchange(g.listen_port, req)
                assert _wait(lambda: sh.usage_log(limit=5), 3.0), "使用量が記録されない"
            finally:
                g.stop()
            return resp, sh.usage_list()["rows"], sh.usage_log(limit=5)
    finally:
        be.close()


# ── T1: 使用量記録に host/method/path が載る ─────────────────────────────────
def test_r3_usage_record_carries_host_method_path():
    """T1: 本番経路の record_traffic 呼び出しが host/method/path を渡しておらず、使用量の
    宛先サイト内訳(top_hosts)と usage_log の host/method/path が常に空だった。"""
    req = (b"GET /r3/usage?q=a HTTP/1.1\r\nHost: App.Example:8080\r\n"
           b"Connection: close\r\n\r\n")
    resp, rows, log = _proxy_once(req)
    assert resp.startswith(b"HTTP/1.1 200"), resp[:80]
    hosts = [h["host"] for row in rows for h in row["top_hosts"]]
    assert "app.example" in hosts, rows                 # 宛先サイト内訳に出る
    e = log[0]
    assert e["host"] == "app.example", e
    assert e["method"] == "GET", e
    assert e["path"].startswith("/r3/usage"), e


def test_r3_usage_record_bounds_overlong_host():
    """T1 の補助: Host は攻撃者が任意長で送れる。そのまま使用量の宛先キー/ログ行へ載せると
    IP×宛先数の上限があっても 1 件ごとの大きさが青天井になるので、DNS 名の上限程度に切る。"""
    req = (b"GET /r3/long HTTP/1.1\r\nHost: " + b"h" * 1000 + b"\r\n"
           b"Connection: close\r\n\r\n")
    resp, rows, log = _proxy_once(req)
    assert resp.startswith(b"HTTP/1.1 200"), resp[:80]
    hosts = [h["host"] for row in rows for h in row["top_hosts"]]
    assert hosts and all(0 < len(h) <= 255 for h in hosts), [len(h) for h in hosts]
    assert 0 < len(log[0]["host"]) <= 255, len(log[0]["host"])
