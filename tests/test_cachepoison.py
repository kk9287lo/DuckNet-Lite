"""
test_cachepoison.py — キャッシュ汚染ヘッダの除去(evolution #75)。
====================================================================================
信頼 proxy 経由でないクライアント供給の unkeyed ヘッダ(X-Forwarded-Host 等)を転送前に除去し、
バックエンド反映による Web キャッシュ汚染/パスワードリセット・ポイズニングを防ぐ。
"""
import socket
import threading
import time

from dataplane.engine.services.proxy import _strip_request_headers, AsyncEdgeGuard


def test_strip_removes_named_headers():
    buf = (b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-Host: evil.com\r\n"
           b"X-Real-IP: 1.2.3.4\r\nAccept: */*\r\n\r\n")
    out = _strip_request_headers(buf, ["x-forwarded-host"])
    assert b"X-Forwarded-Host" not in out
    assert b"Host: x" in out and b"Accept: */*" in out          # 他は保持
    assert out.startswith(b"GET / HTTP/1.1\r\n")                 # リクエストライン保持


def test_strip_preserves_body():
    buf = b"POST / HTTP/1.1\r\nHost: x\r\nX-Host: evil\r\nContent-Length: 4\r\n\r\nbody"
    out = _strip_request_headers(buf, ["x-host"])
    assert out.endswith(b"\r\n\r\nbody") and b"X-Host" not in out


def test_strip_incomplete_head_unchanged():
    raw = b"GET / HTTP/1.1\r\nHost: x\r\n"
    assert _strip_request_headers(raw, ["x-host"]) == raw


def _capture_backend():
    got = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                ch = c.recv(4096)
                if not ch:
                    break
                data += ch
            got.append(data)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            c.close()
        except Exception:
            pass
        finally:
            srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return got, port


def test_cache_poison_header_stripped_end_to_end():
    # 直結(trusted_proxies 既定=空=非信頼)→ X-Forwarded-Host は backend へ届かない。
    got, bport = _capture_backend()
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport, listen_port=0)
    g.start()
    try:
        c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=5)
        c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-Host: evil.attacker\r\n\r\n")
        try:
            c.recv(1024)
        except Exception:
            pass
        c.close()
        for _ in range(50):
            if got:
                break
            time.sleep(0.02)
        assert got, "backend received nothing"
        assert b"evil.attacker" not in got[0]                    # 汚染ヘッダ除去済み
        assert b"x-forwarded-host" not in got[0].lower()
    finally:
        g.stop()
