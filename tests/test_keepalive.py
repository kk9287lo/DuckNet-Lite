"""
test_keepalive.py — keep-alive 越しの検査回避を封じる(evolution #31)。
====================================================================================
本機は接続の先頭リクエスト1本だけを検査して以降を生パイプするため、Connection を close に
書き換えて 1接続=1リクエストにしないと、keep-alive の2本目以降が未検査でバックエンドへ
素通りする(WAFバイパス)。純関数 _force_conn_close の書き換えと、実バックエンドへ実際に
Connection: close が転送されること(end-to-end)を回帰から守る。
"""
import socket
import threading
import time

from dataplane.engine.services.proxy import AsyncEdgeGuard, _force_conn_close


def test_rewrites_keepalive_to_close():
    out = _force_conn_close(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
    assert b"Connection: close\r\n" in out
    assert b"keep-alive" not in out.lower()


def test_adds_close_when_absent():
    out = _force_conn_close(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert out.count(b"Connection: close") == 1


def test_strips_keepalive_and_proxy_connection_headers():
    out = _force_conn_close(
        b"GET / HTTP/1.1\r\nHost: x\r\nKeep-Alive: timeout=5\r\n"
        b"Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n")
    low = out.lower()
    assert b"keep-alive:" not in low and b"proxy-connection:" not in low
    assert low.count(b"connection: close") == 1


def test_preserves_request_line_other_headers_and_body():
    out = _force_conn_close(
        b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
        b"Connection: keep-alive\r\n\r\nbody")
    assert out.startswith(b"POST /api HTTP/1.1\r\n")
    assert b"Host: x\r\n" in out and b"Content-Length: 4\r\n" in out
    assert out.endswith(b"\r\n\r\nbody")                 # body 部を保持


def test_case_insensitive_header_match():
    out = _force_conn_close(b"GET / HTTP/1.1\r\nHost: x\r\nCONNECTION: Keep-Alive\r\n\r\n")
    assert out.lower().count(b"connection: close") == 1


def test_incomplete_head_unchanged():
    raw = b"GET / HTTP/1.1\r\nHost: x\r\n"                # \r\n\r\n 未達=触らない
    assert _force_conn_close(raw) == raw


def _capture_backend():
    """受信した生リクエスト(head)を記録し最小200を返すバックエンド。捕捉リスト/ポートを返す。"""
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


def test_close_is_forwarded_to_backend_end_to_end():
    got, bport = _capture_backend()
    guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport,
                           listen_host="127.0.0.1", listen_port=0)
    guard.start()
    try:
        c = socket.create_connection(("127.0.0.1", guard.listen_port), timeout=5)
        c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        c.recv(4096); c.close()
        for _ in range(50):
            if got:
                break
            time.sleep(0.02)
        assert got, "backend received nothing"
        low = got[0].lower()
        assert b"connection: close" in low and b"keep-alive" not in low   # 検査回避を封じた
    finally:
        guard.stop()


def _greedy_backend():
    """Connection: close を *尊重しない* バックエンドの近似: 接続が閉じるまで全バイトを読む。
    パイプライン2本目が上流に届いたかを観測するための回帰用(evolution #46)。"""
    got = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            c.settimeout(1.0)
            data = b""
            try:
                while len(data) < 65536:
                    ch = c.recv(4096)
                    if not ch:
                        break
                    data += ch
            except socket.timeout:
                pass
            got.append(data)
            try:
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                          b"Connection: close\r\n\r\nok")
                c.close()
            except Exception:
                pass
        except Exception:
            pass
        finally:
            srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return got, port


def _send_through(sends):
    got, bport = _greedy_backend()
    guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport,
                           listen_host="127.0.0.1", listen_port=0)
    guard.start()
    try:
        c = socket.create_connection(("127.0.0.1", guard.listen_port), timeout=5)
        for s in sends:
            c.sendall(s)
            time.sleep(0.05)
        try:
            c.recv(4096)
        except Exception:
            pass
        c.close()
        for _ in range(100):
            if got:
                break
            time.sleep(0.02)
        return got[0] if got else b""
    finally:
        guard.stop()


def test_pipelined_second_request_does_not_reach_backend():
    # #46: 本文皆無の GET の後ろにパイプラインした第2要求は、backend が close を
    #   尊重しなくても上流に到達してはならない(inspect-once バイパスの遮断)。
    saw = _send_through([b"GET /benign HTTP/1.1\r\nHost: x\r\n\r\n"
                         b"GET /admin-secret HTTP/1.1\r\nHost: x\r\n\r\n"])
    assert b"/benign" in saw                          # 1本目は正常に届く
    assert b"/admin-secret" not in saw                # 2本目(smuggle)は届かない


def test_dribbled_second_request_does_not_reach_backend():
    # 2本目を別パケットで遅延送信しても封じる(write_eof で client→backend を流さない)。
    saw = _send_through([b"GET /benign HTTP/1.1\r\nHost: x\r\n\r\n",
                         b"GET /admin-secret HTTP/1.1\r\nHost: x\r\n\r\n"])
    assert b"/benign" in saw
    assert b"/admin-secret" not in saw


def test_post_body_still_forwarded_intact():
    # 本文付き(Content-Length)は従来どおり body を完全転送する(誤遮断しない)。
    saw = _send_through([b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\nbody123"])
    assert b"POST /api" in saw and b"body123" in saw
