"""
test_origin.py — バックエンド・バイパス防止(オリジントークン・evolution #77)。
====================================================================================
エッジ経由を証明する時間有界 HMAC トークンを転送要求へ付与し、バックエンドが検証する。鍵を
持たない迂回トラフィック(backend 直叩き/再ルーティング)は弾かれる。
"""
import os
import socket
import threading
import time

from dataplane.engine.core.origin import origin_token, verify_origin_token
from dataplane.engine.services.proxy import _set_request_header, AsyncEdgeGuard


def test_token_roundtrip():
    tok = origin_token("k", now=1000.0, window=30.0)
    assert verify_origin_token(tok, "k", now=1000.0, window=30.0)
    assert verify_origin_token(tok, "k", now=1005.0, window=30.0)        # 同窓内
    assert not verify_origin_token(tok, "wrong", now=1000.0)             # 鍵違い=偽造不可
    assert not verify_origin_token("", "k")                              # 空


def test_token_window_and_skew():
    tok = origin_token("k", now=1000.0, window=30.0)
    # 次の窓でも skew=1 で許容(時計ずれ吸収)
    assert verify_origin_token(tok, "k", now=1031.0, window=30.0, skew=1)
    # 遠い未来は拒否(リプレイ窓を抜ける)
    assert not verify_origin_token(tok, "k", now=2000.0, window=30.0, skew=1)


def test_set_request_header_replaces_client_supplied():
    buf = b"GET / HTTP/1.1\r\nHost: x\r\nX-Edge-Token: ATTACKER-FAKE\r\nAccept: */*\r\n\r\n"
    out = _set_request_header(buf, "X-Edge-Token", "real-token")
    assert b"ATTACKER-FAKE" not in out                                  # 偽装値は除去
    assert b"X-Edge-Token: real-token" in out
    assert b"Host: x" in out and b"Accept: */*" in out                  # 他は保持
    assert out.startswith(b"GET / HTTP/1.1\r\n")


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


def test_origin_token_injected_end_to_end():
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    saved = {k: sh.cfg.get(k) for k in ("origin_cloaking_enabled", "origin_header")}
    os.environ["DUCKNET_ORIGIN_KEY"] = "shared-edge-key"
    sh.cfg["origin_cloaking_enabled"] = True
    sh.cfg["origin_header"] = "X-Edge-Token"
    try:
        got, bport = _capture_backend()
        g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport, listen_port=0)
        g.start()
        try:
            c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=5)
            # 攻撃者が偽トークンを付けても差し替えられる
            c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Edge-Token: FORGED\r\n\r\n")
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
            req = got[0]
            assert b"FORGED" not in req                                 # 偽装は除去
            # backend が受け取ったトークンは正規鍵で検証できる(=エッジ経由の証明)
            line = [l for l in req.split(b"\r\n") if l.lower().startswith(b"x-edge-token:")]
            assert line, "no edge token injected"
            tok = line[0].split(b":", 1)[1].strip().decode()
            assert verify_origin_token(tok, "shared-edge-key")
        finally:
            g.stop()
    finally:
        sh.cfg.update(saved)
        os.environ.pop("DUCKNET_ORIGIN_KEY", None)
