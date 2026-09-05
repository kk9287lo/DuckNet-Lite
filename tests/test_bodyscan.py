"""
test_bodyscan.py — 要求ボディ検査(head-only の死角を塞ぐ・evolution #61)。
====================================================================================
POST/JSON/GraphQL 本文に潜む SQLi/XSS/RCE/SSTI を、本文先頭を有界に走査して捉える。
head と同じ署名エンジン・正規化。block_score 超で BAN。バイト透過プロキシでの end-to-end も。
"""
import socket
import threading
import time
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.services.proxy import AsyncEdgeGuard


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True               # 既定OFF=パススルー。検査を試すので有効化。
    sh.cfg.update(cfg)
    return sh


def test_clean_body_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect_body("1.2.3.4", b"username=alice&password=s3cret&remember=1")
        assert r["action"] == "allow"


def test_sqli_body_scored_or_blocked():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=1000)             # 高閾=単発はスコアのみ
        r = sh.inspect_body("9.9.9.9", b"user=admin' or 1=1-- -&pw=x")
        assert r["action"] in ("score", "block") and r.get("signature")
        assert sh._decayed_score(sh._state("9.9.9.9")) > 0


def test_sqli_body_blocks_over_threshold():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=20)               # 低閾=単発本文ヒットで BAN
        r = sh.inspect_body("6.6.6.6", b"q=login' or 1=1-- -")
        assert r["action"] == "block" and r["banned"]
        assert sh.is_banned_fast("6.6.6.6")


def test_body_single_hit_does_not_ban_at_default_threshold():
    # 誤BAN耐性(#FP): 既定閾値(100)では本文の単発ヒットは BAN せずスコア記録止まり。
    # 一般ユーザーが問い合わせフォームに SQL 風の文章を書いただけで永久BAN…を避ける。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)                               # block_score 既定=100
        # 一般ユーザーが SQL 風の文章をフォームに書いた例(SELECT…FROM…WHERE を含む)
        body = "q=SELECT name FROM users WHERE id=1 がエラーになります".encode("utf-8")
        r = sh.inspect_body("7.7.7.7", body)
        assert r["action"] != "block"                 # 単発ではBANしない
        assert not sh.is_banned_fast("7.7.7.7")


def test_body_weight_factor_reduces_score():
    # 係数を下げると本文由来スコアが小さくなる(誤BANしにくくなる)ことを確認。
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        full = _shield(d1, block_score=1000, body_sig_weight_factor=1.0)
        soft = _shield(d2, block_score=1000, body_sig_weight_factor=0.4)
        payload = b"user=admin' or 1=1-- -"
        full.inspect_body("a", payload)
        soft.inspect_body("a", payload)
        assert soft._decayed_score(soft._state("a")) < full._decayed_score(full._state("a"))


def test_xss_body_detected():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=1000)
        r = sh.inspect_body("3.3.3.3", b"comment=<script>alert(document.cookie)</script>")
        assert r.get("signature")


def test_disabled_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, body_scan_enabled=False)
        assert sh.inspect_body("x", b"' or 1=1-- -")["action"] == "allow"


def test_bounded_scan_only_prefix():
    # cap を超えた位置の悪性ペイロードは走査されない(全バッファしない有界性)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, body_scan_max_bytes=16, block_score=20)
        body = b"A" * 40 + b"' or 1=1-- -"            # 悪性部は先頭16Bの外
        assert sh.inspect_body("y", body)["action"] == "allow"


def test_empty_body_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.inspect_body("z", b"")["action"] == "allow"


def test_padded_body_payload_still_detected():
    # #61 反パディング: 先頭8KBを無害バイトで埋めて payload を後段へ押し出しても、重複ウィンドウ
    #   走査で捉える(単一窓だと _MAX_SCAN 頭打ちで見逃す=#39 と同種の回避を本文で塞ぐ)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=1000, body_scan_max_bytes=65536)
        body = b"x" * 9000 + b"&q=login' or 1=1-- -"     # 悪性部は先頭窓(8192)の外
        r = sh.inspect_body("p.p.p.p", body)
        assert r.get("signature")


# ── end-to-end(プロキシ経由でボディ走査) ──────────────────────────────
def _capture_backend():
    got = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept(); c.settimeout(1.0)
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


def _post(guard, body: bytes):
    c = socket.create_connection(("127.0.0.1", guard.listen_port), timeout=5)
    req = (b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    c.sendall(req)
    try:
        c.recv(1024)
    except Exception:
        pass
    c.close()


def test_proxy_blocks_malicious_body_end_to_end():
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    saved = {k: sh.cfg.get(k) for k in ("body_scan_enabled", "block_score", "enabled")}
    sh.cfg["enabled"] = True
    sh.cfg["body_scan_enabled"] = True
    sh.cfg["block_score"] = 20                         # 単発本文ヒットで block
    try:
        got, bport = _capture_backend()
        guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport, listen_port=0)
        guard.start()
        try:
            _post(guard, b"username=admin' or 1=1-- -&password=x")   # 悪性本文
            for _ in range(50):
                if got:
                    break
                time.sleep(0.02)
            # 悪性本文は上流へ到達しない(backend は受信しないか接続即切断)
            assert not got or b"or 1=1" not in got[0]
        finally:
            guard.stop()
    finally:
        sh.cfg.update(saved)
        with sh._lock:                                 # 共有シングルトンの 127.0.0.1 状態を掃除
            sh._ips.pop("127.0.0.1", None)


def test_proxy_forwards_clean_body_intact():
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    saved = {k: sh.cfg.get(k) for k in ("body_scan_enabled", "enabled")}
    sh.cfg["enabled"] = True
    sh.cfg["body_scan_enabled"] = True
    try:
        got, bport = _capture_backend()
        guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport, listen_port=0)
        guard.start()
        try:
            _post(guard, b"username=alice&password=hunter2&csrf=abc")   # 正常本文
            for _ in range(50):
                if got:
                    break
                time.sleep(0.02)
            assert got and b"username=alice" in got[0] and b"hunter2" in got[0]
        finally:
            guard.stop()
    finally:
        sh.cfg.update(saved)
        with sh._lock:
            sh._ips.pop("127.0.0.1", None)
