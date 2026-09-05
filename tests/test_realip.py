"""
test_realip.py — 信頼 proxy 背後の実クライアントIP解決(evolution #32)。
====================================================================================
本機の手前に信頼できる proxy/LB がいる構成で、peer がその CIDR に含まれる時 *だけ*
X-Forwarded-For から実クライアントIPを採る(rate-limit/ban/subnet が proxyIP に潰れない)。
直結/未設定では XFF を一切信頼しない(偽装無効化)。純関数で決定論検証。
"""
import socket
import threading
import time

from dataplane.engine.services.proxy import (_real_client_ip, _header_value,
                                             _forwarded_proto_tls,
                                             _set_forwarded_for, AsyncEdgeGuard)
import dataplane.engine.lifeform.pipeline as ND


def _req(xff=None):
    h = b"GET / HTTP/1.1\r\nHost: x\r\n"
    if xff is not None:
        h += b"X-Forwarded-For: " + xff + b"\r\n"
    return h + b"\r\n"


def test_header_value_extraction():
    buf = _req(b"1.2.3.4, 10.0.0.9")
    assert _header_value(buf, b"x-forwarded-for") == "1.2.3.4, 10.0.0.9"
    assert _header_value(buf, b"x-real-ip") == ""        # 無いヘッダ


def test_empty_trusted_keeps_peer():
    # 既定 []=XFF を信頼しない(現状不変・偽装無効)。
    assert _real_client_ip("203.0.113.7", _req(b"1.2.3.4"), []) == "203.0.113.7"


def test_untrusted_peer_ignores_xff():
    # peer が信頼CIDR外=直結とみなし XFF 無視(クライアントの偽装を無効化)。
    assert _real_client_ip("203.0.113.7", _req(b"9.9.9.9"),
                           ["10.0.0.0/8"]) == "203.0.113.7"


def test_trusted_peer_takes_real_client_from_xff():
    # peer が信頼 proxy=XFF の右から信頼でない最初(=実クライアント)を採用。
    buf = _req(b"1.2.3.4, 10.0.0.9")                      # client, trusted-proxy
    assert _real_client_ip("10.0.0.5", buf, ["10.0.0.0/8"]) == "1.2.3.4"


def test_trusted_peer_no_xff_keeps_peer():
    assert _real_client_ip("10.0.0.5", _req(), ["10.0.0.0/8"]) == "10.0.0.5"


def test_invalid_ips_in_xff_skipped():
    buf = _req(b"garbage, 1.2.3.4, 10.0.0.9")
    assert _real_client_ip("10.0.0.5", buf, ["10.0.0.0/8"]) == "1.2.3.4"


def test_all_trusted_chain_falls_back_to_peer():
    buf = _req(b"10.0.0.1, 10.0.0.9")                     # すべて信頼CIDR内
    assert _real_client_ip("10.0.0.5", buf, ["10.0.0.0/8"]) == "10.0.0.5"


def test_single_ip_trusted_entry():
    # trusted に素のIP(/32相当)も使える。
    buf = _req(b"1.2.3.4")
    assert _real_client_ip("198.51.100.1", buf, ["198.51.100.1"]) == "1.2.3.4"


# ── X-Forwarded-Proto の信頼(#33): tls 偽装の封じ込め ──
def _req_xfp(https):
    proto = b"https" if https else b"http"
    return b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-Proto: " + proto + b"\r\n\r\n"


def test_xfp_unset_trusted_fails_closed():
    # trusted_proxies 未設定=XFPは一切信頼しない(#111・フェイルクローズ。_real_client_ip の
    # XFF と同じ既定方針: 設定しない限り、直結の平文クライアントが自己申告のヘッダ1本で
    # 「これはTLS経由」と偽装して require_tls 系ポリシーを回避できてはならない)。
    assert _forwarded_proto_tls("203.0.113.7", _req_xfp(True), []) is False
    assert _forwarded_proto_tls("203.0.113.7", _req_xfp(False), None) is False


def test_xfp_direct_client_cannot_spoof_https():
    # trusted 設定時、直結クライアント(peer非trusted)の https 偽装は無効=tls False。
    assert _forwarded_proto_tls("203.0.113.7", _req_xfp(True), ["10.0.0.0/8"]) is False


def test_xfp_trusted_peer_honored():
    # 信頼 proxy 経由の XFP:https は採用=tls True。
    assert _forwarded_proto_tls("10.0.0.5", _req_xfp(True), ["10.0.0.0/8"]) is True
    assert _forwarded_proto_tls("10.0.0.5", _req_xfp(False), ["10.0.0.0/8"]) is False


# ── バックエンドへ実クライアントIPを転送(#35) ──
def test_set_forwarded_for_replaces_and_strips():
    out = _set_forwarded_for(
        b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\nX-Real-IP: 9.9.9.9\r\n\r\n",
        "1.2.3.4")
    assert b"X-Forwarded-For: 1.2.3.4\r\n" in out
    assert b"X-Real-IP: 1.2.3.4\r\n" in out
    assert out.lower().count(b"x-forwarded-for:") == 1          # 既存の偽装値は除去
    assert b"9.9.9.9" not in out


def test_set_forwarded_for_preserves_request_line_and_body():
    out = _set_forwarded_for(b"POST /a HTTP/1.1\r\nHost: x\r\n\r\nbody", "1.2.3.4")
    assert out.startswith(b"POST /a HTTP/1.1\r\n") and out.endswith(b"\r\n\r\nbody")


def test_set_forwarded_for_empty_client_unchanged():
    raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    assert _set_forwarded_for(raw, "") == raw


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


def test_backend_receives_resolved_client_ip_end_to_end():
    # 信頼proxy構成: peer=127.0.0.1 を信頼に入れ、client が XFF 偽装(9.9.9.9)+実IP(1.2.3.4)を送る。
    # バックエンドは解決済み実IP(1.2.3.4)を XFF/X-Real-IP で受け取り、偽装値は消える。
    import tempfile
    osh = ND._SHIELD
    got, bport = _capture_backend()
    with tempfile.TemporaryDirectory() as tmp:
        ND._SHIELD = ND.NetShield(state_dir=tmp)
        ND._SHIELD.cfg["trusted_proxies"] = ["127.0.0.1/32"]
        guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport,
                               listen_host="127.0.0.1", listen_port=0)
        guard.start()
        try:
            c = socket.create_connection(("127.0.0.1", guard.listen_port), timeout=5)
            c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n"
                      b"X-Forwarded-For: 1.2.3.4, 127.0.0.1\r\n\r\n")
            c.recv(4096); c.close()
            for _ in range(50):
                if got:
                    break
                time.sleep(0.02)
            assert got, "backend received nothing"
            low = got[0].lower()
            assert b"x-forwarded-for: 1.2.3.4" in low          # 解決済み実クライアント
            assert b"x-real-ip: 1.2.3.4" in low
        finally:
            guard.stop()
            ND._SHIELD = osh


# ── IPv4-mapped IPv6 正規化(#14): dual-stack 束縛時の BAN すり抜けを防ぐ ──
def test_norm_ip_unmaps_ipv4_mapped_ipv6():
    from dataplane.engine.services.proxy import AsyncEdgeGuard
    g = AsyncEdgeGuard()
    assert g._norm_ip("::ffff:192.0.2.1") == "192.0.2.1"   # 射影→純IPv4(BAN一致するように)
    assert g._norm_ip("::ffff:1.2.3.4") == "1.2.3.4"
    assert g._norm_ip("1.2.3.4") == "1.2.3.4"              # 純IPv4はそのまま(ゼロ負荷)
    assert g._norm_ip("2001:db8::1") == "2001:db8::1"      # 通常IPv6は不変
    assert g._norm_ip("") == "" and g._norm_ip("garbage") == "garbage"
