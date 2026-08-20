"""
test_dns_threat.py — DNS の L7 ヒューリスティック検知(トンネリング/C2/AD偵察)
====================================================================================
宛先IP/ポートではなく『問い合わせの中身と振る舞い』で異常を切り分けるエンジンの検証。
ソケットは張らず、組み立てたDNSクエリのバイト列を decide() に渡して判定だけを見る。
実stateは汚さない(state_dir=tmp で隔離。[[feedback-verification-coverage-honesty]])。
"""
import tempfile

from dataplane.engine.lifeform.dns import (
    DnsFilter, DnsAnomalyDetector, parse_question, _shannon, QTYPE)


def _build_query(name: str, qtype: int = 1) -> bytes:
    """最小のDNSクエリ(1 question)を組む。tid/flags は固定で十分。"""
    header = b"\xab\xcd" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
    q = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("latin1")
        q += bytes([len(b)]) + b
    q += b"\x00"
    q += bytes([(qtype >> 8) & 0xFF, qtype & 0xFF]) + b"\x00\x01"  # qtype, qclass=IN
    return header + q


def _filter(tmp):
    """既定(L7検知ON・監査寄り)の DnsFilter を隔離stateで生成。"""
    return DnsFilter(state_dir=tmp)


# ── 低レベル部品 ────────────────────────────────────────────────────

def test_parse_question_extracts_qtype():
    q = _build_query("mail.example.com", qtype=16)   # TXT
    name, qtype = parse_question(q)
    assert name == "mail.example.com"
    assert qtype == 16 and QTYPE[qtype] == "TXT"


def test_shannon_distinguishes_encoded_from_words():
    # 英単語ドメインは低エントロピー、base32風ランダムは高エントロピー。
    assert _shannon("wordpress") < 3.2
    assert _shannon("mfrggzdfmztwq2lknnwg23tp") > 3.6


# ── ヒューリスティック本体 ─────────────────────────────────────────

def test_clean_domain_is_allowed():
    det = DnsAnomalyDetector()
    r = det.inspect("www.example.com", qtype=1)
    assert r["verdict"] == "clean" and r["score"] == 0


def test_tunneling_long_high_entropy_txt_is_malicious():
    det = DnsAnomalyDetector()
    # 長い高エントロピー・ラベル + TXT = 古典的 DNS トンネリング/持出し。
    label = "mfrggzdfmztwq2lknnwg23tpmfrggzdfmztwq2lknnwg23tp"
    r = det.inspect(f"{label}.tunnel.evil.example", qtype=16)
    assert r["verdict"] == "malicious"
    assert any("エントロピー" in s for s in r["signals"])


def test_ad_srv_recon_is_visualized_not_blocked():
    det = DnsAnomalyDetector()
    r = det.inspect("_ldap._tcp.dc._msdcs.corp.example", qtype=33)
    # 正規にも出る照会なので suspicious 止まり(recon)・score では malicious に昇格しない。
    assert r["verdict"] == "suspicious" and r["recon"] is True


def test_beaconing_encoded_subdomains_is_malicious():
    # 現実の DNS トンネリングは『同一上位ドメインへ、毎回ユニークなエンコード済み
    # サブドメイン』を連打する。エントロピー(チャンク)+ビーコン(頻度)が重なる。
    det = DnsAnomalyDetector()
    verdict = "clean"
    chunk = "mfrggzdfmztwq2lknnwg23tp"       # base32 風の高エントロピー塊
    for i in range(25):
        verdict = det.inspect(f"{i:02d}{chunk}.exfil.example", qtype=1,
                              client="10.0.0.9")["verdict"]
    assert verdict == "malicious"


def test_detector_bounds_tracked_clients_against_spoof_flood():
    # UDP 送信元IPは偽装容易。多数の別送信元を投げても追跡表は上限で頭打ちになる。
    det = DnsAnomalyDetector(max_clients=2)
    for i in range(50):
        det.inspect("a.b.example", qtype=1, client=f"10.0.0.{i}")
    assert len(det._recent) <= 2


def test_short_label_beacon_alone_is_only_suspicious():
    # 短く規則的なサブドメインだけの連打は曖昧 → 誤遮断を避け suspicious 止まり。
    det = DnsAnomalyDetector()
    verdict = "clean"
    for i in range(25):
        verdict = det.inspect(f"s{i}.poll.example", qtype=1,
                              client="10.0.0.8")["verdict"]
    assert verdict == "suspicious"


# ── DnsFilter への統合(監査=可視化 / 強制=遮断) ─────────────────────

def test_audit_mode_alerts_but_forwards():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)                     # 既定 heuristics_audit=True(止めず可視化)
        label = "mfrggzdfmztwq2lknnwg23tpmfrggzdfmztwq2lknnwg23tp"
        d = f.decide(_build_query(f"{label}.x.evil.example", qtype=16))
        assert d["action"] == "alert"        # 遮断しない=上流転送される
        assert f.metrics["suspicious"] == 1 and f.metrics["blocked"] == 0


def test_enforce_mode_blocks_malicious():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.set_heuristics(audit=False)        # 強制=悪性は遮断
        label = "mfrggzdfmztwq2lknnwg23tpmfrggzdfmztwq2lknnwg23tp"
        d = f.decide(_build_query(f"{label}.x.evil.example", qtype=16))
        assert d["action"] == "block"
        assert f.metrics["heuristic_blocked"] == 1


def test_recon_never_blocked_even_when_enforced():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.set_heuristics(audit=False)        # 強制でも偵察は止めない(誤遮断回避)
        d = f.decide(_build_query("_kerberos._tcp.corp.example", qtype=33))
        assert d["action"] == "alert" and f.metrics["recon"] == 1


def test_explicit_blocklist_still_takes_priority():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.add_block("evil.example")
        d = f.decide(_build_query("www.evil.example", qtype=1))
        assert d["action"] == "block" and d["blocked"] is True


def test_allowlisted_source_is_exempt_from_heuristics():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.set_heuristics(audit=False)        # 強制モードでも…
        assert f.add_allow("10.0.0.0/8")["ok"] is True
        label = "mfrggzdfmztwq2lknnwg23tpmfrggzdfmztwq2lknnwg23tp"
        q = _build_query(f"{label}.x.evil.example", qtype=16)
        d = f.decide(q, client="10.1.2.3")   # 免除元 → 検知スキップ
        assert d["action"] == "allow" and d["threat"] is None
        # 免除外の送信元なら同じクエリは遮断される
        d2 = f.decide(q, client="192.0.2.9")
        assert d2["action"] == "block"


def test_allowlist_does_not_exempt_explicit_blocklist():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.add_allow("10.0.0.0/8")
        f.add_block("evil.example")          # 既知悪性は免除しない
        d = f.decide(_build_query("www.evil.example", qtype=1), client="10.1.2.3")
        assert d["action"] == "block" and d["blocked"] is True


def test_heuristics_can_be_disabled():
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.set_heuristics(enabled=False)
        label = "mfrggzdfmztwq2lknnwg23tpmfrggzdfmztwq2lknnwg23tp"
        d = f.decide(_build_query(f"{label}.x.evil.example", qtype=16))
        assert d["action"] == "allow" and d["threat"] is None


def test_recon_mode_alert_flags_ad_srv():
    # 既定(alert): AD向け SRV 照会は recon=suspicious として可視化される。
    det = DnsAnomalyDetector()                 # 既定 recon_mode="alert"
    r = det.inspect("_ldap._tcp.dc._msdcs.corp.example", qtype=33)
    assert r["verdict"] == "suspicious" and r["recon"] is True


def test_recon_mode_off_silences_ad_srv():
    # 利用者の選択(off): AD前段の騒音回避。SRV 照会はフラグされず clean。
    det = DnsAnomalyDetector(recon_mode="ignore")
    r = det.inspect("_ldap._tcp.dc._msdcs.corp.example", qtype=33)
    assert r["verdict"] == "clean" and r["recon"] is False


def test_dns_dedup_collapses_repeated_threat_persistence():
    import os
    from dataplane.engine.core.atomic_io import tail_jsonl
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)                       # 既定 dedup_window=60
        q = _build_query("_ldap._tcp.corp.example", qtype=33)   # recon alert
        for i in range(5):                     # 同一の連打(窓内)
            d = f.decide(q, client="10.0.0.7", now=1000.0 + i)
            assert d["action"] == "alert"
        rows = tail_jsonl(os.path.join(tmp, "dns_log.jsonl"), 20)
        assert len(rows) == 1                  # 永続化は1件に集約
        # メトリクス(累計)は素通し=毎回カウント(集約はログ/画面の氾濫防止が目的)
        assert f.status()["metrics"]["recon"] == 5


def test_dns_dedup_window_expiry_re_persists():
    import os
    from dataplane.engine.core.atomic_io import tail_jsonl
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        q = _build_query("_ldap._tcp.corp.example", qtype=33)
        f.decide(q, client="10.0.0.7", now=1000.0)
        f.decide(q, client="10.0.0.7", now=1100.0)   # 窓外=再記録
        rows = tail_jsonl(os.path.join(tmp, "dns_log.jsonl"), 20)
        assert len(rows) == 2


def test_dns_dedup_can_be_disabled():
    import os
    from dataplane.engine.core.atomic_io import tail_jsonl
    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.set_detection(dedup_window=0)        # 利用者の選択: 集約しない
        q = _build_query("_ldap._tcp.corp.example", qtype=33)
        for i in range(3):
            f.decide(q, client="10.0.0.7", now=1000.0 + i)
        rows = tail_jsonl(os.path.join(tmp, "dns_log.jsonl"), 20)
        assert len(rows) == 3                  # 集約無効=毎回永続化


def test_forward_rejects_forged_transaction_id():
    # 応答インジェクション耐性: txid が一致しない偽造応答は採用しない。
    import socket
    import threading
    with tempfile.TemporaryDirectory() as tmp:
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.bind(("127.0.0.1", 0)); upp = up.getsockname()[1]
        st = {"on": True, "mode": "wrong"}

        def srv():
            up.settimeout(0.3)
            while st["on"]:
                try:
                    data, addr = up.recvfrom(4096)
                except Exception:
                    continue
                tid = b"\xff\xff" if st["mode"] == "wrong" else data[:2]
                try:
                    up.sendto(tid + b"\x81\x80" + data[4:6] + b"\x00\x00" * 3, addr)
                except Exception:
                    pass
        threading.Thread(target=srv, daemon=True).start()
        try:
            f = _filter(tmp); f.upstream = "127.0.0.1"; f.upstream_port = upp
            q = _build_query("good.example", qtype=1)
            raised = False
            try:
                f._forward(q, timeout=0.4)         # 偽造txid → 採用されず例外
            except Exception:
                raised = True
            assert raised
            st["mode"] = "right"
            data = f._forward(q, timeout=1.0)       # 正txid → 採用
            assert data[:2] == q[:2]
        finally:
            st["on"] = False; up.close()


def test_slow_upstream_does_not_serialize_queries():
    # 遅い上流(1問い合わせ D 秒)でも、複数クエリが並行処理される(全体≈D, 直列ならN*D)。
    import socket
    import threading
    import time as _t
    D = 0.3
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up.bind(("127.0.0.1", 0))
    up_port = up.getsockname()[1]
    run = {"on": True}

    def _upstream():
        while run["on"]:
            try:
                q, addr = up.recvfrom(4096)
            except Exception:
                break
            def _reply(q=q, addr=addr):
                _t.sleep(D)                    # 上流の遅延を模擬
                try:
                    up.sendto(q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x00" * 3, addr)
                except Exception:
                    pass
            threading.Thread(target=_reply, daemon=True).start()
    threading.Thread(target=_upstream, daemon=True).start()

    with tempfile.TemporaryDirectory() as tmp:
        f = _filter(tmp)
        f.upstream, f.upstream_port = "127.0.0.1", up_port
        info = f.start()
        try:
            assert info["ok"]
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.settimeout(3)
            n = 5
            start = _t.time()
            for i in range(n):                 # 通常ドメイン=allow→上流転送
                c.sendto(_build_query(f"h{i}.example", qtype=1), ("127.0.0.1", f.port))
            got = 0
            for _ in range(n):
                try:
                    c.recvfrom(4096)
                    got += 1
                except socket.timeout:
                    break
            elapsed = _t.time() - start
            assert got == n                    # 全応答が返る
            assert elapsed < D * n * 0.6       # 直列(N*D=1.5s)よりはるかに速い
        finally:
            f.stop()
            run["on"] = False
            up.close()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")


# ── 応答レート制限 RRL(#15): UDP spoof による反射増幅の踏み台化を防ぐ ──
def test_dns_response_rate_limiting():
    with tempfile.TemporaryDirectory() as tmp:
        df = DnsFilter(state_dir=tmp)
        df._rrl_max = 3                                # 送信元毎 3応答/窓
        src = "203.0.113.50"                          # 攻撃者が詐称し得る『被害者IP』
        results = [df._rate_limited(src) for _ in range(6)]
        assert results[:3] == [False, False, False]   # 上限までは応答
        assert any(results[3:])                        # 超過分は破棄(被害者へ撃ち返さない)
        assert df._rate_limited("198.51.100.9") is False   # 別送信元は独立(巻き添えなし)
        df._rrl_max = 0
        assert df._rate_limited("any") is False        # 0=無効(従来挙動)
