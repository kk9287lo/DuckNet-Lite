"""
test_credrate.py — クレデンシャル単位レート制限(evolution #70)。
====================================================================================
IP ではなく Bearer トークン/API キーの識別子単位でレートを集計し、攻撃者が IP をローテーション
しつつ同一の盗用キーを使う濫用を、IP に依らず絞る。トークンは生で保持せずハッシュ短縮。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["cred_rate_enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_credential_rate_counts_window():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_window_sec=60)
        with sh._lock:
            for i in range(5):
                n = sh._credential_rate("tok-abc")
        assert n == 5
        # 別クレデンシャルは別カウント
        with sh._lock:
            assert sh._credential_rate("tok-xyz") == 1


def test_raw_token_not_stored():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        with sh._lock:
            sh._credential_rate("super-secret-token")
        # キーは生トークンでなくハッシュ(bytes)
        keys = list(sh._cred_rate.keys())
        assert keys and isinstance(keys[0], bytes)
        assert b"super-secret-token" not in b"".join(keys)


def test_same_key_across_ips_escalates():
    # 同一キーを *異なる IP* から大量送信→キー単位の窓が上限超過→各 IP に加点(チャレンジ/遮断へ)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_limit=20, cred_rate_score=40,
                     challenge_score=40, block_score=100)
        token = "Bearer stolen-key-123"  # inspect は cred をそのまま使う
        acts = set()
        for i in range(40):
            r = sh.inspect(f"10.0.0.{i % 250}", path="/api", cred="stolen-key-123")
            acts.add(r["action"])
        assert acts & {"challenge", "block", "throttle"}    # キー濫用が IP 横断で escalation
        assert sh.metrics().get("cred_rate_hit", 0) >= 1


def test_under_limit_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_limit=100)
        for i in range(10):
            r = sh.inspect("1.1.1.1", path="/api", cred="legit-key")
        assert r["action"] == "allow"


def test_disabled_no_limit():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_enabled=False, cred_rate_limit=2)
        for i in range(20):
            r = sh.inspect("2.2.2.2", path="/api", cred="key")
        assert r["action"] == "allow"


def test_no_cred_skips():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_limit=1)
        # cred 無し=このレート制限は作動しない
        assert sh.inspect("3.3.3.3", path="/api")["action"] == "allow"


def test_cred_rate_map_bounded():
    from dataplane.engine.lifeform import pipeline as P
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        old = P._CRED_RATE_CAP
        P._CRED_RATE_CAP = 100
        try:
            with sh._lock:
                for i in range(300):
                    sh._credential_rate(f"key-{i}")
            assert len(sh._cred_rate) <= 100        # マップは有界
        finally:
            P._CRED_RATE_CAP = old
