"""
test_posmodel.py — 正のセキュリティモデル(スキーマ allowlist・evolution #62)。
====================================================================================
許可した (パス, メソッド) だけ通し、それ以外を逸脱として弾く/記録する。未知の攻撃・ゼロデイにも
構造的に強い(許可外=通さない)。純粋マッチング + NetShield 統合(enforce/audit・署名永続)を守る。
"""
import tempfile

from dataplane.engine.lifeform.posmodel import build_model, PositiveModel, Rule
from dataplane.engine.lifeform.pipeline import NetShield


def test_empty_model_allows_everything():
    m = PositiveModel()
    assert m.empty
    assert m.check("GET", "/anything")["allowed"]


def test_prefix_and_method_matching():
    m = build_model([{"path": "/api/", "match": "prefix", "methods": ["GET", "POST"]}])
    assert m.check("GET", "/api/users")["allowed"]
    assert m.check("POST", "/api/users?q=1")["allowed"]          # query 無視
    d = m.check("DELETE", "/api/users")
    assert not d["allowed"] and d["reason"] == "method-not-allowed"
    d2 = m.check("GET", "/admin")
    assert not d2["allowed"] and d2["reason"] == "path-not-in-allowlist"


def test_exact_match():
    m = build_model([{"path": "/health", "match": "exact", "methods": ["GET"]}])
    assert m.check("GET", "/health")["allowed"]
    assert not m.check("GET", "/health/x")["allowed"]            # exact=前方一致でない


def test_regex_match_and_any_method():
    m = build_model([{"path": r"/u/\d+", "match": "regex"}])     # methods 空=任意
    assert m.check("GET", "/u/123")["allowed"]
    assert m.check("DELETE", "/u/999")["allowed"]
    assert not m.check("GET", "/u/abc")["allowed"]


def test_build_model_skips_dangerous_regex():
    # ReDoS 検証で危険なパターンは載せない(自己DoS防止)。validate は『危険なら理由』を返す。
    danger = lambda p: "redos" if "(.*)+" in p else ""
    m = build_model([{"path": "(.*)+x", "match": "regex"},
                     {"path": "/ok", "match": "prefix"}], validate=danger)
    assert m.size == 1 and m.check("GET", "/ok/y")["allowed"]


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_netshield_enforce_blocks_unlisted():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, posmodel_enabled=True, posmodel_mode="enforce")
        sh.set_posmodel([{"path": "/api/", "methods": ["GET", "POST"]}])
        assert sh.inspect("1.1.1.1", path="/api/users", method="GET")["action"] == "allow"
        # 許可外パス→遮断
        assert sh.inspect("2.2.2.2", path="/secret", method="GET")["action"] == "block"
        # 許可パスだが許可外メソッド→遮断
        assert sh.inspect("3.3.3.3", path="/api/users", method="DELETE")["action"] == "block"


def test_netshield_audit_records_but_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, posmodel_enabled=True, posmodel_mode="audit")
        sh.set_posmodel([{"path": "/api/", "methods": ["GET"]}])
        r = sh.inspect("4.4.4.4", path="/secret", method="GET")
        assert r["action"] == "allow"                            # audit=遮断しない
        evs = [e for e in sh.events(50) if e.get("kind") == "posmodel_violation"]
        assert evs and evs[-1]["reason"] == "path-not-in-allowlist"


def test_netshield_disabled_or_empty_no_constraint():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, posmodel_enabled=True)                   # ルール空=制約なし
        assert sh.inspect("5.5.5.5", path="/whatever", method="GET")["action"] == "allow"
        sh.set_posmodel([{"path": "/api/"}])
        sh.cfg["posmodel_enabled"] = False                       # 無効=制約なし
        assert sh.inspect("6.6.6.6", path="/secret", method="GET")["action"] == "allow"


def test_posmodel_persists_signed_and_reloads():
    import json
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_posmodel([{"path": "/api/", "methods": ["GET"]}])
        with open(sh._posmodel_path, encoding="utf-8") as f:
            assert "_sig" in json.load(f)                        # 署名永続(#52 と一貫)
        sh2 = _shield(d)                                         # 再起動相当
        assert sh2._posmodel.size == 1
