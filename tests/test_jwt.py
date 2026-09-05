"""
test_jwt.py — JWT 検査(認証層の防御・evolution #68)。
====================================================================================
署名鍵を持たなくても、Authorization: Bearer の JWT header から alg:none(無署名=認証バイパス)/
許可外 alg(alg 混同攻撃)を構造点検だけで遮断する。署名検証はアプリの責務(鍵が無い)。
"""
import base64
import json
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield, _jwt_alg, _jwt_violation


def _b64u(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(alg: str) -> str:
    return f"{_b64u({'alg': alg, 'typ': 'JWT'})}.{_b64u({'sub': 'admin'})}.sig"


def test_jwt_alg_extraction():
    assert _jwt_alg(_jwt("RS256")) == "RS256"
    assert _jwt_alg(_jwt("none")) == "none"
    assert _jwt_alg("not.a.jwt-bad-base64!!!") is None
    assert _jwt_alg("only.two") is None
    assert _jwt_alg("") is None


def test_jwt_violation_none():
    assert _jwt_violation("Bearer " + _jwt("none"), []) == "jwt:alg=none"
    assert _jwt_violation("Bearer " + _jwt("None"), []) == "jwt:alg=none"   # 大小無視
    assert _jwt_violation("Bearer " + _jwt("nOnE"), []) == "jwt:alg=none"


def test_jwt_violation_allowed_algs():
    # ホワイトリスト指定時、許可外 alg(alg 混同)を遮断
    assert _jwt_violation("Bearer " + _jwt("HS256"), ["RS256", "ES256"]).startswith(
        "jwt:alg-not-allowed")
    assert _jwt_violation("Bearer " + _jwt("RS256"), ["RS256", "ES256"]) == ""   # 許可
    assert _jwt_violation("Bearer " + _jwt("HS256"), []) == ""                   # 空=none のみ遮断


def test_jwt_violation_non_jwt():
    assert _jwt_violation("Bearer opaque-session-token", []) == ""    # 非JWT=対象外
    assert _jwt_violation("Basic dXNlcjpwYXNz", []) == ""             # 非Bearer
    assert _jwt_violation("", []) == ""


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_inspect_blocks_alg_none():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect("9.9.9.9", path="/api", auth="Bearer " + _jwt("none"))
        assert r["action"] == "block"
        assert sh.is_banned_fast("9.9.9.9")


def test_inspect_blocks_disallowed_alg():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, jwt_allowed_algs=["RS256"])
        assert sh.inspect("8.8.8.8", path="/api", auth="Bearer " + _jwt("HS256"))["action"] == "block"
        assert sh.inspect("1.1.1.1", path="/api", auth="Bearer " + _jwt("RS256"))["action"] == "allow"


def test_inspect_allows_normal_jwt():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.inspect("2.2.2.2", path="/api", auth="Bearer " + _jwt("RS256"))["action"] == "allow"


def test_inspect_disabled():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, jwt_inspect_enabled=False)
        assert sh.inspect("3.3.3.3", path="/api", auth="Bearer " + _jwt("none"))["action"] == "allow"


def test_inspect_no_auth_header():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.inspect("4.4.4.4", path="/api")["action"] == "allow"   # auth 無し=素通り
