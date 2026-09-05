"""
test_pathoverride.py — パスオーバーライド ACL バイパス対策(evolution #73)。
====================================================================================
X-Original-URL/X-Rewrite-URL は内部 rewrite 用ヘッダ。前段エッジにクライアントが送る=パス ACL
回避の手口(IIS/nginx)。既定で遮断。無効化も可。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_path_override_blocked():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        # GET /(許可)に override で /admin → 遮断
        r = sh.inspect("9.9.9.9", path="/", method="GET", override_path="/admin")
        assert r["action"] == "block"


def test_no_override_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.inspect("1.1.1.1", path="/", method="GET")["action"] == "allow"


def test_disabled_passes():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, path_override_block=False)
        r = sh.inspect("2.2.2.2", path="/", method="GET", override_path="/admin")
        assert r["action"] == "allow"
