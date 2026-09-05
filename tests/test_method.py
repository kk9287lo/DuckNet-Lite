"""
test_method.py — HTTPメソッドポリシー(evolution #26)。
====================================================================================
XST(TRACE/TRACK)・プロキシ濫用(CONNECT)等、アプリ前段にまず正規には来ない異常メソッドを
遮断する。既定3種の遮断・通常メソッド通過・大小無視・設定の検証/置換/永続化・空で無効化を守る。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _shield(tmp, **cfg):
    sh = NetShield(state_dir=tmp); sh.enable()
    sh.cfg.update(cfg)
    return sh


def test_default_blocks_trace_track_connect():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for m in ("TRACE", "TRACK", "CONNECT"):
            r = sh.inspect(f"203.0.113.{hash(m) % 200 + 1}", path="/", method=m)
            assert r["action"] == "block" and f"メソッド遮断: {m}" in r["reason"]


def test_normal_methods_pass():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for m in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"):
            r = sh.inspect("203.0.113.40", path="/", method=m)
            assert r["action"] == "allow"


def test_method_match_is_case_insensitive():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        r = sh.inspect("203.0.113.41", path="/", method="trace")    # 小文字でも遮断
        assert r["action"] == "block" and "メソッド遮断: TRACE" in r["reason"]


def test_empty_list_disables_blocking():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_blocked_methods([])
        r = sh.inspect("203.0.113.42", path="/", method="TRACE")
        assert r["action"] == "allow"


def test_custom_blocked_method():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_blocked_methods(["delete"])                          # 小文字入力→正規化
        assert sh.cfg["blocked_methods"] == ["DELETE"]
        assert sh.inspect("203.0.113.43", path="/", method="DELETE")["action"] == "block"
        assert sh.inspect("203.0.113.43", path="/", method="GET")["action"] == "allow"


def test_set_blocked_methods_validation_and_persist():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        res = sh.set_blocked_methods(["trace", "TRACE", "BAD-METHOD", "", 5, "CONNECT"])
        assert res["blocked_methods"] == ["TRACE", "CONNECT"]        # 重複/非英字/空/非str を除去
        sh2 = NetShield(state_dir=tmp)                              # 永続化を別インスタンスで確認
        assert sh2.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
