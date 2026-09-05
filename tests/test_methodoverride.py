"""
test_methodoverride.py — メソッドオーバーライド悪用対策(evolution #72)。
====================================================================================
X-HTTP-Method-Override 等で実効メソッドを差し替え、blocked_methods や method ベース認可を回避する
手口を塞ぐ。オーバーライド先にも method ポリシーを適用。method_override_block で存在自体を遮断。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_override_to_blocked_method_is_blocked():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, blocked_methods=["TRACE", "CONNECT", "DELETE"])
        # line method は無害な POST だが、override で DELETE に差し替え→遮断
        r = sh.inspect("9.9.9.9", path="/x", method="POST", override_method="DELETE")
        assert r["action"] == "block"


def test_override_to_allowed_method_passes():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, blocked_methods=["TRACE"])
        r = sh.inspect("1.1.1.1", path="/x", method="POST", override_method="PUT")
        assert r["action"] == "allow"                  # PUT は blocked_methods に無い


def test_override_check_disabled():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, blocked_methods=["DELETE"], method_override_check=False)
        r = sh.inspect("2.2.2.2", path="/x", method="POST", override_method="DELETE")
        assert r["action"] == "allow"                  # チェック無効=override は見ない


def test_override_block_rejects_any_override():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, method_override_block=True, blocked_methods=[])
        # blocked_methods が空でも、オーバーライドヘッダの存在自体を遮断
        r = sh.inspect("3.3.3.3", path="/x", method="POST", override_method="PUT")
        assert r["action"] == "block"


def test_no_override_unaffected():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, method_override_block=True, blocked_methods=["DELETE"])
        r = sh.inspect("4.4.4.4", path="/x", method="POST")   # override 無し
        assert r["action"] == "allow"


def test_line_method_still_blocked():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, blocked_methods=["TRACE"])
        r = sh.inspect("5.5.5.5", path="/x", method="TRACE")  # 従来の line メソッド遮断は不変
        assert r["action"] == "block"
