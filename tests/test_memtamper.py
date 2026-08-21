"""
test_memtamper.py — in-memory cfg すり替え検知+復元(evolution #85)。
====================================================================================
デバッガ/プロセス注入で in-memory cfg を *API を通さず* 書き換える(例: enabled を False に)攻撃を、
整合 MAC の不一致で検知し、署名検証済みディスク state から正規状態へ復元する。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def test_clean_cfg_not_flagged():
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        r = sh.verify_cfg_integrity()
        assert r["tampered"] is False


def test_legit_change_updates_mac():
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.set_config(flood_threshold=200)              # 正規変更=_save が MAC 更新
        assert sh.verify_cfg_integrity()["tampered"] is False   # 正規変更は誤検知しない


def test_out_of_band_memory_edit_detected_and_restored():
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.set_config(block_score=100)                 # 正規状態を確定(MAC 更新)
        # 攻撃者が API を通さず in-memory cfg を直接書換(WAF を無効化 + 閾値を骨抜き)
        sh.cfg["enabled"] = False
        sh.cfg["block_score"] = 999999
        r = sh.verify_cfg_integrity()
        assert r["tampered"] is True and r["restored"] is True
        # 署名済みディスクの正規値へ復元される
        assert sh.cfg["enabled"] is True
        assert sh.cfg["block_score"] == 100
        # 復元後は再び健全
        assert sh.verify_cfg_integrity()["tampered"] is False


def test_type_change_tamper_restored():
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.set_config(flood_threshold=200)
        sh.cfg["flood_threshold"] = "x"                # 型まで改変
        r = sh.verify_cfg_integrity()
        assert r["tampered"] and sh.cfg["flood_threshold"] == 200   # 保存済み正規値へ確実に復元


def test_tamper_reported():
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.set_config(flood_threshold=200)
        sh.cfg["flood_threshold"] = 999999             # out-of-band 改変(既定と異なる値)
        sh.verify_cfg_integrity()
        assert sh.metrics()["tamper"]["count"] >= 1
        assert sh.metrics()["tamper"]["last"]["kind"] == "memory_tamper"
