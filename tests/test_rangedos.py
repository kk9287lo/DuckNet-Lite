"""
test_rangedos.py — Range ヘッダ DoS 対策(Apache Killer・evolution #76)。
====================================================================================
多数レンジ要求(Range: bytes=0-,0-,0-,...)でサーバに大量バッファを確保させる DoS を、レンジ数の
上限で遮断する。正規クライアント(動画プレイヤ等)は 1〜2 レンジ=低FP。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_many_ranges_blocked():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, range_max_ranges=8)
        rng = "bytes=" + ",".join(f"{i}-{i+1}" for i in range(50))
        r = sh.inspect("9.9.9.9", path="/big.iso", range_header=rng)
        assert r["action"] == "block"


def test_few_ranges_allowed():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, range_max_ranges=8)
        assert sh.inspect("1.1.1.1", path="/v.mp4", range_header="bytes=0-1023")["action"] == "allow"
        assert sh.inspect("1.1.1.2", path="/v.mp4",
                          range_header="bytes=0-1023,2048-4095")["action"] == "allow"


def test_non_bytes_range_ignored():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, range_max_ranges=2)
        # bytes= でない単位(items 等)は本チェック対象外
        r = sh.inspect("2.2.2.2", path="/x", range_header="items=0-100,1-2,3-4,5-6")
        assert r["action"] == "allow"


def test_disabled_passes():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, range_check_enabled=False, range_max_ranges=2)
        rng = "bytes=" + ",".join(f"{i}-{i+1}" for i in range(50))
        assert sh.inspect("3.3.3.3", path="/x", range_header=rng)["action"] == "allow"


def test_no_range_unaffected():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, range_max_ranges=2)
        assert sh.inspect("4.4.4.4", path="/x")["action"] == "allow"
