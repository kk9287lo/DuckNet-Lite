"""
test_stall.py — 迂回検知 / dead-man's switch(evolution #78)。
====================================================================================
DuckNet 経由のトラフィックが直近 busy だったのに突然ゼロ=再ルーティング等で迂回された疑い。
busy→ゼロ の遷移のみ警報し、自然な低トラフィック/初回ではFPしない。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg.update(cfg)
    return sh


def test_warmup_no_stall():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.traffic_stall_check(now=1000.0)["stall"] is False    # 初回=warmup


def test_busy_then_zero_is_stall():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, stall_min_rate=1.0)
        # t0: 基準
        sh._metrics["requests"] = 0
        sh.traffic_stall_check(now=0.0)
        # t1: 30秒で 300 件(=10 req/s = busy)
        sh._metrics["requests"] = 300
        r1 = sh.traffic_stall_check(now=30.0)
        assert r1["stall"] is False and r1["prev_rate"] == 0.0          # 前区間が基準=まだ
        # t2: さらに 30 秒で +0 件(突然ゼロ)。直前区間は busy(10/s)→ stall
        r2 = sh.traffic_stall_check(now=60.0)
        assert r2["stall"] is True and r2["prev_rate"] >= 1.0


def test_low_traffic_no_false_positive():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, stall_min_rate=5.0)        # 5 req/s 未満は静観
        sh._metrics["requests"] = 0
        sh.traffic_stall_check(now=0.0)
        sh._metrics["requests"] = 10               # 30秒で10件=0.33/s(busyでない)
        sh.traffic_stall_check(now=30.0)
        r = sh.traffic_stall_check(now=60.0)       # その後ゼロでも busy でなかった→警報しない
        assert r["stall"] is False


def test_disabled_no_stall():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, stall_detect_enabled=False, stall_min_rate=1.0)
        sh._metrics["requests"] = 0; sh.traffic_stall_check(now=0.0)
        sh._metrics["requests"] = 300; sh.traffic_stall_check(now=30.0)
        assert sh.traffic_stall_check(now=60.0)["stall"] is False


def test_sustained_traffic_no_stall():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, stall_min_rate=1.0)
        sh._metrics["requests"] = 0; sh.traffic_stall_check(now=0.0)
        for i, t in enumerate([30.0, 60.0, 90.0], start=1):
            sh._metrics["requests"] = 300 * i      # 継続的にトラフィックあり
            r = sh.traffic_stall_check(now=t)
            assert r["stall"] is False             # 流れている限り警報しない
