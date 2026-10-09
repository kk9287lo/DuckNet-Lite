"""
test_sweep_det_periphery.py — 検知エンジン周辺(BAN ブルーム)の回帰。
====================================================================================
一時停止の補正で延長した BAN をブルームへ戻さず偽陰性になった(#45・Lite では呼び出し元が
無く潜在)、間引いたブルーム再構築が二度と走らなかった(#46)。
"""
import tempfile
import time

from dataplane.engine.lifeform.pipeline import NetShield


# ── #45 一時停止の補正で延長した BAN がブルームから漏れる ─────────────────────
def test_d45_absorb_suspend_readds_extended_bans_to_bloom():
    """停止中に wall-clock で切れた BAN を absorb_suspend が延長しても、その間にブルームが
    作り直されていると BAN 中なのに is_banned_fast が False(偽陰性)になっていた。"""
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        a, b = "192.0.2.10", "192.0.2.20"
        sh.ban(a, ttl_sec=60)
        sh.ban(b, ttl_sec=3600)
        gap = 120.0
        # 120 秒の凍結中に a の 60 秒 BAN が wall-clock で切れた(30 秒前に失効)状態を作る
        sh._ips[a]["ban_until"] = time.time() - 30.0
        sh.rebuild_ban_bloom(force=True)                   # 復帰直後の再構築で a が落ちる
        assert not sh.is_banned_fast(a)                    # 前提: この時点では失効扱い
        r = sh.absorb_suspend(gap)
        assert r["bans"] >= 1
        assert sh._ips[a]["ban_until"] > time.time()       # 延長されて BAN 中
        assert sh.is_banned_fast(a), "延長した BAN がブルームに無い(偽陰性)"
        assert sh.is_banned_fast(b)


# ── #46 間引いたブルーム再構築が走らない ──────────────────────────────────────
def test_d46_periodic_tick_runs_deferred_bloom_rebuild():
    """解除の連打で間引いた再構築(_bloom_dirty)を誰も消化せず、陳腐ビットが残り続けた。"""
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        ips = ["198.51.100.%d" % i for i in range(1, 30)]
        for ip in ips:
            sh.ban(ip, ttl_sec=3600)
        keep = "192.0.2.99"
        sh.ban(keep, ttl_sec=3600)
        sh.rebuild_ban_bloom(force=True)
        sh.cfg["bloom_rebuild_min_interval_sec"] = 3600.0   # 連打中は必ず間引かせる
        for ip in ips:
            sh.unban(ip)
        assert sh._bloom_dirty                             # 前提: 再構築が間引かれた
        sh.cfg["bloom_rebuild_min_interval_sec"] = 2.0
        sh._bloom_rebuilt = time.time() - 10.0             # 最小間隔は過ぎた
        sh.traffic_stall_check()                           # 周期 tick(proxy の定期ループが呼ぶ)
        assert not sh._bloom_dirty, "間引いた再構築が周期 tick で消化されない"
        assert sh._ban_bloom.n == 1                        # 現役 BAN(keep)だけが残る
        assert sh.is_banned_fast(keep)
        assert not any(ip in sh._ban_bloom for ip in ips[:3])


def test_d46_periodic_tick_purges_naturally_expired_bans():
    """自然失効した BAN はブルームから一度も落ちず、長期稼働でブルームが飽和していた。"""
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        ips = ["198.51.100.%d" % i for i in range(1, 21)]
        for ip in ips:
            sh.ban(ip, ttl_sec=3600)
        keep = "192.0.2.99"
        sh.ban(keep, ttl_sec=7200)
        sh.rebuild_ban_bloom(force=True)
        assert sh._ban_bloom.n == 21
        for ip in ips:                                     # 20 件が自然失効
            sh._ips[ip]["ban_until"] = time.time() - 1.0
        sh._bloom_rebuilt = time.time() - 3600.0           # 前回の再構築から 1 時間
        sh.traffic_stall_check()
        assert sh._ban_bloom.n == 1, "自然失効した BAN がブルームに残り続ける"
        assert sh.is_banned_fast(keep)
