"""
test_connlimit_global.py — グローバル同時接続上限 / 資源枯渇ハードニング(evolution #79)。
====================================================================================
接続フラッドで FD/ソケット/メモリを枯渇させ OS ごと落とす攻撃に対し、*全体* の同時接続数で
頭打ちにしてロードシェッドする(per-IP の #30 の上)。FD ソフト上限引き上げは best-effort。
"""
import asyncio

from dataplane.engine.services.proxy import AsyncEdgeGuard
from dataplane.engine.lifeform.pipeline import net_shield


class _NullWriter:
    def get_extra_info(self, _k):
        return ("9.9.9.9", 1234)

    def close(self):
        pass


def test_global_cap_rejects_over_limit():
    sh = net_shield()
    saved = sh.cfg.get("max_total_conn")
    sh.cfg["max_total_conn"] = 5
    try:
        g = AsyncEdgeGuard()
        g._active = 6                                  # 既に上限超過の状態を模す
        before = g.metrics.get("conn_rejected_global", 0)
        # _handle は _active を +1 してから判定(7 > 5)→ 即切断
        asyncio.run(g._handle(None, _NullWriter()))
        assert g.metrics.get("conn_rejected_global", 0) == before + 1
        assert g.metrics["accepted"] == 0              # 本体(_handle_conn)に通っていない
    finally:
        if saved is None:
            sh.cfg.pop("max_total_conn", None)
        else:
            sh.cfg["max_total_conn"] = saved


def test_global_cap_zero_means_unlimited():
    sh = net_shield()
    saved = sh.cfg.get("max_total_conn")
    sh.cfg["max_total_conn"] = 0
    try:
        g = AsyncEdgeGuard()
        g._active = 100000
        # 0=無制限 → グローバル上限では切らない(_handle_conn 側で head 読取に進む=writer 操作で例外→握り潰し)
        before = g.metrics.get("conn_rejected_global", 0)
        asyncio.run(g._handle(None, _NullWriter()))
        assert g.metrics.get("conn_rejected_global", 0) == before   # グローバル切断は発生しない
    finally:
        if saved is None:
            sh.cfg.pop("max_total_conn", None)
        else:
            sh.cfg["max_total_conn"] = saved


def test_raise_fd_limit_is_safe():
    # 非対応プラットフォームでも例外を投げない(best-effort)。
    AsyncEdgeGuard._raise_fd_limit()                   # 例外が出ないこと


def test_per_ip_connection_rate_gate():
    # #10: 接続→即RST を高速反復する churn フラッドを per-IP の接続レートで shed する。
    from dataplane.engine.services.proxy import AsyncEdgeGuard
    g = AsyncEdgeGuard()
    res = [g._conn_rate_exceeded("203.0.113.7", 3) for _ in range(6)]
    assert res[:3] == [False, False, False]               # 上限までは通す
    assert all(res[3:])                                    # 超過は shed(即切断対象)
    assert g._conn_rate_exceeded("198.51.100.1", 3) is False   # 別IPは独立(巻き添えなし)
