"""
test_connlimit.py — per-IP 同時接続数の上限(evolution #30・nginx limit_conn 相当)。
====================================================================================
レート(per-request トークンバケツ)とは別軸で、1 IP が同時に保持できる接続数を上限で絞る
(接続枯渇/slowloris 増幅対策)。既定0=無制限(NAT巻き添え回避でオプトイン)。上限超過は head
解析前に即切断し本体へ通さない・終了/例外でも必ず計数を戻す。fake writer で _handle を直接駆動。
"""
import asyncio
import tempfile

import dataplane.engine.lifeform.pipeline as ND
from dataplane.engine.services.proxy import AsyncEdgeGuard


class _W:
    def __init__(self, ip): self.ip, self.closed = ip, False
    def write(self, b): pass
    async def drain(self): pass
    def close(self): self.closed = True
    def get_extra_info(self, k, default=None):
        return (self.ip, 5555) if k == "peername" else default


def _guard_with_cap(tmp, cap):
    ND._SHIELD = ND.NetShield(state_dir=tmp)
    ND._SHIELD.cfg["max_conn_per_ip"] = cap
    return AsyncEdgeGuard()


def test_conn_cap_rejects_over_limit():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard_with_cap(tmp, 2)
        called = []
        async def fake(r, w): called.append(1)
        g._handle_conn = fake
        try:
            g._conn_per_ip["9.9.9.9"] = 2                  # 既に上限本数
            w = _W("9.9.9.9")
            asyncio.run(g._handle(None, w))
            assert called == [] and w.closed              # 本体に通さず即切断
            assert g.metrics.get("conn_rejected") == 1
            assert g._conn_per_ip["9.9.9.9"] == 2          # 拒否は計上しない
        finally:
            ND._SHIELD = osh


def test_conn_under_cap_processes_and_cleans_up():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard_with_cap(tmp, 2)
        seen = []
        async def fake(r, w): seen.append(g._conn_per_ip.get("8.8.8.8"))
        g._handle_conn = fake
        try:
            asyncio.run(g._handle(None, _W("8.8.8.8")))
            assert seen == [1]                            # 処理中は1本計上
            assert "8.8.8.8" not in g._conn_per_ip        # 終了後に破棄(0本=辞書有界)
        finally:
            ND._SHIELD = osh


def test_conn_cap_zero_is_unlimited():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard_with_cap(tmp, 0)                       # 既定OFF
        called = []
        async def fake(r, w): called.append(1)
        g._handle_conn = fake
        try:
            g._conn_per_ip["7.7.7.7"] = 999               # 上限なし=無視
            asyncio.run(g._handle(None, _W("7.7.7.7")))
            assert called == [1] and g.metrics.get("conn_rejected", 0) == 0
        finally:
            ND._SHIELD = osh


def test_conn_counter_decrements_on_exception():
    osh = ND._SHIELD
    with tempfile.TemporaryDirectory() as tmp:
        g = _guard_with_cap(tmp, 5)
        async def boom(r, w): raise RuntimeError("x")
        g._handle_conn = boom
        try:
            try:
                asyncio.run(g._handle(None, _W("6.6.6.6")))
            except RuntimeError:
                pass
            assert "6.6.6.6" not in g._conn_per_ip        # 例外でも finally で減算/破棄
        finally:
            ND._SHIELD = osh
