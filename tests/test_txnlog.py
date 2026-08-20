"""
test_txnlog.py — 構造化トランザクションログ(evolution #14)。
====================================================================================
安定スキーマ(uid付き)・末尾読取・SIEM 任意転送と、proxy._txn の配線(action→verdict 導出・
reason→sig 抽出・既定OFFはゼロ書込み)を回帰から守る。
"""
import contextlib
import tempfile
import time

import dataplane.engine.lifeform.forwarders as F
import dataplane.engine.services.txnlog as T
from dataplane.engine.services.proxy import AsyncEdgeGuard
from dataplane.engine.services.txnlog import TransactionLog, new_uid
from dataplane.engine.lifeform.pipeline import net_shield

_SCHEMA = ("ts", "uid", "src", "method", "host", "uri", "ua", "zone", "action",
           "verdict", "reason", "sig", "score", "bytes_in", "bytes_out", "duration")


class _Fake:
    def __init__(self):
        self.events = []

    def send(self, event, source, severity):
        self.events.append((dict(event), source, severity))


@contextlib.contextmanager
def _txn_enabled(tmp, forward=False):
    """txn_log を tmp バックエンドへ、net_shield の cfg を txnlog ON へ(後で復元)。"""
    sh = net_shield()
    pt, prev = T._TXN, dict(sh.cfg)
    T._TXN = TransactionLog(state_dir=tmp)
    sh.cfg["txnlog_enabled"] = True
    sh.cfg["txnlog_forward"] = forward
    try:
        yield T._TXN
    finally:
        T._TXN = pt
        sh.cfg.clear(); sh.cfg.update(prev)


# ── TransactionLog 本体 ──────────────────────────────────────────────────
def test_record_stable_schema_and_uid():
    with tempfile.TemporaryDirectory() as tmp:
        tl = TransactionLog(state_dir=tmp)
        r = tl.record({"src": "1.2.3.4", "method": "GET", "host": "h", "uri": "/x",
                       "action": "block", "verdict": "malicious", "reason": "signature:sqli",
                       "sig": "sqli", "score": 80, "bytes_in": 10, "bytes_out": 20,
                       "duration": 0.5})
        assert all(k in r for k in _SCHEMA)              # 全列が存在(安定スキーマ)
        assert r["uid"] and r["src"] == "1.2.3.4" and r["score"] == 80
        assert len({new_uid() for _ in range(200)}) == 200   # uid は一意
        tail = tl.tail(10)
        assert tail and tail[0]["uid"] == r["uid"]       # 末尾読取(最新が先頭)


def test_record_fills_defaults_for_missing_fields():
    with tempfile.TemporaryDirectory() as tmp:
        r = TransactionLog(state_dir=tmp).record({"src": "5.5.5.5", "action": "allow"})
        assert r["method"] == "" and r["sig"] == "" and r["bytes_out"] == 0
        assert isinstance(r["ts"], float) and r["uid"]


def test_record_forwards_to_siem_when_requested():
    fake = _Fake()
    prev = F._DEFAULT
    F._DEFAULT = F.Fanout([fake])
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tl = TransactionLog(state_dir=tmp)
            tl.record({"src": "9.9.9.9", "action": "block", "verdict": "malicious"},
                      forward=True)
            F._DEFAULT.close()
            deadline = time.time() + 2.0
            while not fake.events and time.time() < deadline:
                time.sleep(0.02)
        assert any(e[0]["src"] == "9.9.9.9" and e[1] == "http" for e in fake.events)
    finally:
        F._DEFAULT = prev


# ── proxy._txn の配線 ────────────────────────────────────────────────────
def test_txn_helper_records_block_and_allow():
    with tempfile.TemporaryDirectory() as tmp, _txn_enabled(tmp) as tl:
        g = AsyncEdgeGuard()
        g._txn(ip="203.0.113.1", method="GET", host="app", path="/a?x=1",
               zone="public", action="block", reason="signature:sqli-tautology",
               score=100, dur=0.01)
        g._txn(ip="203.0.113.2", method="POST", host="app", path="/b", zone="public",
               action="allow", b_in=120, b_out=900, dur=0.2)
        rows = {r["action"]: r for r in tl.tail(10)}
        assert len(rows) == 2
        assert rows["block"]["verdict"] == "malicious"          # action→verdict 導出
        assert rows["block"]["sig"] == "sqli-tautology"         # reason→sig 抽出
        assert rows["allow"]["verdict"] == "clean"
        assert rows["allow"]["bytes_out"] == 900 and rows["allow"]["method"] == "POST"


def test_txn_helper_disabled_is_noop():
    with tempfile.TemporaryDirectory() as tmp:
        sh = net_shield()
        pt, prev = T._TXN, dict(sh.cfg)
        T._TXN = TransactionLog(state_dir=tmp)
        sh.cfg["txnlog_enabled"] = False
        try:
            AsyncEdgeGuard()._txn(ip="1.1.1.1", method="GET", host="h", path="/",
                                  action="allow")
            assert T._TXN.tail(10) == []                        # 既定OFF=何も書かない
        finally:
            T._TXN = pt
            sh.cfg.clear(); sh.cfg.update(prev)
