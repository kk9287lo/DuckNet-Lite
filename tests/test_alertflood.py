"""
test_alertflood.py — AlertSink の distinct-key フラッド有界化 + /c/ 未知トークン抑制(evolution #83)。
====================================================================================
公開・無認証・WAF 手前の /c/<token> を悪用した『大量の異なるキーで dedup 表を肥大 / SIEM を
フラッド』する DoS を塞ぐ。AlertSink にハードキャップ、record_hit は未知トークンを記録しない。
"""
import tempfile

from dataplane.engine.lifeform.alerts import AlertSink, _RECENT_CAP
from dataplane.engine.lifeform.datasets import TokenLedger


def test_recent_map_hard_capped_under_distinct_flood():
    with tempfile.TemporaryDirectory() as d:
        s = AlertSink("t", state_dir=d, dedup_window=600.0)   # 長い窓=期限切れで間引けない
        # 窓内に大量の *異なる* キーを送る(=/c/<ランダム> 連打の模擬)
        for i in range(_RECENT_CAP + 5000):
            s.record((f"tok{i}", "hit", "1.2.3.4"), {"i": i},
                     verdict="malicious", action="alert", now=1000.0)
        assert len(s._recent) <= _RECENT_CAP                  # ハードキャップで有界
        assert s._log.maxlen == 2000                          # ログも有界(既存)


def test_within_window_dedup_still_works():
    with tempfile.TemporaryDirectory() as d:
        s = AlertSink("t", state_dir=d, dedup_window=60.0)
        r1 = s.record(("k", "hit", "c"), {"x": 1}, verdict="malicious", action="alert", now=100.0)
        r2 = s.record(("k", "hit", "c"), {"x": 1}, verdict="malicious", action="alert", now=110.0)
        assert r2["count"] == 2 and len(s._recent) == 1       # 同キー連打は畳む(従来)


def test_ledger_unknown_token_not_recorded():
    with tempfile.TemporaryDirectory() as d:
        L = TokenLedger(state_dir=d)
        L.register_canary("planted-123", kind="web", memo="docs/")
        # 既知トークン=記録(alert 生成)
        r = L.record_hit("planted-123", "9.9.9.9", ua="curl")
        assert r.get("known") is True
        assert len(L.sink.log()) >= 1                          # 既知はログに残る
        # 未知トークン(攻撃者の /c/<ランダム>)=記録しない(カウントのみ)
        before_log = len(L.sink.log())
        for i in range(100):
            rr = L.record_hit(f"random-{i}", "6.6.6.6")
            assert rr == {"known": False, "recorded": False}
        assert len(L.sink.log()) == before_log                # ログ/SIEM を汚さない
        assert L._unknown_probes == 100                       # カウントのみ
        assert L.status()["unknown_probes"] == 100


def test_ledger_known_pull_still_alerts():
    with tempfile.TemporaryDirectory() as d:
        L = TokenLedger(state_dir=d)
        # pull(持ち出し)は token 既知/未知に関わらず高重大度のまま(record_hit のみ未知抑制)
        r = L.record_pull("9.9.9.9", {"name": "secrets.xlsx", "token": "t"})
        assert r and L.sink.metrics.get("pull", 0) >= 1
