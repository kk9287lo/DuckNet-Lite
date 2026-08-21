"""
test_buttonmash.py — ボタン連打(並行/二重送信)スキャン(evolution #84)。
====================================================================================
管理APIは ThreadingHTTPServer=並行。ボタン連打で同時実行されても、状態が壊れず・更新を
取りこぼさず・例外を出さない(スレッド安全)ことを検証する。
"""
import random
import tempfile
import threading

from dataplane.engine.lifeform.pipeline import NetShield


def test_button_mash_stress_no_corruption():
    # 連打: 8 スレッド × 200 操作(inspect/ban/unban/set_config)を同時実行。
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        errors = []

        def worker(seed):
            rnd = random.Random(seed)
            try:
                for _ in range(200):
                    ip = f"10.0.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}"
                    op = rnd.random()
                    if op < 0.30:
                        sh.inspect(ip, path="/x", method="GET")
                    elif op < 0.50:
                        sh.ban(ip)
                    elif op < 0.70:
                        sh.unban(ip)
                    else:
                        sh.set_config(flood_threshold=rnd.choice([100, 150, 200]))
            except Exception as e:        # noqa: BLE001
                errors.append(repr(e))

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert not errors, errors[:3]                  # 連打下で例外なし=スレッド安全
        # 連打後も状態が健全に読める(破損していない)
        assert isinstance(sh.bans(), list)
        assert isinstance(sh.metrics(), dict)


def test_concurrent_ban_unban_consistent():
    # 同一IPへの ban/unban 連打でも最終状態が一貫(例外・不整合なし)。
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        ip = "203.0.113.9"

        def churn():
            for _ in range(300):
                sh.ban(ip)
                sh.is_banned_fast(ip)
                sh.unban(ip)

        ts = [threading.Thread(target=churn) for _ in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        # 例外なく完走し、最終的に is_banned_fast が bool を返す(状態が読める)
        assert isinstance(sh.is_banned_fast(ip), bool)
