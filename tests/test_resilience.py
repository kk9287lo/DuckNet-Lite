"""
test_resilience.py — 自己防衛/レジリエンス(evolution #47)。
====================================================================================
一時停止(OSスリープ/SIGSTOP/VM一時停止)を idle と取り違えず検出し、復帰を死亡と誤認して
再起動しない=安定性を回帰から守る。判定ロジックは純粋関数、Watchdog はコールバック注入。
"""
import time

from dataplane.engine.core.resilience import (
    measure_skew, assess, Watchdog, backoff_delay, restart_decision, Supervisor,
)


class _FakeProc:
    def __init__(self, rc):
        self.rc = rc
        self.terminated = False

    def wait(self):
        return self.rc

    def terminate(self):
        self.terminated = True


def test_measure_skew_idle_is_zero():
    # 無トラフィック idle: wall も mono も同じだけ進む → skew≈0(一時停止と誤認しない)。
    sk, nw, nm = measure_skew(100.0, 50.0, now_wall=160.0, now_mono=110.0)
    assert abs(sk) < 1e-9
    assert nw == 160.0 and nm == 110.0


def test_measure_skew_detects_suspend():
    # 一時停止: wall +200 だが monotonic は +5 しか進まない → skew≈195。
    sk, _, _ = measure_skew(100.0, 50.0, now_wall=300.0, now_mono=55.0)
    assert abs(sk - 195.0) < 1e-9


def test_assess_ok_when_healthy():
    assert assess(alive=True, heartbeat_age=1.0, skew=0.0, max_silence=10) == "ok"


def test_assess_suspend_has_priority_over_hang():
    # 一時停止中はハートビートも凍る。古い拍動 *だけ* を見て restart しないため suspend を優先。
    assert assess(alive=True, heartbeat_age=999.0, skew=300.0, max_silence=10) == "suspend"
    assert assess(alive=True, heartbeat_age=1.0, skew=200.0, max_silence=10) == "suspend"


def test_assess_restart_on_death():
    assert assess(alive=False, heartbeat_age=None, skew=0.0, max_silence=10) == "restart"


def test_assess_restart_on_hang():
    assert assess(alive=True, heartbeat_age=50.0, skew=0.0, max_silence=10) == "restart"


def test_assess_no_hang_restart_without_heartbeat():
    # heartbeat 未対応(None)はハング判定しない(死亡のみで restart)。
    assert assess(alive=True, heartbeat_age=None, skew=0.0, max_silence=10) == "ok"


def test_watchdog_beat_restarts_dead_target():
    state = {"alive": True, "hb": time.monotonic(), "restarts": 0, "suspends": []}
    wd = Watchdog(is_alive=lambda: state["alive"],
                  restart=lambda: state.__setitem__("restarts", state["restarts"] + 1),
                  heartbeat=lambda: state["hb"],
                  on_suspend=lambda s: state["suspends"].append(s),
                  max_silence=10.0)
    assert wd.beat() == "ok"
    state["alive"] = False
    assert wd.beat() == "restart"
    assert state["restarts"] == 1
    assert wd.metrics["restarts"] == 1


def test_watchdog_suspend_notifies_not_restarts():
    state = {"restarts": 0, "suspends": []}
    wd = Watchdog(is_alive=lambda: True,
                  restart=lambda: state.__setitem__("restarts", state["restarts"] + 1),
                  on_suspend=lambda s: state["suspends"].append(s),
                  max_silence=10.0)
    # 基準を過去にずらして wall を大きく進め、monotonic は据え置き=一時停止を模す。
    wd._prev_wall = time.time() - 120.0
    wd._prev_mono = time.monotonic()
    assert wd.beat() == "suspend"
    assert state["restarts"] == 0
    assert state["suspends"] and state["suspends"][0] > 100.0
    assert wd.metrics["suspends"] == 1


def test_watchdog_callback_exceptions_are_swallowed():
    # コールバックが投げても watchdog ループは死なない(防御継続)。
    def boom():
        raise RuntimeError("x")
    wd = Watchdog(is_alive=boom, restart=boom, heartbeat=boom, max_silence=1.0)
    # is_alive 例外→alive=False、restart 例外も握り潰し。例外を外へ出さない。
    assert wd.beat() == "restart"


def test_watchdog_thread_start_stop():
    state = {"beats0": 0}
    wd = Watchdog(is_alive=lambda: True, restart=lambda: None,
                  heartbeat=lambda: time.monotonic(), interval=0.05, max_silence=10.0)
    wd.start()
    time.sleep(0.2)
    info = wd.stop()
    assert info["ok"]
    assert wd.metrics["beats"] >= 1            # スレッドが実際に拍動した


def test_watchdog_jitter_within_bounds_and_varies():
    wd = Watchdog(is_alive=lambda: True, restart=lambda: None, jitter=0.5)
    draws = [wd._jittered(30.0) for _ in range(50)]
    assert all(15.0 <= x <= 45.0 for x in draws)     # ±50% の範囲内
    assert len(set(round(x, 6) for x in draws)) > 1   # ばらつく(予測させない)
    # jitter=0 は決定論的
    wd0 = Watchdog(is_alive=lambda: True, restart=lambda: None, jitter=0.0)
    assert wd0._jittered(30.0) == 30.0


def test_watchdog_on_period_fires_on_interval():
    state = {"periods": 0}
    wd = Watchdog(is_alive=lambda: True, restart=lambda: None,
                  heartbeat=lambda: time.monotonic(),
                  on_period=lambda: state.__setitem__("periods", state["periods"] + 1),
                  period=30.0, max_silence=10.0)
    # period 未到達では呼ばれない
    wd.beat()
    assert state["periods"] == 0
    # 基準を過去にずらして period 到達を模す → 次の beat で1回呼ばれる
    wd._last_period = time.monotonic() - 31.0
    wd.beat()
    assert state["periods"] == 1


def test_absorb_suspend_extends_only_active_timers():
    # #49: 一時停止からの復帰で、進行中の nonce/検証済みセッション/時限BAN を停止秒数だけ延命。
    #   永続BANと『停止前に失効済み』のタイマーは触らない(復活させない)。
    import tempfile
    from dataplane.engine.lifeform.pipeline import NetShield, _now
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        ch = sh._issue_challenge("1.2.3.4", 4)          # 進行中 nonce(120s)
        nonce = ch["nonce"]; exp0 = sh._nonces[nonce][1]
        st = sh._state("5.6.7.8"); st["verified_until"] = _now() + 60
        vu0 = st["verified_until"]
        sh.ban("9.9.9.9", ttl_sec=100)                  # 時限BAN
        bu0 = sh._ips["9.9.9.9"]["ban_until"]
        sh.ban("10.0.0.1", permanent=True)              # 永続BAN(不変であるべき)
        ste = sh._state("11.0.0.1"); ste["ban_until"] = _now() - 10000.0  # 停止前に失効済み
        be0 = ste["ban_until"]

        r = sh.absorb_suspend(300.0)
        assert r["nonces"] >= 1 and r["sessions"] >= 1 and r["bans"] >= 1
        assert abs(sh._nonces[nonce][1] - (exp0 + 300)) < 1e-6
        assert abs(sh._state("5.6.7.8")["verified_until"] - (vu0 + 300)) < 1e-6
        assert abs(sh._ips["9.9.9.9"]["ban_until"] - (bu0 + 300)) < 1e-6
        assert sh._ips["10.0.0.1"]["ban_until"] == float("inf")   # 永続は不変
        assert sh._ips["11.0.0.1"]["ban_until"] == be0            # 失効済みは復活しない


def test_absorb_suspend_zero_or_negative_is_noop():
    import tempfile
    from dataplane.engine.lifeform.pipeline import NetShield
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        assert sh.absorb_suspend(0.0)["absorbed"] == 0.0
        assert sh.absorb_suspend(-5.0)["nonces"] == 0


def test_backoff_delay_exponential_capped():
    assert backoff_delay(0, base=0.5, cap=30) == 0.5
    assert backoff_delay(1, base=0.5, cap=30) == 1.0
    assert backoff_delay(3, base=0.5, cap=30) == 4.0
    assert backoff_delay(20, base=0.5, cap=30) == 30.0      # 上限で頭打ち


def test_restart_decision():
    assert restart_decision(0, 0, 10) == "stop"             # 正常終了=再起動しない
    assert restart_decision(1, 0, 10) == "restart"
    assert restart_decision(1, 10, 10) == "giveup"          # クラッシュループ遮断


def test_supervisor_clean_exit_does_not_restart():
    sup = Supervisor(["x"], spawn=lambda a: _FakeProc(0))
    r = sup.supervise(handle_signals=False)
    assert r["reason"] == "clean_exit"
    assert sup.metrics["starts"] == 1 and sup.metrics["restarts"] == 0


def test_supervisor_restarts_then_gives_up_on_crash_loop():
    sup = Supervisor(["x"], spawn=lambda a: _FakeProc(1), max_restarts=3,
                     backoff_base=0.001, backoff_cap=0.01, window=60.0)
    r = sup.supervise(handle_signals=False)
    assert r["reason"] == "crash_loop"
    assert sup.metrics["restarts"] == 3                     # 3回再起動して諦める
    assert sup.metrics["starts"] == 4                       # 起動は4回(初回+3)


def test_supervisor_max_cycles_stops():
    sup = Supervisor(["x"], spawn=lambda a: _FakeProc(1), max_restarts=99,
                     backoff_base=0.001, backoff_cap=0.01)
    r = sup.supervise(max_cycles=2, handle_signals=False)
    assert r["reason"] == "max_cycles" and sup.metrics["starts"] == 2


def test_supervisor_stop_terminates_child():
    proc = _FakeProc(1)
    sup = Supervisor(["x"], spawn=lambda a: proc)
    sup.run_once()
    sup.stop()
    assert proc.terminated and sup._stop.is_set()


def test_supervisor_real_subprocess_crash_loop():
    import sys
    sup = Supervisor([sys.executable, "-c", "import sys; sys.exit(3)"],
                     max_restarts=2, backoff_base=0.01, backoff_cap=0.05)
    r = sup.supervise(handle_signals=False)
    assert r["reason"] == "crash_loop"
    assert sup.metrics["starts"] >= 2


def test_supervisor_real_subprocess_clean_exit():
    import sys
    sup = Supervisor([sys.executable, "-c", "import sys; sys.exit(0)"])
    r = sup.supervise(handle_signals=False)
    assert r["reason"] == "clean_exit" and sup.metrics["starts"] == 1


def test_guard_heartbeat_advances_and_restart():
    # AsyncEdgeGuard の serving ループが周期的に拍動し、watchdog のハング検出器に前進が見える。
    from dataplane.engine.services.proxy import AsyncEdgeGuard
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9, listen_port=0)
    assert g.start().get("ok")
    try:
        assert g.is_alive()
        hb0 = g.heartbeat()
        time.sleep(1.3)                        # ハートビート間隔は 1s
        assert g.heartbeat() > hb0             # 拍動が前進(無通信でも刻む)
        # 強制再起動: 新しい serving スレッドが立ち上がり、生存する。
        info = g.restart()
        assert info.get("ok")
        assert g.is_alive()
    finally:
        g.stop()
