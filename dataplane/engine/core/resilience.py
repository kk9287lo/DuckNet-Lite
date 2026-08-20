"""
resilience.py — 常駐サービスの自己防衛/レジリエンス(標準ライブラリのみ・依存ゼロ)
====================================================================================
防御エージェントは『落とされたら終わり』。攻撃者がプロセスを止める/凍らせる/差し替える前提で、
生存監視・強制再起動・一時停止からの安定復帰を担う層。EDR 等の self-protection と同系統の
*正当な* 自己防衛であり、OS/管理者からのプロセス隠蔽やフォレンジック妨害は **行わない**(正直)。

中核は2つの純粋関数(テスト容易):
  · measure_skew … wall-clock と monotonic の経過差。OS スリープ/SIGSTOP/VM 一時停止/デバッガ
    凍結の間 monotonic は進まない(Linux/macOS)が wall は進むため、その乖離=『一時停止していた量』。
    無トラフィックの idle では両者が揃って進む=skew≈0 なので、idle と一時停止を取り違えない。
  · assess … 監視1拍の判定(suspend / restart / ok)。一時停止を最優先で判定するのが要:
    停止中は対象のハートビートも止まるため、これを死亡=restart と誤認しないため。

Watchdog はこの判定を周期実行し、ハング/死亡なら restart()、一時停止なら on_suspend() を呼ぶ。
対象との結合はすべてコールバック注入(is_alive/heartbeat/restart/on_suspend)=密結合しない。

正直な限界: in-process の watchdog は対象スレッドの *死亡*(例外失活)を再生成で復旧できるが、
ループが完全に *ハング* して listen ソケットを握ったままだと同ポート再 bind は確実でない。真に
堅牢な強制再開は親プロセス監督(run_supervised)= 別レイヤの責務(段階導入)。
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque

# 一時停止(OSスリープ/SIGSTOP/VM一時停止/デバッガ凍結)とみなす wall-mono 乖離の閾値[秒]。
# idle では両者が揃って進む(skew≈0)ので誤検出しない。小さすぎると稀な GC/スケジューラ遅延を
# 拾うため、数秒に置く(一時停止は通常これより遥かに大きい)。
SUSPEND_SKEW_THRESHOLD = 5.0


def measure_skew(prev_wall: float, prev_mono: float,
                 now_wall: float = None, now_mono: float = None):
    """前回基準からの (wall経過 - monotonic経過) = skew と、更新後の (wall, mono) を返す。
    skew>0 ≈ その区間にプロセスが一時停止していた秒数(monotonic は停止中進まないため)。"""
    nw = time.time() if now_wall is None else now_wall
    nm = time.monotonic() if now_mono is None else now_mono
    skew = (nw - prev_wall) - (nm - prev_mono)
    return skew, nw, nm


def assess(*, alive: bool, heartbeat_age, skew: float, max_silence: float,
           skew_threshold: float = SUSPEND_SKEW_THRESHOLD) -> str:
    """監視1拍の判定(純粋関数)。返り値 "suspend" | "restart" | "ok"。
      · skew>閾値 … 一時停止からの復帰。死亡ではない → "suspend"(restart しない)。
      · not alive … 対象が消えた → "restart"。
      · heartbeat_age>max_silence … 生きているが拍動が止まった(ハング)→ "restart"。
      · それ以外 … "ok"。
    suspend を最優先で見るのが肝:一時停止中はハートビートも凍るので、復帰直後に
    『拍動が古い』だけを見て誤って restart しないため。"""
    if skew > skew_threshold:
        return "suspend"
    if not alive:
        return "restart"
    if heartbeat_age is not None and heartbeat_age > max_silence:
        return "restart"
    return "ok"


class Watchdog:
    """常駐サービスの生存監視・強制再起動・一時停止検出を行う低依存スーパーバイザ。

    コールバック:
      · is_alive() -> bool        … 対象が生存しているか(必須)。
      · restart()  -> None        … 強制再起動(stop+start 等・必須)。
      · heartbeat() -> float|None … 対象が最後に拍動した monotonic 時刻(任意・ハング検出用)。
      · on_suspend(skew) -> None  … 一時停止検出時の通知(任意・セッション延命等を上位で行う)。
    """

    def __init__(self, is_alive, restart, heartbeat=None, on_suspend=None,
                 on_period=None, period: float = 30.0,
                 interval: float = 1.0, max_silence: float = 10.0,
                 jitter: float = 0.0,
                 skew_threshold: float = SUSPEND_SKEW_THRESHOLD, name: str = None):
        self._is_alive = is_alive
        self._restart = restart
        self._heartbeat = heartbeat
        self._on_suspend = on_suspend
        # 周期タスク(任意): N 秒ごとに on_period() を呼ぶ。ファイル完全性の継続検査等に使う。
        self._on_period = on_period
        self.period = max(1.0, float(period))
        # 周期/間隔のランダム化(±jitter 割合・0=無効)。攻撃者が『検査の隙』を予測して
        # kill+改竄を検査間に差し込むのを難しくする(タイミングを un-gameable に)。隠蔽ではない。
        self.jitter = max(0.0, min(0.9, float(jitter)))
        self._last_period = time.monotonic()
        self._period_target = self._jittered(self.period)
        self.interval = max(0.05, float(interval))
        self.max_silence = float(max_silence)
        self.skew_threshold = float(skew_threshold)
        # スレッド名は cover 名に従う(ステルス時に製品名を露出しない)。プロセス隠蔽はしない=正直。
        self.name = name or (os.environ.get("CHICKENNET_COVER", "chickennet").split()[0] + "-wd")
        self._thread = None
        self._stop = threading.Event()
        self._prev_wall = time.time()
        self._prev_mono = time.monotonic()
        self.metrics = {"beats": 0, "restarts": 0, "suspends": 0, "suspend_sec": 0.0}

    def _jittered(self, base: float) -> float:
        """base に ±jitter 割合のゆらぎを与える(jitter=0 なら base のまま=決定論的)。"""
        if self.jitter <= 0:
            return base
        import random
        return max(0.05, base * (1.0 + random.uniform(-self.jitter, self.jitter)))

    def _age(self):
        if self._heartbeat is None:
            return None
        try:
            hb = self._heartbeat()
        except Exception:
            return None
        return None if hb is None else max(0.0, time.monotonic() - hb)

    def beat(self) -> str:
        """監視1拍(テストから直接呼べる)。判定して必要なら restart/通知し、判定文字列を返す。"""
        skew, self._prev_wall, self._prev_mono = measure_skew(
            self._prev_wall, self._prev_mono)
        try:
            alive = bool(self._is_alive())
        except Exception:
            alive = False
        verdict = assess(alive=alive, heartbeat_age=self._age(), skew=skew,
                         max_silence=self.max_silence, skew_threshold=self.skew_threshold)
        self.metrics["beats"] += 1
        if verdict == "suspend":
            self.metrics["suspends"] += 1
            self.metrics["suspend_sec"] = round(self.metrics["suspend_sec"] + skew, 1)
            if self._on_suspend:
                try:
                    self._on_suspend(skew)
                except Exception:
                    pass
        elif verdict == "restart":
            self.metrics["restarts"] += 1
            try:
                self._restart()
            except Exception:
                pass
        # 周期タスク(完全性検査等)。一時停止中は period も凍るので復帰直後に1回走る。
        # 発火ごとに次回までを再ランダム化=検査タイミングを予測させない。
        if self._on_period is not None:
            nm = time.monotonic()
            if nm - self._last_period >= self._period_target:
                self._last_period = nm
                self._period_target = self._jittered(self.period)
                try:
                    self._on_period()
                except Exception:
                    pass
        return verdict

    def _loop(self):
        # 起動/復帰の初回拍で誤検出しないよう基準時刻を取り直す。
        self._prev_wall, self._prev_mono = time.time(), time.monotonic()
        while not self._stop.wait(self._jittered(self.interval)):
            self.beat()

    def start(self):
        if self._thread and self._thread.is_alive():
            return self
        self._stop.clear()
        self._prev_wall, self._prev_mono = time.time(), time.monotonic()
        self._thread = threading.Thread(target=self._loop, daemon=True, name=self.name)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=self.interval + 1.0)
        return {"ok": True, "metrics": dict(self.metrics)}


# ── 親プロセス監督(プロセスレベルの強制再開)──────────────────────────────
def backoff_delay(attempt: int, base: float = 0.5, cap: float = 30.0) -> float:
    """指数バックオフ秒(クラッシュループで再起動を詰め込み過ぎない)。attempt=0 から。"""
    return min(float(cap), float(base) * (2 ** max(0, int(attempt))))


def restart_decision(returncode, restarts_in_window: int, max_restarts: int) -> str:
    """子の終了をどう扱うか(純粋関数)。"stop" | "giveup" | "restart"。
      · returncode==0 … サービスが正常に停止を要求した → "stop"(再起動しない)。
      · 直近窓内の再起動が上限以上 … クラッシュループ → "giveup"(無限再起動しない)。
      · それ以外(異常終了)… "restart"。"""
    if returncode == 0:
        return "stop"
    if restarts_in_window >= max_restarts:
        return "giveup"
    return "restart"


class Supervisor:
    """子プロセスとしてサービスを起動し、異常終了したら再起動する親監督(systemd Restart= 相当)。
    *可視・正規*: 自分の名で動き、SIGTERM/SIGINT を受けたら子を畳んで自身も終了する(終了を
    妨害しない=透明)。指数バックオフ + 短時間 N 回超で停止(クラッシュループ遮断)。

    spawn は注入可能(既定 subprocess.Popen)=ロジックを実プロセス無しでテストできる。
    返り値のプロセス様オブジェクトは wait()->int と terminate() を備えればよい。"""

    def __init__(self, argv, *, spawn=None, max_restarts: int = 10, window: float = 60.0,
                 backoff_base: float = 0.5, backoff_cap: float = 30.0, name: str = None):
        self.argv = list(argv)
        self._spawn = spawn or self._default_spawn
        self.max_restarts = max(1, int(max_restarts))
        self.window = float(window)
        self.backoff_base = float(backoff_base)
        self.backoff_cap = float(backoff_cap)
        self.name = name or (os.environ.get("CHICKENNET_COVER", "chickennet").split()[0] + "-sup")
        self._stop = threading.Event()
        self._child = None
        self.metrics = {"starts": 0, "restarts": 0, "clean_exits": 0, "crash_loops": 0}

    @staticmethod
    def _default_spawn(argv):
        import subprocess
        return subprocess.Popen(argv)

    def run_once(self) -> int:
        """子を1回起動して終了コードを返す(終了までブロック)。"""
        proc = self._spawn(self.argv)
        self._child = proc
        self.metrics["starts"] += 1
        try:
            return int(proc.wait())
        except Exception:
            return 1

    def stop(self):
        """監督を停止し、生きている子を終了させる(管理者/シグナルからの正規停止)。"""
        self._stop.set()
        ch = self._child
        if ch is not None:
            try:
                ch.terminate()
            except Exception:
                pass

    def supervise(self, max_cycles: int = None, handle_signals: bool = True) -> dict:
        """監督ループ。子の異常終了を窓内回数とバックオフ付きで再起動する。正常終了(0)や
        クラッシュループ検出、max_cycles 到達、stop() で終了。返り値=終了理由と metrics。
        テストは max_cycles と注入 spawn で決定論的に回せる(handle_signals=False で
        プロセス全体のシグナルハンドラを触らない)。"""
        if handle_signals:
            self._install_signals()
        recent = deque()                          # 窓内の再起動時刻(monotonic)
        cycle = 0
        reason = "stopped"
        while not self._stop.is_set():
            rc = self.run_once()
            cycle += 1
            now = time.monotonic()
            while recent and now - recent[0] > self.window:
                recent.popleft()
            decision = restart_decision(rc, len(recent), self.max_restarts)
            if decision == "stop":
                self.metrics["clean_exits"] += 1
                reason = "clean_exit"
                break
            if decision == "giveup":
                self.metrics["crash_loops"] += 1
                reason = "crash_loop"
                break
            recent.append(now)
            self.metrics["restarts"] += 1
            if max_cycles is not None and cycle >= max_cycles:
                reason = "max_cycles"
                break
            if self._stop.wait(backoff_delay(len(recent) - 1, self.backoff_base,
                                             self.backoff_cap)):
                break
        return {"ok": True, "reason": reason, "cycles": cycle,
                "metrics": dict(self.metrics)}

    def _install_signals(self):
        """SIGTERM/SIGINT で正規停止(終了を妨害しない=透明)。メインスレッド以外/非対応は無視。"""
        try:
            import signal
            for s in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
                if s is not None:
                    signal.signal(s, lambda *_a: self.stop())
        except Exception:
            pass
