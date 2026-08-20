"""
forwarders.py — アラートの外部転送(SIEM/Syslog/Webhook・標準ライブラリのみ・opt-in)
====================================================================================
デコイ/LDAPプロキシ/DNS の検知を、ローカル JSONL + 独自ダッシュボードに閉じ込めず、
企業 SOC が実際に監視する先(SIEM・チャット Webhook)へ送り出す層。
「外部依存ゼロだから SIEM 連携が無い」という因果は誤り=Syslog は socket、Webhook は
urllib.request、いずれも *標準ライブラリ* で書ける。本モジュールがそれを実装する。

設計の鉄則を守る:
  · 依存ゼロ: socket / urllib / json / concurrent.futures(全て stdlib)。
  · 防御専用=既定で *送らない*: 外部送信は明示の opt-in(環境変数 or CLI)でのみ有効。
    防御製品が黙って phone-home しないため。設定が無ければ完全な no-op(オーバーヘッド無)。
  · 非ブロッキング: 送信先が遅い/落ちていても検知ホットパスを止めない。送信は小さな
    ワーカープールへ投げ切り(submit は即時)、各送信は短いタイムアウト+例外握り潰し。

設定(環境変数):
  · CHICKENNET_SYSLOG = "udp://10.0.0.5:514" | "tcp://host:601" | "host:port"(既定 udp/514)
  · CHICKENNET_WEBHOOK = "https://example.com/webhook"({"text":...} 形式で POST)
  · CHICKENNET_SYSLOG_FACILITY = 0..23(既定 16 = local0)
正直な範囲: RFC5424 の一般的サブセット(STRUCTURED-DATA は "-"、本体に JSON を載せる)。
Webhook は {"text":...} 形式の text フィールド。受け側により軽いアダプタが要る場合がある。
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from collections import deque

# RFC5424 severity(数値が小さいほど重大)。検知の verdict をここへ写像する。
_SEV = {"emergency": 0, "alert": 1, "critical": 2, "error": 3,
        "warning": 4, "notice": 5, "informational": 6, "debug": 7}
_VERDICT_SEV = {"malicious": _SEV["alert"], "suspicious": _SEV["warning"],
                "info": _SEV["informational"]}


def _parse_endpoint(spec: str, default_port: int = 514):
    """"udp://h:p" / "tcp://h:p" / "h:p" / "h" を (proto, host, port) へ。"""
    spec = (spec or "").strip()
    proto = "udp"
    if "://" in spec:
        proto, _, spec = spec.partition("://")
        proto = proto.lower()
    host, _, port = spec.partition(":")
    return (proto if proto in ("udp", "tcp") else "udp",
            host or "127.0.0.1", int(port) if port.isdigit() else default_port)


def _summary(event: dict, source: str, verdict: str) -> str:
    """人が Webhook/Syslog でひと目で分かる1行に圧縮する。"""
    who = event.get("client", "?")
    what = event.get("kind") or event.get("base") or event.get("detail") or ""
    sig = "; ".join((event.get("signals") or [])[:3])
    tail = f" — {sig}" if sig else ""
    return f"[{verdict}] {source}: {who} {what}{tail}".strip()


class SyslogForwarder:
    """RFC5424 syslog を UDP/TCP で送る(stdlib socket のみ)。"""

    def __init__(self, spec: str, *, facility: int = 16, app: str = "chickennet"):
        self.proto, self.host, self.port = _parse_endpoint(spec)
        self.facility = int(facility) & 0x1F
        self.app = app
        self.hostname = (socket.gethostname() or "-")[:255]
        self.pid = os.getpid()

    def _line(self, event: dict, source: str, severity: int) -> bytes:
        pri = self.facility * 8 + (severity & 0x07)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
        msgid = (source or "alert")[:32].replace(" ", "_")
        body = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        # <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED-DATA MSG
        line = f"<{pri}>1 {ts} {self.hostname} {self.app} {self.pid} {msgid} - {body}"
        return line.encode("utf-8", "replace")

    def send(self, event: dict, source: str, severity: int) -> None:
        data = self._line(event, source, severity)
        try:
            if self.proto == "tcp":
                with socket.create_connection((self.host, self.port), timeout=2.0) as s:
                    s.sendall(data + b"\n")          # 非透過フレーミング(LF区切り)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.sendto(data[:65000], (self.host, self.port))   # UDP=投げ切り
                finally:
                    s.close()
        except Exception:
            pass                                     # SIEM が落ちていても検知は止めない


class WebhookForwarder:
    """汎用 Webhook({"text":...} 形式)へ POST する(stdlib urllib のみ)。"""

    def __init__(self, url: str, *, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout

    def send(self, event: dict, source: str, severity: int) -> None:
        """1件 POST。失敗(429/5xx/タイムアウト/ダウン)は *例外を伝播* させる=上位 Fanout が
        バックオフ判断できるようにする(握り潰すと盲目化に気づけない)。呼び出しは別スレッド。"""
        verdict = event.get("verdict", "alert")
        payload = json.dumps({"text": _summary(event, source, verdict)}).encode()
        req = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=self.timeout).close()   # 失敗時は例外→Fanoutが捕捉


class Fanout:
    """検知1件を転送先へ *完全非同期* に配る。設定が無ければ no-op。
    SIEW フラッド/盲目化(#8)対策を内蔵する:
      · 容量固定の drop-oldest キュー … 異なるIPからのアラート洪水でも無制限に溜めない(メモリ枯渇回避)。
      · 単一ワーカ + レート配分(max_per_sec)… 自分で SIEM/Webhook を 429 で溺れさせない。
      · 失敗時の指数バックオフ … 429/5xx/ダウンの相手を叩き続けない(自滅回避)。
      · 抑制サマリ通知 … 取りこぼし(dropped/suppressed)を周期的に1件のメタアラートで *必ず知らせる*
        =『静かに盲目化』を防ぐ(攻撃者が通知窓口をパンクさせても "N件抑制" が SIEM に届く)。
    emit はイベントループから呼ばれてもキューに積むだけ=1ミリ秒も奪わない(完全分離)。
    """

    def __init__(self, forwarders=None, *, capacity: int = 1024,
                 max_per_sec: float = 20.0, summary_sec: float = 15.0):
        self._fws = list(forwarders or [])
        self._cap = max(16, int(capacity))
        self._min_interval = (1.0 / max_per_sec) if max_per_sec and max_per_sec > 0 else 0.0
        self._summary_sec = float(summary_sec)
        self._q = deque()
        self._cv = threading.Condition()
        self._dropped = 0          # 容量超過で捨てた件数(drop-oldest)
        self._suppressed = 0       # バックオフ中に送れず畳んだ件数
        self._last_send = 0.0
        self._last_summary = time.monotonic()
        self._cooldown_until = 0.0
        self._fails = 0
        self._stop = False
        self._worker = None
        if self._fws:
            self._worker = threading.Thread(target=self._run, daemon=True,
                                            name="alert-fwd")
            self._worker.start()

    @property
    def active(self) -> bool:
        return bool(self._fws)

    def stats(self) -> dict:
        with self._cv:
            return {"queued": len(self._q), "dropped": self._dropped,
                    "suppressed": self._suppressed}

    def emit(self, event: dict, source: str, verdict: str) -> None:
        if not self._fws:
            return                                   # 無効時はゼロコスト
        sev = _VERDICT_SEV.get(verdict, _SEV["warning"])
        with self._cv:
            if len(self._q) >= self._cap:
                self._q.popleft()                    # drop-oldest(容量固定=メモリ有界)
                self._dropped += 1
            self._q.append((dict(event), source, sev))
            self._cv.notify()

    # ── 内部: 単一ワーカ(送信 I/O は完全にここだけ。emit 側は塞がない) ──
    def _send_one(self, ev, source, sev) -> bool:
        ok = True
        for fw in self._fws:
            try:
                fw.send(ev, source, sev)
            except Exception:
                ok = False                           # 1つでも失敗=失敗扱い(バックオフ判断へ)
        return ok

    def _maybe_summary(self) -> None:
        """取りこぼしを周期的に1件のメタアラートで通知(盲目化を可視化)。"""
        now = time.monotonic()
        if now - self._last_summary < self._summary_sec:
            return
        with self._cv:
            dropped, suppressed = self._dropped, self._suppressed
            self._dropped = self._suppressed = 0
        self._last_summary = now
        if dropped or suppressed:
            self._send_one({"client": "-", "kind": "forwarder_backpressure",
                            "verdict": "warning",
                            "signals": [f"alerts suppressed: dropped={dropped} "
                                        f"throttled={suppressed} (forwarder backpressure)"]},
                           "chickennet", _SEV["warning"])
            self._last_send = time.monotonic()

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._q and not self._stop:
                    self._cv.wait(timeout=1.0)
                    # アイドルでも周期サマリは出す(ロック解放のため抜ける)
                    if not self._q:
                        break
                if self._stop and not self._q:
                    self._maybe_summary()
                    return
                item = self._q.popleft() if self._q else None
            if item is None:
                self._maybe_summary()
                continue
            now = time.monotonic()
            if now < self._cooldown_until:           # バックオフ中=送らず畳む(サマリで可視化)
                with self._cv:
                    self._suppressed += 1
                self._maybe_summary()
                continue
            gap = self._min_interval - (now - self._last_send)
            if gap > 0:
                time.sleep(min(gap, 0.5))            # レート配分=自分で相手を溺れさせない
            ok = self._send_one(*item)
            self._last_send = time.monotonic()
            if ok:
                self._fails = 0
            else:
                self._fails += 1                     # 連続失敗=指数バックオフ(最大30s)
                self._cooldown_until = self._last_send + min(30.0, 0.5 * (2 ** min(self._fails, 6)))
            self._maybe_summary()

    def close(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()


def build_from_env(env=None) -> Fanout:
    """環境変数から転送先を組む。未設定なら active=False の no-op Fanout。"""
    env = os.environ if env is None else env
    fws = []
    syslog = env.get("CHICKENNET_SYSLOG", "").strip()
    if syslog:
        try:
            fac = int(env.get("CHICKENNET_SYSLOG_FACILITY", "16"))
        except ValueError:
            fac = 16
        fws.append(SyslogForwarder(syslog, facility=fac))
    hook = env.get("CHICKENNET_WEBHOOK", "").strip()
    if hook:
        fws.append(WebhookForwarder(hook))
    try:
        qps = float(env.get("CHICKENNET_ALERT_QPS", "20"))
    except ValueError:
        qps = 20.0
    try:
        cap = int(env.get("CHICKENNET_ALERT_CAP", "1024"))
    except ValueError:
        cap = 1024
    return Fanout(fws, capacity=cap, max_per_sec=qps)


_DEFAULT: Fanout = None


def default_fanout() -> Fanout:
    """プロセス共有の Fanout(env から1度だけ構築)。複数 AlertSink でプールを共有する。"""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = build_from_env()
    return _DEFAULT
