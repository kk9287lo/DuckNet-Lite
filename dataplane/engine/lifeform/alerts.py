"""
alerts.py — アラート記録の共有機構(除外/重複集約/メトリクス/ローテログ・依存ゼロ)
====================================================================================
複数の検知系モジュール(datasets.py の台帳ほか)が個別に持ちがちな『送信元の除外・
連打の集約・メトリクス計上・ログのローテーション保存』を1つに束ねる。各モジュールは
イベントの *中身* (分類/採点)に集中し、記録の作法はここへ委譲する。

提供する作法:
  · アローリスト … 信頼送信元(スキャナ/監視/正規アプリ)を IP/CIDR で除外。
  · 重複 collapse … 呼び出し側が渡す key で、窓内の連打を1件+count に畳む。
  · メトリクス … 総数(total_key)/alerts/ignored/sources + 任意の事前ゼロ初期化キー。
  · 永続化 … {name}.json(enabled/allowlist)+ {name}_log.jsonl(サイズ超でローテ)。
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque

from ..core.atomic_io import default_state_dir, atomic_write_json, safe_read_json, append_jsonl
from .netutil import valid_cidr, ip_in_any
from .forwarders import default_fanout

_SOURCES_MAX = 50000     # distinct 送信元IPの記憶上限(超過で飽和=多数IPからの記録でも有界)
_RECENT_CAP = 8192       # dedup 表(_recent)の件数ハードキャップ(distinct-key フラッドでも有界)


class AlertSink:
    """記録の共通作法。イベントの分類/採点は呼び出し側(consumer)が行う。"""

    def __init__(self, name: str, *, state_dir: str = "", dedup_window: float = 60.0,
                 total_key: str = "hits", metric_keys=(), forwarders=None):
        base = state_dir or default_state_dir()
        os.makedirs(base, exist_ok=True)
        self.name = name
        # SIEM/Webhook 転送(opt-in)。env 未設定なら no-op = ゼロコスト。
        self._fanout = forwarders if forwarders is not None else default_fanout()
        self.path = os.path.join(base, f"{name}.json")
        self.log_path = os.path.join(base, f"{name}_log.jsonl")
        self.dedup_window = dedup_window
        self.total_key = total_key
        self._lock = threading.RLock()
        self._log = deque(maxlen=2000)
        self._recent: dict = {}                 # key -> {last_ts, entry}
        self._sources: set = set()
        d = safe_read_json(self.path, {}) or {}
        self.enabled = bool(d.get("enabled", True))
        self.allowlist = [n for n in (d.get("allowlist") or []) if valid_cidr(n)]
        self.metrics = {total_key: 0, "alerts": 0, "ignored": 0, "sources": 0}
        for k in metric_keys:
            self.metrics.setdefault(k, 0)

    # ── 永続化/設定 ──
    def _save(self):
        with self._lock:
            atomic_write_json(self.path, {"enabled": self.enabled,
                                          "allowlist": self.allowlist})

    def set_enabled(self, on: bool) -> dict:
        with self._lock:
            self.enabled = bool(on)
            self._save()
        return {"ok": True, "enabled": self.enabled}

    # ── アローリスト ──
    def add_allow(self, cidr: str) -> dict:
        cidr = (cidr or "").strip()
        if not valid_cidr(cidr):
            return {"ok": False, "error": f"IP/CIDR 不正: {cidr}"}
        with self._lock:
            if cidr not in self.allowlist:
                self.allowlist.append(cidr)
            self._save()
        return {"ok": True, "allowlist": list(self.allowlist)}

    def remove_allow(self, cidr: str) -> dict:
        with self._lock:
            before = len(self.allowlist)
            self.allowlist = [c for c in self.allowlist if c != cidr]
            self._save()
        return {"ok": True, "removed": before - len(self.allowlist)}

    def is_allowed(self, ip: str) -> bool:
        return ip_in_any(ip, self.allowlist)

    # ── 記録(重複集約 + メトリクス + ローテログ) ──
    def record(self, key, entry: dict, *, verdict: str, action: str,
               count_metrics=(), now: float = None) -> dict:
        """1イベントを記録。entry は consumer が組んだ payload(client 等を含む)。
        ts/last_ts/count/action は本メソッドが付与する。窓内の連打は畳んで返す。"""
        now = time.time() if now is None else now
        with self._lock:
            self.metrics[self.total_key] += 1
            self._prune(now)
            rec = self._recent.get(key)
            if rec and now - rec["last_ts"] <= self.dedup_window:
                rec["last_ts"] = now           # 連打 → count 加算のみ(新規ログ無し)
                e = rec["entry"]
                e["count"] += 1
                e["last_ts"] = now
                return dict(e)
            entry["ts"] = entry.get("ts", now)
            entry["last_ts"] = now
            entry["count"] = 1
            entry["action"] = action
            self._recent[key] = {"last_ts": now, "entry": entry}
            self._log.append(entry)
            if action == "ignored":
                self.metrics["ignored"] += 1
            else:                               # 初出のみ加算(連打で水増ししない)
                self.metrics["alerts"] += 1
                self.metrics[verdict] = self.metrics.get(verdict, 0) + 1
                for k in count_metrics:
                    self.metrics[k] = self.metrics.get(k, 0) + 1
            client = entry.get("client")
            if (client and client not in self._sources
                    and len(self._sources) < _SOURCES_MAX):   # 上限で飽和=無界増加を防ぐ
                self._sources.add(client)
                self.metrics["sources"] = len(self._sources)
            append_jsonl(self.log_path, entry)  # サイズ超で自動ローテーション
            if action != "ignored":             # 初出の実アラートのみ SIEM/Webhook へ
                self._fanout.emit(entry, self.name, verdict)   # submit は即時=非ブロッキング
            return dict(entry)

    def _prune(self, now: float):
        """dedup 表を間引く(無制限肥大を防ぐ)。呼び出し側でロック済み。
        ① 窓超のエントリを除去。② それでも上限(_RECENT_CAP)超なら *最古から* 強制退避する。
        ②が無いと、窓内に大量の *異なるキー*(例: 公開 /c/<ランダム> 連打)を送られたとき誰も
        期限切れにならず無制限成長していた(メモリ DoS)。最古退避で件数を必ず有界に保つ。"""
        if len(self._recent) < _RECENT_CAP:
            return
        cutoff = now - self.dedup_window
        for k in [k for k, v in self._recent.items() if v["last_ts"] < cutoff]:
            self._recent.pop(k, None)
        if len(self._recent) >= _RECENT_CAP:        # 全部が窓内=最古から強制退避(ハードキャップ)
            for k in sorted(self._recent, key=lambda k: self._recent[k]["last_ts"]
                            )[:len(self._recent) - _RECENT_CAP + 1]:
                self._recent.pop(k, None)

    def log(self, n: int = 100) -> list:
        with self._lock:
            return list(self._log)[-max(1, n):]
