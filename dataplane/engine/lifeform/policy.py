"""
policy.py — 高度なアプリ層ファイアウォール(OSに干渉しない・ON/OFF可)
====================================================================================
DuckNet **自身のサーバ/ソケットへ来る接続** を、送信元IPのゾーン分類で
承認/拒否/保留(承認待ち)し、すべて記録・設定を永続化する。

重要な線引き(「Windows/Mac/Linux に干渉しない」):
  · これは **アプリ層** のファイアウォール。OSのネットワークスタック(WFP/iptables/pf)は
    一切触らない=他アプリやOSの通信はブロックしない・できない(正直)。本アプリの
    リスナー(Webサービス等)が accept した接続を、配信前に本エンジンへ照会して弾く方式。
  · よって「システム全体のファイアウォール」ではない。OS非侵襲・可逆・透明。

機能:
  · ON/OFF … OFF は完全パススルー(挙動を変えない)。既定OFF。
  · ゾーン分類 … loopback(自機) / private(Windows・LAN) / public(インターネット) /
    special(メタデータ/予約等) / unknown(解析不能)。monitor.classify_ip を再利用。
  · ポリシー … ゾーン毎に allow / deny / prompt(承認待ち)。
  · ルール … IP/CIDR 単位の allow/deny(ipaddress で照合・deny優先)。
  · 承認待ち … prompt で保留された未知接続を、GUI/CLIで承認(allow化)/拒否(deny化)。
  · 記録 … 全判定を acl_log.jsonl に追記(承認/拒否/保留・送信元・理由・時刻)。
  · 設定保存 … firewall.json に enabled/policy/rules を原子書込で永続化。
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import deque

from ..core.atomic_io import default_state_dir, atomic_write_json, safe_read_json, append_jsonl
from .monitor import classify_ip

ZONES = ["loopback", "private", "public", "special", "unknown"]
ACTIONS = ["allow", "deny", "prompt"]

# 既定ポリシー(安全側・アプリを壊さない): 自機は許可、LANは承認待ち、ネットは拒否。
_DEFAULT_POLICY = {"loopback": "allow", "private": "prompt",
                   "public": "deny", "special": "deny", "unknown": "prompt"}
_LOG_MAX = 2000


def _zone_of(ip: str) -> str:
    c = classify_ip(ip)
    if not c.get("ok"):
        return "unknown"
    cat = c.get("category")
    if cat == "loopback":
        return "loopback"
    if cat in ("private", "site_local", "link_local"):
        return "private"
    if cat == "global":
        return "public"
    return "special"


class AppFirewall:
    """アプリ層ファイアウォールの中核。OS非侵襲・ON/OFF・記録・永続化。"""

    def __init__(self, state_dir: str = ""):
        base = state_dir or default_state_dir()
        os.makedirs(base, exist_ok=True)
        self.path = os.path.join(base, "acl.json")
        self.log_path = os.path.join(base, "acl_log.jsonl")
        self._lock = threading.RLock()
        self._pending: dict = {}                 # id -> {ip, port, zone, ts, meta}
        self._log = deque(maxlen=_LOG_MAX)
        self._pid_seq = 0
        self._load()

    # ── 永続化 ───────────────────────────────────────────────────
    def _load(self):
        d = safe_read_json(self.path, {}) or {}
        self.enabled = bool(d.get("enabled", False))         # 既定OFF
        self.policy = dict(_DEFAULT_POLICY)
        for z, a in (d.get("policy") or {}).items():
            if z in ZONES and a in ACTIONS:
                self.policy[z] = a
        self.rules = [r for r in (d.get("rules") or [])
                      if isinstance(r, dict) and r.get("net")]
        # ログ末尾を読み込む(記録の継続表示用)
        try:
            if os.path.isfile(self.log_path):
                with open(self.log_path, encoding="utf-8", errors="replace") as f:
                    import json as _j
                    for line in f.readlines()[-_LOG_MAX:]:
                        line = line.strip()
                        if line:
                            try:
                                self._log.append(_j.loads(line))
                            except Exception:
                                pass
        except Exception:
            pass

    def _save(self) -> bool:
        with self._lock:
            return atomic_write_json(self.path, {
                "enabled": self.enabled, "policy": self.policy,
                "rules": self.rules, "saved": time.time()})

    # ── ON/OFF ───────────────────────────────────────────────────
    def is_enabled(self) -> bool:
        return self.enabled

    def enable(self) -> dict:
        with self._lock:
            self.enabled = True
            self._save()
        return {"ok": True, "enabled": True}

    def disable(self) -> dict:
        with self._lock:
            self.enabled = False
            self._save()
        return {"ok": True, "enabled": False}

    def toggle(self) -> dict:
        return self.disable() if self.enabled else self.enable()

    # ── ポリシー/ルール ──────────────────────────────────────────
    def set_policy(self, zone: str, action: str) -> dict:
        if zone not in ZONES or action not in ACTIONS:
            return {"ok": False, "error": "zone/action が不正",
                    "zones": ZONES, "actions": ACTIONS}
        with self._lock:
            self.policy[zone] = action
            self._save()
        return {"ok": True, "policy": dict(self.policy)}

    def add_rule(self, net: str, action: str, note: str = "") -> dict:
        if action not in ("allow", "deny"):
            return {"ok": False, "error": "action は allow/deny"}
        try:
            ipaddress.ip_network(net, strict=False)       # 妥当性
        except Exception as e:
            return {"ok": False, "error": f"IP/CIDR 不正: {e}"}
        with self._lock:
            self.rules = [r for r in self.rules if r.get("net") != net]
            self.rules.append({"net": net, "action": action, "note": note,
                               "added": time.time()})
            self._save()
        return {"ok": True, "rules": list(self.rules)}

    def remove_rule(self, net: str) -> dict:
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r.get("net") != net]
            self._save()
        return {"ok": True, "removed": before - len(self.rules)}

    def _match_rule(self, ip: str):
        """ルール照合。deny 優先・最長一致を尊重。一致が無ければ None。"""
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return None
        matches = []
        for r in self.rules:
            try:
                if addr in ipaddress.ip_network(r["net"], strict=False):
                    matches.append(r)
            except Exception:
                continue
        if not matches:
            return None
        # deny を優先、その中で最長プレフィクス
        denies = [r for r in matches if r["action"] == "deny"]
        pool = denies or matches
        return max(pool, key=lambda r: ipaddress.ip_network(
            r["net"], strict=False).prefixlen)

    # ── 判定(サーバ等が接続受理前に呼ぶ) ──────────────────────────
    def evaluate(self, ip: str, port: int = None, meta: dict = None) -> dict:
        zone = _zone_of(ip)
        if not self.enabled:
            return self._record(ip, port, zone, "allow",
                                "firewall OFF(パススルー)", None)
        rule = self._match_rule(ip)
        if rule is not None:
            return self._record(ip, port, zone, rule["action"],
                                f"ルール {rule['net']} に一致", rule["net"])
        action = self.policy.get(zone, "deny")
        if action == "prompt":
            pid = self._enqueue_pending(ip, port, zone, meta)
            return self._record(ip, port, zone, "pending",
                                f"{zone} は承認待ち", None, pending_id=pid)
        return self._record(ip, port, zone, action,
                            f"{zone} の既定ポリシー={action}", None)

    def _enqueue_pending(self, ip, port, zone, meta) -> str:
        with self._lock:
            # 同一IPの保留が既にあれば再利用(氾濫防止)
            for pid, p in self._pending.items():
                if p["ip"] == ip:
                    return pid
            self._pid_seq += 1
            pid = f"p{self._pid_seq}"
            self._pending[pid] = {"id": pid, "ip": ip, "port": port,
                                  "zone": zone, "ts": time.time(),
                                  "meta": meta or {}}
            return pid

    def _record(self, ip, port, zone, action, reason, rule, pending_id=None):
        entry = {"ts": time.time(), "ip": ip, "port": port, "zone": zone,
                 "action": action, "reason": reason, "rule": rule,
                 "pending_id": pending_id}
        with self._lock:
            self._log.append(entry)
            append_jsonl(self.log_path, entry)     # サイズ超で自動ローテーション
        return dict(entry)

    # ── 承認待ちの解決 ───────────────────────────────────────────
    def pending(self) -> list:
        with self._lock:
            return list(self._pending.values())

    def approve(self, pid: str, remember: bool = True) -> dict:
        return self._resolve(pid, "allow", remember)

    def deny_pending(self, pid: str, remember: bool = True) -> dict:
        return self._resolve(pid, "deny", remember)

    def _resolve(self, pid: str, action: str, remember: bool) -> dict:
        with self._lock:
            p = self._pending.pop(pid, None)
        if p is None:
            return {"ok": False, "error": f"承認待ち {pid} が無い"}
        if remember:
            net = p["ip"] + ("/32" if ":" not in p["ip"] else "/128")
            self.add_rule(net, action, note=f"{action} via approval")
        self._record(p["ip"], p["port"], p["zone"], action,
                     f"承認操作で {action}" + ("(記憶)" if remember else "(一時)"), None)
        return {"ok": True, "resolved": pid, "action": action,
                "remembered": remember, "ip": p["ip"]}

    def clear_pending(self) -> dict:
        with self._lock:
            n = len(self._pending)
            self._pending.clear()
        return {"ok": True, "cleared": n}

    # ── 参照 ─────────────────────────────────────────────────────
    def log(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._log)[-max(1, limit):]

    def stats(self) -> dict:
        with self._lock:
            counts = {}
            for e in self._log:
                counts[e["action"]] = counts.get(e["action"], 0) + 1
            return {"total": len(self._log), "by_action": counts,
                    "pending": len(self._pending), "rules": len(self.rules)}

    def status(self) -> dict:
        return {"enabled": self.enabled, "policy": dict(self.policy),
                "rules": list(self.rules), "pending": self.pending(),
                "stats": self.stats(),
                "note": "アプリ層FW(OS非侵襲)。OFFは完全パススルー。"}


# ── プロセス共有シングルトン(Webサービス等から共有) ──
_FW: AppFirewall = None
_FW_LOCK = threading.Lock()


def app_firewall() -> AppFirewall:
    global _FW
    if _FW is None:
        with _FW_LOCK:
            if _FW is None:
                _FW = AppFirewall()
    return _FW
