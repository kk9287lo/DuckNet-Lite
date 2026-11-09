"""
policy.py — 高度なアプリ層ファイアウォール(OSに干渉しない・ON/OFF可)
====================================================================================
DuckNet **自身のサーバ/ソケットへ来る接続** を、送信元IPのゾーン分類で
承認/拒否/保留(承認待ち)し、判定を有界なメモリ履歴に保持・設定を永続化する。

重要な線引き(「Windows/Mac/Linux に干渉しない」):
  · これは **アプリ層** のファイアウォール。OSのネットワークスタック(WFP/iptables/pf)は
    一切触らない=他アプリやOSの通信はブロックしない・できない(正直)。本アプリの
    リスナー(Webサービス等)が accept した接続を、配信前に本エンジンへ照会して弾く方式。
  · よって「システム全体のファイアウォール」ではない。OS非侵襲・可逆・透明。

機能:
  · ON/OFF … OFF は完全パススルー(挙動を変えない)。状態欠落時は既定ON。
  · ゾーン分類 … loopback(自機) / private(Windows・LAN) / public(インターネット) /
    special(メタデータ/予約等) / unknown(解析不能)。monitor.classify_ip を再利用。
  · ポリシー … ゾーン毎に allow / deny / prompt(承認待ち)。
  · ルール … IP/CIDR 単位の allow/deny(ipaddress で照合・deny優先)。
  · 承認待ち … prompt で保留された未知接続を、GUI/CLIで承認(allow化)/拒否(deny化)。
  · 記録 … 最新2000件をメモリに保持し、acl_log.jsonl へ best effort で追記する。
    追記失敗は判定の log_written と、本プロセスの stats.log_write_failed に示す。
  · 設定保存 … acl.json に enabled/policy/rules を署名付きで原子書込する。
"""
from __future__ import annotations

import ipaddress
import copy
import os
import threading
import time
from collections import deque

from ..core.atomic_io import default_state_dir, append_jsonl, atomic_write_text
from ..core.commit_barrier import policy_commit
from ..core.signed_state import (persistent_key, read_signed_json,
                                 write_signed_json, has_signed_history,
                                 MISSING_FINGERPRINT, payload_fingerprint)
from .monitor import classify_ip

ZONES = ["loopback", "private", "public", "special", "unknown"]
ACTIONS = ["allow", "deny", "prompt"]

# 既定ポリシー(安全側・アプリを壊さない): 自機は許可、LANは承認待ち、ネットは拒否。
_DEFAULT_POLICY = {"loopback": "allow", "private": "prompt",
                   "public": "deny", "special": "deny", "unknown": "prompt"}
_LOG_MAX = 2000
_LOG_READ_MAX = 8 * 1024 * 1024     # 通常の 5 MB ローテーションより大きく、持込巨大ログは有界
_SAVE_ERR = "ACL 状態を保存できません"
_RULES_MAX = 4096                    # 接続ごとのルール照合と署名状態を有界にする
_NET_MAX_CHARS = 64                  # IPv6 CIDR と通常の scope ID を含めても十分
_NOTE_MAX_CHARS = 256                # 管理用注記は表示と永続化に必要な長さだけ
_ACL_LOG_FIELDS = ("ts", "ip", "port", "zone", "action", "reason", "rule", "pending_id")


def _log_ip(ip) -> str:
    """Only a parsed peer address belongs in the durable ACL decision log."""
    if not isinstance(ip, str) or len(ip) > _NET_MAX_CHARS:
        return "<invalid ip>"
    try:
        # An IPv6 scope suffix is interface metadata, not part of the source
        # address needed for an ACL audit; it can contain arbitrary text.
        return str(ipaddress.ip_address(ip.split("%", 1)[0]))
    except ValueError:
        return "<invalid ip>"


def _unmap_v4(ip: str) -> str:
    """dual-stack 待受で届く IPv4-mapped(::ffff:a.b.c.d)を純 IPv4 に戻す。それ以外は不変。
    戻さないと _match_rule は版(v4/v6)違いの IPv4 ルールを照合せず deny を素通りし、ゾーン判定
    (loopback/private)も外れていた。呼び出し側の正規化に頼らず判定の入口で揃える。"""
    if not ip or ":" not in ip:
        return ip                                   # 純 IPv4/空は即返し(接続ごとの固定費ゼロ)
    try:
        m = ipaddress.ip_address(ip).ipv4_mapped
    except ValueError:
        return ip
    return str(m) if m is not None else ip


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


_PENDING_MAX = 4096    # 承認待ち接続の保持上限(未承認のまま溜め込ませない)


def _unmap_network(network):
    """Only wholly mapped IPv6 ranges have an equivalent IPv4 peer range."""
    if network.version == 6 and network.prefixlen >= 96:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.ip_network((mapped, network.prefixlen - 96), strict=False)
    return network


def _compile_net(cidr: str):
    """CIDR 文字列 -> ip_network(不正なら None)。照合ループの外で一度だけ呼ぶこと。"""
    try:
        return _unmap_network(ipaddress.ip_network(cidr, strict=False))
    except Exception:
        return None


class AppFirewall:
    """アプリ層ファイアウォールの中核。OS非侵襲・ON/OFF・記録・永続化。"""

    def __init__(self, state_dir: str = ""):
        base = state_dir or default_state_dir()
        os.makedirs(base, mode=0o700, exist_ok=True)
        self.path = os.path.join(base, "acl.json")
        self._history_path = os.path.join(base, ".acl_signed")
        self.log_path = os.path.join(base, "acl_log.jsonl")
        self._state_key = persistent_key(base)
        self._lock = threading.RLock()
        self._active_fork_clusters = 0  # local reservation: ACL audit/prompt state is not shared
        self._pending: dict = {}                 # id -> {ip, port, zone, ts, meta}
        self._pending_by_ip: dict = {}           # ip -> id(同一IPの重複保留を O(1) で判定)
        self._nets: dict = {}                    # ルールの CIDR 文字列 -> ip_network(事前コンパイル)
        self._log = deque(maxlen=_LOG_MAX)
        self._log_write_failed = 0
        self._reload_untrusted = False
        self._first_save_pending = False
        self._pid_seq = 0
        self._load()

    # ── 永続化 ───────────────────────────────────────────────────
    def _load(self, *, reload_only: bool = False):
        # v1/v2 envelopes were not bound to a filename. A newer signed usage
        # or Shield file can otherwise be copied over acl.json and advance the
        # ACL high-water before the missing enabled field triggers deny-all.
        # Validate the one required ACL root field while still under the
        # signed-state lock, preserving legitimate partial legacy policies.
        status, d = read_signed_json(
            self.path, self._state_key, {},
            payload_validator=lambda payload: (type(payload) is dict
                                               and type(payload.get("enabled")) is bool))
        # Compare later saves against the exact loaded payload, before default
        # merging and validation. A stale instance must not replace newer ACLs.
        self._state_fingerprint = (MISSING_FINGERPRINT if status == "missing"
                                   else payload_fingerprint(d))
        # The shield's .state_signed marker does not prove this ACL was signed:
        # a genuine legacy ACL can coexist with a migrated shield. This ACL's
        # own marker survives removal of acl.json.hw alone.
        marker_ready = status != "ok" or self._ensure_signed_history()
        history = (has_signed_history(self.path, self._state_key)
                   or os.path.lexists(self._history_path))
        self._load_warning = ""
        # 署名保存後の削除・平文すり替え・改竄は既定 OFF に倒さない。
        # 初回導入時だけ旧来の無署名 acl.json を受け入れ、直ちに署名形式へ移行する。
        invalid = not isinstance(d, dict)
        fail_closed = (not marker_ready or status in ("tampered", "rolled_back")
                       or (history and status in ("missing", "unsigned"))
                       or (status == "ok" and invalid))
        if fail_closed or invalid:
            d = {}
            self._load_warning = "ACL 状態を検証できません"
        # bool("false") や bool([]) では署名された不正値を ON/OFF に読み替えてしまう。
        # 欠損/型違いは安全側へ倒し、明示的な JSON false だけを OFF として尊重する。
        bad_enabled = (status in ("ok", "unsigned") and not fail_closed
                       and not isinstance(d.get("enabled"), bool))
        if bad_enabled:
            invalid = True
            d = {}
            self._load_warning = "ACL enabled が欠損または不正です"
        self.enabled = d.get("enabled") is not False
        self.policy = dict(_DEFAULT_POLICY)
        saved_policy = d.get("policy")
        bad_policy = ("policy" in d and
                      (not isinstance(saved_policy, dict) or
                       any(z not in ZONES or a not in ACTIONS
                           for z, a in saved_policy.items())))
        if bad_policy:
            invalid = True
            self._load_warning = "ACL ポリシーが不正です"
        elif isinstance(saved_policy, dict):
            self.policy.update(saved_policy)
        saved_rules = d.get("rules")
        self.rules = []
        if "rules" in d:
            bad_rules = not isinstance(saved_rules, list) or len(saved_rules) > _RULES_MAX
            normalized_rules = []
            if not bad_rules:
                for rule in saved_rules:
                    net = rule.get("net") if isinstance(rule, dict) else None
                    note = rule.get("note", "") if isinstance(rule, dict) else None
                    compiled = _compile_net(net) if isinstance(net, str) else None
                    if (not isinstance(net, str) or not net or len(net) > _NET_MAX_CHARS
                            or compiled is None
                            or rule.get("action") not in ("allow", "deny")
                            or not isinstance(note, str) or len(note) > _NOTE_MAX_CHARS):
                        bad_rules = True
                        break
                    try:
                        note.encode("utf-8")
                    except UnicodeEncodeError:
                        bad_rules = True
                        break
                    normalized_rules.append({**rule, "net": compiled.with_prefixlen}
                                            if compiled.version == 4 and ":" in net else dict(rule))
            if bad_rules:
                invalid = True
                self._load_warning = "ACL ルールが不正または上限超過です"
                # 一部の deny だけ落とすと permissive policy が残り得る。失敗した
                # ルール集合を丸ごと適用せず、全ゾーンを拒否して明示的に警告する。
                self.enabled = True
                self.policy = {z: "deny" for z in ZONES}
            else:
                self.rules = normalized_rules
        if fail_closed or bad_enabled or bad_policy:
            # A rejected replacement cannot retain its OFF bit or allow rules.
            self.enabled = True
            self.policy = {z: "deny" for z in ZONES}
            self.rules = []
        if reload_only:
            # Fork workers retain their pending decisions and in-memory audit
            # entries. Re-reading the log here would duplicate old rows.
            return status
        # ログ末尾を読み込む(記録の継続表示用)。外部で肥大したファイルを readlines() で
        # 全読込すると、起動前にログを置ける相手がメモリを使い切らせられる。
        try:
            if os.path.isfile(self.log_path):
                with open(self.log_path, "rb") as f:
                    import json as _j
                    f.seek(0, os.SEEK_END)
                    end = f.tell()
                    start = max(0, end - _LOG_READ_MAX)
                    f.seek(start - 1 if start else start)
                    partial = start > 0 and f.read(1) != b"\n"
                    f.seek(start)
                    lines = f.read(end - start).rsplit(b"\n", _LOG_MAX + 1)
                    if lines and not lines[-1]:
                        lines.pop()
                    if partial:
                        lines = lines[1:]
                    for raw in lines[-_LOG_MAX:]:
                        line = raw.decode("utf-8", "replace").strip()
                        if line:
                            try:
                                entry = _j.loads(line)
                                if isinstance(entry, dict) and isinstance(entry.get("action"), str):
                                    self._log.append(entry)
                            except Exception:
                                pass
        except Exception:
            pass
        if status == "unsigned" and not history and not invalid:
            detail = {}
            saved = self._save(status=detail)    # 正規の旧状態だけ署名形式へ移行
            if not saved:
                # A failed migration may leave the history marker beside an
                # unsigned file. Match the next boot's fail-closed decision now.
                self.enabled = True
                self.policy = {z: "deny" for z in ZONES}
                self.rules = []
                self._nets.clear()
                self._load_warning = self._save_failure(detail)["error"]
            elif detail.get("durable") is False:
                self._load_warning = self._saved_result({"ok": True}, detail)["error"]
        return status

    def reload_verified(self) -> bool:
        """Apply a newer signed ACL in a fork worker before new admission."""
        with self._lock:
            if self._reload_untrusted:
                return False
            pristine = self._state_fingerprint == MISSING_FINGERPRINT
            main_missing = not os.path.lexists(self.path)
            hw_missing = not os.path.lexists(self.path + ".hw")
            marker_seen = os.path.lexists(self._history_path)
            if pristine and main_missing and hw_missing:
                if marker_seen:
                    # The first writer establishes ACL history before its
                    # signed main file. A child may observe this short gap.
                    # Deny this admission but retry on the next one; a valid
                    # signed commit can then recover without a worker restart.
                    self._first_save_pending = True
                    self.enabled = True
                    self.policy = {zone: "deny" for zone in ZONES}
                    self.rules = []
                    self._nets = {}
                    self._load_warning = "ACL 初回保存を検証中です"
                    return False
                if not self._first_save_pending:
                    return True
                # A marker we already observed has vanished without a signed
                # main file. Treat that as removal of signed history below.
            try:
                status = self._load(reload_only=True)
                if (status == "missing" and pristine and marker_seen
                        and not os.path.lexists(self.path)
                        and not os.path.lexists(self.path + ".hw")):
                    # The writer may have rolled back a tentative high-water
                    # after we first observed it. Keep denying, but allow a
                    # later valid signed commit to repair this transient gap.
                    self._first_save_pending = True
                    return False
                if status != "ok" or self._load_warning:
                    raise ValueError("signed ACL state is unavailable")
                compiled = {rule["net"]: _compile_net(rule["net"]) for rule in self.rules}
                if any(value is None for value in compiled.values()):
                    raise ValueError("signed ACL rule is invalid")
                self._nets = compiled
                self._first_save_pending = False
                return True
            except Exception:
                self._reload_untrusted = True
                self.enabled = True
                self.policy = {zone: "deny" for zone in ZONES}
                self.rules = []
                self._nets = {}
                self._load_warning = "ACL 状態を検証できません"
                self._state_fingerprint = None
                return False

    def _ensure_signed_history(self) -> bool:
        """Establish ACL-specific history before publishing a signed ACL."""
        if os.path.lexists(self._history_path):
            return os.path.isfile(self._history_path) and not os.path.islink(self._history_path)
        detail = {}
        return (atomic_write_text(self._history_path, "acl:v1\n", newline="", status=detail)
                and detail.get("durable") is not False)

    def _save(self, *, status: dict | None = None) -> bool:
        with self._lock:
            detail = {} if status is None else status
            detail.clear()
            if self._reload_untrusted:
                detail.update(published=False, durable=False,
                              conflict=True, stage="acl-untrusted")
                return False
            if self._first_save_pending:
                # This worker observed a parent's marker-only first save.
                # It must not publish its temporary deny-all fallback as a
                # competing signed ACL while that commit is unresolved.
                detail.update(published=False, durable=False,
                              conflict=True, stage="acl-first-save-pending")
                return False
            with policy_commit(self.path) as ready:
                if not ready:
                    detail.update(published=False, durable=False,
                                  stage="cluster-policy-barrier")
                    return False
                if not self._ensure_signed_history():
                    detail.update(published=False, durable=False, stage="acl-history")
                    return False
                payload = {"enabled": self.enabled, "policy": self.policy,
                           "rules": self.rules, "saved": time.time()}
                try:
                    saved = write_signed_json(self.path, payload, self._state_key,
                                              status=detail,
                                              expected_fingerprint=self._state_fingerprint)
                    # Published data is already observable. Keep the same live
                    # state even if syncing its name failed after replacement.
                    published = bool(saved or detail.get("published") is True)
                except Exception:
                    published = detail.get("published") is True
                if published:
                    self._state_fingerprint = (detail.get("fingerprint")
                                               or payload_fingerprint(payload))
                return published

    @staticmethod
    def _save_failure(status: dict, **state) -> dict:
        result = {"ok": False, "error": _SAVE_ERR, **state}
        if status.get("stage") == "cluster-policy-barrier":
            result["error"] = "cluster policy commit barrier is unavailable"
        if status.get("conflict") is True:
            result.update(conflict=True,
                          error="ACL 状態が別の書き手に更新されています。再起動して最新状態を読み込み直してください")
        return result

    @staticmethod
    def _saved_result(result: dict, status: dict) -> dict:
        """Attach this commit's durability result, never an earlier operation's."""
        if status.get("published") is True and status.get("durable") is False:
            return {**result, "ok": False, "applied_in_memory": True,
                    "published": True, "persisted": False, "durable": False,
                    "error": "ACL 変更は公開済みですが保存先の同期に失敗しました。再起動後の保持を確認できません"}
        return result

    # ── ON/OFF ───────────────────────────────────────────────────
    def _reserve_fork_cluster(self) -> bool:
        with self._lock:
            if type(self.enabled) is not bool or self.enabled:
                return False
            self._active_fork_clusters += 1
            return True

    def _release_fork_cluster(self) -> None:
        with self._lock:
            if self._active_fork_clusters > 0:
                self._active_fork_clusters -= 1

    def is_enabled(self) -> bool:
        with self._lock:
            return self.enabled

    def enable(self) -> dict:
        with self._lock:
            if self._active_fork_clusters:
                return {"ok": False, "enabled": self.enabled,
                        "published": False, "persisted": False,
                        "error": "ACL audit and prompt state requires a single worker while cluster is active"}
            before = self.enabled
            self.enabled = True
            status = {}
            if not self._save(status=status):
                self.enabled = before
                return self._save_failure(status, enabled=before)
            return self._saved_result({"ok": True, "enabled": True}, status)

    def disable(self) -> dict:
        with self._lock:
            before = self.enabled
            self.enabled = False
            status = {}
            if not self._save(status=status):
                self.enabled = before
                return self._save_failure(status, enabled=before)
            return self._saved_result({"ok": True, "enabled": False}, status)

    def toggle(self) -> dict:
        with self._lock:
            return self.disable() if self.enabled else self.enable()

    # ── ポリシー/ルール ──────────────────────────────────────────
    def set_policy(self, zone: str, action: str) -> dict:
        if zone not in ZONES or action not in ACTIONS:
            return {"ok": False, "error": "zone/action が不正",
                    "zones": ZONES, "actions": ACTIONS}
        with self._lock:
            before = self.policy[zone]
            self.policy[zone] = action
            status = {}
            if not self._save(status=status):
                self.policy[zone] = before
                return self._save_failure(status, policy=dict(self.policy))
            return self._saved_result({"ok": True, "policy": dict(self.policy)}, status)

    def set_global_block(self, on: bool) -> dict:
        """public の一括遮断と FW 有効化を、1 回の保存として反映する。"""
        if not isinstance(on, bool):
            return {"ok": False, "error": "on は true/false"}
        with self._lock:
            if self._active_fork_clusters:
                return {"ok": False, "enabled": self.enabled,
                        "published": False, "persisted": False,
                        "error": "ACL audit and prompt state requires a single worker while cluster is active"}
            before_enabled, before_policy = self.enabled, self.policy
            self.enabled = True
            self.policy = {**self.policy, "public": "deny" if on else "allow"}
            status = {}
            if not self._save(status=status):
                self.enabled, self.policy = before_enabled, before_policy
                return self._save_failure(status, enabled=before_enabled, policy=dict(before_policy))
            return self._saved_result({"ok": True, "enabled": True, "policy": dict(self.policy)}, status)

    def add_rule(self, net: str, action: str, note: str = "") -> dict:
        if action not in ("allow", "deny"):
            return {"ok": False, "error": "action は allow/deny"}
        # ipaddress.ip_network(bool/int) は数値アドレスとして受け入れるが、保存後の
        # ローダは CIDR 文字列以外を捨てる。許可ルールが成功表示の直後に消えないよう、
        # 入力境界で型と大きさを確定する。
        if not isinstance(net, str) or not net or len(net) > _NET_MAX_CHARS:
            return {"ok": False, "error": "net は短い IP/CIDR 文字列で指定してください"}
        if not isinstance(note, str) or len(note) > _NOTE_MAX_CHARS:
            return {"ok": False, "error": "note は 256 文字以内の文字列で指定してください"}
        try:
            note.encode("utf-8")
        except UnicodeEncodeError:
            return {"ok": False, "error": "note は UTF-8 文字列で指定してください"}
        try:
            parsed = ipaddress.ip_network(net, strict=False)
            normalized = _unmap_network(parsed)
        except Exception as e:
            return {"ok": False, "error": f"IP/CIDR 不正: {e}"}
        if normalized.version != parsed.version:
            net = normalized.with_prefixlen
        with self._lock:
            before = self.rules
            replacement = [r for r in before if self._compiled_rule_net(r.get("net")) != normalized]
            if len(replacement) >= _RULES_MAX:
                return {"ok": False, "rules": copy.deepcopy(before),
                        "error": f"ACL ルールは {_RULES_MAX} 件まで"}
            self.rules = replacement + [{"net": net, "action": action, "note": note,
                                         "added": time.time()}]
            status = {}
            if not self._save(status=status):
                self.rules = before
                return self._save_failure(status, rules=copy.deepcopy(before))
            live = {r["net"] for r in self.rules}
            self._nets = {k: v for k, v in self._nets.items() if k in live}
            self._nets[net] = normalized
            return self._saved_result({"ok": True, "rules": copy.deepcopy(self.rules)}, status)

    def remove_rule(self, net: str) -> dict:
        if (not isinstance(net, str) or not net or len(net) > _NET_MAX_CHARS
                or _compile_net(net) is None):
            return {"ok": False, "removed": 0, "error": "有効な IP/CIDR 文字列を指定してください"}
        compiled = _compile_net(net)
        with self._lock:
            before = self.rules
            self.rules = [r for r in self.rules if self._compiled_rule_net(r.get("net")) != compiled]
            removed = len(before) - len(self.rules)
            status = {}
            if not self._save(status=status):
                self.rules = before
                return self._save_failure(status, removed=0)
            live = {r["net"] for r in self.rules}
            self._nets = {k: v for k, v in self._nets.items() if k in live}
            return self._saved_result({"ok": True, "removed": removed}, status)

    def _compiled_rule_net(self, cidr):
        if not isinstance(cidr, str):
            return None
        if cidr not in self._nets:
            self._nets[cidr] = _compile_net(cidr)
        return self._nets[cidr]

    def _match_rule(self, ip: str):
        """ルール照合。deny 優先・最長一致を尊重。一致が無ければ None。"""
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return None
        # ルールごとに ip_network() を作り直すと、接続 1 本あたり O(ルール数) の *パース* が
        # 走る(実測 1000 ルールで 1.6ms/接続)。しかも最長プレフィクス選択でもう一度作って
        # いた。ルールは滅多に変わらないので、変更時に一度だけコンパイルして使い回す。
        deny, allow = None, None
        deny_prefix, allow_prefix = -1, -1
        for r in self.rules:
            net = self._compiled_rule_net(r["net"])
            if net is not None and addr.version == net.version and addr in net:
                prefix = net.prefixlen
                if r["action"] == "deny":
                    if prefix > deny_prefix:
                        deny, deny_prefix = r, prefix
                    if prefix == net.max_prefixlen:
                        return deny          # longest possible; keep the first tie
                elif prefix > allow_prefix:
                    allow, allow_prefix = r, prefix
        return deny if deny is not None else allow

    # ── 判定(サーバ等が接続受理前に呼ぶ) ──────────────────────────
    def evaluate(self, ip: str, port: int = None, meta: dict = None, *, _defer_log: bool = False) -> dict:
        ip = _unmap_v4(ip)
        zone = _zone_of(ip)
        with self._lock:
            # 保存が失敗して設定を戻すまで、途中の値を接続判定に見せない。
            pending_id, matched = None, None
            if not self.enabled:
                action, reason = "allow", "firewall OFF(パススルー)"
            else:
                rule = self._match_rule(ip)
                if rule is not None:
                    action, matched = rule["action"], rule["net"]
                    reason = f"ルール {matched} に一致"
                else:
                    action = self.policy.get(zone, "deny")
                    if action == "prompt":
                        pending_id = self._enqueue_pending(ip, port, zone, meta)
                        action, reason = "pending", f"{zone} は承認待ち"
                    else:
                        reason = f"{zone} の既定ポリシー={action}"
            # The decision and in-memory audit entry share the state snapshot.
            entry = self._record_locked(ip, port, zone, action, reason, matched, pending_id)
        # A slow filesystem must not retain the live policy lock. The caller's
        # decision is already fixed. Direct callers append before returning;
        # the proxy can hand a detached work item to its bounded log worker.
        if _defer_log:
            result = dict(entry)
            result["log_written"] = None
            result["_acl_log_work"] = dict(entry)
            return result
        return self._append_record(entry)

    def _enqueue_pending(self, ip, port, zone, meta) -> str:
        with self._lock:
            # 同一IPの保留が既にあれば再利用(氾濫防止)。旧実装は保留表を毎接続 *線形走査*
            # しており、しかも表に上限が無かった。攻撃者が送信元を増やすだけで保留数 P が
            # 伸び、以後どの接続も O(P) を払う(= 接続数に対して二次)。IP 逆引きで O(1) に
            # し、表そのものにも上限を設ける。
            pid = self._pending_by_ip.get(ip)
            if pid is not None and pid in self._pending:
                return pid
            if len(self._pending) >= _PENDING_MAX:   # 最古から間引く(承認待ちの氾濫で OOM しない)
                for old_pid in list(self._pending)[:max(1, _PENDING_MAX // 10)]:
                    old = self._pending.pop(old_pid, None)
                    if old is not None:
                        self._pending_by_ip.pop(old["ip"], None)
            self._pid_seq += 1
            pid = f"p{self._pid_seq}"
            self._pending[pid] = {"id": pid, "ip": ip, "port": port,
                                  "zone": zone, "ts": time.time(),
                                  "meta": copy.deepcopy(meta) if meta else {}}
            self._pending_by_ip[ip] = pid
            return pid

    def _record_locked(self, ip, port, zone, action, reason, rule, pending_id=None):
        entry = {"ts": time.time(), "ip": _log_ip(ip), "port": port, "zone": zone,
                 "action": action, "reason": reason, "rule": rule,
                 "pending_id": pending_id}
        self._log.append(entry)
        return entry

    def _record(self, ip, port, zone, action, reason, rule, pending_id=None):
        with self._lock:
            entry = self._record_locked(ip, port, zone, action, reason, rule, pending_id)
        return self._append_record(entry)

    def _append_record(self, entry):
        written = self.write_acl_log(entry)
        with self._lock:
            entry["log_written"] = written
            return dict(entry)

    def write_acl_log(self, work) -> bool:
        """Append a fixed decision snapshot; no state lock spans filesystem I/O."""
        try:
            row = {name: work.get(name) for name in _ACL_LOG_FIELDS}
            row["ip"] = _log_ip(row["ip"])
            written = append_jsonl(self.log_path, row, wait=False) is True
        except Exception:
            written = False
        if not written:
            with self._lock:
                self._log_write_failed += 1
        return written

    # ── 承認待ちの解決 ───────────────────────────────────────────
    def pending(self) -> list:
        with self._lock:
            return copy.deepcopy(list(self._pending.values()))

    # remember の既定は False=この接続だけの一時許可/拒否(#111: 1 回の操作で恒久ルールを黙って
    # acl.json へ書かない)。旧既定 True では remember を渡し忘れた呼び出しが /32 の恒久 allow/deny を
    # 積み得た。恒久化は remember=True の明示のみ。
    def approve(self, pid: str, remember: bool = False) -> dict:
        return self._resolve(pid, "allow", remember)

    def deny_pending(self, pid: str, remember: bool = False) -> dict:
        return self._resolve(pid, "deny", remember)

    def _resolve(self, pid: str, action: str, remember: bool) -> dict:
        if not isinstance(pid, str) or not pid or len(pid) > 64:
            return {"ok": False, "error": "承認待ち ID が不正"}
        if not isinstance(remember, bool):
            return {"ok": False, "error": "remember は true/false で指定してください"}
        with self._lock:
            p = self._pending.get(pid)
            if p is None:
                return {"ok": False, "error": f"承認待ち {pid} が無い"}
            saved = None
            if remember:
                net = p["ip"] + ("/32" if ":" not in p["ip"] else "/128")
                saved = self.add_rule(net, action, note=f"{action} via approval")
                if not saved.get("ok") and saved.get("published") is not True:
                    result = {"ok": False, "error": saved.get("error", _SAVE_ERR)}
                    if saved.get("conflict") is True:
                        result["conflict"] = True
                    return result
            self._pending.pop(pid, None)
            self._pending_by_ip.pop(p["ip"], None)
        uncertain = saved is not None and saved.get("durable") is False
        suffix = "(公開済み・保存先同期失敗)" if uncertain else "(記憶)" if remember else "(一時)"
        self._record(p["ip"], p["port"], p["zone"], action,
                     f"承認操作で {action}" + suffix, None)
        result = {"ok": True, "resolved": pid, "action": action,
                  "remembered": remember, "ip": p["ip"]}
        if saved is not None and saved.get("ok") is False:
            result.update({key: saved[key] for key in
                           ("ok", "applied_in_memory", "published", "persisted", "durable", "error")
                           if key in saved})
            result["remembered"] = False
        return result

    def clear_pending(self) -> dict:
        with self._lock:
            n = len(self._pending)
            self._pending.clear()
            self._pending_by_ip.clear()
        return {"ok": True, "cleared": n}

    # ── 参照 ─────────────────────────────────────────────────────
    def log(self, limit: int = 100) -> list:
        with self._lock:
            return copy.deepcopy(list(self._log)[-max(1, limit):])

    def stats(self) -> dict:
        with self._lock:
            counts = {}
            for e in self._log:
                counts[e["action"]] = counts.get(e["action"], 0) + 1
            return {"total": len(self._log), "by_action": counts,
                    "pending": len(self._pending), "rules": len(self.rules),
                    "log_write_failed": self._log_write_failed}

    def status(self) -> dict:
        with self._lock:
            return {"enabled": self.enabled, "policy": dict(self.policy),
                    "rules": copy.deepcopy(self.rules), "pending": self.pending(),
                    "stats": self.stats(),
                    "load_warning": self._load_warning,
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
