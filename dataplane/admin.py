"""
admin.py — DuckNet-Lite 管理ダッシュボード(Web GUI・stdlib http.server)
====================================================================================
中小企業のWeb担当者が『管理画面で攻撃をグラフ化・ON/OFFをクリック』できる製品UI。
外部依存ゼロ(標準ライブラリのみ)。app_firewall + net_shield を1画面で操作・監視する。

  · GET  /                  … ダッシュボード(HTML。トークンは埋め込まない)
  · GET  /api/state         … 現在の全状態(firewall/shield/指標/capabilities)
  · POST /api/firewall/*    … ON/OFF・ゾーンポリシー・IPルール
  · POST /api/shield/*      … ON/OFF・config・unban
  · GET  /api/shield/events|top|bans
  · GET  /api/edge          … エッジ前衛(リバースプロキシ)設定(444 Drop)テキストを取得

既定は localhost 待受 + ランダム Bearer トークン。商用配布可。
"""
from __future__ import annotations

import hmac
import hashlib
import copy
import html as html_lib
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import stat
import sys
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit

# 旧版の生トークン Cookie を失効させるためだけに名前を保持する。
_COOKIE_NAME = "ducknet_admin"

from dataplane.engine.lifeform.policy import (app_firewall, ZONES, ACTIONS,
                                              _compile_net, _NET_MAX_CHARS, _RULES_MAX)
from dataplane.engine.lifeform.pipeline import (net_shield, _DEFAULTS, _ENUM_KEYS,
                                                _OPTIONAL_SIGS, _PARANOIA_TIERS,
                                                _CUSTOM_NAME_RE, _BUILTIN_SIG_NAMES,
                                                _CUSTOM_SIG_MAX, _sig_weight,
                                                _canon_cfg_ip)
from dataplane.engine.services import edge_config
from dataplane.engine.core.atomic_io import (default_state_dir, tail_jsonl,
                                                      append_jsonl)

# 管理APIのリクエストボディ上限(Content-Length 詐称・巨大ボディのメモリ枯渇防止)。
_MAX_BODY = 1 << 20
_MAX_AUDIT_READ_BYTES = 8 * 1024 * 1024
_ADMIN_HEAD_DEADLINE_SEC = 3.0
_ADMIN_BODY_DEADLINE_SEC = 30.0
_ADMIN_READY_DEADLINE_SEC = 5.0
_ADMIN_STOP_DEADLINE_SEC = 3.0
_ADMIN_MAX_HANDLERS = 64
_ADMIN_PENDING_HEAD_MAX = 8
_ADMIN_REJECT_BODY_DRAINS_MAX = 8
_ADMIN_PENDING_HEAD_GRACE_SEC = 0.05
_ADMIN_HEAD_MAX_BYTES = 65536
_BROWSER_AUTH_SKEW_MS = 30_000
_BROWSER_NONCE_TTL_SEC = 60
_BROWSER_NONCE_MAX = 8192
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_DASHBOARD_MARKERS = re.compile(r"__(?:BRAND|LOGO|FAVICON|SUBTITLE|AUTH_INSTANCE)__")


class _AdminHeadTooLarge(Exception):
    pass


class _AdminHeadReader:
    """Count the exact request-line and header bytes consumed by http.server."""

    def __init__(self, source):
        self._source = source
        self._bytes = 0
        self._complete = False

    def readline(self, limit=-1):
        line = self._source.readline(limit)
        if not self._complete:
            self._bytes += len(line)
            if self._bytes > _ADMIN_HEAD_MAX_BYTES:
                raise _AdminHeadTooLarge
            if line in (b"\r\n", b"\n", b""):
                self._complete = True
        return line

    def __getattr__(self, name):
        return getattr(self._source, name)


def _render_dashboard_html(app) -> str:
    # Only template-owned markers are expanded. Values inserted in one field
    # must not be interpreted as another field or moved into another context.
    values = {"__BRAND__": html_lib.escape(app.brand, quote=True),
              "__LOGO__": app._logo_html,
              "__FAVICON__": app._favicon_html,
              "__SUBTITLE__": html_lib.escape(str(app.subtitle), quote=True),
              "__AUTH_INSTANCE__": app._browser_instance_id}
    return _DASHBOARD_MARKERS.sub(lambda match: values[match.group(0)], _HTML)
# 真偽値を必須とするルートとそのキー。欠落・綴り違い・非 bool を False 扱いで実行すると
# 「無効化・拒否」側が走る(シールド OFF・全体遮断の解除・申立の却下)ため 400 で弾く(#24)。
_BOOL_KEYS = {"/api/firewall/toggle": "on", "/api/shield/toggle": "on",
              "/api/global_block": "on", "/api/shield/optional_sig": "on",
              "/api/firewall/resolve": "approve", "/api/appeal/resolve": "approve"}
# The HTTP API has a fixed schema even when an underlying Python setter has
# convenience defaults. Ignoring a typo such as `permanent` on manual BAN or a
# misspelled signature weight must never return ok:true for a different action.
_POST_FIELDS = {
    "/api/firewall/toggle": frozenset(("on",)),
    "/api/firewall/policy": frozenset(("zone", "action")),
    "/api/firewall/rule": frozenset(("op", "net", "action")),
    "/api/firewall/resolve": frozenset(("id", "approve", "remember")),
    "/api/shield/toggle": frozenset(("on",)),
    "/api/shield/config": frozenset(_DEFAULTS) | {"_expected_revision"},
    "/api/shield/optional_sig": frozenset(("name", "on")),
    "/api/shield/paranoia": frozenset(("level", "optional_sigs")),
    "/api/shield/path_limits": frozenset(("rules",)),
    "/api/shield/blocked_methods": frozenset(("methods",)),
    "/api/shield/sig_add": frozenset(("name", "pattern", "weight")),
    "/api/shield/sig_remove": frozenset(("name",)),
    "/api/shield/unban": frozenset(("ip",)),
    "/api/shield/ban": frozenset(("ip",)),
    "/api/appeal/resolve": frozenset(("ip", "approve", "note")),
    "/api/global_block": frozenset(("on",)),
    "/api/shield/sig_test": frozenset(("pattern", "sample")),
}
_POST_REQUIRED = {
    "/api/firewall/toggle": ("on",),
    "/api/firewall/policy": ("zone", "action"),
    "/api/firewall/rule": ("net",),
    "/api/firewall/resolve": ("id", "approve"),
    "/api/shield/toggle": ("on",),
    "/api/shield/optional_sig": ("name", "on"),
    "/api/shield/paranoia": ("level",),
    "/api/shield/path_limits": ("rules",),
    "/api/shield/blocked_methods": ("methods",),
    "/api/shield/sig_add": ("name", "pattern"),
    "/api/shield/sig_remove": ("name",),
    "/api/shield/unban": ("ip",),
    "/api/shield/ban": ("ip",),
    "/api/appeal/resolve": ("ip", "approve"),
    "/api/global_block": ("on",),
    "/api/shield/sig_test": ("pattern",),
}


def _rule_request_error(body: dict) -> str | None:
    """Validate the operation-specific rule fields before quiescing workers."""
    op = body.get("op", "add")
    if op not in ("add", "remove"):
        return "'op' must be add or remove"
    allowed = ({"op", "net", "action"} if op == "add" else {"op", "net"})
    if any(key not in allowed for key in body):
        return "unknown firewall rule field"
    if op == "add" and body.get("action") not in ("allow", "deny"):
        # A misspelled/missing action used to replace an allow rule with deny.
        return "'action' must be allow or deny"
    return None


def _preview_admin_mutation(path: str, body: dict, fw, sh):
    """Under the selected state lock, reject impossible edits before fork teardown.

    Return (error, unchanged). The setter still revalidates on commit; a pure
    preview must never publish a partial policy or consume an audit row.
    """
    def bad(error, code=400):
        return (code, {"ok": False, "error": error}), False

    if path == "/api/firewall/toggle":
        return None, not fw._load_warning and fw.enabled is body["on"]
    if path == "/api/firewall/policy":
        return None, (not fw._load_warning and
                      fw.policy.get(body["zone"]) == body["action"])
    if path == "/api/global_block":
        target = "deny" if body["on"] else "allow"
        return None, (not fw._load_warning and fw.enabled is True and
                      fw.policy.get("public") == target)
    if path == "/api/firewall/rule":
        net = body["net"]
        if not isinstance(net, str) or not net or len(net) > _NET_MAX_CHARS:
            return bad("有効な IP/CIDR 文字列を指定してください")
        parsed = _compile_net(net)
        if parsed is None:
            return bad("有効な IP/CIDR 文字列を指定してください")
        matching = [rule for rule in fw.rules
                    if isinstance(rule.get("net"), str)
                    and _compile_net(rule["net"]) == parsed]
        if body.get("op", "add") == "remove":
            return None, not matching and not fw._load_warning
        if len(fw.rules) - len(matching) >= _RULES_MAX:
            return bad(f"ACL ルールは {_RULES_MAX} 件まで")
        return None, False  # add_rule changes its timestamp even for same action
    if path == "/api/firewall/resolve":
        pending_id = body["id"]
        if not isinstance(pending_id, str) or not 0 < len(pending_id) <= 64:
            return bad("承認待ち ID が不正")
        if pending_id not in fw._pending:
            return bad(f"承認待ち {pending_id} が無い", 404)
        return None, False
    if path == "/api/shield/toggle":
        return None, (not sh._cfg_state_untrusted and
                      sh.cfg.get("enabled") is body["on"])
    if path == "/api/shield/optional_sig":
        return None, (not sh._cfg_state_untrusted and
                      bool(sh.cfg.get("optional_sigs", {}).get(body["name"]))
                      is body["on"])
    if path == "/api/shield/paranoia":
        selected = (body["optional_sigs"] if "optional_sigs" in body else
                    {name: True for name in _PARANOIA_TIERS[body["level"]]})
        return None, (not sh._cfg_state_untrusted and
                      sh.cfg.get("paranoia") == body["level"] and
                      sh.cfg.get("optional_sigs") == selected)
    if path == "/api/shield/sig_add":
        name, pattern, weight = (body["name"], body["pattern"],
                                 body.get("weight", 40))
        if not isinstance(name, str) or not _CUSTOM_NAME_RE.fullmatch(name):
            return bad("name は英数・._- のみ、1〜64文字")
        if name.lower() in _BUILTIN_SIG_NAMES:
            return bad("組込シグネチャと同名")
        normalized_weight = _sig_weight(weight)
        if normalized_weight is None:
            return bad("weight は 0 以上の有限の数値")
        error = sh.validate_pattern(pattern) if isinstance(pattern, str) else "pattern は文字列"
        if error:
            return bad(error)
        if sh.is_duplicate_pattern(pattern, exclude_name=name):
            return bad("重複(既存と同一/挙動同値)のため不採用")
        others = [entry for entry in sh._custom if entry.get("name") != name]
        if len(others) >= _CUSTOM_SIG_MAX:
            return bad(f"カスタムシグネチャは最大 {_CUSTOM_SIG_MAX} 件")
        candidate = others + [{"name": name, "category": "custom",
                               "pattern": pattern, "weight": normalized_weight,
                               "enabled": True, "source": "user"}]
        try:
            sh._compile_custom(candidate)
        except Exception:
            return bad("signature compilation failed", 503)
        return None, not sh._sig_state_untrusted and candidate == sh._custom
    if path == "/api/shield/sig_remove":
        if not isinstance(body["name"], str) or not _CUSTOM_NAME_RE.fullmatch(body["name"]):
            return bad("name は英数・._- のみ、1〜64文字")
        return None, (not sh._sig_state_untrusted and
                      not any(entry.get("name") == body["name"]
                              for entry in sh._custom))
    if path == "/api/shield/ban":
        _key, _ttl, error = sh._ban_args(body["ip"], None, False)
        if error:
            return (400, error), False
        return None, False
    if path == "/api/shield/unban":
        ip = body["ip"]
        raw = ip if isinstance(ip, str) else ""
        key = _canon_cfg_ip(ip)
        targets = {key, raw, raw.strip()} - {""}
        found = any(target in sh._ips or target in sh._restrictions
                    for target in targets)
        if not key and not found:
            return bad("単一のIPアドレスを指定してください")
        return None, (not sh._ban_state_untrusted and not sh._bans_dirty and not found)
    if path == "/api/appeal/resolve":
        ip, note = body["ip"], body.get("note", "")
        if not isinstance(ip, str) or not isinstance(note, str):
            return bad("approve must be a boolean and note a string")
        appeal = sh._appeals.get(ip)
        if not appeal:
            return bad(f"申立が無い: {ip}", 404)
        if appeal.get("status") != "pending" or not sh._review_matches_ban(ip, appeal):
            return bad("現在のBANに対する審査待ち申立ではありません")
    return None, False

# These reads are drawn from the parent's process-local state. During a true
# fork cluster, a 200 response would silently omit child traffic or decisions.
_FORK_LOCAL_READ_ENDPOINTS = frozenset((
    "/api/series", "/api/analysis", "/api/appeals", "/api/nodes", "/api/apt",
    "/api/shield/events", "/api/shield/top", "/api/shield/bans",
    "/api/shield/subnet", "/api/shield/tamper", "/api/metrics",
))


def _json_finite(o, _active=None):
    """NaN/±Infinity の float を None にした複製(dict/list/tuple を再帰)。dict のキーは従来の
    json.dumps と同じ文字列("NaN" 等)にする。循環参照は辿らず元の値を残す(直後の json.dumps が
    従来どおり ValueError を出す=無限再帰にしない)。"""
    if isinstance(o, float):
        return o if math.isfinite(o) else None
    if not isinstance(o, (dict, list, tuple)):
        return o
    active = set() if _active is None else _active
    if id(o) in active:
        return o
    active.add(id(o))
    try:
        if isinstance(o, dict):
            return {(json.dumps(k) if isinstance(k, float) and not math.isfinite(k) else k):
                    _json_finite(v, active) for k, v in o.items()}
        return [_json_finite(v, active) for v in o]
    finally:
        active.discard(id(o))


def _j(obj) -> bytes:
    # allow_nan=False: 既定の json.dumps は NaN/Infinity を出すが、ブラウザの JSON.parse はそれを
    # 拒否する=状態のどこか 1 つの非有限値で応答全体が解析不能になり、ダッシュボードが『切断』の
    # まま戻らなかった。通常は 1 回で済み、ValueError の時だけ非有限を null にして出し直す。
    # backslashreplace: 本文は json.loads 由来なので孤立サロゲート('\udc80')が入り得る。厳格な
    # UTF-8 では応答が毎回 500 になっていた。文字列中の \udXXX は JSON の正しいエスケープ。
    try:
        s = json.dumps(obj, ensure_ascii=False, allow_nan=False,
                       default=lambda _o: "<unsupported>")
    except ValueError:
        s = json.dumps(_json_finite(obj), ensure_ascii=False, allow_nan=False,
                       default=lambda _o: "<unsupported>")
    return s.encode("utf-8", "backslashreplace")


def _config_revision(config: dict) -> str:
    """Opaque precondition for the exact configuration snapshot shown to the GUI."""
    raw = json.dumps(config, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _metrics_exposition(sh) -> str:
    """NetShield の指標を plain-text 露出形式で出す(監視系のスクレイプ用・依存ゼロ)。
    `# HELP`/`# TYPE` + `ducknet_<name>{label="v"} <int>`。ラベル値はサニタイズ(改行/引用符除去)。"""
    m = sh.metrics()
    out = []

    def scalar(name, val, typ, help_):
        out.append(f"# HELP ducknet_{name} {help_}")
        out.append(f"# TYPE ducknet_{name} {typ}")
        out.append(f"ducknet_{name} {val}")

    for key, name, h in (("requests", "requests_total", "Requests inspected"),
                         ("allow", "allow_total", "Allowed requests"),
                         ("block", "block_total", "Blocked requests"),
                         ("throttle", "throttle_total", "Throttled requests"),
                         ("dlp_leak", "dlp_leak_total", "Egress secret leaks"),
                         ("subnet_flag", "subnet_flag_total", "Subnet-aggregation soft flags")):
        scalar(name, int(m.get(key, 0)), "counter", h)
    scalar("shield_enabled", 1 if sh.is_enabled() else 0, "gauge", "Shield enabled (1/0)")
    # 監査モード(mode=audit=記録のみ・遮断しない)。トレイはこれを見て『防御 ON』と区別して表示する
    scalar("shield_audit_mode", 1 if sh.cfg.get("mode") == "audit" else 0, "gauge",
           "Monitor-only mode: records but does not block (1/0)")
    scalar("tracked_ips", int(m.get("tracked_ips", 0)), "gauge", "Tracked source IPs")
    scalar("active_bans", int(m.get("active_bans", 0)), "gauge", "Active bans")
    scalar("paranoia_level", int(sh.cfg.get("paranoia", 1) or 1), "gauge", "Detection paranoia level")
    _sn = sh.subnet_status()
    scalar("hot_subnets", int(_sn.get("hot_subnets", 0)), "gauge", "Hot subnets (distributed-attack)")
    scalar("tracked_subnets", int(_sn.get("tracked_subnets", 0)), "gauge", "Tracked subnets")

    def labeled(name, d, label, help_):
        if not isinstance(d, dict) or not d:
            return
        out.append(f"# HELP ducknet_{name} {help_}")
        out.append(f"# TYPE ducknet_{name} counter")
        for k, v in d.items():
            lv = str(k).replace("\\", "").replace('"', "").replace("\n", "")[:64]
            out.append(f'ducknet_{name}{{{label}="{lv}"}} {int(v)}')

    labeled("sig_hits_total", m.get("sig_hits"), "signature", "Signature hits by category")
    labeled("zone_hits_total", m.get("zone_hits"), "zone", "Requests by zone")
    return "\n".join(out) + "\n"


_AUDIT_REDACTED = "[REDACTED]"
_AUDIT_KNOWN_ENDPOINTS = frozenset({
    "/api/firewall/toggle", "/api/firewall/policy", "/api/firewall/rule",
    "/api/firewall/resolve", "/api/shield/toggle", "/api/shield/config",
    "/api/shield/optional_sig", "/api/shield/paranoia", "/api/shield/path_limits",
    "/api/shield/blocked_methods", "/api/shield/sig_add", "/api/shield/sig_remove",
    "/api/shield/unban", "/api/shield/ban", "/api/appeal/resolve",
    "/api/global_block",
})


def _audit_rule(value):
    """The rule's CIDR and action identify the operation; notes do not."""
    if not isinstance(value, dict):
        return None
    net = value.get("net")
    if isinstance(net, str) and len(net) <= 64 and "%" not in net:
        try:
            net = str(ipaddress.ip_network(net, strict=False))
        except ValueError:
            net = _AUDIT_REDACTED
    else:
        net = _AUDIT_REDACTED
    action = value.get("action")
    return {"net": net, "action": action if action in ("allow", "deny") else "unknown"}


def _audit_ip(value):
    if not isinstance(value, str) or len(value) > 128:
        return _AUDIT_REDACTED
    # Scope IDs are arbitrary interface text and are not needed in audit rows.
    raw = value.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return _AUDIT_REDACTED


def _audit_bool(value):
    return value if type(value) is bool else None


def _audit_paranoia(value):
    return value if type(value) is int and 1 <= value <= 4 else None


def _audit_optionals(value):
    if not isinstance(value, dict) or len(value) > len(_OPTIONAL_SIGS):
        return None
    if any(key not in _OPTIONAL_SIGS or type(flag) is not bool
           for key, flag in value.items()):
        return None
    return dict(value)


def _audit_list_count(value):
    if not isinstance(value, list):
        return 0
    if len(value) == 1 and isinstance(value[0], dict):
        marker = value[0]
        count = marker.get("count")
        if set(marker) == {"count"} and type(count) is int and count >= 0:
            return count
    return len(value)


def _audit_scalar(key, value):
    """Keep only fixed-schema values in an audit record or its undo body."""
    if value is None or type(value) is bool:
        return value, True
    if type(value) in (int, float):
        try:
            if math.isfinite(value) and abs(value) <= 10**15:
                return value, True
        except (OverflowError, ValueError):
            pass
    if isinstance(value, str) and key in _ENUM_KEYS and value in _ENUM_KEYS[key]:
        return value, True
    return _AUDIT_REDACTED, False


def _audit_privacy(entry: dict) -> dict:
    """Limit new and legacy audit views to operation metadata and safe values.

    Freeform paths, signature patterns and names can contain URL credentials or
    private data. An undo body must not preserve a secret just to keep the button.
    """
    if not isinstance(entry, dict):
        return {"ts": 0, "endpoint": "", "summary": "invalid audit entry",
                "before": None, "after": None, "revert": None}
    out = {key: entry.get(key) for key in
           ("ts", "endpoint", "summary", "before", "after", "revert")}
    try:
        if type(out["ts"]) not in (int, float) or not math.isfinite(out["ts"]):
            out["ts"] = 0
    except (OverflowError, ValueError):
        out["ts"] = 0
    out.update({key: entry[key] for key in
                ("applied_in_memory", "published", "persisted", "durable")
                if type(entry.get(key)) is bool})
    path = out["endpoint"]
    if not isinstance(path, str) or path not in _AUDIT_KNOWN_ENDPOINTS:
        out.update(endpoint="", summary="audit event", before=None, after=None, revert=None)
        return out
    if path == "/api/shield/config":
        before = entry.get("before") if isinstance(entry.get("before"), dict) else {}
        after = entry.get("after") if isinstance(entry.get("after"), dict) else {}
        keys = [key for key in dict.fromkeys((*before, *after))
                if isinstance(key, str) and key in _DEFAULTS][:len(_DEFAULTS)]
        bsafe, asafe, all_safe = {}, {}, True
        for key in keys:
            bsafe[key], b_ok = _audit_scalar(key, before.get(key))
            asafe[key], a_ok = _audit_scalar(key, after.get(key))
            all_safe = all_safe and b_ok and a_ok
        out["before"], out["after"] = bsafe, asafe
        out["summary"] = ("config: " + "; ".join(
            f"{key}: {bsafe[key]} -> {asafe[key]}" for key in keys)
            if keys else "config updated")
        out["revert"] = ({"endpoint": path, "body": {keys[0]: bsafe[keys[0]]}}
                         if len(keys) == 1 and all_safe and bsafe[keys[0]] is not None else None)
    elif path in ("/api/shield/sig_add", "/api/shield/sig_remove"):
        out["summary"] = "signature added" if path.endswith("sig_add") else "signature removed"
        out["before"] = ({"name": _AUDIT_REDACTED} if entry.get("before") is not None else None)
        out["after"] = ({"name": _AUDIT_REDACTED} if entry.get("after") is not None else None)
        out["revert"] = None
    elif path in ("/api/shield/path_limits", "/api/shield/blocked_methods"):
        before = entry.get("before")
        after = entry.get("after")
        before_count, count = _audit_list_count(before), _audit_list_count(after)
        out["before"] = ([{"count": before_count}] if before_count else [])
        out["after"] = ([{"count": count}] if count else [])
        out["summary"] = (f"path limits updated ({count} rules)" if path.endswith("path_limits")
                          else f"blocked methods updated ({count})")
        out["revert"] = None
    elif path == "/api/firewall/rule":
        out["before"] = _audit_rule(entry.get("before"))
        out["after"] = _audit_rule(entry.get("after"))
        rule = out["after"] or out["before"]
        net = rule["net"] if rule else _AUDIT_REDACTED
        out["summary"] = (f"firewall rule {net} -> {rule['action']}" if out["after"] else
                          f"firewall rule {net} removed")
        out["revert"] = None
    elif path in ("/api/firewall/toggle", "/api/shield/toggle"):
        out["before"] = _audit_bool(entry.get("before"))
        out["after"] = _audit_bool(entry.get("after"))
        subject = "firewall" if path.startswith("/api/firewall/") else "shield"
        out["summary"] = (f"{subject} {'enabled' if out['after'] else 'disabled'}"
                          if out["after"] is not None else f"{subject} toggle")
        out["revert"] = ({"endpoint": path, "body": {"on": out["before"]}}
                         if out["before"] is not None and out["after"] is not None else None)
    elif path == "/api/firewall/policy":
        before, after = entry.get("before"), entry.get("after")
        out["before"] = before if type(before) is str and before in ACTIONS else None
        out["after"] = after if type(after) is str and after in ACTIONS else None
        out["summary"] = (f"firewall policy -> {out['after']}" if out["after"]
                          else "firewall policy changed")
        out["revert"] = None
    elif path == "/api/firewall/resolve":
        after = entry.get("after") if isinstance(entry.get("after"), dict) else {}
        pid = after.get("id")
        pid = pid if isinstance(pid, str) and re.fullmatch(r"p[0-9]{1,18}", pid) else None
        approve = _audit_bool(after.get("approve"))
        remember = _audit_bool(after.get("remember"))
        ip = _audit_ip(after.get("ip"))
        out["before"] = None
        out["after"] = {"id": pid, "approve": approve, "remember": remember, "ip": ip}
        uncertain = out.get("published") is True and out.get("durable") is False
        suffix = ("(公開済み・保存未確認)" if uncertain else
                  "(記憶=常時許可)" if approve is True and remember is True else
                  "(一時)" if approve is True else "")
        out["summary"] = (f"pending connection {ip if ip != _AUDIT_REDACTED else pid or ''} "
                          f"{'approved' if approve else 'denied'}{suffix}" if approve is not None
                          else "pending connection resolved")
        out["revert"] = None
    elif path == "/api/shield/optional_sig":
        out["before"] = _audit_bool(entry.get("before"))
        out["after"] = _audit_bool(entry.get("after"))
        old_revert = entry.get("revert")
        body = old_revert.get("body") if isinstance(old_revert, dict) else None
        name = body.get("name") if isinstance(body, dict) else None
        name = name if isinstance(name, str) and name in _OPTIONAL_SIGS else None
        out["summary"] = (f"optional signature {name} -> {'on' if out['after'] else 'off'}"
                          if name and out["after"] is not None else "optional signature changed")
        out["revert"] = ({"endpoint": path, "body": {"name": name, "on": out["before"]}}
                         if name and out["before"] is not None and out["after"] is not None
                         else None)
    elif path == "/api/shield/paranoia":
        out["before"] = _audit_paranoia(entry.get("before"))
        out["after"] = _audit_paranoia(entry.get("after"))
        out["summary"] = (f"paranoia level {out['before']} -> {out['after']}"
                          if out["before"] is not None and out["after"] is not None
                          else "paranoia level changed")
        old_revert = entry.get("revert")
        body = old_revert.get("body") if isinstance(old_revert, dict) else None
        opts = _audit_optionals(body.get("optional_sigs")) if isinstance(body, dict) else None
        out["revert"] = ({"endpoint": path,
                          "body": {"level": out["before"], "optional_sigs": opts}}
                         if out["before"] is not None and out["after"] is not None
                         and isinstance(body, dict) and body.get("level") == out["before"]
                         and type(body.get("level")) is int and opts is not None else None)
    elif path in ("/api/shield/ban", "/api/shield/unban"):
        before = entry.get("before") if isinstance(entry.get("before"), dict) else {}
        after = entry.get("after") if isinstance(entry.get("after"), dict) else {}
        ip = _audit_ip(after.get("ip"))
        out["before"] = {"ip": _audit_ip(before.get("ip"))} if before else None
        out["after"] = {"ip": ip}
        for key in ("persisted", "applied_in_memory"):
            if type(after.get(key)) is bool:
                out["after"][key] = after[key]
        verb = "banned manually" if path.endswith("/ban") else "unbanned"
        memory_only = (out["after"].get("applied_in_memory") is True
                       and out["after"].get("persisted") is False)
        out["summary"] = (f"IP {ip} {verb}" +
                          (" (memory only; save failed)" if memory_only else ""))
        out["revert"] = None
    elif path == "/api/appeal/resolve":
        after = entry.get("after") if isinstance(entry.get("after"), dict) else {}
        ip = _audit_ip(after.get("ip"))
        approve = _audit_bool(after.get("approve"))
        out["before"] = None
        out["after"] = {"ip": ip, "approve": approve}
        out["summary"] = (f"appeal {ip} {'approved' if approve else 'denied'}"
                          if approve is not None else "appeal resolved")
        out["revert"] = None
    elif path == "/api/global_block":
        before, after = entry.get("before"), entry.get("after")
        out["before"] = before if type(before) is str and before in ACTIONS else None
        out["after"] = after if type(after) is str and after in ACTIONS else None
        out["summary"] = (f"global block -> {'on' if out['after'] == 'deny' else 'off'}"
                          if out["after"] in ("allow", "deny") else "global block changed")
        out["revert"] = None
    else:
        out.update(summary="audit event", before=None, after=None, revert=None)
    return out


def _audit_entry(path: str, b: dict, r: dict, pre_cfg: dict, pre_fw: dict):
    """状態が変わった POST (保存失敗後のメモリ内 BAN/解除を含む)から監査ログ行を組み立てる。
    (summary, before, after, revert) を返す。ログに残す価値が無ければ None
    (例: /api/shield/config で実際には何も変わらなかった呼び出し)。

    このフォークのルート一覧に合わせて絞ってある(honeypot/intel_reload/posmodel/
    under_attack は Lite に存在しないため対象外)。revert は「単純なスカラー設定値」を
    1回だけ元に戻すための {endpoint, body} のみ持たせる。add/remove系(シグネチャ・
    ルール・BAN等)は一覧操作で戻せるためここでは revert を付けない。"""
    def cfgrevert(key, before):
        return {"endpoint": "/api/shield/config", "body": {key: before}}

    if path == "/api/firewall/toggle":
        on = bool(b.get("on"))
        return (f"firewall {'enabled' if on else 'disabled'}", pre_fw["enabled"], on,
                {"endpoint": path, "body": {"on": pre_fw["enabled"]}})
    if path == "/api/firewall/policy":
        zone, action = b.get("zone", ""), b.get("action", "")
        before = pre_fw["policy"].get(zone)
        return (f"firewall zone '{zone}' policy -> {action}", before, action, None)
    if path == "/api/firewall/rule":
        net = b.get("net", "")
        if b.get("op") == "remove":
            prev = next((x for x in pre_fw["rules"] if x.get("net") == net), None)
            return (f"firewall rule {net} removed", prev, None, None)
        return (f"firewall rule {net} -> {b.get('action', 'deny')}", None,
                {"net": net, "action": b.get("action", "deny")}, None)
    if path == "/api/firewall/resolve":
        approve = bool(b.get("approve"))
        remember = r.get("remembered", b.get("remember")) is True
        ip = r.get("ip", "")
        uncertain = r.get("published") is True and r.get("durable") is False
        suffix = ("(公開済み・保存未確認)" if uncertain else
                  "(記憶=常時許可)" if approve and remember else "(一時)" if approve else "")
        return (f"pending connection {ip or b.get('id', '')} "
                f"{'approved' if approve else 'denied'}{suffix}",
                None, {"id": b.get("id", ""), "approve": approve,
                       "remember": remember, "ip": ip}, None)
    if path == "/api/shield/toggle":
        on = bool(b.get("on"))
        return (f"shield {'enabled' if on else 'disabled'}", pre_cfg.get("enabled"), on,
                {"endpoint": path, "body": {"on": pre_cfg.get("enabled")}})
    if path == "/api/shield/config":
        changed = r.get("changed") or {}
        if not changed:
            return None
        before = {k: pre_cfg.get(k) for k in changed}
        parts = [f"{k}: {before[k]} -> {v}" for k, v in changed.items()]
        revert = None
        if len(changed) == 1:
            (k, v), = changed.items()
            revert = cfgrevert(k, before[k])
        return ("config: " + "; ".join(parts), before, changed, revert)
    if path == "/api/shield/optional_sig":
        name, on = b.get("name", ""), bool(b.get("on"))
        before = bool((pre_cfg.get("optional_sigs") or {}).get(name))
        return (f"optional signature '{name}' -> {'on' if on else 'off'}", before, on,
                {"endpoint": path, "body": {"name": name, "on": before}})
    if path == "/api/shield/paranoia":
        before = pre_cfg.get("paranoia")
        after = r.get("paranoia")
        # set_paranoia はプリセットで optional_sigs を丸ごと上書きする。level だけ戻すと、
        # 変更前に個別に点けていた任意シグネチャ(例 ssti)が消えたままになる(#69)ので、
        # 変更前の optional_sigs も revert に同梱し、/api/shield/paranoia 側で復元する。
        opt = {k: bool(v) for k, v in (pre_cfg.get("optional_sigs") or {}).items()}
        return (f"paranoia level {before} -> {after}", before, after,
                (cfgrevert("paranoia", before) if before is None else
                 {"endpoint": "/api/shield/paranoia",
                  "body": {"level": before, "optional_sigs": opt}}))
    if path == "/api/shield/path_limits":
        after = r.get("path_limits", [])
        before = pre_cfg.get("path_limits")
        return (f"path limits updated ({len(after)} rules)", before, after, None)
    if path == "/api/shield/blocked_methods":
        after = r.get("blocked_methods", [])
        before = pre_cfg.get("blocked_methods")
        return (f"blocked methods -> {', '.join(after) or '(none)'}", before, after, None)
    if path == "/api/shield/sig_add":
        return (f"signature '{b.get('name', '')}' added", None,
                {"name": b.get("name", ""), "pattern": b.get("pattern", "")}, None)
    if path == "/api/shield/sig_remove":
        return (f"signature '{b.get('name', '')}' removed", {"name": b.get("name", "")}, None, None)
    if path == "/api/shield/unban":
        memory_only = r.get("applied_in_memory") is True and r.get("persisted") is False
        return (f"IP {b.get('ip', '')} unbanned" + (" (memory only; save failed)" if memory_only else ""),
                {"ip": b.get("ip", "")},
                {"ip": b.get("ip", ""), "persisted": r.get("persisted"),
                 "applied_in_memory": r.get("applied_in_memory", False)}, None)
    if path == "/api/shield/ban":
        memory_only = r.get("applied_in_memory") is True and r.get("persisted") is False
        return (f"IP {b.get('ip', '')} banned manually" + (" (memory only; save failed)" if memory_only else ""),
                None, {"ip": b.get("ip", ""), "persisted": r.get("persisted"),
                       "applied_in_memory": r.get("applied_in_memory", False)}, None)
    if path == "/api/appeal/resolve":
        ip, approve = b.get("ip", ""), bool(b.get("approve"))
        return (f"appeal {ip} {'approved' if approve else 'denied'}", None,
                {"ip": ip, "approve": approve}, None)
    if path == "/api/global_block":
        on = bool(b.get("on"))
        before = pre_fw["policy"].get("public")
        return (f"global block -> {'on' if on else 'off'}", before, "deny" if on else "allow", None)
    return None


class AdminDashboard:
    def __init__(self, host: str = "127.0.0.1", port: int = 8081, token: str = "",
                 state_dir: str = "",
                 brand: str = "", logo: str = "🦆",
                 subtitle: str = "L7 防御 — 管理ダッシュボード",
                 edge_guard=None, show_brand_icon: bool = True):
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(24)
        self._browser_nonce_lock = threading.Lock()
        self._browser_nonces: dict[str, tuple[float, int]] = {}
        self._browser_nonce_prune_at = 0.0
        self._browser_nonce_floor_ms = -1
        self._browser_auth_started_ms = 0
        self._browser_instance_id = ""
        # トレイが起動した子との内部確認用。管理トークンとは独立した起動毎の鍵。
        try:
            proof_key = bytes.fromhex(os.environ.get("DUCKNET_TRAY_PROOF_KEY", ""))
        except ValueError:
            proof_key = b""
        self._tray_proof_key = proof_key if len(proof_key) == 32 else b""
        # 前衛ガード(AsyncEdgeGuard)への参照(任意)。渡されれば接続受理/バックエンド
        # 不達等の生指標(self.metrics)を state() 経由でダッシュボードへ可視化する。
        # 未指定(単体テスト等)なら空 dict で degrade=既存呼び出し元は変更不要。
        self.edge_guard = edge_guard
        # 画面の表示名/アイコン。ステルス運用では汎用名(例 "System Health Monitor")に
        # 差し替えて、管理画面のタイトル/ヘッダ/Server ヘッダから製品を伏せる。明示が無ければ
        # DUCKNET_COVER env を尊重し(遮断ページと同じ秘匿源=適用漏れを防ぐ)、無ければ製品名。
        # 表示名は Server ヘッダにも入るので制御文字を除く(CRLF の env ファイルの末尾 CR 等)。
        from .engine.services.proxy import _cover_brand
        self.brand = ("".join(ch if ch.isprintable() else " " for ch in str(brand or "")).strip()
                      or _cover_brand("DuckNet-Lite"))
        self.logo = logo
        self.subtitle = subtitle
        # ブランドアイコン: 実ファイル DuckNet.ico(無ければ .png)を /brand-icon で配信し、
        # ヘッダ画像と favicon から参照する。ステルス時は配信せず、ロゴ/favicon を汎用グリフ(⚙)へ
        # フォールバック=製品(鴨)を伏せる。呼び出し側の指定に依らず DUCKNET_COVER でも自動で伏せる。
        if _cover_brand(""):
            show_brand_icon = False
            if self.logo == "🦆":
                self.logo = "⚙"
        self._icon_bytes, self._icon_ct = (_load_brand_icon() if show_brand_icon else (b"", ""))
        if self._icon_bytes:
            self._logo_html = '<img class="brand-ico" src="/brand-icon" alt="">'
            self._favicon_html = '<link rel="icon" href="/brand-icon">'
        else:
            self._logo_html = html_lib.escape(str(self.logo), quote=True)
            svg = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
                   "<text y='.9em' font-size='58'>" + html_lib.escape(str(self.logo))
                   + "</text></svg>")
            self._favicon_html = ('<link rel="icon" href="data:image/svg+xml,'
                                  + quote(svg, safe="") + '">')
        # 検知ログの所在(別プロセスが書く)。DUCKNET_STATE_DIR で移設可。テストは上書き可。
        self._state_dir = state_dir or default_state_dir()
        self._server = None
        self._thread = None
        self._lifecycle_lock = threading.RLock()
        self._mutation_gate = threading.RLock()
        self._stopping = True

    # ── 監査ログ ──
    @property
    def _audit_path(self) -> str:
        # self._state_dir は construction 後にテストが直接差し替える運用なので、ここも
        # __init__ でキャッシュせず毎回その場で組み立てる(キャッシュすると差し替えが効かず
        # 別テスト間で監査ログが混線する)。
        return os.path.join(self._state_dir, "admin_audit.jsonl")

    def record_audit(self, path: str, b: dict, r: dict, pre_cfg: dict, pre_fw: dict):
        """Append one changed POST. False means the write failed; None means no row.

        The committed change remains live if this ancillary write fails, but
        its HTTP result must disclose the missing audit row. Keep a legacy
        None return from a test override distinct from an explicit failure.
        """
        try:
            built = _audit_entry(path, b, r, pre_cfg, pre_fw)
            if not built:
                return None
            summary, before, after, revert = built
            entry = {"ts": time.time(), "endpoint": path,
                     "summary": summary, "before": before,
                     "after": after, "revert": revert}
            # A visible update whose directory sync failed is still an actual
            # state change. Preserve its incomplete persistence result in audit.
            entry.update({key: r[key] for key in
                          ("applied_in_memory", "published", "persisted", "durable") if key in r})
            result = append_jsonl(self._audit_path, _audit_privacy(entry))
            return result if type(result) is bool else None
        except Exception:
            return False

    def audit_log(self, n: int = 200) -> dict:
        """直近の監査ログ(新しい順)。GET /api/admin_audit が返す。"""
        rows = tail_jsonl(self._audit_path, n, strict=True,
                          max_bytes=_MAX_AUDIT_READ_BYTES)
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid audit history row")
        if not rows:
            # A completed rotation keeps the prior generation in .1 until a
            # new active row is written. An absent/empty active file with a
            # nonempty backup is an incomplete history, never "no changes".
            try:
                active = os.lstat(self._audit_path)
            except FileNotFoundError:
                active = None             # pristine first boot is a valid empty log
            if active is not None and (not stat.S_ISREG(active.st_mode) or active.st_size):
                raise OSError("audit log changed during read")
            try:
                previous = os.lstat(self._audit_path + ".1")
            except FileNotFoundError:
                previous = None
            if previous is not None and (not stat.S_ISREG(previous.st_mode)
                                         or previous.st_size > 0):
                raise OSError("audit backup exists without active rows")
        return {"entries": [_audit_privacy(row) for row in rows]}

    # ── 状態取得 ──
    @staticmethod
    def _safe_dict(fn, *a, **kw) -> dict:
        """1データソースの取得を他から独立して保護する。辞書を返す想定のソース向け:
        失敗してもそのキーだけ {"error": ...} に degrade し、/api/state 全体を
        巻き込まない(1箇所のバグで管理画面が丸ごと落ちるのを防ぐ)。"""
        try:
            return fn(*a, **kw)
        except Exception:
            return {"error": "source unavailable"}

    @staticmethod
    def _safe_list(fn, *a, **kw) -> list | dict:
        """List source failures must differ from a healthy empty result.

        Otherwise the dashboard says 'no leaks' or 'none' when telemetry was
        unavailable. The browser checks this sentinel before drawing panels.
        """
        try:
            return fn(*a, **kw)
        except Exception:
            return {"error": "source unavailable"}

    def state(self) -> dict:
        fw = app_firewall()
        sh = net_shield()
        from dataplane.engine.services.proxy import AsyncEdgeGuard
        # Fork children own separate counters and ACL decision logs. The
        # parent's values are useful diagnostics, but never a global total.
        live_children = bool(getattr(self.edge_guard, "_workers", ())) if self.edge_guard else False
        def firewall_status():
            # A signed ACL that could not be restored is deliberately denying
            # normal traffic. Do not render its empty fallback rules as a
            # healthy policy in the dashboard.
            with fw._lock:
                if fw._load_warning:
                    raise ValueError("firewall state is untrusted")
                return fw.status()

        def shield_status():
            # Management reports signed integrity even while Shield is
            # deliberately OFF. A corrupt rule or BAN source must not paint
            # a healthy policy that would fail closed if protection is enabled.
            with sh._lock:
                if any((sh._cfg_state_untrusted,
                        sh._sig_state_untrusted,
                        sh._ban_state_untrusted,
                        sh._traffic_state_untrusted)):
                    raise ValueError("shield state is untrusted")
                state = sh.status()
                state["config_revision"] = _config_revision(state["cfg"])
                return state

        # 以下のサブ状態はそれぞれ独立に取得する: 1つが例外を投げても、その
        # キーだけが degrade し、他のパネルは正常なデータで描画され続ける。
        return {"firewall": self._safe_dict(firewall_status),
                "shield": self._safe_dict(shield_status),
                "shield_metrics": self._safe_dict(sh.metrics),
                "top": self._safe_list(sh.top_talkers, 12),
                "events": self._safe_list(sh.events, 40),
                "zones": ZONES, "actions": ACTIONS,
                "telemetry_complete": not live_children,
                "telemetry_scope": "per-worker" if live_children else "single",
                "capabilities": self._safe_dict(AsyncEdgeGuard.platform_capabilities),
                # 前衛ガード(接続受理/バックエンド不達等)の生指標。edge_guard 未配線
                # (単体テスト・旧呼び出し元)なら空 dict=既存の見た目を壊さない。
                "edge_metrics": (self._safe_dict(lambda: dict(self.edge_guard.metrics))
                                 if self.edge_guard else {})}

    def deception_status(self) -> dict:
        """動的デセプション(MTD)の状態。env 駆動・状態レスのため本プロセスの env を反映し、
        サンプル攻撃者から見える偽バナー+随伴ヘッダのローテーションをプレビューする(可視化のみ)。"""
        from dataplane.engine.services import banner as dc
        enabled = dc.is_enabled()
        preview = []
        if enabled:
            now = time.time()
            for i in range(4):           # 直近4窓: 同一攻撃者には時間で *矛盾* して見える
                hs = dc.headers_for("203.0.113.1", now=now + 30 * i)
                banner = next((v for k, v in hs if k == "Server"), "")
                comp = [f"{k}: {v}" for k, v in hs if k != "Server"]
                preview.append({"window": i, "family": dc._family(banner),
                                "server": banner, "companions": comp})
        return {"enabled": enabled, "families": list(dc._FAMILIES),
                "family_count": len(dc._FAMILIES), "sample_seed": "203.0.113.1",
                "preview": preview,
                "note": "既定OFF。DUCKNET_DECEPTION で有効化(本プロセスの env を反映)。"}

    def start(self) -> dict:
        with self._lifecycle_lock:
            if self._server is not None:
                if self._thread is not None and self._thread.is_alive():
                    if self._stopping:
                        return {"ok": False, "error": "admin server is stopping"}
                    from .engine.core import netaddr
                    return {"ok": True, "url": netaddr.url(self.host, self.port),
                            "token": self.token}
                return {"ok": False, "error": "admin server thread is not running"}
            return self._start()

    def _start(self) -> dict:
        handler = _make_handler(self)
        serving = threading.Event()

        from .engine.core import netaddr

        class _Server(ThreadingHTTPServer):
            # Windows の SO_REUSEADDR は「他プロセスが待受中のポートにも bind できる」
            # 意味になり、管理面を横取りされ得る(POSIX の TIME_WAIT 再利用とは別物)。
            # 管理プレーンは再利用より排他を優先する。
            allow_reuse_address = not sys.platform.startswith("win")
            # http.server の既定は AF_INET 固定。--admin-host に IPv6(::1 や ::)を
            # 指定すると gaierror(-9) で bind に失敗し、起動そのものが止まっていた
            # (= IPv6 専用ホストでは製品が一切動かない)。待受先に合わせて解決する。
            address_family = netaddr.family_for(self.host, self.port)

            def server_bind(self):
                if sys.platform.startswith("win"):
                    # Windows wildcard 管理待受で別 IP の SO_REUSEADDR bind を拒否する。
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()

            def __init__(self, *args, **kwargs):
                self._handler_slots = threading.BoundedSemaphore(_ADMIN_MAX_HANDLERS)
                self._pending_head_slots = threading.BoundedSemaphore(_ADMIN_PENDING_HEAD_MAX)
                self._reject_body_drain_slots = threading.BoundedSemaphore(
                    _ADMIN_REJECT_BODY_DRAINS_MAX)
                self._pending_head_lock = threading.Lock()
                self._pending_heads = set()
                self._active_request_lock = threading.Lock()
                self._active_requests = set()
                self._readiness_probe_lock = threading.Lock()
                self._readiness_probes = {}
                self._closing_pending_heads = False
                super().__init__(*args, **kwargs)

            def watch_readiness_probe(self, peer_address):
                done = threading.Event()
                with self._readiness_probe_lock:
                    self._readiness_probes[peer_address] = done
                return done

            def forget_readiness_probe(self, peer_address, done):
                with self._readiness_probe_lock:
                    if self._readiness_probes.get(peer_address) is done:
                        self._readiness_probes.pop(peer_address, None)

            def finish_readiness_probe(self, peer_address):
                with self._readiness_probe_lock:
                    done = self._readiness_probes.pop(peer_address, None)
                if done is not None:
                    done.set()

            @staticmethod
            def _head_complete(request):
                # Peek without consuming bytes. Complete, ordinary requests
                # must retain access to handler capacity while slow peers hold
                # the small pending-header budget.
                previous = request.gettimeout()
                try:
                    request.setblocking(False)
                    try:
                        head = request.recv(_ADMIN_HEAD_MAX_BYTES, socket.MSG_PEEK)
                    except (BlockingIOError, InterruptedError):
                        return False
                    return re.search(rb"\r?\n\r?\n", head) is not None
                except OSError:
                    return False
                finally:
                    try:
                        request.settimeout(previous)
                    except OSError:
                        pass

            def _release_pending_head(self, request):
                with self._pending_head_lock:
                    if request not in self._pending_heads:
                        return
                    self._pending_heads.remove(request)
                    self._pending_head_slots.release()

            def process_request(self, request, client_address):
                # ThreadingHTTPServer otherwise spawns one thread for every slow peer.
                if not self._handler_slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                with self._active_request_lock:
                    self._active_requests.add(request)
                try:
                    if not self._head_complete(request):
                        if self._pending_head_slots.acquire(blocking=False):
                            with self._pending_head_lock:
                                self._pending_heads.add(request)
                        else:
                            # A full pending-header pool must not reject a
                            # complete request whose last packet has just
                            # arrived. The small grace is only used at capacity.
                            deadline = time.monotonic() + _ADMIN_PENDING_HEAD_GRACE_SEC
                            while time.monotonic() < deadline:
                                if self._head_complete(request):
                                    break
                                time.sleep(0.001)
                            else:
                                with self._active_request_lock:
                                    self._active_requests.discard(request)
                                self._handler_slots.release()
                                self.shutdown_request(request)
                                return
                    super().process_request(request, client_address)
                except BaseException:
                    with self._active_request_lock:
                        self._active_requests.discard(request)
                    self._release_pending_head(request)
                    self._handler_slots.release()
                    self.finish_readiness_probe(client_address)
                    raise

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    with self._active_request_lock:
                        self._active_requests.discard(request)
                    self._release_pending_head(request)
                    self._handler_slots.release()
                    # A complete 401 body can reach the startup client before
                    # this slot becomes available. Signal only after release.
                    self.finish_readiness_probe(client_address)

            def server_close(self):
                # Interrupt accepted partial heads as well as the listener on
                # stop; their handler finally blocks return both budgets.
                self._closing_pending_heads = True
                with self._pending_head_lock:
                    pending = list(self._pending_heads)
                for request in pending:
                    self._release_pending_head(request)
                with self._active_request_lock:
                    active = list(self._active_requests)
                for request in active:
                    try:
                        request.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        request.close()
                    except OSError:
                        pass
                super().server_close()

            def service_actions(self):
                super().service_actions()
                serving.set()  # The serve_forever selector has processed a cycle.

        with self._browser_nonce_lock:
            self._browser_auth_started_ms = int(time.time() * 1000)
            self._browser_instance_id = secrets.token_hex(16)
            self._browser_nonces.clear()
            self._browser_nonce_prune_at = 0.0
            self._browser_nonce_floor_ms = -1
        self._server = _Server((self.host, self.port), handler)
        self.port = self._server.server_address[1]
        try:
            self._thread = threading.Thread(target=self._server.serve_forever,
                                            daemon=True, name="shield-admin")
            self._thread.start()
        except BaseException:
            # A listener without a serving thread must not retain the admin port.
            self._server.server_close()
            self._server = self._thread = None
            raise
        # thread.start() only proves the thread was created. A bound TCP socket
        # also accepts connections when its serving thread exits immediately.
        # Require a complete, unauthenticated HTTP response without sending the
        # operator's token. Keep the first-start wait bounded on every platform.
        import http.client
        probe_host = ("127.0.0.1" if self.host in ("", "0.0.0.0") else
                      "::1" if self.host == "::" else self.host)
        ready = False
        deadline = time.monotonic() + _ADMIN_READY_DEADLINE_SEC
        attempts = 0
        while (attempts < 3 and self._thread.is_alive()
               and time.monotonic() < deadline):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # A short first attempt keeps normal startup fast. If a healthy
            # accept/handler loop is delayed by host load, give the next proof
            # the remaining total budget instead of flooding the listen queue
            # with abandoned 300 ms connections.
            timeout = min(0.75, remaining) if attempts == 0 else remaining
            connection = http.client.HTTPConnection(probe_host, self.port, timeout=timeout)
            probe_peer = None
            probe_done = None
            try:
                connection.connect()
                if connection.sock is not None:
                    probe_peer = connection.sock.getsockname()
                    probe_done = self._server.watch_readiness_probe(probe_peer)
                connection.request("GET", "/api/state", headers={"Host": "localhost"})
                response = connection.getresponse()
                ready = (probe_done is not None and response.status == 401
                         and response.read(128) ==
                         _j({"ok": False, "error": "token required"}))
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            if ready and probe_done is not None:
                while self._thread.is_alive() and not probe_done.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    probe_done.wait(min(0.05, remaining))
                ready = probe_done.is_set()
            if probe_peer is not None:
                self._server.forget_readiness_probe(probe_peer, probe_done)
            attempts += 1
            if ready:
                break
            if not serving.is_set():
                # serve_forever has not completed even one selector cycle yet.
                # Wait for that evidence before retrying; a bound socket can
                # queue requests while no thread is accepting them. Check the
                # thread in short slices so an early exit still fails fast.
                while self._thread.is_alive() and not serving.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    serving.wait(min(0.05, remaining))
            else:
                time.sleep(0.01)
        if not ready or not self._thread.is_alive():
            server, thread = self._server, self._thread
            # shutdown() waits forever if serve_forever never entered its loop.
            if serving.is_set() and thread.is_alive():
                server.shutdown()
            server.server_close()
            thread.join(timeout=0.3)
            self._server = self._thread = None
            return {"ok": False, "error": "admin HTTP serving thread did not become ready"}
        # IPv6 リテラルは [] で囲う。素の f-string だと `http://::1:8081` という
        # 不正な URL になり、GUI が本体を見つけられなくなる(RFC 3986)。
        with self._mutation_gate:
            self._stopping = False
        return {"ok": True, "url": netaddr.url(self.host, self.port),
                "token": self.token}

    def stop(self) -> dict:
        with self._lifecycle_lock:
            try:
                deadline = time.monotonic() + _ADMIN_STOP_DEADLINE_SEC
                # A POST already committing finishes before stop can succeed;
                # a handler still reading its body cannot commit afterwards.
                # The audit append is part of that commit and can stall on
                # storage. Do not claim success or wait forever while its gate
                # is held; leave the live listener and generation intact so a
                # later stop can retry after the operation finishes.
                if not self._mutation_gate.acquire(
                        timeout=max(0.0, deadline - time.monotonic())):
                    return {"ok": False, "error": "admin operation still in progress"}
                try:
                    if time.monotonic() >= deadline:
                        return {"ok": False, "error": "admin operation still in progress"}
                    self._stopping = True
                finally:
                    self._mutation_gate.release()
                if self._server:
                    self._server.shutdown()
                    self._server.server_close()
                    self._server = None
                t = self._thread
                if t is not None and t.is_alive():
                    t.join(timeout=max(0.0, deadline - time.monotonic()))
                if t is not None and t.is_alive():
                    return {"ok": False, "error": "admin server thread did not stop"}
                self._thread = None
                return {"ok": True}
            except Exception:
                return {"ok": False, "error": "admin server stop failed"}


_ICON_MAX_BYTES = 1024 * 1024      # ブランドアイコン読込の上限(メモリ有界)


def _load_brand_icon():
    """ブランドアイコンを読み込んで (bytes, content_type) を返す。DuckNet.ico(軽量・多サイズ)を
    優先し、無ければ .png。探索: env DUCKNET_ICON_DIR → パッケージ直下の ico/ → 同梱 assets/。
    CWD は探索しない(攻撃者が置いたファイルを読まない)。サイズは _ICON_MAX_BYTES で有界。
    見つからなければ (b"", "")=呼び出し側は絵文字グリフへフォールバック。"""
    here = os.path.dirname(os.path.abspath(__file__))          # …/dataplane
    repo_root = os.path.dirname(here)                          # リポジトリ直下
    bundled = os.path.join(here, "gui", "assets")
    cands = []
    env = os.environ.get("DUCKNET_ICON_DIR", "").strip()
    for name in ("DuckNet.ico", "DuckNet.png"):
        if env:
            cands.append(os.path.join(env, name))
    for name in ("DuckNet.ico", "DuckNet.png"):
        cands.append(os.path.join(repo_root, "ico", name))
        cands.append(os.path.join(bundled, name))
    for p in cands:
        try:
            if p and os.path.exists(p):
                if os.path.getsize(p) > _ICON_MAX_BYTES:   # 肥大ファイルは読まない
                    continue
                with open(p, "rb") as f:
                    data = f.read(_ICON_MAX_BYTES + 1)
                if not data or len(data) > _ICON_MAX_BYTES:
                    continue
                ct = "image/png" if p.lower().endswith(".png") else "image/x-icon"
                return data, ct
        except Exception:
            pass
    return b"", ""


def _make_handler(app: AdminDashboard):
    class H(BaseHTTPRequestHandler):
        timeout = 20
        server_version = app.brand
        sys_version = ""

        def setup(self):
            super().setup()
            self.rfile = _AdminHeadReader(self.rfile)

        def _finish_header_deadline(self):
            state = self._header_state
            with state["lock"]:
                state["pending"] = False
                state["timer"].cancel()
            # On Windows a shutdown from the timer thread may leave a blocked
            # makefile().readline() asleep. Its socket timeout is the fallback;
            # restore the normal timeout before reading any POST body.
            try:
                self.connection.settimeout(self._head_previous_timeout)
            except OSError:
                pass
            release = getattr(self.server, "_release_pending_head", None)
            if release is not None:
                release(self.request)

        def _expire_headers(self, state):
            with state["lock"]:
                if not state["pending"]:
                    return
                state["pending"] = False
                state["expired"] = True
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        def handle_one_request(self):
            # socket.timeout is per recv; a byte every few seconds can keep
            # readline() alive indefinitely. A timer bounds the whole head.
            state = {"lock": threading.Lock(), "pending": True, "expired": False}
            timer = threading.Timer(_ADMIN_HEAD_DEADLINE_SEC,
                                    self._expire_headers, args=(state,))
            state["timer"] = timer
            self._header_state = state
            timer.daemon = True
            self._head_previous_timeout = self.connection.gettimeout()
            try:
                self.connection.settimeout(
                    min(self._head_previous_timeout or float("inf"),
                        _ADMIN_HEAD_DEADLINE_SEC + 0.1))
            except OSError:
                self.close_connection = True
                self.connection.close()
                return
            try:
                timer.start()
            except RuntimeError:
                self.close_connection = True
                self.connection.close()
                return
            try:
                return super().handle_one_request()
            except _AdminHeadTooLarge:
                self.close_connection = True
                self._send(431, _j({"ok": False, "error": "request headers too large"}))
            except OSError:
                if not state["expired"] and not getattr(
                        self.server, "_closing_pending_heads", False):
                    raise
                self.close_connection = True
            finally:
                self._finish_header_deadline()
                timer.join(timeout=0.1)
                self._header_state = None

        def parse_request(self):
            try:
                parsed = super().parse_request()
            finally:
                self._finish_header_deadline()
            if not parsed or self._header_state["expired"]:
                return False
            # The management server must not apply a state change after another
            # HTTP reader chose a different body boundary. Check every field
            # before authentication can spend a browser nonce or read a body.
            if not self._framing_ok():
                self._reject(400, _j({"ok": False, "error": "invalid request framing"}))
                return False
            return True

        def _framing_ok(self):
            lengths = self._header_values("Content-Length")
            if self._header_values("Transfer-Encoding") or len(lengths) > 1:
                return False
            if not lengths:
                return True  # Existing HTTP/1.0 requests can be bodyless.
            value = lengths[0]
            return (isinstance(value, str) and
                    re.fullmatch(r"[0-9]{1,20}", value.strip(" \t")) is not None)

        def version_string(self):
            # Server ヘッダはブランド名のみ(Python/BaseHTTP のバージョンや余分な空白を
            # 晒さない=指紋低減)。ステルス時は cover 名になり製品が露見しない。
            # http.server encodes headers as latin-1; retain the UTF-8 UI name.
            return app.brand.encode("latin-1", "backslashreplace").decode("latin-1")

        def log_message(self, *a):
            pass

        def end_headers(self):
            # Apply to the entire management surface, including http.server's
            # own parser/unsupported-method errors that do not call _send().
            # Custom authentication headers do not imply shared-cache exclusion.
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Referrer-Policy", "no-referrer")
            super().end_headers()

        def _auth(self) -> bool:
            # CLI の既存ヘッダ認証。ブラウザは生トークンをネットワークへ送らず
            # _browser_auth の要求単位 HMAC を使う。Cookie は認証に使わない。
            self._browser_nonce = None
            self._browser_body_sha = None
            tokens = self._header_values("X-Token")
            auths = self._header_values("Authorization")
            if not tokens and not auths:
                return self._browser_auth()
            # An explicit malformed credential is a failed authentication, not
            # permission to try a different proof. All readers must see the
            # same single identity even when both supported headers are sent.
            if len(tokens) > 1 or len(auths) > 1:
                return False
            token = tokens[0].strip() if tokens else ""
            bearer = ""
            if tokens and not token:
                return False
            if auths:
                value = auths[0]
                if not value.lower().startswith("bearer "):
                    return False
                bearer = value[7:].strip()
                if not bearer:
                    return False
            try:
                if token and bearer and not hmac.compare_digest(token.encode("utf-8"),
                                                               bearer.encode("utf-8")):
                    return False
                return bool(app.token) and hmac.compare_digest((bearer or token).encode("utf-8"),
                                                               app.token.encode("utf-8"))
            except UnicodeError:
                return False

        def _header_values(self, name):
            # Message preserves duplicate wire fields. Dict support keeps the
            # existing direct-handler callers usable without losing live data.
            if hasattr(self.headers, "get_all"):
                return self.headers.get_all(name, [])
            value = self.headers.get(name)
            return [] if value is None else [value]

        def _browser_auth(self) -> bool:
            names = ("X-Admin-Auth-Instance", "X-Admin-Auth-Time", "X-Admin-Auth-Nonce",
                     "X-Admin-Auth-Body", "X-Admin-Auth-Mac")
            values = [self.headers.get_all(name, []) for name in names]
            if any(len(v) != 1 for v in values):
                return False
            instance, timestamp, nonce, body_sha, supplied = (v[0] for v in values)
            hexdigits = "0123456789abcdef"
            if (len(instance) != 32 or any(c not in hexdigits for c in instance)
                    or not hmac.compare_digest(instance, app._browser_instance_id)
                    or not timestamp.isascii() or not timestamp.isdigit() or len(timestamp) > 16
                    or len(nonce) != 32 or any(c not in hexdigits for c in nonce)
                    or len(body_sha) != 64 or any(c not in hexdigits for c in body_sha)
                    or len(supplied) != 64 or any(c not in hexdigits for c in supplied)):
                return False
            now_ms = int(time.time() * 1000)
            sent_ms = int(timestamp)
            if abs(now_ms - sent_ms) > _BROWSER_AUTH_SKEW_MS:
                return False
            if self.command == "GET" and body_sha != _EMPTY_SHA256:
                return False
            if self.command not in ("GET", "POST"):
                return False
            message = f"{instance}\n{self.command}\n{self.path}\n{timestamp}\n{nonce}\n{body_sha}"
            try:
                expected = hmac.new(app.token.encode("utf-8"), message.encode("utf-8"),
                                    hashlib.sha256).hexdigest()
            except UnicodeError:
                return False
            if not hmac.compare_digest(supplied, expected):
                return False
            with app._browser_nonce_lock:
                now_ms = int(time.time() * 1000)
                now = time.monotonic()
                if (not hmac.compare_digest(instance, app._browser_instance_id)
                        or abs(now_ms - sent_ms) > _BROWSER_AUTH_SKEW_MS):
                    return False
                # Once full, a valid-token flood must not turn every rejected
                # request into an O(cache-size) scan. Keep all live nonces for
                # replay safety; retry one bounded prune at its next deadline.
                if (len(app._browser_nonces) >= _BROWSER_NONCE_MAX
                        and now < app._browser_nonce_prune_at):
                    return False
                if now >= app._browser_nonce_prune_at:
                    kept = {}
                    floor = app._browser_nonce_floor_ms
                    for seen, (expiry, signed_ms) in app._browser_nonces.items():
                        # TTL alone is insufficient: a future timestamp stays
                        # valid at the TTL boundary, or after a wall-clock step.
                        if expiry <= now and signed_ms + _BROWSER_AUTH_SKEW_MS < now_ms:
                            floor = max(floor, signed_ms)
                        else:
                            kept[seen] = (expiry, signed_ms)
                    app._browser_nonces = kept
                    # Retired signatures must not become fresh again after a
                    # later clock rollback. Under a steady clock this floor is
                    # strictly below the allowed timestamp window.
                    app._browser_nonce_floor_ms = floor
                    app._browser_nonce_prune_at = now + 5.0
                if (sent_ms <= app._browser_nonce_floor_ms
                        or nonce in app._browser_nonces
                        or len(app._browser_nonces) >= _BROWSER_NONCE_MAX):
                    return False
                app._browser_nonces[nonce] = (now + _BROWSER_NONCE_TTL_SEC, sent_ms)
            self._browser_nonce = nonce
            self._browser_body_sha = body_sha if self.command == "POST" else None
            return True

        def _send(self, code, body, ctype="application/json; charset=utf-8",
                  set_cookie=None, extra_headers=()):
            # 全体を1つの try で囲む: send_response/send_header/end_headers 自体も
            # (クライアント切断後の broken pipe 等で)例外を投げ得る。ここで漏らすと、
            # 呼び出し元の「例外→_send(500,...) でフォールバック応答」という型の処理
            # (do_GET/do_POST の外側ハンドラ)が、既に壊れた接続へ二重に _send を試みて
            # 二重に例外を出すことになる。_send は常に無害に失敗できる=決して例外を
            # 外へ漏らさない、という契約にする。
            authenticated = getattr(self, "_admin_authenticated", False)
            try:
                with app._mutation_gate:
                    stale = authenticated and (app._stopping or self.server is not app._server)
                    response_instance = (getattr(self, "_response_instance_id", "")
                                         if getattr(self, "_committed_response", False) else
                                         app._browser_instance_id)
                if stale and not getattr(self, "_committed_response", False):
                    code, body = 503, _j({"ok": False, "error": "admin server stopped"})
                    ctype, set_cookie, extra_headers = "application/json; charset=utf-8", None, ()
                    self._browser_nonce = None
                data = body if isinstance(body, bytes) else body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                nonce = getattr(self, "_browser_nonce", None)
                if nonce:
                    message = f"{response_instance}\n{nonce}\n{code}\n{hashlib.sha256(data).hexdigest()}"
                    proof = hmac.new(app.token.encode("utf-8"), message.encode("ascii"),
                                     hashlib.sha256).hexdigest()
                    self.send_header("X-Admin-Response-Mac", proof)
                if set_cookie:
                    self.send_header("Set-Cookie", set_cookie)
                for name, value in extra_headers:
                    self.send_header(name, value)
                # セキュリティヘッダ(深層防御): クリックジャッキング/MIME詮索/外部読込/参照漏れの抑止。
                # 本体は依存ゼロの単一HTML(全インライン)なので script/style は 'unsafe-inline' を許可、
                # 通信先は同一オリジンのみ(connect-src 'self')に縛る。
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                 "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                 "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                pass

        def _reject(self, code: int, body: bytes):
            """拒否済み本文を短い総期限内で読み捨てる。送信済みの本文を残して閉じると
            Windows が応答まで RST で捨てる。一方、宣言長まで無期限に待つと未認証 peer が
            handler を占有できる。期限を過ぎたら応答して接続を閉じる。"""
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if not self.headers.get("Transfer-Encoding") and 0 < n <= _MAX_BODY:
                    # A peer can send a complete unauthenticated head, claim a
                    # large body, then never send it. Keep the short response-
                    # preservation drain for ordinary clients, but do not let
                    # 64 such peers occupy every management handler at once.
                    slots = getattr(self.server, "_reject_body_drain_slots", None)
                    reserved = slots is None or slots.acquire(blocking=False)
                    if reserved:
                        try:
                            previous_timeout = self.connection.gettimeout()
                            deadline = time.monotonic() + 0.2
                            read_available = getattr(self.rfile, "read1", self.rfile.read)
                            try:
                                while n > 0:
                                    left = deadline - time.monotonic()
                                    if left <= 0:
                                        break
                                    self.connection.settimeout(left)
                                    chunk = read_available(min(n, 65536))
                                    if not chunk:
                                        break
                                    n -= len(chunk)
                            finally:
                                self.connection.settimeout(previous_timeout)
                        finally:
                            if slots is not None:
                                slots.release()
            except (OSError, ValueError, OverflowError):
                pass
            self.close_connection = True
            self._send(code, body)

        def _body(self):
            """POST 本文(JSON object)を dict で返す。本文なし(Content-Length 0/無し)は {}。
            読めない本文は None を返し、do_POST がルートを実行せずに 4xx で弾く(#24)。
            以前はどの失敗も {} に潰していたため、ルートが既定値=破壊側(disable()・
            public=allow・path_limits 全消去)で走り、『ON にする』要求でシールドが OFF になった。"""
            # Defend direct-handler callers too; live HTTP was checked before
            # any authentication proof was consumed in parse_request().
            if not self._framing_ok():
                return None
            lengths = self._header_values("Content-Length")
            n = int(lengths[0].strip(" \t")) if lengths else 0
            if n == 0:
                self._body_actual_sha = _EMPTY_SHA256
                return {}
            # 上限超は読まずに拒否(先頭だけ読んで JSON 失敗→{} に化けさせない・メモリ枯渇防止)。
            if n < 0 or n > _MAX_BODY:
                return None
            try:
                raw = bytearray()
                previous_timeout = self.connection.gettimeout()
                deadline = time.monotonic() + _ADMIN_BODY_DEADLINE_SEC
                read_available = getattr(self.rfile, "read1", self.rfile.read)
                try:
                    # read(n) can perform many socket receives, each resetting
                    # an idle timeout. Refresh a shrinking total budget between
                    # bounded reads so a trickle cannot retain a handler forever.
                    while len(raw) < n:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self.close_connection = True
                            return None
                        timeout = (min(previous_timeout, remaining)
                                   if previous_timeout is not None else remaining)
                        self.connection.settimeout(timeout)
                        piece = read_available(min(n - len(raw), 65536))
                        if not piece:
                            self.close_connection = True
                            return None
                        raw.extend(piece)
                    if time.monotonic() > deadline:
                        self.close_connection = True
                        return None
                finally:
                    self.connection.settimeout(previous_timeout)
                self._body_actual_sha = hashlib.sha256(raw).hexdigest()
                # JSON 再帰爆弾([[[[…]]]])はパース前に深さで弾く(graphql と統一・自己DoS回避)。
                from .engine.core import saferegex
                d = saferegex.safe_json_loads(raw.decode("utf-8"), max_len=_MAX_BODY,
                                              default=None, reject_duplicates=True,
                                              reject_nonfinite=True)
                return d if isinstance(d, dict) else None
            except Exception:
                self.close_connection = True
                return None

        def _hostname_allowed(self, hostname) -> bool:
            """hostname(port/[]除去済み・小文字)が管理面の正規ホストとして許可されるか。
            DNSリバインディング対策の核心: 攻撃者ページは *ドメイン名*(evil.com)でしか
            ゲートウェイの loopback へ到達させられない(rebind 後も URL のホストは evil.com)。
            そこで **IPリテラル or localhost or 自身の bind host or 運用者許可リスト** のみ許可し、
            それ以外のホスト名は拒否する=rebinding(Host: evil.com)と、管理面を外部ドメインで
            前段公開する構成(全 peer が loopback に見えトークンが誰にでも渡る)を同時に塞ぐ。"""
            if not hostname:
                return True     # Host 無し(HTTP/1.0/生クライアント)は rebinding 経路になり得ない
            if hostname in ("localhost", str(app.host).lower()):
                return True
            try:
                import ipaddress
                ipaddress.ip_address(hostname)   # IPリテラル(loopback/LAN/直IP アクセス)は許可
                return True
            except ValueError:
                pass
            allowed = os.environ.get("DUCKNET_ADMIN_ALLOWED_HOSTS", "")
            allow = {h.strip().lower() for h in allowed.split(",") if h.strip()}
            return hostname in allow

        @staticmethod
        def _authority(raw: str):
            """A complete HTTP authority, never a URL or a repaired prefix."""
            if (not raw or any(ord(c) <= 32 or ord(c) == 127 for c in raw)
                    or any(c in raw for c in "/?#@\\%,")):
                return None
            try:
                parsed = urlsplit("//" + raw)
                host, port = parsed.hostname, parsed.port
                if (parsed.netloc != raw or parsed.path or parsed.query or parsed.fragment
                        or not host or raw.endswith(":") or port is not None and not 1 <= port <= 65535):
                    return None
                if raw.startswith("["):
                    host = str(ipaddress.IPv6Address(host))
                else:
                    if raw.count(":") > 1:
                        return None
                    try:
                        host = str(ipaddress.ip_address(host))
                    except ValueError:
                        host = host.lower()
                return host, port
            except (ValueError, UnicodeError):
                return None

        @staticmethod
        def _origin_tuple(raw: str, origin_only: bool):
            if not raw or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
                return None
            try:
                parsed = urlsplit(raw)
                if (parsed.scheme.lower() not in ("http", "https")
                        or origin_only and (parsed.path or "?" in raw or "#" in raw)):
                    return None
                authority = H._authority(parsed.netloc)
                if authority is None:
                    return None
                host, port = authority
                scheme = parsed.scheme.lower()
                return scheme, host, port or (443 if scheme == "https" else 80)
            except (ValueError, UnicodeError):
                return None

        def _host_ok(self) -> bool:
            """Host ヘッダの検証(全リクエスト・認証やトークン配布より手前)。"""
            values = self._header_values("Host")
            if not values:
                return True  # Preserve the existing HTTP/1.0 direct-client contract.
            if len(values) != 1:
                return False
            authority = self._authority(values[0])
            return authority is not None and self._hostname_allowed(authority[0])

        def _origin_ok(self) -> bool:
            """Validate every supplied browser context, including paired origins.

            HTTP/HTTPS termination remains a deployment contract: this plain
            listener does not infer the public scheme from Forwarded headers.
            The legacy allowed-host exception still supports proxy Host rewrites.
            """
            origins, referers = self._header_values("Origin"), self._header_values("Referer")
            if len(origins) > 1 or len(referers) > 1:
                return False
            if not origins and not referers:
                return True  # Header or request-MAC authentication remains required.
            hosts = self._header_values("Host")
            authority = self._authority(hosts[0]) if len(hosts) == 1 else None
            if authority is None:
                return False
            host, port = authority
            allowed = {h.strip().lower() for h in
                       os.environ.get("DUCKNET_ADMIN_ALLOWED_HOSTS", "").split(",") if h.strip()}
            source = None
            for values, origin_only in ((origins, True), (referers, False)):
                if not values:
                    continue
                current = self._origin_tuple(values[0], origin_only)
                if current is None or source is not None and current != source:
                    return False
                source = current
                scheme, shost, sport = current
                expected_port = port or (443 if scheme == "https" else 80)
                if not (shost == host and sport == expected_port) and shost not in allowed:
                    return False
            return True

        def _tray_proof(self, path: str) -> str:
            """401 に nonce と現在の shield 状態を結び付けた MAC を添える。"""
            nonce = self.headers.get("X-DuckNet-Tray-Nonce") or ""
            if (path != "/api/state" or not app._tray_proof_key or len(nonce) != 32
                    or any(ch not in "0123456789abcdef" for ch in nonce)):
                return ""
            try:
                sh = net_shield()
                cfg = sh.cfg
                state = ("off" if not cfg.get("enabled") else
                         "audit" if cfg.get("mode") == "audit" else "on")
            except Exception:
                return ""
            return hmac.new(app._tray_proof_key, (nonce + ":" + state).encode("ascii"),
                            hashlib.sha256).hexdigest()

        def do_GET(self):
            self._browser_nonce = None
            self._admin_authenticated = False
            self._committed_response = False
            # Host 検証は公開 HTML より手前。421=Misdirected Request。
            if not self._host_ok():
                self._send(421, _j({"ok": False, "error": "host not allowed"}))
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                html = _render_dashboard_html(app)
                # 旧版の生トークン Cookie を失効させる。認証用 Cookie は発行しない。
                expired = f"{_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"
                self._send(200, html, "text/html; charset=utf-8", set_cookie=expired)
                return
            if path == "/brand-icon":
                # ブランドアイコン(favicon/ヘッダロゴ)。認証前に読み込まれる=公開。
                # ステルス時は配信しない(404)=製品(鴨)を伏せたまま。
                if app._icon_bytes:
                    self._send(200, app._icon_bytes, app._icon_ct)
                else:
                    self._send(404, _j({"ok": False, "error": "not found"}))
                return
            if not self._auth():
                proof = self._tray_proof(path)
                headers = (("X-DuckNet-Tray-Proof", proof),) if proof else ()
                self._send(401, _j({"ok": False, "error": "token required"}),
                           extra_headers=headers)
                return
            self._admin_authenticated = True
            try:
                self._dispatch_get(path)
            except Exception:
                # do_POST と同じ思想: 個々の GET ルート(state() 等、複数のサブ状態を
                # 無防備に連結)のどこか1箇所が例外を投げても、ベースHTTPサーバの既定
                # 処理(無言で接続を切る)に落とさず、ダッシュボード全体を道連れにしない。
                self._send(500, _j({"ok": False, "error": "internal error"}))

        def _dispatch_get(self, path):
            if path == "/api/shield/config_schema":
                from .gui.settings import settings_schema
                self._send(200, _j({"ok": True, **settings_schema()}))
                return
            sh = net_shield()
            if (app.edge_guard is not None
                    and getattr(app.edge_guard, "_workers", ())
                    and path in _FORK_LOCAL_READ_ENDPOINTS):
                self._send(503, _j({"ok": False, "error":
                                    "aggregate telemetry is unavailable across fork workers",
                                    "telemetry_scope": "per-worker"}))
                return
            if path == "/api/state":
                self._send(200, _j(app.state()))
            elif path == "/api/deception":
                self._send(200, _j(app.deception_status()))
            elif path == "/api/series":
                # チャートの時間範囲ズームがクライアント側の既存retained分をフルに切り出せる
                # よう、サーバ側の返却上限を _series の実容量(maxlen=600・約10分)まで返す。
                # 新たな長期保存は追加しない(既にメモリ上にある分をそのまま返すだけ)。
                self._send(200, _j({"series": sh.series(600)}))
            elif path == "/api/admin_audit":
                try:
                    history = app.audit_log()
                except (OSError, ValueError, UnicodeError):
                    self._send(503, _j({"ok": False, "error": "audit log unavailable"}))
                else:
                    self._send(200, _j(history))
            elif path == "/api/analysis":
                self._send(200, _j(sh.analysis()))
            elif path == "/api/appeals":
                self._send(200, _j({"appeals": sh.list_appeals()}))
            elif path == "/api/nodes":
                self._send(200, _j(sh.nodes()))
            elif path == "/api/apt":
                self._send(200, _j(sh.apt_report()))
            elif path == "/api/shield/events":
                self._send(200, _j({"events": sh.events(100)}))
            elif path == "/api/shield/top":
                self._send(200, _j({"top": sh.top_talkers(20)}))
            elif path == "/api/shield/bans":
                with sh._lock:
                    if sh._ban_state_untrusted:
                        result = (503, {"ok": False, "error": "state unavailable"})
                    else:
                        result = (200, {"bans": sh.bans()})
                self._send(result[0], _j(result[1]))
            elif path == "/api/shield/signatures":
                with sh._lock:
                    if sh._sig_state_untrusted:
                        result = (503, {"ok": False, "error": "state unavailable"})
                    else:
                        result = (200, sh.list_signatures())
                self._send(result[0], _j(result[1]))
            elif path == "/api/shield/subnet":
                self._send(200, _j(sh.subnet_status()))
            elif path == "/api/shield/tamper":          # 改竄検知の可視化(#55)
                self._send(200, _j(sh.tamper_report()))
            elif path == "/api/edge":
                self._send(200, edge_config.edge_proxy_config(),
                           "text/plain; charset=utf-8")
            elif path == "/api/metrics":
                self._send(200, _metrics_exposition(sh),
                           "text/plain; version=0.0.4; charset=utf-8")
            else:
                self._send(404, _j({"ok": False, "error": "not found"}))

        def do_POST(self):
            self._browser_nonce = None
            self._admin_authenticated = False
            self._committed_response = False
            # Host + Origin 検証を認証より手前に置く(rebinding/CSRF の多層防御)。
            if not self._host_ok():
                self._reject(421, _j({"ok": False, "error": "host not allowed"}))
                return
            if not self._origin_ok():
                self._reject(403, _j({"ok": False, "error": "bad origin"}))
                return
            if not self._auth():
                self._reject(401, _j({"ok": False, "error": "token required"}))
                return
            self._admin_authenticated = True
            path = self.path.split("?")[0]
            b = self._body()
            if b is None:
                # 読めない本文(chunked・上限超・途中切れ・JSON object でない)はルートを実行しない(#24)。
                self._send(400, _j({"ok": False, "error":
                                    "invalid body (JSON object with Content-Length required)"}))
                return
            if (self._browser_body_sha is not None
                    and not hmac.compare_digest(self._browser_body_sha,
                                                getattr(self, "_body_actual_sha", ""))):
                self._send(400, _j({"ok": False, "error": "body digest mismatch"}))
                return
            key = _BOOL_KEYS.get(path)
            if key and not isinstance(b.get(key), bool):
                # 真偽値の欠落・綴り違いを False(=無効化・拒否側)として実行しない(#24)。
                self._send(400, _j({"ok": False, "error": f"'{key}' must be true or false"}))
                return
            if (path == "/api/firewall/resolve" and "remember" in b
                    and not isinstance(b["remember"], bool)):
                self._send(400, _j({"ok": False, "error": "'remember' must be true or false"}))
                return
            allowed = _POST_FIELDS.get(path)
            config_patch = None
            expected_revision = None
            if allowed is not None:
                if any(field not in allowed for field in b):
                    self._send(400, _j({"ok": False, "error": "unknown request field"}))
                    return
                if any(field not in b for field in _POST_REQUIRED.get(path, ())):
                    self._send(400, _j({"ok": False, "error": "required request field is missing"}))
                    return
                if path == "/api/shield/config" and "_expected_revision" in b:
                    expected_revision = b["_expected_revision"]
                    if (not isinstance(expected_revision, str)
                            or re.fullmatch(r"[0-9a-f]{64}", expected_revision) is None):
                        self._send(400, _j({"ok": False, "error": "invalid configuration revision"}))
                        return
                    b = {key: value for key, value in b.items() if key != "_expected_revision"}
                if path == "/api/shield/config" and not b:
                    self._send(400, _j({"ok": False, "error": "configuration patch is empty"}))
                    return
                if path == "/api/shield/config":
                    config_patch = b
                elif path == "/api/shield/path_limits":
                    config_patch = {"path_limits": b["rules"]}
                elif path == "/api/shield/blocked_methods":
                    config_patch = {"blocked_methods": b["methods"]}
                if config_patch is not None:
                    # Reuse the setter's complete candidate validation before
                    # quiescing fork workers. This includes cross-field site
                    # and cadence constraints; the setter rechecks under its
                    # own lock before committing after the mutation gate.
                    try:
                        shield = net_shield()
                        preview = shield.preview_config_patch(config_patch)
                        if not isinstance(preview, dict):
                            raise TypeError("invalid config preview")
                    except Exception:
                        self._send(503, _j({"ok": False,
                                            "error": "configuration validation unavailable"}))
                        return
                    if preview.get("ok") is not True:
                        self._send(400, _j({"ok": False,
                                            "rejected": preview.get("rejected", []),
                                            "error": "invalid configuration value"}))
                        return
                if path == "/api/firewall/rule":
                    rule_error = _rule_request_error(b)
                    if rule_error:
                        self._send(400, _j({"ok": False, "error": rule_error}))
                        return
                if path == "/api/firewall/policy" and (
                        b["zone"] not in ZONES or b["action"] not in ACTIONS):
                    self._send(400, _j({"ok": False, "error": "invalid firewall zone/action"}))
                    return
                if path == "/api/shield/optional_sig":
                    name = b["name"]
                    if type(name) is not str or name not in _OPTIONAL_SIGS:
                        self._send(400, _j({"ok": False, "error": "invalid optional signature name"}))
                        return
                if path == "/api/shield/paranoia":
                    level = b["level"]
                    # The direct Python setter retains legacy clamping, but
                    # the management HTTP contract requires a real 1-4 level.
                    valid_level = type(level) is int and 1 <= level <= 4
                    opt = b.get("optional_sigs")
                    valid_options = ("optional_sigs" not in b or
                                     isinstance(opt, dict) and
                                     all(type(name) is str and name in _OPTIONAL_SIGS and
                                         type(enabled) is bool for name, enabled in opt.items()))
                    if not valid_level or not valid_options:
                        self._send(400, _j({"ok": False, "error": "invalid paranoia options"}))
                        return
            held_locks = ExitStack()
            try:
                with app._mutation_gate:
                    if app._stopping or self.server is not app._server:
                        code, response = 503, _j({"ok": False, "error": "admin server stopped"})
                    else:
                        fw, sh = app_firewall(), net_shield()
                        firewall_op = (path.startswith("/api/firewall/")
                                       or path == "/api/global_block")
                        # Hold the same state generation from preview through
                        # worker teardown and the setter. A direct writer must
                        # not invalidate a dynamic no-op/unknown-ID decision
                        # in the gap before an irreversible fork downgrade.
                        state_lock = fw._lock if firewall_op else sh._lock
                        held_locks.enter_context(state_lock)
                        cluster = {"ok": True, "cluster_downgraded": False}
                        preflight_code = None
                        if (expected_revision is not None
                                and not hmac.compare_digest(expected_revision,
                                                            _config_revision(sh.cfg))):
                            preflight_code = 409
                            cluster = {"ok": False,
                                       "error": "configuration changed; reload settings"}
                        synced_fork = (app.edge_guard is not None
                                       and getattr(app.edge_guard, "_cluster_policy_sync", False) is True
                                       and bool(getattr(app.edge_guard, "_workers", ())))
                        no_quiesce = False
                        if cluster.get("ok") is True and config_patch is not None:
                            # The first preview ran before entering this gate.
                            # Another admin request may have committed between
                            # that read and this turn; recheck the same pure
                            # plan before a child worker can be stopped.
                            try:
                                gated_preview = sh.preview_config_patch(config_patch)
                                if not isinstance(gated_preview, dict):
                                    raise TypeError("invalid config preview")
                            except Exception:
                                preflight_code = 503
                                cluster = {"ok": False,
                                           "error": "configuration validation unavailable"}
                            else:
                                if gated_preview.get("ok") is not True:
                                    preflight_code = 400
                                    cluster = {"ok": False,
                                               "error": "invalid configuration value",
                                               "rejected": gated_preview.get("rejected", [])}
                                elif synced_fork:
                                    no_quiesce = gated_preview.get("unchanged") is True
                        if cluster.get("ok") is True:
                            try:
                                rejected, unchanged = _preview_admin_mutation(path, b, fw, sh)
                            except Exception:
                                preflight_code = 503
                                cluster = {"ok": False,
                                           "error": "state validation unavailable"}
                            else:
                                if rejected is not None:
                                    preflight_code, failed_preview = rejected
                                    cluster = {"ok": False,
                                               "error": failed_preview["error"]}
                                elif synced_fork and unchanged:
                                    # Existing signed-source synchronization
                                    # makes a re-saved no-op safe without
                                    # discarding fork workers.
                                    no_quiesce = True
                        if (cluster.get("ok") is True and path in _AUDIT_KNOWN_ENDPOINTS
                                and app.edge_guard is not None and not no_quiesce):
                            quiesce = getattr(app.edge_guard,
                                              "quiesce_cluster_for_mutation", None)
                            if callable(quiesce):
                                cluster = quiesce()
                            elif getattr(app.edge_guard, "_workers", None):
                                cluster = {"ok": False,
                                           "error": "cluster workers cannot be quiesced"}
                        if (not isinstance(cluster, dict)
                                or cluster.get("ok") is not True):
                            code = preflight_code or 503
                            failed = {"ok": False, "error":
                                      (cluster.get("error", "cluster workers are active")
                                       if isinstance(cluster, dict)
                                       else "cluster state is unavailable")}
                            if code == 400:
                                failed["rejected"] = cluster.get("rejected", [])
                            response = _j(failed)
                        else:
                            # Gate, state lock, commit and audit are one generation;
                            # response I/O remains outside the gate.
                            with (fw._lock if firewall_op else sh._lock):
                                pre_cfg = {} if firewall_op else copy.deepcopy(sh.cfg)
                                pre_fw = ({"enabled": fw.enabled, "policy": dict(fw.policy),
                                           "rules": copy.deepcopy(fw.rules)} if firewall_op else {})
                                code, r = self._apply_post(path, b, fw, sh)
                                if path == "/api/shield/config" and isinstance(r, dict):
                                    r["config_revision"] = _config_revision(sh.cfg)
                                if not isinstance(r, dict) or type(r.get("ok")) is not bool:
                                    r = {"ok": False, "error": "invalid operation result"}
                                if cluster.get("cluster_downgraded") is True:
                                    r = dict(r)
                                    r["cluster_downgraded"] = True
                                    r["cluster_mode"] = "single"
                                    r["cluster_note"] = "forked workers stopped before defense update"
                                if r["ok"] is True or r.get("applied_in_memory") is True:
                                    audit_result = app.record_audit(path, b, r, pre_cfg, pre_fw)
                                    if audit_result is False:
                                        # The defense change is committed; report
                                        # the failed secondary write separately.
                                        r = dict(r)
                                        r["audit_recorded"] = False
                                        r["warning"] = "admin audit log was not saved"
                                response = _j(r)
                            self._committed_response = True
                            self._response_instance_id = app._browser_instance_id
                held_locks.close()  # release before response I/O
                self._send(code, response)
            except Exception:
                held_locks.close()
                self._send(500, _j({"ok": False, "error": "internal error"}))
            finally:
                held_locks.close()  # includes BaseException, e.g. process shutdown

        def _apply_post(self, path, b, fw, sh):
            if path == "/api/firewall/toggle":
                r = fw.enable() if b.get("on") else fw.disable()
            elif path == "/api/firewall/policy":
                r = fw.set_policy(b.get("zone", ""), b.get("action", ""))
            elif path == "/api/firewall/rule":
                rule_error = _rule_request_error(b)
                if rule_error:
                    return 400, {"ok": False, "error": rule_error}
                op = b.get("op", "add")
                r = (fw.add_rule(b.get("net", ""), b["action"]) if op == "add"
                     else fw.remove_rule(b.get("net", "")))
            elif path == "/api/firewall/resolve":
                # ゾーン policy が "prompt" の未知接続(保留)を承認(allow)/拒否(deny)する。
                # これが無いと prompt は deny と等価な行き止まりになる(#2)。
                # remember 未指定は既定 False=この接続だけの一時許可/拒否(#D6/#111: 「承認」
                # 1クリックで恒久 allow ルールが黙って acl.json に積まれるのを避ける。恒久化は
                # 明示チェックボックス経由)。Full 版へ移植済みの挙動を Lite にも反映。
                remember = b.get("remember", False)
                r = (fw.approve(b.get("id", ""), remember=remember)
                     if b.get("approve")
                     else fw.deny_pending(b.get("id", ""), remember=remember))
            elif path == "/api/shield/toggle":
                r = sh.enable() if b.get("on") else sh.disable()
            elif path == "/api/shield/config":
                # The HTTP API is strict even when a legacy Python configuration
                # caller intentionally ignores keys unavailable in this edition.
                if any(key not in _DEFAULTS for key in b):
                    return 400, {"ok": False, "error": "unknown configuration key",
                                 "applied": [], "rejected": list(b)}
                else:
                    r = sh.set_config(**b)
            elif path == "/api/shield/optional_sig":
                # 'on' は _BOOL_KEYS で JSON の真偽値と確かめ済み。bool() で包まずそのまま渡す
                # (セッターも bool 以外を拒否する・#57)。
                r = sh.set_optional_signature(b.get("name", ""), b.get("on"))
            elif path == "/api/shield/paranoia":
                # level は必須(欠落を既定 1=任意署名を全 OFF として実行しない)。復元用の
                # optional_sigs は {名前: true/false} だけ("false" を bool() で ON にしない・#57)。
                # どちらかが不正なら何も適用せず 400。
                opt = b.get("optional_sigs")
                if "level" not in b:
                    return 400, {"ok": False, "error": "'level' is required (1-4)"}
                if "optional_sigs" in b and not (isinstance(opt, dict) and
                                            all(isinstance(v, bool) for v in opt.values())):
                    return 400, {"ok": False, "error":
                                 "'optional_sigs' must map names to true or false"}
                # 監査ログの「元に戻す」で level と個別署名を一回で保存する。
                # 逐次 set_optional_signature() だと途中の保存失敗で半分だけ戻った。
                r = sh.set_paranoia(b["level"], optional_sigs=opt)
            elif path == "/api/shield/path_limits":
                # rules が配列でない(綴り違い {"rule": …} 等)なら置換しない(#24: 空へ
                # 正規化して全ルールを消し、ok:true を返していた)。
                rules = b.get("rules")
                r = (sh.set_path_limits(rules) if isinstance(rules, list)
                     else {"ok": False, "error": "'rules' must be a list"})
            elif path == "/api/shield/blocked_methods":
                r = sh.set_blocked_methods(b.get("methods"))
            elif path == "/api/shield/sig_add":
                # weight の検証(有限・範囲)は add_signature に一本化。ここで float() すると
                # "nan" が NaN として素通りし、"abc" は例外文言がそのまま返っていた。
                r = sh.add_signature(b.get("name", ""), b.get("pattern", ""),
                                     weight=b.get("weight", 40))
            elif path == "/api/shield/sig_remove":
                r = sh.remove_signature(b.get("name", ""))
            elif path == "/api/shield/unban":
                r = sh.unban(b.get("ip", ""))
            elif path == "/api/shield/ban":
                r = sh.ban(b.get("ip", ""))
            elif path == "/api/appeal/resolve":
                r = sh.resolve_appeal(b.get("ip", ""), b["approve"],
                                      b.get("note", ""))
            elif path == "/api/global_block":
                r = fw.set_global_block(b["on"])
            elif path == "/api/shield/sig_test":
                # カスタムシグネチャの試験(状態は一切変更しない・読み取り専用)。まず既存の
                # validate_pattern(ReDoS/安全性検査)へ通し、危険なパターンは
                # コンパイル/マッチすら試みない(危険パターンを試験名目で実行させない)。
                # 照合は live と同じ(走査面の正規化+大小無視)。生サンプルへの re.search は
                # 実際には永久に当たらない規則を「一致」と表示していた(#30)。
                r = sh.dry_run_signature(b.get("pattern", ""),
                                         str(b.get("sample", ""))[:4096])
            else:
                return 404, {"ok": False, "error": "not found"}
            return 200, r
    return H


_HTML = r"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
__FAVICON__
<title>__BRAND__</title><style>
:root{
 /* タイポグラフィ(型スケール) */
 --f-sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Hiragino Kaku Gothic ProN","Noto Sans JP",Meiryo,sans-serif;
 --f-mono:ui-monospace,"SF Mono","Cascadia Code","JetBrains Mono",Consolas,monospace;
 --fs-2xl:30px;--fs-xl:19px;--fs-lg:15px;--fs-md:13px;--fs-sm:12px;--fs-xs:10.5px;
 --lh:1.5;--tracking:.04em;
 /* 余白・角丸 */
 --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:22px;--s6:32px;--r:14px;--r2:9px;
 /* ダークテーマ(既定) */
 --bg:#0a0d13;--panel:#10141d;--panel2:#161b27;--line:#222b3b;--line2:#1a2130;
 --fg:#e7edf6;--dim:#98a6bb;--faint:#5f6c80;
 --brand:#ff5d4d;--blue:#56a6ff;--green:#41d27f;--amber:#f4b740;--red:#ff5b5b;--purple:#b78cff;
 --accentbg:rgba(86,166,255,.12);
 --shadow:0 1px 0 rgba(255,255,255,.03) inset,0 10px 30px -16px rgba(0,0,0,.7);
}
html[data-theme="light"]{
 --bg:#eef1f7;--panel:#ffffff;--panel2:#f5f7fc;--line:#e0e6f0;--line2:#eef1f7;
 --fg:#141b27;--dim:#566175;--faint:#8a97a9;
 --brand:#e8443a;--blue:#2f74d8;--green:#1f9d54;--amber:#c98209;--red:#d83a3a;--purple:#7c4dd0;
 --accentbg:rgba(47,116,216,.10);
 --shadow:0 1px 2px rgba(16,24,40,.05),0 14px 32px -18px rgba(16,24,40,.22);
}
*{box-sizing:border-box}
html,body{margin:0}
body{font-family:var(--f-sans);font-size:var(--fs-md);line-height:var(--lh);
 background:radial-gradient(1200px 600px at 80% -10%,var(--accentbg),transparent 60%),var(--bg);
 color:var(--fg);-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
a{color:var(--blue)}
.num{font-family:var(--f-mono);font-variant-numeric:tabular-nums}
/* アプリバー */
.bar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:var(--s4);
 padding:12px clamp(14px,3vw,28px);background:color-mix(in srgb,var(--panel) 86%,transparent);
 backdrop-filter:saturate(160%) blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-size:var(--fs-xl);font-weight:700;letter-spacing:-.01em}
.brand .logo{font-size:22px;filter:drop-shadow(0 2px 6px rgba(255,93,77,.5))}
.brand .brand-ico{height:24px;width:24px;border-radius:6px;display:block;filter:drop-shadow(0 2px 6px rgba(0,0,0,.25))}
.brand small{display:block;font-size:var(--fs-xs);font-weight:500;color:var(--dim);letter-spacing:var(--tracking);text-transform:uppercase}
.spacer{flex:1}
.pill{display:inline-flex;align-items:center;gap:7px;font-size:var(--fs-sm);font-weight:600;
 padding:5px 11px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--dim)}
.pill .dot{width:8px;height:8px;border-radius:50%;background:var(--faint)}
.pill.ok{color:var(--green);border-color:color-mix(in srgb,var(--green) 40%,var(--line))}
.pill.ok .dot{background:var(--green);box-shadow:0 0 0 0 var(--green);animation:pulse 2s infinite}
.pill.warn{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 40%,var(--line))}
.pill.warn .dot{background:var(--amber)}
.pill.bad{color:var(--red)}.pill.bad .dot{background:var(--red)}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--green) 70%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
.iconbtn{font-size:16px;line-height:1;min-width:36px;height:36px;padding:0 8px;border-radius:var(--r2);
 cursor:pointer;background:var(--panel2);border:1px solid var(--line);color:var(--fg);display:inline-flex;
 align-items:center;justify-content:center;white-space:nowrap}
.iconbtn:hover{border-color:var(--blue)}
.wrap{max-width:1280px;margin:0 auto;padding:clamp(14px,2.5vw,26px)}
.wrap.state-stale{opacity:.55;pointer-events:none}
/* 操作行 */
.controls{display:flex;flex-wrap:wrap;gap:var(--s3);align-items:center;margin-bottom:var(--s5)}
.sw{display:inline-flex;align-items:center;gap:10px;font-size:var(--fs-md);font-weight:600;
 padding:9px 14px;border-radius:var(--r2);background:var(--panel);border:1px solid var(--line);cursor:pointer}
.toggle{appearance:none;width:42px;height:23px;border-radius:999px;background:var(--line);position:relative;cursor:pointer;transition:background .18s;flex:none}
.toggle::after{content:"";position:absolute;top:2px;left:2px;width:19px;height:19px;border-radius:50%;background:#fff;transition:.18s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.toggle:checked{background:var(--green)}.toggle:checked.red{background:var(--brand)}
.toggle:checked::after{left:21px}
.toggle:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
/* KPI */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:var(--s3);margin-bottom:var(--s5)}
.kpi{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
 padding:14px 16px;box-shadow:var(--shadow);overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--blue)}
.kpi.i-green::before{background:var(--green)}.kpi.i-amber::before{background:var(--amber)}
.kpi.i-red::before{background:var(--brand)}.kpi.i-blue::before{background:var(--blue)}
.kpi .kn{font-family:var(--f-mono);font-size:var(--fs-2xl);font-weight:700;letter-spacing:-.02em;line-height:1.1}
.kpi .kl{font-size:var(--fs-xs);color:var(--faint);text-transform:uppercase;letter-spacing:var(--tracking);margin-top:4px}
/* グリッド/パネル */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:var(--s4)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);
 display:flex;flex-direction:column;min-width:0;transition:border-color .15s}
.panel:hover{border-color:color-mix(in srgb,var(--blue) 30%,var(--line))}
.panel.wide{grid-column:1/-1}
.sect{grid-column:1/-1;display:flex;align-items:center;gap:10px;margin:14px 0 -4px;
 font-size:var(--fs-xs);font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:var(--tracking)}
.sect:first-child{margin-top:0}
.sect .ic{font-size:13px;filter:saturate(140%)}
.sect::after{content:"";flex:1;height:1px;background:var(--line2)}
.sbar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:var(--fs-sm)}
.sbl{width:118px;flex:0 0 118px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sbt{flex:1;height:8px;background:var(--panel2);border-radius:6px;overflow:hidden}
.sbf{display:block;height:100%;background:linear-gradient(90deg,var(--amber),var(--red));border-radius:6px;transition:width .3s}
.sbn{width:46px;text-align:right;color:var(--faint)}
.phead{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--line2)}
.phead h2{margin:0;font-size:var(--fs-sm);font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:var(--tracking)}
.phead .meta{margin-left:auto;font-size:var(--fs-xs);color:var(--faint)}
.pbody{padding:14px 16px;min-width:0;overflow-x:auto}
.pbody.tight{padding:8px}
/* ボタン/入力 */
button{font-family:inherit;font-size:var(--fs-sm);font-weight:600;border:1px solid transparent;border-radius:8px;
 padding:7px 13px;cursor:pointer;background:var(--green);color:#fff;transition:.12s}
button:hover{filter:brightness(1.08)}button:active{transform:translateY(1px)}
button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
button.red{background:var(--brand)}
button.ghost{background:var(--panel2);color:var(--fg);border-color:var(--line)}
input,select,textarea{font-family:inherit;font-size:var(--fs-sm);background:var(--bg);color:var(--fg);
 border:1px solid var(--line);border-radius:8px;padding:8px 10px;min-width:0}
input:focus,select:focus,textarea:focus{outline:2px solid var(--blue);outline-offset:-1px;border-color:var(--blue)}
.settings-group{border-top:1px solid var(--line);padding-top:12px;margin-top:12px}
.settings-field{display:grid;grid-template-columns:minmax(210px,1fr) minmax(220px,1fr);gap:10px;padding:10px 0;border-bottom:1px solid var(--line)}
.settings-field label{font-weight:600;display:block}.settings-field code{font-size:11px;color:var(--muted)}
.settings-field .meta{line-height:1.5;margin-top:4px}.settings-field input:not([type=checkbox]),.settings-field select,.settings-field textarea{width:100%;box-sizing:border-box}
.settings-field textarea{min-height:86px;resize:vertical;padding:8px;border:1px solid var(--line);border-radius:var(--r2);font-family:ui-monospace,monospace}
.settings-field.dirty{border-left:3px solid var(--blue);padding-left:8px}.settings-field.invalid{border-left-color:var(--red)}
.setting-chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:7px}.setting-chip{display:inline-flex;align-items:center;gap:6px;background:var(--panel2);border:1px solid var(--line);border-radius:15px;padding:3px 8px;max-width:100%;overflow-wrap:anywhere}
.setting-chip button{padding:0 4px;background:transparent;color:var(--fg)}.setting-rows input{width:100%;box-sizing:border-box}.setting-rows td{padding:5px}.setting-raw{margin-top:8px}.setting-raw textarea{width:100%}
.settings-savebar{position:sticky;bottom:8px;z-index:8;background:var(--panel);border:1px solid var(--line);border-radius:var(--r2);padding:10px;box-shadow:var(--shadow);margin-top:14px}.settings-savebar .row{margin:0}.settings-diff{max-height:300px;overflow:auto}.settings-diff pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:38vw;margin:0}
#settingsstatus{white-space:pre-wrap}#settingsdetail summary{cursor:pointer;list-style-position:inside}
@media(max-width:700px){.settings-field{grid-template-columns:1fr}}
input::placeholder{color:var(--faint)}
.row{display:flex;gap:var(--s2);flex-wrap:wrap;align-items:center;margin-top:var(--s3)}
.row input{flex:1}
/* テーブル */
table{width:100%;border-collapse:collapse;font-size:var(--fs-sm)}
th,td{padding:8px 6px;text-align:left;border-bottom:1px solid var(--line2)}
th{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:var(--tracking);color:var(--faint);font-weight:600}
tbody tr:hover{background:var(--panel2)}
td .num{font-size:var(--fs-sm)}
/* バッジ/タグ */
.badge{display:inline-block;font-size:var(--fs-xs);font-weight:700;padding:2px 8px;border-radius:999px;
 text-transform:uppercase;letter-spacing:.03em;border:1px solid transparent}
.badge.danger{color:var(--red);background:color-mix(in srgb,var(--red) 16%,transparent);border-color:color-mix(in srgb,var(--red) 35%,transparent)}
.badge.warn{color:var(--amber);background:color-mix(in srgb,var(--amber) 16%,transparent);border-color:color-mix(in srgb,var(--amber) 35%,transparent)}
.badge.info{color:var(--purple);background:color-mix(in srgb,var(--purple) 16%,transparent);border-color:color-mix(in srgb,var(--purple) 35%,transparent)}
.badge.muted{color:var(--dim);background:var(--panel2);border-color:var(--line)}
/* 行リスト(検知/イベント) */
.feed{max-height:280px;overflow:auto;margin:0;display:flex;flex-direction:column}
.frow{display:flex;align-items:center;gap:10px;padding:7px 4px;border-bottom:1px solid var(--line2);font-size:var(--fs-sm)}
.frow:last-child{border-bottom:0}
.frow .time{font-family:var(--f-mono);font-size:var(--fs-xs);color:var(--faint);flex:none;width:64px}
.frow .desc{color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
.frow .cnt{font-family:var(--f-mono);font-size:var(--fs-xs);color:var(--dim);flex:none}
.code{font-family:var(--f-mono);font-size:var(--fs-xs);line-height:1.55;white-space:pre;overflow:auto;
 max-height:240px;margin:0;color:var(--dim)}
.empty{color:var(--faint);font-size:var(--fs-sm);padding:14px 2px;text-align:center}
.note{color:var(--faint);font-size:var(--fs-xs);margin-top:10px}
canvas,svg{display:block;width:100%}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:var(--line);border-radius:9px}
/* トースト通知 */
.toastwrap{position:fixed;right:16px;bottom:16px;z-index:300;display:flex;flex-direction:column-reverse;
 gap:8px;max-width:min(360px,calc(100vw - 32px));pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--r2);background:var(--panel);
 border:1px solid var(--line);box-shadow:var(--shadow);font-size:var(--fs-sm);color:var(--fg);
 opacity:0;transform:translateY(8px);transition:opacity .18s,transform .18s;pointer-events:auto}
.toast.show{opacity:1;transform:translateY(0)}
.toast.ok{border-color:color-mix(in srgb,var(--green) 45%,var(--line))}
.toast.ok::before{content:"✓";color:var(--green);font-weight:700}
.toast.err{border-color:color-mix(in srgb,var(--red) 45%,var(--line))}
.toast.err::before{content:"✕";color:var(--red);font-weight:700}
.toast.info::before{content:"ℹ";color:var(--blue);font-weight:700}
.toast .ttext{flex:1;min-width:0;overflow-wrap:anywhere}
.toast .tclose{background:transparent;border:0;color:var(--faint);padding:0 2px;font-size:14px;
 line-height:1;cursor:pointer}
.toast .tclose:hover{color:var(--fg)}
/* 確認ダイアログ */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;
 justify-content:center;z-index:250;padding:16px}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);
 padding:20px;max-width:420px;width:100%;max-height:calc(100vh - 32px);overflow-y:auto;overflow-wrap:anywhere}
.modal.wide{max-width:640px}
.modal-msg{font-size:var(--fs-md);color:var(--fg);margin-bottom:16px;line-height:1.5;white-space:pre-line;overflow-wrap:anywhere}
.modal-body{max-height:min(60vh,520px);overflow-y:auto;margin-bottom:16px;font-size:var(--fs-sm)}
.modal-body h3{margin:16px 0 8px;font-size:var(--fs-md)}
.modal-body h3:first-child{margin-top:0}
.modal-body ol,.modal-body ul{margin:0 0 4px;padding-left:20px;line-height:1.7}
.modal-body p{margin:0 0 4px;color:var(--dim)}
.modal-body .upsell{margin-top:16px;padding:12px 14px;border-radius:var(--r2);
 background:color-mix(in srgb,var(--amber) 10%,transparent);
 border:1px solid color-mix(in srgb,var(--amber) 30%,var(--line))}
.modal-body .upsell h3{margin-top:0}
.modal-body .upsell ul{margin-bottom:0}
.modal-body .upsell li{margin-bottom:6px}
.modal-body .upsell li b{color:var(--fg)}
.modal-actions{display:flex;justify-content:flex-end;gap:8px}
/* 初回ロードのスケルトン: 『本当にゼロ』ではなく『まだ届いていない』と分かるように */
.skel-bar{display:inline-block;height:.85em;min-width:24px;border-radius:4px;vertical-align:middle;
 background:linear-gradient(90deg,var(--panel2) 25%,var(--line2) 37%,var(--panel2) 63%);
 background-size:400% 100%;animation:skel 1.4s ease-in-out infinite}
@keyframes skel{0%{background-position:100% 50%}100%{background-position:0 50%}}
.kpi.skel .kn{margin-bottom:2px}
/* ボタンのビジー状態: 二重送信防止 + 進行中フィードバック */
button.busy{color:transparent!important;pointer-events:none;position:relative}
button.busy::after{content:"";position:absolute;left:50%;top:50%;width:13px;height:13px;
 margin:-6.5px 0 0 -6.5px;border-radius:50%;border:2px solid rgba(255,255,255,.55);
 border-top-color:#fff;animation:spin .6s linear infinite}
button.ghost.busy::after,button.red.busy::after{border-color:var(--line);border-top-color:var(--fg)}
@keyframes spin{to{transform:rotate(360deg)}}
/* チャート時間範囲ズーム */
.chartzoom{display:inline-flex;gap:4px;margin-left:10px}
.chartzoom button{padding:3px 9px;font-size:var(--fs-xs)}
.chartzoom button.active{background:var(--blue);color:#fff;border-color:var(--blue)}
.chart-wrap{position:relative}.chart-tip{position:absolute;top:8px;left:10px;background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 10px;pointer-events:none;font-size:var(--fs-xs);max-width:calc(100% - 24px)}
/* テーブル検索/ソート */
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--fg)}
th.sortable .sortarrow{display:inline-block;width:9px;font-size:9px;color:var(--blue)}
.searchrow{margin-top:0}
.searchrow input{flex:1;min-width:120px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:560px){
 .bar{flex-wrap:wrap;gap:8px}
 .brand{flex-basis:100%;min-width:0;overflow-wrap:anywhere}
 .brand>div{min-width:0}.brand .logo,.iconbtn{flex-shrink:0}
 .brand small,.bar>.spacer{display:none}
 .bar>.pill{flex:1;min-width:0;white-space:nowrap}
 .pill .dot{flex:none}#connt{overflow:hidden;text-overflow:ellipsis;min-width:0}
 .wrap{padding:14px}.grid{grid-template-columns:minmax(0,1fr)}
 .phead{flex-wrap:wrap}.phead h2,.phead .meta{min-width:0;overflow-wrap:anywhere}
 .chartzoom{flex-wrap:wrap;margin-left:0}
 .modal-actions{flex-wrap:wrap}
}
</style></head><body>
<div class="toastwrap" id="toastwrap"></div>
<div class="modal-overlay" id="adminAuthOverlay" style="display:flex;z-index:1000" role="dialog" aria-modal="true" aria-labelledby="adminAuthTitle">
  <div class="modal" id="adminAuthDialog" tabindex="-1">
    <h2 id="adminAuthTitle">管理画面のロック解除</h2>
    <p class="meta">管理トークンはこのページのメモリだけで保持します。ページを閉じるか再読み込みすると消去されます。</p>
    <form id="adminAuthForm" method="post" action="/">
      <label for="adminTokenInput">管理トークン</label>
      <input id="adminTokenInput" type="password" autocomplete="current-password" maxlength="4096" spellcheck="false" autocapitalize="off" style="width:100%;margin:8px 0">
      <p class="meta" id="adminAuthStatus" role="status" aria-live="polite">トークンを入力してロックを解除してください</p>
      <div class="modal-actions"><button type="button" id="adminUnlock">ロック解除</button></div>
    </form>
  </div>
</div>
<div class="modal-overlay" id="confirmOverlay" style="display:none">
  <div class="modal">
    <div class="modal-msg" id="confirmMsg"></div>
    <div class="modal-actions">
      <button class="ghost" id="confirmCancel">キャンセル</button>
      <button class="red" id="confirmOk">実行</button>
    </div>
  </div>
</div>
<div class="modal-overlay" id="helpOverlay" style="display:none">
  <div class="modal wide">
    <h2 style="margin:0 0 12px">__BRAND__</h2>
    <div class="modal-body" id="helpBody">
      <h3>使い方</h3>
      <pre class="code" style="margin:0 0 10px">python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081</pre>
      <ol>
        <li>起動すると --listen 宛の通信を検査し、問題なければ --backend(あなたのWebサーバ)へ転送します。</li>
        <li>本ダッシュボードは --admin ポートで待受け、起動時にコンソールへ表示されるトークンで認証します。</li>
        <li>上部の「ファイアウォール」「DDoS / 侵入防御」トグルで防御レイヤーをON/OFFできます。</li>
        <li>「攻撃イベント」「BAN中のIP」でリアルタイム監視。手動でのBAN/解除も可能です。</li>
        <li>「WAF / 検知設定」パネルでしきい値・機能ごとのON/OFFを調整できます(保存は即時反映)。</li>
      </ol>
      <h3>できること(Lite版)</h3>
      <ul>
        <li>WAF: SQLi・XSS・RCE・パストラバーサル・XXE・SSRF・JNDI・スキャナー等のシグネチャ照合、カスタムシグネチャ追加</li>
        <li>L7 DDoS防御: レート制限・脅威スコアリング・自動BAN(拒否スコア/BANスコアの2段階)</li>
        <li>双方向の検査: リクエストボディ(POST/JSON/GraphQL・gzip解凍を含む)+ 応答のDLP・セキュリティヘッダ付与</li>
        <li>認証・濫用対策: JWT検査・クレデンシャル単位のレート制限</li>
        <li>状態の整合性: BAN/設定のHMAC署名による改竄耐性</li>
      </ul>
      <h3>バージョン情報</h3>
      <p>__BRAND__ — v1.3.0</p>
      <p>軽量な L7 WAF / DDoS セキュリティゲートウェイ(無償版・AGPL-3.0-or-later)。外部依存ゼロ・OS 非侵襲・防御専用。ライセンス全文は LICENSE.txt、詳細は README.md を参照してください。</p>
      <p>より詳しい説明は README.md および docs/ 配下のドキュメントを参照してください。</p>
      <div class="upsell">
        <h3>フル版でできること</h3>
        <p>Lite は WAF / DDoS 対策の中核機能を無償で提供します。次のような領域は上位版(フル版)で加わります。</p>
        <ul>
          <li><b>可用性:</b> ファイルの改竄を自己完全性監視で検知・自動修復し、プロセスが落ちても watchdog が自動再起動します。無人運用でも稼働を維持できます。</li>
          <li><b>ボットとの選別:</b> 動的PoWチャレンジで、正規ユーザーを通しながら自動化された攻撃だけを絞り込みます(Liteは拒否/BANの二値判定のみ)。GeoIP・許可リスト(allowlist)・ステルス運用によるアクセス制御も加わります。</li>
          <li><b>侵入後の検知:</b> LDAP/SMB/Kerberosデコイ、囮ファイル、カナリアトークン、ハニーポットで、境界を突破された後の不審な動きも捕捉します。DNSフィルタはC2通信やトンネリングを見つけます。</li>
          <li><b>運用への統合:</b> 検知結果をSIEMやSlackへリアルタイム転送(Webhook/Syslog)。脅威インテリジェンス(IoC)照合とMITRE ATT&CK対応のルールで、既知の攻撃手口を継続的にカバーします。</li>
          <li><b>複数拠点・大規模環境:</b> LDAP 列挙検知プロキシと、ノード間でBAN情報を同期する分散ゴシップにより、組織全体で一貫した防御になります(商用ライセンス管理つき)。</li>
        </ul>
      </div>
    </div>
    <div class="modal-actions"><button class="ghost" id="helpClose">閉じる</button></div>
  </div>
</div>
<div class="bar" id="appbar">
  <div class="brand"><span class="logo">__LOGO__</span><div>__BRAND__<small>__SUBTITLE__</small></div></div>
  <div class="spacer"></div>
  <span class="pill" id="conn"><span class="dot"></span><span id="connt">接続中</span></span>
  <button class="ghost" id="adminLock">ロック</button>
  <button class="iconbtn" id="help" title="使い方 / できること" aria-label="ヘルプ">❓</button>
  <button class="iconbtn" id="lang" title="Language / 言語" aria-label="Language">EN</button>
  <button class="iconbtn" id="theme" title="テーマ切替" aria-label="テーマ切替">☀️</button>
</div>
<div class="wrap state-stale" id="stateview" inert>
  <div class="controls">
    <label class="sw"><input type="checkbox" id="fw" class="toggle"> ファイアウォール</label>
    <label class="sw"><input type="checkbox" id="sh" class="toggle"> DDoS / 侵入防御</label>
    <label><span>実行モード</span> <select id="shieldmode" aria-label="実行モード"><option value="enforce">遮断モード</option><option value="audit">監査モード(検知は記録のみ)</option></select></label>
    <span class="badge" id="modestat">状態取得中</span>
    <span class="badge warn" id="cfgwarn" style="display:none"></span>
    <span class="badge warn" id="clusterwarning" style="display:none" role="status"></span>
    <div class="spacer"></div>
    <button class="red" onclick="globalBlock(true,this)">🌍 グローバル遮断</button>
    <button class="ghost" onclick="globalBlock(false,this)">解除</button>
  </div>
  <div class="kpis" id="cards"></div>
  <div class="grid">
    <div class="sect"><span class="ic">📈</span>概況</div>
    <section class="panel wide">
      <div class="phead"><h2>リアルタイム通信</h2><span class="meta" id="chartleg">req/s · block/s</span>
        <div class="chartzoom" id="chartzoom">
          <button class="ghost" data-sec="60" onclick="setChartWindow(60)">1m</button>
          <button class="ghost" data-sec="300" onclick="setChartWindow(300)">5m</button>
          <button class="ghost" data-sec="600" onclick="setChartWindow(600)">10m</button>
          <button class="ghost active" data-sec="all" onclick="setChartWindow(Infinity)">全保持(最大600点)</button>
        </div></div>
      <div class="pbody chart-wrap"><canvas id="chart" height="180" style="height:180px" tabindex="0" aria-label="要求・遮断レート。矢印キーで値を確認"></canvas><div id="charttip" class="chart-tip" role="status" hidden></div><span class="meta">保持中のデータだけを表示・マウスまたは矢印キーで値を確認</span></div>
    </section>
    <section class="panel wide">
      <div class="phead"><h2>ネットワーク図</h2><span class="meta">中心=本機 / 内→外=loopback·private·public / ノードclickで一時BAN·解除(ACLは変更しません)</span></div>
      <div class="pbody"><svg id="netmap" height="300" viewBox="0 0 1040 300" preserveAspectRatio="xMidYMid meet" style="height:300px"></svg></div>
    </section>

    <div class="sect"><span class="ic">🛡</span>脅威モニタリング</div>
    <section class="panel">
      <div class="phead"><h2>攻撃イベント</h2><span class="meta" id="eventsmeta">—</span></div>
      <div class="pbody tight">
        <div class="row searchrow" style="margin:8px 8px 0"><input id="eventsearch" placeholder="IP/種別/理由/シグネチャで絞り込み" oninput="renderEvents()">
        <button class="ghost" onclick="exportData('events','csv')">CSV</button>
        <button class="ghost" onclick="exportData('events','json')">JSON</button></div>
        <div class="feed" id="events"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>BAN中のIP</h2><span class="meta" id="bansmeta">—</span></div>
      <div class="pbody">
        <div class="row searchrow"><input id="bansearch" placeholder="IPで絞り込み" oninput="renderBans()">
        <button class="ghost" onclick="exportData('bans','csv')">CSV</button>
        <button class="ghost" onclick="exportData('bans','json')">JSON</button></div>
        <table id="bans"><thead><tr>
          <th style="width:22px"><input type="checkbox" id="banall" onchange="toggleAllBans(this.checked)" title="表示中の全行を選択"></th>
          <th>IP</th><th class="sortable" data-sort="remain">残り時間<span class="sortarrow"></span></th>
          <th class="sortable" data-sort="score">スコア<span class="sortarrow"></span></th><th></th>
        </tr></thead><tbody></tbody></table>
        <div class="row"><button class="ghost" onclick="unbanSelected(this)">選択解除</button>
        <button class="red ghost" onclick="unbanAll(this)">全解除</button></div>
        <div class="row"><input id="banip" placeholder="手動BANするIP">
        <button class="red" onclick="ban(this)">BAN</button></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>上位送信元(脅威スコア順)</h2></div>
      <div class="pbody"><div id="top"></div></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>APT級の兆候</h2><span class="meta">低速持続 · 規則的ビーコン · 累積</span></div>
      <div class="pbody"><div id="apt"></div></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>シグネチャ別ヒット</h2><span class="meta" id="sigmetatop">—</span></div>
      <div class="pbody">
        <svg id="sigtrend" height="30" viewBox="0 0 300 30" preserveAspectRatio="none" style="width:100%;height:30px;margin:0 0 8px"></svg>
        <div id="sigbars"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>トラフィック構成(ゾーン / アクション)</h2><span class="meta">外部(public)推移 · 内訳</span></div>
      <div class="pbody">
        <svg id="pubtrend" height="30" viewBox="0 0 300 30" preserveAspectRatio="none" style="width:100%;height:30px;margin:0 0 8px"></svg>
        <div class="meta" style="margin:2px 0 4px">ゾーン別</div><div id="zonebars"></div>
        <div class="meta" style="margin:8px 0 4px">アクション別</div><div id="actbars"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>HTTPメソッド別</h2></div>
      <div class="pbody">
        <div id="methbars"></div>
      </div>
    </section>

    <div class="sect"><span class="ic">⚙️</span>WAF / 検知設定</div>
    <section class="panel">
      <div class="phead"><h2>WAF 追加シグネチャ(任意・高FP)</h2><span class="meta">既定OFF · 誤検知許容な環境のみ点灯</span></div>
      <div class="pbody tight"><div id="optsigs"></div></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>カスタムシグネチャ</h2><span class="meta" id="sigmeta">—</span></div>
      <div class="pbody">
        <div class="row" style="margin-top:0"><button class="ghost" onclick="exportData('sigs','csv')">CSV</button>
        <button class="ghost" onclick="exportData('sigs','json')">JSON</button></div>
        <table id="customsigs"><tbody></tbody></table>
        <div class="row"><input id="signame" placeholder="名前 例:my-rule">
        <input id="sigpat" placeholder="正規表現 例:evil-?bot"></div>
        <div class="row"><button onclick="addSig(this)">追加</button>
        <span class="meta" id="sigerr"></span></div>
        <div class="row"><input id="sigtestsample" placeholder="テスト対象の文字列(パス/UA/ヘッダ値など)" title="実際に追加する前に、このパターンがサンプル文字列にマッチするかを試せます(状態は変更されません)。">
        <button class="ghost" onclick="testSig(this)">テスト</button>
        <span class="meta" id="sigtestresult"></span></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>パス別レート制限</h2><span class="meta" id="prlmeta">—</span></div>
      <div class="pbody">
        <table id="pathlimits"><tbody></tbody></table>
        <div class="row"><input id="prpath" placeholder="パス前方一致 例:/login">
        <input id="prrate" type="number" step="0.1" placeholder="毎秒 例:0.5" style="max-width:130px">
        <input id="prburst" type="number" step="1" placeholder="バースト 例:5" style="max-width:130px"></div>
        <div class="row"><button onclick="addPathLimit(this)">追加</button>
        <span class="meta" id="prerr"></span></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>レート/メソッド/分散(運用)</h2><span class="meta" id="opsstat">—</span></div>
      <div class="pbody tight">
        <div class="row"><label class="sw"><input type="checkbox" id="throttle" class="toggle"> レート超過に429応答</label>
          <input id="retryaft" type="number" step="1" min="0" placeholder="Retry-After 秒" style="max-width:150px"></div>
        <div class="row"><label class="sw"><input type="checkbox" id="subnetdef" class="toggle"> サブネット集約防御</label>
          <input id="subthr" type="number" step="1" min="1" placeholder="しきい値(別IP数)" style="max-width:170px"
          title="同一サブネット(IPv4は/24・IPv6は/64)内でこの数の別IPがBANされると分散攻撃(ボットネット等)とみなし、そのサブネットの新規IPに事前スコアを加点します(即BANはしません・共有NAT巻き添え回避のため既定OFF)。"></div>
        <div class="row"><span class="meta" id="subnetmeta">—</span></div>
        <div class="row"><input id="blockmeth" placeholder="遮断メソッド(カンマ区切) 例:TRACE,TRACK,CONNECT">
          <button onclick="saveBlockedMethods(this)">適用</button>
          <span class="meta" id="methoderr"></span></div>
        <div class="row"><input id="maxconnip" type="number" step="1" min="0" placeholder="上限接続数/IP(0=無制限)" style="max-width:180px"
          title="1つのIPが同時に保持できる接続数の上限。0=無制限。超過分は即切断し、接続保持型のflood(スロットループ等)を防ぎます。">
          <input id="connrateip" type="number" step="1" min="0" placeholder="新規接続/秒/IP(0=無制限)" style="max-width:190px"
          title="1つのIPからの新規接続を1秒あたりこの数までに制限。0=無制限。接続→即RST/即切断を高速反復するRSTフラッド/churnフラッドを、リクエスト解析より手前の安価な段階で遮断します。">
          <input id="maxtotalconn" type="number" step="1" min="0" placeholder="全体同時接続上限(0=無制限)" style="max-width:200px"
          title="サーバ全体の同時接続数の上限。0=無制限。超過分は即切断し、大量接続によるFD/メモリ枯渇でサーバごと落ちるのを防ぎます。"></div>
        <div class="row"><label class="sw" title="転送するリクエストのConnectionをcloseへ書き換えます。OFFでも要求本文の終端で転送を止め、接続内の2本目の要求をバックエンドへ送りません。"><input type="checkbox" id="forceclose" class="toggle"> keep-alive を強制切断</label></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>出口DLP(秘密漏洩)</h2><span class="meta" id="dlpstat">—</span></div>
      <div class="pbody tight">
        <div class="row">
          <label class="sw"><input type="checkbox" id="dlp" class="toggle"> 秘密漏洩検知</label>
          <select id="dlpact" title="応答本文にAPIキー等の秘密が含まれていた場合の挙動。監査=記録のみで送出は止めません。遮断=漏洩を検知した応答を送出せず遮断します。" style="background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--r2);padding:6px 9px;font:inherit">
            <option value="audit">監査(記録のみ)</option>
            <option value="block">遮断(漏洩を送出しない)</option>
          </select>
        </div>
        <svg id="leaktrend" height="30" viewBox="0 0 300 30" preserveAspectRatio="none" style="width:100%;height:30px;margin:6px 0"></svg>
        <div id="leakkinds" style="margin-bottom:6px"></div>
        <div class="feed" id="leaks"></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>詳細防御(評価)</h2><span class="meta" id="advstat">—</span></div>
      <div class="pbody tight">
        <div class="row"><label class="sw"><input type="checkbox" id="sech" class="toggle"> 応答セキュリティヘッダ</label></div>
        <div class="row"><span class="meta">検知の厳格度(paranoia)</span>
          <select id="paranoia" title="検知の段階的な厳格度。レベルを上げるほど誤検知が起きやすい任意シグネチャを段階的に有効化します(2:オープンリダイレクト → 3:+内部SSRF → 4:+テンプレート注入)。既定は1(常時ONの低誤検知ルールのみ)。" style="background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:var(--r2);padding:6px 9px;font:inherit">
            <option value="1">1 · 保守(誤検知最小)</option>
            <option value="2">2 · やや積極</option>
            <option value="3">3 · 積極</option>
            <option value="4">4 · 最大(高FP許容)</option>
          </select></div>
        <div class="row"><span class="meta" id="tamperstat">—</span></div>
      </div>
    </section>
    <details class="panel wide" id="settingsdetail">
      <summary class="phead"><h2 style="display:inline">実行時の防御設定</h2><span class="meta">変更した項目だけをまとめて保存</span></summary>
      <div class="pbody">
        <p class="meta">稼働中に変更できるDDoS / 侵入防御の設定を種類別に表示します。監査モードは検知による遮断を記録に替えます。不正なHTTPや検証できない状態の拒否は継続します。変更は保存するまで適用されません。</p>
        <p class="meta">待受・backend・ワーカー・状態保存先などの起動設定は、起動引数や環境変数で指定します。変更にはこのアプリの停止・起動が必要です。Windows自体の再起動は不要です。本文退避には固定の安全上限があります。</p>
        <p class="meta">上段の個別設定は操作時に即適用されます。この詳細画面の編集は「変更を保存」まで未適用です。同じ項目を別の場所で変更した場合は、競合を確認してから再編集してください。</p>
        <div class="row"><input id="settingssearch" type="search" placeholder="設定名・機能で検索" aria-label="設定を検索"></div>
        <div id="settingsfields"></div>
      </div>
        <div class="settings-savebar"><p class="meta" id="settingsstatus" role="status" aria-live="polite">開くと設定項目を読み込みます</p>
          <div class="row"><button id="settingsdiffbutton" class="ghost" onclick="toggleSettingsDiff()" disabled>変更内容を比較</button>
          <button id="settingsreload" class="ghost" onclick="reloadAdvancedSettings(this)">変更を破棄して再読込</button>
          <button id="settingssave" onclick="saveAdvancedSettings(this)" disabled>変更を保存</button></div>
          <div id="settingsdiff" class="settings-diff" hidden></div></div>
    </details>

    <div class="sect"><span class="ic">🚦</span>アクセス制御・申立</div>
    <section class="panel">
      <div class="phead"><h2>アクセスルール</h2></div>
      <div class="pbody">
        <p class="meta">ゾーンの既定動作。登録済みACLは個別ルールとして優先されます。</p>
        <div class="row" id="zonepolicies">
          <label>loopback <select id="zone_loopback" aria-label="loopback policy" onchange="setFirewallPolicy('loopback',this)"><option value="allow">許可</option><option value="deny">拒否</option><option value="prompt">承認待ち</option></select></label>
          <label>private <select id="zone_private" aria-label="private policy" onchange="setFirewallPolicy('private',this)"><option value="allow">許可</option><option value="deny">拒否</option><option value="prompt">承認待ち</option></select></label>
          <label>public <select id="zone_public" aria-label="public policy" onchange="setFirewallPolicy('public',this)"><option value="allow">許可</option><option value="deny">拒否</option><option value="prompt">承認待ち</option></select></label>
        </div>
        <div class="row"><input id="aclsearch" type="search" placeholder="IP/CIDR・動作・メモで検索" aria-label="ACLルール検索" oninput="renderFirewallRules()"><span class="meta" id="aclmeta">—</span></div>
        <table><thead><tr><th>IP/CIDR</th><th>動作</th><th>メモ</th><th></th></tr></thead><tbody id="aclrows"></tbody></table>
        <div class="row"><input id="ruleip" placeholder="IP/CIDR 例:203.0.113.0/24">
        <button onclick="rule('allow',this)">許可</button>
        <button class="red" onclick="rule('deny',this)">拒否</button>
        <button class="ghost" onclick="edge()">エッジ前衛設定DL</button></div>
      </div>
    </section>
    <section class="panel">
      <div class="phead"><h2>解除リクエスト(異議申立)</h2></div>
      <div class="pbody"><table id="appeals"><tbody></tbody></table></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>承認待ち接続(ファイアウォール)</h2><span class="meta" id="pendingmeta">—</span></div>
      <div class="pbody">
        <div class="row" style="margin-top:0"><button onclick="approveAllPending(this)">すべて承認</button>
        <button class="red ghost" onclick="denyAllPending(this)">すべて拒否</button></div>
        <table id="fwpending"><tbody></tbody></table>
      </div>
    </section>

    <div class="sect"><span class="ic">🌐</span>欺瞞</div>
    <section class="panel">
      <div class="phead"><h2>デセプション(MTD)</h2><span class="meta" id="decepstat">—</span></div>
      <div class="pbody"><div id="deception"></div></div>
    </section>

    <div class="sect"><span class="ic">🔬</span>詳細分析</div>
    <section class="panel wide">
      <div class="phead"><h2>詳細分析</h2></div>
      <div class="pbody"><div id="analysis"></div></div>
    </section>
    <section class="panel wide">
      <div class="phead"><h2>変更履歴(監査ログ)</h2><span class="meta" id="auditmeta">—</span></div>
      <div class="pbody tight"><div class="feed" id="auditlog"></div></div>
    </section>
  </div>
</div>
<script>
// 管理トークンはこのページのメモリだけに保持し、再読み込み時は入力し直す。
// 旧版が保存した生トークンを読み戻さず削除する。
try{sessionStorage.removeItem("ducknet-admin-token")}catch(e){}
// 旧 URL に token が含まれていても採用せず、通信や UI 操作より前に取り除く。
let TOKEN="";
let authGeneration=0,authSubmitPending=false;
const adminRequestControllers=new Set();
let refreshGeneration=0,refreshProGeneration=0;
let auditRefreshGeneration=0,sigRefreshGeneration=0,deceptionRefreshGeneration=0;
let settingsSchema=null,settingsSchemaPromise=null,settingsLatestConfig=null,settingsLatestRevision=null,settingsBaseConfig={},settingsControls={},settingsRows={},settingsDirty=new Set(),settingsSavePending=false,settingsAvailable=false,settingsMessage="",settingsMessageError=false;
try{
 const u=new URL(location.href);
 const hasCredentialKey=s=>/(?:^|[?&#/])(?:token|access[_-]?token|admin[_-]?token|ducknet-admin-token)(?:[ \t]*[=:/]|$)/i.test(s);
 const decodeLayer=s=>s.replace(/%([0-9a-f]{2})/gi,(_,h)=>String.fromCharCode(parseInt(h,16)));
 const sensitiveKey=key=>{
  let decoded=key;
  for(let i=0;i<4;i++){
   if(hasCredentialKey(decoded))return true;
   const next=decodeLayer(decoded);if(next===decoded)break;decoded=next;
  }
  // Keep bounded work: a still-encoded key may hide another token layer.
  return hasCredentialKey(decoded)||/%[0-9a-f]{2}/i.test(decoded);
 };
 const legacyKeys=[...u.searchParams.keys()].filter(sensitiveKey);
 // A manually opened legacy token fragment is not sent to this server, but
 // stays in the address bar and browser history unless removed here. Decode
 // bounded percent-encoding layers for legacy case/encoded key aliases.
 let fragment=u.hash.slice(1),fragmentToken=false;
 for(let i=0;i<4;i++){
  if(hasCredentialKey(fragment)){fragmentToken=true;break;}
  const decoded=decodeLayer(fragment);
  if(decoded===fragment)break;fragment=decoded;
 }
 // The cap must not leave a still-encoded token in history. Unrelated hashes
 // that fully decode (for example #panel%20view) remain untouched.
 if(!fragmentToken&&(hasCredentialKey(fragment)||/%[0-9a-f]{2}/i.test(fragment)))fragmentToken=true;
 if(legacyKeys.length||fragmentToken){
  for(const key of legacyKeys)u.searchParams.delete(key);
  history.replaceState(null,"",u.pathname+u.search+(fragmentToken?"":u.hash));
 }
}catch(e){}
const H={"Content-Type":"application/json"};
let AUTH_INSTANCE="__AUTH_INSTANCE__";
let AUTH_KEY_PROMISE=null, AUTH_PROBLEM="";
const AUTH_ENC=new TextEncoder();
const hex=bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,"0")).join("");
function authFailure(kind){AUTH_PROBLEM=errText(kind);const e=new Error(kind);e.authFail=true;e.authKind=kind;throw e;}
function sameHex(a,b){if(typeof a!=="string"||a.length!==b.length)return false;
 let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0;}
async function readAdminResponse(response,limit){
 const length=response.headers.get("Content-Length");
 if(length!==null&&(!/^\d+$/.test(length)||Number(length)>limit))throw new Error("admin response too large");
 if(!response.body||typeof response.body.getReader!=="function")throw new Error("bounded response reader unavailable");
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{while(true){const part=await reader.read();if(part.done)break;
   if(!(part.value instanceof Uint8Array))throw new Error("invalid admin response bytes");
   size+=part.value.byteLength;if(size>limit){await reader.cancel();throw new Error("admin response too large");}
   chunks.push(part.value);}}
 finally{reader.releaseLock();}
 const raw=new Uint8Array(size);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.byteLength;}
 return raw;
}
async function signedRequest(method,path,body){
 const origin=new URL(location.href);
 const local=origin.protocol==="http:"&&["127.0.0.1","localhost","[::1]","::1"].includes(origin.hostname);
 if(!TOKEN)authFailure("auth");
 if(!(origin.protocol==="https:"||local)||typeof crypto==="undefined"||!crypto.subtle||
    !crypto.getRandomValues)authFailure("secure");
 const token=TOKEN,instance=AUTH_INSTANCE,epoch=typeof authGeneration==="number"?authGeneration:0;
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),method==="POST"?30000:10000);
 if(typeof adminRequestControllers!=="undefined")adminRequestControllers.add(controller);
 try{
  if(!AUTH_KEY_PROMISE)AUTH_KEY_PROMISE=crypto.subtle.importKey("raw",AUTH_ENC.encode(token),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const key=await AUTH_KEY_PROMISE;
  const payload=body===undefined?"":body;
  const bodySha=hex(await crypto.subtle.digest("SHA-256",AUTH_ENC.encode(payload)));
  const nonce=hex(crypto.getRandomValues(new Uint8Array(16))),stamp=String(Date.now());
  const message=[instance,method,path,stamp,nonce,bodySha].join("\n");
  const mac=hex(await crypto.subtle.sign("HMAC",key,AUTH_ENC.encode(message)));
  const headers={...H,"X-Admin-Auth-Instance":instance,
   "X-Admin-Auth-Time":stamp,"X-Admin-Auth-Nonce":nonce,
   "X-Admin-Auth-Body":bodySha,"X-Admin-Auth-Mac":mac};
  const options={method,headers,cache:"no-store",redirect:"error",credentials:"omit",referrerPolicy:"no-referrer",signal:controller.signal};if(body!==undefined)options.body=body;
  const response=await fetch(path,options);
  let raw;try{raw=await readAdminResponse(response,16777216);}
  catch(_e){const invalid=new Error("unverified admin response");invalid.adminResponse=true;throw invalid;}
  const actualSha=hex(await crypto.subtle.digest("SHA-256",raw));
  const responseMessage=[instance,nonce,String(response.status),actualSha].join("\n");
  const expected=hex(await crypto.subtle.sign("HMAC",key,AUTH_ENC.encode(responseMessage)));
  const supplied=response.headers.get("X-Admin-Response-Mac")||"";
  if(TOKEN!==token||AUTH_INSTANCE!==instance||(typeof authGeneration==="number"&&authGeneration!==epoch)){const e=new Error("stale token");e.staleToken=true;throw e;}
  if(!sameHex(supplied,expected))authFailure(response.status===401?"auth":"unverified");
  const text=new TextDecoder().decode(raw);
  return {status:response.status,ok:response.ok,json:async()=>JSON.parse(text),text:async()=>text};
 }catch(e){
  if(TOKEN!==token||AUTH_INSTANCE!==instance||(typeof authGeneration==="number"&&authGeneration!==epoch)){const stale=new Error("stale token");stale.staleToken=true;throw stale;}
  if(e&&(e.authFail||e.staleToken))throw e;
  if(e&&e.adminResponse)authFailure("unverified");
  if(controller.signal.aborted){const timeout=new Error("admin request timed out");timeout.name="NetworkError";throw timeout;}
  if(e instanceof TypeError||e.name==="NetworkError")throw e;
  authFailure("secure");}
 finally{clearTimeout(timer);controller.abort();if(typeof adminRequestControllers!=="undefined")adminRequestControllers.delete(controller);}
}
const $=id=>document.getElementById(id);
const cssv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const esc=s=>(s==null?"":String(s)).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const tm=ts=>new Date((ts||0)*1000).toLocaleTimeString();
const nf=n=>(n||0).toLocaleString();
function sev(s){s=(s||"").toLowerCase();
 if(["malicious","block","blocked","deny"].includes(s))return"danger";
 if(["suspicious","alert","throttle"].includes(s))return"warn";
 if(["recon","info"].includes(s))return"info";return"muted";}
/* 言語(i18n): 既定は日本語=サーバHTMLそのまま。EN はクライアントで適用。 */
const JA2EN={
 "管理画面のロック解除":"Unlock the admin dashboard","管理トークン":"Admin token",
 "管理トークンはこのページのメモリだけで保持します。ページを閉じるか再読み込みすると消去されます。":"The admin token stays only in this page's memory. Closing or reloading the page clears it.",
 "トークンを入力してロックを解除してください":"Enter the token to unlock the dashboard",
 "ロック解除":"Unlock","ロック":"Lock","認証が必要です":"Authentication required",
 "管理トークンを入力してください":"Enter the admin token","認証を確認しています":"Verifying authentication",
 "認証を確認できません。接続先とトークンを確認してください":"Authentication could not be verified. Check the destination and token.",
 "使い方":"Usage","できること(Lite版)":"What it can do (Lite)","フル版でできること":"What the full edition adds",
 "閉じる":"Close",
 "起動すると --listen 宛の通信を検査し、問題なければ --backend(あなたのWebサーバ)へ転送します。":
  "Once started, traffic to --listen is inspected and, if clean, forwarded to --backend (your web server).",
 "本ダッシュボードは --admin ポートで待受け、起動時にコンソールへ表示されるトークンで認証します。":
  "This dashboard listens on --admin and authenticates with the token printed to the console at startup.",
 "上部の「ファイアウォール」「DDoS / 侵入防御」トグルで防御レイヤーをON/OFFできます。":
  "Use the \"Firewall\" / \"DDoS / Intrusion\" toggles above to turn each defense layer on/off.",
 "「攻撃イベント」「BAN中のIP」でリアルタイム監視。手動でのBAN/解除も可能です。":
  "Monitor live via \"Attack events\" / \"Banned IPs\"; manual ban/unban is also available.",
 "「WAF / 検知設定」パネルでしきい値・機能ごとのON/OFFを調整できます(保存は即時反映)。":
  "Tune thresholds and per-feature on/off in the \"WAF / detection\" panel (changes apply immediately).",
 "WAF: SQLi・XSS・RCE・パストラバーサル・XXE・SSRF・JNDI・スキャナー等のシグネチャ照合、カスタムシグネチャ追加":
  "WAF: signature matching for SQLi, XSS, RCE, path traversal, XXE, SSRF, JNDI, scanners, etc., plus custom signatures",
 "L7 DDoS防御: レート制限・脅威スコアリング・自動BAN(拒否スコア/BANスコアの2段階)":
  "L7 DDoS defense: rate limiting, threat scoring, auto-ban (2-tier: deny score / ban score)",
 "双方向の検査: リクエストボディ(POST/JSON/GraphQL・gzip解凍を含む)+ 応答のDLP・セキュリティヘッダ付与":
  "Bidirectional inspection: request body (POST/JSON/GraphQL, incl. gzip decompression) + response DLP and security headers",
 "認証・濫用対策: JWT検査・クレデンシャル単位のレート制限":
  "Auth & abuse controls: JWT inspection, per-credential rate limiting",
 "状態の整合性: BAN/設定のHMAC署名による改竄耐性":
  "State integrity: HMAC-signed ban/config state resists tampering",
 "バージョン情報":"About",
 "軽量な L7 WAF / DDoS セキュリティゲートウェイ(無償版・AGPL-3.0-or-later)。外部依存ゼロ・OS 非侵襲・防御専用。ライセンス全文は LICENSE.txt、詳細は README.md を参照してください。":
  "A lightweight L7 WAF/DDoS security gateway (free edition, AGPL-3.0-or-later) — zero-dependency, OS-non-invasive, defense-only. See LICENSE.txt for the full license and README.md for details.",
 "より詳しい説明は README.md および docs/ 配下のドキュメントを参照してください。":
  "See README.md and the docs under docs/ for more detail.",
 "Lite は WAF / DDoS 対策の中核機能を無償で提供します。次のような領域は上位版(フル版)で加わります。":
  "Lite provides the core WAF / DDoS defenses at no cost. The full edition adds the following.",
 "可用性:":"Availability:",
 "ファイルの改竄を自己完全性監視で検知・自動修復し、プロセスが落ちても watchdog が自動再起動します。無人運用でも稼働を維持できます。":
  "Self-integrity monitoring detects and repairs file tampering, and a watchdog restarts the process if it goes down — it keeps running with nobody watching.",
 "ボットとの選別:":"Telling bots from people:",
 "動的PoWチャレンジで、正規ユーザーを通しながら自動化された攻撃だけを絞り込みます(Liteは拒否/BANの二値判定のみ)。GeoIP・許可リスト(allowlist)・ステルス運用によるアクセス制御も加わります。":
  "A dynamic proof-of-work challenge lets real users through while filtering out automated traffic (Lite only makes a binary deny/ban call). GeoIP, an allowlist, and stealth operation round out access control.",
 "侵入後の検知:":"Detecting what happens after a breach:",
 "LDAP/SMB/Kerberosデコイ、囮ファイル、カナリアトークン、ハニーポットで、境界を突破された後の不審な動きも捕捉します。DNSフィルタはC2通信やトンネリングを見つけます。":
  "LDAP/SMB/Kerberos decoys, decoy files, canary tokens, and a honeypot catch suspicious activity once someone is already past the perimeter. A DNS filter picks up C2 traffic and tunneling.",
 "運用への統合:":"Fitting into existing operations:",
 "検知結果をSIEMやSlackへリアルタイム転送(Webhook/Syslog)。脅威インテリジェンス(IoC)照合とMITRE ATT&CK対応のルールで、既知の攻撃手口を継続的にカバーします。":
  "Detections forward to a SIEM or Slack in real time (Webhook/Syslog), and threat-intel (IoC) matching plus MITRE ATT&CK-mapped rules keep coverage current against known techniques.",
 "複数拠点・大規模環境:":"Multi-site and larger deployments:",
 "LDAP 列挙検知プロキシと、ノード間でBAN情報を同期する分散ゴシップにより、組織全体で一貫した防御になります(商用ライセンス管理つき)。":
  "An LDAP enumeration-detection proxy and gossip-based ban-state sync across nodes keep enforcement consistent across the whole organization (with commercial license management).",
 "ファイアウォール":"Firewall","DDoS / 侵入防御":"DDoS / Intrusion","🌍 グローバル遮断":"🌍 Global block",
 "解除":"Release","接続中":"Connected","接続中・親ワーカーのみ":"Connected · parent worker only",
 "親ワーカーのみ":"Parent worker only","接続不可":"Disconnected","状態取得不可":"State unavailable",
 "複数ワーカーの集計値・イベントは親ワーカー分のみです。":"Counters and events cover only the parent worker.",
 "認証エラー・再読込":"Auth error — reload",
 "管理トークンを入力できません。通常のブラウザで開いてください":"Token prompt unavailable. Open this page in a standard browser.",
 "概況":"Overview","脅威モニタリング":"Threat monitoring","WAF / 検知設定":"WAF / detection",
 "アクセス制御・申立":"Access control & appeals","欺瞞":"Deception","詳細分析":"Analysis",
 "リアルタイム通信":"Live traffic","ネットワーク図":"Network map",
 "攻撃イベント":"Attack events","BAN中のIP":"Banned IPs","上位送信元(脅威スコア順)":"Top sources (by score)",
 "APT級の兆候":"APT-grade indicators","シグネチャ別ヒット":"Hits by signature",
 "トラフィック構成(ゾーン / アクション)":"Traffic mix (zone / action)",
 "WAF 追加シグネチャ(任意・高FP)":"WAF optional signatures (high-FP)","カスタムシグネチャ":"Custom signatures",
 "出口DLP(秘密漏洩)":"Egress DLP (secret leak)","アクセスルール":"Access rules",
 "詳細防御(評価)":"Advanced defenses (eval)",
 "応答セキュリティヘッダ":"Response security headers",
 "検知の厳格度(paranoia)":"Detection strictness (paranoia)","ヘッダ":"headers",
 "1 · 保守(誤検知最小)":"1 · conservative (min FP)","2 · やや積極":"2 · moderate",
 "3 · 積極":"3 · aggressive","4 · 最大(高FP許容)":"4 · maximum (high FP ok)",
 "解除リクエスト(異議申立)":"Unban requests (appeals)",
 "承認待ち接続(ファイアウォール)":"Pending connections (firewall)","zone policy=prompt の未知接続":"Unknown connections under zone policy=prompt",
 "承認待ちなし":"No pending connections","常時許可として記憶":"Remember as always-allow",
 "デセプション(MTD)":"Deception (MTD)",
 "低速持続 · 規則的ビーコン · 累積":"Low-and-slow · beacon · cumulative",
 "外部(public)推移 · 内訳":"External (public) trend · breakdown","既定OFF · 誤検知許容な環境のみ点灯":"Off by default · enable where FPs OK",
 "中心=本機 / 内→外=loopback·private·public / ノードclickで遮断·解除":"Center=node / in→out=loopback·private·public / click to block·unblock",
 "ゾーン別":"By zone","アクション別":"By action","HTTPメソッド別":"By HTTP method",
 "許可":"Allow","拒否":"Deny","追加":"Add","エッジ前衛設定DL":"Download edge proxy config",
 "秘密漏洩検知":"Secret leak detection","監査(記録のみ)":"Audit (log only)","遮断(漏洩を送出しない)":"Block (withhold leak)",
 "手動BANするIP":"IP to ban manually","IP/CIDR 例:203.0.113.0/24":"IP/CIDR e.g. 203.0.113.0/24",
 "名前 例:my-rule":"Name e.g. my-rule",
 "正規表現 例:evil-?bot":"Regex e.g. evil-?bot",
 "パス別レート制限":"Per-path rate limits","パス前方一致 例:/login":"Path prefix e.g. /login",
 "毎秒 例:0.5":"Per sec e.g. 0.5","バースト 例:5":"Burst e.g. 5","ルール":"rules","ルールなし":"No rules",
 "パスと毎秒(>0)を入力":"Enter path and rate (>0)",
 "レート/メソッド/分散(運用)":"Rate / method / subnet (ops)","レート超過に429応答":"429 on rate-limit",
 "サブネット集約防御":"Subnet aggregation defense","適用":"Apply","分散":"subnet","メソッド":"methods",
 "追跡":"tracked","遮断メソッド":"Blocked methods","Retry-After 秒":"Retry-After sec",
 "しきい値(別IP数)":"threshold (distinct IPs)",
 "遮断メソッド(カンマ区切) 例:TRACE,TRACK,CONNECT":"Blocked methods (comma) e.g. TRACE,TRACK,CONNECT",
 "無視":"Ignored",
 "BAN なし":"No bans","(なし)":"(none)","イベントなし":"No events","なし":"none","ヒットなし":"No hits",
 "カスタムなし":"No custom signatures",
 "削除":"Remove","DLP 無効":"DLP off","漏洩なし":"No leaks",
 "IP/種別/理由/シグネチャで絞り込み":"Filter by IP, type, reason or signature",
 "中心=本機 / 内→外=loopback·private·public / ノードclickで一時BAN·解除(ACLは変更しません)":"Center=this host / rings=loopback, private, public / click a node to temporarily ban or unban (ACL unchanged)",
 "ゾーンの既定動作。登録済みACLは個別ルールとして優先されます。":"Default action for each zone. Saved ACL rules take precedence.",
 "IP/CIDR・動作・メモで検索":"Search IP/CIDR, action or note","ACLルール検索":"Search ACL rules",
 "動作":"Action","メモ":"Note","承認待ち":"Approval required","登録ルールなし":"No saved rules",
 "このACLルールを削除しますか?":"Remove this ACL rule?","このゾーンの既定動作を変更しますか?":"Change this zone's default action?",
 "ゾーンポリシーを保存しました":"Zone policy saved","検知の詳細":"Detection details",
 "イベントで絞込":"Filter events","BAN表で絞込":"Filter bans",
 "クラスタ稼働中はワーカー別集計のため、このパネルを非表示にしています":"This panel is hidden while cluster workers hold separate telemetry",
 "防御設定の変更は子ワーカーを停止して単一プロセスへ切り替えます":"Defense changes stop cluster workers and switch to a single process",
 "クラスタの子ワーカーを停止し、単一プロセスで変更を適用します。続行しますか?":"This change stops cluster workers and applies in a single process. Continue?",
 "操作をキャンセルしました":"Action cancelled","直近100件まで":"Up to the latest 100 events",
 "申立なし":"No appeals","承認":"Approve","却下":"Reject","名前とパターンを入力":"Enter name and pattern",
 "SSTI(テンプレート注入 {{…}})":"SSTI (template injection {{…}})","内部SSRF(localhost/内部IP)":"Internal SSRF (localhost/internal IP)",
 "オープンリダイレクト(=//)":"Open redirect (=//)",
 "要求":"Requests","スロットル":"Throttle","ブロック":"Block","BAN中":"Banned","漏洩":"Leaks",
 "バックエンド不通":"Backend unreachable",
 "有効":"on","無効":"off","計":"total","種別":"types","系統":"families","前":"ago",
 "インターネット(public)を一括遮断します。よろしいですか?":"Block all public (internet) traffic. Are you sure?",
 "(DUCKNET_DECEPTION 未設定 = 偽装なし)":"(DUCKNET_DECEPTION unset = no deception)",
 "サンプル攻撃者":"Sample attacker","から見える偽装(隣接窓で必ず別系統):":"sees this deception (adjacent windows always differ):",
 "残":"remaining ","組込":"built-in","カスタム":"custom","停止中":"inactive","注意":"note",
 "(兆候なし)":"(no indicators)","本機":"This host","失敗":"failed",
 "改竄検知":"Tamper detection","直近":"Last",
 /* トースト/確認ダイアログ/汎用保存文言 */
 "キャンセル":"Cancel","実行":"Confirm","保存しました":"Saved",
 "ファイアウォールを更新しました":"Firewall updated","シールドを更新しました":"Shield updated",
 "DLP設定を保存しました":"DLP settings saved","設定を保存しました":"Settings saved",
 "検知の厳格度を変更しました":"Detection strictness changed",
 "このシグネチャを削除しますか?":"Delete this signature?","追加に失敗":"Add failed","削除に失敗":"Delete failed",
 "シグネチャを追加しました":"Signature added","シグネチャを削除しました":"Signature deleted",
 "このレート制限ルールを削除しますか?":"Delete this rate-limit rule?",
 "ルールを削除しました":"Rule deleted","レート制限を追加しました":"Rate limit added",
 "ルールが更新されました。確認して再操作してください":"Rules changed. Review them and try again.",
 "遮断メソッドを保存しました":"Blocked methods saved","保存に失敗":"Save failed",
 "この申立を却下しますか?":"Reject this appeal?","申立を承認しました":"Appeal approved",
 "申立を却下しました":"Appeal rejected","処理に失敗":"Action failed",
 "この接続を拒否しますか?":"Deny this connection?","接続を承認しました":"Connection approved",
 "接続を拒否しました":"Connection denied","BANを解除しました":"IP unbanned","解除に失敗":"Unban failed",
 "このIPをBANしますか?":"Ban this IP?","IPをBANしました":"IP banned","BANに失敗":"Ban failed",
 "このIP/CIDRを拒否ルールに追加しますか?":"Add this IP/CIDR as a deny rule?","ルールを追加しました":"Rule added",
 "拒否ルールを追加しました":"Deny rule added","グローバル遮断を有効にしました":"Global block enabled",
 "グローバル遮断を解除しました":"Global block released",
 /* テーブル検索/ソート */
 "IPで絞り込み":"Filter by IP","IP/種別で絞り込み":"Filter by IP/kind","該当なし":"No matches",
 "残り時間":"Remaining","スコア":"Score",
 /* より実用的な空状態 */
 "カスタムシグネチャなし — 下のフォームから追加できます(組込シグネチャで拾えないパターン用)":
  "No custom signatures yet — add one below to catch patterns the built-in signatures don't cover",
 "承認待ちなし — ゾーンポリシーが「承認待ち」のゾーンで新規接続があるとここに表示されます":
  "No pending connections — new connections appear here when a zone's policy is \"prompt\"",
 "申立なし — BANされた利用者が異議申立を送るとここに表示されます":
  "No appeals yet — requests appear here when a banned user submits one",
 /* 変更履歴(監査ログ) */
 "変更履歴(監査ログ)":"Change history (audit log)","元に戻す":"Revert","変更履歴なし":"No changes yet",
 "元に戻しました":"Reverted","復元に失敗":"Revert failed",
  "変更は適用されましたが、監査ログを保存できませんでした":"The change was applied, but the audit log could not be saved",
 /* チャートのズーム */
 "全期間":"All",
 /* シグネチャの試験(ドライラン) */
 "テスト":"Test","テスト対象の文字列(パス/UA/ヘッダ値など)":"Sample to test (path/UA/header value…)",
 "パターンを入力":"Enter a pattern","エラー":"Error","無効なパターン":"Invalid pattern",
 "一致":"Match","不一致":"No match",
 /* エクスポート */
 "エクスポートしました":"Exported",
 /* 一括操作 */
 "選択なし":"Nothing selected","選択したIPを解除しました":"Unbanned selected IPs",
 "BAN中の全IPを解除します。よろしいですか?":"Unban all currently banned IPs. Are you sure?",
 "すべてのBANを解除しました":"Unbanned all IPs","選択解除":"Unban selected","全解除":"Unban all",
 "すべて承認":"Approve all","すべて拒否":"Deny all",
 "すべての承認待ち接続を承認します。よろしいですか?":"Approve all pending connections. Are you sure?",
 "すべて承認しました":"Approved all","すべて拒否しました":"Denied all",
 "上限接続数/IP(0=無制限)":"Max conns/IP (0=unlimited)","新規接続/秒/IP(0=無制限)":"New conns/sec/IP (0=unlimited)",
 "全体同時接続上限(0=無制限)":"Total conn limit (0=unlimited)","keep-alive を強制切断":"Force keep-alive close",
 /* 詳細分析の節見出し */
 "上位シグネチャ":"Top signatures","イベント種別":"Event kinds",
 /* 送信失敗の説明(何が起きたか+次の一手) */
 "ゲートウェイに接続できません。ゲートウェイが起動しているか確認してください":
  "Cannot reach the gateway. Check that it is running.",
 "認証に失敗しました。ページを再読み込みして管理トークンを入力してください":
  "Authentication failed. Reload the page and enter the admin token.",
 "安全な管理認証を利用できません。localhost または HTTPS で開いてください":
  "Secure admin authentication is unavailable. Open localhost or HTTPS.",
 "管理ポートの応答を確認できません。ゲートウェイの起動状態を確認してください":
  "Cannot verify the admin response. Check that the gateway is running.",
 "操作中に管理トークンが変わりました。もう一度操作してください":
  "The admin token changed during the request. Try the action again.",
 "この開き方では変更を受け付けません。ダッシュボードのアドレスを直接開き直してください":
  "Changes are refused from how this page was opened. Open the dashboard address directly.",
 "ゲートウェイがエラーを返しました。ゲートウェイのログを確認してください":
  "The gateway returned an error. Check the gateway log.",
 "0以上の整数を入力してください":"Enter a whole number of zero or more",
 "1以上の整数を入力してください":"Enter a whole number of one or more",
 "バーストは空欄または正の数を入力してください":"Leave burst empty or enter a positive number",
 "処理中です":"An operation is already in progress","無期限":"Permanent",
 "完了できなかった操作があります":"Some operations did not complete",
 "実行モード":"Operating mode","遮断モード":"Enforce mode","監査モード(検知は記録のみ)":"Audit mode (record detections)",
 "防御停止中":"Protection is off","検知は監査のみ・構文等の拒否は継続":"Detections are audited; malformed traffic is still rejected","遮断モードで動作中":"Enforcement is active",
 "実行時の防御設定":"Runtime defense settings","変更した項目だけをまとめて保存":"Save changed settings together",
 "稼働中に変更できるDDoS / 侵入防御の設定を種類別に表示します。監査モードは検知による遮断を記録に替えます。不正なHTTPや検証できない状態の拒否は継続します。変更は保存するまで適用されません。":"DDoS / intrusion protection settings that can be changed while running are grouped below. Audit mode records detection-based blocks. Malformed HTTP and unverifiable state can still be rejected. Edits apply only after saving.",
 "待受・backend・ワーカー・状態保存先などの起動設定は、起動引数や環境変数で指定します。変更にはこのアプリの停止・起動が必要です。Windows自体の再起動は不要です。本文退避には固定の安全上限があります。":"Startup settings such as listeners, backend, workers, and state directory use command-line arguments or environment variables. Changes require stopping and starting this app. Windows itself does not need to restart. Body staging has fixed safety limits.",
 "設定名・機能で検索":"Search settings or capabilities","設定を検索":"Search settings","変更を保存":"Save changes",
 "変更を破棄して再読込":"Discard edits and reload","開くと設定項目を読み込みます":"Open to load settings",
 "設定項目を読み込み中":"Loading settings","設定項目を取得できませんでした":"Settings could not be loaded",
 "既定値":"Default","変更項目":"Changed settings","設定項目":"Settings","未保存の変更があります":"There are unsaved changes",
 "状態取得後に編集できます":"Editing is available after state refresh","設定の取得に失敗しました。接続を確認してください":"Settings refresh failed. Check the connection.",
 "入力値を確認してください":"Check the input value","保存する変更はありません":"There are no changes to save",
 "詳細設定を保存しました":"Advanced settings saved","保存に失敗しました":"Saving failed",
 "変更は有効ですが、永続化を確認できません。再読込して状態を確認してください":"Changes are active, but persistence is unconfirmed. Reload and review the state.",
 "設定が別の操作で変更されました。再読込して確認してください":"Settings changed elsewhere. Reload and review them.",
 "未保存の変更を破棄して再読込しますか？":"Discard unsaved edits and reload?","設定を再読込しました":"Settings reloaded",
 "JSONの配列を入力してください":"Enter a JSON array","JSONのオブジェクトを入力してください":"Enter a JSON object",
 "JSONのキーが重複しています":"JSON contains a duplicate key","有効なJSONを入力してください":"Enter valid JSON",
 "範囲":"Range","入力例・未適用":"Example input (not applied)",
 "有限の数値を入力してください":"Enter a finite number","整数を入力してください":"Enter a whole number",
 "値が許容範囲外です":"The value is outside its allowed range","設定全体が大きすぎます":"The settings patch is too large",
 "読み込み済みの設定を確認してください":"Review the loaded settings","状態取得中":"Loading state",
 "変更内容を比較":"Compare changes","現在値":"Current value","変更後":"New value","キー":"Key","値":"Value","パス":"Path","レート/秒":"Rate / second","バースト":"Burst","行を追加":"Add row","追加する値":"Value to add",
 "JSONで直接編集（上級）":"Edit JSON directly (advanced)","追加で入力を確定してください":"Use Add to confirm the entered value","正の有限数を入力してください":"Enter a positive finite number","空または重複したキーがあります":"A key is empty or duplicated",
 "行数の上限を超えています":"The row limit was exceeded",
 "全保持(最大600点)":"All retained (up to 600 samples)","要求・遮断レート。矢印キーで値を確認":"Request and block rates. Use arrow keys to inspect values","保持中のデータだけを表示・マウスまたは矢印キーで値を確認":"Only retained data is shown. Inspect values with the pointer or arrow keys","保持データなし":"No retained data",
 "APTスコア":"APT score","兆候":"Signals","ヒット":"Hits","操作":"Actions","窓内要求":"Requests in window","規則的ビーコン":"Regular beacon","低速持続":"Low and slow","時間窓":"Time window","随伴ヘッダ":"Companion headers","プレビューのみ・実通信の記録ではありません":"Preview only; this is not a record of real traffic",
 "上段の個別設定は操作時に即適用されます。この詳細画面の編集は「変更を保存」まで未適用です。同じ項目を別の場所で変更した場合は、競合を確認してから再編集してください。":"The individual controls above apply immediately. Edits here apply only after Save changes. If the same setting changes elsewhere, review the conflict before editing again.",
 "クラスタの子ワーカーを停止し、単一プロセスで動作します":
  "Cluster workers were stopped; the gateway now runs as one process"};
let LANG="ja";try{LANG=localStorage.getItem("fn-lang")||"ja"}catch(e){}
function tr(s){if(LANG!=="en"||s==null)return s;const k=String(s).trim();return JA2EN[k]!==undefined?JA2EN[k]:s;}
function applyStatic(){
 document.documentElement.lang=LANG;
 document.querySelectorAll(".phead h2,.phead .meta:not([id]),.pbody .meta:not([id]),button:not(.iconbtn),#dlpact option,#paranoia option,#shieldmode option,#zonepolicies option,#helpBody h3,#helpBody li,#helpBody p").forEach(el=>{
  if(el.children.length)return;
  if(el.dataset.o===undefined)el.dataset.o=el.textContent.trim();
  el.textContent=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 const labels=[...document.querySelectorAll(".controls label.sw")];
 ["dlp","sech","throttle","subnetdef","forceclose"].forEach(id=>{const e=$(id)&&$(id).closest("label");if(e)labels.push(e);});
 labels.forEach(el=>{const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=" "+(LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o);});
 // アップセル項目(<b>見出し:</b> 本文)。子要素を持つため上の汎用ループはスキップする=個別に訳す。
 document.querySelectorAll(".upsell li").forEach(el=>{
  const b=el.querySelector("b");if(!b)return;
  if(b.dataset.o===undefined)b.dataset.o=b.textContent.trim();
  b.textContent=LANG==="en"?(JA2EN[b.dataset.o]||b.dataset.o):b.dataset.o;
  const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=" "+(LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o);});
 document.querySelectorAll(".sect").forEach(el=>{const tn=el.lastChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 // ソート可能な列見出し(先頭テキストノード + 矢印用span)。.sect と対称(こちらは先頭側)。
 document.querySelectorAll("th.sortable").forEach(el=>{const tn=el.firstChild;if(!tn||tn.nodeType!==3)return;
  if(el.dataset.o===undefined)el.dataset.o=tn.nodeValue.trim();
  tn.nodeValue=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 document.querySelectorAll("input[placeholder]").forEach(el=>{
  if(el.dataset.o===undefined)el.dataset.o=el.placeholder;
  el.placeholder=LANG==="en"?(JA2EN[el.dataset.o]||el.dataset.o):el.dataset.o;});
 if(typeof renderSettingsLabels==="function")renderSettingsLabels();
}
function setLang(l){LANG=l;try{localStorage.setItem("fn-lang",l)}catch(e){}
 $("lang").textContent=l==="en"?"日本語":"EN";
 $("help").title=l==="en"?"Usage / capabilities":"使い方 / できること";
 $("help").setAttribute("aria-label",l==="en"?"Help":"ヘルプ");applyStatic();
 try{refresh()}catch(e){}try{refreshPro()}catch(e){}}
$("lang").onclick=()=>setLang(LANG==="en"?"ja":"en");
/* テーマ */
function setTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem("fn-theme",t)}catch(e){}
 $("theme").textContent=t==="light"?"🌙":"☀️";
 $("theme").title=t==="light"?"ダークに切替":"ライトに切替";try{refreshPro()}catch(e){}}
(function(){let t;try{t=localStorage.getItem("fn-theme")}catch(e){}
 if(!t)t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";setTheme(t);})();
$("theme").onclick=()=>setTheme(document.documentElement.dataset.theme==="light"?"dark":"light");
/* ヘルプ(使い方/できること) */
let helpReturnFocus=null;
function closeHelp(){
 $("helpOverlay").style.display="none";
 document.removeEventListener("keydown",helpKeydown);
 const target=(helpReturnFocus&&helpReturnFocus.isConnected!==false)?helpReturnFocus:$("help");
 helpReturnFocus=null;
 if(target&&typeof target.focus==="function")target.focus();
}
function helpKeydown(e){
 if(e.key==="Escape"){e.preventDefault();closeHelp();}
 else if(e.key==="Tab"){e.preventDefault();$("helpClose").focus();}
}
$("help").onclick=()=>{
 if($("helpOverlay").style.display==="flex")return;
 helpReturnFocus=document.activeElement;
 $("helpOverlay").style.display="flex";applyStatic();
 $("helpClose").focus();
 document.addEventListener("keydown",helpKeydown);
};
$("helpClose").onclick=closeHelp;
$("helpOverlay").onclick=e=>{if(e.target===$("helpOverlay"))closeHelp();};
$("lang").textContent=LANG==="en"?"日本語":"EN";
$("help").title=LANG==="en"?"Usage / capabilities":"使い方 / できること";
$("help").setAttribute("aria-label",LANG==="en"?"Help":"ヘルプ");applyStatic();
/* 送信失敗の説明: 生の例外文字列(TypeError: Failed to fetch)・401 の {"error":"token required"}・
   5xx の内部メッセージをそのまま見せず、何が起きたか+次の一手を平文で返す。 */
function errText(kind,status){
 if(kind==="net")return tr("ゲートウェイに接続できません。ゲートウェイが起動しているか確認してください");
 if(kind==="auth")return tr("認証に失敗しました。ページを再読み込みして管理トークンを入力してください");
 if(kind==="secure")return tr("安全な管理認証を利用できません。localhost または HTTPS で開いてください");
 if(kind==="unverified")return tr("管理ポートの応答を確認できません。ゲートウェイの起動状態を確認してください");
 if(kind==="stale")return tr("操作中に管理トークンが変わりました。もう一度操作してください");
 if(kind==="origin")return tr("この開き方では変更を受け付けません。ダッシュボードのアドレスを直接開き直してください");
 return tr("ゲートウェイがエラーを返しました。ゲートウェイのログを確認してください")+(status?" (HTTP "+status+")":"");
}
// 例外は投げない(呼び出し側は {ok,error} だけ見ればよい)。以前は通信断や本文が JSON でない応答
// (前段プロキシの 502 等)で例外が素通りし、一括操作は途中で止まったまま何も言わなかった。
async function post(p,b){
 if(typeof clusterMutationAllowed==="function"&&!(await clusterMutationAllowed(p,b)))return {ok:false,cancelled:true,error:tr("操作をキャンセルしました")};
 let resp;
 try{resp=await signedRequest("POST",p,JSON.stringify(b));}
 catch(e){if(e&&e.staleToken)return {ok:false,error:errText("stale")};
  if(e&&e.authFail){markAuthError();return {ok:false,authFail:true,error:AUTH_PROBLEM};}
  return {ok:false,error:errText("net")};}
 if(resp.status===401){markAuthError();return {ok:false,authFail:true,error:errText("auth")};}
 if(resp.status===403||resp.status===421)return {ok:false,error:errText("origin")};
 let r=null;try{r=await resp.json();}catch(e){}
 if(!r||typeof r!=="object"||Array.isArray(r)||resp.status>=500)return {ok:false,error:errText("http",resp.status)};
 if(resp.ok&&typeof r.ok!=="boolean")return {ok:false,error:errText("http",resp.status)};
 // 4xx/2xx の r.error はサーバが運用者向けに書いた検証メッセージなのでそのまま見せる
 if(!resp.ok){r.ok=false;if(typeof r.error!=="string"||!r.error)r.error=errText("http",resp.status);}
 if(r.cluster_downgraded===true&&typeof setTelemetryAvailability==="function")setTelemetryAvailability(false);
 return r;
}
// 認証エラー(401 / {ok:false})はネットワーク断とは別物として扱う: トークン不一致等
// (例: サーバ再起動でトークンが再生成された)で接続断ではなくデータが"正常"に見えてしまうのを防ぐ。
function isAuthFail(e){return !!(e&&e.authFail)}
function markAuthError(){TOKEN="";AUTH_KEY_PROMISE=null;
 if(typeof settingsSetAvailable==="function")settingsSetAvailable(false);
 $("conn").className="pill bad";
 $("connt").textContent=tr("認証が必要です");
 $("conn").title=AUTH_PROBLEM||errText("auth");
 if(typeof lockDashboard==="function")lockDashboard(AUTH_PROBLEM||errText("auth"));}
function showAdminAuth(message){
 const overlay=$("adminAuthOverlay"),input=$("adminTokenInput"),button=$("adminUnlock");
 if(!overlay||!input||!button)return;
 if(typeof closeHelp==="function"&&$("helpOverlay").style.display==="flex")closeHelp();
 overlay.style.display="flex";$("appbar").inert=true;
 $("stateview").inert=true;$("stateview").className="wrap state-stale";
 input.value="";input.disabled=false;button.disabled=false;
 $("adminAuthStatus").textContent=message||tr("トークンを入力してロックを解除してください");
 if(typeof input.focus==="function")input.focus();
}
function lockDashboard(message){
 TOKEN="";AUTH_KEY_PROMISE=null;authGeneration++;authSubmitPending=false;
 for(const controller of adminRequestControllers)controller.abort();adminRequestControllers.clear();
 if(typeof message!=="string")AUTH_PROBLEM="";
 refreshGeneration++;refreshProGeneration++;auditRefreshGeneration++;sigRefreshGeneration++;deceptionRefreshGeneration++;
 if(typeof settingsSetAvailable==="function")settingsSetAvailable(false);
 if(typeof cancelActiveConfirm==="function")cancelActiveConfirm();
 $("conn").className="pill bad";$("connt").textContent=tr("認証が必要です");
 showAdminAuth(typeof message==="string"?message:"");
}
async function fetchAdminInstance(){
 const origin=new URL(location.href);
 const local=origin.protocol==="http:"&&["127.0.0.1","localhost","[::1]","::1"].includes(origin.hostname);
 if(!(origin.protocol==="https:"||local))throw new Error("insecure origin");
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
 adminRequestControllers.add(controller);
 try{
 const response=await fetch("/",{method:"GET",cache:"no-store",redirect:"error",credentials:"omit",referrerPolicy:"no-referrer",signal:controller.signal});
 if(response.status!==200)throw new Error("instance unavailable");
 const type=response.headers.get("Content-Type")||"";
 if(!/^text\/html(?:;|$)/i.test(type))throw new Error("invalid instance response");
 const raw=await readAdminResponse(response,2097152);
 const text=new TextDecoder("utf-8",{fatal:true}).decode(raw);
 const matches=[...text.matchAll(/^(?:const|let) AUTH_INSTANCE="([0-9a-f]{32})";$/gm)];
 if(matches.length!==1)throw new Error("invalid instance identity");
 return matches[0][1];
 }finally{clearTimeout(timer);controller.abort();adminRequestControllers.delete(controller);}
}
async function submitAdminAuth(event){
 if(event&&typeof event.preventDefault==="function")event.preventDefault();
 if(authSubmitPending)return;
 const input=$("adminTokenInput"),button=$("adminUnlock"),token=input.value;
 input.value="";
 if(typeof token!=="string"||!token||token.length>4096){$("adminAuthStatus").textContent=tr("管理トークンを入力してください");input.focus();return;}
 const generation=++authGeneration;TOKEN=token;AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
 authSubmitPending=true;input.disabled=true;button.disabled=true;
 $("adminAuthStatus").textContent=tr("認証を確認しています");
 try{
  try{await guardedFetch("/api/state");}
  catch(e){
   if(generation!==authGeneration||e&&e.staleToken)return;
   if(!(e&&e.authFail&&e.authKind==="auth"))throw e;
   const instance=await fetchAdminInstance();if(generation!==authGeneration)return;
   if(instance===AUTH_INSTANCE)throw e;
   AUTH_INSTANCE=instance;AUTH_KEY_PROMISE=null;await guardedFetch("/api/state");
  }
  if(generation!==authGeneration||TOKEN!==token)return;
  $("adminAuthOverlay").style.display="none";$("appbar").inert=false;
  $("adminAuthStatus").textContent="";authSubmitPending=false;input.disabled=false;button.disabled=false;
  await Promise.allSettled([refresh(),refreshPro()]);
 }catch(e){
  if(generation!==authGeneration||e&&e.staleToken)return;
  lockDashboard(e&&e.authFail?(AUTH_PROBLEM||errText("auth")):tr("認証を確認できません。接続先とトークンを確認してください"));
 }finally{
  if(generation===authGeneration){authSubmitPending=false;input.disabled=false;button.disabled=false;}
 }
}
function initializeAdminAuth(){
 $("adminAuthForm").onsubmit=submitAdminAuth;$("adminUnlock").onclick=submitAdminAuth;
 $("adminLock").onclick=()=>lockDashboard();
 document.addEventListener("keydown",event=>{
  if($("adminAuthOverlay").style.display!=="flex")return;
  if(event.key==="Escape"){event.preventDefault();$("adminTokenInput").value="";return;}
  if(event.key==="Tab"){
   event.preventDefault();
   if(authSubmitPending){$("adminAuthDialog").focus();return;}
   const input=$("adminTokenInput"),button=$("adminUnlock");
   (document.activeElement===input?button:input).focus();
  }
 });
 lockDashboard();
}
async function guardedFetch(path){
 const resp=await signedRequest("GET",path);
 let data=null;try{data=await resp.json()}catch(e){}
 if(resp.status===401){const err=new Error("auth");err.authFail=true;err.authKind="auth";throw err;}
 if(!resp.ok||!data||typeof data!=="object"||Array.isArray(data)||("ok" in data&&data.ok!==true))throw new Error("http " + resp.status);
 return data;
}
/* トースト通知: kind は ok/err/info。~3秒で自動消去・手動での×閉じにも対応。 */
function toast(message,kind){
 const wrap=$("toastwrap");if(!wrap)return;
 const el=document.createElement("div");el.className="toast "+(kind||"info");
 const t=document.createElement("span");t.className="ttext";t.textContent=message;
 const x=document.createElement("button");x.className="tclose";x.setAttribute("aria-label","close");x.textContent="×";
 el.appendChild(t);el.appendChild(x);wrap.appendChild(el);
 requestAnimationFrame(()=>el.classList.add("show"));
 const hide=()=>{el.classList.remove("show");setTimeout(()=>el.remove(),220);};
 const timer=setTimeout(hide,3000);
 x.onclick=()=>{clearTimeout(timer);hide();};
}
/* ボタンのビジー状態: 二重送信防止 + 進行中フィードバック(disabled+スピナー)。 */
function busy(btn,on){
 if(!btn)return;
 if(on){if(btn.dataset.obusy===undefined)btn.dataset.obusy="1";btn.disabled=true;btn.classList.add("busy");}
 else{btn.disabled=false;btn.classList.remove("busy");delete btn.dataset.obusy;}
}
/* post + トースト: 成否をトーストで知らせ、btn があれば送信中ビジー表示する。既存の post()
   はそのまま(内部/連続呼び出し用)に残し、ユーザー操作の起点はこちらへ寄せる。post() は失敗を
   平文の {ok:false,error} で返す(念のため例外も捕まえ、生の例外文字列は出さない)。 */
async function postT(p,b,btn,okMsg,errPrefix){
 if(btn&&btn.dataset.obusy!==undefined)return {ok:false,error:tr("処理中です")};
 busy(btn,true);
 let r;try{r=await post(p,b);}catch(e){r={ok:false,error:errText("net")};}
 busy(btn,false);
  if(r&&r.ok&&r.audit_recorded!==false)toast(okMsg||tr("保存しました"),"ok");
  if(!(r&&r.ok))toast((errPrefix?errPrefix+": ":"")+(r&&r.error?r.error:tr("失敗")),"err");
  if(r&&r.cluster_downgraded===true)toast(tr("クラスタの子ワーカーを停止し、単一プロセスで動作します"),"info");
  if(r&&r.audit_recorded===false)toast(tr("変更は適用されましたが、監査ログを保存できませんでした"),"err");
 return r;
}
/* 確認ダイアログ: 破壊的操作向けのスタイル付きモーダル。confirm() の置き換え。 */
let confirmActive=false;
let cancelActiveConfirm=null;
function confirmDialog(message){
 if($("stateview").inert)return Promise.resolve(false);
 if(confirmActive)return Promise.resolve(false);
 confirmActive=true;
 return new Promise(resolve=>{
  const ov=$("confirmOverlay"),ok=$("confirmOk"),cancel=$("confirmCancel");
  const opener=document.activeElement;
  $("confirmMsg").textContent=message;
  ov.style.display="flex";
  const done=v=>{if(!confirmActive)return;confirmActive=false;cancelActiveConfirm=null;
   ov.style.display="none";ok.onclick=null;cancel.onclick=null;ov.onclick=null;
   document.removeEventListener("keydown",onKey);
   const target=(opener&&opener.isConnected!==false)?opener:$("help");
   if(target&&typeof target.focus==="function")target.focus();
   resolve(v);};
  cancelActiveConfirm=()=>done(false);
  const onKey=e=>{
   if(e.key==="Escape"){e.preventDefault();done(false);return;}
   if(e.key==="Tab"){e.preventDefault();
    (document.activeElement===ok?cancel:ok).focus();return;}
   if(e.key==="Enter"&&document.activeElement===ok)done(true);};
  ok.onclick=()=>done(true);cancel.onclick=()=>done(false);
  ov.onclick=e=>{if(e.target===ov)done(false);};
  document.addEventListener("keydown",onKey);
  ok.focus();
 });
}
/* 初回ロードのスケルトン: /api/state 到着前は『0』ではなく『未取得』と分かる表示にする。 */
function showSkeleton(){
 const bar=w=>`<span class="skel-bar" style="width:${w}"></span>`;
 $("cards").innerHTML=Array.from({length:7}).map(()=>
  `<div class="kpi skel"><div class="kn">${bar("44%")}</div><div class="kl">${bar("72%")}</div></div>`).join("");
 $("top").textContent="…";$("apt").textContent="…";
 $("events").innerHTML=`<div class="frow skel"><span class="time">${bar("40px")}</span><span class="desc">${bar("60%")}</span></div>`.repeat(4);
 $("bans").querySelector("tbody").innerHTML=`<tr class="skel"><td colspan="5">${bar("90%")}</td></tr>`.repeat(3);
}
/* 設定の警告(status の warnings)。サーバの message は日本語だけなので、英語表示ではサーバの message_en
   (あれば)か、既知の code ごとの英文を出す。日本語表示と未知の code はサーバの message(無ければ code)。 */
const WARN_EN={
 site_whitelist_empty:()=>"site_mode=whitelist but site_whitelist is empty, so every Host is allowed (a setting saved by an earlier version, kept for compatibility). Add the Hosts to allow to site_whitelist, or set site_mode to off.",
 cfg_enum_normalized:(w,cfg)=>{
  const now=(Array.isArray(w.keys)?w.keys:[]).map(k=>String(k)+"="+String(cfg&&cfg[k]!=null?cfg[k]:"?")).join(", ");
  return "Settings saved by an earlier version were spelled differently (letter case or spaces)"+(now?" and are now read as "+now:"")
   +". Earlier versions did not recognize that spelling; this version applies them as written. Check that this is what you want and change them if not (after you save the settings again, this warning no longer appears from the next start).";}};
function warnText(w,cfg){
 w=w||{};
 if(LANG==="en"){
  if(typeof w.message_en==="string"&&w.message_en)return w.message_en;
  if(Object.prototype.hasOwnProperty.call(WARN_EN,w.code))return WARN_EN[w.code](w,cfg);
 }
 return String(w.message||w.code||"");
}
async function refresh(){
 if(typeof TOKEN!=="undefined"&&!TOKEN)return;
 if(typeof authSubmitPending!=="undefined"&&authSubmitPending)return;
 const generation=++refreshGeneration;
 let s;try{s=await guardedFetch("/api/state")}catch(e){
  if(generation!==refreshGeneration)return;
  $("stateview").inert=true;$("stateview").className="wrap state-stale";
  if(typeof settingsSetAvailable==="function")settingsSetAvailable(false);
  if(typeof cancelActiveConfirm==="function")cancelActiveConfirm();
  if(e&&e.staleToken){$("conn").className="pill bad";$("connt").textContent=tr("認証エラー・再読込");return;}
  if(isAuthFail(e)){markAuthError();}else{$("conn").className="pill bad";$("connt").textContent=tr("接続不可");
   $("conn").title=errText("net");}
  return}
 if(generation!==refreshGeneration)return;
 // /api/state は個別ソースの失敗を {error:"source unavailable"} として 200 で返す。
 // 必須状態が欠けた応答を正常扱いすると、実際は有効な防御を OFF と表示したり、
 // cfg の参照で描画が止まったまま「接続中」を残してしまう。表示を一切更新せず異常を示す。
 const fw=s&&s.firewall,sh=s&&s.shield,dc0=sh&&sh.cfg,m0=s&&s.shield_metrics;
 if(!fw||typeof fw.enabled!=="boolean"||!dc0||typeof dc0.enabled!=="boolean"||
    !m0||typeof m0!=="object"||Array.isArray(m0)||m0.error||
    !Array.isArray(s.events)||!Array.isArray(s.top)||
    (s.telemetry_complete!==undefined&&
     (typeof s.telemetry_complete!=="boolean"||
      s.telemetry_scope!==(s.telemetry_complete?"single":"per-worker")))||
    (s.edge_metrics&&(typeof s.edge_metrics!=="object"||Array.isArray(s.edge_metrics)||
     s.edge_metrics.error))){
  if(s&&!Array.isArray(s.events)){
   $("leaks").textContent=tr("状態取得不可");$("events").textContent=tr("状態取得不可");}
  if(s&&!Array.isArray(s.top))$("top").textContent=tr("状態取得不可");
  $("stateview").inert=true;$("stateview").className="wrap state-stale";
  if(typeof settingsSetAvailable==="function")settingsSetAvailable(false);
  if(typeof cancelActiveConfirm==="function")cancelActiveConfirm();
  $("conn").className="pill bad";$("connt").textContent=tr("状態取得不可");
  $("conn").title=errText("http");return;
 }
 $("stateview").inert=false;$("stateview").className="wrap";
 const partialTelemetry=s.telemetry_complete===false&&s.telemetry_scope==="per-worker";
 if(typeof setTelemetryAvailability==="function")setTelemetryAvailability(partialTelemetry);
 if(typeof renderFirewallSnapshot==="function")renderFirewallSnapshot(s.firewall);
 $("conn").className=partialTelemetry?"pill warn":"pill ok";
 $("connt").textContent=tr(partialTelemetry?"接続中・親ワーカーのみ":"接続中");
 $("conn").title=partialTelemetry?tr("複数ワーカーの集計値・イベントは親ワーカー分のみです。"):"";
 if(!$("fw").disabled)$("fw").checked=s.firewall.enabled;
 if(!$("sh").disabled)$("sh").checked=s.shield.cfg.enabled;
 if(!$("shieldmode").disabled)$("shieldmode").value=s.shield.cfg.mode||"enforce";
 $("modestat").textContent=tr(!s.shield.cfg.enabled?"防御停止中":s.shield.cfg.mode==="audit"?"検知は監査のみ・構文等の拒否は継続":"遮断モードで動作中");
 $("modestat").className="badge "+(!s.shield.cfg.enabled||s.shield.cfg.mode==="audit"?"warn":"");
 // 直すべき設定(旧版が保存した site whitelist+空 など)を警告バッジで出す。本文は必ず esc() を通す
 // 本文は表示言語に合わせて差し替えてから描く(warnText)
 const W=(s.shield.warnings||[]).map(w=>Object.assign({},w,{message:warnText(w,s.shield.cfg)}));
 $("cfgwarn").style.display=W.length?"":"none";
 $("cfgwarn").innerHTML=W.map(w=>"⚠ "+esc(w.message||w.code||"")).join("<br>");
 const m=s.shield_metrics;
 const em=s.edge_metrics||{};
 $("cards").innerHTML=[["要求",m.requests,"i-blue"],["許可",m.allow,"i-green"],["スロットル",m.throttle,"i-amber"],
   ["ブロック",m.block,"i-red"],["BAN中",m.active_bans,"i-red"],
   ["漏洩",m.dlp_leak,"i-red"],["バックエンド不通",em.backend_unreachable||0,"i-red"]]
   .map(([l,n,a])=>`<div class="kpi ${a}"><div class="kn">${nf(n)}</div><div class="kl">${esc(tr(l)+(partialTelemetry?" · "+tr("親ワーカーのみ"):""))}</div></div>`).join("");
 // 出口DLP: 設定の反映 + 漏洩イベントの抽出表示
 // dlp_enabled はサブフラグに過ぎず、実際の稼働は本体(dc.enabled)とのAND(pipeline.py dlp_active()と同一条件) —
 // 本体OFF中に「有効」と表示して安心させない(#5)。
 const dc=s.shield.cfg;if(!$("dlp").disabled)$("dlp").checked=!!dc.dlp_enabled;
 if(typeof updateSettingsSnapshot==="function")updateSettingsSnapshot(dc,s.shield.config_revision);
 if(!$("dlpact").disabled)$("dlpact").value=dc.dlp_action||"audit";
 const dlpOn=!!dc.enabled&&!!dc.dlp_enabled;
 const dlpEffective=dc.mode==="audit"?"audit":(dc.dlp_action||"audit");
 $("dlpstat").textContent=tr(dlpOn?"有効":"無効")+(dlpOn?" · "+tr(dlpEffective==="block"?"遮断モード":"監査モード(検知は記録のみ)"):"")+" · "+tr("漏洩")+" "+nf(m.dlp_leak||0);
 // 詳細防御(評価): 応答ヘッダ / paranoia
 if(!$("sech").disabled)$("sech").checked=!!dc.sec_headers_enabled;
 if(!$("paranoia").disabled)$("paranoia").value=String(dc.paranoia||1);
 $("advstat").textContent=[dc.sec_headers_enabled&&tr("ヘッダ"),"P"+(dc.paranoia||1)].filter(Boolean).join(" · ");
 // 改竄検知の可視化(#55): 件数+直近イベントをダッシュボードに要約表示(READMEの記載どおり実物を出す)
 const tp=m.tamper||{};
 const tpCount=nf(tp.count||0)+(LANG==="en"?"":"件");
 const tpLast=tp.last?((tp.last.kind||"")+" "+tm(tp.last.ts)):tr("(なし)");
 $("tamperstat").textContent=tr("改竄検知")+": "+tpCount+" · "+tr("直近")+": "+tpLast;
 // WAF 任意(高FP)シグネチャのトグル一覧
 const OPTL={ssti:"SSTI(テンプレート注入 {{…}})",ssrf_internal:"内部SSRF(localhost/内部IP)",redirect:"オープンリダイレクト(=//)"};
 const oset=dc.optional_sigs||{};
 if(![...document.querySelectorAll("#optsigs input")].some(input=>input.disabled))$("optsigs").innerHTML=(s.shield.optional_signatures||[]).map(n=>
   `<div class="row"><label class="sw"><input type="checkbox" class="toggle" ${oset[n]?"checked":""}`
   +` data-name="${esc(n)}" onchange="postT('/api/shield/optional_sig',{name:this.dataset.name,on:this.checked},this,tr('設定を保存しました')).then(refresh)">`
   +` ${esc(tr(OPTL[n]||n))}</label></div>`).join("")||'<div class="empty">'+tr("なし")+'</div>';
 // パス別レート制限(per-path token bucket): 現在のルール一覧 + 削除
 curPathLimits=dc.path_limits||[];
 $("prlmeta").textContent=curPathLimits.length?(curPathLimits.length+" "+tr("ルール")):tr("無効");
 $("pathlimits").querySelector("tbody").innerHTML=curPathLimits.map((r,i)=>
   `<tr><td><span class="num">${esc(r.path)}</span></td><td class="num">${r.rate}/s</td>`
   +`<td class="num">burst ${r.burst}</td>`
   +`<td><button class="ghost" onclick="removePathLimit(${i},this)">${tr("削除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("ルールなし")+'</td></tr>';
 // レート/メソッド/分散(運用): #24/#25/#26 のトグルと値。free-text は編集中クロバー回避。
 if(!$("throttle").disabled)$("throttle").checked=dc.throttle_response!==false;
 if(!$("subnetdef").disabled)$("subnetdef").checked=!!dc.subnet_defense;
 setIfBlur("retryaft",String(dc.throttle_retry_after!=null?dc.throttle_retry_after:1));
 setIfBlur("subthr",String(dc.subnet_threshold!=null?dc.subnet_threshold:8));
 setIfBlur("blockmeth",(dc.blocked_methods||[]).join(","));
 // 上限接続数/IP・新規接続レート/IP・全体同時接続上限・keep-alive強制切断: pipeline.py の
 // _DEFAULTS には存在するが元々ダッシュボードUIが無かった4項目(#4)。汎用 /api/shield/config
 // を再利用する。conn_rate_per_ip 等は int 既定値のため set_config() の型チェックが float を
 // 黙って弾く — parseFloat ではなく parseInt を使うこと。
 setIfBlur("maxconnip",String(dc.max_conn_per_ip!=null?dc.max_conn_per_ip:0));
 setIfBlur("connrateip",String(dc.conn_rate_per_ip!=null?dc.conn_rate_per_ip:0));
 setIfBlur("maxtotalconn",String(dc.max_total_conn!=null?dc.max_total_conn:20000));
 if(!$("forceclose").disabled)$("forceclose").checked=dc.force_conn_close!==false;
 $("opsstat").textContent=[dc.throttle_response!==false&&"429",dc.subnet_defense&&tr("分散"),
   (dc.blocked_methods||[]).length+tr("メソッド")].filter(Boolean).join(" · ");
 if(!partialTelemetry)try{const sn=await guardedFetch("/api/shield/subnet");
  if(generation!==refreshGeneration)return;
  $("subnetmeta").textContent=tr("追跡")+" "+nf(sn.tracked_subnets||0)+" · hot "+nf(sn.hot_subnets||0)
   +" · "+tr("遮断メソッド")+": "+((dc.blocked_methods||[]).join(", ")||tr("なし"));}catch(e){
   if(generation!==refreshGeneration)return;
   if(isAuthFail(e))markAuthError();}
 // シグネチャ別ヒット / トラフィック構成(累積・テレメトリ)= 横棒グラフ(共通ヘルパ)
 const si=Object.entries(m.sig_hits||{});
 $("sigmetatop").textContent=tr("計")+" "+nf(si.reduce((a,x)=>a+x[1],0))+" · "+tr("種別")+" "+si.length;
 $("sigbars").innerHTML=barHTML(si,10);
 $("zonebars").innerHTML=barHTML(Object.entries(m.zone_hits||{}),6);
 $("actbars").innerHTML=barHTML([["allow",m.allow],["throttle",m.throttle],
   ["block",m.block]],5);
 $("methbars").innerHTML=barHTML(Object.entries(m.method_hits||{}),8);
 // 漏洩した秘密種別の内訳(累積・テレメトリ)
 const lkm=m.dlp_kinds||{},lki=Object.entries(lkm).sort((a,b)=>b[1]-a[1]).slice(0,6);
 $("leakkinds").innerHTML=lki.map(([k,v])=>`<span class="badge danger">${esc(k)} ${v}</span>`).join(" ");
 const lk=(s.events||[]).filter(e=>e.kind==="dlp_leak");
 $("leaks").innerHTML=lk.slice(-30).reverse().map(e=>
   `<div class="frow"><span class="time">${tm(e.ts)}</span><span class="badge danger">leak</span>`
   +`<span class="desc num">${esc(e.ip||"")}</span>`
   +`<span class="desc">${esc((e.kinds||[]).join(", "))}</span></div>`).join("")
   ||'<div class="empty">'+tr(dlpOn?"漏洩なし":"DLP 無効")+'</div>';
 curBans=s.shield.bans||[];renderBans();
 if(typeof renderThreatTable==="function")renderThreatTable("top",s.top||[],false);
 if(typeof refreshEvents==="function")await refreshEvents(()=>generation===refreshGeneration);
 else{curEvents=s.events||[];renderEvents();}
 if(generation!==refreshGeneration)return;
 // ゾーン policy=prompt の保留接続(#2): アピール一覧と同じ承認/拒否UXで、行き止まりを解消
 const pend=(s.firewall||{}).pending||[];curPending=pend;
 const remembered=new Set([...document.querySelectorAll("#fwpending input[data-pid]")]
  .filter(cb=>cb.checked).map(cb=>cb.dataset.pid));
 $("pendingmeta").textContent=pend.length?String(pend.length):"—";
 $("fwpending").querySelector("tbody").innerHTML=pend.map(p=>
   `<tr><td class="num">${esc(p.ip)}</td><td><span class="badge info">${esc(p.zone)}</span></td>
   <td class="num">${tm(p.ts)}</td>
   <td><label class="meta" style="font-weight:normal;cursor:pointer"><input type="checkbox" id="rem_${esc(p.id)}" data-pid="${esc(p.id)}" ${remembered.has(p.id)?"checked":""}> ${tr("常時許可として記憶")}</label>
   <button data-pid="${esc(p.id)}" onclick="resolvePending(this.dataset.pid,true,this)">${tr("承認")}</button>
   <button class="red" data-pid="${esc(p.id)}" onclick="resolvePending(this.dataset.pid,false,this)">${tr("却下")}</button></td></tr>`).join("")
   ||'<tr><td colspan="4" class="empty">'+tr("承認待ちなし — ゾーンポリシーが「承認待ち」のゾーンで新規接続があるとここに表示されます")+'</td></tr>';
}
/* BAN中IPテーブル: 検索/ソート/一括選択。curBans はサーバから取得した最新配列。 */
let curBans=[],banSort={key:null,dir:1},banSel=new Set(),lastBanRows=[];
function renderBans(){
 const active=new Set(curBans.map(b=>b.ip));
 for(const ip of banSel)if(!active.has(ip))banSel.delete(ip);
 const q=($("bansearch").value||"").toLowerCase();
 let rows=curBans.filter(b=>!q||String(b.ip).toLowerCase().includes(q));
 if(banSort.key){
  rows=rows.slice().sort((a,b)=>{
   const av=banSort.key==="score"?a.score:(a.remain_sec===-1?Infinity:a.remain_sec);
   const bv=banSort.key==="score"?b.score:(b.remain_sec===-1?Infinity:b.remain_sec);
   return av===bv?0:((av||0)-(bv||0))*banSort.dir;
  });
 }
 lastBanRows=rows;
 $("bansmeta").textContent=curBans.length?(rows.length+"/"+curBans.length):"—";
 $("bans").querySelector("tbody").innerHTML=rows.map(b=>
   `<tr><td><input type="checkbox" class="bansel" data-ip="${esc(b.ip)}" ${banSel.has(b.ip)?"checked":""}></td>`
   +`<td class="num">${esc(b.ip)}</td><td class="num">${b.remain_sec===-1?esc(tr("無期限")):esc(tr("残"))+Math.round(b.remain_sec)+"s"}</td>`
   +`<td><span class="badge ${b.score>40?"danger":"warn"}">score ${b.score}</span></td>`
   // IP は data 属性で渡す(#1/#40: onclick の JS 文字列に埋めると属性の実体参照復号で
   // &#39; が ' に戻る。IPv6 スコープ ID は引用符ごと ip_address() を通るため保存型 XSS になった)。
   +`<td><button class="ghost" data-ip="${esc(b.ip)}" onclick="unban(this.dataset.ip,this)">${tr("解除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="5" class="empty">'+tr(curBans.length?"該当なし":"BAN なし")+'</td></tr>';
 document.querySelectorAll(".bansel").forEach(cb=>cb.onchange=()=>{
  if(cb.checked)banSel.add(cb.dataset.ip);else banSel.delete(cb.dataset.ip);
  $("banall").checked=rows.length>0&&rows.every(b=>banSel.has(b.ip));
 });
 $("banall").checked=rows.length>0&&rows.every(b=>banSel.has(b.ip));
}
$("bans").querySelector("thead").addEventListener("click",e=>{
 const th=e.target.closest("th.sortable");if(!th)return;
 const k=th.dataset.sort;
 banSort.dir=(banSort.key===k)?-banSort.dir:-1;
 banSort.key=k;
 document.querySelectorAll("#bans th.sortable .sortarrow").forEach(s=>s.textContent="");
 th.querySelector(".sortarrow").textContent=banSort.dir<0?"▼":"▲";
 renderBans();
});
function toggleAllBans(checked){
 lastBanRows.forEach(b=>{if(checked)banSel.add(b.ip);else banSel.delete(b.ip);});
 renderBans();
}
async function unbanSelected(btn){
 if(btn&&btn.dataset.obusy!==undefined)return;
 const ips=[...banSel];
 if(!ips.length){toast(tr("選択なし"),"info");return;}
 busy(btn,true);
  const fails=[];let auditWarnings=0;for(const ip of ips){const r=await post("/api/shield/unban",{ip});
   if(r&&r.cancelled){busy(btn,false);toast(tr("操作をキャンセルしました"),"info");return;}
   if(!(r&&r.ok))fails.push(r);else banSel.delete(ip);
   if(r&&r.audit_recorded===false)auditWarnings++;}
 busy(btn,false);
  bulkReport(fails,ips.length,tr("選択したIPを解除しました"),auditWarnings);
 refresh();
}
/* 一括操作の結果: 1件でも失敗したら成功とは言わない(以前は全件失敗でも「解除しました」)。
   件数と最初の理由(post() が平文にしたもの)を出す。 */
function bulkReport(fails,n,okMsg,auditWarnings=0){
  if(!fails.length&&!auditWarnings){toast(okMsg,"ok");return;}
  if(fails.length)toast(tr("完了できなかった操作があります")+" ("+fails.length+"/"+n+"): "+((fails[0]&&fails[0].error)||tr("失敗")),"err");
  if(auditWarnings)toast(tr("変更は適用されましたが、監査ログを保存できませんでした")+" ("+auditWarnings+"/"+n+")","err");
}
async function unbanAll(btn){
 if(btn&&btn.dataset.obusy!==undefined)return;
 const ips=curBans.map(b=>b.ip);if(!ips.length)return;
 if(!(await confirmDialog(tr("BAN中の全IPを解除します。よろしいですか?"))))return;
 busy(btn,true);
  const fails=[];let auditWarnings=0;for(const ip of ips){const r=await post("/api/shield/unban",{ip});
   if(r&&r.cancelled){busy(btn,false);toast(tr("操作をキャンセルしました"),"info");return;}
   if(!(r&&r.ok))fails.push(r);else banSel.delete(ip);
   if(r&&r.audit_recorded===false)auditWarnings++;}
 busy(btn,false);
  bulkReport(fails,ips.length,tr("すべてのBANを解除しました"),auditWarnings);
 refresh();
}
/* 攻撃イベント: 検索フィルタ。curEvents はサーバから取得した最新配列。 */
let curEvents=[];
let curFirewallRules=[],curFirewallPolicy={},eventsRefreshGeneration=0;
var clusterTelemetryPartial=false,clusterMutationPending=false;
const nodeActionsPending=new Set();
function setTelemetryAvailability(partial){
 clusterTelemetryPartial=!!partial;
 const warning=$("clusterwarning");if(warning){warning.style.display=partial?"":"none";
  warning.textContent=tr("防御設定の変更は子ワーカーを停止して単一プロセスへ切り替えます");}
 for(const id of ["chart","netmap","events","bans","top","apt","analysis","appeals"]){
  const target=$(id),panel=target&&typeof target.closest==="function"?target.closest(".panel"):null;
  if(!panel)continue;const body=panel.querySelector(".pbody");if(body)body.hidden=!!partial;
  let note=panel.querySelector(".cluster-panel-note");
  if(!note){note=document.createElement("p");note.className="meta cluster-panel-note";panel.appendChild(note);}
  note.hidden=!partial;note.textContent=tr("クラスタ稼働中はワーカー別集計のため、このパネルを非表示にしています");
 }
}
async function clusterMutationAllowed(path,body){
 if(!clusterTelemetryPartial||path==="/api/shield/sig_test")return true;
 if(clusterMutationPending)return false;
 clusterMutationPending=true;
 try{return await confirmDialog(tr("クラスタの子ワーカーを停止し、単一プロセスで変更を適用します。続行しますか?"));}
 finally{clusterMutationPending=false;}
}
function renderFirewallSnapshot(firewall){
 if(!firewall||!firewall.policy||!Array.isArray(firewall.rules))return;
 curFirewallRules=firewall.rules;curFirewallPolicy=firewall.policy;
 for(const zone of ["loopback","private","public"]){const input=$("zone_"+zone);
  if(input&&!input.disabled)input.value=curFirewallPolicy[zone]||"deny";}
 renderFirewallRules();
}
function renderFirewallRules(){
 const q=($("aclsearch").value||"").toLowerCase();
 const rows=curFirewallRules.filter(r=>!q||[r.net,r.action,r.note].some(v=>String(v||"").toLowerCase().includes(q)));
 $("aclmeta").textContent=rows.length+"/"+curFirewallRules.length;
 $("aclrows").innerHTML=rows.map(r=>`<tr><td class="num">${esc(r.net)}</td><td>${esc(tr(r.action==="allow"?"許可":r.action==="deny"?"拒否":"承認待ち"))}</td>`
  +`<td>${esc(r.note||"")}</td><td><button class="ghost" data-net="${esc(r.net)}" onclick="removeFirewallRule(this.dataset.net,this)">${esc(tr("削除"))}</button></td></tr>`).join("")
  ||'<tr><td colspan="4" class="empty">'+esc(tr(curFirewallRules.length?"該当なし":"登録ルールなし"))+'</td></tr>';
}
async function removeFirewallRule(net,btn){
 if(btn&&btn.dataset.obusy!==undefined)return;
 const old=curFirewallRules.find(r=>r.net===net);if(!old)return;
 const snapshot=JSON.stringify(old);
 if(!(await confirmDialog(tr("このACLルールを削除しますか?")+" "+net)))return;
 if(!curFirewallRules.some(r=>r.net===net&&JSON.stringify(r)===snapshot)){toast(tr("ルールが更新されました。確認して再操作してください"),"err");return;}
 await postT("/api/firewall/rule",{op:"remove",net},btn,tr("ルールを削除しました"),tr("削除に失敗"));
 await refresh();
}
async function setFirewallPolicy(zone,input){
 if(!["loopback","private","public"].includes(zone)||!input||input.dataset.obusy!==undefined)return;
 const action=input.value,previous=curFirewallPolicy[zone];
 if(!["allow","deny","prompt"].includes(action))return;
 if(action===previous)return;
 input.disabled=true;
 try{
  if(!(await confirmDialog(tr("このゾーンの既定動作を変更しますか?")+" "+zone+": "+previous+" → "+action))){input.value=curFirewallPolicy[zone]||previous;return;}
  if(curFirewallPolicy[zone]!==previous){input.value=curFirewallPolicy[zone];toast(tr("ルールが更新されました。確認して再操作してください"),"err");return;}
  await postT("/api/firewall/policy",{zone,action},input,tr("ゾーンポリシーを保存しました"),tr("保存に失敗"));
 }finally{input.disabled=false;await refresh();}
}
async function refreshEvents(current=()=>true){
 const generation=++eventsRefreshGeneration,valid=()=>current()&&generation===eventsRefreshGeneration;
 if(clusterTelemetryPartial){curEvents=[];renderEvents();return;}
 try{
  const data=await guardedFetch("/api/shield/events");if(!valid())return;
  if(!Array.isArray(data.events))throw new Error("invalid events");
  curEvents=data.events;renderEvents();
 }catch(e){if(!valid())return;curEvents=[];$("events").textContent=tr("状態取得不可");$("eventsmeta").textContent=tr("状態取得不可");
  if(isAuthFail(e))markAuthError();}
}
function renderEvents(){
 const q=($("eventsearch").value||"").toLowerCase();
 const rows=curEvents.filter(e=>!q||Object.entries(e).some(([k,v])=>(k+" "+(typeof v==="object"?JSON.stringify(v):String(v==null?"":v))).toLowerCase().includes(q)));
 const open=new Set([...document.querySelectorAll("#events details[open]")].map(el=>el.dataset.eventkey));
 $("eventsmeta").textContent=(curEvents.length?rows.length+"/"+curEvents.length:"0")+" · "+tr("直近100件まで");
 $("events").innerHTML=rows.slice().reverse().map(e=>{
   const key=JSON.stringify(e);
   const detail=Object.entries(e).map(([k,v])=>`<tr><th>${esc(k)}</th><td class="num" style="overflow-wrap:anywhere">${esc(typeof v==="object"?JSON.stringify(v):String(v==null?"":v))}</td></tr>`).join("");
   return `<details data-eventkey="${esc(key)}" ${open.has(key)?"open":""}><summary class="frow"><span class="time">${esc(tm(e.ts))}</span><span class="badge ${sev(e.kind)}">${esc(e.kind)}</span>`
   +`<span class="desc num">${esc(e.ip||"")}</span><span class="desc">${esc(e.reason||e.signature||e.rule||e.note||"")}</span>`
   +(e.score!==undefined?`<span class="badge">score ${esc(e.score)}</span>`:"")+(e.would?`<span class="badge warn">would: ${esc(e.would)}</span>`:"")+`</summary>`
   +`<div class="pbody"><div class="meta">${esc(tr("検知の詳細"))}</div><table>${detail}</table>`
   +(e.ip?`<div class="row"><button data-ip="${esc(e.ip)}" onclick="banFromEvent(this.dataset.ip,this)">BAN</button>`
   +`<button class="ghost" data-ip="${esc(e.ip)}" onclick="filterEventsForIP(this.dataset.ip)">${esc(tr("イベントで絞込"))}</button>`
   +`<button class="ghost" data-ip="${esc(e.ip)}" onclick="filterBansForIP(this.dataset.ip)">${esc(tr("BAN表で絞込"))}</button></div>`:"")+`</div></details>`;
  }).join("")
   ||'<div class="empty">'+tr(curEvents.length?"該当なし":"イベントなし")+'</div>';
}
function filterEventsForIP(ip){
 $("eventsearch").value=ip;renderEvents();const el=$("events");if(el&&typeof el.scrollIntoView==="function")el.scrollIntoView({block:"nearest"});
}
function filterBansForIP(ip){
 $("bansearch").value=ip;renderBans();const el=$("bans");if(el&&typeof el.scrollIntoView==="function")el.scrollIntoView({block:"nearest"});
}
async function banFromEvent(ip,btn){
 return runNodeAction(ip,false,btn);
}
async function runNodeAction(ip,banned,btn){
 if(!ip||nodeActionsPending.has(ip))return;
 nodeActionsPending.add(ip);
 try{
  if(!banned&&!(await confirmDialog(tr("このIPをBANしますか?")+" "+ip)))return;
  const result=await postT(banned?"/api/shield/unban":"/api/shield/ban",{ip},btn,tr(banned?"BANを解除しました":"IPをBANしました"));
  if(result&&result.ok){await refresh();await refreshPro();}
  return result;
 }finally{nodeActionsPending.delete(ip);}
}
/* 承認待ち接続の一括操作: 承認は影響が大きいため確認、拒否は安全側なので確認なし。 */
let curPending=[];
async function approveAllPending(btn){
 if(btn&&btn.dataset.obusy!==undefined)return;
 const ids=curPending.map(p=>p.id);if(!ids.length)return;
 if(!(await confirmDialog(tr("すべての承認待ち接続を承認します。よろしいですか?"))))return;
 busy(btn,true);
  const fails=[];let auditWarnings=0;for(const id of ids){const r=await post("/api/firewall/resolve",{id,approve:true});
   if(r&&r.cancelled){busy(btn,false);toast(tr("操作をキャンセルしました"),"info");return;}
   if(!(r&&r.ok))fails.push(r);if(r&&r.audit_recorded===false)auditWarnings++;}
 busy(btn,false);
  bulkReport(fails,ids.length,tr("すべて承認しました"),auditWarnings);
 refresh();
}
async function denyAllPending(btn){
 if(btn&&btn.dataset.obusy!==undefined)return;
 const ids=curPending.map(p=>p.id);if(!ids.length)return;
 busy(btn,true);
  const fails=[];let auditWarnings=0;for(const id of ids){const r=await post("/api/firewall/resolve",{id,approve:false});
   if(r&&r.cancelled){busy(btn,false);toast(tr("操作をキャンセルしました"),"info");return;}
   if(!(r&&r.ok))fails.push(r);if(r&&r.audit_recorded===false)auditWarnings++;}
 busy(btn,false);
  bulkReport(fails,ids.length,tr("すべて拒否しました"),auditWarnings);
 refresh();
}
$("fw").onchange=e=>postT("/api/firewall/toggle",{on:e.target.checked},e.target,tr("ファイアウォールを更新しました")).then(refresh);
$("sh").onchange=e=>postT("/api/shield/toggle",{on:e.target.checked},e.target,tr("シールドを更新しました")).then(refresh);
$("shieldmode").onchange=e=>postT("/api/shield/config",{mode:e.target.value},e.target,tr("設定を保存しました")).then(refresh);
$("dlp").onchange=e=>postT("/api/shield/config",{dlp_enabled:e.target.checked},e.target,tr("DLP設定を保存しました")).then(refresh);
$("dlpact").onchange=e=>postT("/api/shield/config",{dlp_action:e.target.value},e.target,tr("DLP設定を保存しました")).then(refresh);
$("sech").onchange=e=>postT("/api/shield/config",{sec_headers_enabled:e.target.checked},e.target,tr("設定を保存しました")).then(refresh);
$("paranoia").onchange=e=>postT("/api/shield/paranoia",{level:Number(e.target.value)},e.target,tr("検知の厳格度を変更しました")).then(refresh);
$("throttle").onchange=e=>postT("/api/shield/config",{throttle_response:e.target.checked},e.target,tr("設定を保存しました")).then(refresh);
$("retryaft").onchange=e=>saveIntegerConfig(e.target,"throttle_retry_after",0);
$("subnetdef").onchange=e=>postT("/api/shield/config",{subnet_defense:e.target.checked},e.target,tr("設定を保存しました")).then(refresh);
$("subthr").onchange=e=>saveIntegerConfig(e.target,"subnet_threshold",1);
$("maxconnip").onchange=e=>saveIntegerConfig(e.target,"max_conn_per_ip",0);
$("connrateip").onchange=e=>saveIntegerConfig(e.target,"conn_rate_per_ip",0);
$("maxtotalconn").onchange=e=>saveIntegerConfig(e.target,"max_total_conn",0);
$("forceclose").onchange=e=>postT("/api/shield/config",{force_conn_close:e.target.checked},e.target,tr("設定を保存しました")).then(refresh);
function saveIntegerConfig(input,key,min){
 const raw=input.value.trim(),value=Number(raw);
 if(!raw||!Number.isSafeInteger(value)||value<min){toast(tr(min?"1以上の整数を入力してください":"0以上の整数を入力してください"),"err");return;}
 return postT("/api/shield/config",{[key]:value},input,tr("設定を保存しました")).then(refresh);
}
/* チャートの時間範囲ズーム: 既にクライアントが取得済みの /api/series 配列を切り出すだけ。
   サーバ側の保持期間(pipeline._series・約10分)より長い範囲を要求することはしない。 */
let chartWindow=Infinity;
function setChartWindow(sec){
 if(![60,300,600,Infinity].includes(sec))return;chartWindow=sec;
 document.querySelectorAll("#chartzoom button").forEach(b=>
  b.classList.toggle("active",(sec===Infinity&&b.dataset.sec==="all")||Number(b.dataset.sec)===sec));
 try{refreshPro()}catch(e){}
}
async function refreshPro(){
 if(typeof TOKEN!=="undefined"&&!TOKEN)return;
 if(typeof authSubmitPending!=="undefined"&&authSubmitPending)return;
 const generation=++refreshProGeneration;
 const current=()=>generation===refreshProGeneration;
 if(typeof clusterTelemetryPartial!=="undefined"&&clusterTelemetryPartial){
  refreshSigs(current);refreshDeception(current);refreshAudit(current);return;
 }
 const get=async path=>{const value=await guardedFetch(path);
  if(!current())throw new Error("stale refresh");return value;};
 try{let s=(await get("/api/series")).series||[];
  if(chartWindow!==Infinity&&s.length){const cutoff=s[s.length-1].t-chartWindow;s=s.filter(x=>x.t>=cutoff);}
  drawChart(s);
  drawSpark("leaktrend",s.map(x=>x.dlp_leak||0));
  drawSpark("sigtrend",s.map(x=>x.sig_total||0));
  drawSpark("pubtrend",s.map(x=>x.pub||0));}catch(e){if(!current())return;if(isAuthFail(e))markAuthError();}
 try{const ap=(await get("/api/appeals")).appeals||[];
  $("appeals").querySelector("tbody").innerHTML=ap.map(a=>
   `<tr><td class="num">${esc(a.ip)}</td><td><span class="badge ${a.status==="pending"?"warn":"muted"}">${esc(a.status)}</span></td>
   <td>${esc((a.reason||"").slice(0,40))}</td>
   <td>${a.status==="pending"?`<button data-ip="${esc(a.ip)}" onclick="resolveAppeal(this.dataset.ip,true,this)">${tr("承認")}</button>
   <button class="red" data-ip="${esc(a.ip)}" onclick="resolveAppeal(this.dataset.ip,false,this)">${tr("却下")}</button>`:""}</td></tr>`
  ).join("")||'<tr><td colspan="4" class="empty">'+tr("申立なし — BANされた利用者が異議申立を送るとここに表示されます")+'</td></tr>';}catch(e){if(!current())return;if(isAuthFail(e))markAuthError();}
 try{const an=await get("/api/analysis");
  $("analysis").innerHTML=analysisHTML(an);}catch(e){if(!current())return;if(isAuthFail(e))markAuthError();}
 try{const ap=await get("/api/apt");
  if(typeof renderThreatTable==="function")renderThreatTable("apt",ap.suspects||[],true);}catch(e){if(!current())return;if(isAuthFail(e))markAuthError();}
 try{drawMap(await get("/api/nodes"));}catch(e){if(!current())return;if(isAuthFail(e))markAuthError();}
 refreshSigs(current);
 refreshDeception(current);
 refreshAudit(current);
}
/* 詳細分析: 以前は /api/analysis の JSON を JSON.stringify で <pre> へ流していた(読めず、次に何を
   見ればいいか分からない)。見出し付きの節に描く。シグネチャ名・ゾーン・イベント種別は外部入力
   由来になり得るので、値は必ず esc() を通す(onclick 等の JS 文字列へは一切入れない)。 */
const ANA_ACT=[["allow","許可"],["throttle","スロットル"],["block","ブロック"]];
function analysisHTML(an){
 an=an||{};const A=an.actions||{},req=Number(A.requests)||0;
 const sec=(t,body)=>`<div><div class="meta" style="margin:2px 0 6px">${esc(tr(t))}</div>${body}</div>`;
 const row=(l,v,pct)=>`<div class="sbar"><span class="sbl">${esc(tr(l))}</span><span class="sbt">`
   +(pct==null?"":`<span class="sbf" style="width:${pct}%"></span>`)+`</span><span class="sbn num">${esc(nf(v))}</span></div>`;
 const acts=row("要求",req,null)+ANA_ACT.filter(([k])=>k in A).map(([k,l])=>{const v=Number(A[k])||0;
   return row(l,v,req?Math.min(100,Math.round(v/req*100)):0);}).join("");
 const zones=barHTML(Object.entries(an.by_zone||{}).map(([k,v])=>[k,Number(v)||0]),8);
 const sigs=(Array.isArray(an.top_signatures)?an.top_signatures:[]).filter(Array.isArray).slice(0,10).map((x,i)=>
   `<div class="frow"><span class="cnt">${i+1}.</span><span class="desc num">${esc(x[0])}</span>`
   +`<span class="cnt">×${esc(nf(Number(x[1])||0))}</span></div>`).join("")
   ||'<div class="empty">'+esc(tr("ヒットなし"))+'</div>';
 const kinds=Object.entries(an.event_kinds||{}).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
   `<span class="badge ${sev(k)}">${esc(k)} ${esc(nf(Number(v)||0))}</span>`).join(" ")
   ||'<div class="empty">'+esc(tr("イベントなし"))+'</div>';
 const bans=`<div class="kpi i-red"><div class="kn">${esc(nf(Number(an.active_bans)||0))}</div>`
   +`<div class="kl">${esc(tr("BAN中"))}</div></div>`;
 return `<div class="grid">${sec("アクション別",acts)}${sec("ゾーン別",zones)}${sec("上位シグネチャ",sigs)}`
   +`${sec("イベント種別",kinds)}${sec("BAN中のIP",bans)}</div>`;
}
/* 変更履歴(監査ログ) */
let curAudit=[];
async function refreshAudit(current=()=>true){
 const generation=++auditRefreshGeneration;
 const valid=()=>current()&&generation===auditRefreshGeneration;
 const unavailable=()=>{curAudit=[];$("auditmeta").textContent=tr("状態取得不可");
  $("auditlog").textContent=tr("状態取得不可");};
 let d;try{d=await guardedFetch("/api/admin_audit")}catch(e){
  if(!valid()||e&&e.staleToken)return;
  if(isAuthFail(e))markAuthError();
  unavailable();return}
 if(!valid())return;
 if(!d||!Array.isArray(d.entries)){unavailable();return;}
 const rows=d.entries;curAudit=rows;
 $("auditmeta").textContent=rows.length?String(rows.length):"—";
 $("auditlog").innerHTML=rows.map((e,i)=>{
   const rv=e.revert?`<button class="ghost" data-auditidx="${i}">${tr("元に戻す")}</button>`:"";
   return `<div class="frow"><span class="time">${tm(e.ts)}</span>`
    +`<span class="desc">${esc(e.summary||e.endpoint||"")}</span>${rv}</div>`;
 }).join("")||'<div class="empty">'+tr("変更履歴なし")+'</div>';
}
$("auditlog").addEventListener("click",e=>{
 const b=e.target.closest("button[data-auditidx]");if(!b)return;
 const entry=curAudit[parseInt(b.dataset.auditidx)];
 if(entry&&entry.revert)revertAudit(entry.revert,b);
});
function revertAudit(revert,btn){
 postT(revert.endpoint,revert.body,btn,tr("元に戻しました"),tr("復元に失敗")).then(()=>{refresh();refreshAudit();});
}
function renderThreatTable(id,rows,apt=false){
 const host=$(id);host.textContent="";const table=document.createElement("table"),head=document.createElement("tr");
 for(const text of apt?["IP","APTスコア","兆候","ヒット","操作"]:["IP","スコア","窓内要求","ヒット","操作"]){const cell=document.createElement("th");cell.textContent=tr(text);head.appendChild(cell);}table.appendChild(head);
 const metric=value=>typeof value==="number"&&Number.isFinite(value)?nf(value):"—";
 for(const entry of (Array.isArray(rows)?rows:[]).slice(0,50)){if(!entry||typeof entry.ip!=="string")continue;
  const row=document.createElement("tr"),ip=entry.ip;
  const values=apt?[ip,metric(entry.apt_score),[entry.regular_beacon&&tr("規則的ビーコン"),entry.low_and_slow&&tr("低速持続")].filter(Boolean).join(" · ")||"—",metric(entry.hits)]:[ip,metric(entry.score),metric(entry.reqs_window),metric(entry.hits)];
  for(const value of values){const cell=document.createElement("td");cell.textContent=value;row.appendChild(cell);}const actions=document.createElement("td");
  const button=(label,fn)=>{const b=document.createElement("button");b.type="button";b.className="ghost";b.textContent=tr(label);b.onclick=()=>fn(b);actions.appendChild(b);return b;};
  const action=button(entry.banned?"解除":"BAN",button=>threatIPAction(ip,entry.banned===true,button));action.disabled=!!(threatIPAction.pending&&threatIPAction.pending.has(ip)||typeof nodeActionsPending!=="undefined"&&nodeActionsPending.has(ip));
  button("イベント",()=>{if(typeof filterEventsForIP==="function")filterEventsForIP(ip);else{$("eventsearch").value=ip;renderEvents();}});
  row.appendChild(actions);table.appendChild(row);
 }if(table.children.length===1){const row=document.createElement("tr"),cell=document.createElement("td");cell.colSpan=5;cell.textContent=tr(apt?"(兆候なし)":"(なし)");row.appendChild(cell);table.appendChild(row);}host.appendChild(table);
}
async function threatIPAction(ip,banned,button){
 const pending=threatIPAction.pending||(threatIPAction.pending=new Set());if(pending.has(ip)||$("stateview").inert)return;
 pending.add(ip);button.disabled=true;
 try{if(typeof runNodeAction==="function")await runNodeAction(ip,banned,button);
  else if(banned){await postT("/api/shield/unban",{ip},button,tr("BANを解除しました"),tr("解除に失敗"));}
  else if(typeof banFromEvent==="function")await banFromEvent(ip,button);
  else if(await confirmDialog(tr("このIPをBANしますか?")+" "+ip))await postT("/api/shield/ban",{ip},button,tr("IPをBANしました"),tr("BANに失敗"));
 }finally{pending.delete(ip);button.disabled=false;await refresh();await refreshPro();}
}
async function refreshDeception(current=()=>true){
 const generation=++deceptionRefreshGeneration;
 const valid=()=>current()&&generation===deceptionRefreshGeneration;
 let d;try{d=await guardedFetch("/api/deception")}catch(e){if(valid()&&isAuthFail(e))markAuthError();return}
 if(!valid())return;
 $("decepstat").innerHTML=`<span class="badge ${d.enabled?"info":"muted"}">${tr(d.enabled?"有効":"無効")}</span>`
   +` ${tr("系統")} ${d.family_count||0}`;
 if(typeof renderDeceptionTable==="function")renderDeceptionTable(d);
}
function renderDeceptionTable(data){
 const host=$("deception");host.textContent="";const note=document.createElement("p");note.className="meta";
 note.textContent=data.enabled?tr("サンプル攻撃者")+" "+String(data.sample_seed||"")+" · "+tr("プレビューのみ・実通信の記録ではありません"):tr("(DUCKNET_DECEPTION 未設定 = 偽装なし)");host.appendChild(note);
 const table=document.createElement("table"),head=document.createElement("tr");for(const text of ["時間窓","系統","Server","随伴ヘッダ"]){const cell=document.createElement("th");cell.textContent=tr(text);head.appendChild(cell);}table.appendChild(head);
 const rows=data.enabled?(Array.isArray(data.preview)?data.preview:[]):(Array.isArray(data.families)?data.families:[]).map(family=>({family}));
 for(const entry of rows.slice(0,64)){if(!entry||typeof entry!=="object")continue;const row=document.createElement("tr");
  for(const value of [Number.isFinite(entry.window)?"+"+entry.window:"—",entry.family||"—",entry.server||"—",Array.isArray(entry.companions)?entry.companions.join(" · "):"—"]){const cell=document.createElement("td");cell.textContent=String(value);row.appendChild(cell);}table.appendChild(row);
 }host.appendChild(table);
}
let curCustomSigs=[];
async function refreshSigs(current=()=>true){
 const generation=++sigRefreshGeneration;
 const valid=()=>current()&&generation===sigRefreshGeneration;
 let d;try{d=await guardedFetch("/api/shield/signatures")}catch(e){if(valid()&&isAuthFail(e))markAuthError();return}
 if(!valid())return;
 curCustomSigs=d.custom||[];
 // 停止中=読込時に載せなかった規則(危険なパターンだけでなく weight 不正・件数上限超過も・#55/#59)
 $("sigmeta").textContent=`${tr("組込")} ${(d.builtin||[]).length} · ${tr("カスタム")} ${d.custom_active||0}`
   +(d.custom_max?"/"+d.custom_max:"")
   +(d.custom_blocked?` · ${tr("停止中")} ${d.custom_blocked}`:"");
 $("customsigs").querySelector("tbody").innerHTML=curCustomSigs.map(c=>
   `<tr><td class="num">${esc(c.name)}`
   +(c.active===false?` <span class="badge danger">${tr("停止中")}</span><div class="meta">${esc(c.reason||"")}</div>`:"")
   +`</td><td><span class="num">${esc((c.pattern||"").slice(0,48))}</span></td>`
   +`<td><button class="ghost" data-signame="${esc(c.name)}">${tr("削除")}</button></td></tr>`).join("")
   ||'<tr><td colspan="3" class="empty">'+tr("カスタムシグネチャなし — 下のフォームから追加できます(組込シグネチャで拾えないパターン用)")+'</td></tr>';
}
$("customsigs").addEventListener("click",e=>{
 const b=e.target.closest("button[data-signame]");
 if(b)removeSig(b.dataset.signame,b);
});
/* sig_add / sig_test の warnings(走査前の正規化で書き換わり、当たらなくなる字面など・#30)。
   各警告は esc() を通して描く(データを生の HTML へ入れない)。 */
function sigWarnHtml(r){
 const W=(r&&Array.isArray(r.warnings))?r.warnings:[];
 return W.length?' <span class="badge warn">'+tr("注意")+'</span> '+W.map(w=>esc(w)).join(" / "):"";
}
async function addSig(btn){
 const name=$("signame").value.trim(),pattern=$("sigpat").value;
 if(!name||!pattern){$("sigerr").textContent=tr("名前とパターンを入力");return;}
 const r=await postT("/api/shield/sig_add",{name,pattern},btn,tr("シグネチャを追加しました"),tr("追加に失敗"));
 if(r.ok)$("sigerr").innerHTML=sigWarnHtml(r);
 else $("sigerr").textContent="✗ "+(r.error||tr("失敗"));
 if(r.ok&&$("signame").value.trim()===name&&$("sigpat").value===pattern){
  $("signame").value="";$("sigpat").value="";$("sigtestresult").textContent="";}
 refreshSigs();
}
async function removeSig(name,btn){
 if(!(await confirmDialog(tr("このシグネチャを削除しますか?")+" "+name)))return;
 postT("/api/shield/sig_remove",{name},btn,tr("シグネチャを削除しました"),tr("削除に失敗")).then(()=>refreshSigs());
}
/* シグネチャのドライラン試験: 追加前にサーバ側の validate_pattern(ReDoS検査)を通した上で
   マッチ確認のみ行う読み取り専用API。状態は一切変更しない。 */
let sigTestGeneration=0;
async function testSig(btn){
 const generation=++sigTestGeneration;
 const pattern=$("sigpat").value,sample=$("sigtestsample").value;
 if(!pattern){$("sigtestresult").innerHTML='<span class="badge muted">'+tr("パターンを入力")+'</span>';return;}
 busy(btn,true);
 let r;try{r=await post("/api/shield/sig_test",{pattern,sample});}finally{busy(btn,false);}
 if(generation!==sigTestGeneration||$("sigpat").value!==pattern||$("sigtestsample").value!==sample)return;
 if(!r||!r.ok){$("sigtestresult").innerHTML='<span class="badge danger">'+tr("エラー")+'</span>'
   +(r&&r.error?" "+esc(r.error):"");return;}
 if(r.error){$("sigtestresult").innerHTML='<span class="badge danger">'+tr("無効なパターン")+': '+esc(r.error)+'</span>';}
 else{$("sigtestresult").innerHTML=(r.matches?'<span class="badge warn">'+tr("一致")+'</span>':'<span class="badge muted">'+tr("不一致")+'</span>')+sigWarnHtml(r);}
}
let curPathLimits=[];
async function addPathLimit(btn){
 const path=$("prpath").value.trim(),rawRate=$("prrate").value,rawBurst=$("prburst").value;
 const rate=Number(rawRate),burst=Number(rawBurst);
 if(!path||!Number.isFinite(rate)||!(rate>0)){$("prerr").textContent=tr("パスと毎秒(>0)を入力");return;}
 if(!Number.isFinite(burst)||(rawBurst.trim()!==""&&!(burst>0))){$("prerr").textContent=tr("バーストは空欄または正の数を入力してください");return;}
 const rule={path,rate};if(burst>0)rule.burst=burst;
 const r=await postT("/api/shield/path_limits",{rules:curPathLimits.concat([rule])},btn,tr("レート制限を追加しました"),tr("追加に失敗"));
 $("prerr").textContent=r.ok?"":("✗ "+(r.error||tr("失敗")));
 if(r.ok&&$("prpath").value.trim()===path&&$("prrate").value===rawRate&&$("prburst").value===rawBurst){
  $("prpath").value="";$("prrate").value="";$("prburst").value="";}
 refresh();
}
async function removePathLimit(i,btn){
 const target=curPathLimits[i];if(!target)return;
 if(!(await confirmDialog(tr("このレート制限ルールを削除しますか?"))))return;
 const index=curPathLimits.findIndex(r=>r.path===target.path&&r.rate===target.rate&&r.burst===target.burst);
 if(index<0){toast(tr("ルールが更新されました。確認して再操作してください"),"info");refresh();return;}
 postT("/api/shield/path_limits",{rules:curPathLimits.filter((_,j)=>j!==index)},btn,tr("ルールを削除しました"),tr("削除に失敗")).then(refresh);
}
function setIfBlur(id,val){const e=$(id);if(e&&!e.disabled&&document.activeElement!==e)e.value=val;}  // 編集中・送信中は上書きしない
async function saveBlockedMethods(btn){
 const m=$("blockmeth").value.split(",").map(s=>s.trim()).filter(Boolean);
 postT("/api/shield/blocked_methods",{methods:m},btn,tr("遮断メソッドを保存しました"),tr("保存に失敗")).then(r=>{
  if(!r||!r.ok){$("methoderr").textContent=(r&&r.error)||tr("保存に失敗");refresh();return;}
  // バックエンドは英字以外・重複を黙って除外するため、送った物と実際に保存された物を突き合わせて
  // ドロップされたトークンをその場で表示する。
  const kept=new Set((r.blocked_methods||[]).map(x=>String(x).toUpperCase()));
  const dropped=m.filter(x=>!kept.has(x.toUpperCase()));
  $("methoderr").textContent=dropped.length?(tr("無視")+": "+dropped.join(", ")):"";
  refresh();
 });
}
const _ZR={loopback:55,private:105,public:150,special:150,unknown:150};
function drawMap(d){
 const W=1040,Hh=300,cx=W/2,cy=Hh/2;
 const line=cssv("--line"),fg=cssv("--fg"),blue=cssv("--blue"),green=cssv("--green"),amber=cssv("--amber"),red=cssv("--brand");
 let g=`<circle cx="${cx}" cy="${cy}" r="24" fill="${blue}"/>`
   +`<text x="${cx}" y="${cy+4}" fill="#fff" font-size="11" font-weight="700" text-anchor="middle">${esc(tr("本機"))}</text>`;
 const byz={};(d.nodes||[]).forEach(n=>{(byz[n.zone]=byz[n.zone]||[]).push(n)});
 Object.keys(byz).forEach(z=>{const arr=byz[z],r=_ZR[z]||150;
  arr.forEach((n,i)=>{const a=(i/Math.max(1,arr.length))*Math.PI*2;
   const x=cx+Math.cos(a)*r,y=cy+Math.sin(a)*r;
   const col=n.banned?red:(n.score>40?amber:green);
   g+=`<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${line}" stroke-width="1"/>`
    +`<circle cx="${x}" cy="${y}" r="7" fill="${col}" style="cursor:pointer"`
    +` data-ip="${esc(n.ip)}" data-banned="${n.banned?1:0}"`
    +` onclick="toggleNode(this.getAttribute('data-ip'),this.getAttribute('data-banned')==='1')"><title>${esc(n.ip)} [${esc(z)}] score${n.score}${n.mac?" "+esc(n.mac):""}</title></circle>`;});});
 $("netmap").innerHTML=g;
}
async function toggleNode(ip,banned){
 return runNodeAction(ip,!!banned,null);
}
async function globalBlock(on,btn){
 if(on&&!(await confirmDialog(tr("インターネット(public)を一括遮断します。よろしいですか?"))))return;
 postT("/api/global_block",{on},btn,on?tr("グローバル遮断を有効にしました"):tr("グローバル遮断を解除しました"),tr("処理に失敗"))
  .then(()=>{refresh();refreshPro();});
}
function barHTML(entries,limit){
 const e=entries.filter(x=>x[1]).sort((a,b)=>b[1]-a[1]),mx=Math.max(1,...e.map(x=>x[1]));
 return e.slice(0,limit||10).map(([k,v])=>
   `<div class="sbar"><span class="sbl">${esc(k)}</span><span class="sbt">`
   +`<span class="sbf" style="width:${Math.round(v/mx*100)}%"></span></span>`
   +`<span class="sbn num">${nf(v)}</span></div>`).join("")||'<div class="empty">'+tr("なし")+'</div>';
}
function drawSpark(id,cum){
 const el=$(id);if(!el)return;
 const d=[];for(let i=1;i<cum.length;i++)d.push(Math.max(0,(cum[i]||0)-(cum[i-1]||0)));  // 累積→毎秒の漏洩数
 const W=300,Hh=30,n=d.length,mx=Math.max(1,...d),red=cssv("--red");
 if(!n){el.innerHTML="";return;}
 const xy=i=>[(i/(n-1||1))*W,Hh-2-(d[i]/mx)*(Hh-5)];
 const pts=d.map((_,i)=>xy(i).join(",")).join(" ");
 const [x0]=xy(0),[xN]=xy(n-1);
 el.innerHTML=`<polyline points="${x0},${Hh} ${pts} ${xN},${Hh}" fill="${red}" fill-opacity=".12" stroke="none"/>`
   +`<polyline points="${pts}" fill="none" stroke="${red}" stroke-width="1.5"/>`;
}
function drawChart(s){
 const c=$("chart"),x=c.getContext("2d"),dpr=devicePixelRatio||1,cw=c.clientWidth||1000,ch=180;
 if(c.width!==Math.round(cw*dpr)){c.width=Math.round(cw*dpr);c.height=Math.round(ch*dpr);}
 x.setTransform(dpr,0,0,dpr,0,0);const W=cw,Hh=ch;
 x.clearRect(0,0,W,Hh);
 const line=cssv("--line2"),faint=cssv("--faint"),blue=cssv("--blue"),red=cssv("--brand");
 for(let i=0;i<=4;i++){const y=5+(Hh-15)*i/4;x.strokeStyle=line;x.lineWidth=1;x.beginPath();x.moveTo(0,y);x.lineTo(W,y);x.stroke();}
 const samples=(Array.isArray(s)?s:[]).filter(p=>p&&[p.t,p.requests,p.block].every(v=>typeof v==="number"&&Number.isFinite(v)));
 const d=[];for(let i=1;i<samples.length;i++){const dt=samples[i].t-samples[i-1].t;if(!(dt>0))continue;
  const r=Math.max(0,(samples[i].requests-samples[i-1].requests)/dt),b=Math.max(0,(samples[i].block-samples[i-1].block)/dt);
  if(Number.isFinite(r)&&Number.isFinite(b))d.push({t:samples[i].t,r,b});}
 const tooltip=$("charttip");if(tooltip)tooltip.hidden=true;
 const show=index=>{if(!tooltip||!d.length)return;const p=d[Math.max(0,Math.min(d.length-1,index))];tooltip.textContent=tm(p.t)+" · req/s "+p.r.toFixed(2)+" · block/s "+p.b.toFixed(2);tooltip.hidden=false;};
 c.onpointermove=event=>{if(!d.length)return;const rect=c.getBoundingClientRect(),at=(event.clientX-rect.left)/Math.max(1,rect.width);if(Number.isFinite(at))show(Math.round(Math.max(0,Math.min(1,at))*(d.length-1)));};
 c.onpointerleave=()=>{if(tooltip)tooltip.hidden=true;};c.onblur=c.onpointerleave;
 let selected=d.length-1;c.onkeydown=event=>{if(event.key!=="ArrowLeft"&&event.key!=="ArrowRight")return;event.preventDefault();selected=Math.max(0,Math.min(d.length-1,selected+(event.key==="ArrowLeft"?-1:1)));show(selected);};
 if(!d.length){$("chartleg").textContent="req/s · block/s · "+tr("保持データなし");return;}
 const mx=Math.max(1,...d.map(p=>Math.max(p.r,p.b)));
 const px=i=>i/Math.max(1,d.length-1)*W,py=v=>Hh-(v/mx)*(Hh-15)-5;
 // req は塗り
 x.beginPath();x.moveTo(0,Hh);d.forEach((p,i)=>x.lineTo(px(i),py(p.r)));x.lineTo(W,Hh);x.closePath();
 const grad=x.createLinearGradient(0,0,0,Hh);grad.addColorStop(0,blue+"55");grad.addColorStop(1,blue+"00");
 x.fillStyle=grad;x.fill();
 const ln=(k,col)=>{x.strokeStyle=col;x.lineWidth=2;x.lineJoin="round";x.beginPath();
  d.forEach((p,i)=>{i?x.lineTo(px(i),py(p[k])):x.moveTo(px(i),py(p[k]));});x.stroke();};
 ln("r",blue);ln("b",red);
 $("chartleg").innerHTML=`<span style="color:${blue}">●</span> req/s &nbsp;<span style="color:${red}">●</span> block/s &nbsp;· peak ${mx.toFixed(1)}/s`;
}
async function resolveAppeal(ip,ok,btn){
 if(!ok&&!(await confirmDialog(tr("この申立を却下しますか?")+" "+ip)))return;
 postT("/api/appeal/resolve",{ip,approve:ok},btn,ok?tr("申立を承認しました"):tr("申立を却下しました"),tr("処理に失敗"))
  .then(()=>{refresh();refreshPro();});
}
async function resolvePending(id,ok,btn){
 if(!ok&&!(await confirmDialog(tr("この接続を拒否しますか?"))))return;
 const remCk=ok?document.getElementById("rem_"+id):null;
 const remember=!!(remCk&&remCk.checked);
 postT("/api/firewall/resolve",{id,approve:ok,remember},btn,ok?tr("接続を承認しました"):tr("接続を拒否しました"),tr("処理に失敗")).then(refresh);
}
function unban(ip,btn){postT("/api/shield/unban",{ip},btn,tr("BANを解除しました"),tr("解除に失敗")).then(refresh)}
async function ban(btn){
 const ip=$("banip").value;if(!ip)return;
 if(!(await confirmDialog(tr("このIPをBANしますか?")+" "+ip)))return;
 postT("/api/shield/ban",{ip},btn,tr("IPをBANしました"),tr("BANに失敗")).then(refresh);
}
async function rule(a,btn){
 const net=$("ruleip").value;if(!net)return;
 if(a==="deny"&&!(await confirmDialog(tr("このIP/CIDRを拒否ルールに追加しますか?")+" "+net)))return;
 postT("/api/firewall/rule",{net,action:a},btn,tr("ルールを追加しました"),tr("追加に失敗")).then(refresh);
}
async function edge(){
 // 失敗時(401 等)の JSON 本文を設定ファイルとして保存しない。理由と次の一手をトーストで出す。
 let resp;try{resp=await signedRequest("GET","/api/edge");}
 catch(e){if(e&&e.staleToken){toast(errText("stale"),"info");return;}
  if(e&&e.authFail){markAuthError();toast(AUTH_PROBLEM,"err");}
  else toast(errText("net"),"err");return;}
 if(resp.status===401){markAuthError();toast(errText("auth"),"err");return;}
 if(!resp.ok){toast(errText("http",resp.status),"err");return;}
 const t=await resp.text();
 downloadFile("ducknet_edge.conf",t,"text/plain");}
/* CSV/JSON エクスポート: 既に取得済みの配列をそのままファイル化するだけ(追加取得なし)。 */
function toCSV(rows,cols){
 const q=v=>{let s=v==null?"":String(v);
  // Spreadsheet-facing CSV: dangerous text prefixes stay quoted and acquire
  // a literal tab. Numeric values remain numeric; JSON retains exact text.
  const text=typeof v==="string"&&/^(?:[\s\u0000-\u001f\u007f-\u009f]*[=+\-@＝＋－＠]|[\s\u0000-\u001f\u007f-\u009f]*[\t\r\n])/.test(s);
  if(text)s="\t"+s;
  return text||/[",;\r\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;};
 return [cols.map(q).join(",")].concat(rows.map(r=>cols.map(c=>q(r[c])).join(","))).join("\r\n");
}
function downloadFile(filename,text,mime){
 const blob=new Blob([text],{type:mime||"text/plain"});
 const u=URL.createObjectURL(blob);
 const a=document.createElement("a");a.href=u;a.download=filename;document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(u),1000);
}
function exportData(which,fmt){
 let rows=[],cols=[],name="";
 if(which==="bans"){rows=curBans;cols=["ip","score","remain_sec"];name="banned_ips";}
 else if(which==="events"){rows=curEvents;cols=["ts","kind","ip","reason","signature","rule","score","would","stage","filename","ext"];
  for(const row of rows)for(const key of Object.keys(row))if(!cols.includes(key))cols.push(key);
  name="attack_events";}
 else if(which==="sigs"){rows=curCustomSigs;cols=["name","category","pattern","weight"];name="custom_signatures";}
 else return;
 if(fmt==="json")downloadFile(name+".json",JSON.stringify(rows,null,2),"application/json");
 else downloadFile(name+".csv",toCSV(rows.map(row=>Object.fromEntries(Object.entries(row).map(([k,v])=>[k,v&&typeof v==="object"?JSON.stringify(v):v]))),cols),"text/csv");
 toast(tr("エクスポートしました"),"ok");
}
function settingsClone(value){return JSON.parse(JSON.stringify(value));}
function settingsStable(value){
 if(Array.isArray(value))return "["+value.map(settingsStable).join(",")+"]";
 if(value&&typeof value==="object")return "{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+settingsStable(value[k])).join(",")+"}";
 return JSON.stringify(value);
}
function settingsSetMessage(message,error){settingsMessage=message||"";settingsMessageError=!!error;renderSettingsStatus();}
function renderSettingsStatus(){
 const el=$("settingsstatus");if(!el)return;
 const summary=settingsSchema?settingsSchema.fields.length+" "+tr("設定項目")+" · "+settingsDirty.size+" "+tr("変更項目"):tr("開くと設定項目を読み込みます");
 el.textContent=settingsMessage?tr(settingsMessage):summary+(settingsDirty.size?" · "+tr("未保存の変更があります"):"");
 el.className="meta"+(settingsMessageError?" bad":"");
 if($("settingsdiff")&&!$("settingsdiff").hidden)renderSettingsDiff();
}
function toggleSettingsDiff(){const host=$("settingsdiff");host.hidden=!host.hidden;if(!host.hidden)renderSettingsDiff();}
function renderSettingsDiff(){
 const host=$("settingsdiff");if(!host||!settingsSchema)return;host.textContent="";
 const table=document.createElement("table"),head=document.createElement("tr");
 for(const text of ["設定項目","現在値","変更後"]){const cell=document.createElement("th");cell.textContent=tr(text);head.appendChild(cell);}table.appendChild(head);
 for(const field of settingsSchema.fields){if(!settingsDirty.has(field.key))continue;
  const row=document.createElement("tr"),key=document.createElement("td");key.textContent=field.key;row.appendChild(key);
  let next;try{next=JSON.stringify(readSettingValue(field,settingsControls[field.key]),null,2);}catch(e){next=tr("入力値を確認してください")+": "+e.message;}
  for(const text of [JSON.stringify(settingsBaseConfig[field.key],null,2),next]){const cell=document.createElement("td"),pre=document.createElement("pre");pre.textContent=text;cell.appendChild(pre);row.appendChild(cell);}table.appendChild(row);
 }host.appendChild(table);
}
function settingsSetAvailable(available){
 settingsAvailable=!!available;
 for(const control of Object.values(settingsControls)){control.disabled=!settingsAvailable||settingsSavePending;
  if(control._structured)for(const input of control._structured.inputs)input.disabled=control.disabled;}
 const save=$("settingssave"),reload=$("settingsreload");
 if(save)save.disabled=!settingsAvailable||settingsSavePending||!settingsDirty.size;
 if(reload)reload.disabled=settingsSavePending;
 if($("settingsdiffbutton"))$("settingsdiffbutton").disabled=settingsSavePending||!settingsDirty.size;
 if(!available&&settingsSchema)settingsSetMessage("設定の取得に失敗しました。接続を確認してください",true);
}
function parseSettingsJson(raw){
 if(typeof raw!=="string"||raw.length>1048576)throw new Error(tr("設定全体が大きすぎます"));
 let at=0;const skip=()=>{while(at<raw.length&&/\s/.test(raw[at]))at++;};
 function string(){
  const start=at++;let escaped=false;
  while(at<raw.length){const c=raw[at++];if(escaped){escaped=false;continue;}if(c==="\\"){escaped=true;continue;}if(c==='"')return JSON.parse(raw.slice(start,at));}
  throw new Error(tr("有効なJSONを入力してください"));
 }
 function value(depth){
  if(depth>64)throw new Error(tr("有効なJSONを入力してください"));skip();const c=raw[at];
  if(c==='"'){string();return;}
  if(c==="{"){at++;skip();const keys=new Set();if(raw[at]==="}"){at++;return;}
   while(at<raw.length){skip();if(raw[at]!=='"')throw new Error(tr("有効なJSONを入力してください"));const key=string();
    if(keys.has(key))throw new Error(tr("JSONのキーが重複しています"));keys.add(key);skip();if(raw[at++]!==":")throw new Error(tr("有効なJSONを入力してください"));
    value(depth+1);skip();const end=raw[at++];if(end==="}")return;if(end!==",")throw new Error(tr("有効なJSONを入力してください"));}
  }else if(c==="["){at++;skip();if(raw[at]==="]"){at++;return;}
   while(at<raw.length){value(depth+1);skip();const end=raw[at++];if(end==="]")return;if(end!==",")throw new Error(tr("有効なJSONを入力してください"));}
  }else{
   const start=at;while(at<raw.length&&!/[\s,\]}]/.test(raw[at]))at++;
   if(start===at)throw new Error(tr("有効なJSONを入力してください"));const item=JSON.parse(raw.slice(start,at));
   if(typeof item==="number"&&(!Number.isFinite(item)||(Number.isInteger(item)&&!Number.isSafeInteger(item))))throw new Error(tr("有限の数値を入力してください"));
   return;
  }
  throw new Error(tr("有効なJSONを入力してください"));
 }
 value(0);skip();if(at!==raw.length)throw new Error(tr("有効なJSONを入力してください"));return JSON.parse(raw);
}
function buildStructuredSetting(field,control){
 const root=document.createElement("div"),visual=document.createElement("div"),host=document.createElement("div"),error=document.createElement("div"),raw=document.createElement("details"),summary=document.createElement("summary");
 const state={kind:field.key==="path_limits"?"paths":field.type==="array"?"tags":field.key==="optional_sigs"?"options":"dictionary",root,visual,host,errorNode:error,raw,inputs:[],rows:[],error:"",errorValue:""};control._structured=state;
 host.className=state.kind==="tags"?"setting-chips":"setting-rows";error.className="meta bad";raw.className="setting-raw";summary.textContent=tr("JSONで直接編集（上級）");raw.appendChild(summary);raw.appendChild(control);visual.appendChild(host);root.appendChild(visual);root.appendChild(error);root.appendChild(raw);
 const input=(type,value)=>{const el=document.createElement("input");el.type=type;el.value=String(value??"");if(type==="number")el.step="any";state.inputs.push(el);return el;};
 const button=(text,fn)=>{const el=document.createElement("button");el.type="button";el.className="ghost";el.textContent=tr(text);el.onclick=()=>{if(control.disabled||settingsSavePending||raw.open)return;try{fn();}catch(e){state.error=e.message;state.errorValue=control.value;error.textContent=state.error;settingEdited(field);}};state.inputs.push(el);return el;};
 const currentRows=()=>state.rows.map(row=>state.kind==="paths"?{path:row.path.value,rate:row.rate.value,burst:row.burst.value}:state.kind==="options"?{key:row.key,value:row.value.checked}:{key:row.key.value,value:row.value.value});
 state.sync=()=>{try{
  let value;if(state.kind==="tags"){if(state.entry.value)throw new Error(tr("追加で入力を確定してください"));value=state.items.slice();}
  else if(state.kind==="paths")value=state.rows.map(row=>{const number=el=>{const n=Number(el.value);if(!el.value.trim()||!Number.isFinite(n)||n<=0)throw new Error(tr("正の有限数を入力してください"));return n;};return {path:row.path.value,rate:number(row.rate),burst:number(row.burst)};});
  else{value=Object.create(null);const keys=new Set();for(const row of currentRows()){const key=row.key,comparison=field.key==="sec_headers_extra"?key.toLowerCase():key;
    if(!key||key!==key.trim()||keys.has(comparison))throw new Error(tr("空または重複したキーがあります"));keys.add(comparison);value[key]=row.value;}}
  control.value=JSON.stringify(value,null,2);state.error="";
 }catch(e){state.error=e.message;state.errorValue=control.value;}error.textContent=state.error;settingEdited(field);};
 state.draw=data=>{host.textContent="";state.rows=[];state.inputs=state.inputs.filter(el=>el===state.entry||el===state.add);state.error="";error.textContent="";
  if(state.kind==="tags"){state.items=Array.isArray(data)?data.slice():[];state.items.forEach((text,index)=>{const chip=document.createElement("span"),label=document.createElement("span");chip.className="setting-chip";label.textContent=String(text);chip.appendChild(label);chip.appendChild(button("×",()=>{state.items.splice(index,1);state.draw(state.items);state.sync();}));host.appendChild(chip);});}
  else{const table=document.createElement("table");host.appendChild(table);const header=document.createElement("tr");
   for(const text of state.kind==="paths"?["パス","レート/秒","バースト",""]:["キー","値",""]){const th=document.createElement("th");th.textContent=tr(text);header.appendChild(th);}table.appendChild(header);
   for(const item of data){const trr=document.createElement("tr"),row={};const cells=[];
    if(state.kind==="paths"){for(const key of ["path","rate","burst"]){row[key]=input(key==="path"?"text":"number",item[key]);cells.push(row[key]);}}
    else if(state.kind==="options"){row.key=item.key;const label=document.createElement("span");label.textContent=item.key;row.value=input("checkbox","");row.value.checked=item.value===true;cells.push(label,row.value);}
    else{row.key=input("text",item.key);row.value=input("text",item.value);cells.push(row.key,row.value);}
    for(const el of cells){const td=document.createElement("td");td.appendChild(el);trr.appendChild(td);if(el.tagName==="INPUT")el.addEventListener("input",state.sync);}
    if(state.kind!=="options"){const td=document.createElement("td");td.appendChild(button("削除",()=>{const index=state.rows.indexOf(row);if(index<0)return;const values=currentRows();values.splice(index,1);state.draw(values);state.sync();}));trr.appendChild(td);}table.appendChild(trr);state.rows.push(row);
   }
  }for(const el of state.inputs)el.disabled=control.disabled;
 };
 if(state.kind==="tags"){const bar=document.createElement("div");bar.className="row";state.entry=input("text","");state.entry.setAttribute("aria-label",tr("追加する値"));state.add=button("追加",()=>{const values=state.entry.value.split(",").map(v=>v.trim()).filter(Boolean);if(!values.length)return;if(state.items.length+values.length>512)throw new Error(tr("行数の上限を超えています"));state.items.push(...values);state.entry.value="";state.draw(state.items);state.sync();});state.entry.addEventListener("input",state.sync);state.entry.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===","){event.preventDefault();state.add.onclick();}});bar.appendChild(state.entry);bar.appendChild(state.add);visual.appendChild(bar);}
 else if(state.kind!=="options"){state.add=button("行を追加",()=>{const values=currentRows();if(values.length>=(state.kind==="paths"?64:128))throw new Error(tr("行数の上限を超えています"));values.push(state.kind==="paths"?{path:"",rate:"1",burst:"1"}:{key:"",value:""});state.draw(values);state.sync();});visual.appendChild(state.add);}
 raw.addEventListener("toggle",()=>{if(!raw.open&&state.rawInvalid){raw.open=true;visual.hidden=true;return;}visual.hidden=!!raw.open;});
 return root;
}
function renderStructuredSetting(field,control){
 const state=control._structured;if(!state)return;
 try{const value=parseSettingsJson(control.value);if(field.type==="array"&&!Array.isArray(value)||field.type==="object"&&(!value||typeof value!=="object"||Array.isArray(value)))throw new Error(tr("入力値を確認してください"));
  if((Array.isArray(value)?value.length:Object.keys(value).length)>(state.kind==="paths"?64:state.kind==="tags"?512:128))throw new Error(tr("行数の上限を超えています"));
  const data=state.kind==="tags"?value:state.kind==="paths"?value:state.kind==="options"?["ssti","ssrf_internal","redirect"].map(key=>({key,value:value[key]===true})):Object.keys(value).map(key=>({key,value:value[key]}));
  state.rawInvalid=false;if(state.entry)state.entry.value="";state.draw(data);
 }catch(e){state.rawInvalid=true;state.error=e.message||tr("有効なJSONを入力してください");state.errorValue=control.value;state.errorNode.textContent=state.error;}
}
function readSettingValue(field,control){
 if(control._structured&&control._structured.error&&control.value===control._structured.errorValue)throw new Error(control._structured.error);
 if(Array.isArray(field.choices)){
  const index=Number(control.value);if(!Number.isInteger(index)||index<0||index>=field.choices.length)throw new Error(tr("入力値を確認してください"));
  return settingsClone(field.choices[index]);
 }
 if(field.type==="boolean")return !!control.checked;
 if(field.type==="integer"||field.type==="number"){
  const raw=control.value.trim(),value=Number(raw);
  if(!raw||!Number.isFinite(value))throw new Error(tr("有限の数値を入力してください"));
  if(field.type==="integer"&&!Number.isSafeInteger(value))throw new Error(tr("整数を入力してください"));
  if((field.minimum!==undefined&&value<field.minimum)||(field.maximum!==undefined&&value>field.maximum))throw new Error(tr("値が許容範囲外です"));
  return value;
 }
 if(field.type==="array"||field.type==="object"){
  const value=parseSettingsJson(control.value);
  if(field.type==="array"&&!Array.isArray(value))throw new Error(tr("JSONの配列を入力してください"));
  if(field.type==="object"&&(!value||typeof value!=="object"||Array.isArray(value)))throw new Error(tr("JSONのオブジェクトを入力してください"));
  return value;
 }
 return control.value;
}
function setSettingControl(field,value){
 const control=settingsControls[field.key];if(!control)return;
 if(Array.isArray(field.choices)){control.value=String(field.choices.findIndex(choice=>settingsStable(choice)===settingsStable(value)));}
 else if(field.type==="boolean")control.checked=value===true;
 else control.value=(field.type==="array"||field.type==="object")?JSON.stringify(value,null,2):String(value);
 if(control._structured)renderStructuredSetting(field,control);
}
function settingEdited(field){
 if(settingsSavePending)return;let changed=true,invalid=false;
 try{changed=settingsStable(readSettingValue(field,settingsControls[field.key]))!==settingsStable(settingsBaseConfig[field.key]);}
 catch(e){invalid=true;}
 if(changed)settingsDirty.add(field.key);else settingsDirty.delete(field.key);
 settingsRows[field.key].row.className="settings-field"+(changed?" dirty":"")+(invalid?" invalid":"");
 settingsMessage="";settingsMessageError=false;settingsSetAvailable(settingsAvailable);renderSettingsStatus();
}
function renderSettingsLabels(){
 if(!settingsSchema)return;
 for(const group of settingsSchema.groups){const header=$("settings-group-"+group.id);if(header)header.textContent=LANG==="en"?(group.label_en||group.label):group.label;}
 for(const field of settingsSchema.fields){const row=settingsRows[field.key];if(!row)continue;
  row.label.textContent=LANG==="en"?(field.label_en||field.label):field.label;
  row.help.textContent=LANG==="en"?(field.description_en||field.description):field.description;
  row.defaultHint.textContent=tr("既定値")+": "+JSON.stringify(field.default);
  row.rangeHint.textContent=(field.minimum!==undefined||field.maximum!==undefined)?tr("範囲")+": "+(field.minimum!==undefined?field.minimum:"−∞")+" ～ "+(field.maximum!==undefined?field.maximum:"∞"):"";
  if(row.exampleSummary){row.exampleSummary.textContent=tr("入力例・未適用");row.exampleText.textContent=JSON.stringify(field.example,null,2);}
 }
 renderSettingsStatus();filterSettings();
}
function filterSettings(){
 if(!settingsSchema)return;const query=String($("settingssearch").value||"").trim().toLowerCase();
 for(const field of settingsSchema.fields){const row=settingsRows[field.key];row.row.hidden=!!query&&![field.key,field.label,field.label_en,field.description,field.description_en].join(" ").toLowerCase().includes(query);}
 for(const group of settingsSchema.groups){const section=$("settings-section-"+group.id);if(section)section.hidden=!settingsSchema.fields.some(field=>field.group===group.id&&!settingsRows[field.key].row.hidden);}
}
function renderSettingsEditor(){
 const host=$("settingsfields");host.textContent="";settingsControls={};settingsRows={};
 const sections={};for(const group of settingsSchema.groups){const section=document.createElement("section");section.className="settings-group";section.id="settings-section-"+group.id;
  const title=document.createElement("h3");title.id="settings-group-"+group.id;section.appendChild(title);host.appendChild(section);sections[group.id]=section;}
 for(const field of settingsSchema.fields){
  const row=document.createElement("div");row.className="settings-field";row.dataset.setting=field.key;
  const information=document.createElement("div"),label=document.createElement("label"),key=document.createElement("code"),help=document.createElement("div"),hint=document.createElement("div"),rangeHint=document.createElement("div");
  label.htmlFor="setting-"+field.key;key.textContent=field.key;help.className="meta";hint.className="meta";rangeHint.className="meta";
  information.appendChild(label);information.appendChild(key);information.appendChild(help);information.appendChild(hint);information.appendChild(rangeHint);
  let exampleSummary=null,exampleText=null;if(Object.prototype.hasOwnProperty.call(field,"example")){
   const example=document.createElement("details");exampleSummary=document.createElement("summary");exampleText=document.createElement("pre");exampleText.className="code";example.appendChild(exampleSummary);example.appendChild(exampleText);information.appendChild(example);}
  let control;if(Array.isArray(field.choices)){control=document.createElement("select");field.choices.forEach((choice,index)=>{const option=document.createElement("option");option.value=String(index);option.textContent=choice===""?"(empty)":String(choice);control.appendChild(option);});}
  else if(field.type==="array"||field.type==="object"){control=document.createElement("textarea");control.spellcheck=false;}
  else{control=document.createElement("input");control.type=field.type==="boolean"?"checkbox":(field.type==="integer"||field.type==="number")?"number":"text";
   if(field.type==="integer"||field.type==="number"){control.step=field.type==="integer"?"1":"any";if(field.minimum!==undefined)control.min=String(field.minimum);if(field.maximum!==undefined)control.max=String(field.maximum);}}
  control.id="setting-"+field.key;control.setAttribute("aria-describedby","setting-help-"+field.key);help.id="setting-help-"+field.key;
  const edited=()=>{if(control._structured){control._structured.error="";renderStructuredSetting(field,control);}settingEdited(field);};
  control.addEventListener("input",edited);control.addEventListener("change",edited);
  row.appendChild(information);row.appendChild(field.type==="array"||field.type==="object"?buildStructuredSetting(field,control):control);sections[field.group].appendChild(row);
  settingsControls[field.key]=control;settingsRows[field.key]={row,label,help,defaultHint:hint,rangeHint,exampleSummary,exampleText};
 }
 renderSettingsLabels();if(settingsLatestConfig)updateSettingsSnapshot(settingsLatestConfig,settingsLatestRevision);else settingsSetAvailable(false);
}
function validateSettingsSchema(data){
 if(!data||!Array.isArray(data.groups)||!Array.isArray(data.fields)||!data.fields.length||data.fields.length>256)throw new Error("invalid settings schema");
 const groups=new Set(data.groups.map(group=>group.id)),keys=new Set();
 if(groups.size!==data.groups.length||data.groups.some(group=>!group||typeof group.id!=="string"||!/^[a-z][a-z0-9_]*$/.test(group.id)))throw new Error("invalid settings groups");
 for(const field of data.fields){if(!field||typeof field.key!=="string"||!/^[a-z][a-z0-9_]*$/.test(field.key)||keys.has(field.key)||!groups.has(field.group)||
   !["boolean","integer","number","string","array","object"].includes(field.type)||!Object.prototype.hasOwnProperty.call(field,"default"))throw new Error("invalid settings field");keys.add(field.key);}
 return data;
}
async function loadSettingsSchema(){
 if(settingsSchema)return settingsSchema;if(settingsSchemaPromise)return settingsSchemaPromise;
 settingsSetMessage("設定項目を読み込み中",false);
 settingsSchemaPromise=(async()=>{try{const data=validateSettingsSchema(await guardedFetch("/api/shield/config_schema"));settingsSchema=data;settingsMessage="";settingsMessageError=false;renderSettingsEditor();return data;}
  catch(e){if(isAuthFail(e))markAuthError();settingsSetAvailable(false);settingsSetMessage("設定項目を取得できませんでした",true);return null;}
  finally{settingsSchemaPromise=null;}})();return settingsSchemaPromise;
}
function validSettingsSnapshot(config,revision){
 return !!config&&typeof config==="object"&&!Array.isArray(config)&&typeof revision==="string"&&/^[0-9a-f]{64}$/.test(revision)&&
  (!settingsSchema||settingsSchema.fields.every(field=>Object.prototype.hasOwnProperty.call(config,field.key)));
}
function updateSettingsSnapshot(config,revision){
 if(!validSettingsSnapshot(config,revision)){settingsSetAvailable(false);return;}
 settingsLatestConfig=settingsClone(config);settingsLatestRevision=revision;if(!settingsSchema)return;
 for(const field of settingsSchema.fields){if(settingsSavePending||settingsDirty.has(field.key))continue;
  settingsBaseConfig[field.key]=settingsClone(config[field.key]);setSettingControl(field,config[field.key]);settingsRows[field.key].row.className="settings-field";}
 settingsSetAvailable(true);renderSettingsStatus();
}
async function saveAdvancedSettings(button){
 if(settingsSavePending)return;if(!settingsAvailable){settingsSetMessage("状態取得後に編集できます",true);return;}
 const patch=Object.create(null),submitted=[];
 for(const field of settingsSchema.fields){if(!settingsDirty.has(field.key))continue;try{const value=readSettingValue(field,settingsControls[field.key]);
   if(settingsStable(value)!==settingsStable(settingsBaseConfig[field.key])){patch[field.key]=value;submitted.push(field.key);}}
  catch(e){settingsSetMessage(field.key+": "+e.message,true);settingsControls[field.key].focus();return;}}
 if(!submitted.length){settingsDirty.clear();if(settingsLatestConfig)updateSettingsSnapshot(settingsLatestConfig,settingsLatestRevision);settingsSetMessage("保存する変更はありません",false);settingsSetAvailable(settingsAvailable);return;}
 settingsSavePending=true;settingsSetAvailable(settingsAvailable);busy(button,true);
 try{
  const state=await guardedFetch("/api/state"),fresh=state&&state.shield&&state.shield.cfg,revision=state&&state.shield&&state.shield.config_revision;
  if(!validSettingsSnapshot(fresh,revision))throw new Error("state unavailable");
  settingsLatestConfig=settingsClone(fresh);settingsLatestRevision=revision;
  if(submitted.some(key=>settingsStable(fresh[key])!==settingsStable(settingsBaseConfig[key]))){settingsSetMessage("設定が別の操作で変更されました。再読込して確認してください",true);return;}
  patch._expected_revision=revision;
  if(new TextEncoder().encode(JSON.stringify(patch)).length>1048576){settingsSetMessage("設定全体が大きすぎます",true);return;}
  const result=await post("/api/shield/config",patch);
  if(result&&result.ok!==true&&(result.applied_in_memory===true||result.published===true)&&validSettingsSnapshot(result.cfg,result.config_revision)){
   for(const key of submitted)settingsDirty.delete(key);settingsLatestConfig=settingsClone(result.cfg);settingsLatestRevision=result.config_revision;
   settingsSetMessage("変更は有効ですが、永続化を確認できません。再読込して状態を確認してください",true);toast(tr(settingsMessage),"err");return;
  }
  if(!result||result.ok!==true){const rejected=result&&Array.isArray(result.rejected)?" ("+result.rejected.join(", ")+")":"";
   settingsSetMessage((result&&result.error?String(result.error):tr("保存に失敗しました"))+rejected,true);return;}
  if(!validSettingsSnapshot(result.cfg,result.config_revision)){settingsSetAvailable(false);settingsSetMessage("設定の取得に失敗しました。接続を確認してください",true);return;}
  for(const key of submitted)settingsDirty.delete(key);
  settingsLatestConfig=settingsClone(result.cfg);settingsLatestRevision=result.config_revision;
  settingsMessage=result.audit_recorded===false?"変更は適用されましたが、監査ログを保存できませんでした":"詳細設定を保存しました";
  settingsMessageError=result.audit_recorded===false;toast(tr(settingsMessage),settingsMessageError?"err":"ok");
  if(result.cluster_downgraded===true)toast(tr("クラスタの子ワーカーを停止し、単一プロセスで動作します"),"info");
 }catch(e){if(isAuthFail(e))markAuthError();settingsSetAvailable(false);settingsSetMessage("設定の取得に失敗しました。接続を確認してください",true);}
 finally{const stillAvailable=settingsAvailable;settingsSavePending=false;busy(button,false);if(stillAvailable&&settingsLatestConfig)updateSettingsSnapshot(settingsLatestConfig,settingsLatestRevision);settingsSetAvailable(stillAvailable);renderSettingsStatus();}
 await refresh();
}
async function reloadAdvancedSettings(button){
 if(settingsSavePending)return;if(settingsDirty.size&&!await confirmDialog(tr("未保存の変更を破棄して再読込しますか？")))return;
 settingsSavePending=true;settingsSetAvailable(settingsAvailable);busy(button,true);let loaded=null;
 try{if(!settingsSchema&&!await loadSettingsSchema())return;
  const state=await guardedFetch("/api/state");if(!state||!state.shield||!validSettingsSnapshot(state.shield.cfg,state.shield.config_revision))throw new Error("state unavailable");
  loaded=state.shield;settingsDirty.clear();settingsBaseConfig={};settingsSetMessage("設定を再読込しました",false);
 }catch(e){if(isAuthFail(e))markAuthError();settingsSetAvailable(false);}
 finally{const ready=settingsAvailable;settingsSavePending=false;if(loaded)updateSettingsSnapshot(loaded.cfg,loaded.config_revision);else settingsSetAvailable(ready);busy(button,false);settingsSetAvailable(settingsAvailable);}
}
const settingsDetails=$("settingsdetail"),settingsSearch=$("settingssearch");
if(settingsDetails&&typeof settingsDetails.addEventListener==="function")settingsDetails.addEventListener("toggle",()=>{if(settingsDetails.open)loadSettingsSchema();});
if(settingsSearch&&typeof settingsSearch.addEventListener==="function")settingsSearch.addEventListener("input",filterSettings);
addEventListener("resize",()=>{try{refreshPro()}catch(e){}});
showSkeleton();initializeAdminAuth();setInterval(refresh,2000);setInterval(refreshPro,2000);
</script></body></html>"""
