"""
edge_config.py — 外部の Lua対応リバースプロキシ連携の生成物
====================================================================================
外部の Lua対応リバースプロキシ前衛で 444 Drop する構成を、本PJの掟(外部依存を抱えない)を
守って実現するための **生成物** を作る。本体はそのプロキシを *動かさない* が、

  · NetShield/firewall の現在の遮断対象(BAN中IP + firewall deny ルール)を **共有ファイル**
    (1行1IP)へ出力する(export_banlist)。
  · それを読んで `return 444`(レスポンスせず即TCP切断)するプロキシ設定 + Lua を
    生成する(edge_proxy_config)。

これにより、対応プロキシを持つ利用者は、NetShield(Python)の判定を **カーネル手前の
最速地点**で適用でき、綺麗なアクセスだけを Python 本体へ通せる。
本体を持たない利用者向けには [[proxy]](stdlib asyncio)が同じ Fail-Fast を依存ゼロで提供する。

正直: ここで返すのは設定テキストとIPリストだけ。実際に 444 を撃つのは利用者側のプロキシ。
本体は外部プロセスを起動・依存しない(オフライン・stdlib のまま)。
"""
from __future__ import annotations

import ipaddress
import os
import re
import stat
import tempfile
import time
from contextlib import nullcontext

from ..core.atomic_io import atomic_write_text

_BANLIST_MAX_BYTES = 8 * 1024 * 1024
_BANLIST_MAX_ROWS = 100000


def _lua_str(s: str) -> str:
    """文字列を Lua の短い文字列リテラル("...")にする。Windows パスの '\\' や引用符をそのまま
    埋め込むと、\\U 等は不正エスケープ(設定の読込失敗)、\\n 等は別の文字(別ファイル)になる。"""
    out = []
    for ch in str(s):
        if ch in ("\\", '"'):
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ch == "\x7f":
            out.append("\\%03d" % ord(ch))         # 制御文字は 10 進 3 桁エスケープ
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def export_banlist(path: str = "") -> dict:
    from ..core.signed_state import _state_guard, _require_private_state_dir
    path = path or os.path.join(os.path.expanduser("~"), ".ducknet", "edge_banlist.txt")
    try:
        path = os.path.abspath(path)
        parent = os.path.dirname(path)
        os.makedirs(parent, mode=0o755, exist_ok=True)
        _require_private_state_dir(parent)
        with _state_guard(path) as locked:
            if not locked:
                return {"ok": False, "path": path, "error": "出力先をロックできません"}
            return _export_banlist(path)
    except (OSError, ValueError, TypeError) as exc:
        return {"ok": False, "path": path, "error": f"安全な出力先ではありません: {exc}"}


def _export_banlist(path: str) -> dict:
    """現在の遮断対象IP(shield BAN + firewall deny)を 1行1IP でファイル出力する。
    前衛の Lua は remote_addr(正規形の単一IP)で *完全一致* を引くだけなので、載せるのは
    正規形(小文字・圧縮表記)の単一IPに限る。/32・/128 は単一IPへ寄せる。それより広い CIDR は
    完全一致では決して命中しないため、部分出力せず失敗を返し以前のファイルを保つ。
    対象 CIDR は skipped_networks に記す。"""
    raw = []
    try:
        from ..lifeform.pipeline import net_shield, NetShield, _now
        shield = net_shield()
    except Exception as exc:
        return {"ok": False, "path": path, "error": f"BAN 状態を取得できません: {exc}"}
    try:
        from ..lifeform.policy import app_firewall
        from ..lifeform.policy import AppFirewall
        firewall = app_firewall()
    except Exception as exc:
        return {"ok": False, "path": path, "error": f"ACL 状態を取得できません: {exc}"}
    try:
        # One fixed lock order makes both sources a single point-in-time view.
        # Reading them separately can omit a deny while its owner changes from
        # the firewall to Shield, despite the IP never becoming permitted.
        with getattr(shield, "_lock", nullcontext()), getattr(firewall, "_lock", nullcontext()):
            # A fork child can add an automatic BAN after this parent's last
            # signed reload. Its process-local _ips is then incomplete, so an
            # acknowledged export could erase an existing edge deny. Keep the
            # previous file until a shared authoritative BAN view exists.
            if isinstance(shield, NetShield) and getattr(shield, "_active_fork_clusters", 0):
                raise ValueError("multiworker BAN state is not globally visible")
            # Both sources can fail closed after an unreadable signed state.
            # Their in-memory BAN/rule lists are then deliberately incomplete;
            # exporting those lists as a successful empty snapshot would erase
            # the previous edge deny list while DuckNet itself is denying.
            if isinstance(shield, NetShield) and any((
                    shield._cfg_state_untrusted, shield._sig_state_untrusted,
                    shield._ban_state_untrusted, shield._traffic_state_untrusted)):
                raise ValueError("shield signed state is untrusted")
            if isinstance(firewall, AppFirewall) and firewall._load_warning:
                raise ValueError("firewall state is untrusted")
            enabled = shield.is_enabled()
            if type(enabled) is not bool:
                raise ValueError("shield enabled state is not boolean")
            if enabled:
                if shield.cfg["mode"] not in ("enforce", "audit"):
                    raise ValueError("shield mode is unknown")
                # Existing manual BANs remain active in audit mode. Real
                # Shield snapshots need only keys, not per-IP score telemetry.
                if isinstance(shield, NetShield):
                    now = _now()
                    raw.extend(ip for ip, state in shield._ips.items()
                               if not state["ban_until"] <= now)
                else:
                    for ban in shield.bans():
                        if not isinstance(ban, dict) or "ip" not in ban:
                            raise ValueError("BAN entry is incomplete")
                        raw.append(ban["ip"])
            enabled = firewall.is_enabled()
            if type(enabled) is not bool:
                raise ValueError("firewall enabled state is not boolean")
            if enabled:
                for rule in firewall.rules:
                    if (not isinstance(rule, dict)
                            or rule.get("action") not in ("allow", "deny")):
                        raise ValueError("ACL entry is invalid")
                    if rule["action"] == "deny":
                        raw.append(rule.get("net"))
    except Exception as exc:
        return {"ok": False, "path": path, "error": f"遮断状態を取得できません: {exc}"}
    # Canonicalization, formatting and file I/O use the detached values only.
    ips, nets = set(), set()
    for v in raw:
        if not isinstance(v, str) or not v or v != v.strip() or "%" in v:
            return {"ok": False, "path": path, "error": "遮断対象のIP/CIDRが不正です"}
        try:
            n = ipaddress.ip_network(v, strict=False)
        except (ValueError, TypeError):
            return {"ok": False, "path": path, "error": "遮断対象のIP/CIDRが不正です"}
        if n.version == 6 and n.prefixlen >= 96:
            mapped = n.network_address.ipv4_mapped
            if mapped is not None:
                n = ipaddress.ip_network((mapped, n.prefixlen - 96), strict=False)
        if n.prefixlen == n.max_prefixlen:
            ip = str(n.network_address)
            if any(c not in "0123456789abcdef:." for c in ip):
                return {"ok": False, "path": path, "error": "前衛で照合できないIPです"}
            ips.add(ip)                             # 'Lua の完全一致' が引ける正規形
        else:
            nets.add(n.with_prefixlen)
    if nets:
        return {"ok": False, "path": path, "skipped_networks": sorted(nets),
                "error": "CIDR deny を完全一致の前衛へ部分適用できません。DuckNet の ACL を経由してください"}
    if not path:
        path = os.path.join(os.path.expanduser("~"), ".ducknet",
                            "edge_banlist.txt")
    try:
        from ..core.signed_state import _require_private_state_dir
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, mode=0o755, exist_ok=True)  # 外部前衛はこの公開生成物を読む
        _require_private_state_dir(parent)           # 既存0755は保ち、他UIDの置換だけ拒否
    except OSError as exc:
        return {"ok": False, "path": path, "error": f"安全な出力先ではありません: {exc}"}
    lines = [f"# DuckNet edge banlist (generated {time.strftime('%Y-%m-%d %H:%M:%S')})"]
    lines.extend(sorted(ips))
    text = "\n".join(lines) + "\n"
    if len(lines) > _BANLIST_MAX_ROWS or len(text.encode("utf-8")) > _BANLIST_MAX_BYTES:
        return {"ok": False, "path": path, "error": "前衛の遮断リスト上限を超えます"}
    previous = _read_export(path)
    status = {}
    if not atomic_write_text(path, text, export_mode=0o644, newline="", status=status):
        return {"ok": False, "path": path, "error": "BAN リストを保存できません"}
    if status.get("durable") is False:
        restored = _restore_export(path, previous)
        return {"ok": False, "path": path, "partial": not restored,
                "error": "BAN リストの耐久化に失敗しました", "durable": False}
    return {"ok": True, "path": path, "count": len(ips),
            "skipped_networks": sorted(nets)}


def edge_proxy_config(banlist_path: str = "/etc/ducknet/edge_banlist.txt",
                      backend: str = "127.0.0.1:8787",
                      listen: int = 8080) -> str:
    """BANリストを読み、命中したら return 444(即切断)するプロキシ設定を返す。
    綺麗なアクセスだけを backend(本体 Web サービス)へ proxy_pass する。"""
    if type(listen) is not int or not 1 <= listen <= 65535:
        raise ValueError("listen must be a port between 1 and 65535")
    if not isinstance(backend, str) or len(backend) > 300 or backend.endswith(":"):
        raise ValueError("backend must be a host and port")
    from urllib.parse import urlsplit
    try:
        address = urlsplit("http://" + backend)
        host, port = address.hostname, address.port
        if (not host or address.username is not None or address.password is not None
                or address.path or address.query or address.fragment
                or not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", backend)
                or (port is not None and not 1 <= port <= 65535)):
            raise ValueError("invalid backend address")
        if ":" in host:
            ipaddress.IPv6Address(host)
    except ValueError as exc:
        raise ValueError("backend must be a host and optional port") from exc
    return f"""# === DuckNet edge shredder (Lua対応リバースプロキシ) ===
# 生成物: NetShield/firewall の判定を「カーネル手前」で 444 Drop する前衛。
# banlist は `banlist 出力ツール` が定期的に更新する想定(1行1IP・正規形)。
# 照合は remote_addr の完全一致のみ。CIDR deny がある export は部分出力せず失敗する。
# backend は DuckNet の前衛へ向け、アプリ本体を未検査で公開しないこと。
#
# 必要: Lua対応リバースプロキシ(lua モジュール)。Lua 無しの場合は geo/map で deny に置換可。

lua_shared_dict ducknet_ban 64m;

init_worker_by_lua_block {{
    local last_raw, last_generation
    local function load_bans()
        local d = ngx.shared.ducknet_ban
        local ready, epoch = "__ducknet_ready", "__ducknet_epoch"
        d:safe_add(ready, 0)
        -- A single atomic attempt increment gates every request before file
        -- I/O. A dead worker leaves no shared lock behind; a newer attempt
        -- fences any late old writer from publishing its stale snapshot.
        local prior = d:get(ready)
        local attempt = d:incr(epoch, 1, 1000000)
        if not attempt then
            -- This marker is safety-critical. On a dictionary allocation
            -- failure, allow eviction rather than retain a stale ready value.
            d:set(ready, 0)
            return
        end
        local function reap_older(cutoff, legacy, keep)
            for _, key in ipairs(d:get_keys(0)) do
                local n = tonumber(key:match("^__ducknet_ban_(%d+):"))
                if (n and n < cutoff and n ~= keep) or
                   (legacy and key:match("^[0-9a-fA-F:.]+$")) then
                    d:delete(key)
                end
            end
        end
        local updated = pcall(function()
        local f = io.open({_lua_str(banlist_path)}, "r")
        if not f then return end
        -- 読めないファイルで既存の遮断を空にしない。最後まで読んでから反映する。
        local ok, raw = pcall(f.read, f, 8 * 1024 * 1024 + 1)
        f:close()
        if not ok or not raw or #raw > 8 * 1024 * 1024 or raw:sub(-1) ~= "\\n" then return end
        if d:get(epoch) ~= attempt then return end
        local prior_attempt, prior_generation
        if type(prior) == "string" then
            prior_attempt, prior_generation = prior:match("^(%d+):(%d+)$")
            prior_attempt, prior_generation = tonumber(prior_attempt), tonumber(prior_generation)
        end
        -- A normal 10-second refresh need only compare the exact wire file
        -- and extend the 20-second readiness lease. Retain one Lua string;
        -- unchanged 100k-row files do not rebuild all shared-dict keys.
        if raw == last_raw and last_generation == prior_generation and
           prior_attempt == attempt - 1 then
            if not d:safe_set(ready, attempt .. ":" .. last_generation, 20) then
                error("ban readiness renewal failed")
            end
            return
        end
        local rows, count = {{}}, 0
        for line in raw:gmatch("([^\\n]*)\\n") do
            count = count + 1
            if count > 100000 or #line > 4096 then return end
            local ip = line:gsub("%s+", "")
            if ip ~= "" and ip:sub(1,1) ~= "#" then
                if not ip:match("^[0-9a-fA-F:.]+$") then return end
                rows[ip] = true
            end
        end
        if d:get(epoch) ~= attempt then return end
        -- Preserve the previous complete generation while staging. A failed
        -- attempt may have filled the dictionary with partial keys; reclaim
        -- every older nonpublished generation before trying again.
        if prior_attempt ~= attempt - 1 then
            reap_older(attempt, false, prior_generation)
        end
        for ip in pairs(rows) do
            if not d:safe_set("__ducknet_ban_" .. attempt .. ":" .. ip, 1) then
                error("ban dictionary full")
            end
        end
        if d:get(epoch) ~= attempt then return end
        -- A 20-second readiness lease expires before a dead reload timer can
        -- silently leave an obsolete BAN set serving indefinitely.
        if not d:safe_set(ready, attempt .. ":" .. attempt, 20) then
            error("ban dictionary unavailable")
        end
        reap_older(attempt, true)
        last_raw, last_generation = raw, attempt
        end)
        if not updated then ngx.log(ngx.ERR, "ducknet ban reload failed") end
    end
    -- worker0 owns the periodic refresh; overlapping generations are fenced.
    if ngx.worker.id() ~= 0 then return end
    load_bans()
    -- 10秒毎にBANリストを再読込(NetShieldの最新判定に追従)
    local ok, err = ngx.timer.every(10, load_bans)
    if not ok then ngx.log(ngx.ERR, "ducknet ban reload timer: ", err) end
}}

server {{
    listen {listen};

    location / {{
        access_by_lua_block {{
            local ip = ngx.var.remote_addr
            local d = ngx.shared.ducknet_ban
            local attempt = d:get("__ducknet_epoch")
            local ready = d:get("__ducknet_ready")
            local ready_attempt, generation
            if type(ready) == "string" then
                ready_attempt, generation = ready:match("^(%d+):(%d+)$")
            end
            if not attempt or tonumber(ready_attempt) ~= attempt or not generation or
               d:get("__ducknet_ban_" .. generation .. ":" .. ip) or
               d:get("__ducknet_epoch") ~= attempt or d:get("__ducknet_ready") ~= ready then
                -- 444: レスポンスを返さず即座にTCP接続を切断(リソースを1ミリも汚さない)
                return ngx.exit(444)
            end
        }}
        proxy_pass http://{backend};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 20s;
    }}
}}
"""


def write_bundle(out_dir: str = "", backend: str = "127.0.0.1:8787",
                 listen: int = 8080) -> dict:
    """edge 連携一式(banlist + プロキシ設定)を out_dir に書き出す。"""
    if not out_dir:
        out_dir = os.path.join(os.path.expanduser("~"), ".ducknet", "edge")
    from ..core.signed_state import _state_guard, _require_private_state_dir
    try:
        out_dir = os.path.abspath(out_dir)
        banlist = os.path.join(out_dir, "edge_banlist.txt")
        conf = os.path.join(out_dir, "ducknet_edge.conf")
        config_text = edge_proxy_config(banlist_path=banlist, backend=backend, listen=listen)
        os.makedirs(out_dir, mode=0o755, exist_ok=True)
        _require_private_state_dir(out_dir)
        with _state_guard(banlist) as locked:
            if not locked:
                return {"ok": False, "dir": out_dir, "error": "出力先をロックできません"}
            old = {path: _read_export(path) for path in (banlist, conf)}
            with tempfile.TemporaryDirectory(prefix=".ducknet-bundle-", dir=out_dir) as staging:
                staged_bans = os.path.join(staging, "edge_banlist.txt")
                bl = _export_banlist(staged_bans)
                if bl.get("ok") is not True:
                    return {**bl, "path": banlist}
                staged_conf = os.path.join(staging, "ducknet_edge.conf")
                status = {}
                if (not atomic_write_text(staged_conf, config_text, export_mode=0o644, newline="", status=status)
                        or status.get("durable") is False):
                    return {"ok": False, "dir": out_dir, "error": "前衛設定を準備できません"}
                new_bans = _read_export(staged_bans)
                for path, text in ((banlist, new_bans), (conf, config_text)):
                    status = {}
                    try:
                        saved = atomic_write_text(path, text, export_mode=0o644, newline="", status=status)
                    except Exception:
                        saved = False
                    if not saved or status.get("durable") is False:
                        restored = [_restore_export(target, previous) for target, previous in old.items()]
                        return {"ok": False, "dir": out_dir, "partial": not all(restored),
                                "error": "前衛設定を保存できません" if all(restored)
                                         else "前衛設定の保存と復元に失敗しました。出力を再生成してください"}
    except (OSError, ValueError, TypeError) as exc:
        return {"ok": False, "dir": out_dir, "error": f"前衛設定を生成できません: {exc}"}
    return {"ok": True, "dir": out_dir, "banlist": banlist,
            "config": conf, "banned": bl["count"],
            "skipped_networks": bl["skipped_networks"],   # 前衛では未適用の CIDR deny
            "note": "対応プロキシに ducknet_edge.conf を読ませ、banlistを定期更新すれば前衛完成。"}


def _read_export(path):
    try:
        previous = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(previous.st_mode):
        raise ValueError("export target must be a regular file")
    if os.name == "posix" and (previous.st_uid != os.geteuid() or previous.st_mode & 0o022):
        raise PermissionError("export target is writable by an untrusted owner")
    with open(path, "rb") as handle:
        raw = handle.read(_BANLIST_MAX_BYTES + 1)
    if len(raw) > _BANLIST_MAX_BYTES:
        raise ValueError("previous export exceeds limit")
    return raw.decode("utf-8")


def _restore_export(path, previous):
    try:
        if _read_export(path) != previous:
            if previous is None:
                os.unlink(path)
                from ..core.atomic_io import _sync_directory
                if _sync_directory(os.path.dirname(path)) is False:
                    return False
            else:
                status = {}
                if (not atomic_write_text(path, previous, export_mode=0o644, newline="", status=status)
                        or status.get("durable") is False):
                    return False
        return _read_export(path) == previous
    except Exception:
        return False
