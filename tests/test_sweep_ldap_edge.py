"""
test_sweep_ldap_edge.py — エッジ前衛生成物(edge_config)の回帰テスト(掃討分)
====================================================================================
(フル版の同名モジュールのうち、Lite にも存在する edge_config 分だけ)
  · c50: エッジ banlist に CIDR/非正規 IPv6 が載り、Lua の完全一致では一切命中しなかった
  · c87: Windows パスを Lua 文字列リテラルへ無エスケープで埋め込み、設定が壊れていた
"""
import ipaddress
import os
import re
import tempfile
import shutil
import subprocess
from unittest import SkipTest, mock

from dataplane.engine.services import edge_config as EC


# ── c50 ────────────────────────────────────────────────────────────────
class _FakeShield:
    cfg = {"mode": "enforce"}

    def is_enabled(self):
        return True

    def bans(self):
        return [{"ip": "198.51.100.7"}, {"ip": "2001:DB8:0:0::5"}]


class _FakeFirewall:
    rules = [{"net": "2001:DB8::1", "action": "deny"},
             {"net": "192.0.2.9/32", "action": "deny"},
             {"net": "10.9.9.9", "action": "allow"}]

    def is_enabled(self):
        return True


def test_c50_banlist_entries_match_lua_exact_lookup():
    """前衛の Lua は remote_addr(正規形の単一IP)で完全一致を引くだけなのに、banlist には
    CIDR や大文字/非圧縮の IPv6 がそのまま載っていた=遮断したつもりで一切命中しない。"""
    import dataplane.engine.lifeform.pipeline as PL
    import dataplane.engine.lifeform.policy as PO
    orig = (PL.net_shield, PO.app_firewall)
    PL.net_shield = lambda: _FakeShield()
    PO.app_firewall = lambda: _FakeFirewall()
    try:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "edge_banlist.txt")
            r = EC.export_banlist(path)
            with open(path, encoding="utf-8") as f:
                keys = [ln.strip() for ln in f
                        if ln.strip() and not ln.lstrip().startswith("#")]
    finally:
        PL.net_shield, PO.app_firewall = orig
    for k in keys:                                # 載るのは Lua が引ける正規形の単一IPだけ
        assert "/" not in k and str(ipaddress.ip_address(k)) == k, k
    assert set(keys) == {"198.51.100.7", "2001:db8::5", "2001:db8::1", "192.0.2.9"}, keys
    assert r["count"] == 4
    assert r["ok"] is True and r.get("skipped_networks") == []


def test_cidr_export_is_not_reported_as_partial_success():
    class FirewallWithCIDR(_FakeFirewall):
        rules = _FakeFirewall.rules + [{"net": "203.0.113.0/24", "action": "deny"}]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "banlist")
        with open(path, "wb") as f:
            f.write(b"192.0.2.9\n")
        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=_FakeShield()), \
                mock.patch("dataplane.engine.lifeform.policy.app_firewall", return_value=FirewallWithCIDR()):
            result = EC.export_banlist(path)
        assert result["ok"] is False and result["skipped_networks"] == ["203.0.113.0/24"]
        with open(path, "rb") as f:
            assert f.read() == b"192.0.2.9\n"


def test_real_sources_export_active_existing_bans_and_active_deny_rules():
    import dataplane.engine.lifeform.pipeline as PL
    import dataplane.engine.lifeform.policy as PO

    with tempfile.TemporaryDirectory() as d:
        shield = PL.NetShield(state_dir=d)
        firewall = PO.AppFirewall(state_dir=d)
        assert shield.set_config(enabled=True, mode="enforce")["ok"]
        assert shield.ban("198.51.100.7")["ok"]
        assert firewall.add_rule("192.0.2.9/32", "deny")["ok"]
        path = os.path.join(d, "edge_banlist.txt")

        def exported():
            assert EC.export_banlist(path)["ok"]
            with open(path, encoding="utf-8") as handle:
                return {line.strip() for line in handle
                        if line.strip() and not line.startswith("#")}

        with mock.patch.object(PL, "net_shield", return_value=shield), \
                mock.patch.object(PO, "app_firewall", return_value=firewall):
            assert exported() == {"198.51.100.7", "192.0.2.9"}
            assert shield.disable()["ok"]
            assert exported() == {"192.0.2.9"}
            assert firewall.disable()["ok"]
            assert exported() == set()
            assert shield.enable()["ok"]
            assert shield.set_config(mode="audit")["ok"]
            assert shield.is_banned_fast("198.51.100.7")
            assert exported() == {"198.51.100.7"}
            assert firewall.enable()["ok"]
            assert exported() == {"198.51.100.7", "192.0.2.9"}
            assert shield.set_config(mode="enforce")["ok"]
            assert exported() == {"198.51.100.7", "192.0.2.9"}


def test_audit_existing_ban_export_matches_real_proxy_enforcement():
    from test_sweep_proxy_request import _shield, _guard, _Backend, _exchange
    backend = _Backend()
    try:
        with tempfile.TemporaryDirectory() as d, _shield(mode="audit") as shield:
            assert shield.ban("127.0.0.1")["ok"]
            with _guard(backend) as guard:
                _exchange(guard, [b"GET /audit-banned HTTP/1.1\r\nHost: x\r\n\r\n"])
                assert backend.saw() == b""
                path = os.path.join(d, "edge_banlist.txt")
                result = EC.export_banlist(path)
                assert result["ok"] and result["count"] == 1
                with open(path, encoding="utf-8") as handle:
                    assert "127.0.0.1\n" in handle.read()
                assert shield.unban("127.0.0.1")["ok"]
                response = _exchange(guard, [b"GET /audit-benign HTTP/1.1\r\nHost: x\r\n\r\n"])
                assert response.startswith(b"HTTP/1.1 200") and b"/audit-benign" in backend.saw()
    finally:
        backend.close()


def test_invalid_ban_or_deny_source_keeps_previous_export_bytes():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "edge_banlist.txt")
        old = b"192.0.2.9\n"
        for bad in (None, 1, "300.1.1.1", "fe80::1%eth0", " 192.0.2.1"):
            with open(path, "wb") as handle:
                handle.write(old)

            class BadShield(_FakeShield):
                def bans(self):
                    return [{"ip": bad}]

            with mock.patch("dataplane.engine.lifeform.pipeline.net_shield",
                            return_value=BadShield()), \
                    mock.patch("dataplane.engine.lifeform.policy.app_firewall",
                               return_value=_FakeFirewall()):
                assert EC.export_banlist(path)["ok"] is False
            with open(path, "rb") as handle:
                assert handle.read() == old

        class BadFirewall(_FakeFirewall):
            rules = [{"action": "deny", "net": None}]

        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield",
                        return_value=_FakeShield()), \
                mock.patch("dataplane.engine.lifeform.policy.app_firewall",
                           return_value=BadFirewall()):
            assert EC.export_banlist(path)["ok"] is False
        with open(path, "rb") as handle:
            assert handle.read() == old


def test_unknown_source_protection_state_keeps_previous_export():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "edge_banlist.txt")
        old = b"192.0.2.9\n"
        with open(path, "wb") as handle:
            handle.write(old)

        class UnknownShield(_FakeShield):
            cfg = {"mode": "unknown"}

        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield",
                        return_value=UnknownShield()), \
                mock.patch("dataplane.engine.lifeform.policy.app_firewall",
                           return_value=_FakeFirewall()):
            assert EC.export_banlist(path)["ok"] is False
        with open(path, "rb") as handle:
            assert handle.read() == old


# ── c87 ────────────────────────────────────────────────────────────────
_LUA_ESC = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f",
            "v": "\v", "\\": "\\", '"': '"', "'": "'"}


def test_unavailable_ban_sources_preserve_previous_export_and_bundle():
    with tempfile.TemporaryDirectory() as d:
        banlist = os.path.join(d, "edge_banlist.txt")
        config = os.path.join(d, "ducknet_edge.conf")
        for path, text in ((banlist, "192.0.2.9\n"), (config, "previous config\n")):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        for failed in ("dataplane.engine.lifeform.pipeline.net_shield",
                       "dataplane.engine.lifeform.policy.app_firewall"):
            with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=_FakeShield()), \
                    mock.patch("dataplane.engine.lifeform.policy.app_firewall", return_value=_FakeFirewall()), \
                    mock.patch(failed, side_effect=OSError("unavailable")):
                assert EC.export_banlist(banlist)["ok"] is False
                assert EC.write_bundle(d)["ok"] is False
            with open(banlist, encoding="utf-8") as f:
                assert f.read() == "192.0.2.9\n"
            with open(config, encoding="utf-8") as f:
                assert f.read() == "previous config\n"


def test_failed_export_write_preserves_previous_bytes():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "banlist")
        with open(path, "w", encoding="utf-8") as f:
            f.write("192.0.2.9\n")
        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=_FakeShield()), \
                mock.patch("dataplane.engine.lifeform.policy.app_firewall", return_value=_FakeFirewall()), \
                mock.patch("dataplane.engine.core.atomic_io.os.replace", side_effect=OSError("disk failure")):
            assert EC.export_banlist(path)["ok"] is False
        with open(path, encoding="utf-8") as f:
            assert f.read() == "192.0.2.9\n"
        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=_FakeShield()), \
                mock.patch("dataplane.engine.lifeform.policy.app_firewall", return_value=_FakeFirewall()), \
                mock.patch.object(EC, "_BANLIST_MAX_ROWS", 2):
            assert EC.export_banlist(path)["ok"] is False
        with open(path, encoding="utf-8") as f:
            assert f.read() == "192.0.2.9\n"


def test_posix_exports_preserve_worker_readable_permissions():
    if os.name != "posix":
        raise SkipTest("POSIX の mode/uid/gid を持つ FS が必要")
    import stat
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "edge_banlist.txt")
        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=_FakeShield()), \
                mock.patch("dataplane.engine.lifeform.policy.app_firewall", return_value=_FakeFirewall()):
            assert EC.export_banlist(path)["ok"]
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
            os.chmod(path, 0o640)
            previous = os.stat(path)
            assert EC.export_banlist(path)["ok"]
            after = os.stat(path)
            assert stat.S_IMODE(after.st_mode) == 0o640
            assert (after.st_uid, after.st_gid) == (previous.st_uid, previous.st_gid)


def _lua_short_string(src: str, start: int) -> str:
    """src[start] の '"' から Lua の短い文字列リテラルを厳格に復号する
    (LuaJIT と同じく未知のエスケープは不正)。"""
    assert src[start] == '"'
    out, i = [], start + 1
    while True:
        ch = src[i]
        if ch == '"':
            return "".join(out)
        if ch in "\r\n":
            raise ValueError("unfinished string")
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = src[i + 1]
        if nxt in _LUA_ESC:
            out.append(_LUA_ESC[nxt])
            i += 2
            continue
        m = re.match(r"\d{1,3}", src[i + 1:])
        if m:
            out.append(chr(int(m.group())))
            i += 1 + len(m.group())
            continue
        raise ValueError("invalid escape sequence \\" + nxt)


def test_c87_banlist_path_is_a_valid_lua_string():
    """Windows パス(バックスラッシュ)や引用符をそのまま io.open("...") に埋め込んでいたため、
    \\U 等で Lua が読込失敗し、\\n 等では別のパスを開いていた。"""
    path = 'C:\\Users\\Tester\\edge "a\'b<c"\\new\\edge_banlist.txt'
    conf = EC.edge_proxy_config(banlist_path=path)
    at = conf.index("io.open(") + len("io.open(")
    assert _lua_short_string(conf, at) == path
    # 既定(POSIX パス)は従来どおりの見た目
    assert 'io.open("/etc/ducknet/edge_banlist.txt", "r")' in EC.edge_proxy_config()


def test_generated_lua_reload_preserves_denies_on_io_or_capacity_failure():
    """生成した Lua を実行し、読み込み・反映失敗中の辞書を観測する。"""
    lua = shutil.which("lua") or shutil.which("luajit")
    if not lua:
        raise SkipTest("Lua 実行環境なし（外部前衛の生成物のみ）")
    conf = EC.edge_proxy_config()
    body = conf.split("init_worker_by_lua_block {", 1)[1].split("\n}\n\nserver", 1)[0]
    access = conf.split("access_by_lua_block {", 1)[1].split("\n        }", 1)[0]
    script = r'''
local data = { ["192.0.2.9"] = 1 }
local mode, callback, worker = "missing", nil, 0
local dict = {}
function dict:flush_all() data = {} end
function dict:set(k,v) data[k] = v; return true end
function dict:safe_set(k,v)
    if mode == "full" and data[k] == nil then return nil, "no memory" end
    data[k] = v; return true
end
function dict:safe_add(k,v)
    if data[k] ~= nil then return nil, "exists" end
    return self:safe_set(k,v)
end
function dict:get(k) return data[k] end
function dict:incr(k,v,initial)
    data[k] = (data[k] or initial) + v
    return data[k]
end
function dict:get_keys()
    local out = {}; for k in pairs(data) do table.insert(out,k) end; return out
end
function dict:delete(k) data[k] = nil end
ngx = { shared={ducknet_ban=dict}, worker={id=function() return worker end,
        pid=function() return 9123 end}, now=function() return 0 end,
        var={remote_addr="203.0.113.88"},
        exit=function(code) return code end,
        timer={every=function(_, fn) callback=fn; return true end}, log=function() end }
io.open = function()
    if mode == "missing" then return nil end
    return {close=function() end, read=function(_, n)
        assert(n <= 8*1024*1024+1, "unbounded file read")
        if mode == "broken" then error("read failure") end
        if mode == "bytes" then return string.rep("x",n) end
        if mode == "rows" then return string.rep("198.51.100.7\n",100001) end
        if mode == "partial" then return "198.51.100.7" end
        if mode == "reentrant" then
            assert(data["__ducknet_epoch"], "read happened before attempt fence")
            local was=mode; mode="ok"; callback(); mode=was
        end
        return "198.51.100.7\n"
    end}
end
local function bootstrap()
''' + body + r'''
end
local function access_request()
''' + access + r'''
end
bootstrap()
assert(data["192.0.2.9"], "missing file cleared existing deny")
assert(access_request()==444, "missing initial file permitted backend access")
assert(callback, "reload timer missing")
mode="broken"; callback()
assert(data["192.0.2.9"], "read failure cleared existing deny")
assert(access_request()==444, "read failure permitted backend access")
mode="full"; callback()
assert(data["192.0.2.9"], "capacity failure cleared existing deny")
for _, m in ipairs({"bytes","rows","partial"}) do
    mode=m; callback()
    assert(data["192.0.2.9"], "over-limit or partial input cleared existing deny")
end
mode="ok"; callback()
local generation=data["__ducknet_epoch"]
assert(data["__ducknet_ban_"..generation..":198.51.100.7"] and not data["192.0.2.9"],
       "valid reload did not replace")
assert(access_request()==nil, "valid harmless peer was blocked")
ngx.var.remote_addr="198.51.100.7"
assert(access_request()==444, "valid reload did not deny listed peer")
ngx.var.remote_addr="203.0.113.88"
mode="reentrant"; callback()
local ready_attempt, ready_generation=data["__ducknet_ready"]:match("^(%d+):(%d+)$")
assert(tonumber(ready_attempt)==data["__ducknet_epoch"],
       "concurrent reload changed readiness")
generation=tonumber(ready_generation)
data["__ducknet_loading"]=1
assert(access_request()==nil, "obsolete loader lock stranded benign traffic")
data["__ducknet_loading"]=nil
mode="missing"; callback()
assert(data["__ducknet_ban_"..generation..":198.51.100.7"],
       "later missing file cleared current deny")
assert(access_request()==444, "later missing file permitted backend access")
worker=1; callback=nil; bootstrap()
assert(not callback, "more than one worker owns reload")
'''
    result = subprocess.run([lua, "-"], input=script, text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, (result.stdout, result.stderr)
