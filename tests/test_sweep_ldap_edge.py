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

from dataplane.engine.services import edge_config as EC


# ── c50 ────────────────────────────────────────────────────────────────
class _FakeShield:
    def bans(self):
        return [{"ip": "198.51.100.7"}, {"ip": "2001:DB8:0:0::5"}]


class _FakeFirewall:
    rules = [{"net": "203.0.113.0/24", "action": "deny"},
             {"net": "2001:DB8::1", "action": "deny"},
             {"net": "192.0.2.9/32", "action": "deny"},
             {"net": "10.9.9.9", "action": "allow"}]


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
    assert "203.0.113.0/24" in r.get("skipped_networks", [])   # 載せない分は明示


# ── c87 ────────────────────────────────────────────────────────────────
_LUA_ESC = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f",
            "v": "\v", "\\": "\\", '"': '"', "'": "'"}


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
