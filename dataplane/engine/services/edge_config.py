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
最速地点**で適用でき、綺麗な(PoWを解いた)アクセスだけを Python 本体へ通せる。
本体を持たない利用者向けには [[proxy]](stdlib asyncio)が同じ Fail-Fast を依存ゼロで提供する。

正直: ここで返すのは設定テキストとIPリストだけ。実際に 444 を撃つのは利用者側のプロキシ。
本体は外部プロセスを起動・依存しない(オフライン・stdlib のまま)。
"""
from __future__ import annotations

import os
import time


def export_banlist(path: str = "") -> dict:
    """現在の遮断対象IP(shield BAN + firewall deny)を 1行1IP でファイル出力する。"""
    ips = set()
    try:
        from ..lifeform.pipeline import net_shield
        for b in net_shield().bans():
            ips.add(b["ip"])
    except Exception:
        pass
    try:
        from ..lifeform.policy import app_firewall
        for r in app_firewall().rules:
            if r.get("action") == "deny" and r.get("net"):
                ips.add(r["net"])
    except Exception:
        pass
    if not path:
        path = os.path.join(os.path.expanduser("~"), ".chickennet",
                            "edge_banlist.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    from ...profile import cover_brand        # ステルス時は生成物にも製品名を出さない
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# {cover_brand('ChickenNet')} edge banlist "
                f"(generated {time.strftime('%Y-%m-%d %H:%M:%S')})\n")
        for ip in sorted(ips):
            f.write(ip + "\n")
    return {"ok": True, "path": path, "count": len(ips)}


def edge_proxy_config(banlist_path: str = "/etc/chickennet/edge_banlist.txt",
                      backend: str = "127.0.0.1:8787",
                      listen: int = 8080) -> str:
    """BANリストを読み、命中したら return 444(即切断)するプロキシ設定を返す。
    綺麗なアクセスだけを backend(本体 Web サービス)へ proxy_pass する。"""
    from ...profile import cover_brand
    return f"""# === {cover_brand('ChickenNet')} edge shredder (Lua対応リバースプロキシ) ===
# 生成物: NetShield/firewall の判定を「カーネル手前」で 444 Drop する前衛。
# banlist は `banlist 出力ツール` が定期的に更新する想定(1行1IP/CIDR)。
#
# 必要: Lua対応リバースプロキシ(lua モジュール)。Lua 無しの場合は geo/map で deny に置換可。

lua_shared_dict chickennet_ban 16m;

init_worker_by_lua_block {{
    local function load_bans()
        local d = ngx.shared.chickennet_ban
        d:flush_all()
        local f = io.open("{banlist_path}", "r")
        if not f then return end
        for line in f:lines() do
            local ip = line:gsub("%s+", "")
            if ip ~= "" and ip:sub(1,1) ~= "#" then d:set(ip, 1) end
        end
        f:close()
    end
    load_bans()
    -- 10秒毎にBANリストを再読込(NetShieldの最新判定に追従)
    local ok, err = ngx.timer.every(10, load_bans)
    if not ok then ngx.log(ngx.ERR, "chickennet ban reload timer: ", err) end
}}

server {{
    listen {listen};

    location / {{
        access_by_lua_block {{
            local ip = ngx.var.remote_addr
            if ngx.shared.chickennet_ban:get(ip) then
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
        out_dir = os.path.join(os.path.expanduser("~"), ".chickennet", "edge")
    os.makedirs(out_dir, exist_ok=True)
    banlist = os.path.join(out_dir, "edge_banlist.txt")
    conf = os.path.join(out_dir, "chickennet_edge.conf")
    bl = export_banlist(banlist)
    with open(conf, "w", encoding="utf-8") as f:
        f.write(edge_proxy_config(banlist_path=banlist, backend=backend, listen=listen))
    return {"ok": True, "dir": out_dir, "banlist": banlist,
            "config": conf, "banned": bl["count"],
            "note": "対応プロキシに chickennet_edge.conf を読ませ、banlistを定期更新すれば前衛完成。"}
