"""
test_complexity.py — 二次コスト(O(N^2))の再発防止。
====================================================================================
どれも「1 回あたりは O(N) に見えるが、N 回繰り返すと O(N^2) になる」形の欠陥だった。
共通する誤りは *上限ちょうどまでしか削らない間引き* で、上限に達した後は毎回フル走査に
なる(しかも回収 0 件で張り付くものもあった)。ここでは低水位まで確実に縮むことを
**構造的に**(実行時間ではなく状態で)確かめる=CI でフレークしない。
併せて、走査を削ったことで結果が変わっていないことも押さえる。
"""
import os
import tempfile
import time

from dataplane.engine.core.atomic_io import append_jsonl, tail_jsonl
from dataplane.engine.lifeform.pipeline import (
    _SUBNET_IP_CAP, _SUBNET_IP_LOW, _USAGE_HOSTS_CAP, _USAGE_HOSTS_LOW, NetShield)
from dataplane.engine.lifeform.policy import _PENDING_MAX, AppFirewall
from dataplane.engine.services.proxy import (
    _CONN_RATE_CAP, _CONN_RATE_LOW, AsyncEdgeGuard)


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


# ── 間引きは「上限ちょうど」ではなく「低水位」まで落ちること ──
def test_conn_rate_table_shrinks_even_when_nothing_expired():
    """期限切れが 1 件も無い(=窓内の別IPで埋まった)状態でも表が縮むこと。
    旧実装は期限切れだけを最大 5000 件消す実装で、この状況では回収 0 件のまま
    *毎接続* 5 万件を走査し続けた(実測 1.53ms/接続)。"""
    g = AsyncEdgeGuard()
    now = time.monotonic()
    for i in range(_CONN_RATE_CAP + 1):
        g._conn_rate["10.%d.%d.%d" % (i // 65536, (i // 256) % 256, i % 256)] = [now, 1]
    g._conn_rate_exceeded("172.16.0.1", 100)
    assert len(g._conn_rate) <= _CONN_RATE_LOW + 1, len(g._conn_rate)


def test_conn_rate_still_limits():
    g = AsyncEdgeGuard()
    hits = [g._conn_rate_exceeded("203.0.113.9", 5) for _ in range(8)]
    assert hits[:5] == [False] * 5 and all(hits[5:])


def test_subnet_ban_table_shrinks_to_low_water():
    """サブネット内 distinct IP の表。IPv4 は /24 に畳まれるので最大 256 個=上限と同値で
    この分岐に到達しない。実際に溢れるのは /64 に畳まれる IPv6 側なのでそちらで確かめる。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, subnet_defense=True)
        for i in range(_SUBNET_IP_CAP + 40):
            sh._record_subnet_ban("2001:db8::%x" % i)
        rec = next(iter(sh._subnets.values()))
        assert len(rec) <= _SUBNET_IP_CAP, len(rec)
        # 上限を跨いだ直後は低水位まで落ちていること(上限ちょうどで止めない)
        sh2 = _shield(d, subnet_defense=True)
        for i in range(_SUBNET_IP_CAP + 1):
            sh2._record_subnet_ban("2001:db8:1::%x" % i)
        assert len(next(iter(sh2._subnets.values()))) == _SUBNET_IP_LOW


def test_usage_hosts_shrink_to_low_water():
    """IP あたりの宛先表。旧実装は 60 件ちょうどまでしか刈らず、そのIPの次の
    リクエストでまた全件ソートになっていた(ホットパス)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, usage_record=True)
        for i in range(_USAGE_HOSTS_CAP + 1):
            sh._record_usage("203.0.113.7", 100, 50, 0.1, "h%d.example" % i, "GET", "/")
        # 上限を跨いだ直後は低水位まで落ちる(上限ちょうどで止めると次の 1 件でまた全ソート)
        assert len(sh._usage["203.0.113.7"]["hosts"]) == _USAGE_HOSTS_LOW
        for i in range(200):                       # その後も上限を超えない
            sh._record_usage("203.0.113.7", 100, 50, 0.1, "g%d.example" % i, "GET", "/")
        assert len(sh._usage["203.0.113.7"]["hosts"]) <= _USAGE_HOSTS_CAP


def test_pending_lookup_is_by_ip_and_table_is_bounded():
    """承認待ち表。旧実装は接続ごとに全件を線形走査し、しかも上限が無かった。"""
    with tempfile.TemporaryDirectory() as d:
        fw = AppFirewall(state_dir=d)
        a = fw._enqueue_pending("203.0.113.9", 443, "public", {})
        b = fw._enqueue_pending("203.0.113.9", 443, "public", {})
        assert a == b                               # 同一IPは再利用(氾濫防止)
        for i in range(_PENDING_MAX + 50):
            fw._enqueue_pending("10.%d.%d.%d" % (i // 65536, (i // 256) % 256, i % 256),
                                443, "public", {})
        assert len(fw._pending) <= _PENDING_MAX
        assert len(fw._pending_by_ip) <= _PENDING_MAX + 1   # 逆引きも一緒に縮む


# ── 走査量を削っても結果が変わらないこと ──
def test_tail_jsonl_reads_only_the_tail_but_stays_correct():
    """末尾 n 行が欲しいだけなのに全体を readlines() していた。末尾読みへ変えても
    件数・順序(新しい順)・内容が変わらないこと。初回の見積りを超える行長でも正しいこと。"""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "log.jsonl")
        for i in range(3000):
            append_jsonl(p, {"i": i, "pad": "x" * 200}, max_bytes=1 << 30)
        rows = tail_jsonl(p, 50)
        assert len(rows) == 50
        assert rows[0]["i"] == 2999 and rows[-1]["i"] == 2950   # 新しい順
        assert tail_jsonl(p, 5)[0]["i"] == 2999
        assert len(tail_jsonl(p, 100000)) == 3000               # n が全行を超えても取り切る


def test_ip_list_block_matches_the_same_set_after_cidr_caching():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, ip_mode="blacklist",
                     ip_blacklist=["203.0.113.0/24", "10.0.0.0/8", "2001:db8::/32"])
        assert sh._ip_list_block("203.0.113.9")
        assert sh._ip_list_block("10.1.2.3")
        assert sh._ip_list_block("2001:db8::1")
        assert not sh._ip_list_block("198.51.100.7")
        assert not sh._ip_list_block("2001:db9::1")


def test_firewall_rule_match_prefers_deny_and_longest_prefix():
    """ルールの ip_network を事前コンパイルへ変えたので、deny 優先・最長一致が
    従来どおりであることを押さえる。"""
    with tempfile.TemporaryDirectory() as d:
        fw = AppFirewall(state_dir=d)
        fw.rules[:] = [{"id": "a", "net": "203.0.113.0/24", "action": "allow"},
                       {"id": "b", "net": "203.0.113.0/28", "action": "deny"},
                       {"id": "c", "net": "0.0.0.0/0", "action": "allow"}]
        assert fw._match_rule("203.0.113.1")["id"] == "b"    # deny 優先
        assert fw._match_rule("203.0.113.99")["id"] == "a"   # 最長一致
        assert fw._match_rule("198.51.100.7")["id"] == "c"


def test_dashboard_top_n_matches_a_full_sort():
    """heap で上位 n 件だけ選ぶよう変えたので、全ソートと同じ並びになることを確かめる。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for i in range(300):
            st = sh._state("10.0.%d.%d" % (i // 256, i % 256))
            st["score"] = float(i % 97)
            st["hits"] = i % 13
        want = sorted(
            ((round(sh._decayed_score(s), 1), len(s["window"]), ip)
             for ip, s in sh._ips.items()), reverse=True)[:15]
        got = [(r["score"], r["reqs_window"], r["ip"]) for r in sh.top_talkers(15)]
        assert got == want
        nd = sh.nodes(20)
        assert len(nd["nodes"]) == 20
        assert sum(nd["zones"].values()) == len(sh._ips)      # ゾーン集計は全件ぶん
        assert nd["nodes"] == sorted(
            nd["nodes"], key=lambda r: (r["banned"], r["score"], r["reqs_window"]),
            reverse=True)


def test_zone_is_cached_on_state_and_matches_direct_resolution():
    from dataplane.engine.lifeform.pipeline import _zone_of
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for ip in ("127.0.0.1", "10.1.2.3", "203.0.113.9"):
            st = sh._state(ip)
            assert st["zone"] == _zone_of(ip)


def test_head_terminator_split_across_reads_is_detected():
    """終端探索を「新着分＋3バイトの重なり」に変えたので、\\r\\n\\r\\n が読取をまたいで
    割れても検出できることを押さえる(全体再走査をやめた代償が出ていないこと)。"""
    import asyncio

    class Split:
        def __init__(self, parts):
            self.parts = list(parts)

        async def read(self, n):
            return self.parts.pop(0) if self.parts else b""

    async def run(parts):
        g = AsyncEdgeGuard()
        g.head_timeout = 5.0
        return await g._read_head(Split(parts))

    for parts in ([b"GET / HTTP/1.1\r\nHost: x\r\n\r", b"\n", b""],
                  [b"GET / HTTP/1.1\r\nHost: x\r", b"\n\r\n", b""],
                  [b"GET / HTTP/1.1\r\nHost: x\r\n", b"\r\n", b""],
                  [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b""]):
        buf = asyncio.run(run(parts))
        assert b"\r\n\r\n" in buf, parts
