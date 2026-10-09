"""
test_sweep_rem_geoip.py — GeoIP の国判定が入れ子の CIDR・IPv6 の行・IPv4-mapped で外れていた。
====================================================================================
· 入れ子の CIDR(/8 の中の /16 など)があると、内側の区間より後ろにある外側のアドレスを『不一致』と
  答えた(区間を開始位置だけで二分探索し、直前の区間に入らなければ諦めていた)。国の遮断が効かなかった。
· IPv4 と IPv6 を同じ整数の数直線に置いていたため、::/8 のような IPv6 の行が IPv4 のアドレスに当たった
  (すべての IPv4 クライアントがその行の国になる)。
· ::ffff:a.b.c.d(dual-stack の待受が渡す IPv4 クライアント)を IPv4 として引かず、不一致になった
  (proxy は正規化して渡すが、NetShield.inspect を直接呼ぶ使い方では国の遮断・CIDR の遮断が効かなかった)。
"""
import ipaddress
import os
import random
import tempfile
from unittest import SkipTest

import dataplane.engine.lifeform.pipeline as ND

try:
    import dataplane.engine.lifeform.geoip as GEO
except ImportError:                                    # Lite は国判定(GeoIP)を持たない
    GEO = None


def _geo(pairs):
    if GEO is None:
        raise SkipTest("GeoIP(国判定)は Full 版のみ")
    g = GEO.GeoIP()
    g.load_pairs(pairs)
    return g


def _inspect_with(g, ip, **cfg):
    old = GEO._GEO if GEO else None
    if GEO:
        GEO._GEO = g
    try:
        with tempfile.TemporaryDirectory() as d:
            sh = ND.NetShield(state_dir=d)
            sh.cfg.update(enabled=True, persist_bans=False)
            r = sh.set_config(**cfg)                   # 運用者の変更と同じ経路(geo_cidrs を組み直す)
            assert r.get("ok", True), r
            return sh.inspect(ip, path="/", method="GET", user_agent="Mozilla/5.0")
    finally:
        if GEO:
            GEO._GEO = old


def test_n1_address_in_outer_range_after_a_nested_range_keeps_the_outer_country():
    g = _geo([("10.0.0.0/8", "AA"), ("10.1.0.0/16", "BB")])
    r = _inspect_with(g, "10.2.0.0", geo_mode="country_block", geo_countries=["AA"])
    assert r["action"] == "block", r                                # 挙動の検査を先に
    assert [g.country(ip) for ip in ("10.0.0.0", "10.0.255.255", "10.1.0.0", "10.1.255.255",
                                     "10.2.0.0", "10.255.255.255", "11.0.0.0")] == \
        ["AA", "AA", "BB", "BB", "AA", "AA", ""]
    # 同じ CIDR が 2 行あれば後の行(上書き)。順序に依らず内側が勝つ
    assert _geo([("192.0.2.0/24", "AA"), ("192.0.2.0/24", "BB")]).country("192.0.2.9") == "BB"
    assert _geo([("10.1.0.0/16", "BB"), ("10.0.0.0/8", "AA")]).country("10.1.0.1") == "BB"


def test_n2_ipv6_rows_do_not_match_ipv4_addresses():
    g = _geo([("::/8", "ZZ"), ("203.0.113.0/24", "AA")])
    r = _inspect_with(g, "198.51.100.7", geo_mode="country_allow", geo_countries=["AA"])
    assert r["action"] == "allow", r          # 国が分からない=判定しない(ZZ と見て遮断しない)
    assert g.country("198.51.100.7") == "" and g.country("203.0.113.1") == "AA"
    assert g.country("::1") == "ZZ"
    assert _geo([("::/96", "ZZ")]).country("192.0.2.1") == ""


def test_n3_ipv4_mapped_addresses_are_looked_up_as_ipv4():
    g = _geo([("192.0.2.0/24", "AA")])
    r = _inspect_with(g, "::ffff:192.0.2.5", geo_mode="country_block", geo_countries=["AA"])
    assert r["action"] == "block", r
    assert g.country("::ffff:192.0.2.5") == "AA" and g.country(" 192.0.2.5 ") == "AA"


def test_n3b_ipv4_mapped_addresses_match_ipv4_geo_cidrs():
    """geo_mode=block / allow(geo_cidrs の CIDR 判定・両版)も ::ffff:a.b.c.d を IPv4 として照合する。"""
    r = _inspect_with(None, "::ffff:192.0.2.5", geo_mode="block", geo_cidrs=["192.0.2.0/24"])
    assert r["action"] == "block", r
    r = _inspect_with(None, "::ffff:192.0.2.5", geo_mode="allow", geo_cidrs=["192.0.2.0/24"])
    assert r["action"] == "allow", r
    r = _inspect_with(None, "::ffff:198.51.100.7", geo_mode="allow", geo_cidrs=["192.0.2.0/24"])
    assert r["action"] == "block", r


def test_n4_lookup_matches_most_specific_row_on_random_tables():
    """入れ子・重複・IPv4/IPv6 混在の表で、『含む行のうち最も細かいもの(同じなら後の行)』と一致する。"""
    rnd = random.Random(20261009)

    def rand_net():
        if rnd.random() < 0.35:
            p = rnd.choice([8, 32, 64, 96, 128])
            a = rnd.choice([0, 0x20010DB8 << 96, 0xFFFF << 32]) | (rnd.getrandbits(128) & ((1 << (128 - min(p, 112))) - 1))
            return ipaddress.ip_network((a, p), strict=False)
        p = rnd.choice([0, 8, 16, 24, 30, 32])
        return ipaddress.ip_network(((10 << 24 | rnd.getrandbits(20)) if rnd.random() < 0.7
                                     else rnd.getrandbits(32), p), strict=False)

    def ref(pairs, ip):
        a = ipaddress.ip_address(ip)
        a = a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a
        best = max(((n.prefixlen, i, c) for i, (n, c) in enumerate(pairs)
                    if n.version == a.version and a in n), default=None)
        return best[2] if best else ""

    for _ in range(150):
        pairs = [(rand_net(), rnd.choice("ABCDE") * 2) for _ in range(rnd.randint(1, 15))]
        g = _geo([(str(n), c) for n, c in pairs])
        for n, _ in pairs:
            lo, hi, mx = int(n.network_address), int(n.broadcast_address), (1 << n.max_prefixlen) - 1
            for x in {lo, hi, max(0, lo - 1), min(mx, hi + 1), (lo + hi) // 2}:
                ip = str(ipaddress.ip_address(x) if n.version == 4 else ipaddress.IPv6Address(x))
                assert g.country(ip) == ref(pairs, ip), (ip, [(str(n), c) for n, c in pairs])


def test_n5_load_from_file_flattens_and_reports_the_rows_read():
    if GEO is None:
        raise SkipTest("GeoIP(国判定)は Full 版のみ")
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "geoip.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("# network,cc\n10.0.0.0/8,aa\n10.1.0.0/16\tBB\n2001:db8::/32,CC\nbad,XX\n::/8,ZZ\n")
        g = GEO.GeoIP()
        r = g.load(p)
        assert r["ok"] and r["count"] == 4, r
        assert (g.country("10.9.9.9"), g.country("10.1.0.1"), g.country("2001:db8::1"),
                g.country("8.8.8.8")) == ("AA", "BB", "CC", "")
