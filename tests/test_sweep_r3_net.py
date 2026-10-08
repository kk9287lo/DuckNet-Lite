"""
test_sweep_r3_net.py — 掃討 3 巡目(r3_net)の回帰: ip_in_any の IPv4-mapped
====================================================================================
  · T2 netutil.ip_in_any() は ipaddress のバージョン一致判定に任せていたため、dual-stack で届く
    '::ffff:192.0.2.1' が IPv4 の CIDR(信頼 proxy 等)に一致せず、呼び出し側ごとに正規化を
    強いていた。
修正前のコードで落ちることを確かめてある。
"""
import unittest

from dataplane.engine.lifeform.netutil import ip_in_any


# ── T2: ip_in_any と IPv4-mapped ─────────────────────────────────────────

def test_r3_ip_in_any_matches_v4_mapped_against_ipv4_cidr():
    """'::ffff:192.0.2.1' は IPv4 の CIDR / 単一 IP に一致する(呼び出し側の正規化に頼らない)。
    素の IPv4 / IPv6 の結果は変えない。"""
    assert ip_in_any("::ffff:192.0.2.1", ["192.0.2.0/24"])
    assert ip_in_any("::FFFF:192.0.2.1", ["198.51.100.0/24", "192.0.2.1"])
    assert ip_in_any("::ffff:c000:201", ["192.0.2.0/24"])          # 16 進表記の mapped も同じ
    assert not ip_in_any("::ffff:198.51.100.1", ["192.0.2.0/24"])
    # mapped は IPv6 の CIDR にも従来どおり一致する
    assert ip_in_any("::ffff:192.0.2.1", ["::ffff:0:0/96"])
    # 素の入力は不変: 別ファミリの CIDR には一致しない
    assert ip_in_any("192.0.2.1", ["192.0.2.0/24"])
    assert ip_in_any("2001:db8::1", ["2001:db8::/32"])
    assert not ip_in_any("192.0.2.1", ["::/0"])
    assert not ip_in_any("192.0.2.1", ["::ffff:0:0/96"])
    assert not ip_in_any("2001:db8::c000:201", ["192.0.2.0/24"])  # 下位 32bit だけの偶然一致はしない
    assert not ip_in_any("::c000:201", ["192.0.2.0/24"])          # IPv4-compatible(非 mapped)も対象外
    assert not ip_in_any("", ["192.0.2.0/24"]) and not ip_in_any("a'b<c", ["192.0.2.0/24"])
    assert not ip_in_any("::ffff:192.0.2.1", ["a'b<c", ""])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except unittest.SkipTest as e:
            ok += 1
            print("SKIP", fn.__name__, "->", e)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")
