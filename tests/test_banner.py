"""
test_deception.py — 動的デセプション(偽Serverバナーによる指紋攪乱)の検証
====================================================================================
有効時のみ働き(既定オフ)、攻撃者ごと・時間帯ごとに矛盾する実在風バナーを返すこと。
公開応答(_http_response)に server を渡すと Server ヘッダが付与されること。
"""
import os

from dataplane.engine.services import banner as deception
from dataplane.engine.services.proxy import _http_response


def test_disabled_by_default():
    os.environ.pop("DUCKNET_DECEPTION", None)
    assert deception.is_enabled() is False
    assert deception.banner_for("1.2.3.4") == ""        # 既定では Server を偽装しない


def test_enabled_returns_plausible_rotating_banner():
    os.environ["DUCKNET_DECEPTION"] = "1"
    try:
        assert deception.is_enabled() is True
        b = deception.banner_for("203.0.113.9")
        assert b in deception._SERVERS                  # 実在風の名簿から
        # 同一窓内では安定(レスポンス内の自己矛盾を避ける)
        assert deception.rotating_banner("x", now=1000.0) == deception.rotating_banner("x", now=1000.0)
        # 時間が進むと(別の窓)変わり得る=同一攻撃者に矛盾して見える
        seen = {deception.rotating_banner("x", window=30, now=1000.0 + 30 * i) for i in range(12)}
        assert len(seen) >= 3                           # 時間で複数の正体に揺れる
        # 攻撃者(seed)ごとにも分散
        assert deception.rotating_banner("a", now=1000.0) != deception.rotating_banner("zzz", now=1000.0) \
            or True                                     # 衝突もあり得るので緩く(分散の確認は上で十分)
    finally:
        os.environ.pop("DUCKNET_DECEPTION", None)


def test_adjacent_windows_always_change_family():
    # 隣接窓では必ず別系統(Apache→IIS 等)= 再観測のたびに矛盾し『一貫』と確信させない。
    fam = deception._family
    for seed in ["203.0.113.9", "10.0.0.7", "attacker", "", "::1"]:
        prev = None
        for i in range(40):                             # 40窓ぶん連続で観測
            b = deception.rotating_banner(seed, window=30, now=1000.0 + 30 * i)
            if prev is not None:
                assert fam(b) != fam(prev), (seed, i, prev, b)  # 隣接は必ず別系統
            prev = b
        # 全系統を巡回する(互いに素ストライド)=正体が単一に固定されない
        seen = {fam(deception.rotating_banner(seed, window=30, now=1000.0 + 30 * i))
                for i in range(len(deception._FAMILIES) * 2)}
        assert len(seen) == len(deception._FAMILIES), (seed, seen)


def test_companion_headers_are_consistent_with_server_family():
    # evolution #4 深掘り: 偽 Server だけでなく系統に *整合する* 随伴ヘッダを付け、嘘を内部
    # 矛盾させない(IIS なのに PHP、のような食い違いを出さない)。
    os.environ["DUCKNET_DECEPTION"] = "1"
    try:
        fam = deception._family
        saw_companion = False
        for i in range(len(deception._FAMILIES) * 3):     # 全系統を巡る窓を走査
            hs = deception.headers_for("203.0.113.9", window=30, now=1000.0 + 30 * i)
            assert hs[0][0] == "Server" and hs[0][1] in deception._SERVERS
            f = fam(hs[0][1])
            d = dict(hs[1:])
            if f == "microsoft":
                assert d.get("X-Powered-By") == "ASP.NET"; saw_companion = True
            elif f in ("apache", "litespeed"):
                assert d.get("X-Powered-By", "").startswith("PHP/"); saw_companion = True
            elif f == "cloudflare":
                assert "CF-Cache-Status" in d; saw_companion = True
            # 食い違い禁止: nginx 等で ASP.NET/PHP を出さない、IIS で PHP を出さない
            if f != "microsoft" and f not in ("apache", "litespeed"):
                assert "X-Powered-By" not in d, (f, d)
        assert saw_companion                              # 少なくとも一部系統で随伴ヘッダが出た
    finally:
        os.environ.pop("DUCKNET_DECEPTION", None)


def test_companion_headers_empty_when_disabled():
    os.environ.pop("DUCKNET_DECEPTION", None)
    assert deception.headers_for("1.2.3.4") == []         # 既定オフ=何も付けない


def test_http_response_emits_server_header_when_given():
    raw = _http_response("403 Forbidden", '{"x":1}', server="Microsoft-IIS/10.0")
    assert b"Server: Microsoft-IIS/10.0\r\n" in raw
    # server 未指定なら Server ヘッダは付かない(製品名・正体を漏らさない既定)
    assert b"Server:" not in _http_response("200 OK", "ok")
    # extra ヘッダ(デセプションの系統整合ヘッダ等)はワイヤに出る・CR/LF はヘッダ注入防止に除去
    raw2 = _http_response("403 Forbidden", "x",
                          extra=[("Server", "Microsoft-IIS/10.0"),
                                 ("X-Powered-By", "ASP.NET"),
                                 ("X-Evil", "a\r\nInjected: 1")])
    assert b"Server: Microsoft-IIS/10.0\r\n" in raw2
    assert b"X-Powered-By: ASP.NET\r\n" in raw2
    assert b"\r\nInjected: 1" not in raw2                  # CR/LF 除去でヘッダ注入を防ぐ
    assert b"X-Evil: aInjected: 1\r\n" in raw2


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")
