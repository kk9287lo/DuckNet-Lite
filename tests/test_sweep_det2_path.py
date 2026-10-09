"""
test_sweep_det2_path.py — 経路照合用パス(_path_for_match)の正規化の回帰(sweep: det2_path 群・Lite)。
====================================================================================
_path_for_match は %デコード+小文字化だけで、ドットセグメント(. / ..)・連続スラッシュ・
';' パスパラメータを解決しなかった。バックエンドは /public/../private を /private として
配信するのに、//admin や /public/../private が '/admin'・'/private' の経路レート規則を外れ、
//graphql・/graphql;x=1 が GraphQL ガードを外れた。照合用のパスだけを *バックエンドが配信
する形*(RFC 3986 remove_dot_segments + '/' の連続を 1 個に + 各セグメントの ';' 以降を除去)に
揃える。転送する要求そのものは変えない。遮断側の経路制御(遮断リスト/経路レート/GraphQL)が
『厳しくなるか同じ』で、普通のパスの判定が変わらないことも見る。
入力は無害な目印・普通のパス・RFC 3986 の例・既存テストにある値だけを使う。
"""
import tempfile
import time

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield, _path_for_match


def _sh(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


# 普通のパス(正規化しても変わらないこと)。非 ASCII・末尾スラッシュ・ドットを含む名前も。
_ORDINARY = {
    "": "",
    "/": "/",
    "/index.html": "/index.html",
    "/api/v1/users/": "/api/v1/users/",
    "/static/app.min.js": "/static/app.min.js",
    "/.well-known/security.txt": "/.well-known/security.txt",
    "/docs/café/": "/docs/café/",
    "/docs/caf%C3%A9": "/docs/café",
    "/Account/Settings": "/account/settings",
    "/%6cogin": "/login",                             # tests/test_hardening.py
    "/search?q=a/../b": "/search",                    # query は従来どおり落とす
    "/v1.2/items..json": "/v1.2/items..json",         # '..' を含むだけの名前はセグメントではない
    "/a.../b": "/a.../b",
}


def test_ordinary_paths_unchanged():
    """普通のパス(非 ASCII・末尾スラッシュ・ドット入りの名前)は従来の正規化と同じ結果。"""
    for raw, want in _ORDINARY.items():
        assert _path_for_match(raw) == want, (raw, _path_for_match(raw))


def test_dot_segments_slashes_and_params_resolved():
    """ドットセグメント・連続スラッシュ・';' パラメータを解決し、バックエンドが配信する形にする。"""
    cases = {
        "/public/../private": "/private",
        "/public/%2e%2e/private": "/private",          # %エンコードしたドットも(デコード後に解決)
        "/public/../private/": "/private/",            # 末尾スラッシュは残す
        "//admin": "/admin",
        "/admin;x=1": "/admin",
        "/admin;x=1/": "/admin/",
        # RFC 3986 5.2.4 の例(remove_dot_segments)
        "/a/b/c/./../../g": "/a/g",
        "mid/content=5/../6": "mid/6",
        # RFC 3986 5.4.1 の結果で末尾がドットセグメントのもの=末尾スラッシュになる
        "/b/c/.": "/b/c/",
        "/b/c/..": "/b/",
        "/..": "/",
    }
    for raw, want in cases.items():
        assert _path_for_match(raw) == want, (raw, _path_for_match(raw))
    # 前段(_path_decoded)は従来どおり復号+小文字化だけ=両方の形で照合したい呼び出し元向け
    assert P._path_decoded("/Public/%2e%2e/Private") == "/public/../private"
    assert P._path_decoded("//admin;x=1?y=2") == "//admin;x=1"


def test_path_limits_match_routed_path():
    """経路レート規則 '/admin' / '/private' を //admin・/public/../private で外せた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d)
        assert sh.set_path_limits([{"path": "/admin", "rate": 1, "burst": 1},
                                   {"path": "/private", "rate": 1, "burst": 1}])["ok"]
        for p, want in (("//admin", "/admin"), ("/admin;x=1", "/admin"),
                        ("/public/../private", "/private"), ("/public/%2e%2e/private", "/private")):
            r = sh._path_rule_for(p)
            assert r is not None and r.get("path") == want, (p, r)
        assert sh._path_rule_for("/public/page.html") is None


def test_blocked_urls_and_extensions_stay_at_least_as_strict():
    """遮断リスト(部分一致/拡張子)は従来どおり当たり、ルーティング先の形でも当たる。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, blocked_urls=["/admin", "/private"], blocked_extensions=[".bak"])
        for p in ("/admin", "//admin", "/admin;x=1", "/public/../private",
                  "/public/%2e%2e/private", "/users/admin.bak"):
            assert sh._policy_block("192.0.2.30", p, True), p
        for p in ("/", "/public/page.html", "/docs/café/", "/api/v1/users/"):
            assert sh._policy_block("192.0.2.30", p, True) == "", p


def test_graphql_guard_matches_routed_path():
    """graphql_paths の前方一致も //graphql・/graphql;x=1 を同じエンドポイントとして扱う。"""
    # 関数内で import する(モジュール冒頭だと、この関数が無い版で他のテストまで読込失敗になり、
    # 修正前に挙動として落ちることを確かめられない)
    from dataplane.engine.lifeform.pipeline import _graphql_path
    for p in ("/graphql", "//graphql", "/graphql;x=1", "/graphql/", "/GraphQL"):
        assert _graphql_path(p, ["/graphql"]), p
    for p in ("/api/data", "/graphql-docs", "/public/page.html"):
        assert not _graphql_path(p, ["/graphql"]), p


def test_fast_path_is_cheap_and_long_inputs_are_linear():
    """普通のパスは早道で、病的な長さ(既存テストの '../'*3000 等)でも線形時間で終わる。"""
    for p in ("../" * 3000, "/" * 9000, ";" * 9000, "a/" * 4000):   # tests/test_hardening.py
        t = time.perf_counter()
        _path_for_match(p)
        assert time.perf_counter() - t < 0.5, p[:12]
    assert ".." not in _path_for_match("../" * 3000).split("/")
    assert _path_for_match("/" * 9000) == "/"
