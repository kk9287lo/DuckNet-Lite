"""
test_graphql.py — GraphQL クエリ防御(深さ/複雑度/イントロスペクション/バッチ・evolution #67)。
====================================================================================
1エンドポイントに任意問い合わせを送る GraphQL 固有の DoS/情報漏洩を、構造の粗い指標で上限化する。
純粋ガード + NetShield 統合(graphql_paths にだけ適用・違反は遮断)を守る。
"""
import json
import tempfile

from dataplane.engine.lifeform.graphql import (
    extract_queries, max_depth, selection_count, has_introspection, check,
)
from dataplane.engine.lifeform.pipeline import NetShield


def test_extract_queries_forms():
    assert extract_queries(b'{"query":"{ me { id } }"}') == ["{ me { id } }"]
    batch = json.dumps([{"query": "{a}"}, {"query": "{b}"}]).encode()
    assert extract_queries(batch) == ["{a}", "{b}"]
    assert extract_queries(b"query { x }")[0].startswith("query")   # 生クエリ
    assert extract_queries(b'{"data":1}') == []                     # query 無し=非GraphQL
    assert extract_queries(b"username=alice") == []                 # 通常フォーム


def test_max_depth_ignores_strings():
    assert max_depth("{ a { b { c } } }") == 3
    assert max_depth('{ a(arg: "x { y } z") { b } }') == 2          # 文字列内の{}は無視


def test_selection_and_introspection():
    assert selection_count("{ a { b } c { d } }") == 3
    assert has_introspection("{ __schema { types { name } } }")
    assert has_introspection("{ __type(name: x){ f } }")
    assert not has_introspection("{ user { name } }")


def test_check_limits():
    assert check(["{ a { b } }"], max_depth_limit=12)["allowed"]
    assert not check(["{a{b{c{d}}}}"], max_depth_limit=2)["allowed"]            # 深さ
    deep = "{" * 50 + "x" + "}" * 50
    assert check([deep], max_depth_limit=12)["reason"].startswith("depth")
    assert not check(["{a}"] * 20, max_batch=10)["allowed"]                     # バッチ過大
    assert not check(["{ __schema { x } }"], block_introspection=True)["allowed"]
    assert check(["{ __schema { x } }"], block_introspection=False)["allowed"]  # 許可設定
    assert check([], max_depth_limit=12)["reason"] == "not-graphql"


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["graphql_enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_inspect_graphql_blocks_deep_query():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, graphql_max_depth=5)
        body = b'{"query":"' + b"{a" * 10 + b" x " + b"}" * 10 + b'"}'
        r = sh.inspect_graphql("9.9.9.9", "/graphql", body)
        assert r["action"] == "block" and r["reason"].startswith("depth")
        assert sh.is_banned_fast("9.9.9.9")


def test_inspect_graphql_blocks_introspection():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect_graphql("8.8.8.8", "/graphql",
                               b'{"query":"{ __schema { types { name } } }"}')
        assert r["action"] == "block" and r["reason"] == "introspection"


def test_inspect_graphql_allows_normal():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect_graphql("1.1.1.1", "/graphql",
                               b'{"query":"{ me { id name } }"}')
        assert r["action"] == "allow"


def test_only_applies_to_graphql_paths():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, graphql_max_depth=2)
        deep = b'{"query":"' + b"{a" * 10 + b" x " + b"}" * 10 + b'"}'
        # 非 GraphQL パスは対象外(REST API に GraphQL 風 JSON が来ても誤遮断しない)
        assert sh.inspect_graphql("2.2.2.2", "/api/data", deep)["action"] == "allow"
        assert sh.inspect_graphql("3.3.3.3", "/graphql", deep)["action"] == "block"


def test_disabled_passes():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, graphql_enabled=False)
        r = sh.inspect_graphql("4.4.4.4", "/graphql",
                               b'{"query":"{ __schema { x } }"}')
        assert r["action"] == "allow"
