"""GraphQL envelope readings must cover the receiving backend's query aliases."""
import itertools
import json
import tempfile

from dataplane.engine.lifeform.graphql import check, parse_body
from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_SAFE = "{ me { id } }"
_LIMITED = "{ __schema { types { name } } }"


def _inspect(body, **cfg):
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        shield.cfg.update(enabled=True, graphql_enabled=True)
        shield.cfg.update(cfg)
        return shield.inspect_graphql("192.0.2.81", "/graphql", body,
                                      "application/json"), shield.events()


def _go_struct_reading(body):
    """Model the case-insensitive, last-matching Go JSON struct field reading."""
    envelope = json.loads(body)
    return next(value for key, value in reversed(list(envelope.items()))
                if key.lower() == "query")


def _transit(body, *, mode="enforce"):
    head = (b"POST /graphql HTTP/1.1\r\nHost: local.test\r\n"
            b"Content-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n")
    backend = _Backend()
    try:
        with _shield(graphql_enabled=True, body_scan_enabled=False,
                     mode=mode, graphql_max_batch=1) as shield, _guard(backend) as guard:
            response = _exchange(guard, [head + body])
            metrics, events = dict(guard.metrics), shield.events()
        return backend.saw(), response, metrics, events
    finally:
        backend.close()


def test_case_aliased_query_reading_cannot_hide_introspection():
    for alias in ("Query", "qUeRy", "QUERY"):
        body = json.dumps({"query": _SAFE, alias: _LIMITED}).encode()
        assert _go_struct_reading(body) == _LIMITED
        result, _ = _inspect(body)
        assert result["action"] == "block" and result["reason"] == "introspection", result


def test_escaped_case_alias_and_utf16_utf32_are_inspected():
    document = '{"query":"' + _SAFE + '","\\u0051uery":"' + _LIMITED + '"}'
    for encoding in ("utf-8", "utf-16", "utf-16-be", "utf-32", "utf-32-be"):
        result, _ = _inspect(document.encode(encoding))
        assert result["action"] == "block" and result["reason"] == "introspection", (encoding, result)


def test_alias_only_array_members_still_count_as_batch_operations():
    body = json.dumps([{"Query": _SAFE}, {"QUERY": _SAFE}]).encode()
    result, _ = _inspect(body, graphql_max_batch=1)
    assert result["action"] == "block" and result["reason"] == "batch-too-large:2", result


def test_alias_only_batch_member_cannot_hide_a_deep_query():
    deep = "{ a { b { c { id } } } }"
    body = json.dumps([{"Query": deep}, {"QUERY": _SAFE}]).encode()
    result, _ = _inspect(body, graphql_max_depth=2)
    assert result["action"] == "block" and result["reason"].startswith("depth:"), result


def test_one_envelope_aliases_are_not_multiple_batch_operations():
    body = json.dumps({"query": _SAFE, "Query": "{ health }", "QUERY": "{ version }"}).encode()
    queries, error = parse_body(body, "application/json")
    assert not error and check(queries, max_batch=1)["allowed"]
    result, _ = _inspect(body, graphql_max_batch=1)
    assert result["action"] == "allow", result


def test_aliases_do_not_hide_true_array_operation_count():
    body = json.dumps([{"query": _SAFE, "Query": "{ health }"}, {"query": _SAFE}]).encode()
    queries, error = parse_body(body, "application/json")
    assert not error and check(queries, max_batch=1)["reason"] == "batch-too-large:2"
    assert check(queries, max_batch=2)["allowed"]


def test_nested_variable_query_members_remain_application_data():
    body = json.dumps({"query": _SAFE, "variables": {"Query": _LIMITED,
                       "query": _LIMITED, "nested": {"QUERY": _LIMITED}}}).encode()
    result, events = _inspect(body, graphql_max_batch=1)
    assert result["action"] == "allow" and not any(e.get("rule") == "graphql_block" for e in events)


def test_exact_duplicate_json_members_remain_rejected():
    for body in (b'{"query":"{ safe }","query":"{ health }"}',
                 b'{"Query":"{ safe }","\\u0051uery":"{ health }"}'):
        assert parse_body(body, "application/json")[1] == "malformed"
        result, _ = _inspect(body)
        assert result["action"] == "block", result


def _all_case_aliases():
    return ["".join(char.upper() if bit else char for char, bit in zip("query", bits))
            for bits in itertools.product((False, True), repeat=5)]


def test_many_alias_readings_have_an_independent_fail_closed_budget():
    item = {alias: _SAFE for alias in _all_case_aliases()}
    at_cap = json.dumps([item] * 16).encode()
    result, _ = _inspect(at_cap, graphql_max_batch=100)
    assert result["action"] == "allow", result
    over_cap = json.dumps([item] * 17).encode()
    result, _ = _inspect(over_cap, graphql_max_batch=100)
    assert result["action"] == "block" and result["reason"] == "query-readings-too-large", result


def test_modified_public_query_list_cannot_reuse_stale_batch_metadata():
    queries, error = parse_body(json.dumps({"query": _SAFE, "Query": "{ health }"}).encode())
    assert not error
    queries.append("{ version }")
    assert not check(queries, max_batch=1)["allowed"]


def test_enforce_alias_finding_keeps_all_body_bytes_from_backend():
    body = json.dumps({"query": _SAFE, "Query": _LIMITED}).encode()
    assert _go_struct_reading(body) == _LIMITED
    received, response, metrics, events = _transit(body)
    # Existing GraphQL block handling closes the client or returns a refusal;
    # either way no GraphQL operation may be delivered to the origin.
    assert received == b"" and (not response or response.startswith(b"HTTP/1.1 403")), (received, response)
    assert metrics["proxied"] == 0 and metrics["dropped"] == 1
    assert any(event["kind"] == "graphql_block" for event in events), events


def test_audit_alias_finding_preserves_exact_backend_bytes_and_records_would_block():
    body = json.dumps({"query": _SAFE, "Query": _LIMITED}).encode()
    received, response, metrics, events = _transit(body, mode="audit")
    assert received.split(b"\r\n\r\n", 1)[1] == body
    assert _go_struct_reading(received.split(b"\r\n\r\n", 1)[1]) == _LIMITED
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert any(event["kind"] == "audit" and event.get("rule") == "graphql_block"
               and event.get("would") == "block" for event in events), events


def test_benign_alias_envelope_reaches_backend_unchanged_with_batch_limit_one():
    body = json.dumps({"query": _SAFE, "Query": "{ health }"}).encode()
    received, response, metrics, events = _transit(body)
    assert received.split(b"\r\n\r\n", 1)[1] == body and _go_struct_reading(body) == "{ health }"
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert not any(event["kind"] == "graphql_block" for event in events), events
