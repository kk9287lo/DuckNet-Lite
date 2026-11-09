"""GraphQL persisted operations must not bypass an enabled query guard."""
import hashlib
import json
import tempfile
from urllib.parse import urlencode

from dataplane.engine.lifeform.pipeline import NetShield
from test_falco_graphql_views import _inspect, _transit
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_SAFE = "{ me { id } }"
_LIMITED = "{ __schema { types { name } } }"


def _persisted(cached_query=_LIMITED, **extra):
    # The local digest models a backend cache lookup; no external service is used.
    envelope = {"operationName": "LocalLookup", "extensions": {
        "persistedQuery": {"version": 1,
                           "sha256Hash": hashlib.sha256(cached_query.encode()).hexdigest()}}}
    envelope.update(extra)
    return json.dumps(envelope, separators=(",", ":")).encode()


def test_uninspectable_persisted_operation_is_rejected_before_backend():
    body = _persisted()
    received, response, metrics, events = _transit(body)
    assert received == b"" and (not response or response.startswith(b"HTTP/1.1 403"))
    assert metrics["proxied"] == 0 and metrics["dropped"] == 1
    assert any(e["kind"] == "graphql_unscannable" for e in events)


def test_audit_persisted_operation_records_and_preserves_exact_bytes():
    body = _persisted()
    received, response, metrics, events = _transit(body, mode="audit")
    assert received.split(b"\r\n\r\n", 1)[1] == body
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert any(e["kind"] == "audit" and e.get("rule") == "graphql_unscannable"
               and e.get("would") == "block" for e in events)


def test_visible_safe_query_and_registration_remain_allowed():
    for body in (json.dumps({"query": _SAFE}).encode(),
                 _persisted(_SAFE, query=_SAFE)):
        received, response, metrics, events = _transit(body)
        assert received.split(b"\r\n\r\n", 1)[1] == body
        assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
        assert not any(e["kind"] == "graphql_unscannable" for e in events)


def test_persisted_member_in_batch_cannot_hide_behind_visible_query():
    body = json.dumps([{"query": _SAFE}, json.loads(_persisted())]).encode()
    result, _ = _inspect(body, graphql_max_batch=2)
    assert result["action"] == "block"


def test_empty_case_alias_cannot_select_cached_operation():
    body = json.dumps({"query": _SAFE, "Query": "",
                       "Extensions": {"PersistedQuery": {
                           "version": 1,
                           "sha256Hash": hashlib.sha256(_LIMITED.encode()).hexdigest()}}}).encode()
    result, _ = _inspect(body)
    assert result["action"] == "block"


def _get_transit(*, visible_query=None, cached_query=_LIMITED,
                 query_name="query", mode="enforce"):
    fields = {"extensions": json.dumps(json.loads(_persisted(cached_query))["extensions"])}
    if visible_query is not None:
        fields[query_name] = visible_query
    target = b"/graphql?" + urlencode(fields).encode()
    request = b"GET " + target + b" HTTP/1.1\r\nHost: local.test\r\n\r\n"
    backend = _Backend()
    try:
        with _shield(graphql_enabled=True, body_scan_enabled=False, mode=mode) as shield, \
                _guard(backend) as guard:
            response = _exchange(guard, [request])
            metrics, events = dict(guard.metrics), shield.events()
        return request, backend.saw(), response, metrics, events
    finally:
        backend.close()


def test_get_persisted_operation_does_not_reach_backend():
    _, received, response, metrics, events = _get_transit()
    assert received == b"" and (not response or response.startswith(b"HTTP/1.1 403"))
    assert metrics["proxied"] == 0 and metrics["dropped"] == 1
    assert any(e["kind"] == "graphql_unscannable" for e in events)


def test_get_visible_safe_query_reaches_backend_exactly():
    request, received, response, metrics, events = _get_transit(
        visible_query=_SAFE, cached_query=_SAFE, query_name="Query")
    assert received.split(b"\r\n", 1)[0] == request.split(b"\r\n", 1)[0]
    assert response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1 and not any(
        e["kind"] == "graphql_unscannable" for e in events)


def test_persisted_operation_rejection_does_not_ban_client():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        shield.cfg.update(enabled=True, graphql_enabled=True)
        result = shield.inspect_graphql("192.0.2.82", "/graphql", _persisted(),
                                        "application/json")
        assert result["action"] == "block"
        assert not shield.is_banned_fast("192.0.2.82")


def test_visible_query_with_different_cached_hash_is_uninspectable():
    body = _persisted(_LIMITED, query=_SAFE)
    received, _, metrics, _ = _transit(body)
    assert received == b"" and metrics["dropped"] == 1
    _, received, _, metrics, _ = _get_transit(
        visible_query=_SAFE, cached_query=_LIMITED, query_name="Query")
    assert received == b"" and metrics["dropped"] == 1


def test_get_case_alias_query_is_scanned_with_matching_hash():
    request, received, _, metrics, _ = _get_transit(
        visible_query=_LIMITED, cached_query=_LIMITED, query_name="Query")
    assert b"Query=" in request and received == b"" and metrics["dropped"] == 1


def test_form_query_case_alias_is_a_visible_reading():
    from dataplane.engine.lifeform.graphql import form_queries, check
    queries = form_queries(urlencode({"Query": _LIMITED}))
    assert not check(queries, block_introspection=True)["allowed"]


def test_duplicate_extension_object_is_not_treated_as_inspected_query():
    from dataplane.engine.lifeform.graphql import form_persisted_uninspectable
    ext = '{"persistedQuery":{"sha256Hash":"' + hashlib.sha256(_LIMITED.encode()).hexdigest() \
          + '"},"persistedQuery":null}'
    assert form_persisted_uninspectable(urlencode({"query": _SAFE, "extensions": ext}))


def test_unicode_query_with_matching_digest_is_not_rejected():
    query = '{ me(note: "こんにちは") { id } }'
    body = json.dumps(json.loads(_persisted(query, query=query)),
                      ensure_ascii=False).encode()
    result, _ = _inspect(body)
    assert result["action"] == "allow"


def test_form_body_without_visible_document_is_uninspectable():
    body = urlencode({"extensions": json.dumps(
        json.loads(_persisted())["extensions"])}).encode()
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        shield.cfg.update(enabled=True, graphql_enabled=True)
        result = shield.inspect_graphql("192.0.2.83", "/graphql", body,
                                        "application/x-www-form-urlencoded")
        assert result["action"] == "block"
