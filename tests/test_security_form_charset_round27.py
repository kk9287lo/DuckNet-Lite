"""Declared form charsets apply after percent decoding, as at the receiver."""

import hashlib
import json
from urllib.parse import parse_qs, urlencode

from dataplane.engine.core import saferegex
from dataplane.engine.lifeform import graphql
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_ENCODINGS = ("cp037", "cp500", "utf-16-le", "utf-32-le", "utf-16", "utf-32", "utf-8-sig")
_LIMITED = "{ health version }"
_SAFE = '{ hello(message: "café & query=ordinary") }'
_MARKER = "ducknetformmarker2727"


def _form(fields, encoding):
    return urlencode(fields, encoding=encoding).encode()


def _type(encoding):
    return "application/x-www-form-urlencoded; charset=" + encoding


def _through(body, encoding, *, mode="enforce", body_scan=False, marker=False, target=b"/graphql"):
    request = (b"POST " + target + b" HTTP/1.1\r\nHost: local.test\r\nContent-Type: "
               + _type(encoding).encode() + b"\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
    backend = _Backend()
    try:
        with _shield(mode=mode, graphql_enabled=not body_scan, graphql_max_complexity=1,
                     body_scan_enabled=body_scan, upload_scan_enabled=False) as shield, _guard(backend) as guard:
            if marker:
                added = shield.add_signature("round27-form-marker", _MARKER, weight=1000)
                assert added["ok"], added
            response = _exchange(guard, [request])
            return dict(received=backend.saw(), response=response, events=shield.events(),
                        metrics=dict(guard.metrics))
    finally:
        backend.close()


def test_percent_encoded_form_names_and_values_are_inspected_in_the_declared_charset():
    for encoding in _ENCODINGS:
        body = _form({"query": _LIMITED}, encoding)
        assert parse_qs(body.decode(), encoding=encoding) == {"query": [_LIMITED]}
        with _shield(graphql_enabled=True, graphql_max_complexity=1,
                     body_scan_enabled=False, upload_scan_enabled=False) as shield:
            result = shield.inspect_graphql("127.0.0.1", "/graphql", body, _type(encoding))
            assert result["action"] in ("block", "reject"), (encoding, result)
        literal_key = b"query=" + body.split(b"=", 1)[1]
        assert parse_qs(literal_key.decode(), encoding=encoding) == {"query": [_LIMITED]}
        with _shield(graphql_enabled=True, graphql_max_complexity=1,
                     body_scan_enabled=False, upload_scan_enabled=False) as shield:
            assert shield.inspect_graphql("127.0.0.1", "/graphql", literal_key,
                                          _type(encoding))["action"] in ("block", "reject")


def test_declared_form_decoding_cannot_bypass_the_guard_on_real_wire():
    for encoding in _ENCODINGS:
        result = _through(_form({"query": _LIMITED}, encoding), encoding)
        assert result["received"] == b"", (encoding, result)
        assert result["metrics"]["proxied"] == 0 and result["metrics"]["dropped"] == 1


def test_audit_records_form_limits_and_keeps_original_percent_bytes():
    for encoding in _ENCODINGS:
        body = _form({"query": _LIMITED}, encoding)
        result = _through(body, encoding, mode="audit")
        assert result["received"].partition(b"\r\n\r\n")[2] == body
        assert result["response"].startswith(b"HTTP/1.1 200")
        assert any(event["kind"] == "audit" and event.get("would") == "block"
                   for event in result["events"]), (encoding, result["events"])


def test_body_signatures_see_the_same_decoded_dummy_form_value_as_the_receiver():
    for encoding in _ENCODINGS:
        body = _form({"ordinary": _MARKER}, encoding)
        blocked = _through(body, encoding, body_scan=True, marker=True)
        assert blocked["received"] == b"", (encoding, blocked)
        assert blocked["metrics"]["dropped"] == 1
        audited = _through(body, encoding, mode="audit", body_scan=True, marker=True)
        assert audited["received"].partition(b"\r\n\r\n")[2] == body
        assert any(event["kind"] == "audit" and event.get("would") == "block"
                   for event in audited["events"])


def test_declared_form_readings_preserve_field_boundaries_and_repeated_query_budget():
    for encoding in _ENCODINGS:
        # The encoded '&query=' is data inside a string, never a second field.
        body = _form({"query": _SAFE}, encoding)
        readings = graphql.parse_readings(body, _type(encoding))
        assert any(list(queries) == [_SAFE] and not error for queries, error in readings)
        assert all(graphql.check(queries, max_batch=1)["allowed"]
                   for queries, error in readings if not error)
        repeated = _form([("query", "{ health }"), ("query", "{ version }")], encoding)
        repeated_readings = graphql.parse_readings(repeated, _type(encoding))
        assert any(not graphql.check(queries, max_batch=1)["allowed"]
                   for queries, error in repeated_readings if not error)


def test_safe_declared_forms_and_visible_persisted_registration_remain_usable():
    safe = "{ health }"
    extension = {"persistedQuery": {"version": 1,
                                  "sha256Hash": hashlib.sha256(safe.encode()).hexdigest()}}
    for encoding in _ENCODINGS:
        for fields in ({"query": safe}, {"query": safe, "extensions": json.dumps(extension)}):
            body = _form(fields, encoding)
            result = _through(body, encoding)
            assert result["received"].partition(b"\r\n\r\n")[2] == body, (encoding, result)
            assert result["response"].startswith(b"HTTP/1.1 200")
        hidden = _through(_form({"extensions": json.dumps(extension)}, encoding), encoding)
        assert hidden["received"] == b"", (encoding, hidden)


def test_excess_form_fields_are_uninspectable_in_query_body_and_signature_paths():
    # The same byte size fits comfortably in the body cap; item count is a
    # separate budget. Ordinary fields alone must not become a clean result.
    fields = [("ordinary", "value")] * 1024 + [("query", "{ health }")]
    for encoding in ("utf-8", "cp037"):
        body = _form(fields, encoding)
        for body_scan in (False, True):
            blocked = _through(body, encoding, body_scan=body_scan)
            assert blocked["received"] == b"", (encoding, body_scan, blocked)
            assert blocked["metrics"]["dropped"] == 1
            audited = _through(body, encoding, mode="audit", body_scan=body_scan)
            assert audited["received"].partition(b"\r\n\r\n")[2] == body
            assert any(event["kind"] == "audit" and event.get("would") in ("reject", "block")
                       for event in audited["events"])
    query = _form(fields, "utf-8")
    result = _through(b"", "utf-8", target=b"/graphql?" + query)
    assert result["received"] == b"" and result["metrics"]["dropped"] == 1


def test_form_field_limit_includes_a_usable_complete_boundary_case():
    fields = [("ordinary", "value")] * 1023 + [("query", "{ health }")]
    for encoding in ("utf-8", "cp037"):
        body = _form(fields, encoding)
        result = _through(body, encoding)
        assert result["received"].partition(b"\r\n\r\n")[2] == body
        assert result["response"].startswith(b"HTTP/1.1 200")


def test_exhausted_aggregate_form_reading_budgets_are_never_a_partial_success():
    body = _form({"query": "{ health }"}, "cp037")
    # Small fixed budgets exercise exhaustion using ordinary data, without
    # allocating a multi-megabyte fixture or changing production thresholds.
    for name in ("_MAX_FORM_READINGS", "_MAX_FORM_READING_BYTES"):
        previous = getattr(saferegex, name, None)
        setattr(saferegex, name, 0)
        try:
            for body_scan in (False, True):
                blocked = _through(body, "cp037", body_scan=body_scan)
                assert blocked["received"] == b"", (name, body_scan, blocked)
                audited = _through(body, "cp037", mode="audit", body_scan=body_scan)
                assert audited["received"].partition(b"\r\n\r\n")[2] == body
                assert any(event["kind"] == "audit" and event.get("would") in ("reject", "block")
                           for event in audited["events"])
        finally:
            if previous is None:
                delattr(saferegex, name)
            else:
                setattr(saferegex, name, previous)
