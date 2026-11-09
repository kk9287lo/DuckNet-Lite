"""Multipart field identity must have one inspectable receiver interpretation."""

import email
from email import policy
import json

from dataplane.engine.lifeform.pipeline import _multipart_field, _UploadScan, _UPLOAD_HDR_MAX
from test_sweep_proxy_request import (_Backend, _exchange, _guard, _shield,
                                      _read_framed_request)


_BOUNDARY = b"round26-local-fields"
_QUERY = {"query": "{ health }"}
_CONTENT = json.dumps(_QUERY, separators=(",", ":")).encode()
_AMBIGUOUS = (
    b'Content-Disposition: form-data; name="operations"; name="notes"',
    b'Content-Disposition: form-data; name="operations"\r\n'
    b'Content-Disposition: form-data; name="notes"',
    b"Content-Disposition: form-data; name*=utf-8''operations; name=notes",
    b'Content-Disposition: form-data; name="=?utf-8?q?operations?="',
)


def _body(disposition, content=_CONTENT):
    return (b"--" + _BOUNDARY + b"\r\n" + disposition
            + b"\r\nContent-Type: application/json\r\n\r\n" + content
            + b"\r\n--" + _BOUNDARY + b"--\r\n")


def _receiver_name(body):
    message = email.message_from_bytes(
        b"MIME-Version: 1.0\r\nContent-Type: multipart/form-data; boundary="
        + _BOUNDARY + b"\r\n\r\n" + body, policy=policy.default)
    return next(message.iter_parts()).get_param("name", header="content-disposition")


class _BodyBackend(_Backend):
    def _one(self, connection):
        try:
            connection.settimeout(3)
            self.got.append(_read_framed_request(connection, limit=2 * 1024 * 1024,
                                                 suffix_wait=0))
            connection.sendall(self.resp)
        except OSError:
            pass
        finally:
            connection.close()


def _wire_body(body, chunked):
    if not chunked:
        return body
    boundary = body.rfind(b"--" + _BOUNDARY)
    disposition = body.rfind(b"Content-Disposition")
    points = sorted({0, len(body), *(point for point in
                    (17, boundary + 3, boundary + 7, disposition + 13,
                     disposition + 17, disposition + 37)
                    if 0 < point < len(body))})
    return b"".join(format(end - start, "x").encode() + b"\r\n" + body[start:end] + b"\r\n"
                    for start, end in zip(points, points[1:])) + b"0\r\n\r\n"


def _transit(body, mode="enforce", *, chunked=False, split=False, path=b"/graphql", **cfg):
    content_type = b"multipart/form-data; boundary=" + _BOUNDARY
    wire = _wire_body(body, chunked)
    framing = (b"Transfer-Encoding: chunked" if chunked else
               b"Content-Length: " + str(len(wire)).encode())
    request = (b"POST " + path + b" HTTP/1.1\r\nHost: local.test\r\nContent-Type: "
               + content_type + b"\r\n" + framing + b"\r\n\r\n" + wire)
    options = dict(graphql_enabled=True, body_scan_enabled=False, mode=mode)
    options.update(cfg)
    backend = _BodyBackend()
    try:
        with _shield(**options) as shield, _guard(backend) as guard:
            if split:
                start = request.rfind(b"Content-Disposition")
                cuts = sorted({0, len(request), 65557, start + 9, start + 18, start + 39})
                cuts = [cut for cut in cuts if 0 <= cut <= len(request)]
                parts = [request[start:end] for start, end in zip(cuts, cuts[1:])]
            else:
                parts = [request]
            response = _exchange(guard, parts, delay=0.002, timeout=8)
            received = backend.saw()
            result = {"received": received, "response": response,
                      "metrics": dict(guard.metrics), "events": shield.events(),
                      "banned": shield.is_banned_fast("127.0.0.1"), "wire": wire}
        return result
    finally:
        backend.close()


def _attachment(*, padding=131072, tail=None, first_operations=True, close=True):
    start = (_body(b'Content-Disposition: form-data; name="operations"')
             .rsplit(b"--" + _BOUNDARY + b"--", 1)[0] if first_operations else b"")
    file_part = (b"--" + _BOUNDARY
                 + b'\r\nContent-Disposition: form-data; name="file"; filename="notes.txt"\r\n\r\n'
                 + b"x" * padding + b"\r\n")
    later = (b"--" + _BOUNDARY + b"\r\n" + tail + b"\r\n\r\n" + _CONTENT + b"\r\n"
             if tail else b"")
    return start + file_part + later + (b"--" + _BOUNDARY + b"--\r\n" if close else b"")


def test_conflicting_disposition_names_do_not_disappear_from_graphql_inspection():
    for disposition in _AMBIGUOUS:
        body = _body(disposition)
        assert _receiver_name(body) == "operations"
        assert _multipart_field(body, [_BOUNDARY], "operations") is False


def test_ambiguous_field_identity_reaches_no_backend_bytes_without_banning():
    for disposition in _AMBIGUOUS:
        result = _transit(_body(disposition))
        assert result["received"] == b""
        assert result["response"].startswith(b"HTTP/1.1 413")
        assert result["metrics"]["proxied"] == 0
        assert result["metrics"]["dropped"] == 1
        assert result["banned"] is False


def test_audit_records_ambiguous_field_identity_and_preserves_exact_body():
    body = _body(_AMBIGUOUS[0])
    result = _transit(body, "audit")
    assert result["received"].partition(b"\r\n\r\n")[2] == body
    assert result["response"].startswith(b"HTTP/1.1 200")
    assert result["metrics"]["proxied"] == 1 and result["banned"] is False
    assert any(event["kind"] == "audit" and event.get("would") == "reject"
               and event.get("rule") == "graphql_multipart_unscannable" for event in result["events"])


def test_ordinary_operations_part_and_filename_remain_exactly_usable():
    for disposition in (b'Content-Disposition: form-data; name="operations"',
                        b'Content-Disposition: form-data; name=operations',
                        b'Content-Disposition: form-data;\r\n name="operations"',
                        b'Content-Disposition: form-data; name="operations"; filename="operations.json"',
                        b'Content-Disposition: form-data; name="operations"; filename="report(1).txt"'):
        body = _body(disposition)
        assert _receiver_name(body) == "operations"
        assert _multipart_field(body, [_BOUNDARY], "operations") == _CONTENT
        for mode in ("enforce", "audit"):
            result = _transit(body, mode)
            assert result["received"].partition(b"\r\n\r\n")[2] == body
            assert result["response"].startswith(b"HTTP/1.1 200")
            assert result["metrics"]["proxied"] == 1 and result["banned"] is False


def test_unrelated_form_fields_are_not_mistaken_for_operations():
    body = _body(b'Content-Disposition: form-data; name="notes"')
    assert _receiver_name(body) == "notes"
    assert _multipart_field(body, [_BOUNDARY], "operations") is None
    result = _transit(body)
    assert result["received"].partition(b"\r\n\r\n")[2] == body
    assert result["response"].startswith(b"HTTP/1.1 200")


def test_duplicate_and_extended_parameter_spellings_fail_closed():
    for disposition in (
        b'Content-Disposition: form-data; name="operations"; name="operations"',
        b'Content-Disposition: form-data; name="operations"; NAME="notes"',
        b'Content-Disposition: form-data; name*0="oper"; name*1="ations"',
        b"Content-Disposition: form-data; name*0*=utf-8''oper; name*1=ations",
        b'Content-Disposition: form-data; name="notes\\\"extra"',
    ):
        assert _multipart_field(_body(disposition), [_BOUNDARY], "operations") is False


def test_late_ambiguous_or_repeated_operations_never_reach_the_backend():
    for tail in (*_AMBIGUOUS, b'Content-Disposition: form-data; name="operations"'):
        for upload_enabled in (True, False):
            result = _transit(_attachment(tail=tail), split=True,
                              graphql_max_bytes=256, upload_scan_enabled=upload_enabled)
            assert result["received"] == b""
            assert result["metrics"]["proxied"] == 0 and result["metrics"]["dropped"] == 1
            assert result["banned"] is False


def test_chunk_and_tcp_boundaries_do_not_hide_late_field_metadata():
    for tail in (_AMBIGUOUS[0], _AMBIGUOUS[-1]):
        result = _transit(_attachment(tail=tail), chunked=True, split=True,
                          graphql_max_bytes=256, upload_scan_enabled=False)
        assert result["received"] == b"" and result["metrics"]["dropped"] == 1


def test_operations_after_an_uninspected_attachment_are_rejected():
    result = _transit(_attachment(first_operations=False,
                                  tail=b'Content-Disposition: form-data; name="operations"'),
                      graphql_max_bytes=256, upload_scan_enabled=False)
    assert result["received"] == b"" and result["metrics"]["dropped"] == 1


def test_large_benign_attachment_preserves_all_wire_bytes():
    body = _attachment(padding=1024 * 1024)
    for chunked in (False, True):
        result = _transit(body, chunked=chunked, split=True,
                          graphql_max_bytes=256, upload_scan_enabled=False,
                          upload_deny_ext=[])
        assert result["received"].partition(b"\r\n\r\n")[2] == result["wire"]
        assert result["response"].startswith(b"HTTP/1.1 200")
        assert result["metrics"]["proxied"] == 1 and result["metrics"]["dropped"] == 0


def test_audit_late_metadata_violation_preserves_the_entire_entity():
    body = _attachment(tail=_AMBIGUOUS[0])
    for chunked in (False, True):
        result = _transit(body, "audit", chunked=chunked, split=True,
                          graphql_max_bytes=256, upload_scan_enabled=False)
        assert result["received"].partition(b"\r\n\r\n")[2] == result["wire"]
        assert result["response"].startswith(b"HTTP/1.1 200")
        assert result["metrics"]["proxied"] == 1 and result["banned"] is False
        assert sum(event.get("rule") == "graphql_multipart_unscannable"
                   for event in result["events"]) == 1


def test_incomplete_final_field_metadata_is_not_partially_accepted():
    for body in (_attachment(close=False),
                 _attachment(close=False) + b"--" + _BOUNDARY
                 + b'\r\nContent-Disposition: form-data; name="operations"; name="notes"\r\n'
                   b'{"query":"{ health }"}\r\n' + b"--" + _BOUNDARY + b"--\r\n"):
        result = _transit(body, graphql_max_bytes=256, upload_scan_enabled=False)
        assert result["received"] == b"" and result["metrics"]["dropped"] == 1


def test_non_graphql_upload_behavior_and_literal_file_boundary_prefix_remain_usable():
    ambiguous = _attachment(tail=_AMBIGUOUS[0])
    for options in ({"graphql_enabled": False}, {"path": b"/upload"}):
        result = _transit(ambiguous, upload_scan_enabled=False, **options)
        assert result["received"].partition(b"\r\n\r\n")[2] == ambiguous
        assert result["response"].startswith(b"HTTP/1.1 200")
    normal = _attachment(padding=70000).replace(b"x" * 10,
              b"\n--" + _BOUNDARY + b"-ordinary-file-data\n", 1)
    result = _transit(normal.rstrip(b"\r\n"), graphql_max_bytes=256, upload_scan_enabled=False)
    assert result["received"].partition(b"\r\n\r\n")[2] == normal.rstrip(b"\r\n")
    assert result["response"].startswith(b"HTTP/1.1 200")


def test_field_metadata_after_a_terminal_boundary_cannot_select_another_operation():
    body = (_attachment(padding=70000) + b"--" + _BOUNDARY
            + b'\r\nContent-Disposition: form-data; name="operations"\r\n\r\n'
            + _CONTENT + b"\r\n--" + _BOUNDARY + b"--\r\n")
    result = _transit(body, graphql_max_bytes=256, upload_scan_enabled=False)
    assert result["received"] == b"" and result["metrics"]["dropped"] == 1


def test_metadata_streaming_retains_bounded_headers_and_boundary_tail_only():
    scanner = _UploadScan([_BOUNDARY], set(), operations_limit=1)
    body = _attachment(padding=1024 * 1024)
    sizes = (1, 2, 7, 31, 1024, 16384)
    offset = index = 0
    while offset < len(body):
        size = sizes[index % len(sizes)]
        assert scanner.feed(body[offset:offset + size]) is None
        offset += size
        index += 1
        for head in scanner._heads:
            assert len(head._hdr) <= _UPLOAD_HDR_MAX
            assert len(head._buf) <= _UPLOAD_HDR_MAX + max(sizes)
    assert scanner.finish() is None
    assert scanner._heads[0]._operations_count == 1


def test_comments_cannot_hide_a_part_name_in_the_initial_or_late_headers():
    for disposition in (b'Content-Disposition: form-data; (ordinary)name="operations"',
                        b'Content-Disposition: form-data; name(ordinary)="operations"',
                        b'Content-Disposition: form-data; name (ordinary) = "operations"'):
        assert _receiver_name(_body(disposition)) == "operations"
        assert _multipart_field(_body(disposition), [_BOUNDARY], "operations") is False
        for body in (_body(disposition), _attachment(tail=disposition)):
            result = _transit(body, upload_scan_enabled=False, graphql_max_bytes=256)
            assert result["received"] == b"" and result["metrics"]["dropped"] == 1
            observed = _transit(body, "audit", upload_scan_enabled=False, graphql_max_bytes=256)
            assert observed["received"].partition(b"\r\n\r\n")[2] == body
            assert observed["response"].startswith(b"HTTP/1.1 200")
            assert any(event.get("rule") == "graphql_multipart_unscannable"
                       and event["kind"] == "audit" for event in observed["events"])


def test_quoted_parentheses_in_an_unrelated_part_name_are_not_comments():
    body = _body(b'Content-Disposition: form-data; name="notes(ordinary)"')
    assert _receiver_name(body) == "notes(ordinary)"
    assert _multipart_field(body, [_BOUNDARY], "operations") is None
    result = _transit(body, upload_scan_enabled=False)
    assert result["received"].partition(b"\r\n\r\n")[2] == body
    assert result["response"].startswith(b"HTTP/1.1 200")
