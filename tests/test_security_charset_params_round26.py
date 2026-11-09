"""Declared MIME charset parameters must not disappear before body inspection."""

import email
from email import policy
import json

from dataplane.engine.core import saferegex
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_EXTENDED = (
    "application/json; charset*=utf-8''ibm037",
    'application/json; charset*0="ibm"; charset*1="037"',
    "application/json; charset*0*=utf-8''ibm; charset*1*=037",
    "application/json; charset=utf-8; CHARSET*=utf-8''ibm037",
)
_DOCUMENT = {"query": "{ health }"}
_EBCDIC = json.dumps(_DOCUMENT, separators=(",", ":")).encode("cp037")
_BOUNDARY = b"round26-charset-fields"


def _part(content_type, data):
    return (b"--" + _BOUNDARY
            + b'\r\nContent-Disposition: form-data; name="operations"\r\nContent-Type: '
            + content_type.encode("ascii") + b"\r\n\r\n" + data
            + b"\r\n--" + _BOUNDARY + b"--\r\n")


def _through(data, content_type, *, mode="enforce", graphql=True, body_scan=False):
    path = b"/graphql" if graphql else b"/ordinary-upload"
    request = (b"POST " + path + b" HTTP/1.1\r\nHost: local.test\r\nContent-Type: "
               + content_type.encode("ascii") + b"\r\nContent-Length: "
               + str(len(data)).encode() + b"\r\n\r\n" + data)
    backend = _Backend()
    try:
        with _shield(graphql_enabled=graphql, body_scan_enabled=body_scan,
                     upload_scan_enabled=False, mode=mode) as shield, _guard(backend) as guard:
            response = _exchange(guard, [request])
            return {"received": backend.saw(), "response": response,
                    "events": shield.events(), "metrics": dict(guard.metrics)}
    finally:
        backend.close()


def test_extended_charset_is_uninspectable_instead_of_an_absent_declaration():
    message = email.message_from_bytes(b"Content-Type: " + _EXTENDED[0].encode()
                                      + b"\r\n\r\n" + _EBCDIC, policy=policy.default)
    assert message.get_content_charset() == "ibm037"
    assert json.loads(message.get_payload(decode=True).decode("cp037")) == _DOCUMENT
    for content_type in _EXTENDED:
        assert saferegex.unsupported_charset(content_type)


def test_top_level_extended_charset_is_rejected_before_backend():
    for content_type in _EXTENDED:
        result = _through(_EBCDIC, content_type)
        assert result["received"] == b"" and result["metrics"]["proxied"] == 0
        assert result["metrics"]["dropped"] == 1


def test_graphql_part_extended_charset_is_rejected_before_backend():
    for content_type in _EXTENDED:
        data = _part(content_type, _EBCDIC)
        result = _through(data, "multipart/form-data; boundary=" + _BOUNDARY.decode())
        assert result["received"] == b"" and result["metrics"]["proxied"] == 0
        assert result["metrics"]["dropped"] == 1


def test_body_signature_scanning_does_not_treat_an_extended_part_charset_as_absent():
    result = _through(_part(_EXTENDED[0], _EBCDIC),
                      "multipart/form-data; boundary=" + _BOUNDARY.decode(),
                      graphql=False, body_scan=True)
    assert result["received"] == b"" and result["metrics"]["proxied"] == 0
    assert any(event.get("stage") == "multipart_part_charset" for event in result["events"])


def test_audit_records_extended_charsets_and_preserves_the_original_wire():
    for data, content_type, graphql, body_scan in (
        (_EBCDIC, _EXTENDED[0], True, False),
        (_part(_EXTENDED[0], _EBCDIC), "multipart/form-data; boundary=" + _BOUNDARY.decode(), True, False),
        (_part(_EXTENDED[0], _EBCDIC), "multipart/form-data; boundary=" + _BOUNDARY.decode(), False, True),
    ):
        result = _through(data, content_type, mode="audit", graphql=graphql, body_scan=body_scan)
        assert result["received"].partition(b"\r\n\r\n")[2] == data
        assert result["response"].startswith(b"HTTP/1.1 200")
        assert any(event["kind"] == "audit" and event.get("would") in ("reject", "block")
                   for event in result["events"])


def test_quoted_notes_are_not_treated_as_charset_parameter_keys():
    for content_type in (
        'application/json; note="charset*=utf-8\'\'ibm037"; charset=utf-8',
        'application/json; note="charset*0=ibm; charset*1=037"; charset="utf-8"',
        'application/json; note="charset=not-a-codec"; charset=utf-8',
        'application/json; note="ordinary; charset=not-a-codec"; charset=utf-8',
        r'application/json; note="ordinary \"quoted\"; charset*=ordinary"; charset=utf-8',
        'application/json; note=charset*=ordinary; charset=utf-8',
    ):
        assert not saferegex.ambiguous_charset(content_type)
        assert not saferegex.unsupported_charset(content_type)
        result = _through(json.dumps(_DOCUMENT).encode(), content_type)
        assert result["response"].startswith(b"HTTP/1.1 200")
        assert result["metrics"]["proxied"] == 1


def test_normal_charsets_unicode_json_and_folded_part_headers_remain_usable():
    unicode_data = json.dumps({"query": '{ hello(message: "日本語") }'}, ensure_ascii=False).encode()
    for content_type, data in (
        ("application/json; charset=utf-8", unicode_data),
        ('application/json; CHARSET = "utf-8"', unicode_data),
        ('application/json;\r\n charset="utf-8"', unicode_data),
        ('application/json; charset="ibm037"', _EBCDIC),
        ('application/json; charset="utf\\-8"', unicode_data),
    ):
        assert not saferegex.unsupported_charset(content_type)
        body = _part(content_type, data)
        for mode in ("enforce", "audit"):
            result = _through(body, "multipart/form-data; boundary=" + _BOUNDARY.decode(), mode=mode)
            assert result["received"].partition(b"\r\n\r\n")[2] == body
            assert result["response"].startswith(b"HTTP/1.1 200")


def test_duplicate_empty_unknown_and_overlong_charset_values_fail_closed():
    assert saferegex.ambiguous_charset('application/json; charset=utf-8; CHARSET="utf-8"')
    for content_type in ("application/json; charset=", 'application/json; charset=""',
                         "application/json; charset=not-a-codec",
                         'application/json; charset="utf-8' + "_" * 59 + 'ibm037"',
                         'application/json; note="' + "x" * 16384 + '"'):
        assert saferegex.unsupported_charset(content_type)


def test_mime_comments_cannot_hide_a_charset_parameter_from_inspection():
    types = ("application/json; (ordinary)charset=ibm037",
             "application/json; charset(ordinary)=ibm037",
             "application/json; charset (ordinary) = ibm037")
    for content_type in types:
        message = email.message_from_bytes(b"Content-Type: " + content_type.encode()
                                          + b"\r\n\r\n" + _EBCDIC, policy=policy.default)
        assert message.get_content_charset() == "ibm037"
        assert saferegex.ambiguous_charset(content_type)
        assert saferegex.unsupported_charset(content_type)


def test_parent_content_type_comments_are_mandatory_refusals_in_both_modes():
    for content_type in ("application/json (ordinary)",
                         "application/json; (ordinary)charset=ibm037",
                         "multipart/form-data; boundary(ordinary)=round26",
                         "multipart/form-data; (ordinary)boundary=round26"):
        for mode in ("enforce", "audit"):
            result = _through(b"ordinary-data", content_type, graphql=False, mode=mode)
            assert result["received"] == b""
            assert result["response"].startswith(b"HTTP/1.1 400")
            assert result["metrics"]["proxied"] == 0 and result["metrics"]["dropped"] == 1


def test_part_charset_comments_are_blocked_or_audited_with_exact_wire():
    body = _part("application/json; charset(ordinary)=ibm037", _EBCDIC)
    content_type = "multipart/form-data; boundary=" + _BOUNDARY.decode()
    for graphql, body_scan in ((True, False), (False, True)):
        result = _through(body, content_type, graphql=graphql, body_scan=body_scan)
        assert result["received"] == b"" and result["metrics"]["proxied"] == 0
        observed = _through(body, content_type, graphql=graphql, body_scan=body_scan, mode="audit")
        assert observed["received"].partition(b"\r\n\r\n")[2] == body
        assert observed["response"].startswith(b"HTTP/1.1 200")
        assert any(event["kind"] == "audit" and event.get("would") in ("block", "reject")
                   for event in observed["events"])


def test_literal_quoted_parentheses_and_quoted_pairs_are_ordinary_values():
    for content_type in ('application/json; note="(ordinary)"; charset=ibm037',
                         r'application/json; note="(ordinary) \"quoted\""; charset=ibm037'):
        assert not saferegex.ambiguous_charset(content_type)
        assert not saferegex.unsupported_charset(content_type)
        for mode in ("enforce", "audit"):
            result = _through(_EBCDIC, content_type, mode=mode)
            assert result["received"].partition(b"\r\n\r\n")[2] == _EBCDIC
            assert result["response"].startswith(b"HTTP/1.1 200")
    boundary = b"round26(ordinary)"
    body = _part("application/json; charset=ibm037", _EBCDIC).replace(_BOUNDARY, boundary)
    for mode in ("enforce", "audit"):
        result = _through(body, 'multipart/form-data; boundary="' + boundary.decode() + '"', mode=mode)
        assert result["received"].partition(b"\r\n\r\n")[2] == body
        assert result["response"].startswith(b"HTTP/1.1 200")
