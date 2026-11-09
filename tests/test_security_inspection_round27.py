"""Multipart transfer declarations must not hide a receiver's decoded body."""

import base64
import email
from email import policy
import gzip
import json

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_BOUNDARY = b"round27-transfer-fields"
_DOCUMENT = {"query": "{ health version }"}
_JSON = json.dumps(_DOCUMENT, separators=(",", ":")).encode()
_TYPE = "multipart/form-data; boundary=" + _BOUNDARY.decode()


def _part(value, transfer="", *, name="operations", extra=b""):
    return (b"--" + _BOUNDARY + b'\r\nContent-Disposition: form-data; name="'
            + name.encode() + b'"\r\nContent-Type: application/json\r\n'
            + (b"Content-Transfer-Encoding: " + transfer.encode() + b"\r\n" if transfer else b"")
            + extra + b"\r\n" + value + b"\r\n--" + _BOUNDARY + b"--\r\n")


def _encoded_parts():
    return (("base64", base64.b64encode(_JSON)),
            ("quoted-printable", b"".join(b"=%02X" % item for item in _JSON)))


def _through(body, *, mode="enforce", graphql=True, body_scan=False,
             content_encoding="", split=False):
    request = (b"POST /graphql HTTP/1.1\r\nHost: local.test\r\nContent-Type: "
               + _TYPE.encode() + b"\r\nContent-Length: " + str(len(body)).encode()
               + (b"\r\nContent-Encoding: " + content_encoding.encode() if content_encoding else b"")
               + b"\r\n\r\n" + body)
    backend = _Backend()
    try:
        with _shield(mode=mode, graphql_enabled=graphql, graphql_max_complexity=1,
                     body_scan_enabled=body_scan, upload_scan_enabled=False) as shield, _guard(backend) as guard:
            parts = [request]
            if split:
                cut = request.index(b"Content-Transfer-Encoding") + 11
                parts = [request[:cut], request[cut:cut + 17], request[cut + 17:]]
            response = _exchange(guard, parts)
            return dict(received=backend.saw(), response=response, events=shield.events(),
                        metrics=dict(guard.metrics), banned=shield.is_banned_fast("127.0.0.1"))
    finally:
        backend.close()


def test_standard_receiver_decodes_an_operation_that_inspection_must_not_skip():
    for transfer, value in _encoded_parts():
        body = _part(value, transfer)
        receiver = email.message_from_bytes(b"Content-Type: " + _TYPE.encode()
                                            + b"\r\n\r\n" + body, policy=policy.default)
        part = list(receiver.iter_parts())[0]
        assert json.loads(part.get_payload(decode=True)) == _DOCUMENT
        with _shield(graphql_enabled=True, graphql_max_complexity=1,
                     body_scan_enabled=False, upload_scan_enabled=False) as shield:
            result = shield.inspect_graphql("127.0.0.1", "/graphql", body, _TYPE)
            assert result["action"] in ("block", "reject"), (transfer, result)


def test_encoded_operations_are_rejected_before_any_backend_bytes():
    for transfer, value in _encoded_parts():
        result = _through(_part(value, transfer))
        assert result["received"] == b"", (transfer, result)
        assert result["metrics"]["proxied"] == 0 and result["metrics"]["dropped"] == 1
        assert not result["banned"]


def test_encoded_operations_audit_keeps_exact_wire_and_records_uninspectable():
    for transfer, value in _encoded_parts():
        body = _part(value, transfer)
        result = _through(body, mode="audit")
        assert result["received"].partition(b"\r\n\r\n")[2] == body
        assert result["response"].startswith(b"HTTP/1.1 200")
        assert any(event["kind"] == "audit" and event.get("would") in ("block", "reject")
                   for event in result["events"]), result["events"]


def test_split_headers_and_compressed_entity_preserve_the_part_encoding_boundary():
    for transfer, value in _encoded_parts():
        body = _part(value, transfer)
        split = _through(body, split=True)
        compressed = _through(gzip.compress(body), content_encoding="gzip")
        for result in (split, compressed):
            assert result["received"] == b""
            assert result["metrics"]["proxied"] == 0 and result["metrics"]["dropped"] == 1


def test_body_inspection_rejects_unreadable_part_transfer_encodings_in_both_modes():
    for transfer, value in _encoded_parts():
        body = _part(value, transfer, name="ordinary")
        blocked = _through(body, graphql=False, body_scan=True)
        assert blocked["received"] == b""
        audited = _through(body, mode="audit", graphql=False, body_scan=True)
        assert audited["received"].partition(b"\r\n\r\n")[2] == body
        assert any(event["kind"] == "audit" and event.get("stage") == "multipart_part_encoding"
                   for event in audited["events"])


def test_identity_transfer_declarations_and_ordinary_data_stay_usable():
    plain = json.dumps({"query": "{ health }"}).encode()
    for transfer in ("", "7bit", "8bit", "binary", "BiNaRy", "\r\n binary"):
        body = _part(plain, transfer)
        for mode in ("enforce", "audit"):
            result = _through(body, mode=mode)
            assert result["received"].partition(b"\r\n\r\n")[2] == body, (transfer, mode, result)
            assert result["response"].startswith(b"HTTP/1.1 200")
            assert result["metrics"]["dropped"] == 0


def test_duplicate_empty_and_unknown_transfer_declarations_are_not_partial_success():
    plain = json.dumps({"query": "{ health }"}).encode()
    for transfer, extra in (("unknown", b""),
                             ("binary", b"Content-Transfer-Encoding: base64\r\n"),
                             ("binary", b"Content-Transfer-Encoding: binary\r\n"),
                             (" ", b"")):
        result = _through(_part(plain, transfer, extra=extra))
        assert result["received"] == b"", (transfer, extra, result)
        assert result["metrics"]["dropped"] == 1


def test_non_graphql_upload_without_body_inspection_keeps_its_original_contract():
    body = _part(base64.b64encode(b"ordinary file data"), "base64", name="ordinary")
    result = _through(body, graphql=False)
    assert result["received"].partition(b"\r\n\r\n")[2] == body
    assert result["response"].startswith(b"HTTP/1.1 200")
