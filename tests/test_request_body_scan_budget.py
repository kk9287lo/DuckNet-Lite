"""Encoded request framing cannot consume the scan budget before decoded content."""

import gzip
from email import policy
from email.parser import BytesParser
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield, _through


_PAYLOAD = b"user=admin' or 1=1-- -"
_CHUNKED_HEAD = (b"POST /login HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n")


def _chunk(data):
    return b"%x\r\n" % len(data) + data + b"\r\n"


def _gzip_head(size):
    return (b"POST /login HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: " + str(size).encode() + b"\r\n\r\n")


def _gzip_with_filename(data, padding):
    member = gzip.compress(data)
    # RFC 1952 FNAME is a zero-terminated field before compressed content.
    return member[:3] + b"\x08" + member[4:10] + b"A" * padding + b"\x00" + member[10:]


def _multipart(second, first_size):
    return (b'--b\r\nContent-Disposition: form-data; name="f1"; filename="photo.jpg"\r\n'
            b'Content-Type: image/jpeg\r\n\r\n' + b'A' * first_size + b'\r\n'
            b'--b\r\nContent-Disposition: form-data; name="f2"; filename="' + second
            + b'"\r\nContent-Type: application/octet-stream\r\n\r\nx\r\n--b--\r\n')


def _multipart_head(size, compressed=False):
    return (b"POST /upload HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: multipart/form-data; boundary=b\r\n"
            + (b"Content-Encoding: gzip\r\n" if compressed else b"")
            + b"Content-Length: " + str(size).encode() + b"\r\n\r\n")


def test_chunk_framing_padding_cannot_hide_signature_within_decoded_cap():
    padding = b"".join(_chunk(b"x") for _ in range(300))
    attack = padding + _chunk(_PAYLOAD) + b"0\r\n\r\n"
    received, _, metrics = _through([_CHUNKED_HEAD, attack],
                                     body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["dropped"] == 1

    direct, _, metrics = _through([_CHUNKED_HEAD, _chunk(_PAYLOAD) + b"0\r\n\r\n"],
                                  body_scan_max_bytes=1024, block_score=20)
    assert direct == b"" and metrics["dropped"] == 1

    benign = padding + _chunk(b"safe=1") + b"0\r\n\r\n"
    received, response, metrics = _through([_CHUNKED_HEAD, benign],
                                            body_scan_max_bytes=1024, block_score=20)
    assert benign in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["dropped"] == 0


def test_gzip_header_padding_cannot_hide_second_member_within_decoded_cap():
    first = gzip.compress(b"safe=1&")
    attack = first + _gzip_with_filename(_PAYLOAD, 1500)
    assert gzip.decompress(attack) == b"safe=1&" + _PAYLOAD
    received, _, metrics = _through([_gzip_head(len(attack)), attack],
                                     body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["dropped"] == 1

    direct = gzip.compress(_PAYLOAD)
    received, _, metrics = _through([_gzip_head(len(direct)), direct],
                                     body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["dropped"] == 1

    benign = first + _gzip_with_filename(b"safe=2", 1500)
    received, response, metrics = _through([_gzip_head(len(benign)), benign],
                                            body_scan_max_bytes=1024, block_score=20)
    assert gzip.decompress(received.partition(b"\r\n\r\n")[2]) == b"safe=1&safe=2"
    assert response.startswith(b"HTTP/1.1 200") and metrics["dropped"] == 0


def test_excessive_framing_overhead_fails_closed_with_total_body_limit():
    # The decoded prefix is still tiny when the bounded raw overhead budget ends.
    large_header = _gzip_with_filename(b"safe=1", 9000)
    received, _, metrics = _through([_gzip_head(len(large_header)), large_header],
                                     body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["dropped"] == 1

    # A body larger than the safe full-scan limit cannot be sent in enforce mode.
    large_body = gzip.compress(b"x" * 2000)
    received, response, metrics = _through([_gzip_head(len(large_body)) + large_body],
                                            body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and response.startswith(b"HTTP/1.1 413")
    assert metrics["proxied"] == 0


def test_compressed_multipart_requires_complete_upload_scan():
    bad_plain = _multipart(b"evil.xyz", 2048)
    bad_gzip = gzip.compress(bad_plain)
    assert len(bad_gzip) < 1024 and len(bad_plain) > 1024
    received, _, metrics = _through([_multipart_head(len(bad_gzip), True), bad_gzip],
                                     body_scan_max_bytes=1024, upload_deny_ext=["xyz"])
    assert received == b"" and metrics["dropped"] == 1

    # A small compressed multipart remains valid and the same extension is caught.
    small_bad = gzip.compress(_multipart(b"evil.xyz", 16))
    received, _, metrics = _through([_multipart_head(len(small_bad), True), small_bad],
                                     body_scan_max_bytes=1024, upload_deny_ext=["xyz"])
    assert received == b"" and metrics["dropped"] == 1
    small_good = gzip.compress(_multipart(b"notes.txt", 16))
    received, response, metrics = _through([_multipart_head(len(small_good), True), small_good],
                                            body_scan_max_bytes=1024, upload_deny_ext=["xyz"])
    assert gzip.decompress(received.partition(b"\r\n\r\n")[2]) == _multipart(b"notes.txt", 16)
    assert response.startswith(b"HTTP/1.1 200") and metrics["dropped"] == 0

    # A complete multi-member stream is scanned, while truncated CRC/ISIZE is not accepted.
    plain = _multipart(b"notes.txt", 16)
    multi = gzip.compress(plain[:80]) + gzip.compress(plain[80:])
    received, response, metrics = _through([_multipart_head(len(multi), True), multi],
                                            body_scan_max_bytes=1024, upload_deny_ext=["xyz"])
    assert gzip.decompress(received.partition(b"\r\n\r\n")[2]) == plain
    assert response.startswith(b"HTTP/1.1 200") and metrics["dropped"] == 0
    truncated = small_good[:-4]
    received, _, metrics = _through([_multipart_head(len(truncated), True), truncated],
                                     body_scan_max_bytes=1024, upload_deny_ext=["xyz"])
    assert received == b"" and metrics["dropped"] == 1

    # Upload scanning is independent of the optional body-signature decoder switch.
    received, _, metrics = _through([_multipart_head(len(small_good), True), small_good],
                                     body_scan_max_bytes=1024, upload_deny_ext=["xyz"],
                                     body_decode_enabled=False)
    assert received == b"" and metrics["dropped"] == 1

    # Upload scanning alone still checks later uncompressed parts when body
    # signature scanning is disabled independently.
    received, _, metrics = _through([_multipart_head(len(bad_plain)), bad_plain],
                                     body_scan_max_bytes=1024, upload_deny_ext=["xyz"],
                                     body_scan_enabled=False)
    assert b"evil.xyz" not in received and metrics["dropped"] >= 1


def test_duplicate_multipart_boundaries_cannot_hide_upload_or_graphql():
    params = b"; ".join(b"boundary=b%d" % i for i in range(1, 6))

    def send(path, boundary, part, value, *, duplicate=True, **cfg):
        ct = b"multipart/form-data; " + (params if duplicate else b"boundary=" + boundary)
        body = (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" + part
                + b"\"" + (b"; filename=\"" + value + b"\"" if part == b"file" else b"")
                + b"\r\n\r\n" + (b"x" if part == b"file" else value)
                + b"\r\n--" + boundary + b"--\r\n")
        head = (b"POST " + path + b" HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct
                + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        return _through([head + body], **cfg)

    cfg = {"upload_deny_ext": ["xyz"], "body_scan_max_bytes": 1024}
    received, response, metrics = send(b"/upload", b"b5", b"file", b"evil.xyz", **cfg)
    assert received == b"" and response.startswith(b"HTTP/1.1 400")
    assert metrics["proxied"] == 0
    received, response, _ = send(b"/upload", b"b1", b"file", b"notes.txt",
                                 duplicate=False, **cfg)
    assert b"notes.txt" in received and response.startswith(b"HTTP/1.1 200")
    received, _, metrics = send(b"/upload", b"b1", b"file", b"evil.xyz",
                                duplicate=False, **cfg)
    assert received == b"" and metrics["proxied"] == 0

    query = b'{"query":"{ __schema { types { name } } }"}'
    gql = {"graphql_enabled": True, "graphql_block_introspection": True,
           "graphql_max_bytes": 1024, "body_scan_max_bytes": 1024}
    received, response, metrics = send(b"/graphql", b"b5", b"operations", query, **gql)
    assert received == b"" and response.startswith(b"HTTP/1.1 400")
    assert metrics["proxied"] == 0
    received, _, metrics = send(b"/graphql", b"b1", b"operations", query,
                                duplicate=False, **gql)
    assert received == b"" and metrics["proxied"] == 0


def test_rfc2231_boundary_is_rejected_before_backend_parser_disagrees():
    def request(content_type, filename=b"evil.xyz"):
        body = (b'--b5\r\nContent-Disposition: form-data; name="f"; filename="'
                + filename + b'"\r\n\r\nx\r\n--b5--\r\n')
        head = (b'POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: ' + content_type
                + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n')
        return head + body

    for ct in (b"multipart/form-data; boundary*=utf-8''b5; boundary=b1",
               b"multipart/form-data; boundary*0*=utf-8''b; boundary*1*=5"):
        raw = request(ct)
        parsed = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + ct + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + raw.partition(b"\r\n\r\n")[2])
        assert parsed.get_boundary() == "b5" and parsed.is_multipart()
        received, response, metrics = _through([raw], body_scan_max_bytes=1024,
                                               upload_deny_ext=["xyz"])
        assert received == b"" and response.startswith(b"HTTP/1.1 400")
        assert metrics["proxied"] == 0

    good = request(b"multipart/form-data; boundary=b5", b"notes.txt")
    received, response, metrics = _through([good], body_scan_max_bytes=1024,
                                           upload_deny_ext=["xyz"])
    assert b"notes.txt" in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_full_body_scan_limit_rejects_late_payloads_before_backend():
    def head(body, content_type, encoding=b""):
        return (b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: " + content_type + b"\r\n"
                + (b"Content-Encoding: " + encoding + b"\r\n" if encoding else b"")
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")

    payload = b"user=admin' or 1=1-- -"
    cases = ((b"a" * 1024 + payload, b"application/x-www-form-urlencoded", b""),
             (gzip.compress(b"a" * 1024 + payload), b"application/x-www-form-urlencoded", b"gzip"),
             (b"\x00" + b"a" * 1024 + payload, b"application/octet-stream", b""))
    for body, ct, enc in cases:
        received, response, metrics = _through([head(body, ct, enc) + body],
                                               body_scan_max_bytes=1024, block_score=20)
        assert received == b"" and response.startswith(b"HTTP/1.1 413"), (ct, enc, response)
        assert metrics["proxied"] == 0

    chunked = _chunk(b"a" * 1024) + _chunk(payload) + b"0\r\n\r\n"
    received, response, metrics = _through([_CHUNKED_HEAD + chunked],
                                           body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and response.startswith(b"HTTP/1.1 413")
    assert metrics["proxied"] == 0

    # Disabling the decoder must not turn an encoded body into a blind pass.
    encoded = gzip.compress(payload)
    received, response, metrics = _through([_gzip_head(len(encoded)) + encoded],
                                           body_scan_max_bytes=1024,
                                           body_decode_enabled=False,
                                           body_reject_unscannable_encoding=False)
    assert received == b"" and response.startswith(b"HTTP/1.1 415")
    assert metrics["proxied"] == 0

    # Complete benign text, compressed, and binary bodies at or below cap pass.
    for body, ct, enc in ((b"a" * 1024, b"text/plain", b""),
                          (gzip.compress(b"a" * 1024), b"text/plain", b"gzip"),
                          (b"\x89PNG\r\n\x1a\n" + b"\x00" * 32,
                           b"application/octet-stream", b"")):
        received, response, metrics = _through([head(body, ct, enc) + body],
                                               body_scan_max_bytes=1024, block_score=20)
        assert body in received and response.startswith(b"HTTP/1.1 200"), (ct, enc, response)
        assert metrics["proxied"] == 1


def test_binary_content_type_cannot_skip_signature_after_control_byte():
    body = b"\x00user=admin' or 1=1-- -"
    head = (b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    received, _, metrics = _through([head + body], body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["proxied"] == 0


def test_multipart_binary_file_cannot_hide_signature():
    def request(payload, filename=b"notes.txt"):
        body = (b'--b\r\nContent-Disposition: form-data; name="file"; filename="'
                + filename + b'"\r\n\r\n' + payload + b'\r\n--b--\r\n')
        head = _multipart_head(len(body))
        return head + body

    bad = request(b"\x00user=admin' or 1=1-- -")
    received, _, metrics = _through([bad], body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["proxied"] == 0

    good = request(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    received, response, metrics = _through([good], body_scan_max_bytes=1024, block_score=20)
    assert good.partition(b"\r\n\r\n")[2] in received
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1


def test_body_scan_runtime_failure_is_not_clean_allow():
    body = b"safe=1"
    head = (b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    original = ND.NetShield._scan_field

    def fail_body(self, text, **kw):
        if kw.get("body"):
            raise RuntimeError("signature scanner unavailable")
        return original(self, text, **kw)

    with patch.object(ND.NetShield, "_scan_field", fail_body):
        received, _, metrics = _through([head + body], body_scan_max_bytes=1024)
    assert received == b"" and metrics["proxied"] == 0

    def fail_charset(*args, **kwargs):
        raise RuntimeError("declared charset decoder unavailable")

    charset_head = head.replace(b"Content-Type: text/plain",
                                b"Content-Type: text/plain; charset=ibm037")
    with patch.object(ND.saferegex, "declared_readings", fail_charset):
        received, _, metrics = _through([charset_head + body], body_scan_max_bytes=1024)
    assert received == b"" and metrics["proxied"] == 0

    for patched, attr, replacement, wire, stage in (
            (ND.NetShield, "_scan_field", fail_body, head + body, "signature"),
            (ND.saferegex, "declared_readings", fail_charset,
             charset_head + body, "declared_readings")):
        backend = _Backend()
        try:
            with patch.object(patched, attr, replacement):
                with _shield(mode="audit", body_scan_max_bytes=1024) as shield:
                    with _guard(backend) as guard:
                        response = _exchange(guard, [wire])
                        assert response.startswith(b"HTTP/1.1 200")
                    assert any(e.get("kind") == "audit" and e.get("stage") == stage
                               for e in shield.events(200))
            assert body in backend.saw()
        finally:
            backend.close()

    received, response, metrics = _through([head + body], body_scan_max_bytes=1024)
    assert body in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_audit_keeps_oversize_body_but_records_would_reject():
    body = b"a" * 1025
    head = (b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    backend = _Backend()
    try:
        with _shield(mode="audit", body_scan_max_bytes=1024) as shield:
            with _guard(backend) as guard:
                response = _exchange(guard, [head + body])
                assert response.startswith(b"HTTP/1.1 200")
            assert any(e.get("kind") == "audit" and e.get("rule") == "body_scan_limit"
                       for e in shield.events(200))
        assert body in backend.saw()
    finally:
        backend.close()


def test_direct_body_inspection_enforces_the_same_total_limit():
    body = b"safe=1" + b"x" * 1024
    with _shield(body_scan_max_bytes=1024) as shield:
        result = shield.inspect_body("192.0.2.41", body, content_type="text/plain")
        assert result["action"] == "block" and result.get("reason")
        assert any(e.get("kind") == "body_scan_limit" for e in shield.events(200))
        assert shield.inspect_body("192.0.2.42", b"safe=1",
                                   content_type="text/plain")["action"] == "allow"
    with _shield(mode="audit", body_scan_max_bytes=1024) as shield:
        assert shield.inspect_body("192.0.2.43", body)["action"] == "allow"
        assert any(e.get("kind") == "audit" and e.get("rule") == "body_scan_limit"
                   for e in shield.events(200))


def test_audit_records_unscannable_encoded_guards_and_preserves_transfer():
    cases = (
        (b"/graphql", b"application/json", gzip.compress(b'{"query":"{ ok }"}'),
         {"graphql_enabled": True, "body_scan_enabled": False}, "graphql_unscannable"),
        (b"/upload", b"multipart/form-data; boundary=b",
         gzip.compress(_multipart(b"notes.txt", 16)),
         {"upload_scan_enabled": True, "body_scan_enabled": False}, "upload_unscannable"),
    )
    for path, ct, body, config, rule in cases:
        head = (b"POST " + path + b" HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct
                + b"\r\nContent-Encoding: gzip\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n")
        backend = _Backend()
        try:
            with _shield(mode="audit", body_scan_max_bytes=1024,
                         body_decode_enabled=False, **config) as shield:
                with _guard(backend) as guard:
                    response = _exchange(guard, [head + body])
                    assert response.startswith(b"HTTP/1.1 200"), (rule, response)
                assert any(e.get("kind") == "audit" and e.get("rule") == rule
                           for e in shield.events(200)), rule
            assert body in backend.saw(), rule
        finally:
            backend.close()

    # Audit does not excuse broken wire framing.
    malformed = (_CHUNKED_HEAD + b"1;=bad\r\nx\r\n0\r\n\r\n")
    received, response, metrics = _through([malformed], mode="audit")
    assert received == b"" and response.startswith(b"HTTP/1.1 400")
    assert metrics["proxied"] == 0


def test_early_413_415_are_received_after_split_small_request_body():
    payloads = (
        (b"/login", b"text/plain", b"a" * 1025, b"", {}, b"413"),
        (b"/login", b"text/plain", gzip.compress(b"safe=1"), b"gzip",
         {"body_decode_enabled": False}, b"415"),
        (b"/graphql", b"application/json", gzip.compress(b'{"query":"{ ok }"}'), b"gzip",
         {"body_scan_enabled": False, "graphql_enabled": True,
          "body_decode_enabled": False}, b"415"),
        (b"/upload", b"multipart/form-data; boundary=b",
         gzip.compress(_multipart(b"notes.txt", 16)), b"gzip",
         {"body_scan_enabled": False, "upload_scan_enabled": True,
          "body_decode_enabled": False}, b"415"),
    )
    for path, ct, body, encoding, cfg, status in payloads:
        head = (b"POST " + path + b" HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct
                + b"\r\n" + (b"Content-Encoding: " + encoding + b"\r\n" if encoding else b"")
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        received, response, metrics = _through([head, body], body_scan_max_bytes=1024, **cfg)
        assert received == b"" and response.startswith(b"HTTP/1.1 " + status), (path, response)
        assert metrics["proxied"] == 0


def test_raw_newline_in_form_values_is_scanned_without_multiline_prose_false_positive():
    def request(body, ct):
        return (b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct
                + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    attacks = (b"next=\r\nSet-Cookie: sid=evil",
               b"=\r\nSet-Cookie: sid=evil",
               b"&next=\r\nSet-Cookie: sid=evil",
               "名前=\r\nSet-Cookie: sid=evil".encode("utf-8"))
    benign = b"review=Great store.\r\nCat food arrived fast"
    for ct in (b"application/x-www-form-urlencoded", b"text/plain"):
        for attack in attacks:
            received, _, metrics = _through([request(attack, ct)],
                                            body_scan_max_bytes=1024, block_score=20)
            assert received == b"" and metrics["proxied"] == 0, (ct, attack)
        received, response, metrics = _through([request(benign, ct)],
                                               body_scan_max_bytes=1024, block_score=20)
        assert benign in received and response.startswith(b"HTTP/1.1 200"), ct
        assert metrics["proxied"] == 1

    def multipart(value):
        return (b'--b\r\nContent-Disposition: form-data; name="next"\r\n\r\n'
                + value + b'\r\n--b--\r\n')

    ct = b"multipart/form-data; boundary=b"
    for value, blocked in ((b"\r\nSet-Cookie: sid=evil", True),
                           (b"Great store.\r\nCat food arrived fast", False)):
        body = multipart(value)
        received, response, metrics = _through([request(body, ct)],
                                               body_scan_max_bytes=1024, block_score=20)
        if blocked:
            assert received == b"" and metrics["proxied"] == 0
        else:
            assert body in received and response.startswith(b"HTTP/1.1 200")
            assert metrics["proxied"] == 1


def test_duplicate_charset_parameters_cannot_hide_middle_backend_reading():
    malicious = b"comment=<script>alert(1)</script>".decode("ascii").encode("cp037")
    duplicate = b"text/plain; charset=utf-16-le; charset=ibm037; charset=utf-16-be"

    def request(ct, body):
        return (b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct
                + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    received, response, metrics = _through([request(duplicate, malicious)],
                                           body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and response.startswith(b"HTTP/1.1 400")
    assert metrics["proxied"] == 0
    with _shield(body_scan_max_bytes=1024, block_score=20) as shield:
        result = shield.inspect_body("192.0.2.44", malicious, content_type=duplicate.decode())
        assert result["action"] == "block" and result.get("reason")

    received, _, metrics = _through([request(b"text/plain; charset=ibm037", malicious)],
                                    body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["proxied"] == 0
    benign = b"hello"
    received, response, metrics = _through([request(b"text/plain; charset=utf-8", benign)],
                                           body_scan_max_bytes=1024, block_score=20)
    assert benign in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_late_and_unsupported_charset_declarations_are_not_silently_ignored():
    malicious = b"comment=<script>alert(1)</script>".decode("ascii").encode("cp037")

    def request(ct, body):
        return (b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Type: " + ct
                + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    late = b"text/plain; x=" + b"a" * 1100 + b"; charset=ibm037"
    received, _, metrics = _through([request(late, malicious)],
                                    body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["proxied"] == 0
    single = b"text/plain; charset=ibm037"
    received, _, metrics = _through([request(single, malicious)],
                                    body_scan_max_bytes=1024, block_score=20)
    assert received == b"" and metrics["proxied"] == 0

    unknown = b"text/plain; charset=x-backend-only"
    received, response, metrics = _through([request(unknown, b"safe=1")],
                                           body_scan_max_bytes=1024)
    assert received == b"" and response.startswith(b"HTTP/1.1 415")
    assert metrics["proxied"] == 0
    with _shield(body_scan_max_bytes=1024) as shield:
        assert shield.inspect_body("192.0.2.45", b"safe=1",
                                   content_type=unknown.decode())["action"] == "block"
        oversized_type = "text/plain; x=" + "a" * 16400 + "; charset=ibm037"
        assert shield.inspect_body("192.0.2.46", malicious,
                                   content_type=oversized_type)["action"] == "block"
    backend = _Backend()
    try:
        with _shield(mode="audit", body_scan_max_bytes=1024) as shield:
            with _guard(backend) as guard:
                response = _exchange(guard, [request(unknown, b"safe=1")])
                assert response.startswith(b"HTTP/1.1 200")
            assert any(e.get("kind") == "audit" and e.get("stage") == "unsupported_charset"
                       for e in shield.events(200))
            assert shield.inspect_body("192.0.2.47", malicious,
                                       content_type=oversized_type)["action"] == "allow"
            assert any(e.get("kind") == "audit" and e.get("stage") == "ambiguous_charset"
                       for e in shield.events(200))
        assert b"safe=1" in backend.saw()
    finally:
        backend.close()
    received, response, metrics = _through([request(unknown, b"safe=1")],
                                           body_scan_max_bytes=1024, enabled=False)
    assert b"safe=1" in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_graphql_multipart_operations_reject_ambiguous_or_unknown_part_charset():
    malicious = b'{"query":"{ __schema { types { name } } }"}'.decode().encode("cp037")

    def request(part_type, operations):
        body = (b'--b\r\nContent-Disposition: form-data; name="operations"\r\n'
                b'Content-Type: ' + part_type + b'\r\n\r\n' + operations + b'\r\n--b--\r\n')
        head = (b'POST /graphql HTTP/1.1\r\nHost: x\r\n'
                b'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n')
        return head + body

    cfg = {"body_scan_enabled": False, "graphql_enabled": True,
           "graphql_block_introspection": True, "graphql_max_bytes": 1024}
    triple = b"application/json; charset=utf-16-le; charset=ibm037; charset=utf-16-be"
    received, _, metrics = _through([request(triple, malicious)], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    received, _, metrics = _through([request(b"application/json; charset=ibm037", malicious)], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    unknown = b"application/json; charset=x-backend-only"
    received, _, metrics = _through([request(unknown, b'{"query":"{ ok }"}')], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    good = request(b"application/json; charset=utf-8", b'{"query":"{ ok }"}')
    received, response, metrics = _through([good], **cfg)
    assert b"/graphql" in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_folded_multipart_operations_name_is_still_a_graphql_request():
    body = (b'--b\r\nContent-Disposition: form-data;\r\n name="operations"\r\n\r\n'
            b'{"query":"{ __schema { types { name } } }"}\r\n--b--\r\n')
    head = (b'POST /graphql HTTP/1.1\r\nHost: x\r\n'
            b'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: '
            + str(len(body)).encode() + b'\r\n\r\n')
    mime = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: multipart/form-data; boundary=b\r\nMIME-Version: 1.0\r\n\r\n' + body)
    assert mime.is_multipart() and mime.get_payload(0).get_param(
        'name', header='content-disposition') == 'operations'
    cfg = {"body_scan_enabled": False, "graphql_enabled": True, "graphql_max_bytes": 1024}
    received, _, metrics = _through([head + body], **cfg)
    assert received == b"" and metrics["proxied"] == 0

    normal = body.replace(b'form-data;\r\n name=', b'form-data; name=').replace(
        b'__schema { types { name } }', b'ok')
    normal_head = head.replace(str(len(body)).encode(), str(len(normal)).encode())
    received, response, metrics = _through([normal_head + normal], **cfg)
    assert b'/graphql' in received and response.startswith(b'HTTP/1.1 200')
    assert metrics['proxied'] == 1


def test_duplicate_graphql_operations_parts_cannot_choose_unchecked_later_value():
    def part(query):
        return (b'--b\r\nContent-Disposition: form-data; name="operations"\r\n\r\n'
                b'{"query":"' + query + b'"}\r\n')

    def request(body):
        head = (b'POST /graphql HTTP/1.1\r\nHost: x\r\n'
                b'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n')
        return head + body

    safe = part(b'{ ok }')
    attack = safe + part(b'{ __schema { types { name } } }') + b'--b--\r\n'
    mime = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: multipart/form-data; boundary=b\r\nMIME-Version: 1.0\r\n\r\n'
        + attack)
    assert mime.is_multipart() and len(mime.get_payload()) == 2
    cfg = {"body_scan_enabled": False, "graphql_enabled": True, "graphql_max_bytes": 1024}
    received, response, metrics = _through([request(attack)], **cfg)
    assert received == b"" and response.startswith(b"HTTP/1.1 413")
    assert metrics["proxied"] == 0
    received, response, metrics = _through([request(safe + b'--b--\r\n')], **cfg)
    assert b'/graphql' in received and response.startswith(b'HTTP/1.1 200')
    assert metrics['proxied'] == 1


def test_graphql_operations_part_charset_is_used_for_body_signatures():
    import json

    def request(part_type, variable, codec):
        operations = json.dumps({"query": "{ ok }", "variables": {"next": variable}}).encode(codec)
        body = (b'--b\r\nContent-Disposition: form-data; name="operations"\r\n'
                b'Content-Type: ' + part_type + b'\r\n\r\n' + operations + b'\r\n--b--\r\n')
        head = (b'POST /graphql HTTP/1.1\r\nHost: x\r\n'
                b'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n')
        return head + body

    cfg = {"body_scan_max_bytes": 1024, "block_score": 20,
           "graphql_enabled": True, "graphql_max_bytes": 1024}
    attack = "\r\nSet-Cookie: sid=evil"
    cp037 = b"application/json; charset=ibm037"
    received, _, metrics = _through([request(cp037, attack, "cp037")], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    received, _, metrics = _through([request(b"application/json; charset=utf-8",
                                             attack, "utf-8")], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    benign = request(cp037, "Great store.\r\nCat food arrived fast", "cp037")
    received, response, metrics = _through([benign], **cfg)
    assert b"/graphql" in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_each_multipart_form_part_uses_its_declared_charset():
    def request(part_type, text, codec):
        payload = text.encode(codec)
        body = (b'--b\r\nContent-Disposition: form-data; name="note"\r\n'
                b'Content-Type: ' + part_type + b'\r\n\r\n' + payload + b'\r\n--b--\r\n')
        head = (b'POST /submit HTTP/1.1\r\nHost: x\r\n'
                b'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n')
        return head + body

    attack = "comment=<script>alert(1)</script>"
    cp037 = b"text/plain; charset=ibm037"
    cfg = {"body_scan_max_bytes": 32768, "block_score": 20}
    received, _, metrics = _through([request(cp037, attack, "cp037")], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    folded = b"text/plain;\r\n charset=ibm037"
    folded_wire = request(folded, attack, "cp037")
    mime = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: multipart/form-data; boundary=b\r\nMIME-Version: 1.0\r\n\r\n"
        + folded_wire.partition(b"\r\n\r\n")[2])
    assert mime.is_multipart() and mime.get_payload(0).get_content_charset() == "ibm037"
    received, _, metrics = _through([folded_wire], **cfg)
    assert received == b"" and metrics["proxied"] == 0
    received, _, metrics = _through([request(b"text/plain; charset=utf-8", attack, "utf-8")], **cfg)
    assert received == b"" and metrics["proxied"] == 0

    for ct in (b"text/plain; charset=x-backend-only",
               b"text/plain; x=" + b"a" * 16400 + b"; charset=ibm037"):
        received, _, metrics = _through([request(ct, "hello", "cp037")], **cfg)
        assert received == b"" and metrics["proxied"] == 0

    benign = request(cp037, "hello", "cp037")
    received, response, metrics = _through([benign], **cfg)
    assert b"/submit" in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_request_head_ceiling_applies_even_when_terminator_arrives_in_last_read():
    def request(size):
        return b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"a" * size + b"\r\n\r\n"

    oversized = request(17000)
    received, response, metrics = _through([oversized[:15000], oversized[15000:]])
    assert received == b"" and response.startswith(b"HTTP/1.1 431")
    assert metrics["proxied"] == 0
    received, response, metrics = _through([request(1000)])
    assert b"X-Pad: " in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_nested_multipart_cannot_hide_inner_upload_filename():
    def request(nested, filename):
        if nested:
            inner = (b'--x\r\nContent-Disposition: attachment; filename="' + filename
                     + b'"\r\n\r\nx\r\n--x--\r\n')
            body = (b'--b\r\nContent-Disposition: form-data; name="files"\r\n'
                    b'Content-Type: multipart/mixed; boundary=x\r\n\r\n'
                    + inner + b'\r\n--b--\r\n')
        else:
            body = (b'--b\r\nContent-Disposition: form-data; name="files"; filename="'
                    + filename + b'"\r\n\r\nx\r\n--b--\r\n')
        head = (b'POST /upload HTTP/1.1\r\nHost: x\r\n'
                b'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n')
        return head + body

    attack = request(True, b"evil.xyz")
    mime = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: multipart/form-data; boundary=b\r\nMIME-Version: 1.0\r\n\r\n'
        + attack.partition(b'\r\n\r\n')[2])
    assert mime.is_multipart() and any(p.get_filename() == "evil.xyz" for p in mime.walk())
    for scan_on in (True, False):
        received, _, metrics = _through([attack], body_scan_max_bytes=1024,
                                        body_scan_enabled=scan_on, upload_deny_ext=["xyz"])
        assert received == b"" and metrics["proxied"] == 0

    benign = request(False, b"notes.txt")
    received, response, metrics = _through([benign], body_scan_max_bytes=1024,
                                           upload_deny_ext=["xyz"])
    assert b"notes.txt" in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1
