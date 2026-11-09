"""Existing egress DLP: decoded-prefix ownership and unsupported representations.

All credentials below are inert synthetic markers, and all network traffic is
between loopback fixtures. State isolation is established by the test runner
before this module imports the product.
"""
import json
from email import policy
from email.parser import BytesParser
import xml.etree.ElementTree as ET

from test_sweep_det_response import _pipe
from test_sweep_proxy_request import _through


_MARKER = b"ghp_" + b"a" * 36
_REQUEST = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(body, media=b"text/plain"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + media
            + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)


def _escaped_then_bad():
    # The first string is complete and decodes to the marker. The next string is
    # malformed; losing the previous decoded prefix cannot make it harmless.
    escaped = b"gh\\u0070_" + b"a" * 36
    return b'{"token":"' + escaped + b'","example":"hello\\q"}'


def test_completed_decoded_json_prefix_is_checked_before_sniff_fallback():
    body = _escaped_then_bad()
    assert json.loads(b'"gh\\u0070_' + b"a" * 36 + b'"').encode() == _MARKER
    response = _response(body)
    for step in (1, 13, 65536):
        out, shield = _pipe([response[i:i+step] for i in range(0, len(response), step)],
                            dlp_enabled=True, dlp_action="block", **_QUIET)
        assert b"gh\\u0070_" not in out, step
        assert shield.metrics().get("dlp_leak", 0) == 1, step
    out, shield = _pipe([response], dlp_enabled=True, dlp_action="audit", **_QUIET)
    assert out == response and shield.metrics().get("dlp_leak", 0) == 1


def test_completed_decoded_prefix_is_withheld_from_real_client():
    body = _escaped_then_bad()
    response = _response(body)
    received, out, _ = _through([_REQUEST], backend_resp=response,
                                 dlp_enabled=True, dlp_action="block", **_QUIET)
    assert received.startswith(b"GET /public/report HTTP/1.1\r\n")
    assert b"gh\\u0070_" not in out
    received, out, _ = _through([_REQUEST], backend_resp=response,
                                 dlp_enabled=True, dlp_action="audit", **_QUIET)
    assert received.startswith(b"GET /public/report HTTP/1.1\r\n") and out == response


def test_unmarked_wide_json_and_xml_are_unscannable_across_read_boundaries():
    examples = []
    for encoding in ("utf-16le", "utf-16be", "utf-32le", "utf-32be"):
        body = ('{"token":"' + _MARKER.decode() + '"}').encode(encoding)
        assert json.loads(body)["token"].encode() == _MARKER
        examples.append((body, b"application/json"))
    for encoding in ("utf-16le", "utf-16be"):
        body = ('<?xml version="1.0" encoding="' + encoding + '"?><item>'
                + _MARKER.decode() + '</item>').encode(encoding)
        assert ET.fromstring(body).text.encode() == _MARKER
        examples.append((body, b"application/xml"))
    for body, media in examples:
        response = _response(body, media)
        for step in (1, 13, 65536):
            out, shield = _pipe([response[i:i+step] for i in range(0, len(response), step)],
                                dlp_enabled=True, dlp_action="block", **_QUIET)
            assert body[:4] not in out, (media, step)
            assert shield.metrics().get("dlp_unscannable", 0) == 1, (media, step)
        out, shield = _pipe([response], dlp_enabled=True, dlp_action="audit", **_QUIET)
        assert out == response and shield.metrics().get("dlp_unscannable", 0) == 1


def test_unmarked_wide_response_is_withheld_from_real_client():
    body = ('<?xml version="1.0" encoding="utf-16le"?><item>'
            + _MARKER.decode() + '</item>').encode("utf-16le")
    assert ET.fromstring(body).text.encode() == _MARKER
    response = _response(body, b"application/xml")
    received, out, _ = _through([_REQUEST], backend_resp=response,
                                 dlp_enabled=True, dlp_action="block", **_QUIET)
    assert received.startswith(b"GET /public/report HTTP/1.1\r\n") and body[:4] not in out
    _, out, _ = _through([_REQUEST], backend_resp=response,
                          dlp_enabled=True, dlp_action="audit", **_QUIET)
    assert out == response


def _multipart():
    boundary = b"egress-test-boundary"
    split = 19
    body = (b"--" + boundary + b"\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-18/40\r\n\r\n"
            + _MARKER[:split] + b"\r\n--" + boundary
            + b"\r\nContent-Type: text/plain\r\nContent-Range: bytes 19-39/40\r\n\r\n"
            + _MARKER[split:] + b"\r\n--" + boundary + b"--\r\n")
    media = b"multipart/byteranges; boundary=" + boundary
    parsed = BytesParser(policy=policy.default).parsebytes(b"Content-Type: " + media + b"\r\n\r\n" + body)
    assert b"".join(part.get_payload(decode=True) for part in parsed.iter_parts()) == _MARKER
    return body, media


def test_uninterpreted_multipart_is_not_marked_clean_by_raw_scanning():
    body, media = _multipart()
    response = _response(body, media)
    for step in (1, 13, 65536):
        out, shield = _pipe([response[i:i+step] for i in range(0, len(response), step)],
                            dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out == b"", step
        assert shield.metrics().get("dlp_unscannable", 0) == 1, step
    out, shield = _pipe([response], dlp_enabled=True, dlp_action="audit", **_QUIET)
    assert out == response and shield.metrics().get("dlp_unscannable", 0) == 1
    received, out, _ = _through([_REQUEST], backend_resp=response,
                                 dlp_enabled=True, dlp_action="block", **_QUIET)
    assert received.startswith(b"GET /public/report HTTP/1.1\r\n") and out == b""


def test_benign_text_json_xml_and_binary_keep_exact_bytes():
    examples = (
        (b'{"example":"hello\\q"}', b"text/plain"),
        (b'{"token":"gh\\\\u0070_' + b"a" * 36 + b'"}', b"application/json"),
        (b'{"text":"public sample"}', b"application/json"),
        (b'<?xml version="1.0"?><item>public sample</item>', b"application/xml"),
        ("東京の公開資料".encode(), b"text/plain; charset=utf-8"),
        (b"\x89PNG\r\n\x1a\npublic image bytes", b"image/png"),
    )
    for body, media in examples:
        response = _response(body, media)
        for step in (1, 65536):
            out, shield = _pipe([response[i:i+step] for i in range(0, len(response), step)],
                                dlp_enabled=True, dlp_action="block", **_QUIET)
            assert out == response, (media, step)
            assert shield.metrics().get("dlp_leak", 0) == 0
            assert shield.metrics().get("dlp_unscannable", 0) == 0
    response = _response(b"public sample", b"text/plain; charset=utf-8")
    received, out, _ = _through([_REQUEST], backend_resp=response,
                                 dlp_enabled=True, dlp_action="block", **_QUIET)
    assert received.startswith(b"GET /public/report HTTP/1.1\r\n") and out == response


def test_master_off_and_global_audit_keep_their_existing_response_semantics():
    multipart_body, multipart_media = _multipart()
    wide_body = '<?xml version="1.0" encoding="utf-16le"?><item>sample</item>'.encode("utf-16le")
    examples = (_response(multipart_body, multipart_media),
                _response(wide_body, b"application/xml"),
                _response(_escaped_then_bad()))
    for response in examples:
        out, shield = _pipe([response], enabled=False,
                            dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out == response and shield.metrics().get("dlp_unscannable", 0) == 0
        out, shield = _pipe([response], mode="audit",
                            dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out == response
        assert shield.metrics().get("dlp_leak", 0) + shield.metrics().get("dlp_unscannable", 0) == 1
