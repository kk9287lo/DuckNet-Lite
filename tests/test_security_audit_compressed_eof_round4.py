"""Audit must distinguish a complete HTTP entity from a complete coding stream."""

import gzip
import zlib

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_CFG = {"body_scan_enabled": True, "body_scan_max_bytes": 1024,
        "upload_scan_enabled": False, "graphql_enabled": False,
        "sec_headers_enabled": False, "cookie_harden_enabled": False,
        "cors_harden_enabled": False, "open_redirect_enabled": False,
        "dlp_enabled": False}


def _request(body, encoding, *, chunked=False):
    head = (b"POST /login HTTP/1.1\r\nHost: local.test\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Encoding: " + encoding + b"\r\n")
    if chunked:
        wire_body = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
        return head + b"Transfer-Encoding: chunked\r\n\r\n" + wire_body
    return head + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _transit(request, mode):
    backend = _Backend()
    try:
        with _shield(mode=mode, **_CFG) as shield, _guard(backend) as guard:
            response = _exchange(guard, [request])
            metrics, events = dict(guard.metrics), shield.events(40)
        return backend.saw(), response, metrics, events
    finally:
        backend.close()


def test_complete_http_body_with_truncated_coding_is_logged_in_audit():
    # Both decoders yield the entire safe plaintext before their checksums.
    # The HTTP length/chunk boundary is complete, but the coding stream is not.
    for encoding, body in ((b"deflate", zlib.compress(b"&q=safe")[:-2]),
                           (b"gzip", gzip.compress(b"&q=safe")[:-4])):
        for chunked in (False, True):
            request = _request(body, encoding, chunked=chunked)
            received, response, metrics, _ = _transit(request, "enforce")
            assert received == b"" and metrics["proxied"] == 0
            assert response.startswith(b"HTTP/1.1 415"), (encoding, response)
            received, response, metrics, events = _transit(request, "audit")
            assert received.partition(b"\r\n\r\n")[2] == request.partition(b"\r\n\r\n")[2]
            assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
            assert metrics["body_unscannable"] == 1
            assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
                       and e.get("encoding") == encoding.decode() for e in events), events


def test_complete_good_coding_and_a_read_prefix_are_not_mistaken_for_truncation():
    good = zlib.compress(b"&q=safe")
    # Level 0 adds wire overhead: the first 1024 received bytes are only a
    # prefix, but the complete coded entity is within the decoded scan cap.
    padded = zlib.compress(b"A" * 1018, level=0)
    assert len(padded) > 1024
    for body in (good, padded):
        for chunked in (False, True):
            request = _request(body, b"deflate", chunked=chunked)
            for mode in ("enforce", "audit"):
                received, response, metrics, events = _transit(request, mode)
                assert received.partition(b"\r\n\r\n")[2] == request.partition(b"\r\n\r\n")[2]
                assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
                assert not any(e.get("rule") == "body_unscannable" for e in events)


def test_decoded_over_limit_keeps_size_reason_and_exact_audit_wire():
    body = zlib.compress(b"A" * 1025)
    request = _request(body, b"deflate")
    received, response, metrics, _ = _transit(request, "enforce")
    assert received == b"" and metrics["proxied"] == 0
    assert response.startswith(b"HTTP/1.1 413"), response
    received, response, metrics, events = _transit(request, "audit")
    assert received.partition(b"\r\n\r\n")[2] == body
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert any(e.get("kind") == "audit" and e.get("rule") == "body_scan_limit"
               for e in events), events
