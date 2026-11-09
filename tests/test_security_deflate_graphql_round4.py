"""GraphQL inspection and backend deflate interpretation must cover one entity."""

import zlib

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_SAFE_FORM = b"query=%7Bme%7Bid%7D%7D"
_LATE_FORM = b"&query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
_SAFE_JSON = b'{"query":"{me{id}}"}'
_CFG = {"graphql_enabled": True, "graphql_block_introspection": True,
        "body_scan_enabled": False, "upload_scan_enabled": False,
        "body_decode_enabled": True, "sec_headers_enabled": False,
        "cookie_harden_enabled": False, "cors_harden_enabled": False,
        "open_redirect_enabled": False, "dlp_enabled": False}


def _request(body, *, media=b"application/x-www-form-urlencoded", chunked=False,
             encoding=b"deflate"):
    fields = (b"POST /graphql HTTP/1.1\r\nHost: local.test\r\nContent-Type: " + media
              + b"\r\nContent-Encoding: " + encoding + b"\r\n")
    if chunked:
        wire_body = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
        return fields + b"Transfer-Encoding: chunked\r\n\r\n" + wire_body, wire_body
    return (fields + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body,
            body)


def _transit(request, *, mode, **overrides):
    backend = _Backend()
    try:
        with _shield(mode=mode, **{**_CFG, **overrides}) as shield, _guard(backend) as guard:
            response = _exchange(guard, [request])
            metrics, events = dict(guard.metrics), shield.events(40)
        return backend.saw(), response, metrics, events
    finally:
        backend.close()


def _raw_deflate(data):
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def test_later_deflate_member_cannot_escape_graphql_only_enforcement():
    rows = ((zlib.compress(_SAFE_FORM) + zlib.compress(_LATE_FORM),
             b"application/x-www-form-urlencoded", False),
            (zlib.compress(_SAFE_FORM) + zlib.compress(_LATE_FORM),
             b"application/x-www-form-urlencoded", True),
            (zlib.compress(_SAFE_JSON) + zlib.compress(b"public-tail"),
             b"application/json", False))
    for encoded, media, chunked in rows:
        request, wire_body = _request(encoded, media=media, chunked=chunked)
        for mode in ("enforce", "audit"):
            upstream, response, metrics, events = _transit(request, mode=mode)
            if mode == "enforce":
                assert upstream == b"" and metrics["proxied"] == 0, (media, chunked, upstream)
                assert response.startswith(b"HTTP/1.1 415"), (media, chunked, response)
            else:
                assert upstream.partition(b"\r\n\r\n")[2] == wire_body
                assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
                assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
                           for e in events), (media, chunked, events)


def test_truncated_deflate_stream_is_not_treated_as_a_complete_query():
    encoded = zlib.compress(_SAFE_FORM)[:-4]  # plaintext appears before the missing checksum
    request, wire_body = _request(encoded)
    for mode in ("enforce", "audit"):
        upstream, response, metrics, events = _transit(request, mode=mode)
        if mode == "enforce":
            assert upstream == b"" and metrics["proxied"] == 0
            assert response.startswith(b"HTTP/1.1 415"), response
        else:
            assert upstream.partition(b"\r\n\r\n")[2] == wire_body
            assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
            assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
                       for e in events), events


def test_single_wrapped_or_raw_deflate_graphql_keeps_exact_backend_bytes():
    for encoded in (zlib.compress(_SAFE_FORM), _raw_deflate(_SAFE_FORM)):
        for chunked in (False, True):
            request, wire_body = _request(encoded, chunked=chunked)
            for mode in ("enforce", "audit"):
                upstream, response, metrics, _ = _transit(request, mode=mode)
                assert upstream.partition(b"\r\n\r\n")[2] == wire_body
                assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1


def test_gzip_multimember_graphql_remains_a_valid_single_query():
    import gzip
    wire = gzip.compress(_SAFE_FORM[:10]) + gzip.compress(_SAFE_FORM[10:])
    request, wire_body = _request(wire, chunked=True, encoding=b"gzip")
    for mode in ("enforce", "audit"):
        upstream, response, metrics, _ = _transit(request, mode=mode)
        assert upstream.partition(b"\r\n\r\n")[2] == wire_body
        assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1


def test_decoded_graphql_limit_still_reports_413_for_large_deflate():
    encoded = zlib.compress(b"query=" + b"A" * 1300)
    request, wire_body = _request(encoded)
    upstream, response, metrics, _ = _transit(
        request, mode="enforce", graphql_max_bytes=1024, body_scan_max_bytes=1024)
    assert upstream == b"" and metrics["proxied"] == 0
    assert response.startswith(b"HTTP/1.1 413"), response
    upstream, response, metrics, events = _transit(
        request, mode="audit", graphql_max_bytes=1024, body_scan_max_bytes=1024)
    assert upstream.partition(b"\r\n\r\n")[2] == wire_body
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert any(e.get("kind") == "audit" and e.get("rule") == "graphql_too_large"
               for e in events), events


def test_uncompressed_two_query_view_is_rejected_by_graphql_guard():
    body = _SAFE_FORM + _LATE_FORM
    request = (b"POST /graphql HTTP/1.1\r\nHost: local.test\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
    upstream, _, metrics, _ = _transit(request, mode="enforce")
    assert upstream == b"" and metrics["proxied"] == 0
