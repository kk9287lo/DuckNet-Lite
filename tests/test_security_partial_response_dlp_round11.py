"""A range client can assemble a secret that no one 206 response contains."""

import zlib

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_TOKEN = b"ghp_" + b"a" * 36  # inert marker recognized by the existing DLP rule
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(body: bytes, first: int, total: int = len(_TOKEN)) -> bytes:
    last = first + len(body) - 1
    return (b"HTTP/1.1 206 Partial Content\r\n"
            + f"Content-Range: bytes {first}-{last}/{total}\r\n".encode()
            + b"Accept-Ranges: bytes\r\nContent-Type: text/plain\r\n"
            + b"Content-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)


def _transit(response: bytes, request: bytes, *, dlp_enabled=True,
             dlp_action="block", mode="enforce"):
    backend = _Backend(response)
    try:
        with _shield(dlp_enabled=dlp_enabled, dlp_action=dlp_action, mode=mode,
                     **_QUIET) as shield, _guard(backend) as guard:
            client = _exchange(guard, [request])
            metrics, events = shield.metrics(), shield.events(100)
        return backend.saw(), client, metrics, events
    finally:
        backend.close()


def test_two_real_range_responses_cannot_reassemble_a_secret_under_block_dlp():
    parts = (_TOKEN[:2], _TOKEN[2:])
    requests = (
        b"GET /download HTTP/1.1\r\nHost: local.test\r\nRange: bytes=0-1\r\n\r\n",
        b"GET /download HTTP/1.1\r\nHost: local.test\r\nRange: bytes=2-39\r\n\r\n",
    )
    assert b"".join(parts) == _TOKEN
    for first, part, request in zip((0, 2), parts, requests):
        response = _response(part, first)
        assert _TOKEN not in response
        backend, client, metrics, events = _transit(response, request)
        assert backend.startswith(request[:-2])
        assert client == b"", (first, client)
        assert metrics.get("dlp_unscannable") == 1
        assert any(event.get("encoding") == "partial-content" for event in events)


def test_range_audit_preserves_each_wire_and_records_incomplete_view():
    request = b"GET /download HTTP/1.1\r\nHost: local.test\r\nRange: bytes=0-1\r\n\r\n"
    response = _response(_TOKEN[:2], 0)
    backend, client, metrics, events = _transit(response, request,
                                                dlp_action="audit")
    assert backend.startswith(request[:-2])
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(event.get("encoding") == "partial-content" for event in events)
    _, client, metrics, events = _transit(response, request,
                                          dlp_action="block", mode="audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(event.get("encoding") == "partial-content" for event in events)


def test_complete_200_and_dlp_off_range_keep_exact_wire():
    request = b"GET /download HTTP/1.1\r\nHost: local.test\r\n\r\n"
    response = (b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
                b"Connection: close\r\n\r\npublic")
    _, client, metrics, _ = _transit(response, request)
    assert client == response and not metrics.get("dlp_unscannable")

    range_request = b"GET /download HTTP/1.1\r\nHost: local.test\r\nRange: bytes=0-1\r\n\r\n"
    range_response = _response(_TOKEN[:2], 0)
    _, client, metrics, _ = _transit(range_response, range_request,
                                     dlp_enabled=False)
    assert client == range_response and not metrics.get("dlp_unscannable")


def test_bodyless_head_with_range_metadata_has_no_content_to_scan():
    request = b"HEAD /download HTTP/1.1\r\nHost: local.test\r\nRange: bytes=0-1\r\n\r\n"
    response = (b"HTTP/1.1 206 Partial Content\r\n"
                b"Content-Range: bytes 0-1/40\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\n")
    _, client, metrics, _ = _transit(response, request)
    assert client == response and not metrics.get("dlp_unscannable")


def test_226_instance_manipulation_cannot_hide_compressed_secret():
    # RFC 3229's IM is an instance manipulation, separate from HTTP
    # Content-Encoding. A delta-capable client reconstructs this view.
    request = (b"GET /download HTTP/1.1\r\nHost: local.test\r\n"
               b"A-IM: deflate\r\n\r\n")
    body = zlib.compress(_TOKEN)
    response = (b"HTTP/1.1 226 IM Used\r\nIM: deflate\r\nETag: \"v2\"\r\n"
                b"Content-Type: text/plain\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    assert _TOKEN not in response and zlib.decompress(body) == _TOKEN
    backend, client, metrics, events = _transit(response, request)
    assert backend.startswith(request[:-2])
    assert client == b"" and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "instance-manipulation" for e in events)

    backend, client, metrics, events = _transit(response, request,
                                                dlp_action="audit")
    assert backend.startswith(request[:-2])
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "instance-manipulation" for e in events)

    _, client, metrics, _ = _transit(response, request, dlp_enabled=False)
    assert client == response and not metrics.get("dlp_unscannable")


def test_bodyless_head_with_im_metadata_has_no_content_to_scan():
    request = (b"HEAD /download HTTP/1.1\r\nHost: local.test\r\n"
               b"A-IM: deflate\r\n\r\n")
    response = (b"HTTP/1.1 226 IM Used\r\nIM: deflate\r\nETag: \"v2\"\r\n"
                b"Content-Length: 40\r\nConnection: close\r\n\r\n")
    _, client, metrics, _ = _transit(response, request)
    assert client == response and not metrics.get("dlp_unscannable")
    get_request = b"GET /download HTTP/1.1\r\nHost: local.test\r\nA-IM: deflate\r\n\r\n"
    empty = (b"HTTP/1.1 226 IM Used\r\nIM: deflate\r\nETag: \"v2\"\r\n"
             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    _, client, metrics, _ = _transit(empty, get_request)
    assert client == empty and not metrics.get("dlp_unscannable")
