"""Inert loopback checks for Falco-aligned protocol and origin metadata boundaries."""
import asyncio

from test_sweep_proxy_request import _through
from test_sweep_det_response import _pipe
from test_seams_transport import _direct


_QUIET = {"dlp_enabled": False, "sec_headers_enabled": False,
          "cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}
_REQUEST = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npublic"
_ORIGIN_HEADERS = (b"X-Origin-IP", b"X-Backend-Server", b"X-Upstream",
                   b"X-Original-IP", b"X-Remote-IP", b"X-Remote-Addr",
                   b"X-Forwarded-Server", b"X-Rewrite-URL", b"X-Original-URL")


def test_duplicate_user_agent_and_range_are_protocol_errors_in_both_modes():
    for mode in ("audit", "enforce"):
        for name, first, second in ((b"User-Agent", b"public-reader", b"second-reader"),
                                    (b"Range", b"bytes=0-1", b"bytes=2-3")):
            for left, right in ((first, second), (second, first), (first, first)):
                request = (b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n"
                           + name + b": " + left + b"\r\n" + name.lower()
                           + b": " + right + b"\r\n\r\n")
                got, response, metrics = _through([request], mode=mode, **_QUIET)
                assert got == b"", (mode, name, got)
                assert response.startswith(b"HTTP/1.1 400 "), (mode, name, response)
                assert metrics["dropped"] == 1, metrics


def test_singleton_protocol_errors_do_not_depend_on_shield_switch():
    request = (b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n"
               b"Range: bytes=0-1\r\nRange: bytes=2-3\r\n\r\n")
    got, response, _ = _through([request], enabled=False, **_QUIET)
    assert got == b"" and response.startswith(b"HTTP/1.1 400 "), (got, response)


def test_single_user_agent_and_range_keep_their_values_and_response_bytes():
    request = (b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n"
               b"User-Agent: public-reader\r\nRange: bytes=0-1\r\n\r\n")
    for mode in ("audit", "enforce"):
        got, response, _ = _through([request], backend_resp=_OK, mode=mode, **_QUIET)
        assert got.startswith(b"GET /public/report HTTP/1.1\r\n"), got
        assert got.count(b"User-Agent: public-reader\r\n") == 1, got
        assert got.count(b"Range: bytes=0-1\r\n") == 1, got
        assert got.endswith(b"\r\n\r\n") and response == _OK, (got, response)


def _bad_responses():
    return (
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\npublic",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\npublic",
        b"HTTP/1.1 200 OK\r\nContent-Length: +6\r\n\r\npublic",
        b"HTTP/1.1 200 OK\r\nX-Sample: harmless\nX-Other: public\r\nContent-Length: 6\r\n\r\npublic",
        b"HTTP/1.1 200 OK\r\n X-Sample: public\r\nContent-Length: 6\r\n\r\npublic",
        b"HTTP/1.1 099 Invalid\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 600 Invalid\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    )


def test_invalid_origin_framing_is_not_an_audit_or_optional_feature_bypass():
    for mode in ("audit", "enforce"):
        for quiet in (False, True):
            for response in _bad_responses():
                settings = dict(_QUIET) if quiet else {"dlp_enabled": False}
                got, out, metrics = _through([_REQUEST], backend_resp=response,
                                               mode=mode, **settings)
                assert got.startswith(b"GET /public/report HTTP/1.1\r\n"), got
                assert out == b"", (mode, quiet, response, out)
                assert metrics.get("backend_invalid_response") == 1, metrics


def test_invalid_origin_head_is_withheld_across_read_boundaries():
    for response in _bad_responses():
        for step in (1, 17, 65536):
            out, _ = _pipe([response[i:i + step] for i in range(0, len(response), step)], **_QUIET)
            assert out == b"", (step, response, out)
    for response in (b"HTTP/1.1 200 OK\r\nX-Public: unfinished",
                     b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 65536 + b"\r\n\r\n"):
        out, _ = _pipe([response], **_QUIET)
        assert out == b"", out[:100]


def test_origin_connection_cannot_nominate_message_semantics_or_invalid_tokens():
    examples = (
        b"Connection: Content-Length\r\nContent-Length: 6\r\n\r\npublic",
        b"Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n6\r\npublic\r\n0\r\n\r\n",
        b"Connection: Content-Encoding\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\npublic",
        b"Connection: Content-Type\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\npublic",
        b"Connection: close, public invalid\r\nContent-Length: 6\r\n\r\npublic",
        b"Connection: close,\r\nContent-Length: 6\r\n\r\npublic",
    )
    for mode in ("audit", "enforce"):
        for fields in examples:
            got, out, metrics = _through([_REQUEST], backend_resp=b"HTTP/1.1 200 OK\r\n" + fields,
                                           mode=mode, **_QUIET)
            assert got.startswith(b"GET /public/report HTTP/1.1\r\n") and out == b"", out
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_origin_metadata_in_response_trailers_never_releases_its_value():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    body = b"6\r\npublic\r\n0\r\n"
    for mode in ("audit", "enforce"):
        for dlp in (False, True):
            cfg = dict(_QUIET, mode=mode, dlp_enabled=dlp, dlp_action="audit")
            for name in _ORIGIN_HEADERS:
                response = head + body + name + b": private-origin.example\r\n\r\n"
                got, out, metrics = _through([_REQUEST], backend_resp=response, **cfg)
                assert got.startswith(b"GET /public/report HTTP/1.1\r\n"), got
                assert b"private" not in out and metrics.get("backend_invalid_response") == 1, (out, metrics)
                for step in (1, 17, 65536):
                    out, _ = _pipe([response[i:i + step] for i in range(0, len(response), step)], **cfg)
                    assert b"private" not in out, (mode, dlp, name, step, out)
    public = head + body + b"X-Public: public-trailer\r\n\r\n"
    for step in (1, 17, 65536):
        out, _ = _pipe([public[i:i + step] for i in range(0, len(public), step)], **_QUIET)
        assert out == public, (step, out)


def test_valid_opaque_and_bodyless_responses_keep_exact_wire_bytes_without_dlp():
    examples = (
        (b"GET", _OK),
        (b"GET", b"HTTP/1.1 103 Early Hints\r\nLink: </public.css>; rel=preload\r\n\r\n" + _OK),
        (b"HEAD", b"HTTP/1.1 200 OK\r\nContent-Type: application/zip; charset=utf-16le\r\nContent-Encoding: gzip\r\nContent-Length: 99\r\n\r\n"),
        (b"GET", b"HTTP/1.1 304 Not Modified\r\nContent-Type: application/zip; charset=utf-16le\r\nContent-Length: 99\r\n\r\n"),
        (b"GET", b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"),
        (b"GET", b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream; charset=unknown-public\r\nContent-Encoding: br\r\nContent-Length: 6\r\n\r\npublic"),
        (b"GET", b"HTTP/1.1 200 OK\r\nSet-Cookie: public=a\r\nSet-Cookie: other=b\r\nContent-Length: 6\r\n\r\npublic"),
    )
    for mode in ("audit", "enforce"):
        for method, response in examples:
            request = method + b" /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
            got, out, _ = _through([request], backend_resp=response, mode=mode, **_QUIET)
            assert got.startswith(method + b" /public/report HTTP/1.1\r\n") and out == response, (method, out)


def test_origin_internal_metadata_is_removed_from_final_and_interim_heads():
    leaked = b"".join(name + b": private-origin.example\r\n" for name in _ORIGIN_HEADERS)
    final = (b"HTTP/1.1 200 OK\r\n" + leaked
             + b"X-Public: public-value\r\nSet-Cookie: public=a\r\nContent-Length: 6\r\n\r\npublic")
    clean_final = (b"HTTP/1.1 200 OK\r\nX-Public: public-value\r\n"
                   b"Set-Cookie: public=a\r\nContent-Length: 6\r\n\r\npublic")
    interim = b"HTTP/1.1 103 Early Hints\r\n" + leaked + b"Link: </public.css>; rel=preload\r\n\r\n"
    clean_interim = b"HTTP/1.1 103 Early Hints\r\nLink: </public.css>; rel=preload\r\n\r\n"
    for mode in ("audit", "enforce"):
        for response, expected in ((final, clean_final), (interim + final, clean_interim + clean_final)):
            got, out, _ = _through([_REQUEST], backend_resp=response, mode=mode, **_QUIET)
            assert got.startswith(b"GET /public/report HTTP/1.1\r\n") and out == expected, out
            for step in (1, 17, 65536):
                out, _ = _pipe([response[i:i + step] for i in range(0, len(response), step)], mode=mode, **_QUIET)
                assert out == expected, (step, out)


def test_upgraded_response_strips_origin_metadata_without_rewriting_handshake():
    response = (b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                b"Upgrade: websocket\r\nX-Origin-IP: private-origin.example\r\n"
                b"Sec-WebSocket-Accept: public-placeholder\r\n\r\n")
    expected = response.replace(b"X-Origin-IP: private-origin.example\r\n", b"")
    got, out, _ = _through([_REQUEST], backend_resp=response, **_QUIET)
    assert got.startswith(b"GET /public/report HTTP/1.1\r\n") and out == expected, out


def test_mandatory_protocol_boundary_discards_nonentity_head_and_304_suffixes():
    async def run():
        for method, head in (("HEAD", b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"),
                             ("GET", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 6\r\n\r\n")):
            out, count, timed_out, closed, _ = await _direct(
                head + b"UNRELATED", eof=True, method=method, enabled=False,
                dlp_enabled=False, sec_headers_enabled=False)
            assert out == head and count == len(head) and not timed_out and closed, (out, count)
    asyncio.run(run())


def test_fragmented_public_trailer_names_have_linear_search_work():
    from dataplane.engine.services.proxy import _ChunkedEnd

    class CountedLine(bytearray):
        def __init__(self):
            super().__init__()
            self.colon_work = 0

        def find(self, needle, start=0, end=None):
            end = len(self) if end is None else end
            if needle == b":":
                self.colon_work += max(0, min(len(self), end) - start)
            return super().find(needle, start, end)

    for width in (1024, 4096):
        tracker = _ChunkedEnd(response_trailers=True)
        assert tracker.feed(b"0\r\n") == 3 and not tracker.bad
        counted = CountedLine()
        tracker._line = counted
        name = b"X-Public-" + b"a" * width
        for value in name:
            assert tracker.feed(bytes((value,))) == 1 and not tracker.bad
        assert counted.colon_work <= 2 * len(name), (len(name), counted.colon_work)
        assert tracker.feed(b": public\r\n\r\n") > 0 and tracker.done and not tracker.bad


def test_real_http_gateway_never_downgrades_non_http_origin_to_raw_passthrough():
    interim = b"HTTP/1.1 103 Early Hints\r\nLink: </public.css>; rel=preload\r\n\r\n"
    prefixes = ((b"\r\n" + _OK, b""),
                (b"X-Public: public-value\r\n\r\npublic", b""),
                (b"public non-http stream", b""), (b"pub", b""),
                (interim + b"pub", interim))
    post = (b"POST /public/report HTTP/1.1\r\nHost: app.example\r\n"
            b"Content-Length: 4\r\n\r\n")
    requests = ([_REQUEST], [post + b"data"], [post, b"data"])
    for mode in ("audit", "enforce"):
        for response, expected in prefixes:
            for parts in requests:
                got, out, metrics = _through(parts, backend_resp=response, mode=mode,
                                               body_scan_enabled=False, upload_scan_enabled=False,
                                               **_QUIET)
                assert got.startswith(parts[0].split(b"\r\n", 1)[0]), got
                assert out == expected and metrics.get("backend_invalid_response") == 1, (out, metrics)


def test_internal_raw_pipe_helper_retains_explicit_legacy_stream_contract():
    for value in (b"public non-http stream\x00sample\r\n", b"pub"):
        for step in (1, 17, 65536):
            out, _ = _pipe([value[i:i + step] for i in range(0, len(value), step)], **_QUIET)
            assert out == value, (step, out)
