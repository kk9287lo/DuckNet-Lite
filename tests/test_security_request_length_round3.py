"""Request length parsing must agree with bounded backend framing."""

from dataplane.engine.services.proxy import _framing_ambiguous
from test_sweep_proxy_request import _through


_CFG = {"body_scan_enabled": False, "upload_scan_enabled": False,
        "graphql_enabled": False, "sec_headers_enabled": False,
        "cookie_harden_enabled": False, "cors_harden_enabled": False,
        "open_redirect_enabled": False, "dlp_enabled": False}


def _request(length: bytes, body: bytes = b"") -> bytes:
    return (b"POST /public HTTP/1.1\r\nHost: local.test\r\n"
            b"Content-Length: " + length + b"\r\n\r\n" + body)


def _assert_rejected_length(length: bytes):
    second = b"GET /hidden HTTP/1.1\r\nHost: local.test\r\n\r\n"
    request = _request(length, second)
    assert len(request.partition(b"\r\n\r\n")[0]) < 16384
    for mode in ("enforce", "audit"):
        upstream, downstream, metrics = _through(
            [request], guard_kw={"head_timeout": 0.2}, mode=mode, **_CFG)
        assert upstream == b"", (len(length), mode, upstream[-100:])
        assert downstream.startswith(b"HTTP/1.1 400"), (len(length), mode, downstream)
        assert metrics["proxied"] == 0, (len(length), mode, metrics)
    assert _framing_ambiguous(request)


def test_signed_64bit_content_length_overflow_never_reaches_backend():
    _assert_rejected_length(b"9223372036854775808")


def test_twenty_digit_content_length_never_reaches_backend():
    _assert_rejected_length(b"99999999999999999999")


def test_python_decimal_int_limit_never_opens_backend():
    _assert_rejected_length(b"9" * 4301)


def test_padded_small_length_preserves_the_entire_benign_request():
    request = _request(b"0002", b"ok")
    assert not _framing_ambiguous(request)
    assert not _framing_ambiguous(_request(b"9223372036854775807"))
    for mode in ("enforce", "audit"):
        upstream, downstream, metrics = _through([request], mode=mode, **_CFG)
        assert upstream.endswith(b"\r\n\r\nok"), (mode, upstream)
        assert b"Content-Length: 0002\r\n" in upstream
        assert downstream.startswith(b"HTTP/1.1 200"), (mode, downstream)
        assert metrics["proxied"] == 1, (mode, metrics)
