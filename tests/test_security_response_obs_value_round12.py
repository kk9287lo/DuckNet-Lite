"""Response header whitespace must have one meaning at the edge and client."""

from io import BytesIO
from http.client import parse_headers

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_REQUEST = b"GET /public/data HTTP/1.1\r\nHost: app.example\r\n\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(content_type, body=b"var token='gh'+'p_" + b"a" * 36 + b"';"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + content_type +
            b"\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\nConnection: close\r\n\r\n" + body)


def _wire(response, *, enabled=True):
    backend = _Backend(response)
    try:
        with _shield(dlp_enabled=enabled, dlp_action="block", **_QUIET) as shield, \
                _guard(backend) as edge:
            client = _exchange(edge, [_REQUEST])
            metrics = shield.metrics()
        return backend.saw(), client, metrics
    finally:
        backend.close()


def test_nel_and_nbsp_cannot_hide_script_media_from_response_boundary():
    for whitespace in (b"\x85", b"\xa0"):
        value = whitespace + b"text/javascript"
        # A real Python HTTP client interprets both as leading whitespace.
        headers = parse_headers(BytesIO(b"Content-Type: " + value + b"\r\n\r\n"))
        assert headers.get_content_type() == "text/javascript"
        response = _response(value)
        upstream, client, _ = _wire(response)
        assert upstream.startswith(_REQUEST[:-2])
        assert client == b"", (whitespace, client)


def test_nel_and_nbsp_cannot_hide_wide_charset_parameter():
    for whitespace in (b"\x85", b"\xa0"):
        value = b"text/plain; charset" + whitespace + b"=utf-16le"
        headers = parse_headers(BytesIO(b"Content-Type: " + value + b"\r\n\r\n"))
        assert headers.get_content_charset() == "utf-16le"
        # The body is harmless; rejection here proves the syntax boundary,
        # independently of whether a later DLP scanner sees secret bytes.
        response = _response(value, b"safe")
        upstream, client, _ = _wire(response, enabled=False)
        assert upstream.startswith(_REQUEST[:-2])
        assert client == b"", (whitespace, client)


def test_ordinary_response_and_unambiguous_latin1_obs_text_still_forward():
    for extra in (b"", b"X-Note: caf\xe9\r\n"):
        body = b"public report"
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    + extra + b"Content-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + body)
        upstream, client, metrics = _wire(response)
        assert upstream.startswith(_REQUEST[:-2]) and client == response
        assert metrics.get("dlp_unscannable", 0) == 0
