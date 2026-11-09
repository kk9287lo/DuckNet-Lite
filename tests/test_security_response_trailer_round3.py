"""Response trailers must not change cache or content handling after the head."""

from test_sweep_det_response import _pipe
from test_sweep_proxy_request import _through


_REQUEST = b"GET /public/item HTTP/1.1\r\nHost: app.example\r\n\r\n"
_QUIET = {"dlp_enabled": False, "sec_headers_enabled": False,
          "cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}
_CONTROL = ((b"Vary", b"Accept-Encoding"),
            (b"Content-Disposition", b"attachment; filename=public.txt"))


def _response(name, value):
    head = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Trailer: " + name + b"\r\n\r\n")
    return head + b"2\r\nok\r\n0\r\n" + name + b": " + value + b"\r\n\r\n"


def test_response_control_trailers_never_reach_the_real_client():
    for name, value in _CONTROL:
        response = _response(name, value)
        head = response.partition(b"\r\n\r\n")[0] + b"\r\n\r\n"
        for mode in ("audit", "enforce"):
            upstream, downstream, metrics = _through(
                [_REQUEST], backend_resp=response, mode=mode, **_QUIET)
            assert upstream.startswith(b"GET /public/item HTTP/1.1\r\n")
            assert downstream.startswith(head), (name, mode, downstream)
            assert name + b": " + value not in downstream, (name, mode, downstream)
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_complete_control_trailer_in_one_read_releases_only_the_head():
    for name, value in _CONTROL:
        response = _response(name, value)
        head = response.partition(b"\r\n\r\n")[0] + b"\r\n\r\n"
        for mode in ("audit", "enforce"):
            delivered, _ = _pipe([response], mode=mode, **_QUIET)
            assert delivered == head, (name, mode, delivered)


def test_ordinary_note_trailer_preserves_exact_wire_bytes():
    response = _response(b"X-Note", b"public")
    for mode in ("audit", "enforce"):
        upstream, downstream, metrics = _through(
            [_REQUEST], backend_resp=response, mode=mode, **_QUIET)
        assert upstream.startswith(b"GET /public/item HTTP/1.1\r\n")
        assert downstream == response, (mode, downstream)
        assert metrics.get("backend_invalid_response", 0) == 0, metrics
