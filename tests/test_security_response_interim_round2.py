"""Bounded informational-response handling on the response stream."""

from test_sweep_det_response import _pipe
from test_sweep_proxy_request import _through


_INTERIM = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
_FINAL = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
_QUIET = {"dlp_enabled": False, "sec_headers_enabled": False,
          "cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def test_excessive_interim_heads_stop_before_the_final_response():
    # Even a cooperative backend can emit an unlimited sequence of 1xx heads.
    # A fixed bound avoids quadratic copying within one large socket read.
    for mode in ("audit", "enforce"):
        for chunks in ([_INTERIM * 33 + _FINAL], [_INTERIM] * 33 + [_FINAL]):
            out, _ = _pipe(chunks, mode=mode, **_QUIET)
            assert out == _INTERIM * 32, (mode, len(chunks), len(out), out[-80:])
            assert _FINAL not in out


def test_two_valid_interim_heads_preserve_the_exact_response_bytes():
    response = _INTERIM * 2 + _FINAL
    request = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
    for mode in ("audit", "enforce"):
        upstream, downstream, metrics = _through(
            [request], backend_resp=response, mode=mode, **_QUIET)
        assert upstream.startswith(b"GET /public HTTP/1.1\r\n")
        assert downstream == response, (mode, downstream)
        assert metrics.get("backend_invalid_response", 0) == 0, metrics


def test_excessive_interim_heads_close_the_real_client_stream():
    request = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
    upstream, downstream, metrics = _through(
        [request], backend_resp=_INTERIM * 33 + _FINAL, **_QUIET)
    assert upstream.startswith(b"GET /public HTTP/1.1\r\n")
    assert downstream == _INTERIM * 32, len(downstream)
    assert metrics.get("backend_invalid_response") == 1, metrics
