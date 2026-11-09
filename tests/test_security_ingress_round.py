"""Connection options cannot change the meaning of protected request fields."""

import os
from unittest.mock import patch

from dataplane.engine.services.proxy import _framing_ambiguous
from test_sweep_proxy_request import _through


_BASE = b"GET /public HTTP/1.1\r\nHost: app.example\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _request(fields):
    return _BASE + b"\r\n".join(fields) + b"\r\n\r\n"


def test_protected_connection_options_are_rejected_before_backend():
    request = _request([b"Connection: x-forwarded-for, close",
                        b"X-Forwarded-For: 198.51.100.73"])
    for mode in ("enforce", "audit"):
        received, response, metrics = _through(
            [request], mode=mode, force_conn_close=False, **_QUIET)
        assert received == b"", (mode, received)
        assert response.startswith(b"HTTP/1.1 400"), (mode, response)
        assert metrics["proxied"] == 0 and metrics["dropped"] == 1, metrics
    names = (b"X-Forwarded-For", b"X-Real-IP", b"Host", b"Content-Length",
             b"Transfer-Encoding", b"Content-Encoding", b"Content-Type",
             b"Authorization", b"Cookie", b"Forwarded", b"X-Forwarded-Proto",
             b"X-Edge-Token", b"User-Agent", b"Range")
    for name in names:
        assert _framing_ambiguous(_request([b"Connection: " + name])), name
        assert _framing_ambiguous(_request([
            b"Connection: close", b"Connection: " + name.lower()])), name


def test_public_connection_option_and_normal_close_still_reach_backend():
    for fields in ((b"Connection: X-Public", b"X-Public: sample"),
                   (b"Connection: keep-alive, X-Public", b"X-Public: sample"),
                   (b"Connection: close",)):
        request = _request(list(fields))
        assert not _framing_ambiguous(request), fields
        for mode in ("enforce", "audit"):
            received, response, metrics = _through(
                [request], mode=mode, force_conn_close=False, **_QUIET)
            for field in fields:
                assert field in received, (field, received)
            assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    received, response, _ = _through(
        [_request([b"Connection: keep-alive"])], **_QUIET)
    assert b"Connection: close\r\n" in received
    assert response.startswith(b"HTTP/1.1 200")


def test_configured_origin_proof_name_uses_the_same_request_boundary():
    configured = {"origin_cloaking_enabled": True,
                  "origin_header": "X-Private-Edge", "force_conn_close": False}
    request = _request([b"Connection: X-Private-Edge"])
    with patch.dict(os.environ, {"DUCKNET_ORIGIN_KEY": "synthetic-local-key"}):
        for mode in ("enforce", "audit"):
            received, response, metrics = _through(
                [request], mode=mode, **configured, **_QUIET)
            assert received == b"" and metrics["proxied"] == 0, (mode, received)
            assert response.startswith(b"HTTP/1.1 400"), (mode, response)
            received, response, metrics = _through(
                [_request([])], mode=mode, **configured, **_QUIET)
            assert b"X-Private-Edge: " in received, (mode, received)
            assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
