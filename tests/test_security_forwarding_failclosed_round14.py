"""Configured request-forwarding defenses must not silently disappear."""

import os
from unittest.mock import patch

import dataplane.engine.services.proxy as proxy
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_GET = b"GET /public HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _wire(key, *, broken_token=False):
    backend = _Backend()
    try:
        with patch.dict(os.environ, {"DUCKNET_ORIGIN_KEY": key}), \
                _shield() as sh:
            assert sh.set_config(origin_cloaking_enabled=True)["ok"]
            with _guard(backend) as guard:
                if broken_token:
                    with patch("dataplane.engine.core.origin.origin_token",
                               side_effect=RuntimeError("fixture token failure")):
                        response = _exchange(guard, [_GET])
                else:
                    response = _exchange(guard, [_GET])
                metrics = dict(guard.metrics)
        return response, backend.saw(), metrics
    finally:
        backend.close()


def test_missing_enabled_origin_key_cannot_reach_backend_without_proof():
    response, upstream, metrics = _wire("")
    assert upstream == b"", (response, upstream)
    assert not response.startswith(b"HTTP/1.1 200"), response
    assert metrics.get("dropped", 0) >= 1


def test_token_generation_failure_cannot_reach_backend_without_proof():
    response, upstream, metrics = _wire("synthetic-r14-key", broken_token=True)
    assert upstream == b"", (response, upstream)
    assert not response.startswith(b"HTTP/1.1 200"), response
    assert metrics.get("dropped", 0) >= 1


def test_valid_enabled_origin_key_still_adds_proof_and_forwards():
    response, upstream, metrics = _wire("synthetic-r14-key")
    assert response.startswith(b"HTTP/1.1 200"), response
    assert upstream.startswith(b"GET /public HTTP/1.1\r\n")
    assert b"\r\nX-Edge-Token: " in upstream
    assert metrics["proxied"] == 1


def test_failed_cache_header_strip_cannot_forward_untrusted_host():
    backend = _Backend()
    original = proxy._strip_request_headers

    def fail_cache_only(buf, names):
        if any(name in (b"x-forwarded-host", "x-forwarded-host") for name in names):
            raise OSError("fixture strip failure")
        return original(buf, names)

    request = (_GET[:-2] + b"X-Forwarded-Host: attacker.test\r\n\r\n")
    try:
        with _shield(), _guard(backend) as guard, \
                patch.object(proxy, "_strip_request_headers", side_effect=fail_cache_only):
            response = _exchange(guard, [request])
            metrics = dict(guard.metrics)
        assert backend.saw() == b"", (response, backend.saw())
        assert metrics.get("dropped", 0) >= 1
    finally:
        backend.close()
