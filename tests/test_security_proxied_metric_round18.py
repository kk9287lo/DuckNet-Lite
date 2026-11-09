"""Only a request head written through the backend gate counts as proxied."""

import os
from unittest.mock import patch

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_GET = b"GET /protected HTTP/1.1\r\nHost: app.example\r\n\r\n"
_POST = (b"POST /protected HTTP/1.1\r\nHost: app.example\r\n"
         b"Content-Length: 4\r\n\r\nsafe")
_CFG = dict(origin_cloaking_enabled=True, body_scan_enabled=False,
            upload_scan_enabled=False, persist_bans=False)


def _wire(request, key):
    backend = _Backend()
    try:
        with patch.dict(os.environ, {"DUCKNET_ORIGIN_KEY": key}), _shield(**_CFG):
            with _guard(backend) as guard:
                client = _exchange(guard, [request])
                metrics = dict(guard.metrics)
        return backend.saw(), client, metrics
    finally:
        backend.close()


def test_unavailable_origin_proof_never_reports_backend_proxy_success():
    for request in (_GET, _POST):
        upstream, client, metrics = _wire(request, "")
        assert upstream == b"", upstream
        assert not client.startswith(b"HTTP/1.1 200"), client
        assert metrics["dropped"] >= 1
        assert metrics["proxied"] == 0, metrics


def test_valid_origin_proof_counts_one_written_request():
    for request in (_GET, _POST):
        upstream, client, metrics = _wire(request, "synthetic-round18-key")
        assert upstream.startswith(request.partition(b"\r\n")[0] + b"\r\n"), upstream
        assert b"\r\nX-Edge-Token: " in upstream
        if request.startswith(b"POST "):
            assert upstream.endswith(b"\r\n\r\nsafe"), upstream
        else:
            assert upstream.endswith(b"\r\n\r\n"), upstream
        assert client.startswith(b"HTTP/1.1 200"), client
        assert metrics["proxied"] == 1 and metrics["dropped"] == 0, metrics
