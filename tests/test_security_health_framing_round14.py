"""A health response must not bypass the gateway's HTTP syntax boundary."""

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_GOOD = b"GET /healthz HTTP/1.1\r\nHost: local.test\r\n\r\n"
_CL_TE = (b"GET /healthz HTTP/1.1\r\nHost: local.test\r\n"
          b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n")
_DUP_HOST = (b"GET /healthz HTTP/1.1\r\nHost: local.test\r\n"
             b"Host: different.test\r\n\r\n")


def _wire(request):
    backend = _Backend()
    try:
        with _shield(), _guard(backend, health_path="/healthz") as guard:
            response = _exchange(guard, [request])
            metrics = dict(guard.metrics)
        return response, backend.saw(), metrics
    finally:
        backend.close()


def test_health_path_rejects_cl_te_before_advertising_ready():
    response, upstream, metrics = _wire(_CL_TE)
    assert response.startswith(b"HTTP/1.1 400 Bad Request"), response
    assert upstream == b""
    assert metrics.get("health", 0) == 0 and metrics["dropped"] >= 1


def test_health_path_rejects_ambiguous_host_before_advertising_ready():
    response, upstream, metrics = _wire(_DUP_HOST)
    assert response.startswith(b"HTTP/1.1 400 Bad Request"), response
    assert upstream == b""
    assert metrics.get("health", 0) == 0 and metrics["dropped"] >= 1


def test_health_path_rejects_invalid_method_header_and_folded_line():
    for request in (
            b"G@T /healthz HTTP/1.1\r\nHost: local.test\r\n\r\n",
            b"GET /healthz HTTP/1.1\r\nHost : local.test\r\n\r\n",
            b"GET /healthz HTTP/1.1\r\nHost: local.test\r\n X-Extra: folded\r\n\r\n"):
        response, upstream, metrics = _wire(request)
        assert response.startswith(b"HTTP/1.1 400 Bad Request"), (request, response)
        assert upstream == b"" and metrics.get("health", 0) == 0


def test_well_formed_health_probe_still_answers_without_backend():
    response, upstream, metrics = _wire(_GOOD)
    assert response.startswith(b"HTTP/1.1 200 OK"), response
    assert b'"status":"ok"' in response
    assert upstream == b""
    assert metrics["health"] == 1
