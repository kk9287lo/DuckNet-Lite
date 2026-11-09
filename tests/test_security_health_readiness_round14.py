"""Health must not advertise readiness when a mandatory defense is unavailable."""

from unittest.mock import patch

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_GET = b"GET /healthz HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _wire(failed_source=""):
    backend = _Backend()
    try:
        with _shield(), _guard(backend, health_path="/healthz") as guard:
            if failed_source:
                with patch(failed_source, side_effect=OSError("fixture source unavailable")):
                    response = _exchange(guard, [_GET])
            else:
                response = _exchange(guard, [_GET])
            metrics = dict(guard.metrics)
        return response, backend.saw(), metrics
    finally:
        backend.close()


def test_unavailable_shield_constructor_is_already_closed_before_health():
    response, upstream, metrics = _wire("dataplane.engine.lifeform.pipeline.net_shield")
    assert not response.startswith(b"HTTP/1.1 200 OK"), response
    assert upstream == b""
    assert metrics.get("health", 0) == 0


def test_unavailable_shield_status_cannot_advertise_healthy_wire():
    response, upstream, metrics = _wire("dataplane.engine.lifeform.pipeline.NetShield.is_enabled")
    assert response.startswith(b"HTTP/1.1 503 Service Unavailable"), response
    assert b'"status":"unavailable"' in response
    assert upstream == b""
    assert metrics.get("health", 0) == 0


def test_unavailable_firewall_cannot_advertise_healthy_wire():
    response, upstream, metrics = _wire("dataplane.engine.lifeform.policy.app_firewall")
    assert response.startswith(b"HTTP/1.1 503 Service Unavailable"), response
    assert b'"status":"unavailable"' in response
    assert upstream == b""
    assert metrics.get("health", 0) == 0


def test_unavailable_firewall_status_cannot_advertise_healthy_wire():
    response, upstream, metrics = _wire("dataplane.engine.lifeform.policy.AppFirewall.is_enabled")
    assert response.startswith(b"HTTP/1.1 503 Service Unavailable"), response
    assert b'"status":"unavailable"' in response
    assert upstream == b""
    assert metrics.get("health", 0) == 0


def test_available_defenses_keep_existing_health_wire_and_skip_backend():
    response, upstream, metrics = _wire()
    assert response.startswith(b"HTTP/1.1 200 OK"), response
    assert b'"status":"ok"' in response
    assert upstream == b""
    assert metrics["health"] == 1


def test_intentionally_disabled_defenses_still_answer_health():
    backend = _Backend()
    try:
        with _shield(), _guard(backend, health_path="/healthz") as guard, \
                patch("dataplane.engine.lifeform.pipeline.NetShield.is_enabled",
                      return_value=False), \
                patch("dataplane.engine.lifeform.policy.AppFirewall.is_enabled",
                      return_value=False):
            response = _exchange(guard, [_GET])
            metrics = dict(guard.metrics)
        assert response.startswith(b"HTTP/1.1 200 OK"), response
        assert backend.saw() == b""
        assert metrics["health"] == 1
    finally:
        backend.close()
