"""A failed enabled redirect policy must not publish the unsafe origin head."""

from unittest.mock import patch

import dataplane.engine.services.proxy as proxy
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_GET = b"GET /landing HTTP/1.1\r\nHost: local.test\r\n\r\n"
_REDIR = (b"HTTP/1.1 302 Found\r\nLocation: https://outside.example/phish\r\n"
          b"Content-Length: 0\r\nConnection: close\r\n\r\n")


def _wire(*, broken=False, mode="enforce"):
    backend = _Backend(_REDIR)
    try:
        with _shield(open_redirect_enabled=True, open_redirect_mode=mode,
                     open_redirect_allow=[], open_redirect_safe_path="/") as sh:
            with _guard(backend) as guard:
                if broken:
                    with patch.object(proxy, "_redirect_violation_host",
                                      side_effect=RuntimeError("fixture policy failure")):
                        response = _exchange(guard, [_GET])
                else:
                    response = _exchange(guard, [_GET])
                metrics = dict(guard.metrics)
            events = sh.events(100)
        return response, backend.saw(), metrics, events
    finally:
        backend.close()


def test_policy_exception_cannot_release_external_location_in_enforce():
    response, upstream, metrics, _events = _wire(broken=True)
    assert upstream.startswith(b"GET /landing HTTP/1.1\r\n")
    assert b"Location: https://outside.example/phish" not in response, response
    assert metrics.get("defense_unavailable", 0) >= 1, metrics


def test_unknown_runtime_redirect_mode_cannot_become_implicit_audit():
    response, upstream, metrics, _events = _wire(mode="unexpected")
    assert upstream.startswith(b"GET /landing HTTP/1.1\r\n")
    assert b"Location: https://outside.example/phish" not in response, response
    assert metrics.get("redirect_policy_failed", 0) >= 1, metrics


def test_benign_enforce_rewrites_external_location_on_actual_wire():
    response, upstream, _metrics, _events = _wire()
    assert upstream.startswith(b"GET /landing HTTP/1.1\r\n")
    assert response.startswith(b"HTTP/1.1 302 Found"), response
    assert b"Location: /\r\n" in response, response
    assert b"outside.example" not in response


def test_benign_audit_preserves_redirect_but_records_it():
    response, upstream, metrics, events = _wire(mode="audit")
    assert upstream.startswith(b"GET /landing HTTP/1.1\r\n")
    assert b"Location: https://outside.example/phish" in response
    assert metrics.get("open_redirect", 0) >= 1
    assert any(e.get("kind") == "open_redirect" for e in events)


def test_audit_policy_failure_preserves_wire_but_records_unexamined_head():
    response, upstream, metrics, events = _wire(broken=True, mode="audit")
    assert upstream.startswith(b"GET /landing HTTP/1.1\r\n")
    assert b"Location: https://outside.example/phish" in response
    assert metrics.get("redirect_policy_failed", 0) >= 1
    assert any(e.get("kind") == "audit" and e.get("rule") == "redirect_policy_unavailable"
               for e in events)
