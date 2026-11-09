"""Only a validated final backend response may change response-aware BAN state."""

import os
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_REQUEST = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
_GOOD_401 = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
_BAD_401 = (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n")
_GOOD_200 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
_INTERIM = b"HTTP/1.1 100 Continue\r\n\r\n"


def _case(response):
    backend = _Backend(response)
    try:
        with tempfile.TemporaryDirectory(prefix="ducknet-r25-status-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            shield = NetShield(state_dir=state)
            firewall = AppFirewall(state_dir=state)
            assert shield.set_config(enabled=True, block_page=False,
                                     resp_error_threshold=1,
                                     resp_error_score=50,
                                     block_score=40)["ok"]
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    _guard(backend) as guard:
                reply = _exchange(guard, [_REQUEST])
                return (backend.saw(), reply, guard.metrics.copy(),
                        shield.metrics()["resp_code_hits"].copy(),
                        shield.is_banned_fast("127.0.0.1"))
    finally:
        backend.close()


def test_malformed_final_401_does_not_ban_a_client_without_a_response():
    backend_wire, client_wire, metrics, hits, banned = _case(_BAD_401)
    assert backend_wire.startswith(b"GET /public HTTP/1.1\r\n"), backend_wire
    assert client_wire == b"", client_wire
    assert metrics.get("backend_invalid_response") == 1, metrics
    assert hits.get("4xx", 0) == 0 and not banned, (hits, banned)


def test_valid_401_still_scores_and_bans_after_complete_head():
    backend_wire, client_wire, metrics, hits, banned = _case(_GOOD_401)
    assert backend_wire.startswith(b"GET /public HTTP/1.1\r\n"), backend_wire
    assert client_wire == _GOOD_401, client_wire
    assert metrics.get("backend_invalid_response", 0) == 0, metrics
    assert hits.get("4xx") == 1 and banned, (hits, banned)


def test_interim_then_valid_final_401_scores_once():
    _backend, client_wire, metrics, hits, banned = _case(_INTERIM + _GOOD_401)
    assert client_wire == _INTERIM + _GOOD_401, client_wire
    assert metrics.get("backend_invalid_response", 0) == 0, metrics
    assert hits.get("4xx") == 1 and banned, (hits, banned)


def test_interim_then_malformed_final_401_does_not_score():
    _backend, client_wire, metrics, hits, banned = _case(_INTERIM + _BAD_401)
    assert client_wire == _INTERIM, client_wire
    assert metrics.get("backend_invalid_response") == 1, metrics
    assert hits.get("4xx", 0) == 0 and not banned, (hits, banned)


def test_valid_200_keeps_response_scoring_clear():
    _backend, client_wire, metrics, hits, banned = _case(_GOOD_200)
    assert client_wire == _GOOD_200, client_wire
    assert metrics.get("backend_invalid_response", 0) == 0, metrics
    assert hits.get("4xx", 0) == 0 and not banned, (hits, banned)
