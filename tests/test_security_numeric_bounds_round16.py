"""Extreme numeric settings cannot silently disable Range/body limits."""

import os
import tempfile
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-numeric-bounds-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_extreme_range_count_cannot_reach_backend():
    with _state_dir() as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 range_check_enabled=True, range_max_ranges=8,
                                 rate_per_sec=1000, burst=1000)["ok"]
        attempted = shield.set_config(range_max_ranges=1_000_000)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                benign = _exchange(edge, [b"GET /range-benign HTTP/1.1\r\n"
                    b"Host: local.test\r\nRange: bytes=0-1\r\n\r\n"])
                many = b",".join(f"{i}-{i}".encode() for i in range(9))
                attack = _exchange(edge, [b"GET /range-many HTTP/1.1\r\n"
                    b"Host: local.test\r\nRange: bytes=" + many + b"\r\n\r\n"])
            upstream = backend.saw()
        finally:
            backend.close()
        assert benign.startswith(b"HTTP/1.1 200") and b"GET /range-benign" in upstream
        assert attempted["ok"] is False and shield.cfg["range_max_ranges"] == 8, attempted
        assert not attack.startswith(b"HTTP/1.1 200"), attack
        assert b"GET /range-many" not in upstream, upstream


def test_extreme_body_deadline_cannot_reach_backend_after_timeout():
    with _state_dir() as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 body_timeout_enabled=True, body_max_sec=1,
                                 body_scan_enabled=True, rate_per_sec=1000,
                                 burst=1000)["ok"]
        attempted = shield.set_config(body_max_sec=10**300)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                head = (b"POST /body-benign HTTP/1.1\r\nHost: local.test\r\n"
                        b"Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n")
                benign = _exchange(edge, [head + b"AB"])
                head = (b"POST /body-slow HTTP/1.1\r\nHost: local.test\r\n"
                        b"Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n")
                attack = _exchange(edge, [head + b"A", b"B"], delay=1.2)
            upstream = backend.saw()
        finally:
            backend.close()
        assert benign.startswith(b"HTTP/1.1 200") and b"POST /body-benign" in upstream
        assert attempted["ok"] is False and shield.cfg["body_max_sec"] == 1, attempted
        assert not attack.startswith(b"HTTP/1.1 200"), attack
        assert b"POST /body-slow" not in upstream, upstream
