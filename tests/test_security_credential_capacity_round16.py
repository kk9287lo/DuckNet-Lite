"""Credential-map saturation must not reset an active token window."""

import os
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _shield(state):
    shield = pipeline.NetShield(state_dir=state)
    assert shield.set_config(enabled=True, block_page=False, persist_bans=False,
                             rate_per_sec=1000, burst=1000, cred_rate_enabled=True,
                             cred_rate_limit=1, cred_rate_window_sec=60,
                             cred_rate_score=0, resp_score_enabled=False)["ok"]
    return shield


def test_active_credential_window_survives_table_saturation_on_real_wire():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-cred-cap-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _shield(state)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_CRED_RATE_CAP", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                wires = []
                for index, key in enumerate(("A", "B", "C", "A")):
                    request = (f"GET /cred-{index} HTTP/1.1\r\nHost: local.test\r\n"
                               f"X-API-Key: {key}\r\n\r\n").encode("ascii")
                    wires.append(_exchange(edge, [request]))
            assert wires[0].startswith(b"HTTP/1.1 200"), wires
            assert wires[1].startswith(b"HTTP/1.1 200"), wires
            assert not wires[2].startswith(b"HTTP/1.1 200"), wires
            assert not wires[3].startswith(b"HTTP/1.1 200"), wires
            upstream = backend.saw()
            assert b"GET /cred-0" in upstream and b"GET /cred-1" in upstream
            assert b"GET /cred-2" not in upstream and b"GET /cred-3" not in upstream
            assert len(shield._cred_rate) == 2
        finally:
            backend.close()


def test_expired_credential_window_can_be_reused_without_active_eviction():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-cred-expire-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _shield(state)
        now = [1000.0]
        with patch.object(pipeline, "_CRED_RATE_CAP", 2), \
                patch.object(pipeline, "_now", side_effect=lambda: now[0]):
            assert shield._credential_rate("A") == 1
            assert shield._credential_rate("B") == 1
            assert shield._credential_rate("C") > 1  # capacity itself is a deny
            assert shield._credential_rate("A") == 2  # old active A survived
            now[0] += 61.0
            assert shield._credential_rate("C") == 1
            assert len(shield._cred_rate) == 2
