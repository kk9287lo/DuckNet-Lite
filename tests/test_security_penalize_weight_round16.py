"""Direct penalty weight cannot poison the score used by real WAF decisions."""

import math
import os
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield, _SIG_WEIGHT_MAX
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-penalty-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _signature_wire(poison):
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 block_score=40, deny_score=20)["ok"]
        assert shield.add_signature("score-probe", "r16scoremarker", weight=100)["ok"]
        firewall = AppFirewall(state_dir=state)
        penalty = shield.penalize("127.0.0.1", weight=float("nan")) if poison else None
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                wire = _exchange(edge, [b"GET /r16scoremarker HTTP/1.1\r\n"
                                        b"Host: local.test\r\n\r\n"])
            return penalty, wire, backend.saw(), shield._ips.get("127.0.0.1")
        finally:
            backend.close()


def test_nan_penalty_cannot_make_blocked_signature_reach_backend():
    _clean_penalty, clean_wire, clean_backend, _clean_state = _signature_wire(False)
    assert not clean_wire.startswith(b"HTTP/1.1 200"), clean_wire
    assert b"GET /r16scoremarker" not in clean_backend

    penalty, poisoned_wire, poisoned_backend, poisoned_state = _signature_wire(True)
    # Old runtime returned score=nan, then allowed this same malicious request.
    assert not poisoned_wire.startswith(b"HTTP/1.1 200"), poisoned_wire
    assert b"GET /r16scoremarker" not in poisoned_backend
    assert penalty.get("ok") is False, penalty
    assert poisoned_state is not None and math.isfinite(poisoned_state["score"])


def test_invalid_weights_reject_before_allocating_ip_state():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        ip = "192.0.2.44"
        for weight in (float("nan"), float("inf"), -float("inf"),
                       -1, True, "50", "bogus", 1e100, _SIG_WEIGHT_MAX + 1):
            result = shield.penalize(ip, weight=weight)
            assert result.get("ok") is False, (weight, result)
            assert ip not in shield._ips


def test_zero_default_and_valid_bounded_penalties_keep_their_meaning():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_score=100,
                                 deny_score=80, slowloris_score=25)["ok"]
        default = shield.penalize("192.0.2.45", weight=0)
        assert default["action"] == "penalize" and default["score"] == 25, default
        assert shield._ips["192.0.2.45"]["score"] == 25
        direct = shield.penalize("192.0.2.46", weight=50)
        assert direct["action"] == "penalize" and direct["score"] == 50, direct
        high = shield.penalize("192.0.2.47", weight=_SIG_WEIGHT_MAX)
        assert high["action"] == "block" and high["banned"] is True, high
