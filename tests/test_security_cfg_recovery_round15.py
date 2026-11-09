"""A valid signed partial legacy config cannot turn a WAF recovery OFF."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.core.signed_state import payload_fingerprint, write_signed_json
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_REQUEST = b"GET /r15vault HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _wire(shield, state):
    backend = _Backend()
    try:
        with patch.object(ND, "_SHIELD", shield), \
                patch.object(FW, "_FW", AppFirewall(state_dir=state)), \
                _guard(backend) as edge:
            response = _exchange(edge, [_REQUEST])
        return backend.got, response
    finally:
        backend.close()


def _seed(state, *, omit_enabled):
    shield = NetShield(state_dir=state)
    assert shield.set_config(enabled=True, block_page=False,
                             blocked_urls=["/r15vault"])["ok"]
    if omit_enabled:
        envelope = json.loads(Path(shield.path).read_text(encoding="utf-8"))
        prior = envelope["_payload"]
        replacement = {**prior, "cfg": {k: v for k, v in prior["cfg"].items()
                                          if k != "enabled"}}
        status = {}
        assert write_signed_json(shield.path, replacement, shield._state_key,
                                 expected_fingerprint=payload_fingerprint(prior),
                                 status=status)
        assert status["published"] is True and status["durable"] is not False
    return NetShield(state_dir=state)


def test_signed_partial_config_memory_recovery_stays_protective_on_wire():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _seed(state, omit_enabled=True)
        assert shield.is_enabled() is True
        before_upstream, before_client = _wire(shield, state)
        assert before_upstream == [] and b"\r\n\r\nok" not in before_client

        shield.cfg["rate_per_sec"] = 999.0  # out-of-band memory corruption
        restored = shield.verify_cfg_integrity()
        assert restored.get("tampered") and restored.get("source") == "disk", restored
        after_upstream, after_client = _wire(shield, state)
        assert after_upstream == [] and b"\r\n\r\nok" not in after_client, (
            after_upstream, after_client)
        assert shield.is_enabled() is True, "verified partial config must not restore shield OFF"


def test_complete_signed_config_recovery_retains_existing_wire_policy():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _seed(state, omit_enabled=False)
        shield.cfg["rate_per_sec"] = 999.0
        restored = shield.verify_cfg_integrity()
        assert restored.get("tampered") and restored.get("source") == "disk", restored
        assert shield.is_enabled() is True
        upstream, client = _wire(shield, state)
        assert upstream == [] and b"\r\n\r\nok" not in client


def test_explicit_signed_off_remains_a_deliberate_passthrough():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=False, block_page=False,
                                 blocked_urls=["/r15vault"])["ok"]
        restarted = NetShield(state_dir=state)
        assert restarted.is_enabled() is False
        restarted.cfg["rate_per_sec"] = 999.0
        restored = restarted.verify_cfg_integrity()
        assert restored.get("tampered") and restored.get("source") == "disk", restored
        assert restarted.is_enabled() is False
        upstream, client = _wire(restarted, state)
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2])
        assert client.startswith(b"HTTP/1.1 200") and client.endswith(b"ok")
