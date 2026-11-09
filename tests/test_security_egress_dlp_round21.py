"""Known credentials remain protected when embedded in a longer word."""

import os
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from test_sweep_proxy_request import _Backend, _exchange, _guard


_REQUEST = b"GET /egress-r21 HTTP/1.1\r\nHost: app.example\r\n\r\n"
_KEYS = (
    b"AKIAIOSFODNN7EXAMPLE",                # synthetic AWS documentation key
    b"ghp_" + b"a" * 36,                    # synthetic legacy PAT shape
    b"AIza" + b"A" * 35,                    # synthetic API key shape
    b"xoxb-" + b"A" * 10,                   # synthetic Slack token shape
    b"sk_live_" + b"A" * 24,               # synthetic Stripe secret shape
)


def _response(body, extra=b""):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + extra
            + b"Content-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)


def _wire(body, *, mode, extra=b""):
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        configured = shield.set_config(enabled=True, mode=mode, block_page=False,
                                       dlp_enabled=True, dlp_action="block",
                                       usage_record=False)
        assert configured.get("ok") is True, configured
        backend = _Backend(_response(body, extra))
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
                with _guard(backend) as edge:
                    client = _exchange(edge, [_REQUEST])
            return client, backend.saw(), shield
        finally:
            backend.close()


def test_embedded_strong_credentials_never_reach_client_in_block_mode():
    for token in _KEYS:
        # One added word character on each side defeats a word-boundary-only
        # detector, while the exact credential remains recoverable by a peer.
        attack = b"public X" + token + b"Z tail"
        client, backend, shield = _wire(attack, mode="enforce")
        assert b"GET /egress-r21" in backend, backend
        assert token not in client and attack not in client, (token[:4], client)
        assert shield.metrics().get("dlp_leak", 0) >= 1, token[:4]


def test_embedded_token_audit_and_lookalike_benign_wires_are_explicit():
    token = _KEYS[0]
    attack = b"public X" + token + b"Z tail"
    audit_client, audit_backend, audit_shield = _wire(attack, mode="audit")
    assert b"GET /egress-r21" in audit_backend
    assert audit_client.endswith(attack), audit_client
    assert audit_shield.metrics().get("dlp_leak", 0) >= 1
    benign = b"public XAKIBIOSFODNN7EXAMPLEZ tail"
    safe_client, safe_backend, safe_shield = _wire(benign, mode="enforce")
    assert b"GET /egress-r21" in safe_backend
    assert safe_client.endswith(benign), safe_client
    assert safe_shield.metrics().get("dlp_leak", 0) == 0


def test_embedded_token_in_response_header_is_withheld_before_client_bytes():
    token = _KEYS[0]
    secret_header = b"X-Debug: X" + token + b"Z\r\n"
    blocked, backend, shield = _wire(b"ordinary", mode="enforce",
                                     extra=secret_header)
    assert b"GET /egress-r21" in backend
    assert token not in blocked and b"ordinary" not in blocked, blocked
    assert shield.metrics().get("dlp_leak", 0) >= 1
    safe_header = b"X-Debug: XAKIBIOSFODNN7EXAMPLEZ\r\n"
    allowed, backend, shield = _wire(b"ordinary", mode="enforce",
                                     extra=safe_header)
    assert b"GET /egress-r21" in backend
    assert safe_header in allowed and allowed.endswith(b"ordinary"), allowed
    assert shield.metrics().get("dlp_leak", 0) == 0
