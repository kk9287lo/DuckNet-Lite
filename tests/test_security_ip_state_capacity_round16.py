"""Active BANs survive a full per-IP table; new admissions fail safely."""

import os
import socket
import tempfile
import time
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_sweep_proxy_request import _Backend, _guard


def _exchange_from(edge, ip, path):
    request = (f"GET {path} HTTP/1.1\r\nHost: local.test\r\n"
               "Connection: close\r\n\r\n").encode("ascii")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(4)
        client.bind((ip, 0))
        client.connect(("127.0.0.1", edge.listen_port))
        client.sendall(request)
        result = bytearray()
        try:
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                result.extend(chunk)
        except OSError:
            pass
    return bytes(result)


def _setup(state):
    shield = pipeline.NetShield(state_dir=state)
    configured = shield.set_config(enabled=True, block_page=False,
                                   persist_bans=False, rate_per_sec=1000,
                                   burst=1000)
    assert configured["ok"], configured
    return shield, policy.AppFirewall(state_dir=state), _Backend()


def _state_dir():
    # The test runner sets this to a throwaway D-scoped directory before imports.
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-ip-cap-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_active_temporary_ban_is_never_evicted_for_new_ip():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield.ban("127.0.0.2", ttl_sec=60)["ok"]
                assert shield.ban("127.0.0.3", ttl_sec=3600)["ok"]
                before = _exchange_from(edge, "127.0.0.2", "/victim-before")
                new = _exchange_from(edge, "127.0.0.4", "/capacity-new")
                after = _exchange_from(edge, "127.0.0.2", "/victim-after")
                assert len(shield._ips) == 2
                assert shield.is_banned_fast("127.0.0.2")
            wire = backend.saw()
        finally:
            backend.close()
        assert not any(r.startswith(b"HTTP/1.1 200") for r in (before, new, after))
        assert b"GET /capacity-new" not in wire
        assert b"GET /victim-after" not in wire


def test_permanent_ban_saturation_rejects_untracked_and_new_manual_ban():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield.ban("127.0.0.2", permanent=True)["ok"]
                assert shield.ban("127.0.0.3", permanent=True)["ok"]
                new = _exchange_from(edge, "127.0.0.4", "/permanent-full")
                third = shield.ban("127.0.0.5", permanent=True)
                assert third["ok"] is False and third.get("error"), third
                assert len(shield._ips) == 2
                assert shield.is_banned_fast("127.0.0.2")
                assert shield.is_banned_fast("127.0.0.3")
            wire = backend.saw()
        finally:
            backend.close()
        assert not new.startswith(b"HTTP/1.1 200"), new
        assert b"GET /permanent-full" not in wire


def test_audit_capacity_records_would_block_without_exceeding_cap():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield.ban("127.0.0.2", permanent=True)["ok"]
                assert shield.ban("127.0.0.3", permanent=True)["ok"]
                assert shield.set_config(mode="audit")["ok"]
                benign = _exchange_from(edge, "127.0.0.4", "/audit-capacity")
                events = shield.events(100)
                assert len(shield._ips) == 2
            wire = backend.saw()
        finally:
            backend.close()
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /audit-capacity" in wire
        assert any(e.get("kind") == "audit" and
                   e.get("rule") == "ip_state_capacity" and
                   e.get("would") == "block" for e in events), events


def test_expired_ban_slot_is_reused_for_benign_client():
    with _state_dir() as state:
        shield, firewall, backend = _setup(state)
        try:
            with patch.object(pipeline, "_MAX_IPS", 2), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield.ban("127.0.0.2", ttl_sec=0.1)["ok"]
                assert shield.ban("127.0.0.3", permanent=True)["ok"]
                time.sleep(0.2)
                benign = _exchange_from(edge, "127.0.0.4", "/expired-reuse")
                assert len(shield._ips) == 2
            wire = backend.saw()
        finally:
            backend.close()
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /expired-reuse" in wire


def test_direct_api_capacity_results_are_explicit_and_bounded():
    with _state_dir() as state:
        shield, _firewall, backend = _setup(state)
        backend.close()
        with patch.object(pipeline, "_MAX_IPS", 1):
            assert shield.ban("127.0.0.2", permanent=True)["ok"]
            attack_ip = "127.0.0.4"
            assert shield.inspect(attack_ip, path="/")["action"] == "block"
            penalized = shield.penalize(attack_ip, weight=1000)
            uploaded = shield.upload_violation(attack_ip, "shell.php", "php")
            banned = shield.ban(attack_ip, permanent=True)
            restricted = shield.restrict(attack_ip, ttl_sec=60)
            assert penalized.get("ok") is False and penalized["action"] == "block", penalized
            assert uploaded["action"] == "block", uploaded
            assert banned.get("ok") is False and banned.get("error"), banned
            assert restricted.get("ok") is False and restricted.get("error"), restricted
            assert len(shield._ips) == 1 and shield.is_banned_fast("127.0.0.2")
