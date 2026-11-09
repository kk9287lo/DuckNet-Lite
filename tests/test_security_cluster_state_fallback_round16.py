"""Fork admission must not multiply local security counters or hide ACL audit."""

import contextlib
import http.client
import json
import os
import signal
import socket
import tempfile
from unittest import SkipTest
from unittest.mock import patch

from dataplane.admin import AdminDashboard
from dataplane.engine.lifeform import pipeline, policy
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_security_cluster_round14 import _backend, _port, _received
from test_security_shared_cluster_round16 import _wires


@contextlib.contextmanager
def _running(*, shield_on=False, acl_on=False, workers=2, **config):
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-fallback-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = pipeline.NetShield(state_dir=state)
        firewall = policy.AppFirewall(state_dir=state)
        settings = dict(enabled=shield_on, mode="enforce", block_page=False,
                        persist_bans=False, usage_record=False, dlp_enabled=False,
                        sec_headers_enabled=False, cors_harden_enabled=False,
                        cookie_harden_enabled=False, open_redirect_enabled=False,
                        resp_score_enabled=False, flood_threshold=1000,
                        rate_per_sec=1000.0, burst=1000, block_score=1000,
                        max_total_conn=0, max_conn_per_ip=0,
                        conn_rate_per_ip=0)
        settings.update(config)
        assert shield.set_config(**settings)["ok"]
        assert (firewall.enable() if acl_on else firewall.disable())["ok"]
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port(),
                              health_path="/healthz")
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall):
                started = edge.serve_cluster(workers=workers)
                assert started.get("ok") is True, started
                yield state, shield, firewall, edge, started, backend_report
        finally:
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)


def _allowed(wires):
    return sum(w.startswith(b"HTTP/1.1 200") for w in wires)


def _health_wire(edge):
    with socket.create_connection(("127.0.0.1", edge.listen_port), timeout=3) as conn:
        conn.settimeout(3)
        conn.sendall(b"GET /healthz HTTP/1.1\r\nHost: test.local\r\n"
                     b"Connection: close\r\n\r\n")
        wire = bytearray()
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                wire.extend(chunk)
        except OSError:
            pass
        return bytes(wire)


def test_enabled_shield_rate_is_one_bucket_and_startup_is_honest():
    with _running(shield_on=True, rate_per_sec=1e-9, burst=1) as (
            _state, _shield, _firewall, edge, started, backend_fd):
        wires = _wires(edge, b"/r16-shield-rate", 40)
        upstream = _received(backend_fd)
        assert _allowed(wires) == 1, [_w[:28] for _w in wires]
        assert upstream.count(b"GET /r16-shield-rate") == 1, upstream
        assert started.get("mode") == "single" and not edge._workers, started
        assert started.get("workers") == 1 and started.get("cluster_downgraded") is True


def test_enabled_acl_keeps_parent_audit_complete():
    with _running(acl_on=True) as (
            _state, _shield, firewall, edge, started, backend_fd):
        before = firewall.stats()["total"]
        wires = _wires(edge, b"/r16-acl-audit", 48)
        upstream = _received(backend_fd)
        assert _allowed(wires) == 48, [_w[:28] for _w in wires]
        assert upstream.count(b"GET /r16-acl-audit") == 48, upstream
        assert firewall.stats()["total"] - before == 48, firewall.stats()
        assert started.get("mode") == "single" and not edge._workers, started


def test_connection_rate_is_one_bucket_even_with_shield_off():
    with _running(conn_rate_per_ip=1) as (
            _state, _shield, _firewall, edge, started, backend_fd):
        wires = _wires(edge, b"/r16-connect-rate", 40)
        upstream = _received(backend_fd)
        assert _allowed(wires) == 1, [_w[:28] for _w in wires]
        assert upstream.count(b"GET /r16-connect-rate") == 1, upstream
        assert started.get("mode") == "single" and not edge._workers, started


def test_stateless_explicit_opt_out_still_runs_two_workers():
    with _running() as (
            state, _shield, _firewall, edge, started, backend_fd):
        wires = _wires(edge, b"/r16-stateless-control", 20)
        upstream = _received(backend_fd)
        assert _allowed(wires) == 20, [_w[:28] for _w in wires]
        assert upstream.count(b"GET /r16-stateless-control") == 20, upstream
        assert started.get("mode") == "cluster" and len(edge._workers) == 1, started
        dashboard = AdminDashboard(host="127.0.0.1", port=0,
                                   token="r16-cluster-telemetry", state_dir=state,
                                   edge_guard=edge)
        try:
            assert dashboard.start().get("ok") is True
            connection = http.client.HTTPConnection("127.0.0.1", dashboard.port,
                                                    timeout=3)
            try:
                connection.request("GET", "/api/state",
                                   headers={"X-Token": dashboard.token})
                response = connection.getresponse()
                body = json.loads(response.read())
            finally:
                connection.close()
            assert response.status == 200, response.status
            assert body["telemetry_complete"] is False, body
            assert body["telemetry_scope"] == "per-worker", body
        finally:
            dashboard.stop()


def test_explicit_one_worker_reports_single_complete_state():
    with _running(workers=1) as (
            _state, _shield, _firewall, edge, started, backend_fd):
        benign = _wires(edge, b"/r16-one-worker", 1)[0]
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /r16-one-worker" in _received(backend_fd)
        assert started.get("mode") == "single" and started.get("workers") == 1, started
        assert started.get("telemetry_complete") is True, started
        assert not edge._workers and not started.get("child_pids"), started


def test_external_signed_enable_fails_closed_before_multiworker_forward():
    with _running() as (
            state, _shield, _firewall, edge, started, backend_fd):
        assert started.get("mode") == "cluster" and len(edge._workers) == 1
        warm = _wires(edge, b"/r16-before-enable", 20)
        assert _allowed(warm) == 20
        assert _received(backend_fd).count(b"GET /r16-before-enable") == 20
        external = pipeline.NetShield(state_dir=state)
        changed = external.set_config(enabled=True, rate_per_sec=1e-9,
                                      burst=1, flood_threshold=1000,
                                      block_score=1000)
        assert changed.get("ok") is True, changed
        after = _wires(edge, b"/r16-after-enable", 40)
        health = _health_wire(edge)
        half_closed_health = _wires(edge, b"/healthz", 1)[0]
        upstream = _received(backend_fd)
        assert _allowed(after) == 0, [_w[:28] for _w in after]
        assert upstream.count(b"GET /r16-after-enable") == 0, upstream
        assert health.startswith(b"HTTP/1.1 503"), health
        assert half_closed_health.startswith(b"HTTP/1.1 503"), half_closed_health


def test_direct_parent_enable_cannot_ack_unshared_cluster_state():
    with _running() as (
            _state, shield, _firewall, edge, started, backend_fd):
        assert started.get("mode") == "cluster" and len(edge._workers) == 1
        changed = shield.set_config(enabled=True, rate_per_sec=1e-9, burst=1)
        if changed.get("ok") is True:
            # A successful update must first reap forked copies.
            assert not edge._workers, changed
        else:
            assert shield.is_enabled() is False and not changed.get("applied_in_memory")
        warm = _wires(edge, b"/r16-direct-enable", 2)
        assert _allowed(warm) >= 1, warm
        assert b"GET /r16-direct-enable" in _received(backend_fd)


def test_direct_parent_acl_enable_and_global_block_are_rejected_before_ack():
    with _running() as (
            _state, _shield, firewall, edge, started, backend_fd):
        assert started.get("mode") == "cluster" and len(edge._workers) == 1
        for mutate in (firewall.enable, lambda: firewall.set_global_block(True)):
            changed = mutate()
            assert changed.get("ok") is False, changed
            assert firewall.is_enabled() is False
            assert edge._workers and edge.is_alive()
        benign = _wires(edge, b"/r16-acl-rejected", 1)[0]
        assert benign.startswith(b"HTTP/1.1 200"), benign
        assert b"GET /r16-acl-rejected" in _received(backend_fd)


def test_external_signed_acl_enable_fails_closed_before_backend_and_health():
    with _running() as (
            state, _shield, _firewall, edge, started, backend_fd):
        assert started.get("mode") == "cluster" and len(edge._workers) == 1
        warm = _wires(edge, b"/r16-acl-before", 8)
        assert _allowed(warm) == 8
        assert _received(backend_fd).count(b"GET /r16-acl-before") == 8
        external = policy.AppFirewall(state_dir=state)
        changed = external.enable()
        assert changed.get("ok") is True, changed
        after = _wires(edge, b"/r16-acl-after", 20)
        health = _health_wire(edge)
        half_closed_health = _wires(edge, b"/healthz", 1)[0]
        upstream = _received(backend_fd)
        assert _allowed(after) == 0, [_w[:28] for _w in after]
        assert b"GET /r16-acl-after" not in upstream, upstream
        assert health.startswith(b"HTTP/1.1 503"), health
        assert half_closed_health.startswith(b"HTTP/1.1 503"), half_closed_health


def test_external_signed_connection_caps_fail_closed_before_backend():
    for setting in ({"max_total_conn": 1}, {"max_conn_per_ip": 1},
                    {"conn_rate_per_ip": 1}):
        with _running() as (
                state, _shield, _firewall, edge, started, backend_fd):
            assert started.get("mode") == "cluster" and len(edge._workers) == 1
            warm = _wires(edge, b"/r16-cap-before", 8)
            assert _allowed(warm) == 8
            assert _received(backend_fd).count(b"GET /r16-cap-before") == 8
            external = pipeline.NetShield(state_dir=state)
            changed = external.set_config(**setting)
            assert changed.get("ok") is True, (setting, changed)
            after = _wires(edge, b"/r16-cap-after", 20)
            health = _health_wire(edge)
            half_closed_health = _wires(edge, b"/healthz", 1)[0]
            upstream = _received(backend_fd)
            assert _allowed(after) == 0, (setting, [_w[:28] for _w in after])
            assert b"GET /r16-cap-after" not in upstream, (setting, upstream)
            assert health.startswith(b"HTTP/1.1 503"), (setting, health)
            assert half_closed_health.startswith(b"HTTP/1.1 503"), (setting, half_closed_health)
