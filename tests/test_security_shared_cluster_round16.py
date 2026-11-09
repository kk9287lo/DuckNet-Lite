"""Stateful fork requests safely downgrade; stateless fork reload stays strict."""

import contextlib
import errno
import json
import os
from pathlib import Path
import signal
import socket
import tempfile
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline as pipeline
from dataplane.engine.lifeform import policy as policy
from dataplane.engine.core.signed_state import write_signed_json
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_security_cluster_round14 import _backend, _port, _received, _request


class _ObservedShield(pipeline.NetShield):
    report_fd = None

    def inspect(self, ip, **kwargs):
        result = super().inspect(ip, **kwargs)
        os.write(self.report_fd, (json.dumps({"pid": os.getpid(),
                                              "action": result.get("action")}) + "\n").encode())
        return result


@contextlib.contextmanager
def _cluster(*, stateless=False, **settings):
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    old_shield, old_firewall = pipeline._SHIELD, policy._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-shared-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        seen_fd, write_fd = os.pipe()
        shield = _ObservedShield(state_dir=state)
        shield.report_fd = write_fd
        pipeline._SHIELD = shield
        policy._FW = policy.AppFirewall(state_dir=state)
        config = dict(enabled=not stateless, mode="enforce", block_page=False,
                      persist_bans=False, usage_record=False, dlp_enabled=False,
                      sec_headers_enabled=False, cors_harden_enabled=False,
                      cookie_harden_enabled=False, open_redirect_enabled=False,
                      resp_score_enabled=False, flood_threshold=1000,
                      rate_per_sec=1000.0, burst=1000, block_score=1000,
                      max_total_conn=0, max_conn_per_ip=0,
                      conn_rate_per_ip=0)
        config.update(settings)
        assert shield.set_config(**config)["ok"]
        assert policy._FW.disable()["ok"]
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        try:
            started = edge.serve_cluster(workers=2)
            expected = "cluster" if stateless else "single"
            assert started.get("ok") and started.get("mode") == expected, started
            assert len(edge._workers) == (1 if stateless else 0), started
            if not stateless:
                assert started.get("cluster_downgraded") is True, started
            yield shield, edge, seen_fd, backend_report
        finally:
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            os.close(seen_fd)
            os.close(write_fd)
            pipeline._SHIELD, policy._FW = old_shield, old_firewall


def _wires(edge, path, n):
    wires = []
    for _ in range(n):
        try:
            wires.append(_request(edge.listen_port, path))
        except OSError as exc:
            if exc.errno not in (errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            wires.append(b"")  # an early fail-closed close can reset TCP
    return wires


def _pids(fd):
    return {json.loads(line)["pid"] for line in _received(fd).splitlines() if line}


def test_global_ip_rate_is_one_bucket_after_safe_downgrade():
    with _cluster(rate_per_sec=1e-9, burst=1) as (_shield, edge, seen_fd, backend_fd):
        wires = _wires(edge, b"/rate-r16", 40)
        assert len(_pids(seen_fd)) == 1, "stateful requests must share one worker"
        allowed = sum(wire.startswith(b"HTTP/1.1 200") for wire in wires)
        upstream = _received(backend_fd)
        assert allowed == 1, (allowed, [w[:28] for w in wires])
        assert upstream.count(b"GET /rate-r16") == 1, upstream


def test_path_rate_is_one_bucket_after_safe_downgrade():
    with _cluster(path_limits=[{"path": "/login", "rate": 1e-9,
                                "burst": 1}]) as (_shield, edge, seen_fd, backend_fd):
        wires = _wires(edge, b"/login-r16", 40)
        assert len(_pids(seen_fd)) == 1, "stateful requests must share one worker"
        allowed = sum(wire.startswith(b"HTTP/1.1 200") for wire in wires)
        upstream = _received(backend_fd)
        assert allowed == 1, (allowed, [w[:28] for w in wires])
        assert upstream.count(b"GET /login-r16") == 1, upstream


def test_automatic_ban_blocks_future_connections_after_safe_downgrade():
    with _cluster(block_score=10) as (_shield, edge, seen_fd, backend_fd):
        warm = _wires(edge, b"/warm-r16", 20)
        assert len(_pids(seen_fd)) == 1, "stateful requests must share one worker"
        assert all(w.startswith(b"HTTP/1.1 200") for w in warm), warm
        assert _received(backend_fd).count(b"GET /warm-r16") == 20
        attack = _request(edge.listen_port, b"/?q=%3Csvg%20onload%3Dalert(1)%3E")
        assert not attack.startswith(b"HTTP/1.1 200"), attack
        after = _wires(edge, b"/after-ban-r16", 48)
        assert not any(w.startswith(b"HTTP/1.1 200") for w in after), after
        assert b"GET /after-ban-r16" not in _received(backend_fd)


def test_direct_parent_ban_blocks_future_connections_after_safe_downgrade():
    with _cluster() as (shield, edge, seen_fd, backend_fd):
        warm = _wires(edge, b"/warm-r16", 20)
        assert len(_pids(seen_fd)) == 1, "stateful requests must share one worker"
        assert all(w.startswith(b"HTTP/1.1 200") for w in warm), warm
        assert _received(backend_fd).count(b"GET /warm-r16") == 20
        result = shield.ban("127.0.0.1", permanent=True)
        assert result.get("ok") is True, result
        after = _wires(edge, b"/after-parent-ban-r16", 48)
        assert not any(w.startswith(b"HTTP/1.1 200") for w in after), after
        assert b"GET /after-parent-ban-r16" not in _received(backend_fd)


def test_signed_parent_ban_stays_enforced_after_safe_downgrade():
    with _cluster(persist_bans=True) as (shield, edge, seen_fd, backend_fd):
        warm = _wires(edge, b"/warm-signed-r16", 20)
        assert len(_pids(seen_fd)) == 1, "stateful requests must share one worker"
        assert all(w.startswith(b"HTTP/1.1 200") for w in warm), warm
        assert _received(backend_fd).count(b"GET /warm-signed-r16") == 20
        result = shield.ban("127.0.0.1", permanent=True)
        assert result.get("ok") is True and result.get("persisted") is True, result
        after = _wires(edge, b"/after-signed-ban-r16", 48)
        assert not any(w.startswith(b"HTTP/1.1 200") for w in after), after
        assert b"GET /after-signed-ban-r16" not in _received(backend_fd)


def test_signed_parent_unban_recovers_after_safe_downgrade():
    with _cluster(persist_bans=True) as (shield, edge, seen_fd, backend_fd):
        warm = _wires(edge, b"/warm-unban-r16", 20)
        assert len(_pids(seen_fd)) == 1, "stateful requests must share one worker"
        assert all(w.startswith(b"HTTP/1.1 200") for w in warm), warm
        assert _received(backend_fd).count(b"GET /warm-unban-r16") == 20
        assert shield.ban("127.0.0.1", permanent=True).get("ok") is True
        blocked = _wires(edge, b"/blocked-unban-r16", 24)
        assert not any(w.startswith(b"HTTP/1.1 200") for w in blocked), blocked
        assert b"GET /blocked-unban-r16" not in _received(backend_fd)
        result = shield.unban("127.0.0.1")
        assert result.get("ok") is True and result.get("persisted") is True, result
        after = _wires(edge, b"/after-unban-r16", 24)
        assert all(w.startswith(b"HTTP/1.1 200") for w in after), after
        assert _received(backend_fd).count(b"GET /after-unban-r16") == 24


def test_signed_ban_file_corruption_fails_closed_in_stateless_fork_workers():
    with _cluster(stateless=True, persist_bans=True) as (shield, edge, seen_fd, backend_fd):
        warm = _wires(edge, b"/warm-tamper-r16", 20)
        assert edge._workers, "test must exercise a real child worker"
        assert all(w.startswith(b"HTTP/1.1 200") for w in warm), warm
        assert _received(backend_fd).count(b"GET /warm-tamper-r16") == 20
        Path(shield._bans_path + ".hw").write_text("corrupt", encoding="ascii")
        after = _wires(edge, b"/after-tamper-r16", 24)
        assert not any(w.startswith(b"HTTP/1.1 200") for w in after), after
        assert b"GET /after-tamper-r16" not in _received(backend_fd)


def test_signed_but_invalid_ban_snapshot_fails_closed_before_backend():
    with _cluster(stateless=True, persist_bans=True) as (shield, edge, seen_fd, backend_fd):
        warm = _wires(edge, b"/warm-invalid-r16", 20)
        assert edge._workers, "test must exercise a real child worker"
        assert all(w.startswith(b"HTTP/1.1 200") for w in warm), warm
        assert _received(backend_fd).count(b"GET /warm-invalid-r16") == 20
        invalid = {"bans": {"127.0.0.1": {
            "until": 0, "started": -1, "permanent": False,
            "count": 0}}, "restrictions": {}}
        assert write_signed_json(shield._bans_path, invalid, shield._state_key)
        after = _wires(edge, b"/after-invalid-r16", 24)
        assert not any(w.startswith(b"HTTP/1.1 200") for w in after), after
        assert b"GET /after-invalid-r16" not in _received(backend_fd)


def test_reload_bans_rejects_signed_invalid_values_before_any_publish():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-ban-reload-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = pipeline.NetShield(state_dir=state)
        assert shield.set_config(enabled=True, persist_bans=True)["ok"]
        first = "192.0.2.1"
        assert shield.ban(first, permanent=True)["ok"]
        good = {"until": None, "started": 1, "permanent": True,
                "count": 1, "generation": "a" * 32}
        second = {"until": 100, "started": 1, "permanent": False,
                  "count": 0}
        bad_rows = [
            {**second, "until": "inf"},
            {**second, "started": -1},
            {**second, "count": True},
            {**second, "count": 1_000_000_001},
            {**second, "permanent": "false"},
        ]
        for row in bad_rows:
            payload = {"bans": {first: good, "192.0.2.2": row},
                       "restrictions": {}}
            assert write_signed_json(shield._bans_path, payload, shield._state_key)
            result = shield.reload_bans()
            assert result["ok"] is False, (row, result)
            assert shield.is_banned_fast(first)
            assert not shield.is_banned_fast("192.0.2.2")
        payload = {"bans": {first: good, "192.0.2.2": {
            "until": float(2**31), "started": 1, "permanent": False,
            "count": 0, "generation": "b" * 32}}, "restrictions": {}}
        assert write_signed_json(shield._bans_path, payload, shield._state_key)
        with patch.object(pipeline, "_MAX_IPS", 1):
            assert shield.reload_bans()["ok"] is False
        assert shield.reload_bans()["ok"] is True
        assert shield.is_banned_fast(first)
        assert shield.is_banned_fast("192.0.2.2")


def test_signed_legacy_ban_uses_single_worker_without_readiness_lie():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-ban-legacy-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        initial = pipeline.NetShield(state_dir=state)
        assert initial.set_config(enabled=True, block_page=False,
                                  persist_bans=True)["ok"]
        legacy = {"bans": {"::ffff:127.0.0.1": {
            "until": None, "started": 1, "permanent": True, "count": 1}},
            "restrictions": {}}
        assert write_signed_json(initial._bans_path, legacy, initial._state_key)
        shield = pipeline.NetShield(state_dir=state)
        assert shield.is_banned_fast("127.0.0.1")
        old_shield, old_firewall = pipeline._SHIELD, policy._FW
        pipeline._SHIELD = shield
        policy._FW = policy.AppFirewall(state_dir=state)
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        try:
            started = edge.serve_cluster(workers=2)
            assert started.get("ok") and started.get("mode") == "single", started
            assert not edge._workers
            wire = _wires(edge, b"/legacy-ban-r16", 1)[0]
            assert not wire.startswith(b"HTTP/1.1 200"), wire
            assert b"GET /legacy-ban-r16" not in _received(backend_report)
        finally:
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            pipeline._SHIELD, policy._FW = old_shield, old_firewall


def test_signed_legacy_ban_loads_for_single_worker_but_strict_reload_rejects():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-ban-legacy-load-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        initial = pipeline.NetShield(state_dir=state)
        assert initial.set_config(enabled=True, persist_bans=True)["ok"]
        legacy = {"bans": {"::ffff:127.0.0.1": {
            "until": None, "started": 1, "permanent": True, "count": 1}},
            "restrictions": {}}
        assert write_signed_json(initial._bans_path, legacy, initial._state_key)
        restarted = pipeline.NetShield(state_dir=state)
        assert restarted.is_banned_fast("127.0.0.1")
        assert restarted.reload_bans()["ok"] is False
        assert restarted.is_banned_fast("127.0.0.1")


def test_tampered_signed_ban_before_cluster_start_never_serves_stale_memory():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-ban-preflight-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        initial = pipeline.NetShield(state_dir=state)
        assert initial.set_config(enabled=True, block_page=False,
                                  persist_bans=True)["ok"]
        assert initial.ban("192.0.2.2", permanent=True)["ok"]
        shield = pipeline.NetShield(state_dir=state)
        assert shield.is_banned_fast("192.0.2.2")
        Path(shield._bans_path + ".hw").write_text("tampered", encoding="ascii")
        old_shield, old_firewall = pipeline._SHIELD, policy._FW
        pipeline._SHIELD = shield
        policy._FW = policy.AppFirewall(state_dir=state)
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        try:
            started = edge.serve_cluster(workers=2)
            assert started.get("ok") is False, started
            assert not edge.is_alive() and not edge._workers
            with socket.socket() as client:
                client.settimeout(.3)
                try:
                    client.connect(("127.0.0.1", edge.listen_port))
                except OSError:
                    pass
                else:
                    raise AssertionError("tampered cluster opened its listener")
            assert b"GET " not in _received(backend_report)
            assert shield._ban_state_untrusted is True
        finally:
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            pipeline._SHIELD, policy._FW = old_shield, old_firewall
