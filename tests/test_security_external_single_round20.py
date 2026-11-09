"""A cluster-origin single listener must track external signed policy."""

import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from unittest import SkipTest
from unittest.mock import patch

from dataplane.admin import AdminDashboard
from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.lifeform import policy as FW
from dataplane.engine.services import proxy as Proxy
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_security_cluster_direct_setter_round15 import _cluster, _received
from test_sweep_proxy_request import _Backend


def _request_host(port, path: bytes, host: bytes = b"test.local",
                  extra: bytes = b"") -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
        client.settimeout(4)
        client.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: " + host +
                       b"\r\n" + extra + b"Connection: close\r\n\r\n")
        client.shutdown(socket.SHUT_WR)
        out = bytearray()
        while True:
            try:
                part = client.recv(65536)
            except (ConnectionResetError, ConnectionAbortedError):
                return bytes(out)
            if not part:
                return bytes(out)
            out.extend(part)


def test_external_signed_enable_during_admin_quiesce_never_reopens_old_policy():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("real POSIX fork/SO_REUSEPORT required")
    with _cluster() as (shield, _firewall, edge, report_fd):
        state = str(Path(shield.path).parent)
        workers = list(edge._workers)
        assert workers and edge._cluster_policy_sync
        admin = AdminDashboard(host="127.0.0.1", port=0, state_dir=state,
                               edge_guard=edge)
        assert admin.start().get("ok") is True
        original_quiesce = edge.quiesce_cluster_for_mutation
        external_results = []

        def external_before_reap():
            external = ND.NetShield(state_dir=state)
            result = external.set_config(enabled=True, site_mode="whitelist",
                                         site_whitelist=["safe.example"],
                                         blocked_urls=["/unsafe-r20"])
            external_results.append(result)
            assert result.get("ok") is True, result
            return original_quiesce()

        try:
            with patch.object(edge, "quiesce_cluster_for_mutation",
                              side_effect=external_before_reap):
                body = json.dumps({"rate_per_sec": 25}).encode("utf-8")
                conn = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=8)
                try:
                    conn.request("POST", "/api/shield/config", body=body,
                                 headers={"X-Token": admin.token,
                                          "Content-Type": "application/json"})
                    response = conn.getresponse()
                    status, result = response.status, json.loads(response.read())
                finally:
                    conn.close()
            assert external_results[0]["ok"] is True
            assert status == 200 and result["ok"] is False, (status, result)
            assert result.get("cluster_downgraded") is True
            assert not edge._workers

            attack = _request_host(edge.listen_port, b"/unsafe-r20")
            attack_backend = _received(report_fd)
            assert not attack.startswith(b"HTTP/1.1 200"), attack[:100]
            assert b"GET /unsafe-r20" not in attack_backend, attack_backend
            assert shield.cfg["enabled"] is True
            assert shield.cfg["site_mode"] == "whitelist"

            benign = _request_host(edge.listen_port, b"/safe-r20", b"safe.example")
            benign_backend = _received(report_fd)
            assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
            assert b"GET /safe-r20" in benign_backend, benign_backend
            reloaded = ND.NetShield(state_dir=state)
            assert reloaded.cfg["enabled"] is True
            assert reloaded.cfg["site_whitelist"] == ["safe.example"]
        finally:
            admin.stop()


def test_external_signed_rule_reloads_in_initial_safe_single_fallback():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("real POSIX fork/SO_REUSEPORT required")
    with _cluster(stateful=True) as (shield, _firewall, edge, report_fd):
        assert not edge._workers
        external = ND.NetShield(state_dir=str(Path(shield.path).parent))
        assert external.set_config(blocked_urls=["/unsafe-r20-single"])["ok"]
        attack = _request_host(edge.listen_port, b"/unsafe-r20-single")
        attack_backend = _received(report_fd)
        assert not attack.startswith(b"HTTP/1.1 200"), attack[:100]
        assert b"GET /unsafe-r20-single" not in attack_backend, attack_backend
        benign = _request_host(edge.listen_port, b"/safe-r20-single")
        benign_backend = _received(report_fd)
        assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
        assert b"GET /safe-r20-single" in benign_backend, benign_backend


def test_windows_cluster_fallback_tracks_external_signed_rule_and_tamper():
    if os.name != "nt":
        raise SkipTest("Windows single-worker fallback required")
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
                edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                      listen_host="127.0.0.1", listen_port=0,
                                      health_path="/healthz")
                started = edge.serve_cluster(workers=2)
                assert started.get("ok") and started.get("mode") == "single", started
                try:
                    external = ND.NetShield(state_dir=state)
                    assert external.set_config(blocked_urls=["/unsafe-r20-win"])["ok"]
                    attack = _request_host(edge.listen_port, b"/unsafe-r20-win")
                    assert not attack.startswith(b"HTTP/1.1 200"), attack[:100]
                    assert b"GET /unsafe-r20-win" not in backend.saw(), backend.saw()
                    benign = _request_host(edge.listen_port, b"/safe-r20-win")
                    assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
                    assert b"GET /safe-r20-win" in backend.saw(), backend.saw()
                    Path(shield.path + ".hw").write_text("tampered", encoding="ascii")
                    unavailable = _request_host(edge.listen_port, b"/after-tamper-r20")
                    health = _request_host(edge.listen_port, b"/healthz")
                    assert not unavailable.startswith(b"HTTP/1.1 200")
                    assert b"GET /after-tamper-r20" not in backend.saw()
                    assert health.startswith(b"HTTP/1.1 503"), health[:100]
                finally:
                    edge.stop(grace=0)
        finally:
            backend.close()


def test_cluster_origin_single_starts_with_pristine_signed_state():
    """A fresh empty state directory still has a usable safe-single listener."""
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
                edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                      listen_host="127.0.0.1", listen_port=0)
                started = edge.serve_cluster(workers=1)
                assert started.get("ok") and started.get("mode") == "single", started
                try:
                    benign = _request_host(edge.listen_port, b"/pristine-r20")
                    assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
                    assert b"GET /pristine-r20" in backend.saw(), backend.saw()
                finally:
                    edge.stop(grace=0)
        finally:
            backend.close()


def test_direct_single_reloads_external_signed_policy_and_ban_before_backend():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
                edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                      listen_host="127.0.0.1", listen_port=0)
                started = edge.start()
                assert started.get("ok"), started
                try:
                    external = ND.NetShield(state_dir=state)
                    assert external.set_config(blocked_urls=["/direct-external-r20"])["ok"]
                    attack = _request_host(edge.listen_port, b"/direct-external-r20")
                    assert not attack.startswith(b"HTTP/1.1 200"), attack[:100]
                    assert b"GET /direct-external-r20" not in backend.saw()
                    benign = _request_host(edge.listen_port, b"/direct-safe-r20")
                    assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
                    assert b"GET /direct-safe-r20" in backend.saw()
                    assert external.ban("127.0.0.1", permanent=True)["ok"]
                    banned = _request_host(edge.listen_port, b"/direct-after-ban-r20")
                    assert not banned.startswith(b"HTTP/1.1 200"), banned[:100]
                    assert b"GET /direct-after-ban-r20" not in backend.saw()
                finally:
                    edge.stop(grace=0)
        finally:
            backend.close()


def test_external_signed_quota_history_cannot_reopen_or_be_overwritten():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 quota_enabled=True, quota_max_gb=1e-6,
                                 trusted_proxies=["127.0.0.1/32"])["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
                edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                      listen_host="127.0.0.1", listen_port=0)
                assert edge.start().get("ok")
                try:
                    benign = _request_host(edge.listen_port, b"/quota-benign-r20",
                                           extra=b"X-Forwarded-For: 198.51.100.8\r\n")
                    assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
                    assert b"GET /quota-benign-r20" in backend.saw()
                    external = ND.NetShield(state_dir=state)
                    external._traffic["203.0.113.7"] = {
                        str(external._day()): [1000.0, 0.0, 0.0]}
                    assert external._save_traffic(force=True) is True
                    attack = _request_host(edge.listen_port, b"/quota-attack-r20",
                                           extra=b"X-Forwarded-For: 203.0.113.7\r\n")
                    assert not attack.startswith(b"HTTP/1.1 200"), attack[:100]
                    assert b"GET /quota-attack-r20" not in backend.saw()
                    persisted = ND.NetShield(state_dir=state)
                    assert persisted._traffic["203.0.113.7"][str(persisted._day())][0] == 1000.0
                finally:
                    edge.stop(grace=0)
        finally:
            backend.close()


def test_external_signed_ban_commit_cannot_overtake_backend_write():
    """A signed external BAN ack is ordered after a checked backend write."""
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("real POSIX safe-single listener required")
    with _cluster(stateful=True) as (shield, firewall, edge, report_fd):
        assert shield.cfg["persist_bans"] is True
        assert not edge._workers
        last_source_path = edge._cluster_policy_sources(shield, firewall)[-1]
        original_stamp = Proxy._signed_source_stamp
        observations = {"last_stamp_calls": 0, "early_done": False, "writer": None}
        code = (
            "import json,sys;"
            "from dataplane.engine.lifeform.pipeline import NetShield;"
            "print(json.dumps(NetShield(state_dir=sys.argv[1]).ban("
            "'127.0.0.1', permanent=True)),flush=True)"
        )

        def interleaved_stamp(path):
            stamp = original_stamp(path)
            if path == last_source_path:
                observations["last_stamp_calls"] += 1
                if observations["last_stamp_calls"] == 4:
                    # This is the final signed-source stat, after acquiring
                    # the commit lock and before queuing backend bytes.
                    writer = subprocess.Popen(
                        [sys.executable, "-c", code, str(Path(shield.path).parent)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=os.environ.copy(), text=True,
                    )
                    observations["writer"] = writer
                    until = time.monotonic() + 1.5
                    while writer.poll() is None and time.monotonic() < until:
                        time.sleep(0.005)
                    observations["early_done"] = writer.poll() is not None
            return stamp

        try:
            with patch.object(Proxy, "_signed_source_stamp", side_effect=interleaved_stamp):
                concurrent = _request_host(edge.listen_port, b"/during-ban-r20")
            writer = observations["writer"]
            assert writer is not None and observations["last_stamp_calls"] >= 4
            stdout, stderr = writer.communicate(timeout=8)
            committed = json.loads(stdout)
            assert writer.returncode == 0 and type(committed.get("ok")) is bool, (
                writer.returncode, stdout, stderr)
            early_ack = observations["early_done"] and committed["ok"]
            during_backend = _received(report_fd)
            if early_ack:
                # An acknowledged BAN before this request's first backend
                # byte must invalidate the old admission decision.
                assert not concurrent.startswith(b"HTTP/1.1 200"), concurrent[:100]
                assert b"GET /during-ban-r20" not in during_backend, during_backend
            else:
                assert concurrent.startswith(b"HTTP/1.1 200"), concurrent[:100]
                assert b"GET /during-ban-r20" in during_backend, during_backend
            if not committed["ok"]:
                # The hot-path BAN writer now fails immediately when a
                # request holds the commit barrier. Its short-lived process
                # cannot run the deferred retry timer, so retry explicitly
                # after the response write has released the barrier.
                assert committed.get("persisted") is False, committed
                retry = ND.NetShield(state_dir=str(Path(shield.path).parent))
                retried = retry.ban("127.0.0.1", permanent=True)
                assert retried.get("ok") is True and retried.get("persisted") is True, retried
            after = _request_host(edge.listen_port, b"/after-ban-r20")
            assert not after.startswith(b"HTTP/1.1 200"), after[:100]
            assert b"GET /after-ban-r20" not in _received(report_fd)
        finally:
            writer = observations["writer"]
            if writer is not None and writer.poll() is None:
                writer.kill()
                writer.communicate(timeout=8)
