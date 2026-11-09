"""A cluster must never acknowledge a defense change absent from its workers."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
import select
import signal
import socket
import tempfile
from unittest import SkipTest
from unittest.mock import patch


from dataplane import admin as ad
from dataplane.engine.lifeform import pipeline as nd
from dataplane.engine.lifeform import policy as fw
from dataplane.engine.services.proxy import AsyncEdgeGuard


def _port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _request(port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.settimeout(3)
        conn.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: test.local\r\n\r\n")
        conn.shutdown(socket.SHUT_WR)
        out = bytearray()
        while True:
            part = conn.recv(65536)
            if not part:
                return bytes(out)
            out.extend(part)


def _admin_post(dashboard, path, body):
    conn = http.client.HTTPConnection("127.0.0.1", dashboard.port, timeout=4)
    try:
        conn.request("POST", path, body=json.dumps(body).encode(), headers={
            "X-Token": dashboard.token, "Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def _admin_state(dashboard):
    conn = http.client.HTTPConnection("127.0.0.1", dashboard.port, timeout=4)
    try:
        conn.request("GET", "/api/state", headers={"X-Token": dashboard.token})
        response = conn.getresponse()
        assert response.status == 200, response.status
        return json.loads(response.read())
    finally:
        conn.close()


def _backend(response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                          b"Connection: close\r\n\r\nok", release_after=1):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            pending = []
            while True:
                client, _ = listener.accept()
                client.settimeout(3)
                req = bytearray()
                while b"\r\n\r\n" not in req and len(req) < 65536:
                    part = client.recv(65536)
                    if not part:
                        break
                    req.extend(part)
                os.write(write_fd, bytes(req).split(b"\r\n", 1)[0] + b"\n")
                pending.append(client)
                if len(pending) >= release_after:
                    for ready in pending:
                        with ready:
                            ready.sendall(response)
                    pending.clear()
        except BaseException:
            pass
        os._exit(0)
    listener.close()
    os.close(write_fd)
    return port, pid, read_fd


def _received(fd):
    data = bytearray()
    while select.select([fd], [], [], 0.01)[0]:
        data.extend(os.read(fd, 65536))
    return bytes(data)


def _stateless_before_fork(shield, firewall):
    assert shield.set_config(enabled=False, block_page=False,
                             max_total_conn=0, max_conn_per_ip=0,
                             conn_rate_per_ip=0)["ok"]
    assert firewall.disable()["ok"]


def test_cluster_admin_rule_ack_after_safe_downgrade():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    old_shield, old_firewall = nd._SHIELD, fw._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r14-admin-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        nd._SHIELD = nd.NetShield(state_dir=state)
        fw._FW = fw.AppFirewall(state_dir=state)
        _stateless_before_fork(nd._SHIELD, fw._FW)
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        dashboard = None
        try:
            info = edge.serve_cluster(workers=2)
            assert info.get("ok") and info.get("mode") == "cluster", info
            assert len(info.get("child_pids") or []) == 1, info
            before = _request(edge.listen_port, b"/before")
            assert before.startswith(b"HTTP/1.1 200"), before
            assert b"GET /before" in _received(backend_report)
            dashboard = ad.AdminDashboard(host="127.0.0.1", port=0,
                                          token="r14-admin-probe", state_dir=state,
                                          edge_guard=edge)
            assert dashboard.start().get("ok") is True
            post_status, update = _admin_post(
                dashboard, "/api/shield/config",
                {"enabled": True, "blocked_urls": ["/vault-round14"]})
            assert post_status == 200 and update.get("ok") is True, (post_status, update)
            status = _admin_state(dashboard)
            assert "/vault-round14" in status["shield"]["cfg"]["blocked_urls"], status

            codes = []
            for _ in range(32):
                wire = _request(edge.listen_port, b"/vault-round14")
                codes.append(wire.split(b"\r\n", 1)[0].decode("ascii", "replace"))
            shield_backend = _received(backend_report)
            assert not any(" 200 " in c for c in codes), codes
            assert b"GET /vault-round14" not in shield_backend, shield_backend
            assert update.get("cluster_downgraded") is True, update
            assert update.get("cluster_mode") == "single", update
            assert not edge._workers and edge.is_alive()

            toggle_status, toggle = _admin_post(
                dashboard, "/api/firewall/toggle", {"on": True})
            assert toggle_status == 200 and toggle.get("ok") is True, (toggle_status, toggle)
            acl_post_status, acl_update = _admin_post(
                dashboard, "/api/firewall/rule",
                {"net": "127.0.0.1/32", "action": "deny"})
            assert acl_post_status == 200 and acl_update.get("ok") is True, (
                acl_post_status, acl_update)
            acl_state = _admin_state(dashboard)
            assert any(r["action"] == "deny" and r["net"] == "127.0.0.1/32"
                       for r in acl_state["firewall"]["rules"]), acl_state
            acl_codes = []
            for _ in range(32):
                wire = _request(edge.listen_port, b"/acl-round14")
                acl_codes.append(wire.split(b"\r\n", 1)[0].decode("ascii", "replace"))
            assert not any(" 200 " in c for c in acl_codes), acl_codes
            assert b"GET /acl-round14" not in _received(backend_report)
        finally:
            if dashboard is not None:
                dashboard.stop()
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            nd._SHIELD, fw._FW = old_shield, old_firewall


def test_finite_egress_quota_uses_single_worker_before_any_fork():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    old_shield, old_firewall = nd._SHIELD, fw._FW
    body = b"public-data-" * 13
    response = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body)
    cap = 300
    assert len(response) < cap < 2 * len(response)
    for mode in ("enforce", "audit"):
        with tempfile.TemporaryDirectory(prefix="ducknet-r14-quota-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            nd._SHIELD = nd.NetShield(state_dir=state)
            fw._FW = fw.AppFirewall(state_dir=state)
            configured = nd._SHIELD.set_config(
                enabled=True, mode=mode, quota_enabled=True,
                quota_max_gb=cap / 1e9, persist_bans=False, usage_record=False,
                dlp_enabled=False, sec_headers_enabled=False,
                cookie_harden_enabled=False, cors_harden_enabled=False,
                open_redirect_enabled=False)
            assert configured["ok"], configured
            backend_port, backend_pid, backend_report = _backend(response, release_after=2)
            edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                                  listen_host="127.0.0.1", listen_port=_port())
            try:
                info = edge.serve_cluster(workers=2)
                assert info.get("ok") and info.get("mode") == "single", info
                assert not info.get("child_pids") and not edge._workers, info
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(_request, edge.listen_port, b"/download")
                               for _ in range(2)]
                    wires = [future.result(timeout=8) for future in futures]
                assert _received(backend_report).count(b"GET /download") == 2
                if mode == "enforce":
                    assert sum(map(len, wires)) <= cap, list(map(len, wires))
                    assert any(wire != response for wire in wires)
                else:
                    assert wires == [response, response], wires
                    assert any(e.get("kind") == "audit" and
                               e.get("rule") == "quota_exceeded"
                               for e in nd._SHIELD.events(100))
            finally:
                edge.stop(grace=0)
                os.kill(backend_pid, signal.SIGTERM)
                os.waitpid(backend_pid, 0)
                os.close(backend_report)
                nd._SHIELD, fw._FW = old_shield, old_firewall


def test_unreaped_cluster_worker_cannot_ack_new_admin_protection():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    old_shield, old_firewall = nd._SHIELD, fw._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r14-reap-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        nd._SHIELD = nd.NetShield(state_dir=state)
        fw._FW = fw.AppFirewall(state_dir=state)
        _stateless_before_fork(nd._SHIELD, fw._FW)
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        dashboard = None
        try:
            info = edge.serve_cluster(workers=2)
            assert info.get("ok") and info.get("mode") == "cluster", info
            dashboard = ad.AdminDashboard(host="127.0.0.1", port=0,
                                          token="r14-reap-probe", state_dir=state,
                                          edge_guard=edge)
            assert dashboard.start().get("ok") is True
            with patch.object(edge, "_stop_workers", return_value=0):
                code, rejected = _admin_post(
                    dashboard, "/api/shield/config",
                    {"enabled": True, "blocked_urls": ["/reap-round14"]})
            assert code == 503 and rejected.get("ok") is False, (code, rejected)
            assert "/reap-round14" not in _admin_state(dashboard)["shield"]["cfg"][
                "blocked_urls"]
            assert edge._workers, "unreaped worker ownership must remain visible"
            wire = _request(edge.listen_port, b"/reap-round14")
            assert wire.startswith(b"HTTP/1.1 200") and b"GET /reap-round14" in _received(
                backend_report), wire
        finally:
            if dashboard is not None:
                dashboard.stop()
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            nd._SHIELD, fw._FW = old_shield, old_firewall


def test_concurrent_admin_changes_quiesce_cluster_once_before_ack():
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    old_shield, old_firewall = nd._SHIELD, fw._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r14-concurrent-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        nd._SHIELD = nd.NetShield(state_dir=state)
        fw._FW = fw.AppFirewall(state_dir=state)
        _stateless_before_fork(nd._SHIELD, fw._FW)
        backend_port, backend_pid, backend_report = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        dashboard = None
        try:
            assert edge.serve_cluster(workers=2).get("mode") == "cluster"
            dashboard = ad.AdminDashboard(host="127.0.0.1", port=0,
                                          token="r14-concurrent-probe", state_dir=state,
                                          edge_guard=edge)
            assert dashboard.start().get("ok") is True
            posts = (("/api/shield/config", {"enabled": True,
                                            "blocked_urls": ["/concurrent-round14"]}),
                     ("/api/firewall/toggle", {"on": True}))
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(_admin_post, dashboard, path, body)
                           for path, body in posts]
                results = [future.result(timeout=10) for future in futures]
            assert all(code == 200 and body.get("ok") is True
                       for code, body in results), results
            assert sum(body.get("cluster_downgraded") is True
                       for _, body in results) == 1, results
            assert not edge._workers and edge.is_alive()
            state_now = _admin_state(dashboard)
            assert "/concurrent-round14" in state_now["shield"]["cfg"]["blocked_urls"]
            assert state_now["firewall"]["enabled"] is True
            for _ in range(12):
                assert not _request(edge.listen_port, b"/concurrent-round14").startswith(
                    b"HTTP/1.1 200")
            assert b"GET /concurrent-round14" not in _received(backend_report)
        finally:
            if dashboard is not None:
                dashboard.stop()
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(backend_report)
            nd._SHIELD, fw._FW = old_shield, old_firewall
