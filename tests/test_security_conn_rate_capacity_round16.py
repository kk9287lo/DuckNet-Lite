"""Connection-rate table fullness must not reset active source windows."""

import os
import socket
import tempfile
import time
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
import dataplane.engine.services.proxy as proxy
from test_sweep_proxy_request import _Backend, _guard


def _request(port, source_ip, path):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2,
                                      source_address=(source_ip, 0)) as conn:
            conn.settimeout(2)
            conn.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: test.local\r\n\r\n")
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            wire = bytearray()
            try:
                while True:
                    part = conn.recv(65536)
                    if not part:
                        break
                    wire.extend(part)
            except OSError:
                pass
            return bytes(wire)
    except OSError:
        return b""


def test_conn_rate_capacity_keeps_existing_ip_window_on_real_wire():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-conn-cap-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = pipeline.NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 rate_per_sec=1000, burst=1000,
                                 conn_rate_per_ip=1, max_total_conn=0)["ok"]
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall), \
                    patch.object(proxy, "_CONN_RATE_CAP", 2), _guard(backend) as edge:
                started = time.monotonic()
                cases = (("127.0.0.2", b"/a-first"),
                         ("127.0.0.2", b"/a-second-no-churn"),
                         ("127.0.0.3", b"/b-first"),
                         ("127.0.0.4", b"/c-first"),
                         ("127.0.0.2", b"/a-after-churn"))
                wires = [_request(edge.listen_port, ip, path) for ip, path in cases]
                elapsed = time.monotonic() - started
            assert elapsed < 1.0, "timing control exceeded the one-second window"
            assert wires[0].startswith(b"HTTP/1.1 200"), wires
            assert wires[2].startswith(b"HTTP/1.1 200"), wires
            for index in (1, 3, 4):
                assert not wires[index].startswith(b"HTTP/1.1 200"), wires
            upstream = backend.saw()
            assert b"GET /a-first" in upstream and b"GET /b-first" in upstream
            assert b"GET /c-first" not in upstream
            assert b"GET /a-after-churn" not in upstream
        finally:
            backend.close()


def test_conn_rate_expired_oldest_reuses_slot_without_active_eviction():
    edge = proxy.AsyncEdgeGuard(listen_port=0)
    now = [1000.0]
    with patch.object(proxy, "_CONN_RATE_CAP", 2), \
            patch.object(proxy.time, "monotonic", side_effect=lambda: now[0]):
        assert edge._conn_rate_exceeded("127.0.0.2", 1) is False
        assert edge._conn_rate_exceeded("127.0.0.3", 1) is False
        assert edge._conn_rate_exceeded("127.0.0.4", 1) is True
        assert edge._conn_rate_exceeded("127.0.0.2", 1) is True
        now[0] += 1.1
        assert edge._conn_rate_exceeded("127.0.0.4", 1) is False
        assert len(edge._conn_rate) == 2
