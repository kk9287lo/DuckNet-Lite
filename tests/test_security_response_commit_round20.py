"""An acknowledged signed edit must not release an old backend response."""

import os
import socket
import tempfile
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.lifeform import policy as FW
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import _Backend


def _request(port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
        client.settimeout(4)
        client.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: test.local\r\n"
                       b"Connection: close\r\n\r\n")
        client.shutdown(socket.SHUT_WR)
        wire = bytearray()
        while True:
            try:
                part = client.recv(65536)
            except (ConnectionResetError, ConnectionAbortedError):
                break
            if not part:
                break
            wire.extend(part)
        return bytes(wire)


def _case(kind):
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = ND.NetShield(state_dir=state)
        firewall = FW.AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 quota_enabled=True, quota_max_gb=1e-6)["ok"]
        assert firewall.disable()["ok"]
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
                edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                                      listen_host="127.0.0.1", listen_port=0)
                started = edge.start()
                assert started.get("ok"), started
                try:
                    benign = _request(edge.listen_port, b"/response-benign-r20")
                    assert benign.startswith(b"HTTP/1.1 200"), benign[:100]
                    assert b"GET /response-benign-r20" in backend.saw()

                    external = ND.NetShield(state_dir=state)
                    original = edge._checked_client_write
                    committed = []

                    async def commit_after_response_precheck(*args, **kwargs):
                        if not committed:
                            if kind == "config":
                                result = external.set_config(
                                    blocked_urls=["/response-attack-r20"])
                            else:
                                result = external.ban("127.0.0.1", permanent=True)
                            committed.append(result)
                        return await original(*args, **kwargs)

                    # send_response has already verified policy and reserved
                    # quota when it calls this method. Commit immediately
                    # before its final lock/stamp check and client write.
                    with patch.object(edge, "_checked_client_write",
                                      side_effect=commit_after_response_precheck):
                        attack = _request(edge.listen_port, b"/response-attack-r20")
                    assert len(committed) == 1 and committed[0].get("ok") is True, committed
                    assert b"GET /response-attack-r20" in backend.saw(), backend.saw()
                    assert not attack.startswith(b"HTTP/1.1 200"), attack[:100]
                    assert b"\r\n\r\nok" not in attack, attack[:100]

                    prior = backend.saw().count(b"GET /response-attack-r20")
                    after = _request(edge.listen_port, b"/response-attack-r20")
                    assert not after.startswith(b"HTTP/1.1 200"), after[:100]
                    assert backend.saw().count(b"GET /response-attack-r20") == prior
                finally:
                    edge.stop(grace=0)
        finally:
            backend.close()


def test_external_signed_config_ack_before_response_write_sends_no_old_bytes():
    _case("config")


def test_external_signed_ban_ack_before_response_write_sends_no_old_bytes():
    _case("ban")
