"""Admin readiness must include release of its own handler slot."""

import socket
import tempfile
import threading
from unittest.mock import patch

from dataplane import admin as A


def test_start_waits_for_its_probe_handler_to_release_capacity():
    with tempfile.TemporaryDirectory() as state, \
            patch.object(A, "_ADMIN_MAX_HANDLERS", 1):
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        original = A.ThreadingHTTPServer.process_request_thread
        body_sent = threading.Event()
        release_handler = threading.Event()
        start_returned = threading.Event()
        outcome = {}

        def hold_probe_finalization(server, request, client_address):
            original(server, request, client_address)
            body_sent.set()  # The 401 and EOF are visible to the startup client.
            release_handler.wait(4)

        def start_dashboard():
            try:
                outcome["result"] = dashboard.start()
            except BaseException as exc:
                outcome["exception"] = exc
            finally:
                start_returned.set()

        worker = threading.Thread(target=start_dashboard, daemon=True)
        try:
            with patch.object(A.ThreadingHTTPServer, "process_request_thread",
                              hold_probe_finalization):
                worker.start()
                assert body_sent.wait(3), "startup HTTP handler never answered"
                assert dashboard._server._handler_slots._value == 0
                # A complete HTTP body does not yet prove an available slot.
                assert not start_returned.wait(1), outcome
                release_handler.set()
                assert start_returned.wait(3), outcome
                assert outcome.get("result", {}).get("ok") is True, outcome
                assert dashboard._server._handler_slots._value == 1

                # The first real request must receive bytes with a one-slot cap.
                with socket.create_connection(("127.0.0.1", dashboard.port), timeout=2) as peer:
                    peer.settimeout(2)
                    peer.sendall(b"GET /api/state HTTP/1.1\r\nHost: localhost\r\n"
                                 b"Connection: close\r\n\r\n")
                    data = bytearray()
                    while True:
                        part = peer.recv(4096)
                        if not part:
                            break
                        data.extend(part)
                assert data.startswith(b"HTTP/1.0 401") and b"token required" in data
        finally:
            release_handler.set()
            if worker.is_alive():
                worker.join(timeout=3)
            assert not worker.is_alive()
            if dashboard._server is not None:
                dashboard.stop()
