"""A cooperative but delayed admin HTTP loop must not be rejected at startup."""

import http.client
import tempfile
import threading
import time
from unittest.mock import patch

from dataplane import admin as A


def test_delayed_serving_thread_can_prove_real_http_readiness():
    with tempfile.TemporaryDirectory() as state:
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        original = A.ThreadingHTTPServer.serve_forever
        threads = []

        def delayed(server, *args, **kwargs):
            threads.append(threading.current_thread())
            time.sleep(2.2)
            if server.socket.fileno() < 0:
                return  # Old code closed the listener before the server could run.
            return original(server, *args, **kwargs)

        try:
            with patch.object(A.ThreadingHTTPServer, "serve_forever", delayed):
                begin = time.monotonic()
                result = dashboard.start()
                elapsed = time.monotonic() - begin
            assert result.get("ok") is True, (result, elapsed)
            assert 2.2 <= elapsed < 6.5, elapsed
            conn = http.client.HTTPConnection("127.0.0.1", dashboard.port, timeout=1)
            try:
                conn.request("GET", "/api/state", headers={"Host": "localhost"})
                response = conn.getresponse()
                assert response.status == 401 and b"token required" in response.read()
            finally:
                conn.close()
        finally:
            if dashboard._server is not None:
                assert dashboard.stop().get("ok") is True
            for thread in threads:
                thread.join(timeout=3)
                assert not thread.is_alive()


def test_healthy_slow_accept_does_not_exhaust_readiness_retries():
    # Under host load, a healthy listener can take longer than a short socket
    # timeout to accept a request. Repeatedly abandoning those probes must not
    # make startup fail despite an eventual real HTTP response.
    with tempfile.TemporaryDirectory() as state:
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        original = A.ThreadingHTTPServer.process_request

        def slow_accept(server, request, client_address):
            time.sleep(0.45)
            return original(server, request, client_address)

        try:
            with patch.object(A.ThreadingHTTPServer, "process_request", slow_accept):
                begin = time.monotonic()
                result = dashboard.start()
                elapsed = time.monotonic() - begin
            assert result.get("ok") is True, (result, elapsed)
            assert elapsed < 6.5, elapsed
            conn = http.client.HTTPConnection("127.0.0.1", dashboard.port, timeout=2)
            try:
                conn.request("GET", "/api/state", headers={"Host": "localhost"})
                response = conn.getresponse()
                assert response.status == 401 and b"token required" in response.read()
            finally:
                conn.close()
        finally:
            if dashboard._server is not None:
                assert dashboard.stop().get("ok") is True


def test_readiness_retries_do_not_flood_a_very_slow_healthy_accept_loop():
    with tempfile.TemporaryDirectory() as state:
        dashboard = A.AdminDashboard(host="127.0.0.1", port=0,
                                     token="isolated-test-token", state_dir=state)
        original = A.ThreadingHTTPServer.process_request

        def slow_accept(server, request, client_address):
            time.sleep(1.2)
            return original(server, request, client_address)

        try:
            with patch.object(A.ThreadingHTTPServer, "process_request", slow_accept):
                begin = time.monotonic()
                result = dashboard.start()
                elapsed = time.monotonic() - begin
            assert result.get("ok") is True, (result, elapsed)
            assert elapsed < 6.5, elapsed
            conn = http.client.HTTPConnection("127.0.0.1", dashboard.port, timeout=2)
            try:
                conn.request("GET", "/api/state", headers={"Host": "localhost"})
                response = conn.getresponse()
                assert response.status == 401 and b"token required" in response.read()
            finally:
                conn.close()
        finally:
            if dashboard._server is not None:
                assert dashboard.stop().get("ok") is True
