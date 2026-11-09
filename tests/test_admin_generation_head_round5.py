"""Admin header admission and stop must agree with live request ownership."""

import http.client
import os
import socket
import threading
import time
from unittest.mock import patch

import dataplane.admin as A
from test_falco_admin_boundaries import _Admin, _signed


def _wait_pending(server, count, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with server._pending_head_lock:
            current = len(server._pending_heads)
        if current == count:
            return
        time.sleep(0.01)
    assert current == count, current


def _headers(admin, credentials, body):
    lines = [b"POST /api/shield/toggle HTTP/1.1",
             ("Host: 127.0.0.1:%d" % admin.port).encode(),
             ("Content-Length: %d" % len(body)).encode()]
    lines.extend((name + ": " + value).encode() for name, value in credentials)
    return b"\r\n".join(lines) + b"\r\n\r\n"


def _finish_socket(client, rest):
    try:
        client.sendall(rest)
        client.settimeout(2)
        response = client.recv(4096)
    except OSError:
        response = b""
    finally:
        client.close()
    return response.split(b"\r\n", 1)[0]


def test_nine_kilobyte_complete_admin_head_passes_with_pending_pool_full():
    with patch.object(A, "_ADMIN_MAX_HANDLERS", 4), \
            patch.object(A, "_ADMIN_PENDING_HEAD_MAX", 2):
        with _Admin() as admin:
            headers = [("X-Token", admin.token), ("X-Padding", "A" * 9000)]
            assert admin.request(headers, method="GET", body=b"")[0] == 200
            peers = []
            try:
                for _ in range(2):
                    client = socket.create_connection(("127.0.0.1", admin.port), timeout=2)
                    client.sendall(b"G")
                    peers.append(client)
                _wait_pending(admin.adm._server, 2)
                assert admin.request(headers, method="GET", body=b"")[0] == 200
            finally:
                for client in peers:
                    client.close()
            assert admin.request(headers, method="GET", body=b"")[0] == 200


def test_head_over_parser_budget_is_rejected_before_browser_nonce():
    with _Admin() as admin:
        signed = _signed(admin, "GET", "/api/state", b"")
        padded = signed + [("X-Padding-%d" % i, "A" * 7000) for i in range(10)]
        before = len(admin.adm._browser_nonces)
        assert admin.request(padded, method="GET", body=b"")[0] == 431
        assert len(admin.adm._browser_nonces) == before
        assert admin.request(signed, method="GET", body=b"")[0] == 200


def test_stop_prevents_cli_and_old_browser_post_from_committing():
    for browser in (False, True):
        with _Admin() as admin:
            assert admin.sh.enable()["ok"]
            body = b'{"on":false}'
            credentials = (_signed(admin, "POST", "/api/shield/toggle", body)
                           if browser else [("X-Token", admin.token)])
            old_instance = admin.adm._browser_instance_id
            old_server = admin.adm._server
            client = socket.create_connection(("127.0.0.1", admin.port), timeout=2)
            try:
                client.sendall(_headers(admin, credentials, body) + body[:1])
                if browser:
                    deadline = time.monotonic() + 1
                    while not admin.adm._browser_nonces and time.monotonic() < deadline:
                        time.sleep(0.01)
                    assert admin.adm._browser_nonces
                assert admin.adm.stop()["ok"] is True
                if browser:
                    admin.adm.port = 0
                    assert admin.adm.start()["ok"] is True
                    admin.port = admin.adm.port
                    assert admin.adm._browser_instance_id != old_instance
                status_line = _finish_socket(client, body[1:])
                assert not status_line.startswith(b"HTTP/1.0 200"), status_line
                assert admin.sh.is_enabled() is True
                assert not os.path.exists(os.path.join(admin.tmp.name, "admin_audit.jsonl"))
                deadline = time.monotonic() + 2
                while old_server._handler_slots._value != 64 and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert old_server._handler_slots._value == 64
                if browser:
                    fresh = _signed(admin, "POST", "/api/shield/toggle", body)
                    status, _, data = admin.request(fresh, method="POST", body=body)
                    assert status == 200 and b'"ok": true' in data
                    assert admin.sh.is_enabled() is False
            finally:
                client.close()


def test_old_browser_get_cannot_serve_new_generation_state():
    with _Admin() as admin:
        old_instance = admin.adm._browser_instance_id
        old_state = admin.adm.state
        entered, release = threading.Event(), threading.Event()
        result = []

        def delayed_state():
            entered.set()
            assert release.wait(3)
            return old_state()

        admin.adm.state = delayed_state
        signed = _signed(admin, "GET", "/api/state", b"")

        def request_old():
            try:
                result.append(admin.request(signed, method="GET", body=b"")[0])
            except (OSError, http.client.HTTPException):
                result.append(None)

        worker = threading.Thread(target=request_old)
        worker.start()
        try:
            assert entered.wait(2)
            assert admin.adm.stop()["ok"] is True
            assert admin.sh.disable()["ok"]
            admin.adm.port = 0
            assert admin.adm.start()["ok"] is True
            admin.port = admin.adm.port
            assert admin.adm._browser_instance_id != old_instance
            release.set()
            worker.join(timeout=3)
            assert not worker.is_alive() and result and result[0] != 200, result
            fresh = _signed(admin, "GET", "/api/state", b"")
            assert admin.request(fresh, method="GET", body=b"")[0] == 200
        finally:
            release.set()
            worker.join(timeout=3)


def test_stop_does_not_wait_for_nonreading_authenticated_response_client():
    with _Admin() as admin:
        admin.adm.state = lambda: {"blob": "X" * (8 * 1024 * 1024)}
        entered = threading.Event()
        handler = admin.adm._server.RequestHandlerClass
        original_send = handler._send

        def observed_send(self, *args, **kwargs):
            if self.path == "/api/state":
                entered.set()
            return original_send(self, *args, **kwargs)

        with patch.object(handler, "_send", observed_send):
            client = socket.socket()
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            client.settimeout(2)
            try:
                client.connect(("127.0.0.1", admin.port))
                client.sendall(("GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                "X-Token: %s\r\nConnection: close\r\n\r\n"
                                % (admin.port, admin.token)).encode())
                assert entered.wait(2)
                time.sleep(0.1)
                began = time.monotonic()
                assert admin.adm.stop()["ok"] is True
                assert time.monotonic() - began < 2.0
            finally:
                client.close()
