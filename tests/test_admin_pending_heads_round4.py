"""Partial unauthenticated heads must leave capacity for real admin requests."""

import socket
import threading
import time
from unittest.mock import patch

import dataplane.admin as A
from test_falco_admin_boundaries import _Admin, _signed


def _wait_slots(server, handlers, pending, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (server._handler_slots._value == handlers
                and server._pending_head_slots._value == pending):
            return
        time.sleep(0.01)
    actual = (server._handler_slots._value, server._pending_head_slots._value)
    assert actual == (handlers, pending), (actual, (handlers, pending))


def _partial(port):
    client = socket.create_connection(("127.0.0.1", port), timeout=1)
    client.sendall(b"G")
    return client


def test_partial_heads_cannot_exhaust_authenticated_admin_capacity():
    with patch.object(A, "_ADMIN_MAX_HANDLERS", 4), \
            patch.object(A, "_ADMIN_PENDING_HEAD_MAX", 2, create=True):
        with _Admin() as admin:
            credential = [("X-Token", admin.token)]
            assert admin.request(credential, method="GET", body=b"")[0] == 200
            clients = []
            try:
                for _ in range(4):
                    clients.append(_partial(admin.port))
                # The old implementation filled all four handler slots here.
                deadline = time.monotonic() + 0.5
                while admin.adm._server._handler_slots._value > 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                time.sleep(0.03)
                signed = _signed(admin, "GET", "/api/state", b"")
                status, _, _ = admin.request(signed, method="GET", body=b"")
                assert status == 200
                assert len(admin.adm._browser_nonces) == 1
                assert admin.adm._server._handler_slots._value >= 1
            finally:
                for client in clients:
                    client.close()
            _wait_slots(admin.adm._server, 4, 2)
            assert admin.request(credential, method="GET", body=b"")[0] == 200


def test_pending_head_deadline_releases_both_budgets():
    with patch.object(A, "_ADMIN_MAX_HANDLERS", 4), \
            patch.object(A, "_ADMIN_PENDING_HEAD_MAX", 2, create=True), \
            patch.object(A, "_ADMIN_HEAD_DEADLINE_SEC", 1.5):
        with _Admin() as admin:
            clients = [_partial(admin.port) for _ in range(2)]
            try:
                server = admin.adm._server
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    with server._pending_head_lock:
                        if len(server._pending_heads) == 2:
                            break
                    time.sleep(0.01)
                else:
                    raise AssertionError("partial heads were not admitted")
                _wait_slots(server, 4, 2, timeout=3.0)
                assert admin.request([("X-Token", admin.token)],
                                     method="GET", body=b"")[0] == 200
            finally:
                for client in clients:
                    client.close()


def test_stop_interrupts_and_releases_pending_heads():
    with patch.object(A, "_ADMIN_MAX_HANDLERS", 4), \
            patch.object(A, "_ADMIN_PENDING_HEAD_MAX", 2, create=True), \
            patch.object(A, "_ADMIN_HEAD_DEADLINE_SEC", 0.5):
        with _Admin() as admin:
            server = admin.adm._server
            client = _partial(admin.port)
            try:
                _wait_slots(server, 3, 1)
                assert admin.adm.stop()["ok"] is True
                assert server._pending_head_slots._value == 2
                _wait_slots(server, 4, 2, timeout=1.5)
            finally:
                client.close()


def test_pending_head_slot_is_released_if_thread_start_fails():
    with patch.object(A, "_ADMIN_MAX_HANDLERS", 4), \
            patch.object(A, "_ADMIN_PENDING_HEAD_MAX", 2, create=True):
        with _Admin() as admin:
            server = admin.adm._server
            called = threading.Event()

            def fail_start(_server, _request, _address):
                called.set()
                raise RuntimeError("synthetic thread-start failure")

            with patch.object(A.ThreadingHTTPServer, "process_request", fail_start), \
                    patch.object(server, "handle_error", lambda *_: None):
                client = _partial(admin.port)
                try:
                    assert called.wait(1)
                finally:
                    client.close()
            _wait_slots(server, 4, 2)
            assert admin.request([("X-Token", admin.token)],
                                 method="GET", body=b"")[0] == 200
