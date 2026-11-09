"""Unauthenticated rejected bodies must leave admin handler capacity."""

import http.client
import json
import socket
import time

from test_falco_admin_boundaries import _Admin, _signed


_ATTACK = (b"POST /api/shield/toggle HTTP/1.1\r\n"
           b"Host: 127.0.0.1\r\nX-Token: wrong-token\r\n"
           b"Content-Length: 1048576\r\n\r\n")


def _state(admin):
    return admin.request(_signed(admin, "GET", "/api/state", b""),
                         method="GET", body=b"")


def test_rejected_body_waits_leave_authenticated_admin_capacity():
    with _Admin() as admin:
        status, _, _ = _state(admin)
        assert status == 200
        before = admin.sh.is_enabled()
        assert admin.adm.audit_log()["entries"] == []
        peers = []
        try:
            # Default production limits: 64 handlers, 8 incomplete heads.
            # Each complete, unauthenticated head claims a 1 MiB body but sends
            # no body bytes. The pre-fix server spends 0.2 s draining each.
            for _ in range(64):
                peer = socket.create_connection(("127.0.0.1", admin.port), timeout=2)
                peer.sendall(_ATTACK)
                peers.append(peer)
            try:
                during, _, wire_body = _state(admin)
            except (OSError, http.client.HTTPException) as exc:
                raise AssertionError(f"authenticated GET lost under reject flood: {exc!r}") from exc
            assert during == 200 and isinstance(json.loads(wire_body)["shield"], dict)
        finally:
            for peer in peers:
                peer.close()
        deadline = time.monotonic() + 1.0
        while admin.adm._server._handler_slots._value != 64 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert admin.adm._server._handler_slots._value == 64
        assert _state(admin)[0] == 200
        assert admin.sh.is_enabled() is before
        assert admin.adm.audit_log()["entries"] == []


def test_ordinary_unauthenticated_post_still_receives_exact_401_body():
    with _Admin() as admin:
        before = admin.sh.is_enabled()
        status, _, body = admin.request([("X-Token", "wrong-token")],
                                        method="POST", body=b'{"on":false}')
        assert status == 401
        assert json.loads(body) == {"ok": False, "error": "token required"}
        assert admin.sh.is_enabled() is before
        assert admin.adm.audit_log()["entries"] == []
