"""Real management HTTP controls for credential, origin and body ownership."""
import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import tempfile
import threading
import time
from unittest.mock import patch

import dataplane.admin as A
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW


class _Admin:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_shield, self.old_firewall = ND._SHIELD, FW._FW
        self.sh = ND._SHIELD = ND.NetShield(state_dir=self.tmp.name)
        FW._FW = FW.AppFirewall(state_dir=self.tmp.name)
        self.sh.cfg["persist_bans"] = False
        self.adm = A.AdminDashboard(host="127.0.0.1", port=0, token="fixture-admin-key",
                                    state_dir=self.tmp.name)
        started = self.adm.start()
        assert started.get("ok") is True, started
        self.port, self.token = self.adm.port, self.adm.token
        return self

    def __exit__(self, *exc):
        try:
            assert self.adm.stop()["ok"] is True
        finally:
            ND._SHIELD, FW._FW = self.old_shield, self.old_firewall
            self.tmp.cleanup()

    def request(self, headers, *, method="POST", body=b'{"on":false}', hosts=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            path = "/api/state" if method == "GET" else "/api/shield/toggle"
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for host in hosts or ["127.0.0.1:" + str(self.port)]:
                connection.putheader("Host", host)
            for name, value in headers:
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()


def _signed(admin, method="POST", path="/api/shield/toggle", body=b'{"on":false}'):
    nonce, stamp = secrets.token_hex(16), str(int(time.time() * 1000))
    digest = hashlib.sha256(body).hexdigest()
    message = "\n".join((admin.adm._browser_instance_id, method, path, stamp, nonce, digest))
    signature = hmac.new(admin.token.encode(), message.encode(), hashlib.sha256).hexdigest()
    return [("X-Admin-Auth-Instance", admin.adm._browser_instance_id),
            ("X-Admin-Auth-Time", stamp), ("X-Admin-Auth-Nonce", nonce),
            ("X-Admin-Auth-Body", digest), ("X-Admin-Auth-Mac", signature)]


def test_unique_header_credentials_preserve_cli_controls():
    with _Admin() as admin:
        for credentials in ([('X-Token', admin.token)],
                            [('Authorization', 'Bearer ' + admin.token)],
                            [('X-Token', admin.token), ('Authorization', 'bEaReR ' + admin.token)]):
            assert admin.sh.enable()["ok"]
            status, _, data = admin.request(credentials)
            assert status == 200 and json.loads(data)["ok"] is True, (status, data)
            assert admin.sh.is_enabled() is False


def test_duplicate_and_conflicting_credentials_cannot_mutate_state():
    with _Admin() as admin:
        cases = [[('X-Token', admin.token), ('X-Token', admin.token)],
                 [('Authorization', 'Bearer ' + admin.token), ('Authorization', 'Bearer wrong')],
                 [('X-Token', 'wrong'), ('Authorization', 'Bearer ' + admin.token)],
                 [('X-Token', admin.token), ('Authorization', 'Basic ignored')],
                 [('X-Token', ''), ('Authorization', 'Bearer ' + admin.token)]]
        results = []
        for credentials in cases:
            assert admin.sh.enable()["ok"]
            status, _, _ = admin.request(credentials)
            results.append((status, admin.sh.is_enabled()))
        assert all(row == (401, True) for row in results), results


def test_invalid_explicit_credentials_do_not_fall_back_to_browser_mac():
    with _Admin() as admin:
        results = []
        for explicit in [('X-Token', ''), ('Authorization', 'Basic ignored'),
                         ('Authorization', 'Bearer ')]:
            signed = _signed(admin, "GET", "/api/state", b"")
            first, _, _ = admin.request([explicit] + signed, method="GET", body=b"")
            # Rejecting the explicit credential must not spend a browser nonce.
            second, headers, data = admin.request(signed, method="GET", body=b"")
            expected = hmac.new(admin.token.encode(),
                                (admin.adm._browser_instance_id + "\n" + dict(signed)["X-Admin-Auth-Nonce"]
                                 + "\n200\n" + hashlib.sha256(data).hexdigest()).encode(),
                                hashlib.sha256).hexdigest()
            results.append((first, second, headers.get("X-Admin-Response-Mac") == expected))
        assert all(row == (401, 200, True) for row in results), results


def test_duplicate_host_is_rejected_before_authentication():
    with _Admin() as admin:
        status, _, _ = admin.request([], method="GET", body=b"",
                                     hosts=["127.0.0.1:" + str(admin.port), "other.example.invalid"])
        assert status == 421, status


def test_every_origin_and_referer_must_be_unambiguous_and_consistent():
    with _Admin() as admin, patch.dict(os.environ, {"DUCKNET_ADMIN_ALLOWED_HOSTS": ""}):
        origin = "http://127.0.0.1:" + str(admin.port)
        other = "http://other.example.invalid"
        cases = [[('Origin', origin), ('Referer', other + '/page')],
                 [('Origin', origin), ('Origin', origin)],
                 [('Origin', origin), ('Referer', origin + '/page'), ('Referer', other + '/page')],
                 [('Origin', origin + '/unexpected-path')],
                 [('Origin', origin.replace('http:', 'ftp:'))],
                 [('Origin', origin), ('Referer', origin.replace('http:', 'https:') + '/page')],
                 [('Origin', 'http://user@127.0.0.1:' + str(admin.port))],
                 [('Origin', origin + '/#fragment')],
                 [('Origin', 'http://127.0.0.1:0')],
                 [('Origin', 'http://127.0.0.1:65536')],
                 [('Origin', 'http://127.0.0.1:')]]
        results = []
        for supplied in cases:
            assert admin.sh.enable()["ok"]
            status, _, _ = admin.request([('X-Token', admin.token)] + supplied)
            results.append((status, admin.sh.is_enabled()))
        assert all(row == (403, True) for row in results), results


def test_valid_origins_and_legacy_https_proxy_contract_keep_working():
    with _Admin() as admin, patch.dict(os.environ, {"DUCKNET_ADMIN_ALLOWED_HOSTS": "ops.example"}):
        for origin in ("http://127.0.0.1:" + str(admin.port),
                       "https://127.0.0.1:" + str(admin.port), "https://ops.example:8443"):
            assert admin.sh.enable()["ok"]
            status, _, data = admin.request([('X-Token', admin.token), ('Origin', origin),
                                             ('Referer', origin + '/console?view=main')])
            assert status == 200 and json.loads(data)["ok"] is True, (origin, status, data)
            assert admin.sh.is_enabled() is False


def test_authenticated_body_trickle_expires_and_releases_its_handler():
    with patch.object(A, "_ADMIN_BODY_DEADLINE_SEC", 0.3, create=True), \
            patch.object(A, "_ADMIN_MAX_HANDLERS", 1):
        with _Admin() as admin:
            assert admin.sh.enable()["ok"]
            client = socket.create_connection(("127.0.0.1", admin.port), timeout=2)
            client.settimeout(0.9)
            stop = threading.Event()

            def drip():
                while not stop.wait(0.04):
                    try:
                        client.sendall(b" ")
                    except OSError:
                        return

            sender = threading.Thread(target=drip, daemon=True)
            output = b""
            try:
                client.sendall(("POST /api/shield/toggle HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                "X-Token: %s\r\nContent-Length: 1048576\r\n\r\n "
                                % (admin.port, admin.token)).encode())
                sender.start()
                started = time.monotonic()
                while True:
                    piece = client.recv(65536)
                    if not piece:
                        break
                    output += piece
                assert time.monotonic() - started < 0.8
                assert output.startswith(b"HTTP/1.0 400"), output[:100]
            finally:
                stop.set()
                client.close()
                sender.join(timeout=1)
                assert not sender.is_alive()
            assert admin.sh.is_enabled() is True
            assert not os.path.exists(os.path.join(admin.tmp.name, "admin_audit.jsonl"))
            # With one available slot, a successful new request proves cleanup.
            deadline = time.monotonic() + 1
            while admin.adm._server._handler_slots._value != 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert admin.adm._server._handler_slots._value == 1
            status, _, _ = admin.request([('X-Token', admin.token)], method="GET", body=b"")
            assert status == 200, status


def test_segmented_body_with_browser_mac_keeps_digest_and_response_proof():
    with patch.object(A, "_ADMIN_BODY_DEADLINE_SEC", 0.8, create=True):
        with _Admin() as admin:
            assert admin.sh.enable()["ok"]
            body = b'{"on":false}'
            signed = _signed(admin, body=body)
            connection = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=2)
            try:
                connection.putrequest("POST", "/api/shield/toggle")
                for key, value in signed:
                    connection.putheader(key, value)
                connection.putheader("Content-Length", str(len(body)))
                connection.endheaders()
                connection.send(body[:4])
                time.sleep(0.05)
                connection.send(body[4:])
                response = connection.getresponse()
                data = response.read()
                assert response.status == 200 and json.loads(data)["ok"] is True, data
                proof = hmac.new(admin.token.encode(),
                    (admin.adm._browser_instance_id + "\n" + dict(signed)["X-Admin-Auth-Nonce"]
                     + "\n200\n" + hashlib.sha256(data).hexdigest()).encode(), hashlib.sha256).hexdigest()
                assert response.getheader("X-Admin-Response-Mac") == proof
                assert admin.sh.is_enabled() is False
            finally:
                connection.close()
