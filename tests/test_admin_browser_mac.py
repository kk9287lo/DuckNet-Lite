"""Real HTTP checks for browser request and response authentication."""

import contextlib
import hashlib
import hmac
import json
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import patch
from unittest import SkipTest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from types import SimpleNamespace

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
import dataplane.admin as admin_module
from dataplane.admin import AdminDashboard


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signed(token, instance, method, path, body=b"", *, nonce=None, timestamp=None):
    nonce = nonce or secrets.token_hex(16)
    timestamp = str(int(time.time() * 1000) if timestamp is None else timestamp)
    digest = _sha(body)
    message = f"{instance}\n{method}\n{path}\n{timestamp}\n{nonce}\n{digest}".encode()
    mac = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
    return {"X-Admin-Auth-Instance": instance,
            "X-Admin-Auth-Time": timestamp,
            "X-Admin-Auth-Nonce": nonce,
            "X-Admin-Auth-Body": digest,
            "X-Admin-Auth-Mac": mac,
            "Content-Type": "application/json"}


def _call(base, method, path, headers, body=None):
    request = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    try:
        return response.status, response.headers, response.read()
    finally:
        response.close()


def _response_is_signed(token, instance, nonce, status, headers, body):
    expected = hmac.new(token.encode(),
                        f"{instance}\n{nonce}\n{status}\n{_sha(body)}".encode(),
                        hashlib.sha256).hexdigest()
    assert hmac.compare_digest(headers.get("X-Admin-Response-Mac") or "", expected)


@contextlib.contextmanager
def _clocked_browser_auth(max_nonces=2):
    """Drive the real admission method with separate controllable clocks."""
    class Clock:
        wall = 1_000_000.0
        mono = 10_000.0

        def time(self):
            return self.wall

        def monotonic(self):
            return self.mono

    with tempfile.TemporaryDirectory() as state_dir:
        app = AdminDashboard(token="synthetic-clock-secret", state_dir=state_dir)
        app._browser_instance_id = "1" * 32
        handler_type = admin_module._make_handler(app)
        clock = Clock()

        def signed(nonce, offset_ms=0):
            return _signed(app.token, app._browser_instance_id, "GET", "/api/state",
                           nonce=nonce, timestamp=int(clock.wall * 1000) + offset_ms)

        def authorize(headers):
            handler = object.__new__(handler_type)
            handler.command, handler.path = "GET", "/api/state"
            handler.headers = Message()
            for name, value in headers.items():
                handler.headers[name] = value
            return handler._auth()

        with patch.object(admin_module, "time", clock), \
                patch.object(admin_module, "_BROWSER_NONCE_MAX", max_nonces):
            yield app, clock, signed, authorize


def test_browser_nonce_rejects_replay_at_exact_timestamp_window_boundary():
    with _clocked_browser_auth() as (app, clock, signed, authorize):
        original = signed("a" * 32, 30_000)
        assert authorize(original) is True
        clock.wall += 60
        clock.mono += 60
        # Timestamp skew remains inclusive here; its nonce must remain reserved.
        assert authorize(original) is False
        assert len(app._browser_nonces) == 1


def test_browser_nonce_survives_expiry_while_wall_clock_moves_back():
    with _clocked_browser_auth() as (app, clock, signed, authorize):
        original = signed("b" * 32, 30_000)
        assert authorize(original) is True
        clock.mono += 61
        clock.wall += 41  # twenty-second wall-clock correction
        assert authorize(original) is False
        assert len(app._browser_nonces) == 1


def test_browser_nonce_pruned_signature_stays_rejected_after_clock_rollback():
    with _clocked_browser_auth() as (app, clock, signed, authorize):
        original = signed("c" * 32, 30_000)
        assert authorize(original) is True
        clock.mono += 61
        clock.wall += 61
        # A different valid request prunes the fully expired original entry.
        assert authorize(signed("d" * 32)) is True
        assert "c" * 32 not in app._browser_nonces
        clock.mono += 1
        clock.wall -= 20
        assert authorize(original) is False
        # A new, current signature remains usable above the discarded-time floor.
        assert authorize(signed("e" * 32)) is True


def test_browser_nonce_admission_preserves_mac_capacity_skew_and_cli_controls():
    with _clocked_browser_auth() as (app, clock, signed, authorize):
        assert authorize({}) is False
        bad = signed("0" * 32)
        bad["X-Admin-Auth-Mac"] = "0" * 64
        assert authorize(bad) is False
        assert not app._browser_nonces
        past, future = signed("1" * 32, -20_000), signed("2" * 32, 20_000)
        assert authorize(past) is True and authorize(future) is True
        assert authorize(signed("3" * 32)) is False
        assert authorize(past) is False
        assert len(app._browser_nonces) == 2
        assert authorize({"X-Token": app.token}) is True
        assert authorize({"Authorization": "Bearer " + app.token}) is True
        assert len(app._browser_nonces) == 2
        clock.wall += 61
        clock.mono += 61
        assert authorize(signed("4" * 32)) is True
        assert len(app._browser_nonces) == 1


def test_browser_nonce_concurrent_replay_has_one_admitted_request():
    with _clocked_browser_auth(max_nonces=1) as (app, _clock, signed, authorize):
        headers = signed("5" * 32)
        barrier = threading.Barrier(2)

        def call(_):
            barrier.wait(timeout=2)
            return authorize(headers)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(call, range(2)))
        assert sorted(results) == [False, True]
        assert len(app._browser_nonces) == 1


def test_browser_mac_binds_method_path_body_nonce_and_real_response():
    with tempfile.TemporaryDirectory() as state_dir:
        old_shield, old_firewall = ND._SHIELD, FW._FW
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        token = "browser-secret"
        admin = AdminDashboard(host="127.0.0.1", port=0, token=token, state_dir=state_dir)
        assert admin.start()["ok"]
        base = "http://127.0.0.1:" + str(admin.port)
        instance = admin._browser_instance_id
        try:
            get_headers = _signed(token, instance, "GET", "/api/state")
            assert "X-Token" not in get_headers and "Authorization" not in get_headers
            status, headers, body = _call(base, "GET", "/api/state", get_headers)
            assert status == 200 and "shield" in json.loads(body)
            _response_is_signed(token, instance, get_headers["X-Admin-Auth-Nonce"],
                                status, headers, body)
            assert _call(base, "GET", "/api/state", get_headers)[0] == 401  # replay

            for changed in ("/api/metrics", "/api/shield/events"):
                wrong_path = _signed(token, instance, "GET", "/api/state")
                assert _call(base, "GET", changed, wrong_path)[0] == 401
            wrong_method = _signed(token, instance, "GET", "/api/state")
            assert _call(base, "POST", "/api/state", wrong_method, b"{}")[0] == 401

            assert ND._SHIELD.is_enabled() is True
            intended = b'{"on":false}'
            changed_body = b'{"on":true}'
            bad_headers = _signed(token, instance, "POST", "/api/shield/toggle", intended)
            status, headers, body = _call(base, "POST", "/api/shield/toggle",
                                          bad_headers, changed_body)
            assert status == 400 and ND._SHIELD.is_enabled() is True
            _response_is_signed(token, instance, bad_headers["X-Admin-Auth-Nonce"],
                                status, headers, body)
            good_headers = _signed(token, instance, "POST", "/api/shield/toggle", intended)
            status, headers, body = _call(base, "POST", "/api/shield/toggle",
                                          good_headers, intended)
            assert status == 200 and ND._SHIELD.is_enabled() is False
            _response_is_signed(token, instance, good_headers["X-Admin-Auth-Nonce"],
                                status, headers, body)
            assert _call(base, "POST", "/api/shield/toggle", good_headers, intended)[0] == 401

            stale = _signed(token, instance, "GET", "/api/state",
                            timestamp=int(time.time() * 1000) - 60_000)
            assert _call(base, "GET", "/api/state", stale)[0] == 401
            # Existing CLI clients still use their header tokens, including mutations.
            status, cli_headers, _ = _call(base, "GET", "/api/state", {"X-Token": token})
            assert status == 200 and cli_headers.get("X-Admin-Response-Mac") is None
            assert _call(base, "POST", "/api/shield/toggle",
                         {"Authorization": "Bearer " + token,
                          "Content-Type": "application/json"}, b'{"on":true}')[0] == 200
        finally:
            admin.stop()
            ND._SHIELD, FW._FW = old_shield, old_firewall


def test_browser_nonce_cache_is_bounded_and_expired_entries_can_be_replaced():
    with tempfile.TemporaryDirectory() as state_dir, \
            patch.object(admin_module, "_BROWSER_NONCE_MAX", 1):
        admin = AdminDashboard(host="127.0.0.1", port=0, token="secret", state_dir=state_dir)
        assert admin.start()["ok"]
        base = "http://127.0.0.1:" + str(admin.port)
        instance = admin._browser_instance_id
        try:
            first = _signed("secret", instance, "GET", "/api/state",
                            timestamp=int(time.time() * 1000) + 20_000)
            assert _call(base, "GET", "/api/state", first)[0] == 200
            full = _signed("secret", instance, "GET", "/api/state")
            assert _call(base, "GET", "/api/state", full)[0] == 401
            assert _call(base, "GET", "/api/state", first)[0] == 401
            future_wall = time.time() + admin_module._BROWSER_NONCE_TTL_SEC + 1
            future_mono = time.monotonic() + admin_module._BROWSER_NONCE_TTL_SEC + 1
            # Advance both clocks beyond full signature expiry instead of
            # replacing private cache metadata with an artificial scalar.
            clock = SimpleNamespace(time=lambda: future_wall,
                                    monotonic=lambda: future_mono)
            with patch.object(admin_module, "time", clock):
                fresh = _signed("secret", instance, "GET", "/api/state",
                                timestamp=int(future_wall * 1000))
                assert _call(base, "GET", "/api/state", fresh)[0] == 200
            # Restarting this same object resets its retired-time floor while
            # changing the instance challenge, so a corrected clock can recover.
            assert admin.stop()["ok"]
            assert admin.start()["ok"]
            assert admin._browser_instance_id != instance
            base = "http://127.0.0.1:" + str(admin.port)
            assert _call(base, "GET", "/api/state", first)[0] == 401
            current = _signed("secret", admin._browser_instance_id, "GET", "/api/state")
            assert _call(base, "GET", "/api/state", current)[0] == 200
        finally:
            admin.stop()


def test_browser_mac_from_previous_instance_is_rejected_after_restart_with_same_token():
    with tempfile.TemporaryDirectory() as state_dir:
        token = "fixed-token"
        first = AdminDashboard(host="127.0.0.1", port=0, token=token, state_dir=state_dir)
        assert first.start()["ok"]
        old_instance = first._browser_instance_id
        old_base = "http://127.0.0.1:" + str(first.port)
        future = int(time.time() * 1000) + 20_000
        old_headers = _signed(token, old_instance, "GET", "/api/state", timestamp=future)
        try:
            assert _call(old_base, "GET", "/api/state", old_headers)[0] == 200
        finally:
            first.stop()
        second = AdminDashboard(host="127.0.0.1", port=0, token=token, state_dir=state_dir)
        assert second.start()["ok"]
        try:
            assert second._browser_instance_id != old_instance
            base = "http://127.0.0.1:" + str(second.port)
            assert _call(base, "GET", "/api/state", old_headers)[0] == 401
            now_ms = int(time.time() * 1000)
            for offset_ms, expected in ((-20_000, 200), (20_000, 200),
                                        (-40_000, 401), (40_000, 401)):
                fresh = _signed(token, second._browser_instance_id, "GET", "/api/state",
                                timestamp=now_ms + offset_ms)
                assert _call(base, "GET", "/api/state", fresh)[0] == expected
        finally:
            second.stop()


def test_windows_admin_wildcard_listener_excludes_second_bind():
    if not sys.platform.startswith("win"):
        raise SkipTest("Windows SO_EXCLUSIVEADDRUSE is required")
    with tempfile.TemporaryDirectory() as state_dir:
        admin = AdminDashboard(host="0.0.0.0", port=0, token="test-secret",
                               state_dir=state_dir)
        assert admin.start()["ok"]
        port = admin.port
        other = socket.socket()
        try:
            other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                other.bind(("127.0.0.1", port))
            except OSError as exc:
                assert exc.winerror in (10013, 10048)
            else:
                raise AssertionError("another listener bound the admin port")
        finally:
            other.close()
            admin.stop()
        benign = socket.socket()
        try:
            benign.bind(("127.0.0.1", port))
        finally:
            benign.close()
