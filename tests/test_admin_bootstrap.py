"""Admin header auth and tray proof do not disclose the reusable token."""

import contextlib
import http.cookiejar
import http.server
import os
import re
import secrets
import socket
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.admin import AdminDashboard
import dataplane.gui.__main__ as GUI
import dataplane.service as service


@contextlib.contextmanager
def _replace(obj, **values):
    old = {key: getattr(obj, key) for key in values}
    try:
        for key, value in values.items():
            setattr(obj, key, value)
        yield
    finally:
        for key, value in old.items():
            setattr(obj, key, value)


@contextlib.contextmanager
def _env(**values):
    old = {key: os.environ.get(key) for key in values}
    try:
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_real_http_header_auth_and_legacy_cookie_rejection():
    with tempfile.TemporaryDirectory() as state_dir:
        old_shield, old_firewall = ND._SHIELD, FW._FW
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        admin = AdminDashboard(host="127.0.0.1", port=0, token="bootstrap-secret",
                               state_dir=state_dir)
        assert admin.start()["ok"]
        base = "http://127.0.0.1:" + str(admin.port)
        try:
            for url, headers in ((base + "/", {}),
                                 (base + "/?token=wrong", {}),
                                 (base + "/", {"X-Forwarded-For": "203.0.113.7"})):
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers)) as response:
                    assert response.status == 200
                    assert "Max-Age=0" in (response.headers.get("Set-Cookie") or "")
            try:
                urllib.request.urlopen(base + "/api/state")
            except urllib.error.HTTPError as error:
                assert error.code == 401
                error.close()
            else:
                raise AssertionError("anonymous loopback peer reached the admin API")
            with urllib.request.urlopen(base + "/?token=bootstrap-secret") as response:
                cookie = response.headers.get("Set-Cookie") or ""
                html = response.read()
            assert "ducknet_admin=;" in cookie and "Max-Age=0" in cookie
            assert b'sessionStorage.removeItem("ducknet-admin-token")' in html
            assert b"sessionStorage.getItem" not in html and b"sessionStorage.setItem" not in html
            assert b"X-Admin-Auth-Mac" in html and b'if(TOKEN)H["X-Token"]' not in html
            assert b"__AUTH_INSTANCE__" not in html
            assert b"history.replaceState" in html and b"bootstrap-secret" not in html
            for path, data, headers in (
                    ("/api/state", None, {"Cookie": "ducknet_admin=bootstrap-secret"}),
                    ("/api/shield/toggle", b'{"on":true}',
                     {"Cookie": "ducknet_admin=bootstrap-secret",
                      "Content-Type": "application/json"})):
                try:
                    urllib.request.urlopen(urllib.request.Request(base + path, data=data,
                                                                  headers=headers))
                except urllib.error.HTTPError as error:
                    assert error.code == 401
                    error.close()
                else:
                    raise AssertionError("legacy cookie authorized admin API")
            with urllib.request.urlopen(urllib.request.Request(
                    base + "/api/state", headers={"X-Token": "bootstrap-secret"})) as response:
                assert response.status == 200
            with urllib.request.urlopen(urllib.request.Request(
                    base + "/api/shield/toggle", data=b'{"on":true}',
                    headers={"X-Token": "bootstrap-secret",
                             "Content-Type": "application/json"})) as response:
                assert response.status == 200 and json.load(response)["ok"] is True
            with urllib.request.urlopen(urllib.request.Request(
                    base + "/api/state", headers={"X-Token": "bootstrap-secret"})) as response:
                assert json.load(response)["shield"]["cfg"]["enabled"] is True
        finally:
            admin.stop()
            ND._SHIELD, FW._FW = old_shield, old_firewall


def _run_tray_dash(token):
    opened, messages, copies = [], [], []

    class FakeChild:
        exited = False

        def poll(self):
            return 0 if self.exited else None

        def terminate(self):
            self.exited = True

        def wait(self, timeout=None):
            self.exited = True
            return 0

    class FakeTray:
        def __init__(self, icon, tip, items, callback):
            self.callback = callback

        def start(self):
            self.callback("dash")
            self.callback("quit")
            return True

        def stop(self):
            pass

        def set_status(self, *args):
            pass

    old_url = os.environ.get("DUCKNET_ADMIN_URL")
    os.environ["DUCKNET_ADMIN_URL"] = "http://127.0.0.1:8081/?mode=dark&token=stale"
    try:
        with _replace(service, load_env_file=lambda: None), \
                _replace(GUI.tray, available=lambda: True, TrayIcon=FakeTray), \
                _replace(GUI, _ensure_gateway=lambda url, tok: (token, FakeChild()),
                         _status_icons=lambda: ("on", "off"),
                         _admin_is_ours=lambda host, port: True,
                         _verify_admin_proof=lambda url, child: True,
                         _offer_token_copy=lambda value, *args, **kwargs: copies.append(value),
                         _msgbox=lambda message, title: messages.append(message)), \
                _replace(GUI.webbrowser, open=lambda url: opened.append(url) or True):
            assert GUI.main([]) == 0
    finally:
        if old_url is None:
            os.environ.pop("DUCKNET_ADMIN_URL", None)
        else:
            os.environ["DUCKNET_ADMIN_URL"] = old_url
    return opened, messages, copies


def test_tray_opens_bare_dashboard_url_and_removes_stale_query_token():
    opened, messages, copies = _run_tray_dash("a+b/&")
    assert len(opened) == 1 and messages == [] and copies == ["a+b/&"]
    parts = urlsplit(opened[0])
    assert parts.path == "/"
    assert parse_qs(parts.query) == {"mode": ["dark"]}
    assert "a%2Bb" not in opened[0] and "stale" not in opened[0]


def test_tray_with_unknown_token_shows_actionable_message_without_opening():
    opened, messages, copies = _run_tray_dash("")
    assert opened == []
    assert copies == []
    assert len(messages) == 1 and "DUCKNET_ADMIN_TOKEN" in messages[0]


@contextlib.contextmanager
def _fake_admin(port=0):
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("X-Token")))
            if self.path.startswith("/api/state"):
                body = b'{"ok": false, "error": "token required"}'
                self.send_response(401)
                self.send_header("X-DuckNet-Tray-Proof", "0" * 64)  # forged proof
            elif self.path.startswith("/api/metrics"):
                body = b"ducknet_shield_enabled 1\n"
                self.send_response(200)
            else:
                body = b"fake dashboard"
                self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), seen
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


def _tray_against_fake(url, token, child):
    opened, messages = [], []

    class FakeTray:
        def __init__(self, icon, tip, items, callback):
            self.callback = callback

        def start(self):
            self.callback("dash")
            timer = threading.Timer(0.05, lambda: self.callback("quit"))
            timer.daemon = True
            timer.start()
            return True

        def stop(self):
            pass

        def set_status(self, *args):
            pass

    with _env(DUCKNET_ADMIN_URL=url, DUCKNET_ADMIN_TOKEN=token), \
            _replace(service, load_env_file=lambda: None), \
            _replace(GUI.tray, available=lambda: True, TrayIcon=FakeTray), \
            _replace(GUI, _ensure_gateway=lambda base, tok: (token, child),
                     _status_icons=lambda: ("on", "off"), _POLL_SEC=0.01,
                     _msgbox=lambda message, title: messages.append(message)), \
            _replace(GUI.webbrowser, open=lambda target: opened.append(target)):
        assert GUI.main([]) == 0
    return opened, messages


def test_forged_401_never_receives_token_from_existing_or_swapped_listener():
    class LiveChild:
        _ducknet_tray_proof_key = secrets.token_hex(32)
        exited = False

        def poll(self):
            return 0 if self.exited else None

        def terminate(self):
            self.exited = True

        def wait(self, timeout=None):
            self.exited = True
            return 0

    with _fake_admin() as (url, seen):
        # Existing gateway may be a fake: its 401 marker is not identity proof.
        assert GUI._ensure_gateway(url, "TOP_SECRET") == ("TOP_SECRET", None)
        opened, messages = _tray_against_fake(url, "TOP_SECRET", None)
        assert not opened and messages
        assert GUI._fetch_shield_state(url, "TOP_SECRET") == GUI.STATE_AUTH

        # Even with a live child handle, a replaced listener cannot forge its HMAC.
        child = LiveChild()
        assert not GUI._verify_admin_proof(url, child)
        assert GUI._fetch_shield_state(url, "TOP_SECRET", owned_child=child) == GUI.STATE_DOWN
        opened, messages = _tray_against_fake(url, "TOP_SECRET", child)
        assert not opened and messages
        assert seen and all(value is None and "token=" not in path
                            for path, value in seen), seen


def test_spawned_gateway_proves_identity_before_token_is_sent():
    with tempfile.TemporaryDirectory() as state_dir:
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        url = "http://127.0.0.1:" + str(port)
        with _env(DUCKNET_STATE_DIR=state_dir, DUCKNET_LISTEN="0",
                  DUCKNET_BACKEND="127.0.0.1:1"):
            child = GUI._spawn_gateway(port, "child-secret")
            assert child is not None
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and not GUI._verify_admin_proof(url, child):
                    if child.poll() is not None:
                        break
                    time.sleep(0.1)
                assert GUI._verify_admin_proof(url, child)
                assert GUI._fetch_shield_state(url, "child-secret", owned_child=child) in (
                    GUI.STATE_ON, GUI.STATE_OFF, GUI.STATE_AUDIT)
            finally:
                GUI._stop_child(child)


def test_proof_binds_state_without_a_second_token_request_after_port_swap():
    proof_key = secrets.token_hex(32)
    with tempfile.TemporaryDirectory() as state_dir, _env(DUCKNET_TRAY_PROOF_KEY=proof_key):
        old_shield, old_firewall = ND._SHIELD, FW._FW
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        admin = AdminDashboard(host="127.0.0.1", port=0, token="TOP_SECRET",
                               state_dir=state_dir)
        assert admin.start()["ok"]
        url = "http://127.0.0.1:" + str(admin.port)

        class LiveChild:
            _ducknet_tray_proof_key = proof_key

            def poll(self):
                return None

        child = LiveChild()
        real_verify = GUI._verify_admin_proof
        swapped = []

        def await_proof(expected):
            # The per-request tray probe has a one-second network deadline.
            # Under a busy VM it may transiently report DOWN even when the
            # signed state is already committed. Poll for the exact state;
            # no management token is sent by any of these proof requests.
            deadline = time.monotonic() + 5
            last = None
            while time.monotonic() < deadline:
                last = real_verify(url, child)
                if last == expected:
                    return last
                time.sleep(.05)
            raise AssertionError((expected, last))

        try:
            assert await_proof(GUI.STATE_ON) == GUI.STATE_ON
            assert ND._SHIELD.disable()["ok"] is True
            assert await_proof(GUI.STATE_OFF) == GUI.STATE_OFF
            assert ND._SHIELD.set_config(mode="audit")["ok"] is True
            assert ND._SHIELD.enable()["ok"] is True
            assert await_proof(GUI.STATE_AUDIT) == GUI.STATE_AUDIT

            def verify_then_swap(base, target, timeout=1.0):
                assert base == url and target is child
                state = await_proof(GUI.STATE_AUDIT)
                assert state in (GUI.STATE_ON, GUI.STATE_OFF, GUI.STATE_AUDIT)
                admin.stop()
                fake_url, seen = stack.enter_context(_fake_admin(int(urlsplit(url).port)))
                assert fake_url == url
                swapped.append(seen)
                return state

            with contextlib.ExitStack() as stack, \
                    _replace(GUI, _verify_admin_proof=verify_then_swap):
                assert GUI._fetch_shield_state(url, "TOP_SECRET", owned_child=child) in (
                    GUI.STATE_ON, GUI.STATE_OFF, GUI.STATE_AUDIT)
                assert swapped and swapped[0] == [], swapped
        finally:
            admin.stop()
            ND._SHIELD, FW._FW = old_shield, old_firewall


def test_legacy_cookie_crosses_loopback_ports_but_cannot_authenticate_and_is_expired():
    with tempfile.TemporaryDirectory() as state_dir:
        old_shield, old_firewall = ND._SHIELD, FW._FW
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        admin = AdminDashboard(host="127.0.0.1", port=0, token="TOP_SECRET",
                               state_dir=state_dir)
        assert admin.start()["ok"]
        base = "http://127.0.0.1:" + str(admin.port)
        seen = []

        class OtherPort(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                seen.append(self.headers.get("Cookie"))
                self.send_response(200)
                if self.path == "/seed":
                    self.send_header("Set-Cookie", "ducknet_admin=TOP_SECRET; Path=/")
                self.send_header("Content-Length", "0")
                self.end_headers()

        fake = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OtherPort)
        thread = threading.Thread(target=fake.serve_forever, daemon=True)
        thread.start()
        try:
            other = "http://127.0.0.1:" + str(fake.server_port)
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            with opener.open(other + "/seed"):
                pass
            with opener.open(other + "/before"):
                pass
            assert seen[-1] == "ducknet_admin=TOP_SECRET"  # Cookie is not port-scoped.
            try:
                opener.open(base + "/api/state")
            except urllib.error.HTTPError as error:
                assert error.code == 401
                error.close()
            else:
                raise AssertionError("legacy cookie authorized the admin API")
            with opener.open(base + "/") as response:
                assert "Max-Age=0" in (response.headers.get("Set-Cookie") or "")
            with opener.open(other + "/after"):
                pass
            assert seen[-1] is None
        finally:
            fake.shutdown()
            fake.server_close()
            thread.join(2)
            admin.stop()
            ND._SHIELD, FW._FW = old_shield, old_firewall


def test_brand_subtitle_and_text_logo_are_html_escaped_on_real_dashboard():
    with tempfile.TemporaryDirectory() as state_dir:
        admin = AdminDashboard(host="127.0.0.1", port=0, token="TOP_SECRET",
                               brand='<img src=x onerror=alert(1)>',
                               logo='\" onerror=alert(2) x=\"',
                               subtitle='<script>alert(3)</script>',
                               show_brand_icon=False, state_dir=state_dir)
        assert admin.start()["ok"]
        try:
            with urllib.request.urlopen("http://127.0.0.1:" + str(admin.port) + "/") as r:
                page = r.read().decode("utf-8")
            assert '<img src=x onerror=alert(1)>' not in page
            assert '&lt;img src=x onerror=alert(1)&gt;' in page
            assert '<script>alert(3)</script>' not in page
            assert '&lt;script&gt;alert(3)&lt;/script&gt;' in page
            assert '<span class="logo">\" onerror=' not in page
            assert 'data:image/svg+xml,%3Csvg' in page
        finally:
            admin.stop()


def test_dashboard_template_replacements_do_not_expand_user_placeholder_text():
    with tempfile.TemporaryDirectory() as state_dir, _env(DUCKNET_COVER=None):
        admin = AdminDashboard(host="127.0.0.1", port=0, token="TOP_SECRET",
                               brand="__LOGO__", logo="__FAVICON__",
                               subtitle="__AUTH_INSTANCE__ <&",
                               show_brand_icon=False, state_dir=state_dir)
        assert admin.start()["ok"]
        try:
            with urllib.request.urlopen("http://127.0.0.1:" + str(admin.port) + "/") as r:
                page = r.read().decode("utf-8")
            assert "<title>__LOGO__</title>" in page
            assert '<span class="logo">__FAVICON__</span>' in page
            assert "<small>__AUTH_INSTANCE__ &lt;&amp;</small>" in page
            assert page.count('<link rel="icon"') == 1
            assert page.count("<script") == 1
            assert re.search(r'(?:const|let) AUTH_INSTANCE="[0-9a-f]{32}";', page)
        finally:
            admin.stop()


def test_non_latin1_brand_keeps_http_response_and_utf8_dashboard_body():
    with _env(DUCKNET_COVER=None):
        for brand in ("DuckNet-Lite", "管理画面"):
            with tempfile.TemporaryDirectory() as state_dir:
                admin = AdminDashboard(host="127.0.0.1", port=0, token="TOP_SECRET",
                                       brand=brand, show_brand_icon=False,
                                       state_dir=state_dir)
                assert admin.start()["ok"]
                try:
                    with urllib.request.urlopen(
                            "http://127.0.0.1:" + str(admin.port) + "/", timeout=3) as r:
                        body = r.read().decode("utf-8")
                        server = r.headers.get("Server")
                        assert r.status == 200 and server
                        assert server.encode("latin-1")
                    assert "<title>" + brand + "</title>" in body
                    if brand == "DuckNet-Lite":
                        assert server == brand
                finally:
                    admin.stop()
