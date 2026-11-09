"""Verified local tray workflows; never touch the user's real clipboard."""
import ctypes
import hashlib
import hmac
import http.server
import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from dataplane.gui import __main__ as GUI, tray
from test_sweep_admin_ui import _Admin


@contextmanager
def _server(callback):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = callback(self)
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_existing_gateway_mode_is_verified_without_transmitting_token():
    with _Admin() as app:
        base = f"http://127.0.0.1:{app.port}"
        original, requests = GUI._read_admin_reply, []
        def exchange(*args, **kwargs):
            requests.append(kwargs.get("headers", {}))
            return original(*args, **kwargs)
        with patch.object(GUI, "_read_admin_reply", side_effect=exchange):
            state = GUI._fetch_shield_state(base, app.token)
            assert state == GUI.STATE_ON
            assert state.bans == 0
            app.sh.set_config(mode="audit")
            assert GUI._fetch_shield_state(base, app.token) == GUI.STATE_AUDIT
            app.sh.disable()
            assert GUI._fetch_shield_state(base, app.token) == GUI.STATE_OFF
            assert GUI._fetch_shield_state(base, "wrong-token") == GUI.STATE_AUTH
        assert requests and any("X-Admin-Auth-Mac" in headers for headers in requests)
        for headers in requests:
            assert "X-Token" not in headers and "Authorization" not in headers
            assert app.token not in json.dumps(headers)


def _signed_server(mode, *, payload=None):
    instance, token, saved = "ab" * 16, "synthetic-workflow-token", {}
    seen = []
    def callback(request):
        seen.append((request.path, dict(request.headers)))
        if request.path == "/":
            page = f'let AUTH_INSTANCE="{instance}";'.encode()
            if mode == "duplicate-instance":
                page += page
            if mode == "redirect":
                return 302, [("Location", "http://127.0.0.1:1/")], b""
            return 200, [], page
        body = (payload if isinstance(payload, bytes) else json.dumps(payload).encode() if payload is not None else
                b'{"shield":{"cfg":{"enabled":true,"mode":"enforce"},"bans":[]},"telemetry_complete":true}')
        nonce = request.headers.get("X-Admin-Auth-Nonce", "")
        signing_instance = "cd" * 16 if mode == "wrong-instance" else instance
        text = f"{signing_instance}\n{nonce}\n200\n{hashlib.sha256(body).hexdigest()}"
        proof = hmac.new(token.encode(), text.encode(), hashlib.sha256).hexdigest()
        if mode == "wrong-mac":
            proof = "00" * 32
        if mode == "replay" and "proof" in saved:
            proof = saved["proof"]
        saved["proof"] = proof
        proofs = [("X-Admin-Response-Mac", proof)]
        if mode == "duplicate-mac":
            proofs += proofs
        return 200, proofs, body
    return callback, token, seen


def test_forged_duplicate_redirect_and_replayed_admin_replies_fail_closed():
    for mode in ("wrong-mac", "wrong-instance", "duplicate-instance", "duplicate-mac", "redirect", "replay"):
        callback, token, seen = _signed_server(mode)
        with _server(callback) as base:
            if mode == "replay":
                assert GUI._signed_admin_state(base, token) == GUI.STATE_ON
            assert GUI._signed_admin_state(base, token) is None, mode
        assert all(token not in json.dumps(headers) for _, headers in seen)
        assert all("Authorization" not in headers and "X-Token" not in headers for _, headers in seen)
        if mode in ("redirect", "duplicate-instance"):
            assert all(path == "/" for path, _ in seen)


def test_external_state_rejects_malformed_modes_and_never_claims_partial_ban_total():
    invalid = [{}, {"shield": {"error": "untrusted"}},
               {"shield": {"cfg": {"enabled": "false", "mode": "enforce"}}},
               {"shield": {"cfg": {"enabled": True, "mode": "unexpected"}}}]
    for payload in invalid:
        callback, token, _ = _signed_server("valid", payload=payload)
        with _server(callback) as base:
            assert GUI._signed_admin_state(base, token) is None
    payload = {"shield": {"cfg": {"enabled": True, "mode": "audit"}, "bans": [{}]},
               "telemetry_complete": False}
    callback, token, _ = _signed_server("valid", payload=payload)
    with _server(callback) as base:
        state = GUI._signed_admin_state(base, token)
    assert state == GUI.STATE_AUDIT and state.bans is None
    assert "未確認" in GUI._status_lines(state)[1]


def test_external_monitor_does_not_resolve_hostnames_or_connect_to_remote_hosts():
    with patch.object(GUI.socket, "create_connection", side_effect=AssertionError("must not connect")):
        for base in ("http://localhost:8081", "http://192.0.2.8:8081", "https://example.invalid"):
            assert GUI._signed_admin_state(base, "synthetic-token") is None


def test_signed_state_rejects_duplicate_json_and_bounded_body_overflow():
    for payload in (
        b'{"shield":{"cfg":{"enabled":true,"enabled":false,"mode":"enforce"},"bans":[]}}',
        b'{"shield":{"cfg":{"enabled":true,"mode":"enforce"},"bans":[]},"padding":"' + b'a' * 1048576 + b'"}',
    ):
        callback, token, _ = _signed_server("valid", payload=payload)
        with _server(callback) as base:
            assert GUI._signed_admin_state(base, token) is None
    seen = []
    def oversized_page(request):
        seen.append(dict(request.headers))
        return 200, [], b'const AUTH_INSTANCE="' + b'ab' * 16 + b'";' + b'x' * 1048576
    with _server(oversized_page) as base:
        assert GUI._signed_admin_state(base, "synthetic-token") is None
    assert len(seen) == 1 and "X-Admin-Auth-Mac" not in seen[0]


def test_existing_service_new_instance_is_authenticated_without_reusing_old_reply():
    with _Admin() as app:
        base = f"http://127.0.0.1:{app.port}"
        assert GUI._signed_admin_state(base, app.token) == GUI.STATE_ON
        app.adm._browser_instance_id = "bc" * 16
        app.sh.set_config(mode="audit")
        assert GUI._signed_admin_state(base, app.token) == GUI.STATE_AUDIT


def test_owned_child_keeps_its_separate_proof_protocol():
    with patch.object(GUI, "_verify_admin_proof", return_value=GUI.STATE_ON), \
            patch.object(GUI, "_signed_admin_state", side_effect=AssertionError("owned proof first")):
        assert GUI._fetch_shield_state("http://127.0.0.1:1", "wrong", owned_child=object()) == GUI.STATE_ON


def test_poller_refreshes_ban_count_even_when_protection_mode_is_unchanged():
    stop, states, shown = threading.Event(), iter([GUI._TrayState(GUI.STATE_ON, 1), GUI._TrayState(GUI.STATE_ON, 2)]), []
    def show(value):
        shown.append(value.bans)
        if len(shown) == 2:
            stop.set()
    GUI._poll_status(lambda: next(states), show, stop, interval=0.001)
    assert shown == [1, 2]


def test_live_tray_rows_are_disabled_and_never_dispatch_an_operation():
    from test_gui_native_edges import _MenuApi
    class Api(_MenuApi):
        def __init__(self):
            super().__init__(None)
            self.rows = []
        def AppendMenuW(self, menu, flags, command, label):
            self.rows.append((flags, command, label))
            return 1
    api, called = Api(), []
    icon = tray.TrayIcon("fixture.ico", "fixture", [("Open", "dash")], called.append)
    icon.set_status_lines(GUI._status_lines(GUI._TrayState(GUI.STATE_AUDIT, 3)))
    with patch.object(ctypes, "windll", SimpleNamespace(user32=api), create=True):
        icon._popup(123)
    rows = [row for row in api.rows if row[0] & tray.MF_GRAYED]
    assert len(rows) == 2 and all(command == 0 for _, command, _ in rows)
    assert rows[1][2] == "BAN: 3"
    icon._dispatch(0)
    assert called == []
    icon._dispatch(1)
    assert called == ["dash"]
    icon._stop_requested.set()
    before = len(api.rows)
    with patch.object(ctypes, "windll", SimpleNamespace(user32=api), create=True):
        icon._popup(123)
    assert len(api.rows) == before


class _Clipboard:
    def __init__(self):
        self.buffers, self.sequence, self.current, self.opens, self.freed = {}, 1, None, 0, []
        self.replace("prior clipboard")
    def replace(self, text):
        handle = self.GlobalAlloc(2, len((text + "\0").encode("utf-16-le")))
        self.buffers[handle].raw = (text + "\0").encode("utf-16-le")
        self.current, self.sequence = handle, self.sequence + 1
    def OpenClipboard(self, owner):
        self.opens += 1
        return True
    def CloseClipboard(self):
        self.opens -= 1
        return True
    def EmptyClipboard(self):
        self.current, self.sequence = None, self.sequence + 1
        return True
    def SetClipboardData(self, kind, handle):
        self.current, self.sequence = handle, self.sequence + 1
        return handle
    def GetClipboardData(self, kind):
        return self.current
    def GetClipboardSequenceNumber(self):
        return self.sequence
    def GlobalAlloc(self, flags, size):
        handle = len(self.buffers) + 1
        self.buffers[handle] = ctypes.create_string_buffer(size)
        return handle
    def GlobalLock(self, handle):
        return ctypes.addressof(self.buffers[handle])
    def GlobalUnlock(self, handle):
        return True
    def GlobalSize(self, handle):
        return ctypes.sizeof(self.buffers[handle])
    def GlobalFree(self, handle):
        self.freed.append(handle)
        return None


def test_clipboard_clear_requires_both_exact_content_and_original_sequence():
    clipboard = _Clipboard()
    with patch.object(GUI, "_clipboard_api", return_value=(clipboard, clipboard)):
        sequence = GUI._clipboard_write("synthetic-secret", lambda: True, 123)
        assert GUI._clipboard_clear_if_ours("wrong-secret", sequence) is False
        assert GUI._clipboard_clear_if_ours("synthetic-secret", sequence) is True
        sequence = GUI._clipboard_write("synthetic-secret", lambda: True, 123)
        clipboard.replace("new user clipboard")
        assert GUI._clipboard_clear_if_ours("synthetic-secret", sequence) is False
        sequence = clipboard.sequence
        clipboard.replace("synthetic-secret")
        assert GUI._clipboard_clear_if_ours("synthetic-secret", sequence) is False
        assert clipboard.current is not None and clipboard.opens == 0


def test_copy_cancellation_and_shutdown_never_overwrite_clipboard():
    clipboard, stop = _Clipboard(), threading.Event()
    with patch.object(GUI, "_clipboard_api", return_value=(clipboard, clipboard)), \
            patch.object(GUI, "_confirm_token_copy", return_value=False):
        before = clipboard.sequence
        assert not GUI._offer_token_copy("synthetic-secret", "fixture", stop, lambda: True, owner=123)
        assert clipboard.sequence == before
    def quit_during_confirmation(_title):
        stop.set()
        return True
    with patch.object(GUI, "_confirm_token_copy", side_effect=quit_during_confirmation), \
            patch.object(GUI, "_clipboard_write", side_effect=AssertionError("no write after quit")):
        assert not GUI._offer_token_copy("synthetic-secret", "fixture", stop, lambda: True, owner=123)


def test_clipboard_failed_transfer_frees_its_memory_and_leaves_no_open_handle():
    clipboard = _Clipboard()
    with patch.object(GUI, "_clipboard_api", return_value=(clipboard, clipboard)), \
            patch.object(clipboard, "SetClipboardData", return_value=0):
        assert GUI._clipboard_write("synthetic-secret", lambda: True, 123) is None
    assert clipboard.opens == 0 and len(clipboard.freed) == 1
    before = clipboard.sequence
    with patch.object(GUI, "_clipboard_api", return_value=(clipboard, clipboard)):
        assert GUI._clipboard_write("synthetic-secret", lambda: False, 123) is None
    assert clipboard.sequence == before


def test_token_copy_requires_owned_proof_and_clears_on_tray_exit_without_raw_notice():
    clipboard, stop, messages = _Clipboard(), threading.Event(), []
    with patch.object(GUI, "_clipboard_api", return_value=(clipboard, clipboard)), \
            patch.object(GUI, "_confirm_token_copy", return_value=True), \
            patch.object(GUI, "_msgbox", side_effect=lambda text, _title: messages.append(text)):
        before = clipboard.sequence
        assert not GUI._offer_token_copy("synthetic-secret", "fixture", stop, lambda: False, owner=123)
        assert clipboard.sequence == before
        worker = GUI._offer_token_copy("synthetic-secret", "fixture", stop, lambda: True, owner=123)
        assert worker and clipboard.current is not None
        stop.set()
        worker.join(1)
        assert not worker.is_alive() and clipboard.current is None
    assert all("synthetic-secret" not in message for message in messages)


def test_external_dashboard_requires_signed_identity_and_never_offers_token_copy():
    from test_gui_launcher import _launcher
    def actions(callback):
        callback("dash")
        callback("quit")
        return True
    for verified in (None, GUI._TrayState(GUI.STATE_AUDIT, 0)):
        with _launcher(actions) as (seen, _child), \
                patch.object(GUI, "_ensure_gateway", return_value=("synthetic-token", None)), \
                patch.object(GUI, "_signed_admin_state", return_value=verified):
            assert GUI.main([]) == 0
        assert bool(seen["opened"]) is bool(verified)
        assert seen["copies"] == []
        assert all("synthetic-token" not in message for message in seen["messages"])


def test_clipboard_cleanup_interrupt_does_not_orphan_owned_gateway():
    from test_gui_launcher import _launcher
    class Worker:
        def join(self, timeout=None):
            raise KeyboardInterrupt
    def actions(callback):
        callback("dash")
        callback("quit")
        return True
    with _launcher(actions) as (seen, child), patch.object(GUI, "_offer_token_copy", return_value=Worker()):
        assert GUI.main([]) == 0
    assert seen["children"] == [child] and seen["stops"] >= 1
