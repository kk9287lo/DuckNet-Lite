"""Native tray and owned launcher failure boundaries, using isolated local fixtures."""
import ctypes
import hashlib
import hmac
import os
import socket
import ssl
import subprocess
import sys
import threading
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import SkipTest
from unittest.mock import patch
from contextlib import contextmanager

from dataplane.gui import tray, ASSET_ICO
from dataplane.gui import __main__ as launcher

ICON = str(Path(tray.__file__).parent / 'assets' / ASSET_ICO)


def _win():
    if not sys.platform.startswith('win'):
        raise SkipTest('requires own Win32 tray window')


def _finish(icon):
    icon.stop()
    if icon._thread is not None:
        icon._thread.join(4)
        assert not icon._thread.is_alive()


def _wait(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(.01)
    return predicate()


def test_native_initial_add_and_timer_failure_cannot_report_started():
    _win()
    shell, u32 = ctypes.windll.shell32, ctypes.windll.user32
    notify = shell.Shell_NotifyIconW
    icon = tray.TrayIcon(ICON, 'isolated failed retry', [], lambda _: None)
    try:
        with patch.object(shell, 'Shell_NotifyIconW', side_effect=lambda op, ref: 0 if op == tray.NIM_ADD else notify(op, ref)), \
                patch.object(u32, 'SetTimer', return_value=0):
            assert icon.start() is False
            assert icon._start_error and 'retry' in icon._start_error.lower()
            assert not icon.is_alive() and icon._hwnd is None
    finally:
        _finish(icon)
    control = tray.TrayIcon(ICON, 'isolated valid control', [], lambda _: None)
    try:
        assert control.start() is True and control.is_alive()
    finally:
        _finish(control)


class _Nid(ctypes.Structure):
    _fields_ = [('uFlags', ctypes.c_uint), ('hIcon', ctypes.c_void_p),
                ('szTip', ctypes.c_wchar * 128)]


class _RetryApi:
    def __init__(self, timer):
        self.timer, self.fail = timer, True

    def Shell_NotifyIconW(self, *args):
        return not self.fail

    def SetTimer(self, *args):
        return self.timer

    def KillTimer(self, *args):
        return 1


def _prepared(api):
    icon = tray.TrayIcon('same.ico', 'old', [], lambda _: None)
    nid = _Nid()
    nid.szTip, nid.hIcon = 'old', 1
    icon._nid, icon._api, icon._hwnd, icon._added = nid, (api, api), 123, True
    icon._applied_tip, icon._applied_icon = 'old', 'same.ico'
    icon.tooltip = 'new'
    return icon


def test_failed_modify_and_retry_timer_stops_instead_of_showing_stale_state():
    icon = _prepared(_RetryApi(0))
    icon._apply_status()
    assert icon._stop_requested.is_set()
    assert icon._start_error and 'retry' in icon._start_error.lower()
    assert icon._applied_tip == 'old' and icon._status_error
    api = _RetryApi(1)
    control = _prepared(api)
    control._apply_status()
    assert not control._stop_requested.is_set() and control._retry_timer
    api.fail = False
    control._on_message(123, tray.WM_TIMER, 1, 0)
    assert control._applied_tip == 'new' and not control._retry_timer


def test_native_running_modify_and_timer_failure_releases_own_window():
    _win()
    shell, u32 = ctypes.windll.shell32, ctypes.windll.user32
    notify = shell.Shell_NotifyIconW
    icon = tray.TrayIcon(ICON, 'initial confirmed state', [], lambda _: None)
    try:
        assert icon.start() is True
        with patch.object(shell, 'Shell_NotifyIconW', side_effect=lambda op, ref: 0 if op == tray.NIM_MODIFY else notify(op, ref)), \
                patch.object(u32, 'SetTimer', return_value=0):
            icon.set_status('updated state could not be displayed')
            assert _wait(lambda: not icon.is_alive())
        assert icon._hwnd is None
    finally:
        _finish(icon)


def test_nonmenu_command_messages_cannot_dispatch_a_menu_action():
    seen = []
    icon = tray.TrayIcon(ICON, 'menu', [('Open', 'open')], seen.append)
    icon._on_message(123, tray.WM_COMMAND, 1 | (1 << 16), 0)
    icon._on_message(123, tray.WM_COMMAND, 1, 456)
    assert seen == []
    icon._on_message(123, tray.WM_COMMAND, 1, 0)
    assert seen == ['open']


def test_stop_requested_cannot_dispatch_an_already_queued_action():
    seen = []
    icon = tray.TrayIcon(ICON, 'queued', [('Open', 'open')], seen.append)
    icon._dispatch(1)
    assert seen == ['open']
    icon._stop_requested.set()
    icon._on_message(123, tray.WM_COMMAND, 1, 0)
    icon._on_message(123, tray.WM_TRAY, 0, tray.WM_LBUTTONDBLCLK)
    assert seen == ['open']


def test_reentrant_start_from_stopping_worker_returns_false_without_self_join():
    icon = tray.TrayIcon(ICON, 'reentrant', [], lambda _: None)
    icon._thread = threading.current_thread()
    icon._ready.set()
    icon._start_ok = True
    with patch.object(tray, 'available', return_value=True):
        assert icon.start() is True
        icon._stop_requested.set()
        assert icon.start() is False


def test_native_callback_can_request_stop_then_try_start_without_exception():
    _win()
    done, results = threading.Event(), []
    icon = None

    def callback(_):
        try:
            icon.stop()
            results.append(icon.start())
        except BaseException as error:
            results.append(type(error).__name__)
        finally:
            done.set()

    icon = tray.TrayIcon(ICON, 'own callback', [('Restart', 'restart')], callback)
    try:
        assert icon.start() is True
        assert ctypes.windll.user32.PostMessageW(icon._hwnd, tray.WM_COMMAND, 1, 0)
        assert done.wait(2)
        assert results == [False]
    finally:
        _finish(icon)


class _MenuApi:
    def __init__(self, fail):
        self.fail, self.shown, self.destroyed = fail, 0, []

    def CreatePopupMenu(self):
        return 123

    def AppendMenuW(self, *args):
        return self.fail != 'append'

    def GetCursorPos(self, *args):
        return self.fail != 'cursor'

    def SetForegroundWindow(self, *args):
        return 1

    def TrackPopupMenu(self, *args):
        self.shown += 1
        return 1

    def PostMessageW(self, *args):
        return 1

    def DestroyMenu(self, handle):
        self.destroyed.append(handle)
        return 1


def test_failed_menu_construction_or_position_never_shows_incomplete_popup():
    for fail in ['append', 'cursor', None]:
        api = _MenuApi(fail)
        icon = tray.TrayIcon(ICON, 'menu', [('Open', 'open')], lambda _: None)
        with patch.object(ctypes, 'windll', SimpleNamespace(user32=api), create=True):
            icon._popup(456)
        assert api.shown == (1 if fail is None else 0), fail
        assert api.destroyed == [123]


def _child(code):
    kwargs = {'stdin': subprocess.PIPE, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
    if sys.platform.startswith('win'):
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return subprocess.Popen([sys.executable, '-c', code], **kwargs)


def test_shutdown_keyboard_interrupt_does_not_orphan_owned_process():
    child = _child('import time;time.sleep(30)')
    original = child.wait
    calls = []

    def interrupted_once(timeout=None):
        if not calls:
            calls.append(True)
            raise KeyboardInterrupt
        return original(timeout=timeout)

    try:
        with patch.object(child, 'wait', side_effect=interrupted_once):
            try:
                stopped = launcher._stop_child(child)
            except KeyboardInterrupt:
                stopped = False
        assert stopped is True and child.poll() is not None
    finally:
        if child.poll() is None:
            child.kill()
            original(timeout=3)
        if child.stdin:
            child.stdin.close()
    control = _child('import sys;sys.stdin.buffer.readline()')
    try:
        assert launcher._stop_child(control) is True and control.poll() == 0
    finally:
        if control.poll() is None:
            control.kill()
            control.wait(timeout=3)
        if control.stdin:
            control.stdin.close()


@contextmanager
def _reply_fixture(*, slow_headers=False, slow_body=False, duplicate_proof=False,
                   oversized_head=False, tls_context=None):
    class Child:
        _ducknet_tray_proof_key = '41' * 32

        def poll(self):
            return None

    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(1)
    stop, seen = threading.Event(), []

    def respond():
        try:
            connection, _ = listener.accept()
            connection.settimeout(1)
            if tls_context is not None:
                connection = tls_context.wrap_socket(connection, server_side=True)
            with connection:
                connection.settimeout(1)
                request = b''
                while b'\r\n\r\n' not in request and len(request) < 4096:
                    part = connection.recv(1024)
                    if not part:
                        return
                    request += part
                seen.append(request)
                nonce = next((line.split(b':', 1)[1].strip() for line in request.split(b'\r\n')
                              if line.lower().startswith(b'x-ducknet-tray-nonce:')), b'')
                proof = hmac.new(bytes.fromhex(Child._ducknet_tray_proof_key),
                                 nonce + b':on', hashlib.sha256).hexdigest().encode()
                body = [b'{"ok":false,', b'"error":', b'"token ', b'required"}']
                headers = [b'HTTP/1.1 401 Unauthorized\r\n', b'Server: fixture\r\n',
                           b'Content-Length: ' + str(sum(map(len, body))).encode() + b'\r\n',
                           b'Connection: close\r\n', b'X-DuckNet-Tray-Proof: ' + proof + b'\r\n', b'\r\n']
                if duplicate_proof:
                    headers.insert(-1, b'X-DuckNet-Tray-Proof: ' + b'0' * 64 + b'\r\n')
                if oversized_head:
                    headers.insert(-1, b'X-Fixture: ' + b'x' * 17000 + b'\r\n')
                for part in headers:
                    if slow_headers and stop.wait(.055):
                        return
                    connection.sendall(part)
                for part in body:
                    if slow_body and stop.wait(.055):
                        return
                    connection.sendall(part)
        except OSError:
            pass

    worker = threading.Thread(target=respond)
    worker.start()
    try:
        scheme = 'https' if tls_context is not None else 'http'
        yield scheme + '://127.0.0.1:' + str(listener.getsockname()[1]), Child(), seen
    finally:
        stop.set()
        listener.close()
        worker.join(2)
        assert not worker.is_alive()


def test_proof_header_deadline_is_total_without_discarding_prompt_valid_proof():
    with _reply_fixture() as (base, child, seen):
        assert launcher._verify_admin_proof(base, child, timeout=.12) == launcher.STATE_ON
        assert seen and b'X-Token:' not in seen[0] and b'Authorization:' not in seen[0]
    with _reply_fixture(slow_headers=True) as (base, child, _seen):
        start = time.monotonic()
        assert launcher._verify_admin_proof(base, child, timeout=.12) is None
        assert time.monotonic() - start < .25


def test_admin_marker_body_deadline_is_total_and_does_not_follow_delayed_marker():
    with _reply_fixture() as (base, _child, seen):
        host, port = launcher._admin_addr(base)
        assert launcher._admin_is_ours(host, port, timeout=.12) is True
        assert seen and b'X-Token:' not in seen[0]
    with _reply_fixture(slow_body=True) as (base, _child, _seen):
        host, port = launcher._admin_addr(base)
        start = time.monotonic()
        assert launcher._admin_is_ours(host, port, timeout=.12) is False
        assert time.monotonic() - start < .25


def test_duplicate_proof_headers_are_rejected_instead_of_selecting_one():
    with _reply_fixture(duplicate_proof=True) as (base, child, _seen):
        assert launcher._verify_admin_proof(base, child) is None
    with _reply_fixture() as (base, child, _seen):
        assert launcher._verify_admin_proof(base, child) == launcher.STATE_ON


def test_admin_proof_headers_have_a_total_byte_budget():
    with _reply_fixture(oversized_head=True) as (base, child, _seen):
        assert launcher._verify_admin_proof(base, child) is None
    with _reply_fixture() as (base, child, _seen):
        assert launcher._verify_admin_proof(base, child) == launcher.STATE_ON


def test_failed_status_notification_is_retried_without_a_new_state_change():
    import dataplane.service as service
    ready, retried = threading.Event(), threading.Event()
    seen, results = {'attempts': 0}, []

    class Tray:
        _status_error = None

        def __init__(self, _icon, _tip, _items, callback):
            seen['callback'] = callback

        def start(self):
            ready.set()
            return True

        def stop(self):
            return True

        def is_alive(self):
            return True

        def set_status(self, _tip, _icon):
            seen['attempts'] += 1
            self._status_error = 'both notification posts failed' if seen['attempts'] == 1 else None
            if seen['attempts'] > 1:
                retried.set()
                seen['callback']('quit')

    with patch.object(service, 'load_env_file', return_value=None), \
            patch.object(launcher.tray, 'available', return_value=True), \
            patch.object(launcher.tray, 'TrayIcon', Tray), \
            patch.object(launcher, '_ensure_gateway', return_value=('', None)), \
            patch.object(launcher, '_fetch_shield_state', return_value=launcher.STATE_OFF), \
            patch.object(launcher, '_POLL_SEC', .01), \
            patch.dict(os.environ, {'DUCKNET_ADMIN_URL': 'http://127.0.0.1:18081'}):
        worker = threading.Thread(target=lambda: results.append(launcher.main([])))
        worker.start()
        try:
            assert ready.wait(2)
            was_retried = retried.wait(.5)
        finally:
            if 'callback' in seen:
                seen['callback']('quit')
            worker.join(3)
        assert was_retried and seen['attempts'] >= 2
        assert not worker.is_alive() and results == [0]


# Public, inert loopback-only certificate/key fixture; never used by the product.
_LOCAL_TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIBrzCCAVSgAwIBAgIUXDozKvW3P9j1tjgyjvqo+jKYZXMwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYRHVja05ldCBpbmVydCBsb2NhbCB0ZXN0MCAXDTI2MTEwMjA2
Mjk0OVoYDzIxMjYxMDA5MDYyOTQ5WjAjMSEwHwYDVQQDDBhEdWNrTmV0IGluZXJ0
IGxvY2FsIHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATXBmHtA//z7EcZ
wycCy1ZMPCk0jShpgls0hlOjxkQkojqW79ttR6QhJqVeusIm4M4TVUEyHuGRlYk4
Wyo5Ufsyo2QwYjAdBgNVHQ4EFgQUlD0z8SgzjLgpG0gS3U1B74+RN6owHwYDVR0j
BBgwFoAUlD0z8SgzjLgpG0gS3U1B74+RN6owDwYDVR0TAQH/BAUwAwEB/zAPBgNV
HREECDAGhwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQC7Dg0A9voEuXy/TzYemuS0
+N+Z/Qy506jSf7Hh9igNbgIhAMkRJhE+z2EdkSs+q8ArSSqLVJnx0qyxi63Zn9EK
QcDJ
-----END CERTIFICATE-----
"""
_LOCAL_TEST_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzvqTvqcPyu7IZB2w
cTY6RQdGqMcX4k1/YFlqssOFUOuhRANCAATXBmHtA//z7EcZwycCy1ZMPCk0jShp
gls0hlOjxkQkojqW79ttR6QhJqVeusIm4M4TVUEyHuGRlYk4Wyo5Ufsy
-----END PRIVATE KEY-----
"""


def test_https_proof_keeps_certificate_verification_and_accepts_explicit_trust():
    with tempfile.TemporaryDirectory() as directory:
        certificate, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
        certificate.write_text(_LOCAL_TEST_CERT, encoding='ascii')
        key.write_text(_LOCAL_TEST_KEY, encoding='ascii')
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(certificate, key)
        with _reply_fixture(tls_context=server) as (base, child, _seen):
            assert launcher._verify_admin_proof(base, child, timeout=.5) is None
        trusted = ssl.create_default_context(cafile=str(certificate))
        with patch.object(ssl, 'create_default_context', return_value=trusted), \
                patch.object(ssl, '_create_default_https_context', return_value=trusted):
            with _reply_fixture(tls_context=server) as (base, child, seen):
                assert launcher._verify_admin_proof(base, child, timeout=.5) == launcher.STATE_ON
                assert seen and b'X-Token:' not in seen[0]
