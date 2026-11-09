"""Local launcher ownership, URL and callback lifecycle regressions."""
import contextlib
import hashlib
import hmac
import http.server
import io
import os
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

import dataplane.gui.__main__ as GUI
import dataplane.service as service


class _Child:
    _ducknet_tray_proof_key = "12" * 32

    def __init__(self):
        self.alive = True

    def poll(self):
        return None if self.alive else 0


@contextlib.contextmanager
def _launcher(start, *, child=None, browser=None, gui_threading=None,
              tray_alive=None, tray_stop=None):
    seen = {"opened": [], "messages": [], "copies": [], "stops": 0, "children": [], "statuses": []}
    child = _Child() if child is None else child

    class Tray:
        def __init__(self, icon, tip, items, callback):
            seen.update(icon=icon, tip=tip, callback=callback)
            self.callback = callback

        def start(self):
            return start(self.callback)

        def stop(self):
            seen["stops"] += 1
            return True if tray_stop is None else tray_stop()

        def is_alive(self):
            return True if tray_alive is None else tray_alive()

        def set_status(self, tip, icon):
            seen["statuses"].append((tip, icon))

    def opened(url):
        seen["opened"].append(url)
        return True if browser is None else browser(url)

    def stop_child(value):
        seen["children"].append(value)
        if isinstance(value, _Child):
            value.alive = False
        return True

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {
            "DUCKNET_ADMIN_URL": "http://127.0.0.1:18081/?token=stale&mode=dark",
            "DUCKNET_ADMIN_TOKEN": "synthetic-token",
        }))
        for obj, name, value in (
            (service, "load_env_file", lambda: None),
            (service, "_force_utf8_stdio", lambda: None),
            (GUI.tray, "available", lambda: True),
            (GUI.tray, "TrayIcon", Tray),
            (GUI, "_ensure_gateway", lambda url, tok: ("synthetic-token", child)),
            (GUI, "_status_icons", lambda: ("on.ico", "off.ico")),
            (GUI, "_admin_is_ours", lambda *args: True),
            (GUI, "_verify_admin_proof", lambda *args: GUI.STATE_ON),
            (GUI, "_fetch_shield_state", lambda *args, **kwargs: GUI.STATE_DOWN),
            (GUI, "_msgbox", lambda message, title: seen["messages"].append(message)),
            (GUI, "_offer_token_copy", lambda token, *args, **kwargs: seen["copies"].append(token)),
            (GUI, "_stop_child", stop_child),
            (GUI.webbrowser, "open", opened),
        ):
            stack.enter_context(patch.object(obj, name, value))
        if gui_threading is not None:
            stack.enter_context(patch.object(GUI, "threading", gui_threading))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        yield seen, child


def test_launcher_start_exception_reaps_its_actual_child():
    kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.DEVNULL,
              "stderr": subprocess.DEVNULL}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)

    def fail(_callback):
        raise RuntimeError("fixture tray startup failed")

    original = GUI._stop_child
    try:
        with _launcher(fail, child=child), patch.object(GUI, "_stop_child", original), \
                patch.object(GUI, "_stop_wait", lambda: 0.05):
            try:
                GUI.main([])
            except RuntimeError:
                pass
        assert child.poll() is not None, "launcher left its child alive after tray.start raised"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        if child.stdin:
            child.stdin.close()


def test_launcher_partial_start_failure_stops_tray_and_owned_child():
    with _launcher(lambda callback: False) as (seen, child):
        assert GUI.main([]) == 1
    assert seen["children"] == [child]
    assert seen["stops"] >= 1, "partial tray startup was not unwound"


def test_launcher_unexpected_wait_failure_stops_tray_and_owned_child():
    class Event(threading.Event):
        def wait(self, timeout=None):
            raise RuntimeError("fixture main wait failed")

    class Thread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            pass

    with _launcher(lambda callback: True,
                   gui_threading=SimpleNamespace(Event=Event, Thread=Thread)) as (seen, child):
        try:
            GUI.main([])
        except RuntimeError:
            pass
    assert seen["children"] == [child]
    assert seen["stops"] >= 1, "tray was left running after main wait failed"


def test_launcher_ignores_callbacks_after_quit():
    def actions(callback):
        callback("quit")
        callback("dash")
        callback("about")
        callback("caps")
        return True

    with _launcher(actions) as (seen, _child):
        assert GUI.main([]) == 0
    assert seen["opened"] == [] and seen["messages"] == []


def test_launcher_inflight_browser_does_not_display_token_after_quit():
    entered, release = threading.Event(), threading.Event()

    def browser(url):
        entered.set()
        assert release.wait(2)
        return True

    def actions(callback):
        worker = threading.Thread(target=lambda: callback("dash"))
        worker.start()
        try:
            assert entered.wait(2)
            callback("quit")
        finally:
            release.set()
            worker.join(2)
        assert not worker.is_alive()
        return True

    with _launcher(actions, browser=browser) as (seen, _child):
        assert GUI.main([]) == 0
    assert len(seen["opened"]) == 1
    assert seen["messages"] == [], "token dialog appeared after quit completed"
    assert seen["copies"] == [], "token handoff appeared after quit completed"


def test_launcher_browser_failure_never_claims_open_or_displays_token():
    def actions(callback):
        callback("dash")
        callback("quit")
        return True

    with _launcher(actions, browser=lambda url: False) as (seen, _child):
        assert GUI.main([]) == 0
    assert len(seen["opened"]) == 1
    assert seen["messages"] and all("synthetic-token" not in msg for msg in seen["messages"])


def test_launcher_normal_open_scrubs_token_and_owned_child_is_stopped():
    def actions(callback):
        callback("dash")
        callback("quit")
        return True

    with _launcher(actions) as (seen, child):
        assert GUI.main([]) == 0
    assert seen["opened"] == ["http://127.0.0.1:18081/?mode=dark"]
    assert seen["copies"] == ["synthetic-token"]
    assert all("synthetic-token" not in message for message in seen["messages"])
    assert seen["children"] == [child]


def test_launcher_rejects_invalid_admin_urls_before_network_or_spawn():
    invalid = ("http://127.0.0.1:bad", "http://127.0.0.1:0", "http://[::1",
               "file:///tmp/local-fixture", "javascript:alert(0)",
               "http://user:secret@127.0.0.1:8081", "http://127.0.0.1/\r\n")
    for value in invalid:
        try:
            GUI._admin_addr(value)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid admin URL silently accepted: " + repr(value))
    with _launcher(lambda callback: False) as (seen, _child), \
            patch.dict(os.environ, {"DUCKNET_ADMIN_URL": invalid[0]}), \
            patch.object(GUI, "_ensure_gateway") as ensure:
        assert GUI.main([]) == 1
        ensure.assert_not_called()
    assert not seen["opened"]


def test_launcher_url_probe_and_browser_use_the_same_endpoint():
    for base, address in (("http://127.0.0.1", ("127.0.0.1", 80)),
                          ("https://127.0.0.1", ("127.0.0.1", 443)),
                          ("http://[::1]:18081/", ("::1", 18081))):
        assert GUI._admin_addr(base) == address
    opened = GUI._dashboard_url("127.0.0.1:18081/?token=old&mode=dark")
    assert opened == "http://127.0.0.1:18081/?mode=dark"
    assert urlsplit(opened).hostname == "127.0.0.1"


def test_launcher_does_not_spawn_plain_http_for_https_or_remote_admin_urls():
    for base in ("https://127.0.0.1:18443/", "http://192.0.2.10:18081/",
                 "http://localhost:18081/"):
        with patch.object(GUI, "_gateway_up", return_value=False), \
                patch.object(GUI, "_spawn_gateway", return_value=None) as spawn:
            _token, child = GUI._ensure_gateway(base, "synthetic-token")
            assert child is None
            spawn.assert_not_called()


def test_launcher_discards_failed_startup_and_keeps_ready_child_control():
    for alive in (False, True):
        child, stopped = _Child(), []
        child.alive = alive
        now = [0.0]

        def sleep(seconds):
            now[0] += seconds

        with patch.object(GUI, "_gateway_up", return_value=False), \
                patch.object(GUI, "_spawn_gateway", return_value=child), \
                patch.object(GUI, "_stop_child", side_effect=lambda value: stopped.append(value) or True), \
                patch.object(GUI, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep)):
            assert GUI._ensure_gateway("http://127.0.0.1:18081", "secret") == ("", None)
        assert stopped == [child]
    child = _Child()
    with patch.object(GUI, "_gateway_up", side_effect=(False, True)), \
            patch.object(GUI, "_spawn_gateway", return_value=child), \
            patch.object(GUI, "_verify_admin_proof", return_value=GUI.STATE_OFF), \
            patch.object(GUI, "_stop_child") as stop:
        assert GUI._ensure_gateway("http://127.0.0.1:18081", "secret") == ("secret", child)
        stop.assert_not_called()


def test_launcher_poller_start_failure_cannot_show_confirmed_protection():
    class Event(threading.Event):
        def wait(self, timeout=None):
            self.set()
            return super().wait(0)

    class Thread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("fixture poller could not start")

    with _launcher(lambda callback: True,
                   gui_threading=SimpleNamespace(Event=Event, Thread=Thread)) as (seen, child):
        assert GUI.main([]) in (0, 1)
    assert seen["icon"] == "off.ico" and "状態を確認できません" in seen["tip"]
    assert seen["children"] == [child]


def test_launcher_worker_exit_does_not_leave_invisible_launcher_running():
    result = []
    with _launcher(lambda callback: True, tray_alive=lambda: False) as (seen, child):
        worker = threading.Thread(target=lambda: result.append(GUI.main([])), daemon=True)
        worker.start()
        try:
            worker.join(1.5)
            stopped_itself = not worker.is_alive()
        finally:
            if worker.is_alive():
                seen["callback"]("quit")
            worker.join(3)
        assert stopped_itself, "launcher waited forever after its tray worker exited"
    assert result == [1] and seen["children"] == [child]


def test_launcher_final_stop_failure_is_not_a_successful_exit():
    def actions(callback):
        callback("quit")
        return True

    with _launcher(actions, tray_stop=lambda: False) as (seen, child):
        assert GUI.main([]) == 1
    assert seen["children"] == [child]
    replies = iter((False, True))  # callback asks, main joins and completes
    with _launcher(actions, tray_stop=lambda: next(replies)) as (seen, child):
        assert GUI.main([]) == 0
    assert seen["children"] == [child]


def test_stop_child_confirms_exit_after_wait_and_reports_unstoppable_child():
    class Child:
        stdin = None

        def __init__(self, exits):
            self.exits, self.alive = exits, True

        def poll(self):
            return None if self.alive else 0

        def wait(self, timeout=None):
            if self.exits:
                self.alive = False
                return 0
            raise subprocess.TimeoutExpired("fixture child", timeout)

        def terminate(self):
            pass

        def kill(self):
            pass

    normal, stuck = Child(True), Child(False)
    assert GUI._stop_child(stuck) is False and stuck.poll() is None
    assert GUI._stop_child(normal) is True and normal.poll() == 0
    assert GUI._stop_child(None) is True
    with _launcher(lambda cb: cb("quit") or True, child=stuck), \
            patch.object(GUI, "_stop_child", return_value=False):
        assert GUI.main([]) == 1


def test_failed_startup_retains_child_when_shutdown_is_unconfirmed():
    child = _Child()
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds

    with patch.object(GUI, "_gateway_up", return_value=False), \
            patch.object(GUI, "_spawn_gateway", return_value=child), \
            patch.object(GUI, "_stop_child", return_value=False), \
            patch.object(GUI, "time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep)):
        assert GUI._ensure_gateway("http://127.0.0.1:18081", "secret") == ("", child)


def test_launcher_keeps_initial_display_unconfirmed_until_first_poll():
    with _launcher(lambda callback: callback("quit") or True) as (seen, _child):
        assert GUI.main([]) == 0
    assert seen["icon"] == "off.ico"
    assert "状態を確認できません" in seen["tip"]


def test_admin_proof_must_still_belong_to_a_live_child_after_response():
    child = _Child()
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("X-Token")))
            nonce = self.headers["X-DuckNet-Tray-Nonce"]
            proof = hmac.new(bytes.fromhex(child._ducknet_tray_proof_key),
                             (nonce + ":on").encode("ascii"), hashlib.sha256).hexdigest()
            if self.server.exit_child:
                child.alive = False
            self.send_response(401)
            self.send_header("X-DuckNet-Tray-Proof", proof)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.exit_child = False
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = "http://127.0.0.1:" + str(server.server_port)
    try:
        assert GUI._verify_admin_proof(base, child) == GUI.STATE_ON
        server.exit_child = True
        assert GUI._verify_admin_proof(base, child) is None
        assert seen == [("/api/state", None), ("/api/state", None)]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
