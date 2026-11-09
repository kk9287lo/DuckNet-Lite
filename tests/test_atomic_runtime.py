"""Runtime success must match listener/process ownership and persisted artifacts."""
import asyncio
import contextlib
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock
from unittest import SkipTest

from dataplane import service
from dataplane.engine.services.proxy import AsyncEdgeGuard
from guard_support import stateless_fork_policy


_SERVICE_RUN = '''
from dataplane.service import run
run(backend="127.0.0.1:9", listen=0, admin_port=0,
    host="127.0.0.1", admin_host="127.0.0.1", token="isolated-test-token",
    defaults_on=False, drain_grace=0)
'''


def _service_child(code, state):
    env = dict(os.environ)
    env.update(DUCKNET_STATE_DIR=state, DUCKNET_OFFLINE="1",
               DUCKNET_SELF_DEFENSE="0", DUCKNET_STDIN_STOP="1",
               PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    return subprocess.Popen([sys.executable, "-u", "-c", code],
                            cwd=str(Path(__file__).resolve().parents[1]), env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)


def test_service_exits_nonzero_when_edge_thread_dies_after_startup():
    code = '''
import asyncio
from dataplane.engine.services.proxy import AsyncEdgeGuard
async def exit_soon(self, interval=30.0):
    await asyncio.sleep(0.6)
    self._stop_event.set()
AsyncEdgeGuard._periodic_checks_loop = exit_soon
''' + _SERVICE_RUN
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix=".validation-service-life-", dir=root) as state:
        proc = _service_child(code, state)
        try:
            try:
                output, _ = proc.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                raise AssertionError("service stayed up after its edge thread died")
            assert proc.returncode != 0, output[-1000:]
            assert b"runtime liveness failure" in output, output[-1000:]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=3)


def test_service_exits_nonzero_when_admin_thread_dies_after_startup():
    code = '''
import threading, time
from dataplane.admin import AdminDashboard
original_start = AdminDashboard.start
def start_then_exit(self):
    result = original_start(self)
    if result.get("ok"):
        def exit_soon():
            time.sleep(0.6)
            self._server.shutdown()
        threading.Thread(target=exit_soon, daemon=True).start()
    return result
AdminDashboard.start = start_then_exit
''' + _SERVICE_RUN
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix=".validation-service-life-", dir=root) as state:
        proc = _service_child(code, state)
        try:
            try:
                output, _ = proc.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                raise AssertionError("service stayed up after its admin thread died")
            assert proc.returncode != 0, output[-1000:]
            assert b"runtime liveness failure" in output, output[-1000:]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=3)


def test_service_idle_listeners_survive_until_graceful_stop():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix=".validation-service-life-", dir=root) as state:
        proc = _service_child(_SERVICE_RUN, state)
        try:
            time.sleep(2.0)
            assert proc.poll() is None, "healthy idle service exited early"
            output, _ = proc.communicate(input=b"stop\n", timeout=6)
            assert proc.returncode == 0, output[-1000:]
            assert b"DuckNet-Lite" in output
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=3)


def _guard():
    return AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                          backend_host="127.0.0.1", backend_port=9)


def _connects(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def test_duplicate_start_keeps_original_listener_owned_and_stoppable():
    guard = _guard()
    assert guard.start()["ok"]
    owner = (guard._thread, guard._loop, guard._server, guard._stop_event)
    port = guard.listen_port
    try:
        result = guard.start()
        assert result["ok"] is False
        assert guard._thread is owner[0] and guard._loop is owner[1]
        assert _connects(port)
        assert guard.stop()["ok"] and not _connects(port)
    finally:
        guard.stop()
        # Clean up the old implementation's orphan if this regression fails.
        if owner[0].is_alive():
            owner[1].call_soon_threadsafe(owner[3].set)
            owner[0].join(3)


def test_timed_out_start_cannot_open_listener_after_returning_failure():
    guard = _guard()
    original = asyncio.start_server

    async def delayed(*args, **kwargs):
        await asyncio.sleep(0.15)
        return await original(*args, **kwargs)

    try:
        with mock.patch("dataplane.engine.services.proxy.asyncio.start_server", delayed):
            result = guard.start(timeout=0.01)
            assert result["ok"] is False
            time.sleep(0.25)
        assert not guard.is_alive() and not _connects(guard.listen_port)
        assert guard.start()["ok"]
        assert _connects(guard.listen_port)
    finally:
        guard.stop()


def test_drain_exception_still_closes_listener_before_stop_success():
    guard = _guard()
    assert guard.start()["ok"]
    port = guard.listen_port

    async def failed(_grace):
        raise OSError("injected drain failure")

    try:
        with mock.patch.object(guard, "_drain", failed):
            result = guard.stop()
        assert result["ok"] is True and result["stopped"] is True
        assert not guard.is_alive() and not _connects(port)
    finally:
        guard.stop()


def test_thread_start_failure_is_reported_and_retryable():
    guard = _guard()
    try:
        with mock.patch("dataplane.engine.services.proxy.threading.Thread.start",
                        side_effect=RuntimeError("cannot start thread")):
            result = guard.start()
        assert result["ok"] is False and not guard.is_alive()
        assert guard.start()["ok"] and _connects(guard.listen_port)
    finally:
        guard.stop()


def test_service_uninstall_exit_code_reports_actual_failure():
    with mock.patch("dataplane.engine.core.autostart.uninstall",
                    return_value={"ok": False, "error": "denied"}):
        assert service.main(["--uninstall-autostart", "--json"]) == 1
    with mock.patch("dataplane.engine.core.autostart.uninstall",
                    return_value={"ok": True}):
        assert service.main(["--uninstall-autostart", "--json"]) == 0


def test_shutdown_collects_failures_and_still_attempts_every_cleanup():
    event = threading.Event()
    event.set()
    calls = []
    def failed():
        calls.append("stop")
        return {"ok": False, "error": "still alive"}
    def saved():
        calls.append("flush")
        return {"ok": True}
    result = service._block_until_shutdown(failed, saved, _event=event)
    assert result["ok"] is False and calls == ["stop", "flush"]
    assert service._block_until_shutdown(saved, _event=event)["ok"] is True


def test_service_failed_admin_result_cleans_started_guard():
    guard = _guard()
    with contextlib.redirect_stdout(io.StringIO()), \
            mock.patch.object(service, "AsyncEdgeGuard", return_value=guard), \
            mock.patch.object(service, "AdminDashboard") as admin, \
            mock.patch.object(service, "_block_until_shutdown"):
        admin.return_value.start.return_value = {"ok": False, "error": "start refused"}
        try:
            try:
                service.run(defaults_on=False)
            except SystemExit:
                pass
            else:
                raise AssertionError("unsuccessful admin startup was accepted")
            assert not guard.is_alive() and not _connects(guard.listen_port)
        finally:
            guard.stop()


def test_service_admin_constructor_failure_cleans_started_guard():
    guard = _guard()
    with mock.patch.object(service, "AsyncEdgeGuard", return_value=guard), \
            mock.patch.object(service, "AdminDashboard", side_effect=OSError("admin allocation failed")):
        try:
            try:
                service.run(defaults_on=False)
            except (SystemExit, OSError):
                pass
            else:
                raise AssertionError("constructor failure was ignored")
            assert not guard.is_alive() and not _connects(guard.listen_port)
        finally:
            guard.stop()


def test_restart_aborts_when_stop_did_not_finish():
    guard = _guard()
    with mock.patch.object(guard, "stop", return_value={"ok": False, "stopped": False}), \
            mock.patch.object(guard, "start") as start:
        assert guard.restart()["ok"] is False
        start.assert_not_called()


def test_service_rejected_declared_config_never_opens_frontend():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "invalid.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"enabled":true,"rate_per_sec":"invalid"}')
        from dataplane.engine.lifeform.pipeline import NetShield
        shield = NetShield(state_dir=directory)
        with contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.object(service, "net_shield", return_value=shield), \
                mock.patch.object(service, "AsyncEdgeGuard") as guard:
            guard.return_value.start.return_value = {"ok": False, "error": "unexpected frontend startup"}
            try:
                service.run(defaults_on=False, config_path=path)
            except SystemExit:
                pass
            else:
                raise AssertionError("invalid declaration was accepted")
            guard.assert_not_called()


def test_start_serving_exception_releases_bound_port():
    guard = _guard()
    created = []
    original = asyncio.start_server

    async def failed(*args, **kwargs):
        server = await original(*args, **kwargs)
        created.extend(s.getsockname()[1] for s in server.sockets)

        async def fail():
            raise OSError("start_serving failed")
        server.start_serving = fail
        return server

    try:
        with mock.patch("dataplane.engine.services.proxy.asyncio.start_server", failed):
            assert guard.start()["ok"] is False
        for port in created:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        assert guard.start()["ok"]
    finally:
        if guard._server is not None:
            guard._server.close()
        guard.stop()


@stateless_fork_policy()
def test_partial_cluster_fork_failure_reaps_created_children():
    if not hasattr(os, "fork"):
        raise SkipTest("requires actual POSIX fork")
    guard = _guard()
    spawned = []
    original = os.fork

    def partial_fork():
        if spawned:
            raise OSError("fork resource exhaustion")
        pid = original()
        if pid:
            spawned.append(pid)
        return pid

    try:
        with mock.patch("dataplane.engine.services.proxy.os.fork", partial_fork):
            result = guard.serve_cluster(workers=3)
        assert result["ok"] is False and not guard._workers
        for pid in spawned:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            raise AssertionError("failed cluster left an unreaped child")
    finally:
        import signal
        for pid in spawned:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
        guard.stop()


def test_failed_worker_signal_retains_ownership_and_reports_not_stopped():
    if not hasattr(os, "fork"):
        raise SkipTest("requires actual POSIX fork")
    guard = _guard()
    pid = os.fork()
    if pid == 0:
        time.sleep(20)
        os._exit(0)
    guard._workers = [pid]
    try:
        with mock.patch("dataplane.engine.services.proxy.os.kill", side_effect=PermissionError("denied")):
            result = guard.stop()
        assert result["ok"] is False and result["stopped"] is False
        assert guard._workers == [pid] and result["workers_stopped"] == 0
    finally:
        import signal
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass
        guard._workers = []
        guard.stop()
