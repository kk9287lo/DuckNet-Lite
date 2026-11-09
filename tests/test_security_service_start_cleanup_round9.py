"""Failed admin startup must not leave a live edge listener behind."""

import contextlib
import io
import os
import socket
import tempfile
from unittest import mock

from dataplane import service
from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.lifeform import policy as FW
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.services.proxy import AsyncEdgeGuard


def _connects(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def _case(first_result):
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        guard = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                               backend_host="127.0.0.1", backend_port=9)
        original_stop = guard.stop
        calls = []

        def stop_once_then_real(*, grace=0.0):
            calls.append(grace)
            if len(calls) == 1:
                assert _connects(guard.listen_port), "no live listener at cleanup boundary"
                if isinstance(first_result, BaseException):
                    raise first_result
                return first_result
            return original_stop(grace=grace)

        with mock.patch.dict(os.environ, {"DUCKNET_STATE_DIR": state,
                                       "DUCKNET_OFFLINE": "1"}), \
                mock.patch.object(ND, "_SHIELD", shield), \
                mock.patch.object(FW, "_FW", firewall), \
                mock.patch.object(service, "net_shield", return_value=shield), \
                mock.patch.object(service, "AsyncEdgeGuard", return_value=guard), \
                mock.patch.object(service, "AdminDashboard",
                                  side_effect=OSError("admin bind failed")), \
                mock.patch.object(guard, "stop", side_effect=stop_once_then_real), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                try:
                    service.run(defaults_on=False)
                except SystemExit as exc:
                    assert "管理ダッシュボード起動失敗" in str(exc)
                else:
                    raise AssertionError("admin startup failure was accepted")
                assert not guard.is_alive() and not _connects(guard.listen_port), \
                    "admin startup failed but edge still accepts sockets"
                assert len(calls) >= 2, "failed first stop was never retried"
            finally:
                # The old implementation fails the assertion above. Still
                # release the real socket before the temporary state is removed.
                original_stop(grace=0.0)


def test_admin_bind_failure_retries_transient_guard_stop_exception():
    _case(OSError("transient stop failure"))


def test_admin_bind_failure_retries_incomplete_guard_stop_result():
    _case({"ok": False, "stopped": False})


def test_admin_bind_failure_normal_cleanup_still_closes_real_listener():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        guard = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                               backend_host="127.0.0.1", backend_port=9)
        with mock.patch.dict(os.environ, {"DUCKNET_STATE_DIR": state,
                                       "DUCKNET_OFFLINE": "1"}), \
                mock.patch.object(ND, "_SHIELD", shield), \
                mock.patch.object(FW, "_FW", firewall), \
                mock.patch.object(service, "net_shield", return_value=shield), \
                mock.patch.object(service, "AsyncEdgeGuard", return_value=guard), \
                mock.patch.object(service, "AdminDashboard",
                                  side_effect=OSError("admin bind failed")), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                try:
                    service.run(defaults_on=False)
                except SystemExit:
                    pass
                else:
                    raise AssertionError("admin startup failure was accepted")
                assert not guard.is_alive() and not _connects(guard.listen_port)
            finally:
                guard.stop(grace=0.0)


def test_admin_failure_retries_stop_for_owned_cluster_listener_without_workers():
    """A cluster listener is owned even if its worker/thread lists are empty."""
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        guard = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0,
                               backend_host="127.0.0.1", backend_port=9)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        guard._listen_sock = listener
        guard.listen_port = listener.getsockname()[1]
        original_stop = guard.stop
        calls = []

        def stop_once_then_real(*, grace=0.0):
            calls.append(grace)
            if len(calls) == 1:
                assert _connects(guard.listen_port)
                raise OSError("transient cluster stop failure")
            return original_stop(grace=grace)

        with mock.patch.dict(os.environ, {"DUCKNET_STATE_DIR": state,
                                       "DUCKNET_OFFLINE": "1"}), \
                mock.patch.object(ND, "_SHIELD", shield), \
                mock.patch.object(FW, "_FW", firewall), \
                mock.patch.object(service, "net_shield", return_value=shield), \
                mock.patch.object(service, "AsyncEdgeGuard", return_value=guard), \
                mock.patch.object(guard, "serve_cluster", return_value={"ok": True,
                                                                  "mode": "cluster"}), \
                mock.patch.object(service, "AdminDashboard",
                                  side_effect=OSError("admin bind failed")), \
                mock.patch.object(guard, "stop", side_effect=stop_once_then_real), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                try:
                    service.run(defaults_on=False, cluster=True)
                except SystemExit:
                    pass
                else:
                    raise AssertionError("admin startup failure was accepted")
                assert not _connects(guard.listen_port), \
                    "cluster listener survived failed admin startup"
                assert len(calls) >= 2, "owned cluster listener was not retried"
            finally:
                original_stop(grace=0.0)
