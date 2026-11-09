"""Direct stateful edits use one worker; stateless forks reject unsafe edits."""

import contextlib
import errno
import os
from pathlib import Path
import signal
import socket
import tempfile
from unittest import SkipTest

from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.lifeform import policy as FW
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_security_cluster_round14 import _backend, _port, _received, _request


@contextlib.contextmanager
def _cluster(*, stateful=False):
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT unavailable")
    old_shield, old_firewall = ND._SHIELD, FW._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r15-direct-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        ND._SHIELD = ND.NetShield(state_dir=state)
        FW._FW = FW.AppFirewall(state_dir=state)
        assert ND._SHIELD.set_config(enabled=stateful, block_page=False,
                                     block_score=40, max_total_conn=0,
                                     max_conn_per_ip=0, conn_rate_per_ip=0)["ok"]
        assert FW._FW.disable()["ok"]
        backend_port, backend_pid, report_fd = _backend()
        edge = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend_port,
                              listen_host="127.0.0.1", listen_port=_port())
        try:
            started = edge.serve_cluster(workers=2)
            expected = "single" if stateful else "cluster"
            assert started.get("ok") and started.get("mode") == expected, started
            assert len(started.get("child_pids") or []) == (0 if stateful else 1), started
            benign = _request(edge.listen_port, b"/before-r15")
            assert benign.startswith(b"HTTP/1.1 200") and b"GET /before-r15" in _received(report_fd)
            yield ND._SHIELD, FW._FW, edge, report_fd
        finally:
            edge.stop(grace=0)
            os.kill(backend_pid, signal.SIGTERM)
            os.waitpid(backend_pid, 0)
            os.close(report_fd)
            ND._SHIELD, FW._FW = old_shield, old_firewall


def _assert_new_rule_on_every_worker(edge, report_fd, path):
    wires = [_request(edge.listen_port, path) for _ in range(32)]
    backend = _received(report_fd)
    assert not any(wire.startswith(b"HTTP/1.1 200") for wire in wires), wires
    assert b"GET " + path not in backend, backend


def test_direct_parent_shield_config_enforced_after_safe_single_fallback():
    with _cluster(stateful=True) as (shield, _firewall, edge, report_fd):
        changed = shield.set_config(blocked_urls=["/direct-shield-r15"])
        assert changed.get("ok") is True, changed
        _assert_new_rule_on_every_worker(edge, report_fd, b"/direct-shield-r15")


def test_direct_parent_acl_rule_enforced_after_safe_single_fallback():
    with _cluster(stateful=True) as (_shield, firewall, edge, report_fd):
        assert firewall.enable()["ok"]
        changed = firewall.add_rule("127.0.0.1/32", "deny")
        assert changed.get("ok") is True, changed
        _assert_new_rule_on_every_worker(edge, report_fd, b"/direct-acl-r15")


def test_direct_parent_custom_signature_enforced_after_safe_single_fallback():
    with _cluster(stateful=True) as (shield, _firewall, edge, report_fd):
        changed = shield.add_signature("direct-r15", "r15sigmarker", weight=100)
        assert changed.get("ok") is True, changed
        _assert_new_rule_on_every_worker(edge, report_fd, b"/r15sigmarker")


def test_direct_parent_finite_quota_rejects_without_changing_live_cluster():
    """An acknowledged finite quota cannot be multiplied by forked workers."""
    with _cluster() as (shield, _firewall, edge, report_fd):
        before = Path(shield.path).read_bytes()
        old_cfg = dict(shield.cfg)
        changed = shield.set_config(quota_enabled=True, quota_max_gb=3e-7)
        assert changed.get("ok") is False, changed
        assert changed.get("changed") == {}, changed
        assert shield.cfg == old_cfg
        assert Path(shield.path).read_bytes() == before
        assert edge._workers and edge.is_alive()
        good = _request(edge.listen_port, b"/quota-rejected-r15")
        assert good.startswith(b"HTTP/1.1 200"), good
        assert b"GET /quota-rejected-r15" in _received(report_fd)


def test_other_instance_finite_quota_fails_closed_in_fork_workers():
    """A signed writer outside the active shield object cannot reopen quota."""
    with _cluster() as (shield, _firewall, edge, report_fd):
        writer = ND.NetShield(state_dir=os.path.dirname(shield.path))
        changed = writer.set_config(quota_enabled=True, quota_max_gb=3e-7)
        assert changed.get("ok") is True, changed
        wires = []
        for _ in range(32):
            try:
                wires.append(_request(edge.listen_port, b"/quota-other-writer-r15"))
            except OSError as exc:
                if exc.errno not in (errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                    raise
                wires.append(b"")  # an early fail-closed close may reset TCP
        assert not any(wire.startswith(b"HTTP/1.1 200") for wire in wires), wires
        assert b"GET /quota-other-writer-r15" not in _received(report_fd)
