"""The first signed ACL save must not strand a fork worker on a marker-only gap."""

import os
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.policy as policy
import dataplane.engine.lifeform.pipeline as pipeline
from dataplane.engine.core.signed_state import read_signed_json
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r15-acl-first-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_first_acl_save_does_not_permanently_latch_a_pristine_worker():
    with _state() as state:
        parent = AppFirewall(state_dir=state)
        worker = AppFirewall(state_dir=state)  # fork-time policy copy
        assert not Path(parent.path).exists()
        assert not Path(parent._history_path).exists()
        assert worker.evaluate("127.0.0.1", _defer_log=True)["action"] == "allow"

        reached_write = threading.Event()
        release_write = threading.Event()
        outcome = []
        real_write = policy.write_signed_json

        def delayed_write(*args, **kw):
            reached_write.set()
            assert release_write.wait(5), "first ACL save did not resume"
            return real_write(*args, **kw)

        def save():
            outcome.append(parent.add_rule("203.0.113.0/24", "deny"))

        with patch.object(policy, "write_signed_json", delayed_write):
            writer = threading.Thread(target=save, daemon=True)
            writer.start()
            try:
                assert reached_write.wait(5), "first ACL save did not reach signed writer"
                # A marker-only state denies this admission, then retries
                # rather than permanently poisoning the child worker.
                assert worker.reload_verified() is False
                assert worker.evaluate("127.0.0.1", _defer_log=True)["action"] == "deny"
                assert worker.add_rule("198.51.100.0/24", "allow")["ok"] is False
                assert not Path(parent.path).exists()
            finally:
                release_write.set()
                writer.join(5)
        assert not writer.is_alive() and outcome and outcome[0]["ok"] is True, outcome
        assert Path(parent._history_path).is_file()
        assert worker.reload_verified() is True
        assert worker.evaluate("203.0.113.5", _defer_log=True)["action"] == "deny"
        assert worker.evaluate("127.0.0.1", _defer_log=True)["action"] == "allow"


def test_first_acl_save_gap_stays_closed_until_single_worker_after_ack():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=False, block_page=False,
                                 max_total_conn=0, max_conn_per_ip=0,
                                 conn_rate_per_ip=0)["ok"]
        parent = AppFirewall(state_dir=state)
        worker = AppFirewall(state_dir=state)
        # A pristine ACL has no file yet. Model the explicit OFF setting that
        # permits a stateless fork; the first parent save enables its own ACL.
        worker.enabled = False
        backend = _Backend()
        reached_write = threading.Event()
        release_write = threading.Event()
        outcome = []
        real_write = policy.write_signed_json

        def delayed_write(*args, **kw):
            reached_write.set()
            assert release_write.wait(5), "first ACL save did not resume"
            return real_write(*args, **kw)

        try:
            with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", worker), \
                    _guard(backend) as edge:
                edge._cluster_policy_sync = True  # same admission path as a fork child
                edge._single_cluster_policy_sync = False  # model a true child, not the direct single fallback
                before = _exchange(edge, [b"GET /acl-before HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                assert before.startswith(b"HTTP/1.1 200")
                with patch.object(policy, "write_signed_json", delayed_write):
                    writer = threading.Thread(
                        target=lambda: outcome.append(parent.add_rule(
                            "203.0.113.0/24", "deny")), daemon=True)
                    writer.start()
                    try:
                        assert reached_write.wait(5)
                        during = _exchange(edge, [
                            b"GET /acl-gap HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                        assert not during.startswith(b"HTTP/1.1 200"), during
                        assert b"GET /acl-gap" not in backend.saw(), backend.got
                    finally:
                        release_write.set()
                        writer.join(5)
                assert not writer.is_alive() and outcome and outcome[0]["ok"] is True, outcome
                unsafe = [_exchange(edge, [
                    b"GET /acl-after-commit HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                    for _ in range(12)]
                assert not any(wire.startswith(b"HTTP/1.1 200") for wire in unsafe), unsafe
                assert b"GET /acl-after-commit" not in backend.saw(), backend.got
                # The real admin path reaps fork children before accepting an
                # enabled ACL. This single-guard harness models that handoff.
                edge._cluster_policy_sync = False
                after = [_exchange(edge, [
                    b"GET /acl-after HTTP/1.1\r\nHost: local.test\r\n\r\n"])
                    for _ in range(12)]
                assert all(wire.startswith(b"HTTP/1.1 200") for wire in after), after
                assert backend.saw().count(b"GET /acl-after") == 12, backend.got
                assert worker.evaluate("203.0.113.5", _defer_log=True)["action"] == "deny"
        finally:
            release_write.set()
            backend.close()


def test_marker_failure_rejects_before_signed_acl_publication():
    with _state() as state:
        firewall = AppFirewall(state_dir=state)
        with patch.object(firewall, "_ensure_signed_history", return_value=False):
            result = firewall.add_rule("127.0.0.1/32", "deny")
        assert result["ok"] is False, result
        assert result.get("published") is not True, result
        assert firewall.is_enabled() is True
        assert not Path(firewall.path).exists()
        status, payload = read_signed_json(firewall.path, firewall._state_key, {})
        assert status == "missing" and payload == {}
        assert firewall.evaluate("127.0.0.1", _defer_log=True)["action"] == "allow"


def test_signed_acl_history_still_denies_after_main_and_highwater_deletion():
    with _state() as state:
        firewall = AppFirewall(state_dir=state)
        assert firewall.set_policy("public", "allow")["ok"]
        assert Path(firewall._history_path).is_file()
        Path(firewall.path).unlink()
        Path(firewall.path + ".hw").unlink()
        restarted = AppFirewall(state_dir=state)
        assert restarted.status()["load_warning"]
        assert restarted.evaluate("127.0.0.1", _defer_log=True)["action"] == "deny"


def test_seen_first_save_marker_cannot_be_removed_into_pristine_allow():
    with _state() as state:
        worker = AppFirewall(state_dir=state)
        Path(worker._history_path).write_text("acl:v1\n", encoding="ascii")
        assert worker.reload_verified() is False
        Path(worker._history_path).unlink()
        assert worker.reload_verified() is False
        assert worker.evaluate("127.0.0.1", _defer_log=True)["action"] == "deny"
