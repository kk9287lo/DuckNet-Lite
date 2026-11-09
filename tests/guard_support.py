"""Ownership-aware shutdown for network test fixtures."""

import time


def stateless_fork_policy():
    """Create a real fork-safe policy fixture for cluster lifecycle tests.

    Both process-local defenses are deliberately OFF and proxy connection
    limits are zero. Tests that need an active defense must assert the honest
    single-worker fallback or a fail-closed signed transition instead.
    """
    from contextlib import contextmanager
    import os
    import tempfile
    from unittest.mock import patch

    from dataplane.engine.lifeform import pipeline, policy

    @contextmanager
    def fixture():
        with tempfile.TemporaryDirectory(prefix="ducknet-stateless-fork-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            shield = pipeline.NetShield(state_dir=state)
            firewall = policy.AppFirewall(state_dir=state)
            assert shield.set_config(enabled=False, max_total_conn=0,
                                     max_conn_per_ip=0, conn_rate_per_ip=0)["ok"]
            assert firewall.disable()["ok"]
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall):
                yield shield, firewall, state

    return fixture()


def stop_guard_owned(guard, *, grace: float = 1.0, wait: float = 3.0):
    """Finish guard-owned diagnostic writes before deleting its temporary state.

    A zero-grace stop can correctly report stopped=False while an ACL/usage log
    worker still owns a file handle. Fixture cleanup must not race that worker.
    """
    result = guard.stop(grace=grace)
    deadline = time.monotonic() + wait
    while result.get("stopped") is not True and time.monotonic() < deadline:
        time.sleep(0.01)
        result = guard.stop(grace=0)
    assert result.get("stopped") is True, result
    return result
