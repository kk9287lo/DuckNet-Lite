"""Fork policy reload preserves local work and fails closed on bad signed state."""

import asyncio
import json
import os
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r15-reload-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_acl_reload_keeps_pending_and_log_after_valid_parent_update():
    with _state() as state:
        child = AppFirewall(state_dir=state)
        assert child.set_policy("public", "prompt")["ok"]
        parent = AppFirewall(state_dir=state)
        pending = child.evaluate("8.8.8.8", _defer_log=True)
        assert pending["action"] == "pending"
        pending_id = pending["pending_id"]
        before_pending = child.pending()
        before_log = child.log()
        assert len(before_pending) == len(before_log) == 1

        assert parent.add_rule("127.0.0.1/32", "deny")["ok"]
        assert child.reload_verified() is True
        assert child.pending() == before_pending
        assert child.log() == before_log
        assert child._pending_by_ip["8.8.8.8"] == pending_id
        assert child.evaluate("127.0.0.1", _defer_log=True)["action"] == "deny"
        assert child._nets["127.0.0.1/32"].with_prefixlen == "127.0.0.1/32"


def test_invalid_signed_acl_reload_blocks_and_retains_evidence():
    with _state() as state:
        child = AppFirewall(state_dir=state)
        assert child.set_policy("public", "allow")["ok"]
        original = Path(child.path).read_bytes()
        envelope = json.loads(original)
        envelope["_sig"] = ("0" if envelope["_sig"][0] != "0" else "1") + envelope["_sig"][1:]
        tampered = json.dumps(envelope).encode("utf-8")
        Path(child.path).write_bytes(tampered)
        assert child.reload_verified() is False
        assert child.evaluate("127.0.0.1", _defer_log=True)["action"] == "deny"
        assert child._reload_untrusted is True
        assert Path(child.path).read_bytes() == tampered


def test_high_water_only_change_rechecks_signature_before_next_admission():
    with _state() as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        assert firewall.set_policy("public", "allow")["ok"]
        guard = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0)
        guard._cluster_policy_sync = True
        # Internal signed reload seam; production stateful fork startup is
        # rejected by the cluster fallback real-wire tests.
        guard._cluster_unshared_reason = lambda *_: ""
        import dataplane.engine.lifeform.pipeline as pipeline
        import dataplane.engine.lifeform.policy as policy
        old_shield, old_firewall = pipeline._SHIELD, policy._FW
        try:
            pipeline._SHIELD, policy._FW = shield, firewall
            first = guard._sync_cluster_policy()
            assert first is not None
            original = Path(shield.path + ".hw").read_bytes()
            Path(shield.path + ".hw").write_bytes(original + b"x")
            try:
                guard._sync_cluster_policy()
            except RuntimeError:
                pass
            else:
                raise AssertionError("tampered high-water file was accepted")
        finally:
            pipeline._SHIELD, policy._FW = old_shield, old_firewall


def test_parent_update_while_backend_connect_waits_sends_no_request_bytes():
    """A decision made before the parent ack cannot write after that ack."""
    import dataplane.engine.lifeform.pipeline as pipeline
    import dataplane.engine.lifeform.policy as policy
    with _state() as state:
        shield = NetShield(state_dir=state)
        firewall = AppFirewall(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False)["ok"]
        backend = _Backend()
        opened = threading.Event()
        release = threading.Event()
        result = []
        try:
            with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall), \
                    _guard(backend) as edge:
                edge._cluster_policy_sync = True
                edge._cluster_unshared_reason = lambda *_: ""
                original_open = edge._open_backend

                async def paused_open():
                    connection = await original_open()
                    opened.set()
                    while not release.is_set():
                        await asyncio.sleep(0.005)
                    return connection

                edge._open_backend = paused_open
                client = threading.Thread(
                    target=lambda: result.append(_exchange(
                        edge, [b"GET /r15late HTTP/1.1\r\nHost: local.test\r\n\r\n"])),
                    daemon=True)
                client.start()
                assert opened.wait(5), "old decision never reached backend connect"
                changed = shield.set_config(blocked_urls=["/r15late"])
                assert changed.get("ok") is True, changed
                release.set()
                client.join(5)
                assert not client.is_alive()
                assert result and not result[0].startswith(b"HTTP/1.1 200"), result
            assert b"GET /r15late" not in backend.saw(), backend.got
        finally:
            release.set()
            backend.close()
