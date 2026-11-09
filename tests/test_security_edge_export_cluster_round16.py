"""A fork-local BAN cannot be omitted from an acknowledged edge export."""

import os
import tempfile
from pathlib import Path
from unittest import SkipTest
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.services import edge_config


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-edge-cluster-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_active_cluster_export_preserves_prior_file_and_single_worker_control():
    with _state() as state:
        shield = pipeline.NetShield(state_dir=state)
        # Only an explicitly stateless policy may fork. The exporter still
        # refuses an incomplete parent view while that fork reservation lives.
        assert shield.set_config(enabled=False, persist_bans=False,
                                 max_total_conn=0, max_conn_per_ip=0,
                                 conn_rate_per_ip=0)["ok"]
        firewall = policy.AppFirewall(state_dir=state)
        output = Path(state) / "edge-banlist.txt"
        output.write_text("192.0.2.55\n", encoding="ascii")
        before = output.read_bytes()
        with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall):
            assert shield._reserve_fork_cluster()
            try:
                result = edge_config.export_banlist(str(output))
                assert result["ok"] is False, result
                assert output.read_bytes() == before
            finally:
                shield._release_fork_cluster()
            assert shield.enable()["ok"]
            assert shield.ban("192.0.2.9", permanent=True)["ok"]
            normal = edge_config.export_banlist(str(output))
            assert normal["ok"] is True, normal
            current = output.read_text(encoding="ascii")
            assert current.endswith("192.0.2.9\n"), current
            assert "192.0.2.55" not in current


def test_fork_child_only_ban_cannot_be_exported_as_empty_success():
    if not hasattr(os, "fork"):
        raise SkipTest("fork unavailable")
    with _state() as state:
        shield = pipeline.NetShield(state_dir=state)
        assert shield.set_config(enabled=False, persist_bans=False,
                                 max_total_conn=0, max_conn_per_ip=0,
                                 conn_rate_per_ip=0)["ok"]
        firewall = policy.AppFirewall(state_dir=state)
        output = Path(state) / "edge-banlist.txt"
        output.write_text("192.0.2.55\n", encoding="ascii")
        before = output.read_bytes()
        with patch.object(pipeline, "_SHIELD", shield), patch.object(policy, "_FW", firewall):
            assert shield._reserve_fork_cluster()
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    result = shield.ban("192.0.2.9", permanent=True)
                    os.write(write_fd, b"1" if result.get("ok") else b"0")
                finally:
                    os._exit(0)
            os.close(write_fd)
            try:
                assert os.read(read_fd, 1) == b"1"
                assert os.waitpid(pid, 0)[1] == 0
                assert not shield.is_banned_fast("192.0.2.9")  # fork copy omitted here
                result = edge_config.export_banlist(str(output))
                assert result["ok"] is False, result
                assert output.read_bytes() == before
            finally:
                os.close(read_fd)
                shield._release_fork_cluster()
