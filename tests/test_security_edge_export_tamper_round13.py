"""An edge export must not replace a known deny list with untrusted state."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.services import edge_config as edge


def _export(path, shield, firewall):
    with patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=shield), \
            patch("dataplane.engine.lifeform.policy.app_firewall", return_value=firewall):
        return edge.export_banlist(str(path))


def test_corrupt_signed_bans_cannot_publish_a_successful_empty_edge_list():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state, "edge_banlist.txt")
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert shield.ban("192.0.2.18", permanent=True)["ok"]
        firewall = AppFirewall(state_dir=state)
        good = _export(path, shield, firewall)
        assert good["ok"] and b"192.0.2.18\n" in path.read_bytes()
        previous = path.read_bytes()

        Path(shield._bans_path).write_bytes(b"{}")
        restarted = NetShield(state_dir=state)
        assert restarted._ban_state_untrusted
        result = _export(path, restarted, firewall)
        assert result["ok"] is False, result
        assert path.read_bytes() == previous
        conf = Path(state, "ducknet_edge.conf")
        conf.write_bytes(b"previous config\n")
        with patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=restarted), \
                patch("dataplane.engine.lifeform.policy.app_firewall", return_value=firewall):
            bundle = edge.write_bundle(state)
        assert bundle["ok"] is False, bundle
        assert path.read_bytes() == previous
        assert conf.read_bytes() == b"previous config\n"


def test_corrupt_signed_acl_cannot_publish_a_successful_empty_edge_list():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state, "edge_banlist.txt")
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        firewall = AppFirewall(state_dir=state)
        assert firewall.enable()["ok"]
        path.write_bytes(b"192.0.2.19\n")
        previous = path.read_bytes()

        Path(firewall.path).write_bytes(b"{}")
        restarted = AppFirewall(state_dir=state)
        assert restarted.status()["load_warning"]
        assert restarted.is_enabled()
        result = _export(path, shield, restarted)
        assert result["ok"] is False, result
        assert path.read_bytes() == previous


def test_healthy_signed_sources_still_export_the_exact_ban():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state, "edge_banlist.txt")
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        assert shield.ban("192.0.2.20", permanent=True)["ok"]
        firewall = AppFirewall(state_dir=state)
        assert firewall.enable()["ok"]
        good = _export(path, NetShield(state_dir=state), AppFirewall(state_dir=state))
        assert good["ok"] and good["count"] == 1, good
        assert b"192.0.2.20\n" in path.read_bytes()
