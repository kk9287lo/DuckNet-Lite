"""A failed bundle must retain its old configuration and banlist."""
import os
import tempfile
from unittest import mock

from dataplane.engine.services import edge_config as EC
from dataplane.engine.core import atomic_io as AIO
from test_sweep_ldap_edge import _FakeShield, _FakeFirewall


def _sources():
    return (mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=_FakeShield()),
            mock.patch("dataplane.engine.lifeform.policy.app_firewall", return_value=_FakeFirewall()))


def test_bundle_config_write_failure_preserves_both_old_files():
    with tempfile.TemporaryDirectory() as directory:
        paths = [os.path.join(directory, n) for n in ("edge_banlist.txt", "ducknet_edge.conf")]
        old = ["192.0.2.99\n", "old config\n"]
        for path, text in zip(paths, old):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
        real_write = EC.atomic_write_text

        def write(path, text, **kwargs):
            if os.path.abspath(path) == os.path.abspath(paths[1]):
                return False
            return real_write(path, text, **kwargs)

        shield, firewall = _sources()
        with shield, firewall, mock.patch.object(EC, "atomic_write_text", write):
            result = EC.write_bundle(directory)
        assert result["ok"] is False
        for path, text in zip(paths, old):
            with open(path, encoding="utf-8") as handle:
                assert handle.read() == text


def test_bundle_rejects_config_injection_before_changing_any_artifacts():
    with tempfile.TemporaryDirectory() as directory:
        shield, firewall = _sources()
        with shield, firewall:
            good = EC.write_bundle(directory, backend="127.0.0.1:8080", listen=8081)
            assert good["ok"] is True
            with open(good["config"], "rb") as handle:
                old_config = handle.read()
            with open(good["banlist"], "rb") as handle:
                old_bans = handle.read()
            for kwargs in ({"backend": "127.0.0.1:80; } server { listen 9; #"},
                           {"listen": "8080; include /tmp/x;"}, {"listen": True},
                           {"listen": 0}, {"backend": "user:password@127.0.0.1:80"},
                           {"backend": "127.0.0.1:"}, {"backend": "[::1]:"}):
                result = EC.write_bundle(directory, **kwargs)
                assert result["ok"] is False, kwargs
                with open(good["config"], "rb") as handle:
                    assert handle.read() == old_config
                with open(good["banlist"], "rb") as handle:
                    assert handle.read() == old_bans


def test_bundle_output_error_is_failure_result_not_an_exception():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "file")
        with open(path, "w") as handle:
            handle.write("retained")
        result = EC.write_bundle(path)
        assert result["ok"] is False
        with open(path) as handle:
            assert handle.read() == "retained"


def test_bundle_failed_rollback_is_explicit_partial_failure():
    with tempfile.TemporaryDirectory() as directory:
        bans = os.path.join(directory, "edge_banlist.txt")
        conf = os.path.join(directory, "ducknet_edge.conf")
        for path in (bans, conf):
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write("old\n")
        real_write = EC.atomic_write_text

        def write(path, text, **kwargs):
            if path == conf:
                raise OSError("configuration disk failure")
            if path == bans and text == "old\n":
                return False
            return real_write(path, text, **kwargs)

        shield, firewall = _sources()
        with shield, firewall, mock.patch.object(EC, "atomic_write_text", write):
            result = EC.write_bundle(directory)
        assert result["ok"] is False and result["partial"] is True
        with open(bans, encoding="utf-8") as handle:
            assert handle.read() != "old\n"
        with open(conf, encoding="utf-8") as handle:
            assert handle.read() == "old\n"


def test_post_publish_sync_failure_is_not_reported_as_success():
    for bundle in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            bans = os.path.join(directory, "edge_banlist.txt")
            conf = os.path.join(directory, "ducknet_edge.conf")
            for path in (bans, conf):
                with open(path, "w", encoding="utf-8", newline="") as handle:
                    handle.write("old\r\n")
            target = conf if bundle else bans
            real_write = EC.atomic_write_text
            injected = []

            def write(path, text, **kwargs):
                if path == target and not injected:
                    injected.append(path)
                    with mock.patch.object(AIO, "_sync_directory", side_effect=(True, False)):
                        return real_write(path, text, **kwargs)
                return real_write(path, text, **kwargs)

            shield, firewall = _sources()
            with shield, firewall, mock.patch.object(EC, "atomic_write_text", write):
                result = EC.write_bundle(directory) if bundle else EC.export_banlist(bans)
            assert result["ok"] is False, result
            assert result.get("partial") is not True, result
            for path in (bans, conf):
                with open(path, "rb") as handle:
                    assert handle.read() == b"old\r\n"
