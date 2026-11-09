"""Legacy signed envelopes cannot be replayed across state purposes."""

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.core import signed_state as ss
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from test_sweep_proxy_request import _Backend, _guard, _exchange


_IP = "127.0.0.1"
_REQUEST = b"GET /safe HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"


def _legacy_v2(path, payload, version, key):
    envelope = {"_sv": 2, "_ver": version, "_payload": payload}
    envelope["_sig"] = ss.sign_payload({"_ver": version, "_payload": payload}, key)
    Path(path).write_text(json.dumps(envelope), encoding="utf-8")
    assert ss._write_file_hw(str(path), version, key, min_sv=2)


def _legacy_v1(path, payload, key):
    envelope = {"_sv": 1, "_payload": payload,
                "_sig": ss.sign_payload(payload, key)}
    Path(path).write_text(json.dumps(envelope), encoding="utf-8")


def _wire_with_state(directory):
    shield = ND.NetShield(state_dir=directory)
    firewall = FW.AppFirewall(state_dir=directory)
    backend = _Backend()
    try:
        with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
            with _guard(backend) as guard:
                response = _exchange(guard, [_REQUEST], timeout=4.0)
        return shield, backend.saw(), response
    finally:
        backend.close()


def _wire_with_acl(directory):
    shield = ND.NetShield(state_dir=directory)
    firewall = FW.AppFirewall(state_dir=directory)
    backend = _Backend()
    try:
        with patch.object(ND, "_SHIELD", shield), patch.object(FW, "_FW", firewall):
            with _guard(backend) as guard:
                response = _exchange(guard, [_REQUEST], timeout=4.0)
        return firewall, backend.saw(), response
    finally:
        backend.close()


def test_same_purpose_legacy_v2_ban_still_blocks_real_backend_wire():
    with tempfile.TemporaryDirectory() as directory:
        key = ss.persistent_key(directory)
        banfile = os.path.join(directory, "blocklist.json")
        ban = {"bans": {_IP: {"until": None, "permanent": True,
                               "count": 1, "started": time.time()}}}
        _legacy_v2(banfile, ban, int(time.time() * 1000), key)
        shield, backend_wire, client_wire = _wire_with_state(directory)
        assert shield.is_banned_fast(_IP)
        assert not shield._ban_state_untrusted
        assert backend_wire == b""
        assert client_wire.startswith(b"HTTP/1.1 403"), client_wire[:100]


def test_newer_legacy_usage_envelope_cannot_erase_ban_or_advance_highwater():
    with tempfile.TemporaryDirectory() as directory:
        key = ss.persistent_key(directory)
        banfile = os.path.join(directory, "blocklist.json")
        usagefile = os.path.join(directory, "usage.json")
        version = int(time.time() * 1000)
        ban = {"bans": {_IP: {"until": None, "permanent": True,
                               "count": 1, "started": time.time()}}}
        _legacy_v2(banfile, ban, version, key)
        _legacy_v2(usagefile, {"usage": {}}, version + 10, key)
        # The local attacker can copy a valid signed body, but does not sign it.
        # Keep the target's own valid v2 high-water and signed-history marker.
        shutil.copyfile(usagefile, banfile)
        (Path(directory) / ".state_signed").write_text("legacy\n", encoding="utf-8")
        assert ss._read_file_hw_meta(banfile, key) == (version, 2, True)
        shield, backend_wire, client_wire = _wire_with_state(directory)
        assert shield._ban_state_untrusted
        assert backend_wire == b"", backend_wire
        assert not client_wire.startswith(b"HTTP/1.1 200"), client_wire[:100]
        assert ss._read_file_hw_meta(banfile, key) == (version, 2, True)


def test_unversioned_signed_usage_cannot_replace_a_legacy_ban():
    with tempfile.TemporaryDirectory() as directory:
        key = ss.persistent_key(directory)
        banfile = os.path.join(directory, "blocklist.json")
        usagefile = os.path.join(directory, "usage.json")
        ban = {"bans": {_IP: {"until": None, "permanent": True,
                               "count": 1, "started": time.time()}}}
        _legacy_v1(banfile, ban, key)
        _legacy_v1(usagefile, {"usage": {}}, key)
        shutil.copyfile(usagefile, banfile)
        (Path(directory) / ".state_signed").write_text("legacy\n", encoding="utf-8")
        shield, backend_wire, client_wire = _wire_with_state(directory)
        assert shield._ban_state_untrusted
        assert backend_wire == b"", backend_wire
        assert not client_wire.startswith(b"HTTP/1.1 200"), client_wire[:100]


def test_legacy_usage_replay_cannot_clear_config_or_custom_signatures():
    for filename, legitimate, flag in (
            ("state.json", {"cfg": {"enabled": True}}, "_cfg_state_untrusted"),
            ("rules.json", {"signatures": []}, "_sig_state_untrusted")):
        with tempfile.TemporaryDirectory() as directory:
            key = ss.persistent_key(directory)
            target = os.path.join(directory, filename)
            usagefile = os.path.join(directory, "usage.json")
            version = int(time.time() * 1000)
            _legacy_v2(target, legitimate, version, key)
            _legacy_v2(usagefile, {"usage": {}}, version + 10, key)
            shutil.copyfile(usagefile, target)
            (Path(directory) / ".state_signed").write_text("legacy\n", encoding="utf-8")
            shield, backend_wire, client_wire = _wire_with_state(directory)
            assert getattr(shield, flag), filename
            assert backend_wire == b"", (filename, backend_wire)
            assert not client_wire.startswith(b"HTTP/1.1 200"), filename
            assert ss._read_file_hw_meta(target, key) == (version, 2, True)


def test_legacy_acl_v1_same_purpose_still_loads_and_forwards():
    with tempfile.TemporaryDirectory() as directory:
        key = ss.persistent_key(directory)
        aclfile = os.path.join(directory, "acl.json")
        _legacy_v1(aclfile, {"enabled": True,
                             "policy": {"loopback": "allow"}, "rules": []}, key)
        firewall, backend_wire, client_wire = _wire_with_acl(directory)
        assert firewall.enabled and firewall.policy["loopback"] == "allow"
        assert backend_wire.startswith(b"GET /safe HTTP/1.1\r\n"), backend_wire
        assert client_wire.startswith(b"HTTP/1.1 200"), client_wire[:100]


def test_newer_legacy_usage_replay_cannot_poison_acl_highwater_or_lock_out_repair():
    with tempfile.TemporaryDirectory() as directory:
        key = ss.persistent_key(directory)
        aclfile = os.path.join(directory, "acl.json")
        usagefile = os.path.join(directory, "usage.json")
        version = int(time.time() * 1000)
        _legacy_v2(aclfile, {"enabled": True,
                             "policy": {"loopback": "allow"}, "rules": []}, version, key)
        original = Path(aclfile).read_bytes()
        _legacy_v2(usagefile, {"usage": {}}, version + 10, key)
        shutil.copyfile(usagefile, aclfile)
        assert ss._read_file_hw_meta(aclfile, key) == (version, 2, True)
        attacked, bad_backend, bad_client = _wire_with_acl(directory)
        assert attacked.enabled and attacked.policy["loopback"] == "deny"
        assert bad_backend == b"", bad_backend
        assert not bad_client.startswith(b"HTTP/1.1 200"), bad_client[:100]
        assert ss._read_file_hw_meta(aclfile, key) == (version, 2, True)
        # A real operator can restore the original valid v2 file; the forged
        # higher version did not become an irreversible rollback floor.
        Path(aclfile).write_bytes(original)
        repaired, good_backend, good_client = _wire_with_acl(directory)
        assert repaired.enabled and repaired.policy["loopback"] == "allow"
        assert good_backend.startswith(b"GET /safe HTTP/1.1\r\n"), good_backend
        assert good_client.startswith(b"HTTP/1.1 200"), good_client[:100]
