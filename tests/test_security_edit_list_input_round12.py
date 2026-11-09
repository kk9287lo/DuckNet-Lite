"""Round 12: list editing must publish exactly the requested validated entries."""

import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.core.atomic_io as atomic_io
from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


def _saved_list(shield, key):
    # Read the actual signed state bytes, not only the in-memory config view.
    envelope = json.loads(Path(shield.path).read_bytes())
    return envelope["_payload"]["cfg"][key]


def _request(host):
    return b"GET /safe HTTP/1.1\r\nHost: " + host.encode("ascii") + b"\r\n\r\n"


def test_scalar_domain_whitelist_set_has_one_saved_entry_and_enforce_wire():
    backend = _Backend()
    try:
        with _shield(mode="enforce", block_page=False) as shield:
            assert shield.set_config(site_mode="whitelist",
                                     site_whitelist=["good.example"])["ok"]
            result = shield.edit_list("domain", "white", "set", "good.example")
            with _guard(backend) as edge:
                denied = _exchange(edge, [_request("evil.e")])
                assert backend.got == [] and b"\r\n\r\nok" not in denied, (backend.got, denied)
                allowed = _exchange(edge, [_request("good.example")])
                assert len(backend.got) == 1 and backend.got[0].startswith(_request("good.example")[:-2])
                assert allowed.startswith(b"HTTP/1.1 200") and allowed.endswith(b"ok")
            assert result["ok"] is True and result["entries"] == ["good.example"], result
            assert shield.cfg["site_whitelist"] == ["good.example"]
            assert _saved_list(shield, "site_whitelist") == ["good.example"]
            assert NetShield(state_dir=str(Path(shield.path).parent)).cfg["site_whitelist"] == ["good.example"]
    finally:
        backend.close()


def test_scalar_domain_whitelist_audit_forwards_and_records_violation():
    backend = _Backend()
    try:
        with _shield(mode="audit", block_page=False) as shield:
            assert shield.set_config(site_mode="whitelist",
                                     site_whitelist=["good.example"])["ok"]
            assert shield.edit_list("domain", "white", "set", "good.example")["ok"]
            with _guard(backend) as edge:
                response = _exchange(edge, [_request("evil.e")])
            assert len(backend.got) == 1 and backend.got[0].startswith(_request("evil.e")[:-2])
            assert response.startswith(b"HTTP/1.1 200") and response.endswith(b"ok")
            assert any(e.get("kind") == "audit" and e.get("would") == "block"
                       for e in shield.events(20)), shield.events(20)
    finally:
        backend.close()


def test_scalar_add_and_remove_operate_on_whole_domain_or_ip():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(site_blacklist=["bad.example"], ip_blacklist=["192.0.2.1"])["ok"]
        added = shield.edit_list("domain", "black", "add", "evil.example")
        assert added["ok"] is True and added["entries"] == ["bad.example", "evil.example"], added
        assert _saved_list(shield, "site_blacklist") == ["bad.example", "evil.example"]
        removed = shield.edit_list("domain", "black", "remove", "bad.example")
        assert removed["ok"] is True and removed["entries"] == ["evil.example"], removed
        ip = shield.edit_list("ip", "black", "add", "192.0.2.9")
        assert ip["ok"] is True and ip["entries"] == ["192.0.2.1", "192.0.2.9"], ip
        assert _saved_list(shield, "ip_blacklist") == ip["entries"]


def test_scalar_ip_blacklist_set_really_blocks_address_and_persists():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, ip_mode="blacklist",
                                 ip_blacklist=["192.0.2.1"])["ok"]
        result = shield.edit_list("ip", "black", "set", "192.0.2.9")
        decision = shield.inspect("192.0.2.9", path="/safe")
        assert decision["action"] == "block", (result, decision)
        assert result["ok"] is True and result["entries"] == ["192.0.2.9"], result
        assert _saved_list(shield, "ip_blacklist") == ["192.0.2.9"]


def test_invalid_list_name_or_entry_rejects_without_memory_or_disk_change():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(site_blacklist=["bad.example"])["ok"]
        for listname, op, entries in (
                ("whitex", "set", ["good.example"]),
                ("other", "set", ["good.example"]),
                ("black", "set", ["safe.example", 7]),
                ("black", "set", [""]),
                ("black", "add", ["safe.example", ""]),
                ("black", "remove", ["bad.example", ""]),
                ("black", "clear", ["ignored.example"])):
            before_cfg = copy.deepcopy(shield.cfg)
            before_wire = Path(shield.path).read_bytes()
            result = shield.edit_list("domain", listname, op, entries)
            assert result.get("ok") is False, (listname, op, entries, result)
            assert shield.cfg == before_cfg
            assert Path(shield.path).read_bytes() == before_wire
        assert _saved_list(shield, "site_blacklist") == ["bad.example"]


def test_valid_list_and_tuple_forms_remain_usable():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.edit_list("domain", "black", "set", ["bad.example"])["ok"]
        assert shield.edit_list("domain", "black", "add",
                                ("other.example", "other.example"))["ok"]
        assert _saved_list(shield, "site_blacklist") == ["bad.example", "other.example"]
        before = Path(shield.path).read_bytes()
        duplicate = shield.edit_list("domain", "black", "set",
                                     ("third.example", "third.example"))
        assert duplicate["ok"] is False
        assert Path(shield.path).read_bytes() == before
        assert shield.cfg["site_blacklist"] == ["bad.example", "other.example"]


def test_post_publication_durability_failure_keeps_new_state_and_reports_it():
    with tempfile.TemporaryDirectory() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(site_blacklist=["bad.example"])["ok"]
        # The first two directory syncs belong to the signed high-water file;
        # the next two bracket the main state's replace. Fail only the last
        # sync, after both signed files have actually been published.
        with patch.object(atomic_io, "_sync_directory",
                          side_effect=[True, True, True, False]) as synced:
            result = shield.edit_list("domain", "black", "add", ["evil.example"])
        assert synced.call_count == 4
        assert shield.cfg["site_blacklist"] == ["bad.example", "evil.example"]
        assert _saved_list(shield, "site_blacklist") == shield.cfg["site_blacklist"]
        assert result.get("ok") is False and result.get("applied_in_memory") is True, result
        assert result.get("published") is True and result.get("durable") is False, result
        assert result.get("persisted") is False and result.get("entries") == shield.cfg["site_blacklist"]
