"""Local ACL scheduling, bounded matching, and coherent export snapshots."""
import copy
import ipaddress
import json
import os
import tempfile
import threading
import tracemalloc
from unittest import mock

from dataplane.engine.lifeform import policy as FW
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.services import edge_config as EC
from dataplane.engine.core.signed_state import write_signed_json
from dataplane.engine.core import atomic_io as AIO


def test_export_takes_one_joint_snapshot_when_a_deny_changes_owner():
    with tempfile.TemporaryDirectory() as directory:
        shield, firewall = NetShield(state_dir=directory), FW.AppFirewall(state_dir=directory)
        ip = "1.1.1.1"
        assert firewall.set_policy("public", "allow")["ok"]
        assert firewall.add_rule(ip + "/32", "deny")["ok"]
        reached, release = threading.Event(), threading.Event()
        result = {}
        def next_source():
            reached.set()
            assert release.wait(3)
            return firewall
        path = os.path.join(directory, "edge.txt")
        def export():
            result.update(EC.export_banlist(path))
        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=shield), \
                mock.patch.object(FW, "app_firewall", side_effect=next_source):
            worker = threading.Thread(target=export)
            worker.start()
            try:
                assert reached.wait(3)
                assert shield.ban(ip, permanent=True)["ok"]
                assert firewall.evaluate(ip)["action"] == "deny" and shield.is_banned_fast(ip)
                assert firewall.remove_rule(ip + "/32")["ok"]
            finally:
                release.set()
                worker.join(5)
        assert not worker.is_alive()
        assert result["ok"] is True and result["count"] == 1, result
        with open(path, encoding="utf-8") as handle:
            assert ip in handle.read()


def test_export_releases_state_locks_before_file_publication():
    with tempfile.TemporaryDirectory() as directory:
        shield, firewall = NetShield(state_dir=directory), FW.AppFirewall(state_dir=directory)
        completed = threading.Event()
        workers = []
        original = EC.atomic_write_text
        def update():
            assert shield.set_config(rate_per_sec=21)["ok"]
            assert firewall.set_policy("private", "deny")["ok"]
            completed.set()
        def publish(*args, **kwargs):
            worker = threading.Thread(target=update)
            workers.append(worker)
            worker.start()
            assert completed.wait(2), "file publication retained a policy lock"
            return original(*args, **kwargs)
        with mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=shield), \
                mock.patch.object(FW, "app_firewall", return_value=firewall), \
                mock.patch.object(EC, "atomic_write_text", side_effect=publish):
            result = EC.export_banlist(os.path.join(directory, "edge.txt"))
        for worker in workers:
            worker.join(3)
            assert not worker.is_alive()
        assert result["ok"] is True, result


def test_acl_slow_log_io_does_not_hold_policy_state():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        entered, release, seen = threading.Event(), threading.Event(), threading.Event()
        snapshots, decisions = [], []
        def slow_log(*_args, **_kwargs):
            entered.set()
            assert release.wait(3)
            return True
        def status():
            snapshots.append(firewall.status())
            seen.set()
        with mock.patch.object(FW, "append_jsonl", side_effect=slow_log):
            request = threading.Thread(target=lambda: decisions.append(firewall.evaluate("127.0.0.1")))
            request.start()
            reader = threading.Thread(target=status)
            try:
                assert entered.wait(2)
                reader.start()
                assert seen.wait(0.5), "status was blocked by unrelated log I/O"
                assert snapshots[0]["stats"]["by_action"]["allow"] == 1
            finally:
                release.set()
                request.join(3)
                if reader.ident is not None:
                    reader.join(3)
        assert not request.is_alive() and not reader.is_alive()
        assert decisions[0]["action"] == "allow"
        decisions[0]["action"] = "deny"
        assert firewall.log()[-1]["action"] == "allow"


def test_acl_match_stops_after_first_max_prefix_deny():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        firewall.rules[:] = [{"net": "192.0.2.7/32", "action": "deny", "id": "winner"}] + [
            {"net": "10.%d.%d.0/24" % (i // 256, i % 256), "action": "allow"}
            for i in range(4095)]
        original = ipaddress.IPv4Network.__contains__
        probes = []
        def contains(network, address):
            probes.append(None)
            return original(network, address)
        with mock.patch.object(ipaddress.IPv4Network, "__contains__", contains):
            assert firewall._match_rule("192.0.2.7")["id"] == "winner"
        assert len(probes) <= 1, len(probes)


def test_overlapping_acl_match_has_bounded_temporary_memory():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        firewall.rules[:] = [{"net": "10.%d.%d.1/8" % (i // 256, i % 256),
                              "action": "deny", "id": i} for i in range(4096)]
        assert firewall._match_rule("10.1.2.3")["id"] == 0
        tracemalloc.start()
        try:
            assert firewall._match_rule("10.1.2.3")["id"] == 0
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 32768, peak


def test_acl_deny_longest_firsttie_mapped_and_rule_mutations():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        firewall.rules[:] = [{"net": "192.0.2.0/24", "action": "deny", "id": "broad"},
                             {"net": "192.0.2.7/32", "action": "allow", "id": "allow"},
                             {"net": "192.0.2.0/28", "action": "deny", "id": "first"},
                             {"net": "192.0.2.1/28", "action": "deny", "id": "tie"},
                             {"net": "2001:db8::/32", "action": "allow", "id": "v6allow"},
                             {"net": "2001:db8::/64", "action": "deny", "id": "v6deny"}]
        assert firewall._match_rule("192.0.2.7")["id"] == "first"
        assert firewall.evaluate("::ffff:192.0.2.7")["rule"] == "192.0.2.0/28"
        assert firewall._match_rule("2001:db8::7")["id"] == "v6deny"
        firewall.rules[2]["action"] = "allow"
        assert firewall._match_rule("192.0.2.7")["id"] == "tie"
        firewall.rules = []
        assert firewall.add_rule("192.0.2.7/32", "deny")["ok"]
        before = copy.deepcopy(firewall.rules)
        with mock.patch.object(FW, "write_signed_json", return_value=False):
            assert firewall.remove_rule("192.0.2.7/32")["ok"] is False
        assert firewall.rules == before and firewall._match_rule("192.0.2.7")["action"] == "deny"
        restored = FW.AppFirewall(state_dir=directory)
        assert restored._match_rule("192.0.2.7")["action"] == "deny"
        assert firewall.remove_rule("192.0.2.7/32")["ok"]
        assert firewall._match_rule("192.0.2.7") is None


def test_acl_unverifiable_state_never_relaxes_saved_loopback_denial():
    for failure in ("tampered", "rolled_back", "deleted", "unsigned_replacement"):
        with tempfile.TemporaryDirectory() as directory:
            firewall = FW.AppFirewall(state_dir=directory)
            assert firewall.set_policy("loopback", "deny")["ok"]
            assert firewall.evaluate("127.0.0.1")["action"] == "deny"
            with open(firewall.path, "rb") as handle:
                previous = handle.read()
            assert firewall.add_rule("198.51.100.9/32", "deny")["ok"]
            if failure == "deleted":
                os.unlink(firewall.path)
            elif failure == "rolled_back":
                with open(firewall.path, "wb") as handle:
                    handle.write(previous)
            else:
                with open(firewall.path, encoding="utf-8") as handle:
                    envelope = json.load(handle)
                if failure == "tampered":
                    envelope["_payload"]["policy"]["public"] = "allow"
                else:
                    envelope = {"enabled": False, "policy": {"loopback": "allow"}, "rules": []}
                with open(firewall.path, "w", encoding="utf-8") as handle:
                    json.dump(envelope, handle)
            restarted = FW.AppFirewall(state_dir=directory)
            assert restarted.evaluate("127.0.0.1")["action"] == "deny", failure
            assert restarted.evaluate("10.0.0.2")["action"] == "deny", failure
            assert restarted.is_enabled() is True and restarted.rules == []
            assert set(restarted.policy.values()) == {"deny"}
            assert restarted.status()["load_warning"]


def test_acl_initial_missing_and_valid_saved_policy_keep_their_meaning():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        assert firewall.evaluate("127.0.0.1")["action"] == "allow"
        assert firewall.status()["load_warning"] == ""
        assert firewall.set_policy("loopback", "deny")["ok"]
        assert firewall.add_rule("198.51.100.9/32", "deny")["ok"]
        restarted = FW.AppFirewall(state_dir=directory)
        assert restarted.evaluate("127.0.0.1")["action"] == "deny"
        assert restarted.rules == firewall.rules and restarted.policy == firewall.policy
        assert restarted.status()["load_warning"] == ""
        assert restarted.disable()["ok"]
        off = FW.AppFirewall(state_dir=directory)
        assert off.is_enabled() is False
        assert off.evaluate("127.0.0.1")["action"] == "allow"
        assert off.status()["load_warning"] == ""


def test_mapped_ipv4_acl_rules_match_both_peer_forms_and_reload():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        for zone in FW.ZONES:
            assert firewall.set_policy(zone, "allow")["ok"]
        original = "::ffff:192.0.2.0/120"
        result = firewall.add_rule(original, "deny")
        assert result["ok"] is True
        assert firewall.evaluate("192.0.2.7")["action"] == "deny"
        assert firewall.evaluate("::ffff:192.0.2.7")["action"] == "deny"
        assert result["rules"][0]["net"] == "192.0.2.0/24"
        restarted = FW.AppFirewall(state_dir=directory)
        assert restarted.evaluate("192.0.2.7")["action"] == "deny"
        assert restarted.evaluate("192.0.3.7")["action"] == "allow"
        assert restarted.evaluate("2001:db8::7")["action"] == "allow"
        assert restarted.remove_rule(original)["removed"] == 1
        assert restarted.evaluate("192.0.2.7")["action"] == "allow"


def test_signed_legacy_mapped_acl_preserves_the_intended_deny():
    with tempfile.TemporaryDirectory() as directory:
        initial = FW.AppFirewall(state_dir=directory)
        assert write_signed_json(initial.path,
                                 {"enabled": True, "policy": {z: "allow" for z in FW.ZONES},
                                  "rules": [{"net": "::ffff:192.0.2.7/128", "action": "deny"}]},
                                 initial._state_key)
        restored = FW.AppFirewall(state_dir=directory)
        assert restored.evaluate("192.0.2.7")["action"] == "deny"
        assert restored.evaluate("::ffff:192.0.2.7")["action"] == "deny"
        assert restored.rules[0]["net"] == "192.0.2.7/32"


def test_mapped_ban_export_uses_the_real_ipv4_client_key():
    class Shield:
        cfg = {"mode": "enforce"}
        def is_enabled(self): return True
        def bans(self): return [{"ip": "::ffff:192.0.2.7"}, {"ip": "192.0.2.7"}]
    class Firewall:
        rules = []
        def is_enabled(self): return False
    with tempfile.TemporaryDirectory() as directory, \
            mock.patch("dataplane.engine.lifeform.pipeline.net_shield", return_value=Shield()), \
            mock.patch.object(FW, "app_firewall", return_value=Firewall()):
        path = os.path.join(directory, "edge.txt")
        result = EC.export_banlist(path)
        assert result["ok"] is True and result["count"] == 1, result
        with open(path, encoding="utf-8") as handle:
            rows = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
        assert rows == ["192.0.2.7"]


def test_ipv6_broad_network_family_and_ipv4_controls_stay_unchanged():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        firewall.policy = {z: "allow" for z in FW.ZONES}
        firewall.rules[:] = [{"net": "::/0", "action": "deny"}]
        assert firewall.evaluate("2001:db8::7")["action"] == "deny"
        assert firewall.evaluate("192.0.2.7")["action"] == "allow"
        assert firewall.evaluate("::ffff:192.0.2.7")["action"] == "allow"
        firewall.rules[:] = [{"net": "::fffe:0:0/95", "action": "deny"}]
        assert firewall.evaluate("::fffe:0:1")["action"] == "deny"
        assert firewall.evaluate("192.0.2.7")["action"] == "allow"
        firewall.rules[:] = [{"net": "192.0.2.0/24", "action": "deny"}]
        assert firewall.evaluate("192.0.2.7")["action"] == "deny"
        assert firewall.evaluate("::ffff:192.0.2.7")["action"] == "deny"
        assert firewall.evaluate("2001:db8::7")["action"] == "allow"
        firewall.rules[:] = [{"net": "::ffff:0:0/96", "action": "deny"}]
        assert firewall.evaluate("192.0.2.7")["action"] == "deny"
        assert firewall.evaluate("::ffff:192.0.2.7")["action"] == "deny"
        assert firewall.evaluate("2001:db8::7")["action"] == "allow"


def test_busy_acl_log_is_observable_without_changing_the_decision():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        lock = AIO._append_lock(firewall.log_path)
        lock.acquire()
        try:
            result = firewall.evaluate("127.0.0.1")
        finally:
            lock.release()
        assert result["action"] == "allow"
        assert result["log_written"] is False
        assert firewall.stats()["log_write_failed"] == 1
        assert firewall.status()["stats"]["log_write_failed"] == 1
        assert firewall.log()[-1]["log_written"] is False
        normal = firewall.evaluate("127.0.0.1")
        assert normal["action"] == "allow" and normal["log_written"] is True
        assert firewall.stats()["log_write_failed"] == 1
        with open(firewall.log_path, encoding="utf-8") as handle:
            assert json.loads(handle.readline())["action"] == "allow"


def test_acl_filesystem_log_failure_is_counted_and_memory_record_survives():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        with mock.patch.object(AIO, "_open_append_nofollow", side_effect=OSError("fixture log failure")):
            result = firewall.evaluate("127.0.0.1")
        assert result["action"] == "allow" and result["log_written"] is False
        assert firewall.stats()["log_write_failed"] == 1
        assert firewall.log()[-1]["action"] == "allow"


def test_deferred_acl_log_keeps_the_fixed_decision_and_does_no_inline_io():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        with mock.patch.object(FW, "append_jsonl") as append:
            decision = firewall.evaluate("127.0.0.1", _defer_log=True)
            append.assert_not_called()
        assert decision["action"] == "allow" and decision["log_written"] is None
        work = decision.pop("_acl_log_work")
        decision["action"] = "deny"
        assert firewall.set_policy("loopback", "deny")["ok"]
        rows = []
        def append(_path, row, **kwargs):
            rows.append(dict(row))
            assert kwargs["wait"] is False
            return True
        with mock.patch.object(FW, "append_jsonl", side_effect=append):
            assert firewall.write_acl_log(work) is True
        assert rows[0]["action"] == "allow" and firewall.log()[0]["action"] == "allow"
        assert firewall.evaluate("127.0.0.1")["action"] == "deny"


def test_deferred_acl_log_failure_is_counted_without_changing_memory_decision():
    with tempfile.TemporaryDirectory() as directory:
        firewall = FW.AppFirewall(state_dir=directory)
        decision = firewall.evaluate("127.0.0.1", _defer_log=True)
        lock = AIO._append_lock(firewall.log_path)
        lock.acquire()
        try:
            assert firewall.write_acl_log(decision["_acl_log_work"]) is False
        finally:
            lock.release()
        assert decision["action"] == "allow" and firewall.log()[-1]["action"] == "allow"
        assert firewall.status()["stats"]["log_write_failed"] == 1
