"""Bounded configuration and benign hot-path regressions."""
import json
import os
import select
import tempfile
import threading
from unittest import SkipTest, mock

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.core.signed_state import write_signed_json
from test_sweep_proxy_request import _Backend, _guard, _exchange


def _shield(directory):
    shield = pipeline.NetShield(state_dir=directory)
    assert shield.enable()["ok"]
    return shield


def test_empty_override_does_not_repeat_private_path_normalization():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(private_paths=["/private"],
                                 private_path_allow=["127.0.0.1"])["ok"]
        seen = []
        original = shield._privacy_policy_block

        def recorded(ip, path):
            seen.append(path)
            return original(ip, path)

        shield._privacy_policy_block = recorded
        result = shield.inspect("192.0.2.1", path="/public", method="GET",
                                override_path="")
        assert result["action"] == "allow"
        assert "" not in seen
        blocked = shield.inspect("192.0.2.2", path="/public", method="GET",
                                 override_path=("/public/new", "/private/file"))
        assert blocked["action"] == "block"


def test_generic_scan_lists_reject_count_item_bytes_total_bytes_and_bad_values():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(blocked_urls=["/deny"])["ok"]
        before = shield.status()["cfg"]
        invalid = ([f"/r{i}" for i in range(513)],
                   ["/" + "x" * 512],
                   [f"/{i:03d}" + "é" * 200 for i in range(200)],
                   ["/safe", ""], ["/safe", "  "],
                   ["/Safe", "/safe"], ["/safe", float("nan")],
                   ["/safe", "\ud800"])
        for entries in invalid:
            result = shield.set_config(blocked_urls=entries, rate_per_sec=17)
            assert result["ok"] is False and result["changed"] == {}
            assert "blocked_urls" in result["rejected"]
            assert shield.cfg == before
        assert shield.inspect("192.0.2.3", path="/deny")["action"] == "block"
        assert shield.inspect("192.0.2.4", path="/public")["action"] == "allow"
        good = [f"/bounded{i}" for i in range(512)]
        result = shield.set_config(blocked_urls=good)
        assert result["ok"] is True and shield.cfg["blocked_urls"] == good


def test_other_generic_scan_lists_share_strict_limits_and_valid_empty_lists():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        for key in ("site_blacklist", "ip_whitelist", "trusted_proxies",
                    "upload_deny_ext", "open_redirect_allow"):
            before = shield.status()["cfg"]
            result = shield.set_config(**{key: ["x"] * 513, "rate_per_sec": 17})
            assert result["ok"] is False and shield.cfg == before
            assert key in result["rejected"]
            assert shield.set_config(**{key: []})["ok"] is True


def test_ip_cidr_lists_strip_only_outer_ascii_spaces_before_strict_validation():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        result = shield.set_config(ip_mode="blacklist",
                                   ip_blacklist=[" 203.0.113.9 ", " 2001:db8::/32 "])
        assert result["ok"] is True
        assert shield.cfg["ip_blacklist"] == ["203.0.113.9", "2001:db8::/32"]
        assert shield.inspect("203.0.113.9", path="/")["action"] == "block"
        assert shield.inspect("2001:db8::7", path="/")["action"] == "block"
        assert shield.inspect("192.0.2.9", path="/")["action"] == "allow"
        for key in ("ip_whitelist", "geo_cidrs", "trusted_proxies"):
            assert shield.set_config(**{key: [" 192.0.2.0/24 "]})["ok"] is True
            assert shield.cfg[key] == ["192.0.2.0/24"]
        before = shield.status()["cfg"]
        for bad in ([" 203.0.113.9 ", "203.0.113.9"], ["  "],
                    ["\t203.0.113.9"], [" " * 513 + "203.0.113.9"],
                    ["203.0.113.9"] * 513):
            result = shield.set_config(ip_blacklist=bad, rate_per_sec=17)
            assert result["ok"] is False and result["changed"] == {}
            assert "ip_blacklist" in result["rejected"]
            assert shield.cfg == before
        restored = pipeline.NetShield(state_dir=directory)
        assert restored.cfg["ip_blacklist"] == shield.cfg["ip_blacklist"]


def test_invalid_site_list_reports_rejected_mode_for_atomic_patch():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        for apply in (lambda: shield.set_config(site_mode="whitelist",
                                                site_whitelist=["  ", ""]),
                      lambda: shield.apply_config({"site_mode": "whitelist",
                                                   "site_whitelist": ["  ", ""]})):
            before = shield.status()["cfg"]
            result = apply()
            assert result["ok"] is False
            assert {"site_mode", "site_whitelist"} <= set(result["rejected"])
            assert shield.cfg == before


def test_legacy_signed_deny_list_is_preserved_and_warning_is_visible():
    with tempfile.TemporaryDirectory() as directory:
        seed = _shield(directory)
        old_deny = [f"/legacy{i}" for i in range(600)]
        assert write_signed_json(seed.path,
                                 {"cfg": {"enabled": True, "blocked_urls": old_deny},
                                  "rev": pipeline._CFG_REV}, seed._state_key)
        restored = pipeline.NetShield(state_dir=directory)
        assert restored.cfg["blocked_urls"] == old_deny
        assert restored.inspect("192.0.2.5", path="/legacy599")["action"] == "block"
        assert restored.inspect("192.0.2.6", path="/public")["action"] == "allow"
        warnings = restored.config_warnings()
        assert any(w["code"] == "cfg_legacy_list_budget"
                   and "blocked_urls" in w["keys"] for w in warnings)
        assert restored.set_config(blocked_urls=["/fixed"])["ok"]
        assert not any(w["code"] == "cfg_legacy_list_budget"
                       for w in restored.config_warnings())


def test_legacy_signed_allow_list_keeps_existing_access_decisions():
    with tempfile.TemporaryDirectory() as directory:
        seed = _shield(directory)
        old_allow = [f"host{i}.example" for i in range(600)]
        assert write_signed_json(seed.path,
                                 {"cfg": {"enabled": True, "site_mode": "whitelist",
                                          "site_whitelist": old_allow},
                                  "rev": pipeline._CFG_REV}, seed._state_key)
        restored = pipeline.NetShield(state_dir=directory)
        assert restored.cfg["site_whitelist"] == old_allow
        assert restored.inspect("192.0.2.8", path="/public",
                                host="host599.example")["action"] == "allow"
        assert restored.inspect("192.0.2.9", path="/public",
                                host="outside.example")["action"] == "block"
        assert any("site_whitelist" in w["keys"] for w in restored.config_warnings()
                   if w["code"] == "cfg_legacy_list_budget")


def test_invalid_declarative_list_does_not_partially_disable_protection():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(blocked_urls=["/admin"])["ok"]
        result = shield.apply_config({"blocked_urls": [f"/item{i}" for i in range(513)],
                                      "enabled": False})
        assert result["ok"] is False and result["applied"] == []
        assert shield.cfg["enabled"] is True
        assert shield.inspect("192.0.2.10", path="/admin")["action"] == "block"


def test_invalid_mixed_patch_preserves_real_wire_block_and_benign_pass():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(blocked_urls=["/deny"])["ok"]
        rejected = shield.set_config(blocked_urls=[f"/item{i}" for i in range(513)],
                                     mode="audit")
        assert rejected["ok"] is False and shield.cfg["mode"] == "enforce"
        backend = _Backend()
        try:
            with mock.patch.object(pipeline, "_SHIELD", shield), mock.patch.object(
                    policy, "_FW", policy.AppFirewall(state_dir=directory)):
                with _guard(backend) as guard:
                    denied = _exchange(guard, [b"GET /deny HTTP/1.1\r\nHost: app.example\r\n\r\n"])
                    assert backend.saw() == b"" and b"403" in denied.split(b"\r\n", 1)[0]
                    allowed = _exchange(guard, [b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"])
                    assert b"GET /public HTTP/1.1\r\n" in backend.saw()
                    assert allowed.startswith(b"HTTP/1.1 200")
        finally:
            backend.close()


def test_usage_log_io_does_not_hold_the_request_state_lock():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        entered, release, inspected = threading.Event(), threading.Event(), threading.Event()
        original = pipeline._open_state_write

        def paused(path, mode):
            if path == shield._usage_log_path and mode == "a":
                entered.set()
                assert release.wait(3)
            return original(path, mode)

        def write_usage():
            shield.record_traffic("192.0.2.101", out_bytes=12, host="example.test",
                                  method="GET", path="/public")

        def inspect():
            shield.inspect("192.0.2.102", path="/public")
            inspected.set()

        with mock.patch.object(pipeline, "_open_state_write", side_effect=paused):
            writer = threading.Thread(target=write_usage)
            reader = threading.Thread(target=inspect)
            writer.start()
            try:
                assert entered.wait(3)
                reader.start()
                assert inspected.wait(.2), "a slow usage log blocked benign inspection"
            finally:
                release.set()
                writer.join(3)
                reader.join(3)
        assert not writer.is_alive() and not reader.is_alive()


def test_deferred_log_work_is_ordered_and_old_generation_is_cleared():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        first = shield.record_traffic("192.0.2.103", out_bytes=5,
                                      method="GET", path="/before?token=private",
                                      _defer_log=True)
        work = first["_usage_log_work"]
        assert shield.usage_log() == []
        assert shield.write_usage_log(work) is True
        assert shield.usage_log()[0]["path"] == "/before"
        stale = shield.record_traffic("192.0.2.103", out_bytes=5,
                                      method="GET", path="/stale", _defer_log=True)
        assert shield.usage_clear()["ok"] is True
        assert shield.write_usage_log(stale["_usage_log_work"]) is True
        current = shield.record_traffic("192.0.2.103", out_bytes=5,
                                        method="GET", path="/after", _defer_log=True)
        assert shield.write_usage_log(current["_usage_log_work"]) is True
        assert [row["path"] for row in shield.usage_log()] == ["/after"]


def test_deferred_log_failure_is_reported_without_losing_usage_counter():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        result = shield.record_traffic("192.0.2.104", out_bytes=7,
                                       method="GET", path="/public", _defer_log=True)
        with mock.patch.object(pipeline, "_open_state_write", side_effect=OSError("disk fault")):
            assert shield.write_usage_log(result["_usage_log_work"]) is False
        assert shield._usage["192.0.2.104"]["out"] == 7
        assert shield.usage_log() == []


def test_clear_waits_for_inflight_log_then_removes_its_row():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        work = shield.record_traffic("192.0.2.105", method="GET",
                                     path="/before", _defer_log=True)["_usage_log_work"]
        entered, release = threading.Event(), threading.Event()
        original = pipeline._open_state_write
        results = {}

        def paused(path, mode):
            if path == shield._usage_log_path and mode == "a":
                entered.set()
                assert release.wait(3)
            return original(path, mode)

        with mock.patch.object(pipeline, "_open_state_write", side_effect=paused):
            writer = threading.Thread(target=lambda: results.setdefault("write", shield.write_usage_log(work)))
            writer.start()
            assert entered.wait(3)
            clearer = threading.Thread(target=lambda: results.setdefault("clear", shield.usage_clear()))
            clearer.start()
            release.set()
            writer.join(3)
            clearer.join(3)
        assert not writer.is_alive() and not clearer.is_alive()
        assert results["write"] is True and results["clear"]["ok"] is True
        assert shield.usage_log() == []


def test_forked_shield_replaces_parent_held_usage_log_lock():
    if not hasattr(os, "fork"):
        raise SkipTest("fork is unavailable on this OS")
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        held, release = threading.Event(), threading.Event()

        def hold_parent_lock():
            with shield._usage_log_lock:
                held.set()
                assert release.wait(5)

        owner = threading.Thread(target=hold_parent_lock)
        owner.start()
        assert held.wait(2)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            result = {}

            def child_log_ops():
                try:
                    work = (shield._usage_generation, {"path": "/child"})
                    assert shield.write_usage_log(work) is True
                    assert shield.usage_log()[0]["path"] == "/child"
                    shield._rotate_usage_log()
                    assert shield.usage_clear()["ok"] is True
                    result["ok"] = True
                except BaseException as exc:
                    result["error"] = repr(exc)

            worker = threading.Thread(target=child_log_ops, daemon=True)
            worker.start()
            worker.join(2)
            os.write(write_fd, json.dumps({"done": not worker.is_alive(),
                                          **result}).encode("ascii"))
            os._exit(0)
        os.close(write_fd)
        try:
            ready, _, _ = select.select([read_fd], [], [], 4)
            if not ready:
                os.kill(pid, 9)
                raise AssertionError("forked child did not finish within deadline")
            result = json.loads(os.read(read_fd, 4096))
            _, status = os.waitpid(pid, 0)
            assert status == 0 and result == {"done": True, "ok": True}, result
        finally:
            os.close(read_fd)
            release.set()
            owner.join(5)
        assert not owner.is_alive()


def test_quota_switch_and_threshold_use_one_config_generation():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(quota_enabled=True, quota_max_gb=10.0,
                                 persist_bans=False, usage_record=False)["ok"]
        assert not shield.record_traffic("192.0.2.110", out_bytes=1).get("exceeded")
        entered, release, updated = threading.Event(), threading.Event(), threading.Event()

        class PausingConfig(dict):
            def get(self, key, default=None):
                value = super().get(key, default)
                if key == "quota_enabled" and threading.current_thread().name == "quota-request":
                    entered.set()
                    assert release.wait(3)
                return value

        shield.cfg = PausingConfig(shield.cfg)
        request_result, update_result = [], []
        request = threading.Thread(name="quota-request", target=lambda:
                                   request_result.append(shield.record_traffic(
                                       "192.0.2.111", out_bytes=1)))

        def change_config():
            update_result.append(shield.set_config(quota_enabled=False,
                                                    quota_max_gb=0.000000001))
            updated.set()

        updater = threading.Thread(target=change_config)
        request.start()
        assert entered.wait(2)
        updater.start()
        try:
            updated.wait(.1)  # the old implementation could commit between two quota reads
        finally:
            release.set()
            request.join(3)
            updater.join(3)
        assert not request.is_alive() and not updater.is_alive()
        assert update_result[0]["ok"] is True
        assert request_result[0]["counted"] is True
        assert not request_result[0].get("exceeded")
        assert not shield.is_banned_fast("192.0.2.111")
        assert shield.record_traffic("192.0.2.112", out_bytes=1) == {"counted": False}


def test_quota_readers_cannot_iterate_a_concurrently_mutated_day_map():
    for reader_kind in ("status_ip", "status_all", "record"):
        with tempfile.TemporaryDirectory() as directory:
            shield = _shield(directory)
            assert shield.set_config(quota_enabled=True, quota_window_days=2,
                                     usage_record=False)["ok"]
            ip = "192.0.2.106"
            day = shield._day()
            entered, release, changed = (threading.Event(), threading.Event(),
                                         threading.Event())

            class PausingDays(dict):
                def items(self):
                    iterator = iter(super().items())
                    first = next(iterator)
                    yield first
                    entered.set()
                    assert release.wait(3)
                    yield from iterator

            shield._traffic[ip] = PausingDays({str(day): [10.0, 0.0, 1.0],
                                               str(day - 1): [20.0, 0.0, 2.0]})
            result = {}

            def read():
                try:
                    if reader_kind == "status_ip":
                        result["value"] = shield.quota_status(ip)
                    elif reader_kind == "status_all":
                        result["value"] = shield.quota_status()
                    else:
                        result["value"] = shield.record_traffic(ip, out_bytes=1)
                except Exception as exc:
                    result["error"] = exc

            def mutate():
                with shield._lock:
                    shield._traffic[ip][str(day + 1)] = [1.0, 0.0, 0.0]
                    changed.set()

            reader = threading.Thread(target=read)
            writer = threading.Thread(target=mutate)
            reader.start()
            try:
                assert entered.wait(3), reader_kind
                writer.start()
                changed.wait(.05)
            finally:
                release.set()
                reader.join(3)
                writer.join(3)
            assert not reader.is_alive() and not writer.is_alive()
            assert "error" not in result, (reader_kind, result)
            assert "value" in result


def test_failed_usage_and_traffic_saves_back_off_but_force_retries():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(quota_enabled=True, quota_max_gb=0.000001,
                                 usage_record=True)["ok"]
        original = pipeline.write_signed_json
        attempts = {shield._usage_path: 0, shield._traffic_path: 0}

        def failing(path, value, key, **kwargs):
            if path in attempts:
                attempts[path] += 1
                return False
            return original(path, value, key, **kwargs)

        base = pipeline.time.monotonic()
        with mock.patch.object(pipeline, "write_signed_json", side_effect=failing):
            with mock.patch.object(pipeline.time, "monotonic", return_value=base):
                for _ in range(12):
                    result = shield.record_traffic("192.0.2.107", out_bytes=1,
                                                   method="GET", path="/public")
                    assert result["counted"] is True and not result.get("exceeded")
            assert attempts[shield._usage_path] == 1
            assert attempts[shield._traffic_path] == 1
            with mock.patch.object(pipeline.time, "monotonic", return_value=base + 16):
                shield.record_traffic("192.0.2.107", out_bytes=1,
                                      method="GET", path="/public")
            assert attempts[shield._usage_path] == 2
            assert attempts[shield._traffic_path] == 2
            flush = shield.flush_state()
            assert flush["ok"] is False
            assert attempts[shield._usage_path] == 3
            assert attempts[shield._traffic_path] == 3
        assert shield.flush_state()["persisted"] is True
        restored = pipeline.NetShield(state_dir=directory)
        assert restored._usage["192.0.2.107"]["conns"] == 13
        assert restored._traffic["192.0.2.107"][str(shield._day())][0] == 13.0


def test_usage_clear_attempts_persistence_during_retry_backoff():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        original = pipeline.write_signed_json
        attempts = []

        def failing(path, value, key, **kwargs):
            if path == shield._usage_path:
                attempts.append(path)
                return False
            return original(path, value, key, **kwargs)

        with mock.patch.object(pipeline, "write_signed_json", side_effect=failing):
            shield.record_traffic("192.0.2.108", out_bytes=1)
            shield.record_traffic("192.0.2.108", out_bytes=1)
            assert attempts == [shield._usage_path]
            result = shield.usage_clear()
            assert result["ok"] is False and result["cleared"] is False
            assert attempts == [shield._usage_path, shield._usage_path]
        assert shield.usage_clear()["ok"] is True
        shield.record_traffic("192.0.2.108", out_bytes=1)
        assert shield.flush_state()["persisted"] is True
        assert pipeline.NetShield(state_dir=directory)._usage["192.0.2.108"]["conns"] == 1
