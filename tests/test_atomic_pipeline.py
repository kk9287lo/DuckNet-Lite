"""Atomicity and truthful-result regressions for NetShield state mutations."""
import copy
import os
import tempfile
import threading
from unittest import mock

from dataplane.engine.lifeform import pipeline


def _shield(directory):
    return pipeline.NetShield(state_dir=directory)


def test_set_paranoia_reports_explicit_success_and_stable_snapshot():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        result = shield.set_paranoia(2)
        assert result.get("ok") is True
        assert result["paranoia"] == 2
        assert result["enabled_optional"] == shield.paranoia_status()["enabled_optional"]


def test_config_result_cannot_mutate_live_nested_configuration():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        result = shield.set_config(rate_per_sec=11)
        assert result["ok"] is True
        before = copy.deepcopy(shield.cfg)
        result["cfg"]["optional_sigs"]["sqli_advanced"] = True
        result["cfg"]["path_limits"].append({"path": "/injected"})
        assert shield.cfg == before
        assert shield.verify_cfg_integrity()["ok"] is True


def test_status_signature_and_path_results_do_not_alias_live_state():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        rule = [{"path": "/safe", "rate": 2, "burst": 2}]
        result = shield.set_path_limits(rule)
        assert result["ok"] is True
        status = shield.status()
        before = copy.deepcopy(shield.cfg)
        result["path_limits"][0]["rate"] = 9999
        status["cfg"]["path_limits"][0]["rate"] = 9999
        assert shield.cfg == before
        assert shield.add_signature("snapshot_rule", "snapshot_unique_marker")["ok"]
        listed = shield.list_signatures()
        listed["custom"][0]["active"] = False
        assert shield.list_signatures()["custom"][0]["active"] is True


def test_cfg_mac_keeps_question_mark_distinct_from_lone_surrogate():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        shield.cfg["open_redirect_safe_path"] = "?"
        shield._refresh_cfg_mac()
        original = shield._cfg_blob()
        shield.cfg["open_redirect_safe_path"] = "\ud800"
        assert shield._cfg_blob() != original
        result = shield.verify_cfg_integrity()
        assert result["tampered"] is True
        assert shield.cfg["open_redirect_safe_path"] == "?"


def test_edit_list_concurrent_adds_keep_both_entries():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        entered, release = threading.Event(), threading.Event()
        original = shield.set_config
        results = {}

        def paused_set_config(**kw):
            if threading.current_thread().name == "first-edit":
                entered.set()
                assert release.wait(3)
            return original(**kw)

        shield.set_config = paused_set_config

        def run(label, entry):
            results[label] = shield.edit_list("ip", "black", "add", [entry])

        first = threading.Thread(target=run, args=("first", "192.0.2.1"), name="first-edit")
        second = threading.Thread(target=run, args=("second", "192.0.2.2"), name="second-edit")
        first.start()
        try:
            assert entered.wait(3)
            second.start()
        finally:
            release.set()
            first.join(3)
            second.join(3)
        assert not first.is_alive() and not second.is_alive()
        assert results["first"]["ok"] and results["second"]["ok"]
        assert set(shield.cfg["ip_blacklist"]) == {"192.0.2.1", "192.0.2.2"}


def test_usage_clear_save_failure_preserves_memory_and_log():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        shield._usage = {"192.0.2.1": {"out": 10, "in": 0, "conns": 1,
                                       "sec": 0, "hosts": {}, "last": 0}}
        with open(shield._usage_log_path, "w", encoding="utf-8") as log:
            log.write('{"ip":"192.0.2.1"}\n')
        before = copy.deepcopy(shield._usage)
        with mock.patch.object(pipeline, "write_signed_json", return_value=False):
            result = shield.usage_clear()
        assert result["ok"] is False
        assert shield._usage == before
        with open(shield._usage_log_path, encoding="utf-8") as log:
            assert '192.0.2.1' in log.read()
        assert shield.usage_clear()["ok"] is True
        assert shield._usage == {}
        with open(shield._usage_log_path, encoding="utf-8") as log:
            assert log.read() == ""


def test_apply_config_rejects_entire_invalid_declaration_and_accepts_valid_one():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        bad = shield.apply_config({"paranoia": "maximum"})
        assert bad["ok"] is False and bad["applied"] == []
        assert "paranoia" in bad["rejected"]
        before = copy.deepcopy(shield.cfg)
        mixed = shield.apply_config({"paranoia": "maximum", "rate_per_sec": 17})
        assert mixed["ok"] is False and mixed["applied"] == []
        assert "paranoia" in mixed["rejected"]
        assert shield.cfg == before
        valid = shield.apply_config({"paranoia": 2, "rate_per_sec": 17})
        assert valid["ok"] is True
        assert set(valid["applied"]) == {"paranoia", "rate_per_sec"}


def test_set_config_rejects_entire_mixed_request_without_partial_commit():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        before = copy.deepcopy(shield.cfg)
        result = shield.set_config(rate_per_sec=17, paranoia="maximum")
        assert result["ok"] is False and result["changed"] == {}
        assert result["rejected"] == ["paranoia"]
        assert shield.cfg == before and _shield(directory).cfg == before
        assert shield.set_config(rate_per_sec=17, paranoia=2)["ok"]
        assert shield.cfg["rate_per_sec"] == 17.0


def test_connection_caps_reject_negative_and_unbounded_values_atomically():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        bounds = {"max_conn_per_ip": 100_000,
                  "max_total_conn": 1_000_000,
                  "conn_rate_per_ip": 100_000}
        for key, upper in bounds.items():
            before = copy.deepcopy(shield.cfg)
            for invalid in (-1, upper + 1):
                result = shield.set_config(**{key: invalid, "rate_per_sec": 17})
                assert result["ok"] is False and result["changed"] == {}
                assert key in result["rejected"] and shield.cfg == before
            assert shield.set_config(**{key: 0})["ok"] is True
            assert shield.set_config(**{key: 4})["ok"] is True
            assert shield.cfg[key] == 4


def test_apply_config_saves_one_complete_snapshot():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        original = pipeline.write_signed_json
        calls = []

        def recorded(path, value, key, **kwargs):
            calls.append((path, copy.deepcopy(value)))
            return original(path, value, key, **kwargs)

        with mock.patch.object(pipeline, "write_signed_json", side_effect=recorded):
            result = shield.apply_config({"blocked_methods": ["TRACE"],
                                          "path_limits": [{"path": "/login", "rate": 2}],
                                          "paranoia": 2, "rate_per_sec": 17})
        assert result["ok"] is True
        cfg_writes = [value["cfg"] for path, value in calls if path == shield.path]
        assert len(cfg_writes) == 1
        assert cfg_writes[0]["rate_per_sec"] == 17.0
        assert cfg_writes[0]["blocked_methods"] == ["TRACE"]
        assert cfg_writes[0]["path_limits"][0]["path"] == "/login"


def test_old_appeal_cannot_release_a_new_permanent_ban():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(appeal_after_sec=0)["ok"]
        ip = "192.0.2.21"
        assert shield.ban(ip, permanent=True)["ok"]
        assert shield.submit_appeal(ip, "first incident")["ok"]
        assert shield.unban(ip)["ok"]
        assert shield.ban(ip, permanent=True)["ok"]
        result = shield.resolve_appeal(ip, True)
        assert result["ok"] is False
        assert shield.is_banned_fast(ip) is True
        assert _shield(directory).is_banned_fast(ip) is True


def test_failed_appeal_release_does_not_claim_approval_or_lose_live_ban():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(appeal_after_sec=0)["ok"]
        ip = "192.0.2.22"
        assert shield.ban(ip, permanent=True)["ok"]
        assert shield.submit_appeal(ip, "please review")["ok"]
        with mock.patch.object(pipeline, "write_signed_json", return_value=False):
            result = shield.resolve_appeal(ip, True)
        assert result["ok"] is False
        assert shield.is_banned_fast(ip) is True
        assert _shield(directory).is_banned_fast(ip) is True
        assert shield.list_appeals()[0]["status"] == "pending"
        assert shield.resolve_appeal(ip, True)["ok"] is True
        assert shield.is_banned_fast(ip) is False


def test_old_restriction_cannot_release_a_new_permanent_ban():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.23"
        assert shield.restrict(ip)["ok"]
        assert shield.unban(ip)["ok"]
        assert shield.ban(ip, permanent=True)["ok"]
        report = shield.submit_report(ip, "old restriction")
        confirm = shield.admin_confirm(ip, True)
        assert report["ok"] is False or confirm["ok"] is False
        assert shield.is_banned_fast(ip) is True
        assert _shield(directory).is_banned_fast(ip) is True


def test_failed_restriction_release_stays_restricted_and_retries():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.24"
        assert shield.restrict(ip)["ok"]
        assert shield.submit_report(ip, "review")["ok"]
        with mock.patch.object(pipeline, "write_signed_json", return_value=False):
            result = shield.admin_confirm(ip, True)
        assert result["ok"] is False
        assert shield.is_banned_fast(ip) is True
        assert shield.list_restrictions()[0]["status"] != "released"
        assert shield.admin_confirm(ip, True)["released"] is True
        assert shield.is_banned_fast(ip) is False


def test_restriction_report_and_consent_survive_each_restart():
    with tempfile.TemporaryDirectory() as directory:
        ip = "192.0.2.52"
        first = _shield(directory)
        assert first.restrict(ip)["ok"] is True
        after_restrict = _shield(directory)
        assert after_restrict.is_banned_fast(ip) is True
        assert after_restrict.list_restrictions()[0]["status"] == "restricted"
        report = after_restrict.submit_report(ip, "legitimate review")
        assert report["ok"] is True and report["released"] is False
        after_report = _shield(directory)
        row = after_report.list_restrictions()[0]
        assert row["report"] == "legitimate review" and row["user_ok"] is True
        released = after_report.admin_confirm(ip, True, "approved")
        assert released["ok"] is True and released["released"] is True
        after_release = _shield(directory)
        assert after_release.is_banned_fast(ip) is False
        assert after_release.list_restrictions() == []


def test_admin_consent_first_survives_restart_before_report():
    with tempfile.TemporaryDirectory() as directory:
        ip = "192.0.2.57"
        first = _shield(directory)
        assert first.restrict(ip)["ok"]
        consent = first.admin_confirm(ip, True, "reviewed")
        assert consent["ok"] is True and consent["released"] is False
        restarted = _shield(directory)
        assert restarted.list_restrictions()[0]["admin_ok"] is True
        assert restarted.submit_report(ip, "my report")["released"] is True
        assert _shield(directory).is_banned_fast(ip) is False


def test_old_blocklist_without_restriction_metadata_keeps_its_ban():
    with tempfile.TemporaryDirectory() as directory:
        first = _shield(directory)
        ip = "192.0.2.58"
        assert first.ban(ip, permanent=True)["ok"]
        from dataplane.engine.core.signed_state import write_signed_json
        assert write_signed_json(first._bans_path,
                                 {"bans": {ip: {"until": None, "started": 1,
                                                 "permanent": True, "count": 1}}},
                                 first._state_key)
        restored = _shield(directory)
        assert restored.is_banned_fast(ip) is True
        assert restored.list_restrictions() == []
        assert restored.submit_report(ip, "old snapshot")["ok"] is False


def test_restrict_save_failure_restores_prior_ban_and_metadata():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.53"
        with mock.patch.object(pipeline, "write_signed_json", return_value=False):
            result = shield.restrict(ip)
        assert result["ok"] is False
        assert shield.is_banned_fast(ip) is False
        assert shield.list_restrictions() == []
        assert _shield(directory).is_banned_fast(ip) is False


def test_restriction_report_save_failure_preserves_old_metadata():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.54"
        assert shield.restrict(ip)["ok"]
        before = shield.list_restrictions()
        with mock.patch.object(pipeline, "write_signed_json", return_value=False):
            result = shield.submit_report(ip, "not saved")
        assert result["ok"] is False
        assert shield.list_restrictions() == before
        assert _shield(directory).list_restrictions() == before
        assert shield.is_banned_fast(ip) and _shield(directory).is_banned_fast(ip)


def test_restriction_release_save_failure_preserves_ban_and_saved_consent():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.55"
        assert shield.restrict(ip)["ok"]
        assert shield.submit_report(ip, "review")["ok"]
        before = shield.list_restrictions()
        with mock.patch.object(pipeline, "write_signed_json", return_value=False):
            result = shield.admin_confirm(ip, True)
        assert result["ok"] is False
        assert shield.list_restrictions() == before
        assert _shield(directory).list_restrictions() == before
        assert shield.is_banned_fast(ip) and _shield(directory).is_banned_fast(ip)


def test_review_release_keeps_ban_active_until_signed_state_is_published():
    for appeal in (False, True):
        with tempfile.TemporaryDirectory() as directory:
            shield = _shield(directory)
            ip = "192.0.2.61"
            if appeal:
                assert shield.set_config(appeal_after_sec=0)["ok"]
                assert shield.ban(ip, permanent=True)["ok"]
                assert shield.submit_appeal(ip, "review")["ok"]
            else:
                assert shield.restrict(ip)["ok"]
                assert shield.submit_report(ip, "review")["ok"]
            entered, release = threading.Event(), threading.Event()
            original = shield._write_state
            result = {}

            def paused(path, value):
                if path == shield._bans_path and threading.current_thread().name == "release":
                    entered.set()
                    assert release.wait(3)
                return original(path, value)

            shield._write_state = paused

            def run():
                result["value"] = (shield.resolve_appeal(ip, True) if appeal
                                   else shield.admin_confirm(ip, True))

            worker = threading.Thread(target=run, name="release")
            worker.start()
            try:
                assert entered.wait(3)
                assert shield.is_banned_fast(ip) is True
            finally:
                release.set()
                worker.join(3)
            assert not worker.is_alive()
            assert result["value"]["ok"] is True
            assert shield.is_banned_fast(ip) is False


def test_published_nondurable_restriction_report_keeps_new_metadata():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.56"
        assert shield.restrict(ip)["ok"]
        with _published_without_directory_sync():
            result = shield.submit_report(ip, "published review")
        assert result["ok"] is False and result["published"] is True
        assert result["applied_in_memory"] is True and result["durable"] is False
        assert shield.list_restrictions()[0]["report"] == "published review"
        assert _shield(directory).list_restrictions()[0]["report"] == "published review"


def test_published_nondurable_restriction_release_keeps_the_release():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.59"
        assert shield.restrict(ip)["ok"]
        assert shield.submit_report(ip, "review")["ok"]
        with _published_without_directory_sync():
            result = shield.admin_confirm(ip, True)
        assert result["ok"] is False and result["released"] is True
        assert result["published"] and result["durable"] is False
        assert not shield.is_banned_fast(ip)
        assert not _shield(directory).is_banned_fast(ip)


def test_new_ban_generation_cannot_use_old_restriction_after_restart():
    with tempfile.TemporaryDirectory() as directory:
        first = _shield(directory)
        ip = "192.0.2.60"
        assert first.restrict(ip)["ok"]
        assert first.unban(ip)["ok"]
        assert first.ban(ip, permanent=True)["ok"]
        restarted = _shield(directory)
        assert restarted.list_restrictions() == []
        assert restarted.submit_report(ip, "old report")["ok"] is False
        assert restarted.is_banned_fast(ip)


def test_reload_bans_removes_externally_unbanned_entry():
    with tempfile.TemporaryDirectory() as directory:
        first = _shield(directory)
        ip = "192.0.2.25"
        assert first.ban(ip, permanent=True)["ok"]
        second = _shield(directory)
        assert second.is_banned_fast(ip) is True
        assert first.unban(ip)["ok"]
        result = second.reload_bans()
        assert result["ok"] is True
        assert second.is_banned_fast(ip) is False


def test_stale_worker_cannot_overwrite_another_workers_permanent_ban():
    with tempfile.TemporaryDirectory() as directory:
        first = _shield(directory)
        stale = _shield(directory)
        permanent_ip, second_ip = "192.0.2.40", "192.0.2.41"
        assert first.ban(permanent_ip, permanent=True)["ok"] is True
        result = stale.ban(second_ip)
        assert result["ok"] is False and result["persisted"] is False
        assert result["applied_in_memory"] is True
        fresh = _shield(directory)
        assert fresh.is_banned_fast(permanent_ip) is True
        assert fresh.is_banned_fast(second_ip) is False


def test_stale_config_writer_cannot_reenable_another_workers_disabled_shield():
    with tempfile.TemporaryDirectory() as directory:
        first = _shield(directory)
        stale = _shield(directory)
        assert first.disable()["ok"] is True
        result = stale.set_config(rate_per_sec=17)
        assert result["ok"] is False and result["changed"] == {}
        assert _shield(directory).is_enabled() is False


def test_stale_signature_writer_cannot_erase_another_workers_rule():
    with tempfile.TemporaryDirectory() as directory:
        first = _shield(directory)
        stale = _shield(directory)
        assert first.add_signature("first_rule", "first_unique_marker")["ok"] is True
        result = stale.add_signature("second_rule", "second_unique_marker")
        assert result["ok"] is False and result.get("added") is None
        names = {row["name"] for row in _shield(directory).list_signatures()["custom"]}
        assert "first_rule" in names and "second_rule" not in names


def test_invalid_appeal_reason_and_approval_type_cannot_mutate_state():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(appeal_after_sec=0)["ok"]
        ip = "192.0.2.26"
        assert shield.ban(ip, permanent=True)["ok"]
        assert shield.submit_appeal(ip, "original")["ok"]
        before = shield.list_appeals()
        assert shield.submit_appeal(ip, 42)["ok"] is False
        assert shield.list_appeals() == before
        assert shield.resolve_appeal(ip, "false")["ok"] is False
        assert shield.is_banned_fast(ip) is True


def test_invalid_restriction_approval_type_never_releases_ban():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.27"
        assert shield.restrict(ip)["ok"]
        assert shield.submit_report(ip, "review")["ok"]
        assert shield.admin_confirm(ip, "false")["ok"] is False
        assert shield.is_banned_fast(ip) is True


def test_invalid_signature_dry_run_is_failure_and_clean_miss_is_success():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.dry_run_signature(42, "sample")["ok"] is False
        assert shield.dry_run_signature("(", "sample")["ok"] is False
        clean = shield.dry_run_signature("select", "ordinary sample")
        assert clean["ok"] is True and clean["matches"] is False


def _published_without_directory_sync():
    original = pipeline.write_signed_json

    def write(path, value, key, **kwargs):
        saved = original(path, value, key, **kwargs)
        if saved and kwargs.get("status") is not None:
            kwargs["status"]["published"] = True
            kwargs["status"]["durable"] = False
        return saved

    return mock.patch.object(pipeline, "write_signed_json", side_effect=write)


def test_published_nondurable_config_reports_failure_but_keeps_live_and_disk_state():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.enable()["ok"]
        with _published_without_directory_sync():
            result = shield.disable()
        assert result["ok"] is False and result["enabled"] is False
        assert result["applied_in_memory"] and result["published"]
        assert result["persisted"] is False and result["durable"] is False
        assert shield.verify_cfg_integrity()["ok"] is True
        assert _shield(directory).is_enabled() is False


def test_writer_false_after_publication_does_not_restore_old_config():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.enable()["ok"]
        original = pipeline.write_signed_json

        def published_then_false(path, value, key, **kwargs):
            assert original(path, value, key, **kwargs)
            kwargs["status"].update(published=True, durable=False)
            return False

        with mock.patch.object(pipeline, "write_signed_json", side_effect=published_then_false):
            result = shield.disable()
        assert result["ok"] is False and result["published"] is True
        assert result["applied_in_memory"] is True and result["enabled"] is False
        assert shield.is_enabled() is False and _shield(directory).is_enabled() is False


def test_published_nondurable_geo_config_updates_compiled_policy():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        with _published_without_directory_sync():
            result = shield.set_config(geo_cidrs=["192.0.2.0/24"])
        assert result["ok"] is False and result["published"] is True
        assert result["changed"]["geo_cidrs"] == ["192.0.2.0/24"]
        assert str(shield._geo_nets[0]) == "192.0.2.0/24"


def test_published_nondurable_signature_reports_failure_but_stays_live():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        with _published_without_directory_sync():
            result = shield.add_signature("atomic_probe", "atomic_probe_marker")
        assert result["ok"] is False and result["published"] is True
        assert result["applied_in_memory"] and result["durable"] is False
        assert any(row["name"] == "atomic_probe" for row in shield.list_signatures()["custom"])
        assert any(row["name"] == "atomic_probe" for row in _shield(directory).list_signatures()["custom"])


def test_signature_compile_failure_never_publishes_candidate():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        with mock.patch.object(shield, "_compile_custom", side_effect=RuntimeError("fault")):
            result = shield.add_signature("atomic_probe", "atomic_probe_marker")
        assert result["ok"] is False
        assert not any(row["name"] == "atomic_probe" for row in shield.list_signatures()["custom"])
        assert not any(row["name"] == "atomic_probe" for row in _shield(directory).list_signatures()["custom"])


def test_published_nondurable_ban_and_flush_are_not_reported_durable():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        ip = "192.0.2.28"
        with _published_without_directory_sync():
            result = shield.ban(ip, permanent=True)
            flushed = shield.flush_state()
        assert result["ok"] is False and result["published"] is True
        assert result["applied_in_memory"] and result["persisted"] is False
        assert flushed["ok"] is False and flushed["bans"] == "published"
        assert flushed["published"] and flushed["durable"] is False
        assert shield.is_banned_fast(ip) and _shield(directory).is_banned_fast(ip)
        assert shield.flush_state()["ok"] is True


def test_published_nondurable_review_release_reports_uncertainty_without_reban():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        assert shield.set_config(appeal_after_sec=0)["ok"]
        ip = "192.0.2.29"
        assert shield.ban(ip, permanent=True)["ok"]
        assert shield.submit_appeal(ip, "review")["ok"]
        with _published_without_directory_sync():
            result = shield.resolve_appeal(ip, True)
        assert result["ok"] is False and result["status"] == "approved"
        assert result["published"] and result["durable"] is False
        assert not shield.is_banned_fast(ip) and not _shield(directory).is_banned_fast(ip)


def test_usage_log_postpublish_sync_failure_is_not_reported_as_success():
    with tempfile.TemporaryDirectory() as directory:
        shield = _shield(directory)
        with open(shield._usage_log_path, "w", encoding="utf-8") as log:
            log.write('{"ip":"192.0.2.31"}\n')
        original = pipeline.atomic_write_text

        def nondurable_log(path, value, **kwargs):
            written = original(path, value, **kwargs)
            if written and kwargs.get("status") is not None:
                kwargs["status"].update(published=True, durable=False)
            return written

        with mock.patch.object(pipeline, "atomic_write_text", side_effect=nondurable_log):
            result = shield.usage_clear()
        assert result["ok"] is False and result["cleared"] is True
        assert result["published"] and result["durable"] is False
        with open(shield._usage_log_path, encoding="utf-8") as log:
            assert log.read() == ""
