"""Invalid numeric controls cannot poison scoring, BAN timing or response bytes."""

from contextlib import contextmanager
import os
import tempfile
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_sweep_proxy_request import _Backend, _exchange, _guard, _OK


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-numeric-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _shield(state, **changes):
    sh = pipeline.NetShield(state_dir=state)
    cfg = dict(enabled=True, block_page=False, rate_per_sec=1000,
               burst=1000, flood_threshold=1000, resp_score_enabled=False,
               dlp_enabled=False, sec_headers_enabled=False,
               cors_harden_enabled=False, cookie_harden_enabled=False,
               open_redirect_enabled=False)
    cfg.update(changes)
    assert sh.set_config(**cfg)["ok"]
    return sh


@contextmanager
def _live(state, sh):
    be = _Backend()
    firewall = policy.AppFirewall(state_dir=state)
    try:
        with patch.object(pipeline, "_SHIELD", sh), patch.object(policy, "_FW", firewall), \
                _guard(be) as edge:
            yield edge, be
    finally:
        be.close()


def _get(edge, path):
    return _exchange(edge, [b"GET " + path +
        b" HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n"])


def _post(edge, path, body):
    return _exchange(edge, [b"POST " + path +
        b" HTTP/1.1\r\nHost: local.test\r\nContent-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() +
        b"\r\nConnection: close\r\n\r\n" + body])


def test_negative_response_stall_cap_cannot_truncate_normal_wire():
    with _state() as state:
        sh = _shield(state, resp_stall_sec=0.0)
        with _live(state, sh) as (edge, be):
            benign = _get(edge, b"/stall-benign")
            changed = sh.set_config(resp_stall_sec=-1.0)
            attack = _get(edge, b"/stall-after-invalid")
            upstream = be.saw()
        assert benign == _OK, benign
        assert attack == _OK, attack
        assert b"GET /stall-after-invalid" in upstream
        assert changed["ok"] is False and sh.cfg["resp_stall_sec"] == 0.0, changed


def test_negative_escalation_cap_cannot_shortcut_repeat_ban():
    with _state() as state:
        sh = _shield(state, persist_bans=False, block_score=100,
                     score_halflife_sec=1.0, ban_ttl_sec=10,
                     ban_escalation_cap=4)
        clock = [pipeline._now()]
        with patch.object(pipeline, "_now", side_effect=lambda: clock[0]):
            assert sh.penalize("127.0.0.1", weight=1000)["banned"]
            changed = sh.set_config(ban_escalation_cap=-1)
            clock[0] += 11
            assert sh.penalize("127.0.0.1", weight=1000)["banned"]
            clock[0] += 11  # base 10 s expired, escalated 20 s remains active
            with _live(state, sh) as (edge, be):
                attack = _get(edge, b"/repeat-cap")
                upstream = be.saw()
        assert b"GET /repeat-cap" not in upstream
        assert not attack.startswith(b"HTTP/1.1 200"), attack
        assert changed["ok"] is False and sh.cfg["ban_escalation_cap"] == 4, changed


def test_negative_retention_cannot_forget_repeat_ban_on_restart():
    with _state() as state:
        sh = _shield(state, persist_bans=True, block_score=100,
                     score_halflife_sec=1.0, ban_ttl_sec=10,
                     ban_escalation_cap=4, ban_escalation_retain_sec=100)
        clock = [pipeline._now()]
        with patch.object(pipeline, "_now", side_effect=lambda: clock[0]):
            changed = sh.set_config(ban_escalation_retain_sec=-1)
            assert sh.penalize("127.0.0.1", weight=1000)["banned"]
            clock[0] += 11
            restarted = pipeline.NetShield(state_dir=state)
            assert restarted.penalize("127.0.0.1", weight=1000)["banned"]
            clock[0] += 11
            with _live(state, restarted) as (edge, be):
                attack = _get(edge, b"/repeat-retain")
                upstream = be.saw()
        assert b"GET /repeat-retain" not in upstream
        assert not attack.startswith(b"HTTP/1.1 200"), attack
        assert changed["ok"] is False and restarted.cfg["ban_escalation_retain_sec"] == 100, changed


def test_negative_cadence_sample_count_cannot_ban_two_benign_requests():
    with _state() as state:
        sh = _shield(state, persist_bans=False, cadence_min_samples=8,
                     cadence_score=100, block_score=100)
        clock = [pipeline._now()]
        with patch.object(pipeline, "_now", side_effect=lambda: clock[0]):
            changed = sh.set_config(cadence_min_samples=-1)
            with _live(state, sh) as (edge, be):
                first = _get(edge, b"/cadence-first")
                clock[0] += 1
                second = _get(edge, b"/cadence-second")
                upstream = be.saw()
        assert b"GET /cadence-first" in upstream and b"GET /cadence-second" in upstream
        assert first == second == _OK, (first, second)
        assert changed["ok"] is False and sh.cfg["cadence_min_samples"] == 8, changed


def test_huge_body_factor_cannot_poison_score_or_block_benign_post():
    with _state() as state:
        sh = _shield(state, persist_bans=False, body_sig_weight_factor=0.7,
                     body_scan_enabled=True, block_score=100)
        body = b"$(id)"
        with _live(state, sh) as (edge, be):
            benign = _post(edge, b"/body-factor-benign", body)
            # A fresh worker has no accumulated score from the benign control.
            # This isolates the bad multiplier from normal repeated scoring.
            restarted = pipeline.NetShield(state_dir=state)
            pipeline._SHIELD = restarted
            changed = restarted.set_config(body_sig_weight_factor=1e308)
            attack = _post(edge, b"/body-factor-after-invalid", body)
            upstream = be.saw()
        assert benign == _OK, benign
        assert b"POST /body-factor-after-invalid" in upstream
        assert attack == _OK, attack
        assert changed["ok"] is False and restarted.cfg["body_sig_weight_factor"] == 0.7, changed


def test_negative_retry_after_cannot_erase_throttle_backoff_header():
    with _state() as state:
        sh = _shield(state, persist_bans=False, rate_per_sec=1e-9,
                     burst=1, throttle_retry_after=7)
        with _live(state, sh) as (edge, be):
            first = _get(edge, b"/rate-first")
            benign = _get(edge, b"/rate-second")
            changed = sh.set_config(throttle_retry_after=-1)
            attack = _get(edge, b"/rate-third")
            upstream = be.saw()
        assert first == _OK, first
        assert benign.startswith(b"HTTP/1.1 429") and b"Retry-After: 7\r\n" in benign, benign
        assert attack.startswith(b"HTTP/1.1 429") and b"Retry-After: 7\r\n" in attack, attack
        assert b"GET /rate-second" not in upstream and b"GET /rate-third" not in upstream
        assert changed["ok"] is False and sh.cfg["throttle_retry_after"] == 7, changed


def test_negative_appeal_delay_cannot_show_immediate_appeal_form():
    with _state() as state:
        sh = _shield(state, persist_bans=False, block_page=True,
                     appeal_after_sec=120)
        assert sh.ban("127.0.0.1", permanent=True)["ok"]
        with _live(state, sh) as (edge, be):
            request = (b"GET /blocked-appeal HTTP/1.1\r\nHost: local.test\r\n"
                       b"Accept: text/html\r\nConnection: close\r\n\r\n")
            benign = _exchange(edge, [request])
            changed = sh.set_config(appeal_after_sec=-1)
            attack = _exchange(edge, [request])
            upstream = be.saw()
        assert b"/__ducknet_appeal__" not in benign, benign[:1000]
        assert b"/__ducknet_appeal__" not in attack, attack[:1000]
        assert b"GET /blocked-appeal" not in upstream
        assert changed["ok"] is False and sh.cfg["appeal_after_sec"] == 120, changed


def test_signed_legacy_extreme_values_restore_safe_defaults_and_zero_optouts():
    with _state() as state:
        sh = _shield(state)
        extremes = {"range_max_ranges": 1_000_000,
                    "body_max_sec": 10**300,
                    "stall_min_rate": 1e308,
                    "body_sig_weight_factor": 1e308,
                    "ban_escalation_cap": 1_000_000,
                    "ban_escalation_retain_sec": 10**300,
                    "throttle_retry_after": 10**300,
                    "appeal_after_sec": 10**300,
                    "resp_stall_sec": 1e308,
                    "cadence_min_samples": -1}
        payload = {"cfg": {**sh.cfg, **extremes},
                   "saved": pipeline._now(), "rev": 3}
        assert sh._write_state(sh.path, payload)["ok"]
        loaded = pipeline.NetShield(state_dir=state)
        for key in ("range_max_ranges", "body_max_sec", "stall_min_rate",
                    "body_sig_weight_factor", "ban_escalation_cap",
                    "ban_escalation_retain_sec", "throttle_retry_after",
                    "appeal_after_sec", "cadence_min_samples"):
            assert loaded.cfg[key] == pipeline._DEFAULTS[key], (key, loaded.cfg[key])
        assert 0 <= loaded.cfg["resp_stall_sec"] <= 300
        events = loaded.events(100)
        bounded = {key for event in events if event.get("kind") == "cfg_load_rejected"
                   for key in event.get("bounded", [])}
        assert set(extremes) <= bounded, (bounded, events)

    with _state() as state:
        sh = _shield(state)
        zero_modes = dict(resp_stall_sec=0.0,
                          ban_escalation_retain_sec=0,
                          body_sig_weight_factor=0.0,
                          throttle_retry_after=0,
                          appeal_after_sec=0,
                          rate_per_sec=0.0)
        result = sh.set_config(**zero_modes)
        assert result["ok"] is True, result
        restarted = pipeline.NetShield(state_dir=state)
        for key, value in zero_modes.items():
            assert restarted.cfg[key] == value, (key, restarted.cfg[key])


def test_huge_stall_threshold_cannot_hide_busy_to_zero_transition():
    with _state() as state:
        sh = _shield(state, persist_bans=False, stall_detect_enabled=True,
                     stall_min_rate=1.0)
        clock = [pipeline._now()]
        with patch.object(pipeline, "_now", side_effect=lambda: clock[0]):
            assert sh.traffic_stall_check(now=clock[0])["stall"] is False
            with _live(state, sh) as (edge, be):
                first = _get(edge, b"/stall-rate-1")
                second = _get(edge, b"/stall-rate-2")
                upstream = be.saw()
            clock[0] += 1
            assert sh.traffic_stall_check(now=clock[0])["stall"] is False
            changed = sh.set_config(stall_min_rate=1e308)
            clock[0] += 1
            alarm = sh.traffic_stall_check(now=clock[0])
        assert first == second == _OK, (first, second)
        assert b"GET /stall-rate-1" in upstream and b"GET /stall-rate-2" in upstream
        assert alarm["stall"] is True, alarm
        assert any(event.get("kind") == "traffic_stall" for event in sh.events(100))
        assert changed["ok"] is False and sh.cfg["stall_min_rate"] == 1.0, changed
