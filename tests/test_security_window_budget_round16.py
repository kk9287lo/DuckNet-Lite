"""Bound aggregate timestamp windows without losing active counters."""

import os
import random
import tempfile
import time
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-window-budget-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _shield(state, **changes):
    shield = pipeline.NetShield(state_dir=state)
    cfg = dict(enabled=True, block_page=False, persist_bans=False,
               rate_per_sec=1000, burst=1000, flood_threshold=100,
               window_sec=60, cred_rate_enabled=False,
               resp_score_enabled=False)
    cfg.update(changes)
    result = shield.set_config(**cfg)
    assert result["ok"], result
    return shield


def _get(edge, path, *, credential=""):
    headers = (f"GET {path} HTTP/1.1\r\nHost: local.test\r\n"
               + (f"X-API-Key: {credential}\r\n" if credential else ""))
    return _exchange(edge, [(headers + "\r\n").encode("ascii")])


def test_flood_timestamp_budget_denies_new_entries_on_real_wire():
    with _state_dir() as state:
        shield = _shield(state)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_WINDOW_ENTRY_BUDGET", 2, create=True), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                wires = [_get(edge, f"/budget-{i}") for i in range(3)]
            upstream = backend.saw()
        finally:
            backend.close()
        assert wires[0].startswith(b"HTTP/1.1 200"), wires
        assert wires[1].startswith(b"HTTP/1.1 200"), wires
        assert not wires[2].startswith(b"HTTP/1.1 200"), wires
        assert b"GET /budget-2" not in upstream
        assert shield._window_entries == 2
        assert shield._metrics["window_capacity"] >= 1


def test_credential_window_cannot_exceed_shared_timestamp_budget_on_wire():
    with _state_dir() as state:
        shield = _shield(state, cred_rate_enabled=True, cred_rate_limit=10,
                         cred_rate_window_sec=60)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_WINDOW_ENTRY_BUDGET", 3, create=True), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                assert shield._credential_rate("A") == 1
                assert shield._credential_rate("B") == 1
                existing = {key: tuple(window) for key, window in shield._cred_rate.items()}
                wire = _get(edge, "/credential-overflow", credential="C")
            upstream = backend.saw()
        finally:
            backend.close()
        assert not wire.startswith(b"HTTP/1.1 200"), wire
        assert b"GET /credential-overflow" not in upstream
        assert shield._window_entries == 3
        assert {key: tuple(window) for key, window in shield._cred_rate.items()} == existing


def test_response_error_window_saturation_blocks_future_request():
    with _state_dir() as state:
        shield = _shield(state, resp_score_enabled=True,
                         resp_error_threshold=100)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_WINDOW_ENTRY_BUDGET", 1, create=True), \
                    patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), _guard(backend) as edge:
                first = shield.note_response("127.0.0.1", 404)
                second = shield.note_response("127.0.0.1", 404)
                wire = _get(edge, "/after-error-budget")
            upstream = backend.saw()
        finally:
            backend.close()
        assert first["action"] == "track", first
        assert second["action"] == "block" and second["banned"], second
        assert not wire.startswith(b"HTTP/1.1 200"), wire
        assert b"GET /after-error-budget" not in upstream
        assert shield._window_entries == 1


def test_expired_windows_reclaim_budget_and_preserve_audit_semantics():
    with _state_dir() as state:
        shield = _shield(state, window_sec=1)
        now = [1000.0]
        with patch.object(pipeline, "_WINDOW_ENTRY_BUDGET", 2, create=True), \
                patch.object(pipeline, "_now", side_effect=lambda: now[0]):
            assert shield.inspect("127.0.0.2", path="/first")["action"] == "allow"
            assert shield.inspect("127.0.0.2", path="/second")["action"] == "allow"
            assert shield.inspect("127.0.0.3", path="/full")["action"] == "block"
            assert shield._window_entries == 2
            now[0] += 2.0
            time.sleep(0.3)
            assert shield.inspect("127.0.0.3", path="/reused")["action"] == "allow"
            assert shield._window_entries == 1
            assert shield.set_config(mode="audit")["ok"]
            assert shield.inspect("127.0.0.4", path="/audit-one")["action"] == "allow"
            assert shield.inspect("127.0.0.5", path="/audit-full")["action"] == "allow"
            assert any(e.get("kind") == "audit"
                       and e.get("rule") == "window_capacity"
                       and e.get("would") == "block"
                       for e in shield.events(100))
            assert shield._window_entries == 2


def test_untrusted_zone_telemetry_cannot_create_unbounded_keys():
    with _state_dir() as state:
        shield = _shield(state, flood_threshold=1000)
        for index in range(128):
            result = shield.inspect("127.0.0.2", path="/zone",
                                    zone=f"client-controlled-{index}")
            assert result["action"] == "allow", result
        assert len(shield._zone_hits) <= 6, len(shield._zone_hits)
        assert shield.inspect("127.0.0.2", path="/zone", zone=["bad"])["action"] == "allow"


def test_mixed_window_mutations_keep_exact_aggregate_accounting():
    with _state_dir() as state:
        shield = _shield(state, window_sec=1, cred_rate_window_sec=1,
                         resp_score_enabled=True, resp_error_window_sec=1,
                         resp_error_threshold=3, resp_error_score=0)
        clock = [1000.0]
        rng = random.Random(16)
        with patch.object(pipeline, "_now", side_effect=lambda: clock[0]), \
                patch.object(pipeline, "_WINDOW_ENTRY_BUDGET", 20), \
                patch.object(pipeline, "_CRED_RATE_CAP", 5), \
                patch.object(pipeline, "_MAX_IPS", 5):
            for _ in range(300):
                clock[0] += 0.07
                ip = f"127.0.0.{rng.randrange(2, 7)}"
                operation = rng.randrange(3)
                if operation == 0:
                    shield.inspect(ip, path="/accounting")
                elif operation == 1:
                    shield._credential_rate(f"key-{rng.randrange(7)}")
                else:
                    shield.note_response(ip, 404)
                actual = sum(len(st["window"]) + len(st.get("resp_err", ()))
                             for st in shield._ips.values())
                actual += sum(len(window) for window in shield._cred_rate.values())
                assert shield._window_entries == actual
                assert actual <= pipeline._WINDOW_ENTRY_BUDGET
