"""Numeric config cannot silently disable the cadence and token detectors."""

import os
import tempfile
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline, policy
from test_sweep_proxy_request import _Backend, _exchange, _guard


def _state_dir():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-cadence-cfg-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _shield(state):
    shield = pipeline.NetShield(state_dir=state)
    result = shield.set_config(enabled=True, block_page=False,
                               persist_bans=False, rate_per_sec=1000, burst=1000,
                               flood_threshold=1000, cadence_min_samples=8,
                               cadence_score=100, score_halflife_sec=120,
                               block_score=100, cadence_min_mean_interval=0.01,
                               cadence_max_mean_interval=3.0)
    assert result["ok"], result
    return shield


def _wire(edge, index):
    return _exchange(edge, [(f"GET /cadence-{index} HTTP/1.1\r\n"
                             "Host: local.test\r\n\r\n").encode("ascii")])


def test_negative_cadence_max_cannot_silence_real_wire_detector():
    with _state_dir() as state:
        shield = _shield(state)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        attempted = shield.set_config(cadence_max_mean_interval=-1)
        clock = [1000.0]
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(pipeline, "_now", side_effect=lambda: clock[0]), \
                    _guard(backend) as edge:
                wires = []
                for index in range(9):
                    clock[0] += 0.5
                    wires.append(_wire(edge, index))
            upstream = backend.saw()
        finally:
            backend.close()
        assert all(wire.startswith(b"HTTP/1.1 200") for wire in wires[:8]), wires
        assert not wires[8].startswith(b"HTTP/1.1 200"), wires[8]
        assert b"GET /cadence-8" not in upstream
        assert attempted["ok"] is False and shield.cfg["cadence_max_mean_interval"] == 3.0


def test_negative_cadence_cv_cannot_silence_real_wire_detector():
    with _state_dir() as state:
        shield = _shield(state)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        attempted = shield.set_config(cadence_cv_threshold=-0.1)
        clock = [2000.0]
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(pipeline, "_now", side_effect=lambda: clock[0]), \
                    _guard(backend) as edge:
                wires = []
                for index in range(9):
                    clock[0] += 0.5
                    wires.append(_wire(edge, index))
            upstream = backend.saw()
        finally:
            backend.close()
        assert all(wire.startswith(b"HTTP/1.1 200") for wire in wires[:8]), wires
        assert not wires[8].startswith(b"HTTP/1.1 200"), wires[8]
        assert b"GET /cadence-8" not in upstream
        assert attempted["ok"] is False and shield.cfg["cadence_cv_threshold"] == 0.15


def test_irregular_benign_requests_still_pass_with_valid_cadence_range():
    with _state_dir() as state:
        shield = _shield(state)
        firewall = policy.AppFirewall(state_dir=state)
        backend = _Backend()
        clock = [1000.0]
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    patch.object(pipeline, "_now", side_effect=lambda: clock[0]), \
                    _guard(backend) as edge:
                wires = []
                for index, interval in enumerate((0.1, 0.9, 0.2, 1.2, 0.1,
                                                  1.3, 0.3, 0.7, 0.15)):
                    clock[0] += interval
                    wires.append(_wire(edge, index))
            upstream = backend.saw()
        finally:
            backend.close()
        assert all(wire.startswith(b"HTTP/1.1 200") for wire in wires), wires
        assert upstream.count(b"GET /cadence-") == len(wires)


def test_invalid_numeric_ranges_and_legacy_signed_values_are_bounded():
    with _state_dir() as state:
        shield = _shield(state)
        for change in ({"rate_per_sec": -1}, {"burst": 0},
                       {"cadence_min_mean_interval": 10},
                       {"cadence_max_mean_interval": 0},
                       {"cadence_cv_threshold": 0}):
            before = dict(shield.cfg)
            result = shield.set_config(**change)
            assert result["ok"] is False and shield.cfg == before, (change, result)
        assert shield.apply_config({"cadence_min_mean_interval": 10,
                                    "cadence_max_mean_interval": 20})["ok"]
        assert shield.set_config(cadence_min_mean_interval=0.01,
                                 cadence_max_mean_interval=3.0)["ok"]
        payload = {"cfg": {**shield.cfg, "rate_per_sec": -1,
                           "cadence_min_mean_interval": 10,
                           "cadence_max_mean_interval": -1,
                           "cadence_cv_threshold": -0.1},
                   "saved": pipeline._now(), "rev": 3}
        assert shield._write_state(shield.path, payload)["ok"]
        loaded = pipeline.NetShield(state_dir=state)
        assert loaded.cfg["rate_per_sec"] == pipeline._DEFAULTS["rate_per_sec"]
        assert loaded.cfg["cadence_min_mean_interval"] < loaded.cfg["cadence_max_mean_interval"]
        assert loaded.cfg["cadence_max_mean_interval"] == pipeline._DEFAULTS["cadence_max_mean_interval"]
        assert loaded.cfg["cadence_cv_threshold"] == pipeline._DEFAULTS["cadence_cv_threshold"]
