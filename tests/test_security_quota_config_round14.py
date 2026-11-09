"""Finite quota configuration cannot silently become unlimited."""

import contextlib
import copy
import os
import tempfile
from pathlib import Path

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from test_sweep_proxy_request import _Backend, _exchange, _guard


_REQUEST = b"GET /download HTTP/1.1\r\nHost: local.test\r\n\r\n"
_BODY = b"public-data-" * 40
_RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(_BODY)).encode()
             + b"\r\nConnection: close\r\n\r\n" + _BODY)
_QUIET = dict(sec_headers_enabled=False, cookie_harden_enabled=False,
              cors_harden_enabled=False, open_redirect_enabled=False,
              dlp_enabled=False, usage_record=False, persist_bans=False)


@contextlib.contextmanager
def _state():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as state:
        yield state


@contextlib.contextmanager
def _sources(shield, state):
    old_shield, old_firewall = ND._SHIELD, FW._FW
    ND._SHIELD = shield
    FW._FW = FW.AppFirewall(state_dir=state)
    try:
        yield
    finally:
        ND._SHIELD, FW._FW = old_shield, old_firewall


def _send(shield, state, response=_RESPONSE):
    backend = _Backend(response)
    try:
        with _sources(shield, state), _guard(backend) as guard:
            wire = _exchange(guard, [_REQUEST])
        return wire, backend.got
    finally:
        backend.close()


def _signed_legacy(state, *, mode, enabled):
    seed = ND.NetShield(state_dir=state)
    assert seed.set_config(enabled=True, block_page=False, **_QUIET)["ok"]
    candidate = copy.deepcopy(seed.cfg)
    candidate.update(quota_enabled=enabled, quota_max_gb=-1.0,
                     quota_max_conn_sec=-1.0, quota_window_days=-7,
                     mode=mode)
    saved = seed._write_state(seed.path,
                              {"cfg": candidate, "saved": ND._now(),
                               "rev": ND._CFG_REV})
    assert saved["ok"], saved
    raw = Path(seed.path).read_bytes()
    return ND.NetShield(state_dir=state), Path(seed.path), raw


def test_invalid_quota_replacement_keeps_prior_cap_on_actual_wire():
    with _state() as state:
        shield = ND.NetShield(state_dir=state)
        assert shield.set_config(enabled=True, quota_enabled=True,
                                 quota_max_gb=256 / 1e9,
                                 quota_window_days=1, **_QUIET)["ok"]
        before = copy.deepcopy(shield.cfg)
        saved = Path(shield.path).read_bytes()
        invalid = shield.set_config(quota_max_gb=-1.0)
        wire, upstream = _send(shield, state)
        assert invalid["ok"] is False, invalid
        assert shield.cfg == before and Path(shield.path).read_bytes() == saved
        assert len(upstream) == 1 and upstream[0].startswith(_REQUEST[:-2])
        assert len(wire) <= 256, len(wire)


def test_quota_numeric_boundaries_reject_whole_replacement_without_silent_clamp():
    with _state() as state:
        shield = ND.NetShield(state_dir=state)
        assert shield.set_config(enabled=True, quota_enabled=True,
                                 quota_max_gb=256 / 1e9,
                                 quota_max_conn_sec=1.0,
                                 quota_window_days=1, **_QUIET)["ok"]
        prior = copy.deepcopy(shield.cfg)
        saved = Path(shield.path).read_bytes()
        for patch in ({"quota_max_gb": -1.0}, {"quota_max_gb": 1_000_001.0},
                      {"quota_max_conn_sec": -1.0},
                      {"quota_max_conn_sec": 1_000_000_001.0},
                      {"quota_window_days": -7}, {"quota_window_days": 0},
                      {"quota_window_days": 31}):
            result = shield.set_config(**patch)
            assert result["ok"] is False, (patch, result)
            assert shield.cfg == prior and Path(shield.path).read_bytes() == saved
        assert shield.set_config(quota_window_days=30)["ok"]
        assert shield.set_config(quota_max_gb=1_000_000.0)["ok"]
        assert shield.set_config(quota_max_conn_sec=1_000_000_000.0)["ok"]


def test_invalid_signed_legacy_quota_fails_closed_in_enforce_without_resigning():
    with _state() as state:
        restarted, path, raw = _signed_legacy(state, mode="enforce", enabled=True)
        wire, upstream = _send(restarted, state)
        assert restarted._cfg_state_untrusted is True
        assert upstream == [] and b"public-data" not in wire, (wire, upstream)
        assert path.read_bytes() == raw


def test_invalid_signed_legacy_quota_audit_forwards_and_records_would_block():
    with _state() as state:
        restarted, path, raw = _signed_legacy(state, mode="audit", enabled=True)
        wire, upstream = _send(restarted, state)
        assert restarted._cfg_state_untrusted is True
        assert len(upstream) == 1 and wire.startswith(b"HTTP/1.1 200"), (wire, upstream)
        assert any(e.get("kind") == "audit" and e.get("would") == "block"
                   for e in restarted.events(100)), restarted.events(100)
        assert path.read_bytes() == raw


def test_disabled_legacy_quota_normalizes_to_prior_effective_values_with_warning():
    with _state() as state:
        restarted, path, raw = _signed_legacy(state, mode="enforce", enabled=False)
        assert restarted._cfg_state_untrusted is False
        assert restarted.cfg["quota_max_gb"] == 0.0
        assert restarted.cfg["quota_max_conn_sec"] == 0.0
        assert restarted.cfg["quota_window_days"] == 1
        assert any(e.get("kind") == "cfg_load_rejected" for e in restarted.events(100))
        wire, upstream = _send(restarted, state)
        assert len(upstream) == 1 and wire.startswith(b"HTTP/1.1 200")
        assert path.read_bytes() == raw
