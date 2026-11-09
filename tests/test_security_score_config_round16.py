"""Signed score configuration cannot turn threat signals into negative credit."""

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _Backend, _exchange, _guard


_ADDITIVE = ("subnet_score", "slowloris_score", "resp_error_score",
             "bot_inconsistency_score", "cred_rate_score", "cadence_score")


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-score-cfg-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_negative_response_score_cannot_let_signature_reach_backend():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 block_score=100, deny_score=40,
                                 resp_error_threshold=1,
                                 resp_error_score=50)["ok"]
        assert shield.add_signature("score-probe", "r16negscore", weight=100)["ok"]
        before = Path(shield.path).read_bytes()
        result = shield.set_config(resp_error_score=-1000)
        noted = shield.note_response("127.0.0.1", 404)
        backend = _Backend()
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", AppFirewall(state_dir=state)), \
                    _guard(backend) as edge:
                wire = _exchange(edge, [b"GET /r16negscore HTTP/1.1\r\n"
                                        b"Host: local.test\r\n\r\n"])
            # Old set_config returned ok:true; score -1000 canceled the
            # signature's 100 and this attack reached backend with HTTP 200.
            assert not wire.startswith(b"HTTP/1.1 200"), wire
            assert b"GET /r16negscore" not in backend.saw(), backend.got
            assert result.get("ok") is False and result.get("changed") == {}, result
            assert "resp_error_score" in result.get("rejected", []), result
            assert Path(shield.path).read_bytes() == before
            assert noted["score"] == 50.0, noted
        finally:
            backend.close()


def test_all_additive_score_keys_reject_negative_and_excessive_values_atomically():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, blocked_urls=["/protected"])["ok"]
        before = Path(shield.path).read_bytes()
        for key in _ADDITIVE:
            for value in (-1, 1001, float("nan"), float("inf")):
                result = shield.set_config(**{key: value,
                                              "blocked_urls": ["/should-not-apply"]})
                assert result.get("ok") is False and result.get("changed") == {}, result
                assert key in result.get("rejected", []), result
                assert shield.cfg["blocked_urls"] == ["/protected"]
                assert Path(shield.path).read_bytes() == before
        declarative = shield.apply_config({"resp_error_score": -1000,
                                           "blocked_urls": ["/should-not-apply"]})
        assert declarative.get("ok") is False and declarative.get("applied") == []
        assert "resp_error_score" in declarative.get("rejected", [])
        assert Path(shield.path).read_bytes() == before


def test_thresholds_reject_nonpositive_and_unbounded_candidates():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        before = Path(shield.path).read_bytes()
        for values in ({"deny_score": 0}, {"block_score": 0},
                       {"deny_score": -1}, {"block_score": -1},
                       {"deny_score": 1_000_001},
                       {"block_score": 1_000_001},
                       {"deny_score": 10 ** 308},
                       {"block_score": 10 ** 308}):
            result = shield.set_config(**values)
            assert result.get("ok") is False and result.get("changed") == {}, (values, result)
            assert Path(shield.path).read_bytes() == before
        reversed_declarative = shield.apply_config({"deny_score": 101,
                                                    "block_score": 100})
        # BAN runs first, so a lower BAN threshold is a supported stricter
        # policy even when the one-request deny tier is unreachable.
        assert reversed_declarative.get("ok") is True, reversed_declarative
        assert reversed_declarative.get("applied") == ["block_score", "deny_score"]
        assert shield.set_config(deny_score=1000, block_score=1000)["ok"]


def test_legacy_signed_negative_score_is_normalized_and_reported():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        legacy = {**shield.cfg, "resp_error_score": -1000,
                  "deny_score": 200, "block_score": 100}
        written = shield._write_state(shield.path, {
            "cfg": legacy, "saved": time.time(), "rev": pipeline._CFG_REV})
        assert written["ok"], written
        restored = NetShield(state_dir=state)
        assert restored.cfg["resp_error_score"] == 50
        assert restored.cfg["deny_score"] == 200
        assert restored.cfg["block_score"] == 100
        assert any(e.get("kind") == "cfg_load_rejected"
                   and "resp_error_score" in e.get("bounded", [])
                   for e in restored.events(100)), restored.events(100)


def test_legacy_signed_huge_thresholds_are_bounded_with_event():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        legacy = {**shield.cfg, "deny_score": 10 ** 308,
                  "block_score": 10 ** 308}
        written = shield._write_state(shield.path, {
            "cfg": legacy, "saved": time.time(), "rev": pipeline._CFG_REV})
        assert written["ok"], written
        restored = NetShield(state_dir=state)
        assert restored.cfg["deny_score"] == 1000
        assert restored.cfg["block_score"] == 1000
        assert any(e.get("kind") == "cfg_load_rejected"
                   and set(("deny_score", "block_score")) <= set(e.get("bounded", []))
                   for e in restored.events(100)), restored.events(100)


def test_legacy_signed_nonpositive_thresholds_restore_protective_defaults():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        legacy = {**shield.cfg, "deny_score": -1, "block_score": 0}
        written = shield._write_state(shield.path, {
            "cfg": legacy, "saved": time.time(), "rev": pipeline._CFG_REV})
        assert written["ok"], written
        restored = NetShield(state_dir=state)
        assert restored.cfg["deny_score"] == 40
        assert restored.cfg["block_score"] == 100
        assert any(e.get("kind") == "cfg_load_rejected"
                   and set(("deny_score", "block_score")) <= set(e.get("bounded", []))
                   for e in restored.events(100)), restored.events(100)
