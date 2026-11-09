"""Invalid score half-life must not erase accumulated threat signals."""

import math
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


_NOT_FOUND = (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
              b"Connection: close\r\n\r\n")


def _state():
    return tempfile.TemporaryDirectory(prefix="ducknet-r16-score-half-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_negative_half_life_cannot_let_repeated_probe_reach_backend():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 deny_score=1000, block_score=100,
                                 resp_error_threshold=1,
                                 resp_error_score=60)["ok"]
        before = Path(shield.path).read_bytes()
        bad = shield.set_config(score_halflife_sec=-1)
        backend = _Backend(resp=_NOT_FOUND)
        clock = [time.time()]
        try:
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", AppFirewall(state_dir=state)), \
                    patch.object(pipeline, "_now", side_effect=lambda: clock[0]), \
                    _guard(backend) as edge:
                replies = []
                for index in range(3):
                    path = f"/r16-half-{index}".encode("ascii")
                    replies.append(_exchange(edge, [b"GET " + path +
                        b" HTTP/1.1\r\nHost: local.test\r\n\r\n"]))
                    clock[0] += 2.0
            wire = backend.saw()
            assert replies[0].startswith(b"HTTP/1.1 404"), replies
            assert replies[1].startswith(b"HTTP/1.1 404"), replies
            assert b"GET /r16-half-0" in wire and b"GET /r16-half-1" in wire
            # Old set_config accepted -1, the runtime silently clamped it to
            # a one-second half-life, and this third request reached backend.
            assert b"GET /r16-half-2" not in wire, wire
            assert not replies[2].startswith(b"HTTP/1.1 404"), replies[2]
            assert bad.get("ok") is False and bad.get("changed") == {}, bad
            assert "score_halflife_sec" in bad.get("rejected", []), bad
            assert shield.cfg["score_halflife_sec"] == 30.0
            assert Path(shield.path).read_bytes() == before
        finally:
            backend.close()


def test_invalid_half_life_values_reject_atomically():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, blocked_urls=["/protected"])["ok"]
        before = Path(shield.path).read_bytes()
        for value in (None, True, "-1", -1, 0, 0.5, float("nan"),
                      float("inf"), 10 ** 308):
            result = shield.set_config(score_halflife_sec=value,
                                       blocked_urls=["/should-not-apply"])
            assert result.get("ok") is False and result.get("changed") == {}, (value, result)
            assert "score_halflife_sec" in result.get("rejected", []), (value, result)
            assert shield.cfg["blocked_urls"] == ["/protected"]
            assert Path(shield.path).read_bytes() == before
        assert shield.set_config(score_halflife_sec=1.0)["ok"]
        assert NetShield(state_dir=state).cfg["score_halflife_sec"] == 1.0


def test_signed_legacy_half_life_outside_bounds_is_reported_and_normalized():
    with _state() as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True)["ok"]
        for invalid, expected in ((-1.0, 30.0), (10 ** 308, 30 * 86400.0)):
            legacy = {**shield.cfg, "score_halflife_sec": invalid}
            written = shield._write_state(shield.path, {
                "cfg": legacy, "saved": time.time(), "rev": pipeline._CFG_REV})
            assert written["ok"], written
            restored = NetShield(state_dir=state)
            assert math.isfinite(restored.cfg["score_halflife_sec"])
            assert restored.cfg["score_halflife_sec"] == expected
            assert any(e.get("kind") == "cfg_load_rejected"
                       and "score_halflife_sec" in e.get("bounded", [])
                       for e in restored.events(100)), restored.events(100)
            shield = restored
