"""A malformed shutdown grace must not silently become an unbounded wait."""

import contextlib
import io
import math
import os
from unittest import mock

import dataplane.service as service
from dataplane.engine.services.proxy import AsyncEdgeGuard


_BAD = ("nan", "inf", "-inf", "-1", "301", "1e12")


def test_cli_rejects_nonfinite_negative_and_excessive_grace_before_start():
    with mock.patch.object(service, "run") as start:
        for raw in _BAD:
            with contextlib.redirect_stderr(io.StringIO()):
                try:
                    service.main(["--drain-grace", raw])
                except SystemExit as exc:
                    assert exc.code == 2, (raw, exc.code)
                else:
                    raise AssertionError(f"accepted unsafe --drain-grace {raw}")
        start.assert_not_called()
        assert service.main(["--drain-grace", "2.5"]) == 0
        assert start.call_args.kwargs["drain_grace"] == 2.5


def test_invalid_grace_environment_uses_bounded_default():
    for raw in _BAD:
        with mock.patch.dict(os.environ, {"DUCKNET_DRAIN_GRACE": raw}):
            with contextlib.redirect_stderr(io.StringIO()):
                assert service._env_float("DUCKNET_DRAIN_GRACE", 5.0) == 5.0, raw
    for raw, expected in (("0", 0.0), ("2.5", 2.5), ("300", 300.0)):
        with mock.patch.dict(os.environ, {"DUCKNET_DRAIN_GRACE": raw}):
            assert service._env_float("DUCKNET_DRAIN_GRACE", 5.0) == expected


def test_programmatic_start_rejects_bad_grace_before_defense_start():
    with mock.patch.object(service, "app_firewall") as firewall, \
            mock.patch.object(service, "AsyncEdgeGuard") as guard:
        for value in (float("nan"), float("inf"), -1.0, 301.0):
            try:
                service.run(drain_grace=value)
            except SystemExit:
                pass
            else:
                raise AssertionError(f"accepted unsafe programmatic drain grace {value}")
        firewall.assert_not_called()
        guard.assert_not_called()


def test_direct_stop_normalizes_huge_grace_to_bounded_wait():
    for value in (float("inf"), 1e12):
        assert 0.0 < AsyncEdgeGuard._clamp_grace(value) <= 300.0
    for value in (float("nan"), -1.0, "bogus"):
        assert AsyncEdgeGuard._clamp_grace(value) == 0.0
    assert math.isclose(AsyncEdgeGuard._clamp_grace(2.5), 2.5)
