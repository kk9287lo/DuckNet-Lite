"""A configured app.env path must not silently select new security state."""

import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from dataplane import service


def _base():
    return tempfile.TemporaryDirectory(prefix="ducknet-r25-explicit-env-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def test_missing_explicit_env_var_refuses_before_any_env_publication():
    with _base() as base:
        missing = str(Path(base) / "typo-app.env")
        sentinel = "DUCKNET_R25_EXPLICIT_ENV_PROBE"
        previous = os.environ.pop(sentinel, None)
        try:
            with patch.dict(os.environ, {"DUCKNET_ENV_FILE": missing}):
                try:
                    service.load_env_file()
                except SystemExit as exc:
                    assert "app.env" in str(exc) and missing in str(exc), exc
                else:
                    raise AssertionError("explicit missing app.env silently selected defaults")
            assert sentinel not in os.environ
        finally:
            if previous is not None:
                os.environ[sentinel] = previous


def test_main_entry_refuses_missing_explicit_env_before_help_or_listener():
    with _base() as base:
        missing = str(Path(base) / "typo-app.env")
        with patch.dict(os.environ, {"DUCKNET_ENV_FILE": missing}):
            try:
                service.main(["--help"])
            except SystemExit as exc:
                assert "app.env" in str(exc) and missing in str(exc), exc
            else:
                raise AssertionError("main silently ignored explicit missing app.env")


def test_existing_explicit_env_and_caller_priority_still_work():
    with _base() as base:
        path = Path(base) / "app.env"
        path.write_text("DUCKNET_R25_EXPLICIT_ENV_PROBE=file-value\n", encoding="utf-8")
        key = "DUCKNET_R25_EXPLICIT_ENV_PROBE"
        previous = os.environ.pop(key, None)
        try:
            with patch.dict(os.environ, {"DUCKNET_ENV_FILE": str(path)}):
                assert service.load_env_file() == 1
                assert os.environ[key] == "file-value"
                os.environ[key] = "caller-value"
                assert service.load_env_file() == 0
                assert os.environ[key] == "caller-value"
        finally:
            os.environ.pop(key, None)
            if previous is not None:
                os.environ[key] = previous


def test_absent_direct_optional_path_keeps_legacy_contract():
    with _base() as base:
        assert service.load_env_file(str(Path(base) / "optional-missing.env")) == 0
