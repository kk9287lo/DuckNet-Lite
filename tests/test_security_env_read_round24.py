"""An unreadable or oversized app.env must not select fallback security state."""

import os
from pathlib import Path
import tempfile
from unittest import SkipTest
from unittest.mock import patch

from dataplane import service


def _base():
    return tempfile.TemporaryDirectory(prefix="ducknet-r24-env-read-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _without_state_key(action):
    key = "DUCKNET_STATE_KEY"
    previous = os.environ.pop(key, None)
    try:
        return action()
    finally:
        os.environ.pop(key, None)
        if previous is not None:
            os.environ[key] = previous


def test_existing_explicit_env_directory_rejects_instead_of_loading_defaults():
    with _base() as base:
        env_path = Path(base) / "app.env"
        env_path.mkdir()

        def check():
            try:
                service.load_env_file(str(env_path))
            except SystemExit as exc:
                assert "app.env" in str(exc), exc
            else:
                raise AssertionError("existing unreadable app.env silently selected defaults")
            assert "DUCKNET_STATE_KEY" not in os.environ

        _without_state_key(check)


def test_existing_explicit_env_permission_error_rejects_without_partial_apply():
    with _base() as base:
        env_path = Path(base) / "app.env"
        env_path.write_text("DUCKNET_STATE_KEY=existing-key\n", encoding="utf-8")

        def check():
            with patch("builtins.open", side_effect=PermissionError(13, "denied", str(env_path))):
                try:
                    service.load_env_file(str(env_path))
                except SystemExit as exc:
                    assert "app.env" in str(exc), exc
                else:
                    raise AssertionError("unreadable app.env silently selected defaults")
            assert "DUCKNET_STATE_KEY" not in os.environ

        _without_state_key(check)


def test_oversized_env_rejects_before_publishing_early_security_key():
    with _base() as base:
        env_path = Path(base) / "app.env"
        env_path.write_bytes(b"DUCKNET_STATE_KEY=existing-key\n" +
                             b"#" * (1024 * 1024 + 1))

        def check():
            try:
                service.load_env_file(str(env_path))
            except SystemExit as exc:
                assert "app.env" in str(exc), exc
            else:
                raise AssertionError("oversized app.env changed security key")
            assert "DUCKNET_STATE_KEY" not in os.environ

        _without_state_key(check)


def test_absent_explicit_env_remains_optional_and_valid_file_loads():
    with _base() as base:
        env_path = Path(base) / "app.env"

        def check():
            assert service.load_env_file(str(env_path)) == 0
            assert "DUCKNET_STATE_KEY" not in os.environ
            env_path.write_text("DUCKNET_STATE_KEY=valid-key\n", encoding="utf-8")
            assert service.load_env_file(str(env_path)) == 1
            assert os.environ["DUCKNET_STATE_KEY"] == "valid-key"

        _without_state_key(check)


def test_autodiscovery_lstat_permission_error_rejects_before_fallback():
    with _base() as base:
        env_path = Path(base) / "app.env"
        env_path.write_text("DUCKNET_STATE_KEY=existing-key\n", encoding="utf-8")
        original_lstat = os.lstat

        def denied(path, *args, **kwargs):
            if os.fspath(path) == str(env_path):
                raise PermissionError(13, "denied", str(env_path))
            return original_lstat(path, *args, **kwargs)

        def check():
            with patch.object(service.os, "getcwd", return_value=str(base)), \
                    patch.object(service.os, "lstat", side_effect=denied):
                try:
                    service.load_env_file()
                except SystemExit as exc:
                    assert "app.env" in str(exc), exc
                else:
                    raise AssertionError("inaccessible discovered app.env selected fallback")
            assert "DUCKNET_STATE_KEY" not in os.environ

        _without_state_key(check)


def test_explicit_lstat_permission_error_rejects_before_open():
    with _base() as base:
        env_path = Path(base) / "app.env"
        env_path.write_text("DUCKNET_STATE_KEY=existing-key\n", encoding="utf-8")
        original_lstat = os.lstat

        def denied(path, *args, **kwargs):
            if os.fspath(path) == str(env_path):
                raise PermissionError(13, "denied", str(env_path))
            return original_lstat(path, *args, **kwargs)

        def check():
            with patch.object(service.os, "lstat", side_effect=denied):
                try:
                    service.load_env_file(str(env_path))
                except SystemExit as exc:
                    assert "app.env" in str(exc), exc
                else:
                    raise AssertionError("explicit app.env stat failure was ignored")
            assert "DUCKNET_STATE_KEY" not in os.environ

        _without_state_key(check)


def test_real_posix_inaccessible_discovered_env_rejects():
    if os.name != "posix" or getattr(os, "geteuid", lambda: 0)() == 0:
        raise SkipTest("requires a nonroot POSIX process")
    with _base() as base:
        launch = Path(base) / "launch"
        launch.mkdir()
        env_path = launch / "app.env"
        env_path.write_text("DUCKNET_STATE_KEY=existing-key\n", encoding="utf-8")
        previous_cwd = os.getcwd()

        def check():
            os.chdir(launch)
            launch.chmod(0)
            try:
                assert not os.path.lexists(env_path)
                try:
                    service.load_env_file()
                except SystemExit as exc:
                    assert "app.env" in str(exc), exc
                else:
                    raise AssertionError("inaccessible app.env selected defaults")
                assert "DUCKNET_STATE_KEY" not in os.environ
            finally:
                os.chdir(previous_cwd)
                launch.chmod(0o700)

        _without_state_key(check)
