"""A damaged app.env must not silently select a fresh security state home."""

import os
from pathlib import Path
import tempfile

from dataplane import service


def test_invalid_utf8_state_home_cannot_silently_replace_existing_state():
    with tempfile.TemporaryDirectory(prefix="ducknet-r24-env-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as base:
        intended = Path(base) / "state\u0080"
        intended.mkdir()
        marker = intended / "existing-ban-state"
        marker.write_text("keep", encoding="ascii")
        env_file = Path(base) / "app.env"
        env_file.write_bytes(b"DUCKNET_STATE_DIR=" +
                             str(intended).encode("latin-1") + b"\n")
        old = os.environ.pop("DUCKNET_STATE_DIR", None)
        try:
            try:
                service.load_env_file(str(env_file))
            except SystemExit as exc:
                assert "UTF-8" in str(exc), exc
            else:
                raise AssertionError("invalid UTF-8 silently selected a new state directory")
            assert "DUCKNET_STATE_DIR" not in os.environ
            assert marker.read_text(encoding="ascii") == "keep"
        finally:
            os.environ.pop("DUCKNET_STATE_DIR", None)
            if old is not None:
                os.environ["DUCKNET_STATE_DIR"] = old


def test_late_invalid_utf8_line_cannot_partially_publish_security_settings():
    with tempfile.TemporaryDirectory(prefix="ducknet-r24-env-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as base:
        env_file = Path(base) / "app.env"
        env_file.write_bytes(b"DUCKNET_ADMIN_TOKEN=valid-test-token\n"
                             b"DUCKNET_STATE_KEY=broken-\xff\n")
        keys = ("DUCKNET_ADMIN_TOKEN", "DUCKNET_STATE_KEY")
        old = {key: os.environ.pop(key, None) for key in keys}
        try:
            try:
                service.load_env_file(str(env_file))
            except SystemExit as exc:
                assert "UTF-8" in str(exc), exc
            else:
                raise AssertionError("invalid UTF-8 partially published credentials")
            assert all(key not in os.environ for key in keys)
        finally:
            for key in keys:
                os.environ.pop(key, None)
                if old[key] is not None:
                    os.environ[key] = old[key]


def test_nul_in_late_line_cannot_partially_publish_security_settings():
    with tempfile.TemporaryDirectory(prefix="ducknet-r24-env-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as base:
        env_file = Path(base) / "app.env"
        env_file.write_bytes(b"DUCKNET_ADMIN_TOKEN=valid-test-token\n"
                             b"DUCKNET_STATE_KEY=broken-\x00-key\n")
        keys = ("DUCKNET_ADMIN_TOKEN", "DUCKNET_STATE_KEY")
        old = {key: os.environ.pop(key, None) for key in keys}
        try:
            try:
                service.load_env_file(str(env_file))
            except SystemExit as exc:
                assert "NUL" in str(exc), exc
            else:
                raise AssertionError("NUL line partially published credentials")
            assert all(key not in os.environ for key in keys)
        finally:
            for key in keys:
                os.environ.pop(key, None)
                if old[key] is not None:
                    os.environ[key] = old[key]


def test_valid_utf8_nonascii_state_home_and_caller_priority_remain_usable():
    with tempfile.TemporaryDirectory(prefix="ducknet-r24-env-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as base:
        selected = str(Path(base) / "状態")
        env_file = Path(base) / "app.env"
        env_file.write_text("DUCKNET_STATE_DIR=" + selected + "\n"
                            "DUCKNET_ADMIN_TOKEN=from-file\n", encoding="utf-8")
        keys = ("DUCKNET_STATE_DIR", "DUCKNET_ADMIN_TOKEN")
        old = {key: os.environ.pop(key, None) for key in keys}
        try:
            os.environ["DUCKNET_ADMIN_TOKEN"] = "from-caller"
            assert service.load_env_file(str(env_file)) == 1
            assert os.environ["DUCKNET_STATE_DIR"] == selected
            assert os.environ["DUCKNET_ADMIN_TOKEN"] == "from-caller"
        finally:
            for key in keys:
                os.environ.pop(key, None)
                if old[key] is not None:
                    os.environ[key] = old[key]
