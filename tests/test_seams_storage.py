"""Faults during JSONL rotation must not discard already stored audit bytes."""
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from dataplane.engine.core import atomic_io as AIO

_CAP = 32  # one new row fits; current + new requires rotation on both OSes


def _seed(folder):
    path = Path(folder, "audit.jsonl")
    path.write_bytes(b'{"row":"current"}\n')
    Path(str(path) + ".1").write_bytes(b'{"row":"prior"}\n')
    Path(str(path) + ".2").write_bytes(b'{"row":"oldest"}\n')
    return path


def _existing(path):
    return {suffix: Path(str(path) + suffix).read_bytes()
            for suffix in ("", ".1", ".2")}


def _faulted_append(path, reject):
    original = os.replace

    def replace(src, dst):
        if reject(str(src), str(dst)):
            raise OSError("synthetic move failure")
        return original(src, dst)

    with mock.patch.object(AIO.os, "replace", side_effect=replace):
        assert AIO.append_jsonl(str(path), {"row": "new"}, max_bytes=_CAP, backups=2) is False


def _assert_old_at_original_paths(path, before):
    assert path.read_bytes() == before[""]
    for suffix in (".1", ".2"):
        assert Path(str(path) + suffix).read_bytes() == before[suffix]


def test_normal_rotation_keeps_recent_generations_and_new_append():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        assert AIO.append_jsonl(str(path), {"row": "new"}, max_bytes=_CAP, backups=2)
        assert json.loads(path.read_bytes())["row"] == "new"
        assert Path(str(path) + ".1").read_bytes() == b'{"row":"current"}\n'
        assert Path(str(path) + ".2").read_bytes() == b'{"row":"prior"}\n'


def test_failed_retirement_keeps_all_old_bytes_at_original_paths():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        before = _existing(path)
        _faulted_append(path, lambda src, dst: src == str(path) + ".2"
                        and ".rot-" in dst)
        _assert_old_at_original_paths(path, before)


def test_failed_current_staging_keeps_all_old_bytes_at_original_paths():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        before = _existing(path)
        _faulted_append(path, lambda src, dst: src == str(path)
                        and ".rot-" in dst)
        _assert_old_at_original_paths(path, before)


def test_failed_backup_shift_keeps_all_old_bytes_at_original_paths():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        before = _existing(path)
        _faulted_append(path, lambda src, dst: src == str(path) + ".1"
                        and dst == str(path) + ".2")
        _assert_old_at_original_paths(path, before)


def test_failed_new_backup_publish_rolls_back_old_generations():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        before = _existing(path)
        _faulted_append(path, lambda src, dst: ".rot-" in src
                        and dst == str(path) + ".1")
        _assert_old_at_original_paths(path, before)


def test_rollback_failure_leaves_staged_bytes_available_for_recovery():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        before = _existing(path)
        original = os.replace

        def replace(src, dst):
            src, dst = str(src), str(dst)
            if (src == str(path) + ".1" and dst == str(path) + ".2"
                    or ".rot-" in src and dst == str(path) + ".2"):
                raise OSError("synthetic forward and restore failure")
            return original(src, dst)

        with mock.patch.object(AIO.os, "replace", side_effect=replace):
            assert AIO.append_jsonl(str(path), {"row": "new"}, max_bytes=_CAP,
                                    backups=2) is False
        all_bytes = b"".join(item.read_bytes() for item in Path(folder).iterdir()
                             if item.is_file())
        assert before[""] in all_bytes and before[".1"] in all_bytes
        assert before[".2"] in all_bytes and b'"new"' not in all_bytes


def test_failed_current_restore_leaves_original_in_staging_file():
    with tempfile.TemporaryDirectory() as folder:
        path = _seed(folder)
        before = _existing(path)
        original = os.replace

        def replace(src, dst):
            src, dst = str(src), str(dst)
            if (src == str(path) + ".1" and dst == str(path) + ".2"
                    or ".rot-current-" in src and dst == str(path)):
                raise OSError("synthetic forward and current-restore failure")
            return original(src, dst)

        with mock.patch.object(AIO.os, "replace", side_effect=replace):
            assert AIO.append_jsonl(str(path), {"row": "new"}, max_bytes=_CAP,
                                    backups=2) is False
        all_bytes = b"".join(item.read_bytes() for item in Path(folder).iterdir()
                             if item.is_file())
        assert before[""] in all_bytes and before[".1"] in all_bytes
        assert before[".2"] in all_bytes and b'"new"' not in all_bytes
