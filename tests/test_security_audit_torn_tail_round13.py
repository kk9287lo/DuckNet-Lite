"""A failed audit rollback must not make the next append claim success."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.core import atomic_io


class _PersistPrefixThenFail:
    def __init__(self, actual):
        self.actual = actual

    def __enter__(self):
        self.actual.__enter__()
        return self

    def __exit__(self, *args):
        return self.actual.__exit__(*args)

    def fileno(self):
        return self.actual.fileno()

    def write(self, wire):
        self.actual.write(wire[:8])
        raise OSError("injected short write after a real prefix")


def test_failed_rollback_leaves_auditable_bytes_and_later_append_fails_closed():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        path = Path(state, "audit.jsonl")
        first = {"row": "before"}
        assert atomic_io.append_jsonl(str(path), first, max_bytes=200)
        original = path.read_bytes()
        opened = atomic_io._open_append_nofollow

        def partial(target, encoding):
            return _PersistPrefixThenFail(opened(target, encoding))

        with patch.object(atomic_io, "_open_append_nofollow", side_effect=partial), \
                patch.object(atomic_io.os, "ftruncate",
                             side_effect=OSError("injected rollback I/O failure")):
            assert atomic_io.append_jsonl(str(path), {"row": "failed"},
                                          max_bytes=200) is False
        torn = path.read_bytes()
        assert torn == original + (json.dumps({"row": "failed"}) + os.linesep).encode()[:8]

        assert atomic_io.append_jsonl(str(path), {"row": "after"},
                                      max_bytes=200) is False
        assert path.read_bytes() == torn
        # Reaching the cap must not hide the torn row in a rotated backup.
        after_bytes = (json.dumps({"row": "after"}) + os.linesep).encode()
        cap = len(torn) + len(after_bytes) - 1
        assert atomic_io.append_jsonl(str(path), {"row": "after"},
                                      max_bytes=cap) is False
        assert path.read_bytes() == torn
        assert not Path(str(path) + ".1").exists()


def test_complete_audit_tail_still_accepts_the_next_row():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        path = Path(state, "audit.jsonl")
        assert atomic_io.append_jsonl(str(path), {"row": "before"}, max_bytes=200)
        assert atomic_io.append_jsonl(str(path), {"row": "after"}, max_bytes=200)
        assert [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] == [
            {"row": "before"}, {"row": "after"}]
