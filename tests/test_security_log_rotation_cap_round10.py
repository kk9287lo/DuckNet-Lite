"""A held log reader must not turn the advertised rotation cap into unbounded growth."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import SkipTest
from unittest.mock import patch

import dataplane.engine.core.atomic_io as atomic_io
from dataplane.engine.core.atomic_io import append_jsonl
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.lifeform.pipeline import NetShield
from test_falco_admin_boundaries import _Admin


_TWO_PROCESS_APPEND = r"""
import sys,time
from pathlib import Path
import dataplane.engine.core.atomic_io as aio
path, started, ready, go, cap = sys.argv[1:]
Path(started).touch()
actual_getsize = aio.os.path.getsize
def observed(candidate):
    size = actual_getsize(candidate)
    if candidate == path:
        Path(ready).touch()
        deadline = time.monotonic() + 8
        while not Path(go).exists() and time.monotonic() < deadline:
            time.sleep(.002)
        if not Path(go).exists():
            raise TimeoutError("test barrier was not released")
    return size
aio.os.path.getsize = observed
print(aio.append_jsonl(path, {"row": "B" * 20}, max_bytes=int(cap)), flush=True)
"""


class _PartialWriter:
    """Persist a real prefix, then mimic a short disk write failure."""

    def __init__(self, actual):
        self.actual = actual

    def __enter__(self):
        self.actual.__enter__()
        return self

    def __exit__(self, *args):
        return self.actual.__exit__(*args)

    def fileno(self):
        return self.actual.fileno()

    def write(self, line):
        self.actual.write(line[:8])
        self.actual.flush()
        raise OSError("injected short disk write")


class _ShortChunks(_PartialWriter):
    def write(self, line):
        return self.actual.write(line[:7])


def _short_write(path, row, max_bytes):
    opened = atomic_io._open_append_nofollow

    def partial(target, encoding, **budget):
        return _PartialWriter(opened(target, encoding, **budget))

    with patch.object(atomic_io, "_open_append_nofollow", side_effect=partial):
        return append_jsonl(str(path), row, max_bytes=max_bytes)


def test_acl_decision_reports_failed_log_when_windows_reader_blocks_rotation():
    if os.name != "nt":
        raise SkipTest("POSIX can rename an open log; Windows sharing boundary")
    with tempfile.TemporaryDirectory() as state:
        firewall = AppFirewall(state_dir=state)
        path = Path(firewall.log_path)
        # A valid JSONL row just below the production 5 MB rotation limit.
        path.write_bytes(b'{"pad":"' + b'A' * 4_999_960 + b'"}\n')
        before = path.read_bytes()
        assert len(before) < 5_000_000
        with path.open("rb"):
            decision = firewall.evaluate("192.0.2.9")
            assert decision["log_written"] is False
            assert path.read_bytes() == before
            assert firewall._log_write_failed == 1
            assert not Path(str(path) + ".1").exists()


def test_admin_post_discloses_audit_log_capacity_failure_on_real_http_wire():
    if os.name != "nt":
        raise SkipTest("POSIX can rename an open log; Windows sharing boundary")
    with _Admin() as admin:
        assert admin.sh.enable()["ok"] is True
        path = Path(admin.tmp.name, "admin_audit.jsonl")
        path.write_bytes(b'{"pad":"' + b'A' * 4_999_960 + b'"}\n')
        before = path.read_bytes()
        with path.open("rb"):
            status, _headers, wire_body = admin.request([("X-Token", admin.token)])
            result = json.loads(wire_body)
            assert status == 200 and result["ok"] is True
            assert result.get("audit_recorded") is False and result.get("warning")
            assert path.read_bytes() == before
            assert admin.sh.is_enabled() is False
            assert NetShield(state_dir=admin.tmp.name).is_enabled() is False


def test_one_oversized_row_is_rejected_before_any_log_publication():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        assert append_jsonl(str(path), {"row": "A" * 120}, max_bytes=80) is False
        assert not path.exists()


def test_unknown_existing_log_size_cannot_claim_a_bounded_append():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        path.write_bytes(b'{"row":"existing"}\n')
        before = path.read_bytes()
        with patch.object(atomic_io.os.path, "getsize",
                          side_effect=PermissionError("metadata unavailable")):
            assert append_jsonl(str(path), {"row": "new"}, max_bytes=80) is False
        assert path.read_bytes() == before

        # A genuinely absent log still permits its first bounded row.
        missing = Path(state) / "first.jsonl"
        assert append_jsonl(str(missing), {"row": "new"}, max_bytes=80) is True
        assert json.loads(missing.read_text(encoding="utf-8")) == {"row": "new"}


def test_two_processes_cannot_both_append_from_the_same_stale_size():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "acl_log.jsonl"
        old = (json.dumps({"row": "A" * 50}) + os.linesep).encode()
        fresh = (json.dumps({"row": "B" * 20}) + os.linesep).encode()
        path.write_bytes(old)
        cap = len(old) + len(fresh) + 1
        go = Path(state) / "go"
        children = []
        try:
            for index in range(2):
                started = Path(state) / f"started-{index}"
                ready = Path(state) / f"ready-{index}"
                child = subprocess.Popen(
                    [sys.executable, "-c", _TWO_PROCESS_APPEND, str(path),
                     str(started), str(ready), str(go), str(cap)],
                    cwd=Path(__file__).resolve().parent.parent,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append((child, started, ready))
            deadline = time.monotonic() + 8
            while not all(started.exists() for _, started, _ in children):
                assert time.monotonic() < deadline, "append children did not start"
                time.sleep(.005)
            # Old code lets both processes size the same file before either
            # writes. A process-wide lock should keep the second at its gate.
            until = time.monotonic() + 1.0
            while (sum(ready.exists() for _, _, ready in children) < 2
                   and time.monotonic() < until):
                time.sleep(.005)
            go.touch()
            outputs = [child.communicate(timeout=8) for child, _, _ in children]
            assert all(child.returncode == 0 and out.strip() == "True"
                       for (child, _, _), (out, _err) in zip(children, outputs)), outputs
            generations = [p for p in (path, Path(str(path) + ".1")) if p.exists()]
            assert all(p.stat().st_size <= cap for p in generations)
            rows = [json.loads(line) for p in generations
                    for line in p.read_text(encoding="utf-8").splitlines()]
            assert sum(row.get("row") == "B" * 20 for row in rows) == 2, rows
        finally:
            go.touch()
            for child, _, _ in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=3)


def test_nonwaiting_log_append_does_not_queue_behind_another_process():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "acl_log.jsonl"
        path.write_bytes(b'{"row":"old"}' + os.linesep.encode())
        started, ready, go = (Path(state) / name for name in
                              ("started", "ready", "go"))
        child = subprocess.Popen(
            [sys.executable, "-c", _TWO_PROCESS_APPEND, str(path),
             str(started), str(ready), str(go), "1000"],
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 8
            while not ready.exists():
                assert child.poll() is None and time.monotonic() < deadline
                time.sleep(.005)
            began = time.monotonic()
            assert append_jsonl(str(path), {"row": "probe"}, max_bytes=1000,
                                wait=False) is False
            assert time.monotonic() - began < .5
            assert path.read_bytes() == b'{"row":"old"}' + os.linesep.encode()
            go.touch()
            output, error = child.communicate(timeout=8)
            assert child.returncode == 0 and output.strip() == "True", error
            assert append_jsonl(str(path), {"row": "after"}, max_bytes=1000,
                                wait=False) is True
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            assert rows == [{"row": "old"}, {"row": "B" * 20}, {"row": "after"}]
        finally:
            go.touch()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=3)


def test_waiting_append_has_one_deadline_for_held_local_mutex():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        assert append_jsonl(str(path), {"row": "old"}) is True
        before = path.read_bytes()
        holder = atomic_io._append_lock(str(path))
        assert holder.acquire(blocking=False)
        started = threading.Event()
        result = []

        def worker():
            started.set()
            began = time.monotonic()
            result.append((append_jsonl(str(path), {"row": "late"}, wait=True),
                           time.monotonic() - began))

        thread = threading.Thread(target=worker)
        try:
            with patch.object(atomic_io, "_APPEND_FILE_WAIT_SEC", .15):
                thread.start()
                assert started.wait(1)
                thread.join(timeout=.3)
                completed_before_release = not thread.is_alive()
        finally:
            holder.release()
            thread.join(timeout=2)
        assert completed_before_release and result and result[0][0] is False, result
        assert result[0][1] < .3 and path.read_bytes() == before
        assert append_jsonl(str(path), {"row": "after"}, wait=True) is True
        assert [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] == [
            {"row": "old"}, {"row": "after"}]


def test_failed_write_releases_the_interprocess_log_lock():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        with patch.object(atomic_io, "_open_append_nofollow",
                          side_effect=OSError("injected open failure")):
            assert append_jsonl(str(path), {"row": "failed"}) is False
        probe = subprocess.run(
            [sys.executable, "-c",
             "import sys; from dataplane.engine.core.atomic_io import append_jsonl; "
             "print(append_jsonl(sys.argv[1], {'row':'after'}))", str(path)],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True, text=True, timeout=5)
        assert probe.returncode == 0 and probe.stdout.strip() == "True", probe.stderr
        assert json.loads(path.read_text(encoding="utf-8")) == {"row": "after"}


def test_encoded_row_budget_uses_actual_backslashreplace_and_exact_lf_bytes():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        row = {"row": "\udc80"}
        line = json.dumps(row, ensure_ascii=False) + "\n"
        encoded = line.replace("\n", os.linesep).encode("utf-8", "backslashreplace")
        assert append_jsonl(str(path), row, max_bytes=len(encoded) - 1) is False
        assert not path.exists()
        assert append_jsonl(str(path), row, max_bytes=len(encoded)) is True
        assert path.read_bytes() == encoded


def test_normal_rotation_preserves_the_previous_row_and_new_row():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        old, new = {"row": "A" * 35}, {"row": "B" * 35}
        assert append_jsonl(str(path), old, max_bytes=70) is True
        first = path.read_bytes()
        assert append_jsonl(str(path), new, max_bytes=70) is True
        assert Path(str(path) + ".1").read_bytes() == first
        assert [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] == [new]


def test_short_write_cannot_leave_a_suffix_on_an_existing_jsonl_row():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        old = {"row": "old"}
        assert append_jsonl(str(path), old, max_bytes=200) is True
        before = path.read_bytes()
        assert _short_write(path, {"row": "new"}, 200) is False
        assert path.read_bytes() == before
        assert append_jsonl(str(path), {"row": "after"}, max_bytes=200) is True
        assert [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] == [
            old, {"row": "after"}]


def test_short_write_after_rotation_preserves_old_generation_and_clean_new_log():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        old = {"row": "A" * 35}
        assert append_jsonl(str(path), old, max_bytes=70) is True
        before = path.read_bytes()
        assert _short_write(path, {"row": "B" * 35}, 70) is False
        assert Path(str(path) + ".1").read_bytes() == before
        assert not path.exists() or path.stat().st_size == 0
        assert append_jsonl(str(path), {"row": "after"}, max_bytes=70) is True
        assert json.loads(path.read_text(encoding="utf-8")) == {"row": "after"}


def test_short_successful_writes_are_completed_before_reporting_success():
    with tempfile.TemporaryDirectory() as state:
        path = Path(state) / "audit.jsonl"
        opened = atomic_io._open_append_nofollow

        def chunks(target, encoding, **budget):
            return _ShortChunks(opened(target, encoding, **budget))

        with patch.object(atomic_io, "_open_append_nofollow", side_effect=chunks):
            assert append_jsonl(str(path), {"row": "A" * 40}, max_bytes=80) is True
        assert json.loads(path.read_text(encoding="utf-8")) == {"row": "A" * 40}
