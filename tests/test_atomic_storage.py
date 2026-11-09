"""Atomic state publication, durable key creation, and process concurrency."""

import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.core import atomic_io as aio
from dataplane.engine.core import signed_state as ss


def test_stale_empty_key_replacement_is_serialized_between_creators():
    """Two recoveries must not return different keys for one state directory."""
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, ".statekey")
        with open(path, "wb"):
            pass
        old = time.time() - 20
        os.utime(path, (old, old))
        paused = threading.Event()
        release = threading.Event()
        results = {}
        real_replace = os.replace

        def delayed_replace(src, dst):
            if dst == path and threading.current_thread().name == "first-key":
                paused.set()
                assert release.wait(3), "first creator was never released"
            return real_replace(src, dst)

        def create(label):
            try:
                results[label] = ss.load_or_create_key(path)
            except Exception as exc:
                results[label] = exc

        with patch.object(ss.os, "replace", side_effect=delayed_replace):
            first = threading.Thread(target=create, args=("first",), name="first-key")
            second = threading.Thread(target=create, args=("second",), name="second-key")
            first.start()
            try:
                assert paused.wait(3), "stale-key replacement was not exercised"
                second.start()
                # The old implementation lets the second creator replace the key
                # while the first is paused immediately before its own replace.
                time.sleep(0.35)
            finally:
                release.set()
                first.join(5)
                if second.ident is not None:
                    second.join(5)
        assert not first.is_alive() and not second.is_alive()
        assert isinstance(results.get("first"), bytes), results
        assert isinstance(results.get("second"), bytes), results
        assert results["first"] == results["second"] == ss.load_or_create_key(path)


def test_first_key_creation_is_identical_across_processes():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, ".statekey")
        code = ("import sys\n"
                "from dataplane.engine.core.signed_state import load_or_create_key\n"
                "print(load_or_create_key(sys.argv[1]).hex(), flush=True)\n")
        children = [subprocess.Popen([sys.executable, "-c", code, path],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True) for _ in range(4)]
        try:
            # On a 1-vCPU WHPX guest, Python startup + this module's import
            # took 2.39-3.39 s while key creation itself took <=0.034 s.
            # Give the four concurrent children one bounded 10 s window so
            # interpreter scheduling does not masquerade as a key-lock hang.
            deadline = time.monotonic() + 10.0
            outputs = [child.communicate(timeout=max(0.0, deadline - time.monotonic()))
                       for child in children]
            assert all(child.returncode == 0 for child in children), outputs
            keys = [out.strip() for out, _ in outputs]
            assert len(set(keys)) == 1 and keys[0] == ss.load_or_create_key(path).hex()
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)


def _fail_directory_sync(fd):
    if stat.S_ISDIR(os.fstat(fd).st_mode):
        raise OSError(errno.EIO, "directory sync failed")
    return _REAL_FSYNC(fd)


_REAL_FSYNC = os.fsync


def test_directory_sync_failure_cannot_claim_signed_commit():
    if os.name != "posix":
        raise SkipTest("POSIX directory fsync is required")
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        key = b"k" * 32
        assert ss.write_signed_json(path, {"v": 1}, key)
        with open(path, "rb") as handle:
            before = handle.read()
        with open(path + ".hw", "rb") as handle:
            before_hw = handle.read()
        result = {}
        with patch.object(aio.os, "fsync", side_effect=_fail_directory_sync):
            assert ss.write_signed_json(path, {"v": 2}, key, status=result) is False
        assert result["stage"] == "highwater"
        assert result["published"] is False and result["durable"] is False
        with open(path, "rb") as handle:
            assert handle.read() == before
        with open(path + ".hw", "rb") as handle:
            assert handle.read() == before_hw
        assert ss.read_signed_json(path, key) == ("ok", {"v": 1})
        assert ss.write_signed_json(path, {"v": 2}, key)
        assert ss.read_signed_json(path, key) == ("ok", {"v": 2})


def test_key_publication_requires_directory_sync():
    if os.name != "posix":
        raise SkipTest("POSIX directory fsync is required")
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, ".statekey")
        with patch.object(ss.os, "fsync", side_effect=_fail_directory_sync):
            try:
                ss.load_or_create_key(path)
            except OSError:
                pass
            else:
                raise AssertionError("key creation claimed durability without syncing its name")
        # A failed start may leave a complete key, but never use an unverified
        # ephemeral key. A later start must recover the durable on-disk one.
        key = ss.load_or_create_key(path)
        assert len(key) == 32 and ss.load_or_create_key(path) == key


def test_key_fallback_publication_also_requires_directory_sync():
    if os.name != "posix":
        raise SkipTest("POSIX directory fsync is required")
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, ".statekey")
        with patch.object(ss.os, "link", side_effect=OSError(errno.ENOTSUP, "no hardlink")), \
                patch.object(ss.os, "fsync", side_effect=_fail_directory_sync):
            try:
                ss.load_or_create_key(path)
            except OSError:
                pass
            else:
                raise AssertionError("fallback key publication ignored directory sync failure")
        assert len(ss.load_or_create_key(path)) == 32


def test_post_replace_sync_reports_published_but_not_durable():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.txt")
        assert aio.atomic_write_text(path, "old")
        status = {}
        with patch.object(aio, "_sync_directory", side_effect=(True, False)):
            assert aio.atomic_write_text(path, "new", status=status) is True
        assert status == {"published": True, "durable": False}
        with open(path, encoding="utf-8") as handle:
            assert handle.read() == "new"       # published: caller must not roll memory back

        status = {}
        with patch.object(aio, "_sync_directory", return_value=None):
            assert aio.atomic_write_text(path, "newer", status=status) is True
        assert status == {"published": True, "durable": None}  # unsupported OS/FS


def test_sidecar_post_replace_sync_failure_restores_old_state():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        key = b"k" * 32
        assert ss.write_signed_json(path, {"v": 1}, key)
        with open(path, "rb") as handle:
            before = handle.read()
        with open(path + ".hw", "rb") as handle:
            before_hw = handle.read()
        # sidecar preflight passes, post-replace sync fails, restore succeeds.
        result = {}
        with patch.object(aio, "_sync_directory", side_effect=(True, False, True, True)):
            assert ss.write_signed_json(path, {"v": 2}, key, status=result) is False
        assert result["stage"] == "highwater"
        assert result["highwater_published"] is True
        assert result["highwater_durable"] is False
        assert result["published"] is False
        with open(path, "rb") as handle:
            assert handle.read() == before
        with open(path + ".hw", "rb") as handle:
            restored_hw = handle.read()
        assert ss._read_file_hw(path, key) == json.loads(before_hw)["_ver"]
        assert restored_hw == before_hw
        assert ss.read_signed_json(path, key) == ("ok", {"v": 1})


def test_main_post_replace_sync_failure_keeps_visible_commit():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        key = b"k" * 32
        assert ss.write_signed_json(path, {"v": 1}, key)
        # High-water is durable; main is published but its directory sync fails.
        result = {}
        with patch.object(aio, "_sync_directory", side_effect=(True, True, True, False)):
            assert ss.write_signed_json(path, {"v": 2}, key, status=result) is True
        assert result["stage"] == "published"
        assert result["published"] is True and result["durable"] is False
        assert result["highwater_durable"] is True and result["main_published"] is True
        assert ss.read_signed_json(path, key) == ("ok", {"v": 2})


def test_main_published_status_prevents_rollback_on_late_wrapper_failure():
    """A later wrapper error cannot turn a visible main commit into rollback."""
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        key = b"k" * 32
        assert ss.write_signed_json(path, {"v": 1}, key)
        actual_write = ss.atomic_write_json

        def fail_after_publish(target, obj, **kwargs):
            result = actual_write(target, obj, **kwargs)
            if target == path:
                assert result is True
                return False                       # late failure after status.published=True
            return result

        result = {}
        with patch.object(ss, "atomic_write_json", side_effect=fail_after_publish):
            assert ss.write_signed_json(path, {"v": 2}, key, status=result) is True
        assert result["published"] is True
        assert ss.read_signed_json(path, key) == ("ok", {"v": 2})


def test_signed_status_reports_normal_and_unsupported_sync():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        key = b"k" * 32
        result = {}
        assert ss.write_signed_json(path, {"v": 1}, key, status=result) is True
        assert result["published"] is True
        assert result["durable"] is (None if os.name == "nt" else True)
        with patch.object(aio, "_sync_directory", return_value=None):
            result = {}
            assert ss.write_signed_json(path, {"v": 2}, key, status=result) is True
        assert result["published"] is True and result["durable"] is None
        assert ss.read_signed_json(path, key) == ("ok", {"v": 2})


def test_replace_error_preserves_old_file_and_removes_temp():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.txt")
        assert aio.atomic_write_text(path, "old")
        with patch.object(aio.os, "replace", side_effect=OSError(errno.EIO, "rename failed")):
            assert aio.atomic_write_text(path, "new") is False
        with open(path, encoding="utf-8") as handle:
            assert handle.read() == "old"
        assert os.listdir(directory) == ["state.txt"]


def test_newline_passthrough_keeps_export_bytes_exact():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "edge.txt")
        assert aio.atomic_write_text(path, "first\r\nsecond\n", newline="") is True
        with open(path, "rb") as handle:
            assert handle.read() == b"first\r\nsecond\n"


def test_json_writer_rejects_payload_its_reader_cannot_load():
    """The byte cap must be checked before replacing a readable state file."""
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        old = {"v": "old"}
        assert aio.atomic_write_json(path, old)
        with open(path, "rb") as handle:
            old_bytes = handle.read()
        too_large = {"v": "界" * 20}
        encoded = json.dumps(too_large, ensure_ascii=False, indent=2)
        assert len(encoded) < 64 < len(encoded.encode("utf-8", "backslashreplace"))
        with patch.object(aio, "_MAX_READ_BYTES", 64):
            status = {}
            assert aio.atomic_write_json(path, too_large, status=status) is False
            assert status == {"published": False, "durable": False}
            with open(path, "rb") as handle:
                assert handle.read() == old_bytes
            assert aio.safe_read_json(path, "unreadable") == old

            # In-limit UTF-8 and JSON-escaped lone surrogates still round-trip.
            within_limit = {"v": "東京é\ud800"}
            assert len(json.dumps(within_limit, ensure_ascii=False, indent=2)
                       .encode("utf-8", "backslashreplace")) <= 64
            assert aio.atomic_write_json(path, within_limit, status=status) is True
            assert status["published"] is True
            assert aio.safe_read_json(path, "unreadable") == within_limit

            exact = {"v": "a" * 15}
            exact_size = len(json.dumps(exact, ensure_ascii=False, indent=2)
                             .encode("utf-8", "backslashreplace"))
            with patch.object(aio, "_MAX_READ_BYTES", exact_size):
                assert aio.atomic_write_json(path, exact, status=status) is True
                assert os.path.getsize(path) == exact_size
                assert aio.safe_read_json(path, "unreadable") == exact


def test_stale_second_process_cannot_erase_newer_signed_ban_snapshot():
    """A later worker must reject its old baseline and keep the first BAN."""
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "blocklist.json")
        ready = os.path.join(directory, "worker-ready")
        key = b"k" * 32
        initial = {"bans": {"1.1.1.1": 1}}
        assert ss.write_signed_json(path, initial, key)
        worker = r'''
import hashlib,json,sys
from dataplane.engine.core.signed_state import _canon,read_signed_json,write_signed_json
path,ready=sys.argv[1:]
key=b"k"*32
state,payload=read_signed_json(path,key)
assert state=="ok"
baseline=hashlib.sha256(_canon(payload)).hexdigest()
with open(ready,"w") as f:f.write("ready")
sys.stdin.readline()
candidate={"bans":dict(payload["bans"])}
candidate["bans"]["3.3.3.3"]=3
result={}
try:
    ok=write_signed_json(path,candidate,key,expected_fingerprint=baseline,status=result)
except TypeError:  # old implementation: execute the actual stale overwrite
    ok=write_signed_json(path,candidate,key,status=result)
print(json.dumps({"ok":ok,"status":result}))
'''
        child = subprocess.Popen([sys.executable, "-c", worker, path, ready],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not os.path.exists(ready) and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not os.path.exists(ready):
                if child.poll() is None:
                    child.kill()
                _output, error = child.communicate(timeout=3)
                raise AssertionError("stale writer did not reach the barrier: " + error)
            newer = {"bans": {"1.1.1.1": 1, "2.2.2.2": 2}}
            assert ss.write_signed_json(path, newer, key)
            with open(path, "rb") as handle:
                before = handle.read()
            with open(path + ".hw", "rb") as handle:
                before_hw = handle.read()
            output, error = child.communicate("go\n", timeout=5)
            assert child.returncode == 0, error
            rejected = json.loads(output)
            assert rejected["ok"] is False and rejected["status"].get("conflict") is True
            with open(path, "rb") as handle:
                assert handle.read() == before
            with open(path + ".hw", "rb") as handle:
                assert handle.read() == before_hw
            assert ss.read_signed_json(path, key) == ("ok", newer)
            merged = {"bans": {**newer["bans"], "3.3.3.3": 3}}
            published = {}
            assert ss.write_signed_json(
                path, merged, key, expected_fingerprint=ss.payload_fingerprint(newer),
                status=published) is True
            assert published["conflict"] is False
            assert published["fingerprint"] == ss.payload_fingerprint(merged)
            assert ss.read_signed_json(path, key) == ("ok", merged)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)


def test_cas_missing_and_legacy_unsigned_migration_are_explicit():
    key = b"k" * 32
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        first = {"cfg": {"enabled": True}}
        result = {}
        assert ss.write_signed_json(
            path, first, key, expected_fingerprint=ss.MISSING_FINGERPRINT,
            status=result) is True
        assert result["fingerprint"] == ss.payload_fingerprint(first)
        with open(path, "rb") as handle:
            previous = handle.read()
        conflict = {}
        assert ss.write_signed_json(
            path, {"cfg": {"enabled": False}}, key,
            expected_fingerprint=ss.MISSING_FINGERPRINT, status=conflict) is False
        assert conflict["conflict"] is True and conflict["published"] is False
        with open(path, "rb") as handle:
            assert handle.read() == previous

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "legacy.json")
        legacy = {"cfg": {"enabled": False}}
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(legacy, handle)
        updated = {"cfg": {"enabled": True}}
        result = {}
        assert ss.write_signed_json(
            path, updated, key, expected_fingerprint=ss.payload_fingerprint(legacy),
            status=result) is True
        assert result["fingerprint"] == ss.payload_fingerprint(updated)
        assert ss.read_signed_json(path, key) == ("ok", updated)


def test_cas_rejects_tampered_rolled_back_and_missing_after_history():
    key = b"k" * 32
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        old = {"bans": {"1.1.1.1": 1}}
        new = {"bans": {"1.1.1.1": 1, "2.2.2.2": 2}}
        assert ss.write_signed_json(path, old, key)
        with open(path, "rb") as handle:
            old_bytes = handle.read()
        assert ss.write_signed_json(path, new, key)
        with open(path + ".hw", "rb") as handle:
            highwater = handle.read()
        with open(path, "wb") as handle:
            handle.write(old_bytes)               # valid but rolled back
        result = {}
        assert ss.write_signed_json(
            path, old, key, expected_fingerprint=ss.payload_fingerprint(old),
            status=result) is False
        assert result["conflict"] is True
        with open(path, "rb") as handle:
            assert handle.read() == old_bytes
        with open(path + ".hw", "rb") as handle:
            assert handle.read() == highwater

        with open(path, "wb") as handle:
            handle.write(b'{"_sv":3,"_sig":"bad","_payload":{"bans":{}}}')
        result = {}
        assert ss.write_signed_json(
            path, old, key, expected_fingerprint=ss.payload_fingerprint(old),
            status=result) is False
        assert result["conflict"] is True
        os.unlink(path)
        result = {}
        assert ss.write_signed_json(
            path, old, key, expected_fingerprint=ss.MISSING_FINGERPRINT,
            status=result) is False
        assert result["conflict"] is True and not os.path.exists(path)
        repaired = {}
        assert ss.write_signed_json(
            path, new, key, expected_fingerprint=ss.MISSING_WITH_HISTORY_FINGERPRINT,
            status=repaired) is True
        assert repaired["fingerprint"] == ss.payload_fingerprint(new)
        assert ss.read_signed_json(path, key) == ("ok", new)
        assert ss.write_signed_json(
            path, old, key, expected_fingerprint=ss.MISSING_WITH_HISTORY_FINGERPRINT,
            status={}) is False                  # 他workerが先に直したら上書きしない
        with open(path + ".hw", "w", encoding="utf-8") as handle:
            handle.write("{}")                    # sidecar改竄をCASで修復扱いしない
        result = {}
        assert ss.write_signed_json(
            path, old, key, expected_fingerprint=ss.payload_fingerprint(new),
            status=result) is False
        assert result["conflict"] is True


def test_invalid_surrogate_cannot_share_a_signature_with_question_mark():
    key = b"k" * 32
    plain = {"v": "?"}
    surrogate = {"v": "\ud800"}
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "state.json")
        assert ss.write_signed_json(path, plain, key)
        with open(path, encoding="utf-8") as handle:
            envelope = json.load(handle)
        envelope["_payload"] = surrogate           # signature and version unchanged
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(envelope, handle, ensure_ascii=True)
        assert ss.read_signed_json(path, key, default="safe") == ("tampered", "safe")
        assert ss.payload_fingerprint(plain) != ss.payload_fingerprint(surrogate)

        # Ordinary UTF-8 signatures retain their historical canonical bytes.
        ordinary = {"v": "東京é"}
        old_canon = json.dumps(ordinary, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8", "replace")
        assert ss._canon(ordinary) == old_canon
        other = os.path.join(directory, "surrogate.json")
        assert ss.write_signed_json(other, surrogate, key)
        assert ss.read_signed_json(other, key) == ("ok", surrogate)
