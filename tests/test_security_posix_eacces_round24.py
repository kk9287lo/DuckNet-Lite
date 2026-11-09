"""Permission-denied state must not become a fresh, permissive state."""

import builtins
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import SkipTest
from unittest.mock import patch

from dataplane.engine.core import atomic_io
from dataplane.engine.core import signed_state
from dataplane.engine.core.signed_state import persistent_key, read_signed_json, sign_payload


ROOT = Path(__file__).resolve().parents[1]


def _run_unprivileged(source: str):
    if os.name != "posix":
        raise SkipTest("POSIX permission enforcement required")
    drop = ("import os\n"
            "if os.geteuid() == 0:\n"
            " os.setgroups([])\n os.setgid(65534)\n os.setuid(65534)\n")
    env = os.environ.copy()
    env.update(PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    run = subprocess.run([sys.executable, "-c", drop + source], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=20)
    assert run.returncode == 0, (run.stdout, run.stderr)
    return json.loads(run.stdout)


def test_unreadable_legacy_ban_and_stale_tmp_deny_admission():
    result = _run_unprivileged('''
import json, tempfile
from pathlib import Path
from dataplane.engine.core.signed_state import read_signed_json, sign_payload
from dataplane.engine.lifeform.pipeline import NetShield
with tempfile.TemporaryDirectory() as directory:
 state=Path(directory)/'state'; state.mkdir()
 seed=NetShield(state_dir=str(state)); key=seed._state_key
 ip='198.51.100.9'; main=state/'blocklist.json'
 active={'bans':{ip:{'until':9999999999,'permanent':True}}}
 stale={'bans':{}}
 def envelope(payload):
  return json.dumps({'_sv':1,'_sig':sign_payload(payload,key),'_payload':payload})
 main.write_text(envelope(active),encoding='utf8')
 def admission():
  sh=NetShield(state_dir=str(state))
  sh.cfg.update(persist_bans=True,enabled=True)
  sh._load_bans()
  return {'banned':sh.is_banned_fast(ip),'untrusted':sh._ban_state_untrusted,
          'action':sh.inspect(ip,path='/clean')['action']}
 good=admission()
 (state/'blocklist.json.tmp').write_text(envelope(stale),encoding='utf8')
 main.chmod(0)
 try:
  denied=admission()
  status=read_signed_json(str(main),key,{})[0]
 finally:
  main.chmod(0o600)
 print(json.dumps({'good':good,'denied':denied,'status':status}))
''')
    assert result["good"] == {"banned": True, "untrusted": False, "action": "block"}
    assert result["status"] == "tampered"
    assert result["denied"]["untrusted"] is True
    assert result["denied"]["action"] == "block"


def test_eacces_legacy_selection_and_ancestor_state_are_not_missing():
    result = _run_unprivileged('''
import json, os, tempfile
from pathlib import Path
from dataplane.engine.core.atomic_io import default_state_dir, LegacyStateSelectionRequired
from dataplane.engine.core.signed_state import read_signed_json
with tempfile.TemporaryDirectory() as directory:
 home=Path(directory); cache=home/'.cache'; legacy=cache/'dataplane'
 legacy.mkdir(parents=True); (legacy/'.statekey').write_bytes(b'x'*32)
 os.environ['HOME']=str(home); os.environ.pop('DUCKNET_STATE_DIR',None)
 cache.chmod(0)
 try:
  try: default_state_dir(); selection='selected'
  except LegacyStateSelectionRequired: selection='refused'
 finally: cache.chmod(0o700)
 outer=home/'outer'; inner=outer/'inner'; inner.mkdir(parents=True)
 (inner/'blocklist.json').write_text('{}',encoding='ascii')
 outer.chmod(0)
 try: state=read_signed_json(str(inner/'blocklist.json'),b'k'*32,{})[0]
 finally: outer.chmod(0o700)
 print(json.dumps({'selection':selection,'state':state}))
''')
    assert result == {"selection": "refused", "state": "tampered"}


def test_lstat_eacces_fault_injection_refuses_both_namespace_paths():
    with tempfile.TemporaryDirectory() as directory:
        cache = Path(directory) / ".cache"
        cache.mkdir()
        legacy = str(cache / "dataplane")
        dedicated = str(cache / "ducknet-lite")
        real_lstat = os.lstat

        def denied(path, *args, **kwargs):
            if os.fspath(path) in (legacy, dedicated):
                raise PermissionError("permission denied")
            return real_lstat(path, *args, **kwargs)

        with patch.object(atomic_io.os, "lstat", side_effect=denied):
            assert atomic_io._legacy_state_needs_selection(legacy) is True

        def denied_dedicated(path, *args, **kwargs):
            if os.fspath(path) == dedicated:
                raise PermissionError("permission denied")
            return real_lstat(path, *args, **kwargs)

        with (patch.dict(os.environ, {"DUCKNET_STATE_DIR": ""}),
              patch.object(atomic_io.os.path, "expanduser", return_value=directory),
              patch.object(atomic_io.os, "lstat", side_effect=denied_dedicated)):
            try:
                atomic_io.default_state_dir()
            except atomic_io.LegacyStateSelectionRequired:
                pass
            else:
                raise AssertionError("inaccessible dedicated state was accepted")


def test_absent_main_recovers_valid_legacy_tmp_but_present_corrupt_refused():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "blocklist.json"
        key = persistent_key(directory)
        payload = {"bans": {}}
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps({"_sv": 1, "_sig": sign_payload(payload, key),
                                   "_payload": payload}), encoding="utf8")
        assert read_signed_json(str(path), key, {}) == ("ok", payload)
        path.write_text("{bad JSON", encoding="ascii")
        assert read_signed_json(str(path), key, {}) == ("tampered", {})
        tmp.unlink()
        path.unlink()
        assert read_signed_json(str(path), key, {}) == ("missing", {})


def test_main_disappearing_after_stat_cannot_load_stale_tmp():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "blocklist.json"
        key = persistent_key(directory)
        active = {"bans": {"198.51.100.9": {"permanent": True}}}
        stale = {"bans": {}}
        for target, payload in ((path, active),
                                (path.with_name(path.name + ".tmp"), stale)):
            target.write_text(json.dumps({"_sv": 1,
                                          "_sig": sign_payload(payload, key),
                                          "_payload": payload}), encoding="utf8")
        real_load = atomic_io._load_json_file

        def disappear(candidate, *args):
            if candidate == str(path):
                raise FileNotFoundError("main vanished after stat")
            return real_load(candidate, *args)

        with patch.object(atomic_io, "_load_json_file", side_effect=disappear):
            assert read_signed_json(str(path), key, {}) == ("tampered", {})


def test_dangling_main_symlink_cannot_load_stale_tmp():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "blocklist.json"
        key = persistent_key(directory)
        stale = {"bans": {}}
        path.with_name(path.name + ".tmp").write_text(
            json.dumps({"_sv": 1, "_sig": sign_payload(stale, key),
                        "_payload": stale}), encoding="utf8")
        try:
            path.symlink_to(Path(directory) / "removed-main.json")
        except (OSError, NotImplementedError):
            raise SkipTest("symlink creation unavailable")
        assert read_signed_json(str(path), key, {}) == ("tampered", {})


def test_highwater_metadata_eacces_cannot_accept_rollback_or_overwrite_history():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "blocklist.json"
        hw = str(path) + ".hw"
        key = persistent_key(directory)
        old = {"bans": {}}
        new = {"bans": {"198.51.100.9": {"permanent": True}}}
        assert signed_state.write_signed_json(str(path), old, key)
        old_main = path.read_bytes()
        assert signed_state.write_signed_json(str(path), new, key)
        path.write_bytes(old_main)
        signed_state._MEM_HW.pop(str(path), None)
        signed_state._MEM_MIN_SV.pop(str(path), None)
        assert read_signed_json(str(path), key, {}) == ("rolled_back", {})
        before_main, before_hw = path.read_bytes(), Path(hw).read_bytes()
        real_lstat, real_open = os.lstat, builtins.open

        def deny_lstat(candidate, *args, **kwargs):
            if os.fspath(candidate) == hw:
                raise PermissionError("highwater metadata denied")
            return real_lstat(candidate, *args, **kwargs)

        def deny_open(candidate, *args, **kwargs):
            if os.fspath(candidate) == hw:
                raise PermissionError("highwater read denied")
            return real_open(candidate, *args, **kwargs)

        with (patch.object(signed_state.os, "lstat", side_effect=deny_lstat),
              patch("builtins.open", side_effect=deny_open)):
            assert signed_state.has_signed_history(str(path), key) is True
            assert read_signed_json(str(path), key, {}) == ("tampered", {})
            status = {}
            assert signed_state.write_signed_json(
                str(path), new, key, status=status,
                expected_fingerprint=signed_state.payload_fingerprint(old)) is False
            assert status["conflict"] is True
        assert path.read_bytes() == before_main
        assert Path(hw).read_bytes() == before_hw
        assert read_signed_json(str(path), key, {}) == ("rolled_back", {})


def test_main_metadata_eacces_cannot_satisfy_missing_cas():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "blocklist.json"
        key = persistent_key(directory)
        old = {"bans": {"198.51.100.9": {"permanent": True}}}
        path.write_text(json.dumps({"_sv": 1, "_sig": sign_payload(old, key),
                                    "_payload": old}), encoding="utf8")
        before = path.read_bytes()
        real_lstat, real_open = os.lstat, builtins.open

        def deny_lstat(candidate, *args, **kwargs):
            if os.fspath(candidate) == str(path):
                raise PermissionError("main metadata denied")
            return real_lstat(candidate, *args, **kwargs)

        def deny_open(candidate, *args, **kwargs):
            if os.fspath(candidate) == str(path):
                raise PermissionError("main read denied")
            return real_open(candidate, *args, **kwargs)

        with (patch.object(signed_state.os, "lstat", side_effect=deny_lstat),
              patch("builtins.open", side_effect=deny_open)):
            status = {}
            assert signed_state.write_signed_json(
                str(path), {"bans": {}}, key, status=status,
                expected_fingerprint=signed_state.MISSING_FINGERPRINT) is False
            assert status["conflict"] is True
        assert path.read_bytes() == before
