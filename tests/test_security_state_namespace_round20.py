"""DuckNet's default state must not silently share FalcoNet's legacy files."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import SkipTest


ROOT = Path(__file__).resolve().parents[1]


def _run(home: Path, source: str, *, explicit: str = ""):
    env = os.environ.copy()
    env.pop("DUCKNET_STATE_DIR", None)
    if explicit:
        env["DUCKNET_STATE_DIR"] = explicit
    env.update(HOME=str(home), USERPROFILE=str(home), TEMP=str(home), TMP=str(home),
               PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-c", source], cwd=ROOT, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace", timeout=8)


_READ_DEFAULT = ("import json\n"
                 "from dataplane.engine.core.atomic_io import default_state_dir\n"
                 "try:\n"
                 " print(json.dumps({'ok':True,'path':default_state_dir()}))\n"
                 "except OSError as exc:\n"
                 " print(json.dumps({'ok':False,'error':str(exc)}))\n")


def test_fresh_default_uses_a_dedicated_namespace_and_explicit_override_wins():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        expected = home / ".cache" / "ducknet-lite"
        fresh = _run(home, _READ_DEFAULT)
        assert fresh.returncode == 0, fresh.stderr
        assert json.loads(fresh.stdout) == {"ok": True, "path": str(expected)}
        assert not expected.exists(), "path selection must not mutate state"

        explicit = home / "operator-selected"
        chosen = _run(home, _READ_DEFAULT, explicit=str(explicit))
        assert chosen.returncode == 0, chosen.stderr
        assert json.loads(chosen.stdout) == {"ok": True, "path": str(explicit)}
        assert not explicit.exists()


def test_legacy_signed_state_requires_explicit_choice_before_any_new_state():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        legacy = home / ".cache" / "dataplane"
        legacy.mkdir(parents=True)
        marker = legacy / ".statekey"
        marker.write_bytes(b"fixture-key-not-used")
        old = marker.read_bytes()
        selected = _run(home, _READ_DEFAULT)
        assert selected.returncode == 0, selected.stderr
        result = json.loads(selected.stdout)
        assert result["ok"] is False and "DUCKNET_STATE_DIR" in result["error"], result
        assert marker.read_bytes() == old
        assert not (home / ".cache" / "ducknet-lite").exists()

        chosen = _run(home, _READ_DEFAULT, explicit=str(legacy))
        assert chosen.returncode == 0, chosen.stderr
        assert json.loads(chosen.stdout) == {"ok": True, "path": str(legacy)}


def test_falconet_only_logs_do_not_claim_ducknet_signed_migration():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        legacy = home / ".cache" / "dataplane"
        legacy.mkdir(parents=True)
        for name in ("sensor_log.jsonl", "decisions.jsonl", "txn_log.jsonl"):
            (legacy / name).write_text("{}\n", encoding="ascii")
        result = _run(home, _READ_DEFAULT)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"ok": True,
                                            "path": str(home / ".cache" / "ducknet-lite")}
        assert not (home / ".cache" / "ducknet-lite").exists()


def test_existing_new_directory_does_not_silently_hide_legacy_audit_state():
    from dataplane.engine.core.signed_state import persistent_key, write_signed_json

    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        cache = home / ".cache"
        legacy = cache / "dataplane"
        dedicated = cache / "ducknet-lite"
        legacy.mkdir(parents=True)
        dedicated.mkdir()
        (legacy / "admin_audit.jsonl").write_text("{}\n", encoding="ascii")
        key = persistent_key(str(dedicated))
        assert write_signed_json(str(dedicated / "state.json"),
                                 {"cfg": {"enabled": True}}, key)
        dedicated_state = (dedicated / "state.json").read_bytes()
        result = _run(home, _READ_DEFAULT)
        assert result.returncode == 0, result.stderr
        selected = json.loads(result.stdout)
        assert selected["ok"] is False and "DUCKNET_STATE_DIR" in selected["error"]
        assert (legacy / "admin_audit.jsonl").read_text(encoding="ascii") == "{}\n"
        assert (dedicated / "state.json").read_bytes() == dedicated_state


def test_unknown_legacy_backup_or_directory_requires_explicit_choice():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        legacy = home / ".cache" / "dataplane"
        legacy.mkdir(parents=True)
        (legacy / "sensor_log.jsonl.backup").write_text("{}\n", encoding="ascii")
        first = _run(home, _READ_DEFAULT)
        assert first.returncode == 0 and json.loads(first.stdout)["ok"] is False
        (legacy / "sensor_log.jsonl.backup").unlink()
        (legacy / "txn_log.jsonl.1").mkdir()
        second = _run(home, _READ_DEFAULT)
        assert second.returncode == 0 and json.loads(second.stdout)["ok"] is False


def test_dedicated_default_cannot_alias_the_legacy_directory():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        cache = home / ".cache"
        legacy = cache / "dataplane"
        legacy.mkdir(parents=True)
        (legacy / "sensor_log.jsonl").write_text("{}\n", encoding="ascii")
        dedicated = cache / "ducknet-lite"
        try:
            dedicated.symlink_to(legacy, target_is_directory=True)
        except (OSError, NotImplementedError):
            raise SkipTest("directory symlink creation unavailable")
        selected = _run(home, _READ_DEFAULT)
        assert selected.returncode == 0, selected.stderr
        result = json.loads(selected.stdout)
        assert result["ok"] is False and "DUCKNET_STATE_DIR" in result["error"], result
        assert (legacy / "sensor_log.jsonl").read_text(encoding="ascii") == "{}\n"


def test_dedicated_default_must_be_a_real_directory_if_it_exists():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        cache = home / ".cache"
        cache.mkdir()
        (cache / "ducknet-lite").write_text("not a directory", encoding="ascii")
        selected = _run(home, _READ_DEFAULT)
        assert selected.returncode == 0, selected.stderr
        result = json.loads(selected.stdout)
        assert result["ok"] is False and "DUCKNET_STATE_DIR" in result["error"], result


def test_oversized_legacy_log_directory_requires_explicit_choice():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        legacy = home / ".cache" / "dataplane"
        legacy.mkdir(parents=True)
        for index in range(65):
            (legacy / f"sensor_log.jsonl.{index}").write_text("{}\n", encoding="ascii")
        selected = _run(home, _READ_DEFAULT)
        assert selected.returncode == 0, selected.stderr
        result = json.loads(selected.stdout)
        assert result["ok"] is False and "DUCKNET_STATE_DIR" in result["error"], result


def test_service_refuses_ambiguous_legacy_state_before_singletons_or_listener():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        legacy = home / ".cache" / "dataplane"
        legacy.mkdir(parents=True)
        (legacy / "blocklist.json").write_text("{}", encoding="ascii")
        source = ("import json\n"
                  "from dataplane import service\n"
                  "service.app_firewall=lambda: (_ for _ in ()).throw("
                  "RuntimeError('singleton constructed before state choice'))\n"
                  "try:\n"
                  " service.run(backend='127.0.0.1:1', listen=0, admin_port=0)\n"
                  "except SystemExit as exc:\n"
                  " print(json.dumps({'error':str(exc)}))\n"
                  "else:\n"
                  " print(json.dumps({'error':'service unexpectedly started'}))\n")
        result = _run(home, source)
        assert result.returncode == 0, result.stderr
        assert "DUCKNET_STATE_DIR" in json.loads(result.stdout)["error"]
        assert (legacy / "blocklist.json").read_text(encoding="ascii") == "{}"


def test_tray_shows_state_choice_before_spawning_a_hidden_gateway():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        legacy = home / ".cache" / "dataplane"
        legacy.mkdir(parents=True)
        (legacy / ".statekey").write_bytes(b"fixture")
        source = ("import json\n"
                  "from dataplane.gui import __main__ as gui\n"
                  "shown=[]\n"
                  "gui._gateway_up=lambda *a,**k:False\n"
                  "gui._spawn_gateway=lambda *a,**k:(_ for _ in ()).throw("
                  "RuntimeError('hidden child was spawned'))\n"
                  "gui._msgbox=lambda message,title:shown.append((message,title))\n"
                  "token,child=gui._ensure_gateway('http://127.0.0.1:8081','')\n"
                  "print(json.dumps({'token':token,'child':child is not None,"
                  "'shown':len(shown),'choice':bool(shown and "
                  "'DUCKNET_STATE_DIR' in shown[0][0])}))\n")
        result = _run(home, source)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"token": "", "child": False,
                                            "shown": 1, "choice": True}
