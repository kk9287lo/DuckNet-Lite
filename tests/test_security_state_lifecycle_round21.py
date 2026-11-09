"""State-key configuration must distinguish an absent key from an empty one."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
_READ_KEY = (
    "import json,sys\n"
    "from dataplane.engine.core.signed_state import persistent_key\n"
    "try:\n"
    " value=persistent_key(sys.argv[1])\n"
    "except OSError as exc:\n"
    " print(json.dumps({'ok':False,'error':str(exc)}))\n"
    "else:\n"
    " print(json.dumps({'ok':True,'length':len(value)}))\n"
)


def _run(state: Path, value):
    env = os.environ.copy()
    env.update(DUCKNET_STATE_DIR=str(state), HOME=str(state), USERPROFILE=str(state),
               TEMP=str(state), TMP=str(state), PYTHONPATH=str(ROOT),
               PYTHONDONTWRITEBYTECODE="1")
    if value is None:
        env.pop("DUCKNET_STATE_KEY", None)
    else:
        env["DUCKNET_STATE_KEY"] = value
    completed = subprocess.run([sys.executable, "-B", "-c", _READ_KEY, str(state)],
                               cwd=ROOT, env=env, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=6)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_explicit_empty_external_state_key_refuses_before_local_key_creation():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        denied = _run(state, "")
        assert denied["ok"] is False and "DUCKNET_STATE_KEY" in denied["error"], denied
        assert not (state / ".statekey").exists(), "empty external key fell back to a local key"


def test_empty_external_key_never_reuses_existing_local_key_silently():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        assert _run(state, None) == {"ok": True, "length": 32}
        key = state / ".statekey"
        before = key.read_bytes()
        denied = _run(state, "")
        assert denied["ok"] is False and "DUCKNET_STATE_KEY" in denied["error"], denied
        assert key.read_bytes() == before


def test_absent_or_nonempty_external_state_key_preserves_existing_behavior():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        assert _run(state, None) == {"ok": True, "length": 32}
        assert (state / ".statekey").is_file()
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        assert _run(state, "A" * 32) == {"ok": True, "length": 32}
        assert not (state / ".statekey").exists()


def test_short_external_state_key_is_rejected_instead_of_weakly_signing():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        denied = _run(state, "x")
        assert denied["ok"] is False and "DUCKNET_STATE_KEY" in denied["error"], denied
        assert not (state / ".statekey").exists()
        assert not (state / "state.json").exists()


def test_service_short_external_key_refuses_before_listener_and_preserves_state():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        state = Path(directory)
        # A valid legacy signed file must remain untouched when startup
        # refuses the weak external key. Migration requires an offline choice.
        from dataplane.engine.core.signed_state import write_signed_json
        policy = state / "state.json"
        assert write_signed_json(str(policy), {"cfg": {"enabled": True}}, b"x")
        before = {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        code = (
            "import json,sys\n"
            "from dataplane import service\n"
            "try:\n"
            " service.run(backend='127.0.0.1:9',listen=int(sys.argv[1]),"
            "admin_port=0,defaults_on=False)\n"
            "except SystemExit as exc:\n"
            " print(json.dumps({'ok':False,'error':str(exc)}))\n"
            "else:\n"
            " print(json.dumps({'ok':True}))\n"
        )
        env = os.environ.copy()
        env.update(DUCKNET_STATE_DIR=str(state), DUCKNET_STATE_KEY="x",
                   HOME=str(state), USERPROFILE=str(state), TEMP=str(state), TMP=str(state),
                   PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1",
                   PYTHONIOENCODING="utf-8")
        completed = subprocess.run([sys.executable, "-B", "-c", code, str(port)],
                                   cwd=ROOT, env=env, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=8)
        assert completed.returncode == 0, completed.stderr
        outcome = json.loads(completed.stdout)
        assert outcome["ok"] is False and "DUCKNET_STATE_KEY" in outcome["error"], outcome
        with socket.socket() as client:
            client.settimeout(0.2)
            assert client.connect_ex(("127.0.0.1", port)) != 0
        assert {path.name: path.read_bytes() for path in state.iterdir()
                if path.is_file() and path.name in before} == before
        assert not (state / ".statekey").exists()
