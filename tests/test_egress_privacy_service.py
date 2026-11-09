"""Prevent startup log credential copies while preserving interactive bootstrap."""
import contextlib
import http.client
import io
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import Mock, patch
from dataplane import service

_TOKEN = "synthetic-service-log-token-not-real"

def _port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

@contextlib.contextmanager
def _running(configured):
    root = Path(service.__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="private-service-") as directory:
        folder = Path(directory)
        empty_env = folder / "empty-app.env"
        empty_env.write_text("", encoding="utf-8")
        admin, listen = _port(), _port()
        while admin == listen: listen = _port()
        env = dict(os.environ, DUCKNET_STATE_DIR=str(folder/"state"), DUCKNET_OFFLINE="1",
                   DUCKNET_ENV_FILE=str(empty_env),
                   DUCKNET_STDIN_STOP="1", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root))
        env.pop("DUCKNET_CONFIG", None)
        env.pop("DUCKNET_ADMIN_TOKEN", None)
        if configured: env["DUCKNET_ADMIN_TOKEN"] = _TOKEN
        log = folder/"service.log"
        with log.open("wb") as output:
            child = subprocess.Popen([sys.executable,"-m","dataplane","--host","127.0.0.1",
                "--listen",str(listen),"--admin",str(admin),"--admin-host","127.0.0.1",
                "--backend","127.0.0.1:9","--drain-grace","0"],cwd=root,env=env,
                stdin=subprocess.PIPE,stdout=output,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                text=log.read_text(encoding="utf-8",errors="replace")
                # The dashboard URL line mentions 管理トークン before the actual
                # credential-guidance line has been written to redirected logs.
                if " 管理トークン       :" in text: break
                assert child.poll() is None,"isolated service exited before readiness"
                time.sleep(.025)
            else: raise AssertionError("isolated startup log was not ready")
            yield admin,text
        finally:
            if child.poll() is None:
                try:
                    child.stdin.write(b"stop\n");child.stdin.flush();child.wait(timeout=10)
                except (OSError,subprocess.TimeoutExpired):
                    child.kill();child.wait(timeout=5)
            if child.stdin: child.stdin.close()

def _state(port,token=None):
    connection=http.client.HTTPConnection("127.0.0.1",port,timeout=3)
    try:
        connection.request("GET","/api/state",headers={"X-Token":token} if token else {})
        response=connection.getresponse()
        return response.status,response.read()
    finally: connection.close()

def test_configured_admin_token_works_without_being_copied_into_service_logs():
    with _running(True) as (port,text):
        assert _TOKEN not in text,"configured credential copied into startup logs"
        assert "DUCKNET_ADMIN_TOKEN" in text
        status,body=_state(port,_TOKEN)
        assert status==200 and b'"shield"' in body
        assert _state(port)[0]==401 and _state(port,"wrong-synthetic-token")[0]==401

def test_headless_generated_token_is_not_written_into_redirected_output():
    with _running(False) as (port,text):
        assert "DUCKNET_ADMIN_TOKEN" in text,"headless bootstrap needs existing-setting guidance"
        assert not re.search(r"管理トークン\s*:\s*[A-Za-z0-9_-]{20,}",text)
        assert _state(port)[0]==401

def test_interactive_bootstrap_displays_only_a_newly_generated_credential():
    class Terminal(io.StringIO):
        def isatty(self): return True
    for supplied in ("",_TOKEN):
        with tempfile.TemporaryDirectory(prefix="interactive-bootstrap-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            output=Terminal();guard,admin,shield=Mock(),Mock(),Mock()
            guard.start.return_value={"ok":True}
            admin.start.return_value={"ok":True,"url":"http://127.0.0.1:8081/","token":_TOKEN}
            shield.config_warnings.return_value=[]

            def completed_shutdown(*stop_fns, **_kwargs):
                for stop in stop_fns:
                    stop()
                # This fixture mocks the guard. Emulate its final state-owner
                # release so the next iteration can start independently.
                guard._serving_lease.close()
                guard._serving_lease = None
                return {"ok":True}

            with patch.dict(os.environ, {"DUCKNET_STATE_DIR":state}), \
                 patch.object(service,"AsyncEdgeGuard",return_value=guard), \
                 patch.object(service,"AdminDashboard",return_value=admin), \
                 patch.object(service,"net_shield",return_value=shield), \
                 patch.object(service,"state_dir_writable",return_value=True), \
                 patch.object(service,"_block_until_shutdown",side_effect=completed_shutdown), \
                 contextlib.redirect_stdout(output):
                service.run(token=supplied,defaults_on=False,drain_grace=0)
            assert (_TOKEN in output.getvalue()) is (not bool(supplied))
