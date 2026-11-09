"""Unreadable or torn audit history must not look like healthy no history."""

import contextlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest
from unittest.mock import patch

import dataplane.admin as A
from dataplane.engine.core import atomic_io as IO
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW


@contextlib.contextmanager
def _admin():
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as state:
        old_fw, old_sh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=state)
        ND._SHIELD = ND.NetShield(state_dir=state)
        admin = A.AdminDashboard(host="127.0.0.1", port=0,
                                 token="audit-read-probe", state_dir=state)
        try:
            assert admin.start()["ok"] is True
            yield admin, Path(state, "admin_audit.jsonl")
        finally:
            admin.stop()
            FW._FW, ND._SHIELD = old_fw, old_sh


def _http(admin, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
    try:
        headers = {"X-Token": admin.token}
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body).encode("utf-8")
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read())
    finally:
        conn.close()


def _seed_one_change(admin, audit_path):
    status, result = _http(admin, "POST", "/api/shield/toggle", {"on": True})
    assert status == 200 and result["ok"] is True, (status, result)
    assert audit_path.is_file() and audit_path.read_bytes().endswith(b"\n")
    status, good = _http(admin, "GET", "/api/admin_audit")
    assert status == 200 and len(good["entries"]) == 1, (status, good)
    return good


def test_audit_read_failure_and_torn_tail_are_not_successful_empty_history():
    with _admin() as (admin, path):
        status, empty = _http(admin, "GET", "/api/admin_audit")
        assert status == 200 and empty == {"entries": []}, (status, empty)
        _seed_one_change(admin, path)
        previous = path.read_bytes()
        with patch.object(IO, "_retry_sharing", side_effect=OSError("injected read failure")):
            status, unavailable = _http(admin, "GET", "/api/admin_audit")
        assert status >= 500 and unavailable.get("ok") is False, (status, unavailable)
        assert path.read_bytes() == previous
        for corrupt in (b'{"ts":', b'{"ts":1,"ts":2}\n', b'{"ts":NaN}\n',
                        b'\n', b'\xff\n'):
            path.write_bytes(corrupt)
            status, torn = _http(admin, "GET", "/api/admin_audit")
            assert status >= 500 and torn.get("ok") is False, (corrupt, status, torn)
            assert path.read_bytes() == corrupt
        with path.open("wb") as stream:
            stream.truncate(A._MAX_AUDIT_READ_BYTES + 1)
        status, too_large = _http(admin, "GET", "/api/admin_audit")
        assert status >= 500 and too_large.get("ok") is False, (status, too_large)


def test_rotated_history_cannot_be_hidden_by_missing_or_empty_active_log():
    with _admin() as (admin, path):
        _seed_one_change(admin, path)
        previous = path.read_bytes()
        assert IO.append_jsonl(str(path), {"row": "new generation"},
                               max_bytes=len(previous) + 1)
        backup = Path(str(path) + ".1")
        assert backup.read_bytes() == previous
        assert path.stat().st_size > 0

        path.unlink()
        missing_status, missing = _http(admin, "GET", "/api/admin_audit")
        path.touch()
        empty_status, empty = _http(admin, "GET", "/api/admin_audit")
        assert missing_status >= 500 and missing.get("ok") is False, (missing_status, missing)
        assert empty_status >= 500 and empty.get("ok") is False, (empty_status, empty)
        assert backup.read_bytes() == previous and path.read_bytes() == b""


_GUI_PROBE = r"""
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const samples=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const found=html.match(/^async function refreshAudit\([^\n]*\)\{[\s\S]*?^\}/m);
if(!found)throw new Error('served refreshAudit missing');
async function show(sample){
 const elements={};
 const get=id=>elements[id]||(elements[id]=(()=>{
  let displayed='';return {get textContent(){return displayed},set textContent(v){displayed=String(v)},
   get innerHTML(){return displayed},set innerHTML(v){displayed=String(v)}};})());
 const ctx={auditRefreshGeneration:0,$:get,tr:s=>s,esc:s=>s,tm:String,
  isAuthFail:()=>false,markAuthError(){},guardedFetch:async()=>{
   if(sample.status>=500)throw new Error('unavailable');return sample.body;}};
 vm.createContext(ctx);vm.runInContext(found[0],ctx);
 await ctx.refreshAudit();
 return {log:get('auditlog').innerHTML,meta:get('auditmeta').textContent};
}
(async()=>{
 const out={};for(const [name,sample] of Object.entries(samples))out[name]=await show(sample);
 process.stdout.write(JSON.stringify(out));
})().catch(e=>{console.error(e);process.exitCode=1});
"""


def test_dashboard_audit_panel_marks_unavailable_instead_of_no_changes():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js unavailable for dashboard execution")
    with _admin() as (admin, path):
        page = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
        try:
            page.request("GET", "/")
            response = page.getresponse()
            assert response.status == 200
            html = response.read()
        finally:
            page.close()
        good = _seed_one_change(admin, path)
        with patch.object(IO, "_retry_sharing", side_effect=OSError("injected read failure")):
            status, bad = _http(admin, "GET", "/api/admin_audit")
        previous = path.read_bytes()
        assert IO.append_jsonl(str(path), {"row": "new generation"},
                               max_bytes=len(previous) + 1)
        assert Path(str(path) + ".1").read_bytes() == previous
        path.write_bytes(b"")
        rotated_status, rotated = _http(admin, "GET", "/api/admin_audit")
        state = Path(path.parent, "audit-states.json")
        pagefile = Path(path.parent, "dashboard.html")
        state.write_text(json.dumps({"good": {"status": 200, "body": good},
                                     "bad": {"status": status, "body": bad},
                                     "rotated": {"status": rotated_status,
                                                 "body": rotated}}),
                         encoding="utf-8")
        pagefile.write_bytes(html)
        run = subprocess.run([node, "-e", _GUI_PROBE, str(pagefile), str(state)],
                             capture_output=True, timeout=10)
        assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
        shown = json.loads(run.stdout)
        assert "変更履歴なし" not in shown["good"]["log"]
        assert "状態取得不可" in shown["bad"]["log"], shown
        assert "状態取得不可" in shown["rotated"]["log"], shown
