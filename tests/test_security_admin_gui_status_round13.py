"""A partial management-state failure must not paint a false healthy GUI."""

import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import SkipTest
from unittest.mock import patch

import dataplane.admin as A
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW


_GUI_PROBE = r"""
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const states=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const start=html.indexOf('async function refresh(){');
const end=html.indexOf(' // 直すべき設定',start);
if(start<0||end<0)throw new Error('dashboard refresh prefix missing');
const refreshPrefix=html.slice(start,end)+'\n}';
async function run(state){
 const elements={};
 const checkbox=()=>({_checked:true,disabled:false,
  get checked(){return this._checked},set checked(v){this._checked=!!v}});
 elements.fw=checkbox();elements.sh=checkbox();
 const ctx={refreshGeneration:0,
  $:id=>elements[id]||(elements[id]={className:'',textContent:'',title:''}),
  tr:s=>s,errText:()=>"State unavailable",guardedFetch:async()=>state};
 vm.createContext(ctx);vm.runInContext(refreshPrefix,ctx);
 let threw=false;
 try{await ctx.refresh()}catch(e){threw=true}
 return {threw,connection:elements.conn.className,
  label:elements.connt.textContent,firewall:elements.fw.checked,
  shield:elements.sh.checked};
}
(async()=>{
 const out={};for(const [name,state] of Object.entries(states))out[name]=await run(state);
 process.stdout.write(JSON.stringify(out));
})().catch(e=>{console.error(e);process.exitCode=1});
"""


def _get(port, path, token=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"X-Token": token} if token else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_status_source_failure_does_not_misreport_persisted_defense_as_healthy_off():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for dashboard execution")
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as state_dir:
        old_fw, old_sh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        admin = A.AdminDashboard(host="127.0.0.1", port=0, token="gui-status-probe",
                                 state_dir=state_dir)
        try:
            assert admin.start()["ok"] is True
            assert FW._FW.enable()["ok"] is True
            saved_acl = Path(state_dir, "acl.json").read_bytes()
            assert FW._FW.is_enabled() is True
            html_status, html = _get(admin.port, "/")
            assert html_status == 200 and b"async function refresh(){" in html
            good_status, good_bytes = _get(admin.port, "/api/state", admin.token)
            with patch.object(FW._FW, "status", side_effect=RuntimeError("fixture failure")):
                fw_status, fw_bytes = _get(admin.port, "/api/state", admin.token)
            with patch.object(ND._SHIELD, "status", side_effect=RuntimeError("fixture failure")):
                sh_status, sh_bytes = _get(admin.port, "/api/state", admin.token)
            real_metrics = ND._SHIELD.metrics
            calls = [0]

            def metrics_failure():
                calls[0] += 1
                if calls[0] == 2:
                    raise RuntimeError("fixture failure")
                return real_metrics()

            with patch.object(ND._SHIELD, "metrics", side_effect=metrics_failure):
                metrics_status, metrics_bytes = _get(admin.port, "/api/state", admin.token)
            admin.edge_guard = SimpleNamespace(metrics=None)
            edge_status, edge_bytes = _get(admin.port, "/api/state", admin.token)
            admin.edge_guard = None
            assert (good_status, fw_status, sh_status, metrics_status, edge_status) == (200,) * 5
            good, bad_fw, bad_sh, bad_metrics, bad_edge = (
                json.loads(x) for x in
                (good_bytes, fw_bytes, sh_bytes, metrics_bytes, edge_bytes))
            assert good["firewall"]["enabled"] is True
            assert bad_fw["firewall"] == {"error": "source unavailable"}
            assert bad_sh["shield"] == {"error": "source unavailable"}
            assert bad_metrics["shield_metrics"] == {"error": "source unavailable"}
            assert bad_edge["edge_metrics"] == {"error": "source unavailable"}
            assert FW._FW.is_enabled() is True
            assert Path(state_dir, "acl.json").read_bytes() == saved_acl
            html_path, state_path = Path(state_dir, "dashboard.html"), Path(state_dir, "states.json")
            html_path.write_bytes(html)
            state_path.write_text(json.dumps({"good": good, "bad_fw": bad_fw, "bad_sh": bad_sh,
                                              "bad_metrics": bad_metrics, "bad_edge": bad_edge,
                                              "missing_metrics": {k: v for k, v in good.items()
                                                                  if k != "shield_metrics"}}),
                                  encoding="utf-8")
            result = subprocess.run([node, "-e", _GUI_PROBE, str(html_path), str(state_path)],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
            shown = json.loads(result.stdout)
            assert shown["good"] == {"threw": False, "connection": "pill ok",
                                     "label": "接続中", "firewall": True, "shield": True}
            assert shown["bad_fw"]["threw"] is False
            assert shown["bad_fw"]["connection"] != "pill ok"
            assert shown["bad_fw"]["firewall"] is True
            assert shown["bad_sh"]["threw"] is False
            assert shown["bad_sh"]["connection"] != "pill ok"
            for name in ("bad_metrics", "bad_edge", "missing_metrics"):
                assert shown[name]["threw"] is False, (name, shown[name])
                assert shown[name]["connection"] != "pill ok", (name, shown[name])
                assert shown[name]["firewall"] is True, (name, shown[name])
        finally:
            admin.stop()
            FW._FW, ND._SHIELD = old_fw, old_sh
