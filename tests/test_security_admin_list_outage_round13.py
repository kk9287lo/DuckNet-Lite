"""Failed dashboard list sources must not look like healthy empty lists."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest
from unittest.mock import patch

import dataplane.admin as A
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from test_security_admin_gui_status_round13 import _get


_GUI_PROBE = r"""
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const states=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const found=html.match(/^async function refresh\([^\n]*\)\{[\s\S]*?^\}/m);
if(!found)throw new Error('served refresh function missing');
async function show(state){
 const els={};
 const element=id=>els[id]||(els[id]=(()=>{
  let shown='';return {className:'',title:'',style:{},disabled:false,checked:true,value:'',
   get textContent(){return shown},set textContent(x){shown=String(x)},
   get innerHTML(){return shown},set innerHTML(x){shown=String(x)},
   querySelector:()=>({innerHTML:''})};})());
 element('leaks').textContent='PRIOR_LEAK';
 element('events').textContent='PRIOR_EVENTS';
 element('top').textContent='PRIOR_TOP';
 const ctx={refreshGeneration:0,LANG:'ja',$:element,tr:s=>s,esc:s=>String(s),
  errText:()=> 'HTTP error',
  nf:String,tm:String,warnText:()=>'',barHTML:()=>'',renderBans(){},renderEvents(){},
  setIfBlur(){},document:{activeElement:null,querySelectorAll:()=>[]},
  guardedFetch:async p=>p==='/api/state'?state:{}};
 vm.createContext(ctx);vm.runInContext(found[0],ctx);
 let threw=false;try{await ctx.refresh()}catch(e){threw=String(e)}
 return {threw,connection:element('conn').className,label:element('connt').textContent,
  leaks:element('leaks').textContent,events:element('events').textContent,
  top:element('top').textContent,fw:element('fw').checked,sh:element('sh').checked};
}
(async()=>{
 const out={};for(const [name,state] of Object.entries(states))out[name]=await show(state);
 process.stdout.write(JSON.stringify(out));
})().catch(e=>{console.error(e);process.exitCode=1});
"""


def test_event_and_top_source_errors_are_visible_without_false_empty_panels():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for dashboard execution")
    base = os.environ["DUCKNET_STATE_DIR"]
    os.makedirs(base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as state_dir:
        old_fw, old_sh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        admin = A.AdminDashboard(host="127.0.0.1", port=0,
                                 token="list-source-probe", state_dir=state_dir)
        try:
            assert FW._FW.enable()["ok"]
            assert ND._SHIELD.set_config(enabled=True, dlp_enabled=True)["ok"]
            assert admin.start()["ok"]
            html_status, html = _get(admin.port, "/")
            assert html_status == 200
            good_status, good_raw = _get(admin.port, "/api/state", admin.token)
            with patch.object(ND._SHIELD, "events", side_effect=RuntimeError("outage")):
                events_status, events_raw = _get(admin.port, "/api/state", admin.token)
            with patch.object(ND._SHIELD, "top_talkers", side_effect=RuntimeError("outage")):
                top_status, top_raw = _get(admin.port, "/api/state", admin.token)
            assert (good_status, events_status, top_status) == (200, 200, 200)
            states = {"good": json.loads(good_raw),
                      "events_out": json.loads(events_raw),
                      "top_out": json.loads(top_raw)}
            assert states["good"]["events"] == []
            assert states["good"]["top"] == []
            html_path = Path(state_dir, "dashboard.html")
            state_path = Path(state_dir, "states.json")
            html_path.write_bytes(html)
            state_path.write_text(json.dumps(states), encoding="utf-8")
            run = subprocess.run([node, "-e", _GUI_PROBE, str(html_path), str(state_path)],
                                 capture_output=True, timeout=15)
            assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
            shown = json.loads(run.stdout)
            assert shown["good"]["threw"] is False, shown["good"]
            assert shown["good"]["connection"] == "pill ok", shown["good"]
            assert "漏洩なし" in shown["good"]["leaks"], shown["good"]
            for name, key, panel in (("events_out", "events", "leaks"),
                                     ("top_out", "top", "top")):
                assert states[name][key] == {"error": "source unavailable"}, states[name]
                assert shown[name]["threw"] is False, shown[name]
                assert shown[name]["connection"] == "pill bad", shown[name]
                assert shown[name]["label"] == "状態取得不可", shown[name]
                assert shown[name][panel] == "状態取得不可", shown[name]
                assert shown[name]["fw"] is True and shown[name]["sh"] is True
        finally:
            admin.stop()
            FW._FW, ND._SHIELD = old_fw, old_sh
