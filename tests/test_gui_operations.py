"""Run existing firewall/event operations through the actual dashboard code."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest

from dataplane import admin
from test_sweep_admin_ui import _Admin


_JS = r'''
const fs=require('fs'),vm=require('vm');
const source=fs.readFileSync(process.argv[2],'utf8');
function take(name){const found=source.match(new RegExp('^(?:async )?function '+name+'\\([^\\n]*\\)\\{[\\s\\S]*?^\\}','m'));if(!found)throw Error('missing '+name);return found[0];}
const els={},sent=[],downloads=[];
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ctx={console,Promise,Set,JSON,Number,String,Object,Array,Map,
 $:id=>els[id]||(els[id]={value:'',textContent:'',innerHTML:'',style:{},dataset:{},disabled:false,
 querySelector:()=>({innerHTML:''}),classList:{add(){},remove(){}}}),
 tr:s=>s,esc,tm:s=>String(s),sev:()=> 'warn',nf:s=>String(s),errText:()=> 'HTTP error',
 postT:async(p,b)=>{sent.push({p,b});return {ok:true};},confirmDialog:async()=>true,
 refresh:async()=>{},refreshPro:async()=>{},toast(){},busy(){},isAuthFail:()=>false,markAuthError(){},
 document:{querySelectorAll:()=>[],getElementById:()=>null},
 curBans:[],curEvents:[],curFirewallRules:[],curFirewallPolicy:{},
 downloadFile:(name,text,mime)=>downloads.push({name,text,mime})};
vm.createContext(ctx);
const turn=()=>new Promise(setImmediate);
async function main(){
 const result={};
 vm.runInContext(take('toggleNode'),ctx);
 if(source.includes('function banFromEvent('))vm.runInContext(take('banFromEvent'),ctx);
 if(source.includes('function runNodeAction('))vm.runInContext(take('runNodeAction'),ctx);
 ctx.nodeActionsPending=new Set();
 await ctx.toggleNode('192.0.2.8',false);await turn();
 await ctx.toggleNode('192.0.2.8',true);await turn();result.node=sent.splice(0);
 ctx.curEvents=[{ts:1,ip:'192.0.2.8',kind:'audit',reason:'boundary marker <img src=x>',signature:'sig-boundary',rule:'r-one',score:42,would:'block',stage:'body',extra:{safe:'value'}}];
 vm.runInContext(take('renderEvents'),ctx);
 ctx.$('eventsearch').value='boundary marker';ctx.renderEvents();
 result.event={html:ctx.$('events').innerHTML,meta:ctx.$('eventsmeta').textContent};
 vm.runInContext(take('toCSV')+'\n'+take('exportData'),ctx);
 ctx.exportData('events','csv');ctx.exportData('events','json');result.downloads=downloads;
 if(source.includes('function renderFirewallSnapshot(')){
  vm.runInContext(take('renderFirewallSnapshot')+'\n'+take('renderFirewallRules')+'\n'+take('removeFirewallRule')+'\n'+take('setFirewallPolicy'),ctx);
  ctx.renderFirewallSnapshot({policy:{loopback:'allow',private:'prompt',public:'deny'},rules:[{net:'192.0.2.8/32',action:'deny',note:'<img src=x>'}]});
  result.acl={html:ctx.$('aclrows').innerHTML,private:ctx.$('zone_private').value};
  await ctx.removeFirewallRule('192.0.2.8/32',null);
  ctx.$('zone_private').value='deny';await ctx.setFirewallPolicy('private',ctx.$('zone_private'));result.acl.sent=sent.splice(0);
 }
 if(source.includes('function clusterMutationAllowed(')){
  vm.runInContext(take('clusterMutationAllowed'),ctx);ctx.clusterTelemetryPartial=true;ctx.clusterMutationPending=false;
  ctx.confirmDialog=async()=>false;result.clusterCancelled=await ctx.clusterMutationAllowed('/api/firewall/rule',{});
  result.clusterRead=await ctx.clusterMutationAllowed('/api/shield/sig_test',{});
 }
 if(source.includes('function refreshEvents(')){
  vm.runInContext(take('refreshEvents'),ctx);ctx.eventsRefreshGeneration=0;ctx.clusterTelemetryPartial=false;ctx.$('eventsearch').value='';
  const paths=[];ctx.guardedFetch=async p=>{paths.push(p);return {events:Array.from({length:100},(_,i)=>({ts:i,ip:'192.0.2.8',kind:'audit',reason:'kept-'+i}))};};
  await ctx.refreshEvents();result.eventFetch={paths,count:ctx.curEvents.length,meta:ctx.$('eventsmeta').textContent};
  ctx.guardedFetch=async()=>{throw Error('unavailable');};await ctx.refreshEvents();result.eventFailureCount=ctx.curEvents.length;
  const replies=[];ctx.guardedFetch=()=>new Promise(resolve=>replies.push(resolve));
  const old=ctx.refreshEvents(),fresh=ctx.refreshEvents();replies[1]({events:[{ts:2,kind:'fresh'}]});await fresh;
  replies[0]({events:[{ts:1,kind:'old'}]});await old;result.eventFreshKind=ctx.curEvents[0].kind;
 }
 if(source.includes('function setTelemetryAvailability(')){
  const panels={};ctx.document.createElement=()=>({className:'',textContent:'',hidden:false});
  for(const id of ['chart','netmap','events','bans','top','apt','analysis','appeals']){
   const body={hidden:false},panel={note:null,querySelector:s=>s==='.pbody'?body:panel.note,appendChild:n=>panel.note=n};
   panels[id]={body,panel};ctx.$(id).closest=()=>panel;
  }
  vm.runInContext(take('setTelemetryAvailability'),ctx);ctx.setTelemetryAvailability(true);
  result.clusterPanels=Object.values(panels).every(p=>p.body.hidden&&p.panel.note.hidden===false&&p.panel.note.textContent);
  ctx.setTelemetryAvailability(false);result.singlePanels=Object.values(panels).every(p=>p.body.hidden===false&&p.panel.note.hidden);
 }
 if(source.includes('function runNodeAction(')){
  sent.length=0;ctx.confirmDialog=async()=>false;await ctx.toggleNode('192.0.2.10',false);result.cancelledNodeCount=sent.length;
  let approve;ctx.confirmDialog=()=>new Promise(resolve=>approve=resolve);
  const first=ctx.toggleNode('192.0.2.10',false);await ctx.toggleNode('192.0.2.10',false);approve(true);await first;
  result.duplicateNodeCount=sent.length;sent.length=0;
  const net='192.0.2.8/32';ctx.curFirewallRules=[{net,action:'deny'}];
  const removal=ctx.removeFirewallRule(net,null);ctx.curFirewallRules=[{net,action:'allow'}];approve(true);await removal;result.changedRulePosts=sent.length;
 }
 if(source.includes('function clusterMutationAllowed(')){
  vm.runInContext(take('post'),ctx);let calls=0;
  ctx.signedRequest=async()=>{calls++;return {status:200,ok:true,json:async()=>({ok:true,cluster_downgraded:true})};};
  ctx.clusterTelemetryPartial=true;ctx.confirmDialog=async()=>false;
  result.cancelledPost=await ctx.post('/api/shield/config',{mode:'audit'});result.cancelledPostCalls=calls;
  ctx.confirmDialog=async()=>true;result.confirmedPost=await ctx.post('/api/shield/config',{mode:'audit'});
  result.confirmedPostCalls=calls;result.partialAfterPost=ctx.clusterTelemetryPartial;
 }
 result.bulkCancelCounts={};
 for(const name of ['unbanSelected','unbanAll','approveAllPending','denyAllPending']){
  ctx.curBans=[{ip:'192.0.2.1'},{ip:'192.0.2.2'}];ctx.banSel=new Set(['192.0.2.1','192.0.2.2']);ctx.curPending=[{id:'first'},{id:'second'}];
  let calls=0;ctx.post=async()=>{calls++;return {ok:false,cancelled:true};};ctx.confirmDialog=async()=>true;
  vm.runInContext(take(name),ctx);await ctx[name](null);result.bulkCancelCounts[name]=calls;
 }
 console.log(JSON.stringify(result));
}main().catch(e=>{console.error(e);process.exitCode=1;});
'''


def _runtime():
    if not shutil.which("node"):
        raise SkipTest("Node.js is required to execute the dashboard")
    with tempfile.TemporaryDirectory() as name:
        base = Path(name)
        page = base / "dashboard.js"
        page.write_text(admin._HTML.split("<script>", 1)[1].split("</script>", 1)[0], encoding="utf-8")
        runner = base / "operations.cjs"
        runner.write_text(_JS, encoding="utf-8")
        proc = subprocess.run(["node", str(runner), str(page)], capture_output=True,
                              text=True, encoding="utf-8", timeout=20)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)


def test_network_node_ban_and_unban_use_the_same_existing_subsystem():
    result = _runtime()
    assert [row["p"] for row in result["node"]] == ["/api/shield/ban", "/api/shield/unban"], result
    assert all(row["b"] == {"ip": "192.0.2.8"} for row in result["node"])


def test_events_search_show_and_export_all_detection_details_without_xss():
    result = _runtime()
    html = result["event"]["html"]
    assert "sig-boundary" in html and "r-one" in html and "would" in html, result
    assert "&lt;img src=x&gt;" in html and "<img src=x>" not in html
    assert "42" in html and "<details" in html and "stage" in html
    csv = result["downloads"][0]["text"]
    assert all(key in csv.splitlines()[0].split(",") for key in ("reason", "signature", "rule", "score", "would", "stage", "extra"))
    assert "boundary marker" in csv and "safe" in csv
    assert json.loads(result["downloads"][1]["text"])[0]["extra"] == {"safe": "value"}


def test_acl_list_delete_zone_policy_and_cluster_warning_run_in_browser_code():
    result = _runtime()
    assert result.get("acl", {}).get("private") == "prompt", result
    assert "192.0.2.8/32" in result["acl"]["html"] and "&lt;img" in result["acl"]["html"]
    assert result["acl"]["sent"] == [
        {"p": "/api/firewall/rule", "b": {"op": "remove", "net": "192.0.2.8/32"}},
        {"p": "/api/firewall/policy", "b": {"zone": "private", "action": "deny"}},
    ]
    assert result["clusterCancelled"] is False and result["clusterRead"] is True


def test_event_fetch_uses_existing_hundred_event_api_and_rejects_old_refresh():
    result = _runtime()
    assert result["eventFetch"]["paths"] == ["/api/shield/events"]
    assert result["eventFetch"]["count"] == 100 and "100/100" in result["eventFetch"]["meta"]
    assert result["eventFailureCount"] == 0 and result["eventFreshKind"] == "fresh"


def test_cluster_panels_are_explicitly_hidden_and_can_recover():
    result = _runtime()
    assert result["clusterPanels"] is True and result["singlePanels"] is True


def test_cancel_duplicate_node_click_and_changed_acl_do_not_mutate():
    result = _runtime()
    assert result["cancelledNodeCount"] == 0 and result["duplicateNodeCount"] == 1
    assert result["changedRulePosts"] == 0


def test_cluster_warning_runs_before_signed_mutation_and_cancel_sends_nothing():
    result = _runtime()
    assert result["cancelledPost"]["ok"] is False and result["cancelledPost"]["cancelled"] is True
    assert result["cancelledPostCalls"] == 0
    assert result["confirmedPost"]["ok"] is True and result["confirmedPostCalls"] == 1
    assert result["partialAfterPost"] is False


def test_cancelled_cluster_warning_stops_the_whole_bulk_operation():
    result = _runtime()
    assert result["bulkCancelCounts"] == {
        "unbanSelected": 1, "unbanAll": 1, "approveAllPending": 1, "denyAllPending": 1,
    }


def test_existing_http_acl_policy_events_and_ban_operations_are_reversible():
    with _Admin() as app:
        for zone, action in (("loopback", "allow"), ("private", "prompt"), ("public", "deny")):
            code, data = app.post("/api/firewall/policy", {"zone": zone, "action": action})
            assert code == 200 and data["ok"] is True
        code, data = app.post("/api/firewall/rule", {"net": "192.0.2.8", "action": "deny"})
        assert code == 200 and data["ok"] is True
        assert any(row["net"] in ("192.0.2.8", "192.0.2.8/32") for row in app.get("/api/state")["firewall"]["rules"])
        code, data = app.post("/api/firewall/rule", {"op": "remove", "net": "192.0.2.8/32"})
        assert code == 200 and data["ok"] is True and app.get("/api/state")["firewall"]["rules"] == []
        code, data = app.post("/api/firewall/policy", {"zone": "public", "action": "not-valid"})
        assert code == 400 and data["ok"] is False
        assert app.get("/api/state")["firewall"]["policy"]["public"] == "deny"
        for path in ("/api/shield/ban", "/api/shield/unban"):
            code, data = app.post(path, {"ip": "192.0.2.8"})
            assert code == 200 and data["ok"] is True
        for i in range(120):
            app.sh._event("192.0.2.8", "audit", {"reason": "body boundary", "signature": "safe-rule", "score": i, "would": "block"})
        events = app.get("/api/shield/events")["events"]
        assert len(events) == 100 and events[-1]["score"] == 119
        assert events[-1]["signature"] == "safe-rule" and events[-1]["would"] == "block"
