"""Execute dashboard event boundaries with local benign browser fixtures."""
import csv
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import SkipTest

from dataplane import admin


_JS = r"""
const fs=require('fs'),vm=require('vm');
const source=fs.readFileSync(process.argv[2],'utf8');
function take(name){
 const pattern=new RegExp('^(?:async )?function '+name+'\\([^\\n]*\\)\\{[\\s\\S]*?^\\}','m');
 const found=source.match(pattern);if(!found)throw new Error('missing '+name);return found[0];
}
const turn=()=>new Promise(setImmediate);
function context(extra={}){
 const els={};const ctx={Promise,Set,Number,LANG:'ja',sigTestGeneration:0,
  $:id=>els[id]||(els[id]={value:'',textContent:'',innerHTML:'',checked:false,style:{},
   dataset:{},disabled:false,classList:{add(){},remove(){}}}),
  tr:s=>s,esc:s=>String(s),errText:()=> 'HTTP error',toast(){},refresh(){},
  refreshPro(){},refreshSigs(){},isAuthFail:()=>false,markAuthError(){},
  busy(btn,on){if(btn){if(on)btn.dataset.obusy='1';else delete btn.dataset.obusy;}}};
 Object.assign(ctx,extra);vm.createContext(ctx);return {ctx,els};
}
async function signatureRemoval(){
 let fetched=0;const h=context({postT:async()=>({ok:true}),guardedFetch:async()=>{fetched++;return {custom:[]};},
  sigRefreshGeneration:0});
 h.ctx.$('customsigs').querySelector=()=>({innerHTML:''});
 vm.runInContext(take('refreshSigs')+'\n'+take('removeSig'),h.ctx);
 let approved;h.ctx.confirmDialog=()=>new Promise(resolve=>approved=resolve);
 const pending=h.ctx.removeSig('ordinary-rule',null);approved(true);await pending;await turn();await turn();
 return {fetched};
}
async function bulkCases(){
 async function once(name,changeAt){
  let approve;const sent=[],reported=[];
  const h=context({curBans:[{ip:'192.0.2.1'},{ip:'192.0.2.2'}],
   curPending:[{id:'old-a'},{id:'old-b'}],banSel:new Set(),
   confirmDialog:()=>new Promise(resolve=>approve=resolve),
   bulkReport:(fails,n)=>reported.push({failed:fails.length,total:n}),
   post:async(_p,body)=>{sent.push(body);if(changeAt==='during'){
    h.ctx.curBans=[{ip:'192.0.2.3'}];h.ctx.curPending=[{id:'new-c'}];}
    return {ok:true};}});
  vm.runInContext(take(name),h.ctx);const job=h.ctx[name](null);
  if(changeAt==='confirm'){
   h.ctx.curBans=[{ip:'192.0.2.3'}];h.ctx.curPending=[{id:'new-c'}];}
  if(approve)approve(true);await job;return {sent,reported};
 }
 return {unbanConfirm:await once('unbanAll','confirm'),approveConfirm:await once('approveAllPending','confirm'),
  unbanDuring:await once('unbanAll','during'),approveDuring:await once('approveAllPending','during'),
  denyDuring:await once('denyAllPending','during'),benign:await once('approveAllPending','none')};
}
async function selectionCase(){
 const sent=[];const h=context({banSel:new Set(['192.0.2.1','192.0.2.2']),bulkReport(){},
  post:async(_p,body)=>{sent.push(body.ip);h.ctx.banSel.add('192.0.2.3');
   return {ok:body.ip==='192.0.2.1',error:'fixture rejected'};}});
 vm.runInContext(take('unbanSelected'),h.ctx);await h.ctx.unbanSelected(null);
 return {sent,selected:[...h.ctx.banSel].sort()};
}
async function numericCases(){
 const sent=[],toasts=[];const h=context({postT:async(p,b)=>{sent.push({p,b});return {ok:true};},
  toast:(m,k)=>toasts.push([m,k])});
 const start=source.indexOf('$("fw").onchange='),end=source.indexOf('/* チャートの時間範囲',start);
 if(start<0||end<0)throw new Error('numeric controls missing');
 if(source.includes('function saveIntegerConfig('))vm.runInContext(take('saveIntegerConfig'),h.ctx);
 vm.runInContext(source.slice(start,end),h.ctx);
 const ids=['retryaft','subthr','maxconnip','connrateip','maxtotalconn'];
 for(const id of ids)for(const value of ['', '1.5', '-1', '7oops', 'Infinity', '9007199254740993']){
  const el=h.ctx.$(id);el.value=value;await el.onchange({target:el});}
 const invalidSent=sent.length;
 for(const [id,value] of [['retryaft','0'],['subthr','1'],['maxconnip','0'],['connrateip','25'],['maxtotalconn','20000']]){
  const el=h.ctx.$(id);el.value=value;await el.onchange({target:el});}
 return {invalidSent,valid:sent.slice(invalidSent),validationErrors:toasts.length};
}
async function busyCase(){
 let release;let sends=0;const notices=[];
 const h=context({post:async()=>{sends++;return new Promise(resolve=>release=resolve);},
  toast:(m,k)=>notices.push([m,k])});
 vm.runInContext(take('busy')+'\n'+take('postT'),h.ctx);
 const btn=h.ctx.$('save');const first=h.ctx.postT('/api/fixture',{safe:1},btn);
 const second=h.ctx.postT('/api/fixture',{safe:1},btn);
 const during={sends,disabled:btn.disabled};release({ok:true});
 if(sends>1){return {during,leaked:true};}
 await Promise.all([first,second]);return {during,disabled:btn.disabled,leaked:false};
}
async function formCases(){
 async function once(name,changed){
  let reply;const h=context({curPathLimits:[],postT:()=>new Promise(resolve=>reply=resolve)});
  const initial=name==='addSig'?{signame:'first',sigpat:'ordinary'}:{prpath:'/first',prrate:'2',prburst:'4'};
  for(const [id,value]of Object.entries(initial))h.ctx.$(id).value=value;
  vm.runInContext(take('sigWarnHtml')+'\n'+take(name),h.ctx);
  const job=h.ctx[name](null);
  if(changed)for(const id of Object.keys(initial))h.ctx.$(id).value='next';
  reply({ok:true});await job;
  return Object.fromEntries(Object.keys(initial).map(id=>[id,h.ctx.$(id).value]));
 }
 return {sigChanged:await once('addSig',true),pathChanged:await once('addPathLimit',true),
  sigBenign:await once('addSig',false),pathBenign:await once('addPathLimit',false)};
}
async function sigTestCases(){
 const replies=[];const h=context({post:()=>new Promise(resolve=>replies.push(resolve))});
 h.ctx.$('sigpat').value='first';h.ctx.$('sigtestsample').value='sample';
 vm.runInContext(take('sigWarnHtml')+'\n'+take('testSig'),h.ctx);
 const old=h.ctx.testSig(null);h.ctx.$('sigpat').value='second';const fresh=h.ctx.testSig(null);
 replies[1]({ok:true,matches:false});await fresh;const current=h.ctx.$('sigtestresult').innerHTML;
 replies[0]({ok:true,matches:true});await old;return {current,afterOld:h.ctx.$('sigtestresult').innerHTML};
}
function chartCase(){
 const points=[];const canvas={clientWidth:400,width:0,height:0,
  getContext:()=>new Proxy({createLinearGradient:()=>({addColorStop(){}})},
   {get:(o,k)=>k in o?o[k]:(...args)=>{if(k==='moveTo'||k==='lineTo')points.push(args);},set:(o,k,v)=>(o[k]=v,true)})};
 const h=context({devicePixelRatio:1,cssv:()=> '#000000'});const original=h.ctx.$;
 h.ctx.$=id=>id==='chart'?canvas:original(id);vm.runInContext(take('drawChart'),h.ctx);
 h.ctx.drawChart([{t:1,requests:1,block:0},{t:2,requests:2,block:0}]);
 return {points:points.length,allFinite:points.every(p=>p.every(Number.isFinite))};
}
async function responseCases(){
 const result={};const h=context({signedRequest:null});vm.runInContext(take('post')+'\n'+take('guardedFetch'),h.ctx);
 for(const [key,body]of Object.entries({null:null,array:[],string:'value',badOk:{ok:'false'},good:{ok:true}})){
  h.ctx.signedRequest=async()=>({status:200,ok:true,json:async()=>body});
  let getRejected=false;try{await h.ctx.guardedFetch('/api/state');}catch(e){getRejected=true;}
  result[key]={post:await h.ctx.post('/api/fixture',{}),getRejected};
 }
 return result;
}
function csvCase(){const h=context();vm.runInContext(take('toCSV'),h.ctx);
 return {carriage:h.ctx.toCSV([{value:'left\rright'}],['value']),benign:h.ctx.toCSV([{value:'ordinary'}],['value'])};}
function csvSafetyCase(){
 const dangerous=['=1+1','+1+1','-1+1','@1+1',' \t=1+1',' \r\n+1+1',
  '\x00=1+1','\v+1+1','\u00a0=1+1','\u3000＝1+1','＝1+1','＋1+1','－1+1','＠1+1',
  '\tordinary','\rordinary','\nordinary','=1+1;ordinary','=1+1,ordinary','=1+1"ordinary'];
 const ordinary=['ordinary','left;=1+1','left,=1+1','left"right','left\rright','日本語'];
 const rows=[...dangerous,...ordinary,0,-1,42].map(value=>({value}));
 const downloads=[];const exact=[{name:'=1+1',category:'ordinary',pattern:'＋1+1',weight:-1}];
 const h=context({curBans:[],curEvents:[],curCustomSigs:exact,
  downloadFile:(filename,text,mime)=>downloads.push({filename,text,mime})});
 vm.runInContext(take('toCSV')+'\n'+take('exportData'),h.ctx);
 h.ctx.exportData('sigs','json');
 return {dangerous,ordinary,csv:h.ctx.toCSV(rows,['value']),
  semicolon:h.ctx.toCSV([{value:'left;=1+1'}],['value']),exact,downloads};
}
function banRenderingCase(){
 const body={innerHTML:''};const h=context({curBans:[
  {ip:'192.0.2.1',remain_sec:-1,score:10},{ip:'192.0.2.2',remain_sec:30,score:20}],
  banSort:{key:'remain',dir:-1},banSel:new Set(['192.0.2.1','192.0.2.9']),lastBanRows:[],
  document:{querySelectorAll:()=>[]}});
 h.ctx.$('bans').querySelector=()=>body;vm.runInContext(take('renderBans'),h.ctx);h.ctx.renderBans();
 return {html:body.innerHTML,order:h.ctx.lastBanRows.map(b=>b.ip),selected:[...h.ctx.banSel]};
}
function rememberCase(){
 const start=source.indexOf(' const pend=(s.firewall||{}).pending||[];');
 const end=source.indexOf('\n}\n/* BAN中IPテーブル:',start);
 if(start<0||end<0)throw new Error('pending row rendering missing');
 const body={innerHTML:''};const h=context({s:{firewall:{pending:[
  {id:'old-a',ip:'192.0.2.1',zone:'public',ts:1},{id:'new-b',ip:'192.0.2.2',zone:'public',ts:1}]}},
  curPending:[],tm:()=> 'time',document:{querySelectorAll:()=>[
   {dataset:{pid:'old-a'},checked:true},{dataset:{pid:'expired'},checked:true}]}});
 h.ctx.$('fwpending').querySelector=()=>body;vm.runInContext(source.slice(start,end),h.ctx);
 return {remembered:/id="rem_old-a"[^>]*\bchecked\b/.test(body.innerHTML),
  newChecked:/id="rem_new-b"[^>]*\bchecked\b/.test(body.innerHTML)};
}
async function pathNumberCases(){
 const sent=[];const h=context({curPathLimits:[],postT:async(_p,b)=>{sent.push(b);return {ok:true};}});
 vm.runInContext(take('addPathLimit'),h.ctx);
 for(const [rate,burst]of [['Infinity','2'],['2tail','2'],['2','Infinity'],['2','-1'],['2','bad'],['2','0']]){
  h.ctx.$('prpath').value='/ordinary';h.ctx.$('prrate').value=rate;h.ctx.$('prburst').value=burst;
  await h.ctx.addPathLimit(null);}
 const invalidSent=sent.length;
 h.ctx.$('prpath').value='/ordinary';h.ctx.$('prrate').value='0.5';h.ctx.$('prburst').value='';
 await h.ctx.addPathLimit(null);return {invalidSent,valid:sent.slice(invalidSent)};
}
async function toggleCases(){
 const results={};const start=source.indexOf('$("fw").onchange=');
 const end=source.indexOf('/* チャートの時間範囲',start);
 for(const id of ['fw','sh','dlp','dlpact','sech','paranoia','throttle','subnetdef','forceclose','optional']){
  const replies=[],sent=[];const h=context({post:async(p,b)=>{sent.push({p,b});return new Promise(resolve=>replies.push(resolve));}});
  vm.runInContext(take('busy')+'\n'+take('postT')+'\n'+source.slice(start,end),h.ctx);
  const el=h.ctx.$(id);el.checked=true;el.value='2';el.dataset.name='ordinary';
  let change=el.onchange;
  if(id==='optional'){
   const match=source.match(/onchange="(postT\('\/api\/shield\/optional_sig'.*?)">/);
   if(!match)throw new Error('optional signature handler missing');
   change=vm.runInContext('(function(){'+match[1]+'})',h.ctx).bind(el);
  }
  const first=change({target:el});const disabled=el.disabled;
  el.checked=false;el.value='1';const second=change({target:el});
  const calls=sent.length;for(const reply of replies)reply({ok:true});
  await Promise.all([first,second]);await turn();
  results[id]={calls,disabled,released:!el.disabled};
 }
 return results;
}
async function pendingRefreshCase(){
 const cfg={enabled:false,dlp_enabled:false,dlp_action:'audit',sec_headers_enabled:false,
  paranoia:1,throttle_response:false,subnet_defense:false,force_conn_close:false,optional_sigs:{}};
 const state={firewall:{enabled:false,pending:[]},shield:{cfg,optional_signatures:['ordinary'],bans:[]},
  shield_metrics:{},events:[],top:[]};
 const optional={disabled:true};const h=context({refreshGeneration:0,nf:String,tm:String,
  warnText:()=>'',barHTML:()=>'',renderBans(){},renderEvents(){},
  guardedFetch:async p=>p==='/api/state'?state:{},
  document:{activeElement:null,querySelectorAll:q=>q==='#optsigs input'?[optional]:[]}});
 for(const id of ['pathlimits','fwpending'])h.ctx.$(id).querySelector=()=>({innerHTML:''});
 const toggles=['fw','sh','dlp','sech','throttle','subnetdef','forceclose'];
 const values=['dlpact','paranoia','retryaft','subthr','maxconnip','connrateip','maxtotalconn'];
 for(const id of toggles){h.ctx.$(id).disabled=true;h.ctx.$(id).checked=true;}
 for(const id of values){h.ctx.$(id).disabled=true;h.ctx.$(id).value='77';}
 h.ctx.$('optsigs').innerHTML='KEEP';
 const blur=source.match(/^function setIfBlur\([^\n]+$/m);if(!blur)throw new Error('setIfBlur missing');
 vm.runInContext(blur[0]+'\n'+take('refresh'),h.ctx);await h.ctx.refresh();
 return {checks:toggles.map(id=>h.ctx.$(id).checked),values:values.map(id=>h.ctx.$(id).value),
  optional:h.ctx.$('optsigs').innerHTML};
}
async function main(){
 // Capture unhandled promise rejection as evidence instead of terminating Node.
 const unhandled=[];process.on('unhandledRejection',e=>unhandled.push(String(e)));
 const out={signature:await signatureRemoval(),bulk:await bulkCases(),selection:await selectionCase(),
  numeric:await numericCases(),busy:await busyCase(),forms:await formCases(),sigTest:await sigTestCases(),
  chart:chartCase(),responses:await responseCases(),csv:csvCase(),bans:banRenderingCase(),
  remember:rememberCase(),pathNumbers:await pathNumberCases(),toggles:await toggleCases(),
  pendingRefresh:await pendingRefreshCase(),csvSafety:csvSafetyCase()};
 await turn();out.unhandled=unhandled;process.stdout.write(JSON.stringify(out)+'\n');
}
main().catch(e=>{console.error(e&&e.stack||e);process.exitCode=1;});
"""

_RESULT = None


def _cases():
    global _RESULT
    if _RESULT is not None:
        return _RESULT
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for dashboard event checks")
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "dashboard_edges.js"
        script.write_text(_JS, encoding="utf-8")
        result = subprocess.run([node, str(script), str(Path(admin.__file__).resolve())],
                                capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    _RESULT = json.loads(result.stdout.decode("utf-8"))
    return _RESULT


def test_signature_delete_refreshes_list_without_passing_result_as_callback():
    result = _cases()
    assert result["signature"]["fetched"] == 1
    assert not result["unhandled"]


def test_bulk_confirmation_cannot_expand_to_new_unseen_rows():
    result = _cases()["bulk"]
    assert [x["ip"] for x in result["unbanConfirm"]["sent"]] == ["192.0.2.1", "192.0.2.2"]
    assert [x["id"] for x in result["approveConfirm"]["sent"]] == ["old-a", "old-b"]
    assert [x["id"] for x in result["benign"]["sent"]] == ["old-a", "old-b"]


def test_bulk_result_counts_use_the_submitted_snapshot():
    result = _cases()["bulk"]
    for key in ("unbanDuring", "approveDuring", "denyDuring", "benign"):
        assert result[key]["reported"] == [{"failed": 0, "total": 2}], key


def test_bulk_unban_retains_failures_and_new_user_selection():
    result = _cases()["selection"]
    assert result["sent"] == ["192.0.2.1", "192.0.2.2"]
    assert result["selected"] == ["192.0.2.2", "192.0.2.3"]


def test_invalid_integer_controls_cannot_turn_empty_values_into_unlimited():
    result = _cases()["numeric"]
    assert result["invalidSent"] == 0
    assert [list(x["b"].values())[0] for x in result["valid"]] == [0, 1, 0, 25, 20000]
    assert result["validationErrors"] == 30


def test_busy_button_rejects_duplicate_submission_and_finishes_owned_request():
    result = _cases()["busy"]
    assert result == {"during": {"sends": 1, "disabled": True}, "disabled": False, "leaked": False}


def test_successful_form_submit_does_not_erase_later_user_edits():
    result = _cases()["forms"]
    assert set(result["sigChanged"].values()) == {"next"}
    assert set(result["pathChanged"].values()) == {"next"}
    assert set(result["sigBenign"].values()) == {""}
    assert set(result["pathBenign"].values()) == {""}


def test_signature_test_discards_result_for_an_older_pattern():
    result = _cases()["sigTest"]
    assert "不一致" in result["current"]
    assert result["afterOld"] == result["current"]


def test_two_sample_chart_has_finite_coordinates():
    result = _cases()["chart"]
    assert result["points"] > 4 and result["allFinite"]


def test_malformed_signed_results_are_not_presented_as_success():
    result = _cases()["responses"]
    for key in ("null", "array", "string", "badOk"):
        assert result[key]["post"]["ok"] is False
    for key in ("null", "array", "string", "badOk"):
        assert result[key]["getRejected"]
    assert result["good"] == {"post": {"ok": True}, "getRejected": False}


def test_csv_quotes_carriage_return_without_changing_ordinary_values():
    result = _cases()["csv"]
    assert result["carriage"] == 'value\r\n"left\rright"'
    assert result["benign"] == "value\r\nordinary"


def test_permanent_ban_is_labelled_and_sorted_as_unlimited_duration():
    result = _cases()["bans"]
    assert "無期限" in result["html"] and "残-1s" not in result["html"]
    assert "残30s" in result["html"]
    assert result["order"] == ["192.0.2.1", "192.0.2.2"]


def test_expired_ban_selection_does_not_survive_into_a_new_unrelated_ban():
    result = _cases()["bans"]
    assert result["selected"] == ["192.0.2.1"]


def test_pending_remember_checkbox_survives_polling_without_selecting_new_rows():
    assert _cases()["remember"] == {"remembered": True, "newChecked": False}


def test_path_limit_rejects_partial_and_nonfinite_numbers_without_silent_defaults():
    result = _cases()["pathNumbers"]
    assert result["invalidSent"] == 0
    assert result["valid"] == [{"rules": [{"path": "/ordinary", "rate": 0.5}]}]


def test_every_toggle_and_select_owns_one_write_until_it_finishes():
    for name, result in _cases()["toggles"].items():
        assert result == {"calls": 1, "disabled": True, "released": True}, name


def test_polling_preserves_values_and_optional_rows_while_their_write_is_pending():
    result = _cases()["pendingRefresh"]
    assert result["checks"] == [True] * 7
    assert result["values"] == ["77"] * 7
    assert result["optional"] == "KEEP"


def test_csv_treats_formula_prefix_and_csv_controls_as_literal_text():
    result = _cases()["csvSafety"]
    # These are harmless arithmetic strings only; no application ever opens or
    # evaluates them. Check exact export bytes and both common CSV separators.
    raw = result["csv"].encode("utf-8")
    assert b'"\t=1+1"' in raw and b'"\t+1+1"' in raw
    # Python 3.10's reader rejects NUL although the export preserves it as
    # literal text. Substitute a non-delimiter only for parsing, then restore
    # it so the exact raw bytes above and every decoded value below are checked.
    placeholder = "\ufdd0"
    assert placeholder not in result["csv"]
    parseable = result["csv"].replace("\x00", placeholder)
    rows = [[cell.replace(placeholder, "\x00") for cell in row]
            for row in csv.reader(io.StringIO(parseable, newline=""))]
    assert rows[0] == ["value"] and all(len(row) == 1 for row in rows)
    values = [row[0] for row in rows[1:]]
    n = len(result["dangerous"])
    assert values[:n] == ["\t" + value for value in result["dangerous"]]
    assert values[n:] == result["ordinary"] + ["0", "-1", "42"]
    semi_rows = list(csv.reader(io.StringIO(result["semicolon"], newline=""), delimiter=";"))
    assert semi_rows == [["value"], ["left;=1+1"]]


def test_csv_protection_does_not_modify_json_exports():
    result = _cases()["csvSafety"]
    assert len(result["downloads"]) == 1
    download = result["downloads"][0]
    assert download["filename"] == "custom_signatures.json"
    assert download["mime"] == "application/json"
    assert json.loads(download["text"]) == result["exact"]
