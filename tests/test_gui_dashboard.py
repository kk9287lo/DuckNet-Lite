"""Execute the real dashboard JavaScript against small browser controls."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import SkipTest

from dataplane import admin
import test_sweep_ux_dashboard_gui as browser_harness


_JS = r"""
const fs=require('fs'),vm=require('vm'),cryptoNode=require('crypto');
const source=fs.readFileSync(process.argv[2],'utf8');
function take(name){
 const pattern=new RegExp('^(?:async )?function '+name+'\\([^\\n]*\\)\\{[\\s\\S]*?^\\}','m');
 const found=source.match(pattern);
 if(!found)throw new Error('missing dashboard function: '+name);
 return found[0];
}
const turn=()=>new Promise(setImmediate);
function confirmHarness(){
 const els={},listeners=[];
 const document={activeElement:null,
  addEventListener(type,fn){if(type==='keydown')listeners.push(fn);},
  removeEventListener(type,fn){const i=listeners.indexOf(fn);if(i>=0)listeners.splice(i,1);}};
 for(const id of ['confirmOverlay','confirmOk','confirmCancel','confirmMsg','help','stateview'])
  els[id]={style:{},onclick:null,textContent:'',focus(){document.activeElement=this;}};
 els.stateview.inert=false; // confirmation starts after a verified refresh
 const ctx={document,$:id=>els[id],Promise,confirmActive:false,
            cancelActiveConfirm:null};
 vm.createContext(ctx);vm.runInContext(take('confirmDialog'),ctx);
 return {ctx,els,document,listeners,dispatch(key,shiftKey=false){
  for(const fn of [...listeners])fn({key,shiftKey,target:document.activeElement,preventDefault(){}});}};
}
async function confirmCases(){
 let h=confirmHarness(),first='pending',second='pending';
 h.ctx.confirmDialog('first').then(v=>first=v);
 h.ctx.confirmDialog('second').then(v=>second=v);
 await turn();h.els.confirmCancel.onclick();await turn();
 const afterCancel={first,second,listeners:h.listeners.length};
 h.dispatch('Enter');await turn();
 const afterLaterEnter={first,second,listeners:h.listeners.length};
 h=confirmHarness();let keyboard='pending';
 h.ctx.confirmDialog('deny?').then(v=>keyboard=v);
 h.els.confirmCancel.focus();h.dispatch('Enter');await turn();
 const beforeNativeClick=keyboard;
 if(keyboard==='pending')h.els.confirmCancel.onclick();
 await turn();
 return {afterCancel,afterLaterEnter,beforeNativeClick,keyboard};
}
async function confirmFocusCase(){
 let h=confirmHarness();
 const opener={focus(){h.document.activeElement=this;}};
 opener.focus();
 const pending=h.ctx.confirmDialog('deny?');
 const opened=h.document.activeElement===h.els.confirmOk;
 h.dispatch('Tab');const forward=h.document.activeElement===h.els.confirmCancel;
 h.dispatch('Tab');const wrapped=h.document.activeElement===h.els.confirmOk;
 h.dispatch('Tab',true);const reverse=h.document.activeElement===h.els.confirmCancel;
 h.dispatch('Escape');const result=await pending;
 const normal={opened,forward,wrapped,reverse,result,
               restored:h.document.activeElement===opener,listeners:h.listeners.length};
 h=confirmHarness();
 const dynamicOpener={isConnected:true,focus(){if(this.isConnected)h.document.activeElement=this;}};
 dynamicOpener.focus();
 const detachedPending=h.ctx.confirmDialog('delete row?');
 dynamicOpener.isConnected=false;
 h.dispatch('Escape');
 const detachedResult=await detachedPending;
 const detached={result:detachedResult,fallbackFocus:h.document.activeElement===h.els.help};
 return {normal,detached};
}
function helpFocusCase(){
 const start=source.indexOf('/* ヘルプ(');
 const end=source.indexOf('$("lang").textContent=LANG===',start);
 if(start<0||end<0)throw new Error('help handlers missing');
 const els={},listeners=[];
 const document={activeElement:null,
  addEventListener(type,fn){if(type==='keydown')listeners.push(fn);},
  removeEventListener(type,fn){const i=listeners.indexOf(fn);if(i>=0)listeners.splice(i,1);}};
 const element=id=>els[id]||(els[id]={style:{},onclick:null,
  focus(){document.activeElement=this;}});
 const ctx={document,$:element,applyStatic(){}};
 vm.createContext(ctx);vm.runInContext(source.slice(start,end),ctx);
 const dispatch=(key,shiftKey=false)=>{for(const fn of [...listeners])
  fn({key,shiftKey,target:document.activeElement,preventDefault(){}});};
 element('help').focus();element('help').onclick();
 const opened=document.activeElement===element('helpClose');
 dispatch('Tab');const forward=document.activeElement===element('helpClose');
 dispatch('Tab',true);const reverse=document.activeElement===element('helpClose');
 dispatch('Escape');
 return {opened,forward,reverse,closed:element('helpOverlay').style.display==='none',
         restored:document.activeElement===element('help'),listeners:listeners.length};
}
function refreshHarness(){
 const els={},pending=[];let authErrors=0;
 const ctx={refreshGeneration:0,
  $:id=>els[id]||(els[id]={className:'',checked:false,title:'',textContent:'',style:{},innerHTML:''}),
  tr:s=>s,isAuthFail:e=>!!(e&&e.authFail),errText:s=>s,
  markAuthError:()=>{authErrors++;},
  guardedFetch:()=>new Promise((resolve,reject)=>pending.push({resolve,reject}))};
 vm.createContext(ctx);vm.runInContext(take('refresh'),ctx);
 return {ctx,els,pending,authErrors:()=>authErrors};
}
async function refreshCases(){
 const state=enabled=>({firewall:{enabled},shield:{cfg:{enabled}},shield_metrics:{},
  events:[],top:[]});
 let h=refreshHarness();
 const old=h.ctx.refresh(),newer=h.ctx.refresh();
 h.pending[1].resolve(state(true));await newer.catch(()=>{});
 const afterNew=h.els.fw.checked;
 h.pending[0].resolve(state(false));await old.catch(()=>{});
 const afterOld=h.els.fw.checked;
 h=refreshHarness();
 const stale=h.ctx.refresh(),fresh=h.ctx.refresh();
 h.pending[1].resolve(state(true));await fresh.catch(()=>{});
 h.pending[0].reject({authFail:true});await stale.catch(()=>{});
 return {afterNew,afterOld,staleAuthErrors:h.authErrors()};
}
function refreshProHarness(){
 const els={},pending=[],drawn=[];let authErrors=0;
 const element=id=>els[id]||(els[id]={textContent:'',innerHTML:'',
  querySelector:()=>({innerHTML:''})});
 const ctx={refreshProGeneration:0,chartWindow:Infinity,LANG:'ja',
  $:element,tr:s=>s,esc:s=>s,tm:s=>s,
  isAuthFail:e=>!!(e&&e.authFail),markAuthError:()=>{authErrors++;},
  guardedFetch:path=>path==='/api/series'
   ?new Promise((resolve,reject)=>pending.push({resolve,reject}))
   :Promise.resolve(path==='/api/appeals'?{appeals:[]}:path==='/api/apt'?{suspects:[]}:{}),
  drawChart:series=>drawn.push(series.map(x=>x.t).join(',')),drawSpark(){},
  drawMap(){},analysisHTML:()=>'',refreshSigs(){},refreshDeception(){},refreshAudit(){}};
 vm.createContext(ctx);vm.runInContext(take('refreshPro'),ctx);
 return {ctx,pending,drawn,authErrors:()=>authErrors};
}
async function refreshProCases(){
 let h=refreshProHarness();
 const old=h.ctx.refreshPro(),newer=h.ctx.refreshPro();
 h.pending[1].resolve({series:[{t:2}]});await newer.catch(()=>{});
 const afterNew=h.drawn.join('|');
 h.pending[0].resolve({series:[{t:1}]});await old.catch(()=>{});
 const afterOld=h.drawn.join('|');
 h=refreshProHarness();
 const stale=h.ctx.refreshPro(),fresh=h.ctx.refreshPro();
 h.pending[1].resolve({series:[{t:3}]});await fresh.catch(()=>{});
 h.pending[0].reject({authFail:true});await stale.catch(()=>{});
 return {afterNew,afterOld,staleAuthErrors:h.authErrors()};
}
async function guardedCases(){
 const ctx={signedRequest:null};vm.createContext(ctx);
 vm.runInContext(take('guardedFetch'),ctx);
 const result={};
 for(const [status,body] of [[200,{ok:true,data:1}],
                             [500,{ok:false,error:'temporary storage error'}],
                             [401,{ok:false,error:'token required'}]]){
  ctx.signedRequest=async()=>({status,ok:status>=200&&status<300,json:async()=>body});
  try{result[status]={value:await ctx.guardedFetch('/api/state')};}
  catch(e){result[status]={error:true,authFail:!!e.authFail};}
 }
 return result;
}
async function pathCases(){
 const original=[{path:'/old',rate:1,burst:1},{path:'/keep',rate:2,burst:2}];
 async function once(mode){
  let resolveConfirm;const sent=[],toasts=[];
  const ctx={curPathLimits:original.slice(),tr:s=>s,
   confirmDialog:()=>new Promise(resolve=>resolveConfirm=resolve),
   postT:async(path,body)=>{sent.push({path,body});return {ok:true};},
   refresh:()=>{},toast:(message,kind)=>toasts.push([message,kind])};
  vm.createContext(ctx);vm.runInContext(take('removePathLimit'),ctx);
  const pending=ctx.removePathLimit(0,null);
  const added={path:'/new',rate:3,burst:3};
  if(mode==='gone')ctx.curPathLimits=[original[1],added];
  if(mode==='shifted')ctx.curPathLimits=[added,...original];
  resolveConfirm(true);await pending;await turn();
  return {sent,toasts};
 }
 return {unchanged:await once('unchanged'),changed:await once('gone'),
         shifted:await once('shifted')};
}
async function methodsCases(){
 async function once(reply){
  const els={blockmeth:{value:'TRACE,CONNECT'},methoderr:{textContent:''}};
  const ctx={$:id=>els[id],tr:s=>s,refresh:()=>{},
   postT:async()=>reply};
  vm.createContext(ctx);vm.runInContext(take('saveBlockedMethods'),ctx);
  await ctx.saveBlockedMethods(null);await turn();
  return els.methoderr.textContent;
 }
 return {failure:await once({ok:false,error:'network unavailable'}),
         success:await once({ok:true,blocked_methods:['TRACE','CONNECT']}),
         partial:await once({ok:true,blocked_methods:['TRACE']})};
}
function promptCases(){
 const start=source.indexOf('let TOKEN="";'),end=source.indexOf('const H=',start);
 if(start<0||end<0)throw new Error('dashboard token bootstrap missing');
 const bootstrap=source.slice(start,end);
 function once(reply){
  let prompts=0;
  const els={conn:{className:'',title:''},connt:{textContent:''}};
  const ctx={URL,location:{href:'http://127.0.0.1:8081/'},
   history:{replaceState(){}},sessionStorage:{removeItem(){}},
   prompt(){prompts++;if(reply==='throw')throw new Error('prompt unsupported');return reply;},
   $:id=>els[id],tr:s=>s,AUTH_KEY_PROMISE:null,AUTH_PROBLEM:'',errText:s=>s};
  vm.createContext(ctx);
  try{
   const result=vm.runInContext(bootstrap+'\n({token:TOKEN})',ctx);result.prompts=prompts;
   vm.runInContext(take('markAuthError'),ctx);
   if(reply==='throw'){ctx.markAuthError();result.display=els.connt.textContent;}
   return result;
  }catch(e){return {error:String(e)};}
 }
 return {unsupported:once('throw'),success:once('KNOWN_SECRET'),cancel:once(null)};
}
async function edgeDownloadCase(){
 const calls={created:0,revoked:0,clicks:0,appended:0};
 const ctx={Blob:class{},URL:{createObjectURL(){calls.created++;return 'blob:edge';},
  revokeObjectURL(){calls.revoked++;}},
  document:{createElement(){return {click(){calls.clicks++;},remove(){}};},
   body:{appendChild(){calls.appended++;}}},
  setTimeout:fn=>fn(),
  signedRequest:async()=>({status:200,ok:true,text:async()=>"server {}"}),
  markAuthError(){},toast(){},errText:s=>s,AUTH_PROBLEM:''};
 vm.createContext(ctx);
 vm.runInContext(take('downloadFile')+'\n'+take('edge'),ctx);
 await ctx.edge();await ctx.edge();
 return calls;
}
async function subviewCases(){
 async function once(name,route,newData,oldData,read){
  const pending=[],els={};
  const element=id=>els[id]||(els[id]={textContent:'',innerHTML:'',
   querySelector:()=>({innerHTML:''})});
  const ctx={$:element,tr:s=>s,esc:s=>s,tm:s=>s,LANG:'ja',
   curAudit:[],curCustomSigs:[],auditRefreshGeneration:0,
   sigRefreshGeneration:0,deceptionRefreshGeneration:0,
   renderDeceptionTable:data=>{element('deception').textContent=(data.families||[]).join(', ');},
   isAuthFail:()=>false,markAuthError(){},
   guardedFetch:path=>{if(path!==route)throw new Error('wrong route '+path);
    return new Promise((resolve,reject)=>pending.push({resolve,reject}));}};
  vm.createContext(ctx);vm.runInContext(take(name),ctx);
  const old=ctx[name](),newer=ctx[name]();
  pending[1].resolve(newData);await newer;
  const afterNew=read(ctx,els);
  pending[0].resolve(oldData);await old;
  return {afterNew,afterOld:read(ctx,els)};
 }
 return {
  audit:await once('refreshAudit','/api/admin_audit',
   {entries:[{summary:'NEW',ts:1}]},{entries:[{summary:'OLD',ts:1}]},
   ctx=>ctx.curAudit[0].summary),
  sigs:await once('refreshSigs','/api/shield/signatures',
   {builtin:[],custom:[{name:'NEW',pattern:'x'}],custom_active:1},
   {builtin:[],custom:[{name:'OLD',pattern:'x'}],custom_active:1},
   ctx=>ctx.curCustomSigs[0].name),
  deception:await once('refreshDeception','/api/deception',
   {enabled:false,families:['NEW'],family_count:1},
   {enabled:false,families:['OLD'],family_count:1},
   (_ctx,els)=>els.deception.textContent)
 };
}
async function authContextCases(){
 const start=source.indexOf('function authFailure('),end=source.indexOf('const $=id=>',start);
 if(start<0||end<0)throw new Error('signed request source missing');
 const code=source.slice(start,end)+'\n'+take('post')+'\n'+take('markAuthError');
 async function once(changeToken,unauthorized){
  const els={conn:{className:'',title:''},connt:{textContent:''}};
  let pending;
  const ctx={TOKEN:'OLD_FIXTURE_SECRET',AUTH_KEY_PROMISE:null,AUTH_PROBLEM:'',
   PROMPT_UNAVAILABLE:false,AUTH_INSTANCE:'1'.repeat(32),AUTH_ENC:new TextEncoder(),
   H:{'Content-Type':'application/json'},URL,TextDecoder,Uint8Array,TypeError,AbortController,setTimeout,clearTimeout,
   crypto:cryptoNode.webcrypto,location:{href:'http://127.0.0.1:8081/'},
   tr:s=>s,errText:s=>s,$:id=>els[id],
   hex:bytes=>Buffer.from(bytes).toString('hex'),
   fetch:async(_path,options)=>new Promise(resolve=>pending={options,resolve})};
  vm.createContext(ctx);vm.runInContext(code,ctx);
  const job=ctx.post('/api/local-fixture',{safe:true});
  // WebCrypto completes outside the JS event loop. A fixed count of
  // setImmediate turns can finish in a few milliseconds before signing does.
  const deadline=performance.now()+5000;
  while(!pending&&performance.now()<deadline)
   await new Promise(resolve=>setTimeout(resolve,1));
  if(!pending)throw new Error('signed request did not reach fetch');
  if(changeToken){ctx.TOKEN='FRESH_FIXTURE_SECRET';ctx.AUTH_KEY_PROMISE=null;}
  const status=unauthorized?401:200;
  const body=Buffer.from(JSON.stringify(unauthorized?{ok:false}:{ok:true}));
  const nonce=pending.options.headers['X-Admin-Auth-Nonce'];
  const hash=cryptoNode.createHash('sha256').update(body).digest('hex');
  const mac=unauthorized?'':cryptoNode.createHmac('sha256','OLD_FIXTURE_SECRET')
   .update(ctx.AUTH_INSTANCE+'\n'+nonce+'\n'+status+'\n'+hash).digest('hex');
  pending.resolve(new Response(body,{status,headers:{'X-Admin-Response-Mac':mac}}));
  const result=await job;
  return {token:ctx.TOKEN,result};
 }
 return {good:await once(false,false),changed:await once(true,false),
         unauthorized:await once(false,true)};
}
async function main(){
 const out={confirm:await confirmCases(),confirmFocus:await confirmFocusCase(),
  helpFocus:helpFocusCase(),refresh:await refreshCases(),
  refreshPro:await refreshProCases(),guarded:await guardedCases(),
  path:await pathCases(),methods:await methodsCases(),prompt:promptCases(),
  edge:await edgeDownloadCase(),subviews:await subviewCases(),
  authContext:await authContextCases()};
 process.stdout.write(JSON.stringify(out)+'\n');
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
        raise SkipTest("Node.js is unavailable for dashboard JavaScript checks")
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "gui.js"
        script.write_text(_JS, encoding="utf-8")
        result = subprocess.run([node, str(script), str(Path(admin.__file__).resolve())],
                                capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    _RESULT = json.loads(result.stdout.decode("utf-8").strip())
    return _RESULT


def test_confirmation_remains_owned_and_cancel_enter_never_approves():
    result = _cases()["confirm"]
    assert result["afterCancel"] == {"first": False, "second": False, "listeners": 0}
    assert result["afterLaterEnter"] == {"first": False, "second": False, "listeners": 0}
    assert result["beforeNativeClick"] == "pending"
    assert result["keyboard"] is False


def test_help_and_confirmation_keep_keyboard_focus_inside_then_restore_it():
    result = _cases()
    assert result["confirmFocus"]["normal"] == {"opened": True, "forward": True,
                                                  "wrapped": True, "reverse": True,
                                                  "result": False, "restored": True,
                                                  "listeners": 0}
    assert result["confirmFocus"]["detached"] == {"result": False,
                                                    "fallbackFocus": True}
    assert result["helpFocus"] == {"opened": True, "forward": True,
                                   "reverse": True, "closed": True,
                                   "restored": True, "listeners": 0}


def test_newer_refresh_wins_and_stale_auth_error_does_not_clear_session():
    result = _cases()["refresh"]
    assert result == {"afterNew": True, "afterOld": True, "staleAuthErrors": 0}


def test_newer_detail_refresh_wins_and_stale_auth_error_is_ignored():
    result = _cases()["refreshPro"]
    assert result == {"afterNew": "2", "afterOld": "2", "staleAuthErrors": 0}


def test_signed_get_500_is_http_error_while_401_remains_auth_error():
    result = _cases()["guarded"]
    assert result["200"]["value"]["data"] == 1
    assert result["500"] == {"error": True, "authFail": False}
    assert result["401"] == {"error": True, "authFail": True}


def test_confirmed_path_removal_uses_target_not_reused_row_index():
    result = _cases()["path"]
    assert [r["path"] for r in result["unchanged"]["sent"][0]["body"]["rules"]] == ["/keep"]
    assert result["changed"]["sent"] == []
    assert [r["path"] for r in result["shifted"]["sent"][0]["body"]["rules"]] == [
        "/new", "/keep"]


def test_failed_blocked_method_save_does_not_claim_methods_were_ignored():
    result = _cases()["methods"]
    assert "network unavailable" in result["failure"] and "無視" not in result["failure"]
    assert result["success"] == ""
    assert "CONNECT" in result["partial"]


def test_prompt_unavailable_degrades_without_aborting_dashboard_bootstrap():
    result = _cases()["prompt"]
    assert result["unsupported"]["token"] == ""
    assert result["unsupported"]["prompts"] == 0
    assert "認証が必要" in result["unsupported"]["display"]
    assert result["success"] == {"token": "", "prompts": 0}
    assert result["cancel"] == {"token": "", "prompts": 0}


def test_full_dashboard_script_survives_unsupported_prompt():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for dashboard JavaScript checks")
    check = r"""
prompt=function(){throw new Error('prompt unsupported');};
"""
    tail = r"""
(async()=>{
 await new Promise(setImmediate);await new Promise(setImmediate);
 __emit({token:TOKEN,status:__els.connt.textContent,
  helpWired:Object.prototype.hasOwnProperty.call(__els.help,'onclick'),
  langWired:Object.prototype.hasOwnProperty.call(__els.lang,'onclick'),
  requests:__requests.length});
})().catch(e=>{console.error(e&&e.stack||e);process.exitCode=1;});
"""
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "full_gui.js"
        script.write_text(browser_harness._PRELUDE + check + browser_harness._script()
                          + tail, encoding="utf-8")
        result = subprocess.run([node, str(script)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    state = json.loads(result.stdout.decode("ascii").splitlines()[-1])
    assert state["token"] == "" and "認証が必要" in state["status"]
    assert state["helpWired"] and state["langWired"] and state["requests"] == 0


def test_edge_download_releases_each_blob_url_after_click():
    result = _cases()["edge"]
    assert result["created"] == result["revoked"] == result["clicks"] == 2
    assert result["appended"] == 2


def test_independent_panel_refreshes_ignore_out_of_order_old_responses():
    result = _cases()["subviews"]
    for name in ("audit", "sigs"):
        assert result[name] == {"afterNew": "NEW", "afterOld": "NEW"}
    assert "NEW" in result["deception"]["afterNew"]
    assert "NEW" in result["deception"]["afterOld"]
    assert "OLD" not in result["deception"]["afterOld"]


def test_stale_request_cannot_clear_new_admin_token():
    result = _cases()["authContext"]
    assert result["good"]["token"] == "OLD_FIXTURE_SECRET"
    assert result["good"]["result"]["ok"] is True
    assert result["changed"]["token"] == "FRESH_FIXTURE_SECRET"
    assert result["changed"]["result"]["ok"] is False
    assert not result["changed"]["result"].get("authFail")
    assert result["unauthorized"]["token"] == ""
    assert result["unauthorized"]["result"]["authFail"] is True
