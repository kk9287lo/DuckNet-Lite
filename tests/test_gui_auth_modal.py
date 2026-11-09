"""Execute masked admin unlock, retry and instance changes without persisting secrets."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest

from dataplane import admin
from dataplane.engine.lifeform.pipeline import _DEFAULTS
from test_sweep_admin_ui import _Admin
import test_sweep_ux_dashboard_gui as dashboard


_JS = r'''
const pause=require('node:timers/promises').setTimeout;
const __keys=[];
document.addEventListener=(kind,fn)=>{if(kind==='keydown')__keys.push(fn);};
const __get=document.getElementById.bind(document);
document.getElementById=id=>{const el=__get(id);el.focus=()=>{document.activeElement=el;};return el;};
'''

_CASES = r'''
(async()=>{
 const out={},key='AUTH_MODAL_SYNTHETIC_SECRET';
 let instance='a'.repeat(32),serverKey=key,fake=false,duplicate=false,large=false;
 const state={firewall:{enabled:true,policy:{loopback:'allow',private:'allow',public:'allow'},rules:[]},
  shield:{cfg:__config,config_revision:'c'.repeat(64)},shield_metrics:{},events:[],top:[]};
 const requests=[];
 const reply=(path,opt)=>{
  const headers=opt.headers||{},nonce=headers['X-Admin-Auth-Nonce']||'';
  if(path==='/')return new Response(large?'x'.repeat(2097153):
   'let AUTH_INSTANCE="'+instance+'";\n'+(duplicate?'let AUTH_INSTANCE="'+instance+'";\n':''),
   {status:200,headers:{'Content-Type':'text/html; charset=utf-8'}});
  const digest=__nodeCrypto.createHash('sha256').update(opt.body||'').digest('hex');
  const message=[instance,opt.method||'GET',path,headers['X-Admin-Auth-Time'],nonce,digest].join('\n');
  const valid=headers['X-Admin-Auth-Instance']===instance&&headers['X-Admin-Auth-Mac']===
   __nodeCrypto.createHmac('sha256',serverKey).update(message).digest('hex');
  if(!valid)return new Response('{"ok":false,"error":"token required"}',{status:401});
  const body=JSON.stringify(path==='/api/state'?state:{});
  const sha=__nodeCrypto.createHash('sha256').update(body).digest('hex');
  const mac=__nodeCrypto.createHmac('sha256',serverKey).update([instance,nonce,'200',sha].join('\n')).digest('hex');
  return new Response(body,{status:200,headers:{'Content-Type':'application/json',
   'X-Admin-Response-Mac':fake?'0'.repeat(64):mac}});
 };
 fetch=async(path,opt={})=>{requests.push({path,opt});return reply(path,opt);};
 out.initial={token:TOKEN,prompts:__prompts.length,visible:__els.adminAuthOverlay.style.display,
  inert:__els.stateview.inert,requests:__requests.length,stored:__store['ducknet-admin-token']||null};
 const unlock=async value=>{$('adminTokenInput').value=value;await submitAdminAuth({preventDefault(){}});};
 await unlock(key);
 out.success={token:TOKEN,visible:$('adminAuthOverlay').style.display,input:$('adminTokenInput').value,
  pending:authSubmitPending,disabled:$('adminUnlock').disabled,raw:JSON.stringify(requests).includes(key)};
 settingsDirty.add('private_paths');lockDashboard();
 out.lock={token:TOKEN,visible:$('adminAuthOverlay').style.display,inert:$('stateview').inert,dirty:[...settingsDirty]};
 await unlock('WRONG_SYNTHETIC_SECRET');
 out.wrong={token:TOKEN,input:$('adminTokenInput').value,visible:$('adminAuthOverlay').style.display};
 await unlock(key);out.retry={token:TOKEN,visible:$('adminAuthOverlay').style.display};
 lockDashboard();instance='b'.repeat(32);await unlock(key);
 out.restart={token:TOKEN,instance:AUTH_INSTANCE,visible:$('adminAuthOverlay').style.display,
  publicReads:requests.filter(r=>r.path==='/').length};
 lockDashboard();fake=true;await unlock(key);fake=false;
 out.fake={token:TOKEN,visible:$('adminAuthOverlay').style.display};
 instance='d'.repeat(32);duplicate=true;await unlock(key);duplicate=false;
 out.duplicate={token:TOKEN,instance:AUTH_INSTANCE,visible:$('adminAuthOverlay').style.display};
 large=true;let bounded=false;try{await fetchAdminInstance();}catch(_e){bounded=true;}large=false;
 out.bounded=bounded;
 const before=requests.length;location.href='http://192.0.2.10:8081/';await unlock(key);
 out.insecure={token:TOKEN,sent:requests.length-before};location.href='http://127.0.0.1:8081/';
 instance='b'.repeat(32);await unlock(key);
 const regular=fetch;let release,oldSignal;
 fetch=async(path,opt={})=>{if(path==='/api/state'&&!release)return new Promise(resolve=>{oldSignal=opt.signal;release=()=>resolve(reply(path,opt));});return regular(path,opt);};
 const pending=signedRequest('GET','/api/state').then(()=>({accepted:true}),e=>({stale:!!e.staleToken}));
 for(let i=0;i<1000&&!release;i++)await pause(2);
 if(!release)throw new Error('delayed authenticated request did not start');
 lockDashboard();const canceled=oldSignal.aborted;await unlock(key);release();out.stale={...(await pending),token:TOKEN,canceled};fetch=regular;
 lockDashboard();$('adminTokenInput').value='UNSUBMITTED_SYNTHETIC_SECRET';
 for(const handler of __keys)handler({key:'Escape',preventDefault(){}});
 $('adminTokenInput').focus();for(const handler of __keys)handler({key:'Tab',preventDefault(){}});
 const forward=document.activeElement===$('adminUnlock');
 for(const handler of __keys)handler({key:'Tab',shiftKey:true,preventDefault(){}});
 out.focus={cleared:$('adminTokenInput').value,forward,back:document.activeElement===$('adminTokenInput')};
 out.noStorage={reads:__storageReads,writes:__storageWrites};
 out.publicRequests=requests.filter(r=>r.path==='/').map(r=>r.opt);
 __emit(out);
})().catch(e=>{console.error(e&&e.stack||e);process.exitCode=1;});
'''

_RESULT = None


def _result():
    global _RESULT
    if _RESULT is not None:
        return _RESULT
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js unavailable for real dashboard authentication execution")
    with tempfile.TemporaryDirectory(prefix="ducknet-auth-modal-", dir=os.environ.get("DUCKNET_STATE_DIR")) as folder:
        script = Path(folder) / "auth.js"
        script.write_text(dashboard._PRELUDE + _JS + dashboard._script()
                          + "\nconst __config=" + json.dumps(_DEFAULTS) + ";\n" + _CASES, encoding="utf-8")
        result = subprocess.run([node, str(script)], capture_output=True, timeout=35)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-3500:]
    _RESULT = json.loads(result.stdout.decode("ascii").splitlines()[-1])
    return _RESULT


def test_real_dashboard_starts_locked_without_prompt_or_credential_requests():
    result = _result()["initial"]
    assert result == {"token": "", "prompts": 0, "visible": "flex", "inert": True,
                      "requests": 0, "stored": None}


def test_masked_unlock_uses_signed_requests_and_clears_the_password_field():
    result = _result()["success"]
    assert result["token"] == "AUTH_MODAL_SYNTHETIC_SECRET"
    assert result["visible"] == "none" and result["input"] == ""
    assert result["pending"] is False and result["disabled"] is False and result["raw"] is False


def test_manual_lock_and_failed_retry_preserve_drafts_without_retaining_credentials():
    result = _result()
    assert result["lock"] == {"token": "", "visible": "flex", "inert": True, "dirty": ["private_paths"]}
    assert result["wrong"] == {"token": "", "input": "", "visible": "flex"}
    assert result["retry"]["visible"] == "none"


def test_gateway_restart_can_be_reauthenticated_without_a_page_reload():
    result = _result()["restart"]
    assert result["token"] == "AUTH_MODAL_SYNTHETIC_SECRET"
    assert result["instance"] == "b" * 32 and result["visible"] == "none"
    assert result["publicReads"] >= 2


def test_fake_duplicate_and_oversized_instance_responses_fail_closed():
    result = _result()
    assert result["fake"] == {"token": "", "visible": "flex"}
    assert result["duplicate"] == {"token": "", "instance": "b" * 32, "visible": "flex"}
    assert result["bounded"] is True


def test_untrusted_http_and_old_same_token_requests_cannot_unlock_or_clear_a_new_session():
    result = _result()
    assert result["insecure"] == {"token": "", "sent": 0}
    assert result["stale"] == {"stale": True, "token": "AUTH_MODAL_SYNTHETIC_SECRET", "canceled": True}
    assert result["noStorage"] == {"reads": 0, "writes": 0}
    assert all(request.get("redirect") == "error" and request.get("credentials") == "omit"
               and not request.get("headers") for request in result["publicRequests"])


def test_locked_dialog_keeps_keyboard_focus_and_escape_erases_only_unsubmitted_input():
    assert _result()["focus"] == {"cleared": "", "forward": True, "back": True}


def test_real_html_password_entry_is_masked_and_not_an_automatic_form_parameter():
    with _Admin() as app:
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{app.port}/", timeout=5) as response:
            html = response.read().decode("utf-8")
    import re
    control = re.search(r'<input id="adminTokenInput"[^>]+>', html).group(0)
    assert 'type="password"' in control and 'autocomplete="current-password"' in control
    assert " name=" not in control and "prompt(" not in html


def test_served_dashboard_unlocks_and_retries_against_the_real_signed_http_server():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js unavailable for dashboard HTTP execution")
    import urllib.request
    with _Admin() as app, tempfile.TemporaryDirectory(prefix="ducknet-auth-wire-", dir=os.environ.get("DUCKNET_STATE_DIR")) as folder:
        base = f"http://127.0.0.1:{app.port}"
        with urllib.request.urlopen(base + "/", timeout=5) as response:
            page = response.read().decode("utf-8")
        source = page.split("<script>", 1)[1].split("</script>", 1)[0]
        code = r'''
const vm=require('node:vm'),nativeFetch=globalThis.fetch,calls=[];
const ctx={require,URL,TextEncoder,TextDecoder,AbortController,Response,Uint8Array,console};
vm.createContext(ctx);vm.runInContext(PRELUDE+'\nlocation.href='+JSON.stringify(BASE+'/')+';\n'+SOURCE,ctx);
ctx.fetch=async(path,options={})=>{calls.push({path,options});return nativeFetch(new URL(path,BASE),options);};
(async()=>{
 const initial=await vm.runInContext('({token:TOKEN,requests:__requests.length,visible:$("adminAuthOverlay").style.display})',ctx);
 ctx.candidate=KEY;await vm.runInContext('$("adminTokenInput").value=candidate;submitAdminAuth()',ctx);
 const good=vm.runInContext('({token:TOKEN,visible:$("adminAuthOverlay").style.display,inert:$("stateview").inert})',ctx);
 await vm.runInContext('lockDashboard();$("adminTokenInput").value="BAD_SYNTHETIC_TOKEN";submitAdminAuth()',ctx);
 const bad=vm.runInContext('({token:TOKEN,visible:$("adminAuthOverlay").style.display})',ctx);
 await vm.runInContext('$("adminTokenInput").value=candidate;submitAdminAuth()',ctx);
 const retry=vm.runInContext('({token:TOKEN,visible:$("adminAuthOverlay").style.display})',ctx);
 console.log(JSON.stringify({initial,good,bad,retry,raw:JSON.stringify(calls).includes(KEY),
  signed:calls.some(c=>c.options.headers&&c.options.headers['X-Admin-Auth-Mac'])}));
})().catch(e=>{console.error(e&&e.stack||e);process.exitCode=1;});
'''
        script = Path(folder) / "wire.js"
        script.write_text("const PRELUDE=" + json.dumps(dashboard._PRELUDE)
                          + ",SOURCE=" + json.dumps(source) + ",BASE=" + json.dumps(base)
                          + ",KEY=" + json.dumps(app.token) + ";\n" + code, encoding="utf-8")
        completed = subprocess.run([node, str(script)], capture_output=True, timeout=35)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")[-3000:]
    result = json.loads(completed.stdout.decode("utf-8").splitlines()[-1])
    assert result["initial"] == {"token": "", "requests": 0, "visible": "flex"}
    assert result["good"] == {"token": app.token, "visible": "none", "inert": False}
    assert result["bad"] == {"token": "", "visible": "flex"}
    assert result["retry"] == {"token": app.token, "visible": "none"}
    assert result["signed"] and not result["raw"]
