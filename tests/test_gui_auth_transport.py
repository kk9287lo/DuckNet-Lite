"""Bound unverified admin bodies before HMAC and release timed-out requests."""

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest

from dataplane import admin


_JS = r'''
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const source=fs.readFileSync(process.argv[2],'utf8');
function take(name){const match=source.match(new RegExp('^(?:async )?function '+name+'\\([^\\n]*\\)\\{[\\s\\S]*?^\\}','m'));if(!match)throw Error('missing '+name);return match[0];}
const LIMIT=16*1024*1024,TOKEN='SYNTHETIC_TRANSPORT_KEY',INSTANCE='a'.repeat(32);
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function context(){
 const durations=[];
 const ctx={URL,TextEncoder,TextDecoder,Uint8Array,AbortController,Response,Promise,Number,Array,JSON,Error,TypeError,
  crypto:crypto.webcrypto,location:{href:'http://127.0.0.1:8081/'},
  TOKEN,AUTH_INSTANCE:INSTANCE,AUTH_KEY_PROMISE:null,AUTH_PROBLEM:'',authGeneration:0,
  AUTH_ENC:new TextEncoder(),H:{'Content-Type':'application/json'},errText:k=>String(k),
  hex:b=>Buffer.from(b).toString('hex'),setTimeout:(fn,ms)=>{durations.push(ms);return setTimeout(fn,Math.min(ms,60));},clearTimeout,
 };
 vm.createContext(ctx);
 const helper=source.includes('async function readAdminResponse(')?take('readAdminResponse')+'\n':'';
 vm.runInContext(helper+take('sameHex')+'\n'+take('authFailure')+'\n'+take('signedRequest'),ctx);
 return {ctx,durations};
}
function response(text,options,status=200){
 const body=Buffer.from(text),nonce=options.headers['X-Admin-Auth-Nonce'];
 const sha=crypto.createHash('sha256').update(body).digest('hex');
 const mac=crypto.createHmac('sha256',TOKEN).update([INSTANCE,nonce,String(status),sha].join('\n')).digest('hex');
 return new Response(body,{status,headers:{'Content-Length':String(body.length),'X-Admin-Response-Mac':mac}});
}
async function overflow(declared){
 const h=context(),chunk=new Uint8Array(65536);let emitted=0,cancelled=false,released=false,signal;
 h.ctx.fetch=async(_path,options)=>{
  signal=options.signal;
  return {status:200,ok:true,headers:{get:name=>name==='Content-Length'&&declared?String(LIMIT+1):null},
   body:{getReader:()=>({read:async()=>{emitted+=chunk.length;return {value:chunk,done:false};},cancel:async()=>{cancelled=true;},releaseLock:()=>released=true})},
   arrayBuffer:async()=>{emitted=LIMIT+chunk.length;return new ArrayBuffer(emitted);}};
 };
 let rejected=false;try{await h.ctx.signedRequest('GET','/api/state');}catch(e){rejected=true;}
 return {emitted,cancelled,released,rejected,aborted:!!(signal&&signal.aborted)};
}
async function timeout(kind,method){
 const h=context();let signal,read=false;
 const pending=options=>new Promise((_resolve,reject)=>{if(options.signal){
  if(options.signal.aborted){reject(new Error('aborted'));return;}
  options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});}});
 h.ctx.fetch=async(_path,options)=>{
  signal=options.signal;
  if(kind==='fetch')return pending(options);
  return {status:200,ok:true,headers:{get:()=>null},
   body:{getReader:()=>({read:()=>{read=true;return pending(options);},cancel:async()=>{},releaseLock(){}})},
   arrayBuffer:()=>{read=true;return pending(options);}};
 };
 let settled=false,rejected=false;
 h.ctx.signedRequest(method,'/api/state',method==='POST'?'{}':undefined).then(()=>settled=true,()=>{settled=true;rejected=true;});
 await wait(180);
 return {settled,rejected,read,aborted:!!(signal&&signal.aborted),durations:h.durations};
}
async function normal(){
 const h=context(),requests=[];
 h.ctx.fetch=async(path,options)=>{
  requests.push({path,options});
  return response(path==='/api/edge'?'# safe edge configuration\n':JSON.stringify({ok:true,value:'safe'}),options);
 };
 const get=await h.ctx.signedRequest('GET','/api/state');
 const post=await h.ctx.signedRequest('POST','/api/shield/config','{"enabled":true}');
 const edge=await h.ctx.signedRequest('GET','/api/edge');
 const results={get:await get.json(),post:await post.json(),edge:await edge.text()};
 results.requests=requests.map(({path,options})=>({path,method:options.method,body:options.body,
  nonce:options.headers['X-Admin-Auth-Nonce'],bodyHash:options.headers['X-Admin-Auth-Body'],
  rawSecret:JSON.stringify(options).includes(TOKEN),aborted:!!(options.signal&&options.signal.aborted),
  redirect:options.redirect,credentials:options.credentials}));
 return results;
}
async function staleFailure(){
 const h=context();let rejectRequest;
 h.ctx.fetch=()=>new Promise((_resolve,reject)=>rejectRequest=reject);
 const job=h.ctx.signedRequest('GET','/api/state').then(()=>({accepted:true}),e=>({stale:!!e.staleToken,authFail:!!e.authFail}));
 for(let i=0;i<100&&!rejectRequest;i++)await wait(2);
 if(!rejectRequest)throw Error('request did not start');
 h.ctx.authGeneration++;h.ctx.TOKEN=TOKEN;h.ctx.AUTH_KEY_PROMISE=null;
 rejectRequest(new TypeError('old connection failed'));const outcome=await job;
 return {...outcome,token:h.ctx.TOKEN,problem:h.ctx.AUTH_PROBLEM};
}
(async()=>console.log(JSON.stringify({declared:await overflow(true),streamed:await overflow(false),
 fetchTimeout:await timeout('fetch','GET'),bodyTimeout:await timeout('body','POST'),
 normal:await normal(),stale:await staleFailure()})))().catch(e=>{console.error(e);process.exitCode=1;});
'''


def _execute(script):
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is required for admin transport execution")
    with tempfile.TemporaryDirectory(prefix="ducknet-auth-transport-", dir=os.environ.get("DUCKNET_STATE_DIR")) as folder:
        base = Path(folder)
        source, runner = base / "dashboard.js", base / "transport.cjs"
        source.write_text(script, encoding="utf-8")
        runner.write_text(_JS, encoding="utf-8")
        result = subprocess.run([node, str(runner), str(source)], capture_output=True,
                                text=True, encoding="utf-8", timeout=10)
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout)


def _from_admin_file(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8-sig"))
    value = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "_HTML" for target in node.targets))
    return ast.literal_eval(value).split("<script>", 1)[1].split("</script>", 1)[0]


_RESULT = None


def _result():
    global _RESULT
    if _RESULT is None:
        _RESULT = _execute(admin._HTML.split("<script>", 1)[1].split("</script>", 1)[0])
    return _RESULT


def test_declared_unverified_body_overflow_is_rejected_before_read_and_closed():
    row = _result()["declared"]
    assert row["rejected"] is True and row["emitted"] == 0 and row["aborted"] is True, row


def test_streamed_unverified_body_overflow_stops_within_one_chunk_and_cancels():
    row = _result()["streamed"]
    assert row["rejected"] is True and row["cancelled"] is True and row["released"] is True, row
    assert 16 * 1024 * 1024 < row["emitted"] <= 16 * 1024 * 1024 + 65536
    assert row["aborted"] is True


def test_hanging_fetch_and_body_are_aborted_by_distinct_total_deadlines():
    result = _result()
    for key, deadline in (("fetchTimeout", 10000), ("bodyTimeout", 30000)):
        row = result[key]
        assert row["settled"] is True and row["rejected"] is True and row["aborted"] is True, row
        assert row["durations"] == [deadline]
    assert result["bodyTimeout"]["read"] is True


def test_bounded_signed_get_post_and_edge_text_preserve_exact_payloads():
    row = _result()["normal"]
    assert row["get"] == row["post"] == {"ok": True, "value": "safe"}
    assert row["edge"] == "# safe edge configuration\n"
    requests = row["requests"]
    assert [item["method"] for item in requests] == ["GET", "POST", "GET"]
    assert requests[1]["body"] == '{"enabled":true}'
    assert len({item["nonce"] for item in requests}) == 3
    assert all(item["rawSecret"] is False and item["aborted"] is True for item in requests)
    assert all(item["redirect"] == "error" and item["credentials"] == "omit" for item in requests)


def test_old_epoch_transport_failure_cannot_turn_new_same_token_into_auth_failure():
    row = _result()["stale"]
    assert row == {"stale": True, "authFail": False, "token": "SYNTHETIC_TRANSPORT_KEY", "problem": ""}
