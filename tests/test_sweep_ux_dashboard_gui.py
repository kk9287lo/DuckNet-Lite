"""
test_sweep_ux_dashboard_gui.py — 運用者に見せる表示から「JSON の垂れ流し」と「生の例外」をなくす(Lite)。
====================================================================================
· ダッシュボードの「詳細分析」パネルは /api/analysis の JSON を JSON.stringify でそのまま
  <pre> へ流していた。見出し付きの節(アクション別・ゾーン別・上位シグネチャ・イベント種別・
  BAN 数)に描き直し、値は必ず esc() を通す。
· ダッシュボードの送信失敗は「TypeError: Failed to fetch」や 401 の {"error":"token required"} が
  そのままトーストに出ていた(Lite の post() は例外を素通しし、一括操作は途中で黙って止まった)。
  何が起きたか+次に何をするかの平文にする。エッジ設定の DL は 401 の JSON 本文を設定ファイル
  として保存していた。
入力は普通の文字列と無害な目印(a'b<c)だけを使う。
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from unittest import SkipTest

from dataplane import admin as A

_MARK = "a'b<c"
_MARK_ESC = "a&#39;b&lt;c"
_INSTANCE = "a" * 32


def _script() -> str:
    page = A._HTML
    i = page.index("<script>") + len("<script>")
    return page[i:page.index("</script>", i)].replace("__AUTH_INSTANCE__", _INSTANCE)


# ── 静的な確認 ─────────────────────────────────────────────────────────
def test_t1_analysis_panel_is_not_a_json_dump():
    """詳細分析パネルが API の JSON を JSON.stringify でそのまま <pre> に流していた。"""
    js = _script()
    code = re.sub(r"/\*.*?\*/", "", js, flags=re.S)          # コメント中の言及は数えない
    code = re.sub(r"(?m)^\s*//.*$", "", code)
    # Configuration editors, inspection of individual event attributes and
    # explicit exports intentionally serialize JSON. Scope this regression
    # to the analysis display that previously dumped the entire API object.
    assert '<pre class="code" id="analysis">' not in A._HTML
    assert 'id="analysis"' in A._HTML
    m = re.search(r"\nfunction analysisHTML\(an\)\{(.*?)\n\}", js, re.S)
    assert m, "詳細分析の描画関数 analysisHTML() が無い"
    assert "JSON.stringify" not in m.group(1), "詳細分析をJSONのまま表示している"
    assert "esc(" in m.group(1) and "tr(" in m.group(1)
    assert re.search(r'\$\("analysis"\)\.innerHTML=analysisHTML\(', js)


# ── node でスクリプト全体を動かす ─────────────────────────────────────
# ブラウザの代わりに最小限の DOM を用意する。要素は id ごとに1つ作り、書き込みを覚えておく。
_PRELUDE = r"""
var __els={},__downloads=[],__toasts=[],__routes={},__requests=[];
var __nodeCrypto=require("crypto");globalThis.crypto=__nodeCrypto.webcrypto;
var __instance="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
var __store={"ducknet-admin-token":"OLD_STORED_SECRET"},__history=[],__prompts=[];
var __storageReads=0,__storageWrites=0,__storageRemoves=0;
var location={href:"http://127.0.0.1:8081/?mode=dark&token=OLD_URL_TOKEN"};
var history={replaceState(_a,_b,url){__history.push(url);location.href="http://127.0.0.1:8081"+url;}};
var sessionStorage={getItem(k){__storageReads++;return __store[k]||null;},
 setItem(k,v){__storageWrites++;__store[k]=String(v);},
 removeItem(k){__storageRemoves++;delete __store[k];}};
function prompt(message){__prompts.push(message);return __prompts.length===1?"KNOWN_SECRET":"MANUAL_SECRET";}
function __mk(id){
 const t={id:id||"",style:{},dataset:{},children:[],
  classList:{add(){},remove(){},toggle(){},contains(){return false}},
  innerHTML:"",textContent:"",value:"",checked:false,title:"",className:"",disabled:false,
  nodeType:1,lastChild:null,firstChild:null,clientWidth:1000,width:0,height:0};
 return new Proxy(t,{get(o,p){if(p in o)return o[p];if(typeof p==="symbol"||p==="then")return undefined;
  return function(){return __mk();};},set(o,p,v){o[p]=v;return true;}});
}
var document={getElementById(id){return __els[id]||(__els[id]=__mk(id));},
 querySelectorAll(){return [];},querySelector(){return __mk();},createElement(){return __mk();},
 addEventListener(){},removeEventListener(){},documentElement:__mk("html"),body:__mk("body"),
 activeElement:null};
var localStorage={getItem(){return null;},setItem(){}};
function matchMedia(){return {matches:false};}
function getComputedStyle(){return {getPropertyValue(){return "";}};}
var devicePixelRatio=1;
function requestAnimationFrame(){}
function setInterval(){return 0;}
function setTimeout(){return 0;}
function clearTimeout(){}
function addEventListener(){}
URL.createObjectURL=function(b){__downloads.push(b);return "blob:x";};
URL.revokeObjectURL=function(){};
async function fetch(p,opt){
 __requests.push({path:p,headers:{...((opt&&opt.headers)||{})}});
 const r=__routes[p];
 if(!r)throw new TypeError("Failed to fetch");
 const raw=Buffer.from(r.body,"utf8"),nonce=(opt&&opt.headers||{})["X-Admin-Auth-Nonce"]||"";
 const hash=__nodeCrypto.createHash("sha256").update(Buffer.from(r.signedBody||r.body,"utf8")).digest("hex");
 const mac=(r.status===401||r.fake)?"":__nodeCrypto.createHmac("sha256","KNOWN_SECRET")
  .update(__instance+"\n"+nonce+"\n"+(r.signedStatus||r.status)+"\n"+hash).digest("hex");
 return new Response(raw,{status:r.status,headers:{"X-Admin-Response-Mac":mac,"Content-Type":"application/json"}});
}
function __emit(o){
 process.stdout.write(JSON.stringify(o).replace(/[\u007f-\uffff]/g,
  c=>"\\u"+c.charCodeAt(0).toString(16).padStart(4,"0"))+"\n");
}
"""

_HARNESS = r"""
(async()=>{
 const out={};
 out.initiallyLocked={token:TOKEN,requests:__requests.length,prompts:__prompts.length};
 __routes["/api/state"]={status:200,body:'{"ok":true}'};
 document.getElementById("adminTokenInput").value="KNOWN_SECRET";
 await submitAdminAuth({preventDefault(){}});delete __routes["/api/state"];
 // 節ごとに独立して走らせる(1か所の失敗で他の確認まで道連れにしない)
 const T=async(name,fn)=>{try{out[name]=await fn();}catch(e){out[name+"_err"]=String(e&&e.stack||e);}};
 // WebCrypto runs on a worker pool; a fixed number of event-loop turns does
 // not mean the bootstrap request completed under concurrent test load.
 const pause=require("node:timers/promises").setTimeout;
 for(let i=0;i<1000&&!__requests.some(r=>r.path==="/api/state"&&
      r.headers["X-Admin-Auth-Mac"]);i++)await pause(5);
 await T("bootstrap",()=>({url:__history[0],stored:__store["ducknet-admin-token"]||null,
  memory:TOKEN,
  storageReads:__storageReads,storageWrites:__storageWrites,storageRemoves:__storageRemoves,
  hasMac:!!(__requests.find(r=>r.path==="/api/state")||{}).headers?.["X-Admin-Auth-Mac"],
  raw:(__requests.find(r=>r.path==="/api/state")||{}).headers?.["X-Token"]||null,
  leaked:JSON.stringify(__requests).includes("KNOWN_SECRET"),
  prompts:__prompts.length}));
 const AN=__input.analysis;
 await T("ja",()=>{LANG="ja";return analysisHTML(AN);});
 await T("empty",()=>analysisHTML({}));
 await T("en",()=>{LANG="en";try{return analysisHTML(AN);}finally{LANG="ja";}});
 await T("panel",async()=>{
  __routes["/api/analysis"]={status:200,body:JSON.stringify(AN)};
  try{await refreshPro();}finally{delete __routes["/api/analysis"];}
  return {html:document.getElementById("analysis").innerHTML,
          text:document.getElementById("analysis").textContent};});
 const P="/api/shield/ban";
 const R=async(route,lang)=>{TOKEN="KNOWN_SECRET";AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
  if(route)__routes[P]=route;else delete __routes[P];
  LANG=lang||"ja";try{return await post(P,{ip:"x"});}finally{LANG="ja";delete __routes[P];}};
 await T("net",()=>R(null));
 await T("auth",()=>R({status:401,body:'{"ok":false,"error":"token required"}'}));
 await T("authClear",()=>({stored:__store["ducknet-admin-token"]||null,
  memory:TOKEN,header:H["X-Token"]||null}));
 await T("reloadPrompt",()=>{
  const vm=require("node:vm");
  const context={URL,crypto:__nodeCrypto.webcrypto,TextEncoder,TextDecoder,
   location:{href:"http://127.0.0.1:8081/"},sessionStorage,prompt,
   history:{replaceState(){throw new Error("unexpected URL rewrite")}}};
  return vm.runInNewContext(__boot+"\n({token:TOKEN,header:H['X-Token']||null})",context);
 });
 await T("bad",()=>R({status:502,body:"<html>bad gateway</html>"}));
 await T("e500",()=>R({status:500,body:'{"ok":false,"error":"Traceback KeyError"}'}));
 await T("val",()=>R({status:200,body:JSON.stringify({ok:false,error:"invalid ip "+__input.mark})}));
 await T("fakeSuccess",()=>R({status:200,body:'{"ok":true}',fake:true}));
 await T("fakeBody",()=>R({status:200,body:'{"ok":true}',signedBody:'{"ok":false}'}));
 await T("fakeStatus",()=>R({status:200,body:'{"ok":true}',signedStatus:403}));
 await T("insecure",async()=>{TOKEN="KNOWN_SECRET";AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
  const before=__requests.length,saved=location.href;location.href="http://192.0.2.1:8081/";
  try{return {result:await post(P,{ip:"x"}),sent:__requests.length-before};}
  finally{location.href=saved;}});
 await T("noCrypto",async()=>{TOKEN="KNOWN_SECRET";AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
  const before=__requests.length,saved=Object.getOwnPropertyDescriptor(globalThis,"crypto");
  Object.defineProperty(globalThis,"crypto",{configurable:true,value:undefined});
  try{return {result:await post(P,{ip:"x"}),sent:__requests.length-before};}
  finally{Object.defineProperty(globalThis,"crypto",saved);}});
 await T("e400",()=>R({status:400,body:'{"ok":false,"error":"\'level\' is required (1-4)"}'}));
 await T("net_en",()=>R(null,"en"));
 await T("auth_en",()=>R({status:401,body:'{"ok":false,"error":"token required"}'},"en"));
 toast=function(m,k){__toasts.push([String(m),k]);};
 await T("toastNet",async()=>{TOKEN="KNOWN_SECRET";AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
  __toasts.length=0;await postT(P,{ip:"x"},null,"ok","BANに失敗");return __toasts.splice(0);});
 const ED="/api/edge";
 const E=async(route)=>{TOKEN="KNOWN_SECRET";AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
  __toasts.length=0;const n0=__downloads.length;
  if(route)__routes[ED]=route;else delete __routes[ED];
  try{await edge();}finally{delete __routes[ED];}
  return {downloads:__downloads.length-n0,toasts:__toasts.splice(0)};};
 await T("edge401",()=>E({status:401,body:'{"ok":false,"error":"token required"}'}));
 await T("edgeNet",()=>E(null));
 await T("edgeOk",()=>E({status:200,body:"server {}"}));
 await T("bulk",async()=>{TOKEN="KNOWN_SECRET";AUTH_KEY_PROMISE=null;AUTH_PROBLEM="";
  __toasts.length=0;banSel=new Set(["192.0.2.1","192.0.2.2"]);
  __routes["/api/shield/unban"]={status:200,body:'{"ok":false,"error":"not banned"}'};
  try{await unbanSelected(null);}finally{delete __routes["/api/shield/unban"];}
  return __toasts.splice(0);});
 __emit(out);
})().catch(e=>__emit({fatal:String(e&&e.stack||e)}));
"""

_ANALYSIS = {
    "actions": {"requests": 120, "allow": 98, "throttle": 10, "block": 12, "dlp_leak": 1},
    "by_zone": {"public": 70, "private": 50, _MARK: 3},
    "top_signatures": [["sqli", 7], [_MARK, 2]],
    "event_kinds": {"block": 4, _MARK: 1},
    "active_bans": 3,
    "top_talkers": [{"ip": "192.0.2.9"}],
    "ts": 1.0,
}


def _run_dashboard():
    node = shutil.which("node")
    if not node:
        raise SkipTest("node が無い環境")
    data = {"analysis": _ANALYSIS, "mark": _MARK}
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "dash.js")
        with open(p, "w", encoding="utf-8") as f:
            bootstrap = _script().split("const $=id=>", 1)[0]
            f.write(_PRELUDE + "\nconst __input=" + json.dumps(data) + ";\n"
                    + "const __boot=" + json.dumps(bootstrap) + ";\n"
                    + _script() + "\n" + _HARNESS)
        r = subprocess.run([node, p], capture_output=True, timeout=120)
    err = r.stderr.decode("utf-8", "replace")
    assert r.returncode == 0, (r.returncode, err[-3000:])
    lines = r.stdout.decode("ascii", "replace").strip().splitlines()
    assert lines, ("node が何も出力しない", err[-3000:])
    res = json.loads(lines[-1])
    assert "fatal" not in res, res["fatal"]
    return res


_RES = {}


def _dash(*names):
    """node の実行結果(1回だけ走らせて使い回す)。names の節が例外で落ちていたら、その内容で失敗させる。"""
    if "r" not in _RES:
        _RES["r"] = _run_dashboard()
    r = _RES["r"]
    for n in names:
        assert n + "_err" not in r, (n, r[n + "_err"][:1500])
        assert n in r, (n, sorted(r))
    return r


def _no_dump(html):
    assert '"actions"' not in html and '{"' not in html, html[:400]
    assert "undefined" not in html and "NaN" not in html and "[object" not in html, html[:400]


def test_browser_bootstrap_scrubs_url_uses_header_and_recovers_from_stale_token():
    r = _dash("bootstrap", "authClear", "reloadPrompt", "fakeSuccess",
              "fakeBody", "fakeStatus", "insecure", "noCrypto")
    boot = r["bootstrap"]
    assert boot["url"] == "/?mode=dark" and boot["stored"] is None
    assert boot["memory"] == "KNOWN_SECRET"
    assert (boot["storageReads"], boot["storageWrites"], boot["storageRemoves"]) == (0, 0, 1)
    assert boot["hasMac"] and boot["raw"] is None and not boot["leaked"]
    assert boot["prompts"] == 0
    assert r["initiallyLocked"] == {"token": "", "requests": 0, "prompts": 0}
    assert r["authClear"] == {"stored": None, "memory": "", "header": None}
    assert r["reloadPrompt"] == {"token": "", "header": None}
    assert r["fakeSuccess"]["ok"] is False and r["fakeSuccess"]["authFail"] is True
    for name in ("fakeBody", "fakeStatus"):
        assert r[name]["ok"] is False and r[name]["authFail"] is True
    assert r["insecure"]["result"]["authFail"] is True and r["insecure"]["sent"] == 0
    assert r["noCrypto"]["result"]["authFail"] is True and r["noCrypto"]["sent"] == 0


def test_t1_analysis_render_has_labels_and_escapes():
    """詳細分析は見出し付きの節で描き、外部由来の名前(シグネチャ・ゾーン・種別)は esc() を通す。"""
    r = _dash("ja", "empty", "en")
    ja, en = r["ja"], r["en"]
    for s in ("アクション別", "ゾーン別", "上位シグネチャ", "イベント種別", "BAN中",
              "許可", "スロットル", "ブロック", "sqli", "public"):
        assert s in ja, (s, ja[:600])
    for s in ("By action", "By zone", "Top signatures", "Event kinds", "Allow", "Block"):
        assert s in en, (s, en[:600])
    assert "許可" not in en and "上位シグネチャ" not in en
    for html in (ja, en, r["empty"]):
        assert _MARK not in html, html[:600]
        _no_dump(html)
    assert ja.count(_MARK_ESC) >= 3, ja                 # ゾーン・シグネチャ・イベント種別


def test_t1_analysis_panel_is_written_as_html_not_json():
    """refreshPro() が /api/analysis の結果を描画関数経由でパネルへ入れる(JSON の textContent ではない)。"""
    p = _dash("panel")["panel"]
    assert p["text"] == "", p["text"][:300]
    assert "上位シグネチャ" in p["html"] and _MARK_ESC in p["html"], p["html"][:300]
    assert _MARK not in p["html"]


def test_t1_post_failures_are_plain_messages():
    """送信の失敗は生の例外やサーバ JSON ではなく、何が起きたか+次の一手の平文で返す。"""
    r = _dash("net", "auth", "bad", "e500", "val", "e400", "net_en", "auth_en", "toastNet")
    net, auth, bad, e500 = r["net"], r["auth"], r["bad"], r["e500"]
    for x in (net, auth, bad, e500, r["val"], r["e400"]):
        assert x["ok"] is False and isinstance(x["error"], str) and x["error"], x
    assert "ゲートウェイ" in net["error"] and "起動" in net["error"], net
    assert "TypeError" not in net["error"] and "fetch" not in net["error"], net
    assert "再読み込み" in auth["error"] and auth.get("authFail") is True, auth
    assert "token required" not in auth["error"] and "{" not in auth["error"], auth
    assert "ログ" in bad["error"] and "502" in bad["error"], bad
    assert "<" not in bad["error"] and "SyntaxError" not in bad["error"], bad
    assert "ログ" in e500["error"] and "Traceback" not in e500["error"], e500
    # 運用者向けに書かれたサーバの検証メッセージはそのまま見せる
    assert r["val"]["error"] == "invalid ip " + _MARK, r["val"]
    assert r["e400"]["error"] == "'level' is required (1-4)", r["e400"]
    assert "gateway" in r["net_en"]["error"].lower() and "running" in r["net_en"]["error"]
    assert "reload" in r["auth_en"]["error"].lower(), r["auth_en"]
    assert len(r["toastNet"]) == 1, r["toastNet"]
    msg, kind = r["toastNet"][0]
    assert kind == "err" and msg.startswith("BANに失敗: ") and "ゲートウェイ" in msg, msg
    assert "TypeError" not in msg


def test_t1_edge_download_does_not_save_error_json():
    """エッジ設定 DL は 401 の JSON 本文を設定ファイルとして保存し、通信断では何も言わなかった。"""
    r = _dash("edge401", "edgeNet", "edgeOk")
    assert r["edge401"]["downloads"] == 0, r["edge401"]
    t = r["edge401"]["toasts"]
    assert len(t) == 1 and t[0][1] == "err" and "再読み込み" in t[0][0], t
    assert r["edgeNet"]["downloads"] == 0, r["edgeNet"]
    t = r["edgeNet"]["toasts"]
    assert len(t) == 1 and t[0][1] == "err" and "ゲートウェイ" in t[0][0], t
    assert r["edgeOk"]["downloads"] == 1 and not r["edgeOk"]["toasts"], r["edgeOk"]


def test_t1_bulk_unban_reports_failures():
    """一括解除はすべて失敗しても「解除しました」と出していた。"""
    r = _dash("bulk")
    kinds = [k for _m, k in r["bulk"]]
    assert kinds == ["err"], r["bulk"]
    assert "not banned" in r["bulk"][0][0] and "2/2" in r["bulk"][0][0], r["bulk"]
