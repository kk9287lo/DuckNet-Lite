"""
test_sweep_rv_operator.py — 独立レビューで見つかった、運用者が触る表面(起動ランチャ・ダッシュボードの文言・
テストの後始末)の回帰(Lite 版)。
====================================================================================
· #7     run.bat が DUCKNET_PYTHON を常に『1 つの実行ファイル』として引用符付きで起動するようになり、
         以前の版で使えた py -3 のような引数付きのコマンドが『Python 3.10 以上が必要です』で止まった。
         既存のファイルを指す値(空白入りのパス・引用符の有無を問わない)は引用符付きで、そうでなければ
         書かれたままのコマンド行として起動する。起動できないことと古すぎることは別の言葉で伝える。
· #23    test_sweep_r2_ipsource をモジュール単体で走らせたときも、run_all.py と同じく状態dirを隔離する
         (Full では本物の状態dirへ .statekey を書いていた。Lite は書かないが、同じ形に揃えて固定する)。
· #24    test_sweep_service_gui が run.ps1 / os.devnull のファイルを閉じていなかった。
· #29    ダッシュボードの設定警告バッジが英語表示でも日本語のままだった(警告の code で訳す)。
· #30    検知の厳格度の変更と、その「元に戻す」が成功しても『失敗』と表示された(応答に ok:true が無い)。
(#20 content stats --json / #22 GUI の認証エラー文言は Full のみの機能=このモジュールには無い)
入力は普通の文字列と文書用の値だけを使う。state は tmp で隔離。
"""
import contextlib
import gc
import http.client
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import warnings
from unittest import SkipTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIN = sys.platform.startswith("win")


# ── #7 run.bat: DUCKNET_PYTHON はファイルなら引用符付き、そうでなければコマンド行 ──────
_RV_MARK = "RVOP"


def _bat_dir(d, app_env=None):
    """run.bat+(任意で app.env)+『受け取った -X と引数を出すだけ』の偽 dataplane を d に置く。"""
    shutil.copy(os.path.join(ROOT, "run.bat"), os.path.join(d, "run.bat"))
    if app_env is not None:
        with open(os.path.join(d, "app.env"), "w", encoding="utf-8", newline="\n") as f:
            f.write(app_env + "\n")
    pkg = os.path.join(d, "dataplane")
    os.makedirs(pkg)
    with open(os.path.join(pkg, "__init__.py"), "w", encoding="utf-8"):
        pass
    with open(os.path.join(pkg, "__main__.py"), "w", encoding="utf-8") as f:
        f.write("import json, sys\n"
                "sys.stdout.write(%r + json.dumps({'x': sys._xoptions, 'argv': sys.argv[1:]}))\n"
                % _RV_MARK)


def _run_bat(d, py):
    """cmd.exe で run.bat --rv-arg を実行する。py=None なら DUCKNET_PYTHON を渡さない。
    専用の(窓の無い)コンソールで動かす: 利用者がダブルクリックしたときと同じ既定のコードページで
    始まり、run.bat の chcp がこのテストを走らせているコンソールのコードページを書き換えない。"""
    env = {k: v for k, v in os.environ.items()
           if k.upper() not in ("DUCKNET_ENV_FILE", "DUCKNET_PYTHON", "PYTHONPATH")}
    if py is not None:
        env["DUCKNET_PYTHON"] = py
    r = subprocess.run(["cmd.exe", "/d", "/c", os.path.join(d, "run.bat"), "--rv-arg"], cwd=d,
                       env=env, capture_output=True, timeout=120,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    out = r.stdout.decode("utf-8", "replace")
    got = json.loads(out[out.index(_RV_MARK) + len(_RV_MARK):].strip()) if _RV_MARK in out else None
    return r, got


def _odd_python(base):
    """空白・&・括弧・! を含むディレクトリに置いた本物の Python(venv の python.exe)。"""
    import venv
    p = os.path.join(base, "Py R&D (x86) !x")
    try:
        venv.EnvBuilder(with_pip=False).create(p)
    except Exception as e:  # noqa: BLE001
        raise SkipTest("venv を作れない環境: %r" % (e,))
    exe = os.path.join(p, "Scripts", "python.exe")
    if not os.path.isfile(exe):
        raise SkipTest("venv の python.exe が見当たらない")
    return exe


def test_rv7_run_bat_runs_command_lines_with_arguments():
    """以前の版は DUCKNET_PYTHON をコマンド行のまま展開していたので『py -3』や『"…python.exe" -X …』が
    使えた。前回の修正(常に "%PY%" で起動)以降は値全体が 1 つのプログラム名になり、rc=9 で止まった。"""
    if not WIN:
        raise SkipTest("cmd.exe が無い環境")
    base = tempfile.mkdtemp(prefix="rvop-bat-")
    try:
        exe = _odd_python(base)
        cases = [('"%s" -X rv_cmd=1' % exe, "env"),                      # 引用符付きパス+引数
                 ('"%s" -X rv_cmd=1' % exe, "app.env")]
        if " " not in sys.executable:                                   # 空白の無いパス+引数
            cases.append(("%s -X rv_cmd=1" % sys.executable, "env"))
        for i, (val, how) in enumerate(cases):
            d = os.path.join(base, "l%d" % i)
            os.makedirs(d)
            _bat_dir(d, app_env=("DUCKNET_PYTHON=" + val) if how == "app.env" else None)
            r, got = _run_bat(d, val if how == "env" else None)
            assert got is not None, (val, how, r.returncode, r.stderr[-300:])
            assert got["x"].get("rv_cmd") == "1", (val, how, got)   # 引数が Python まで届いた
            assert got["argv"] == ["--rv-arg"], (val, how, got)
        # 実物の py ランチャ(3.10 以上を起動できるときだけ)
        py = shutil.which("py")
        if py and subprocess.run([py, "-3", "-c", "import sys;raise SystemExit(sys.version_info[:2]<(3,10))"],
                                 capture_output=True, timeout=60).returncode == 0:
            d = os.path.join(base, "lpy")
            os.makedirs(d)
            _bat_dir(d)
            r, got = _run_bat(d, "py -3")
            assert got is not None and got["argv"] == ["--rv-arg"], (r.returncode, r.stderr[-300:])
    finally:
        shutil.rmtree(base, True)


def test_rv7_run_bat_runs_existing_paths_quoted():
    """既存のファイルを指す値は、空白・&・括弧・! を含んでも、引用符の有無を問わず起動できる
    (前回の修正で直った『空白入りのパスを引用符なしで書くと起動できない』を戻さない)。"""
    if not WIN:
        raise SkipTest("cmd.exe が無い環境")
    base = tempfile.mkdtemp(prefix="rvop-bat-")
    try:
        exe = _odd_python(base)
        cases = [(exe, "env"), ('"%s"' % exe, "env"), (exe, "app.env"), ('"%s"' % exe, "app.env"),
                 (sys.executable, "env")]
        for i, (val, how) in enumerate(cases):
            d = os.path.join(base, "l%d" % i)
            os.makedirs(d)
            _bat_dir(d, app_env=("DUCKNET_PYTHON=" + val) if how == "app.env" else None)
            r, got = _run_bat(d, val if how == "env" else None)
            assert got is not None, (val, how, r.returncode, r.stderr[-300:])
            assert got["argv"] == ["--rv-arg"], (val, how, got)
    finally:
        shutil.rmtree(base, True)


def test_rv7_run_bat_says_it_cannot_start_python():
    """起動できない値(無いパス・無いコマンド)に『Python 3.10 以上が必要です』と言っていた。
    DUCKNET_PYTHON の値を見直すよう案内し、3.10 の話はしない(終了コードは従来どおり 9)。"""
    if not WIN:
        raise SkipTest("cmd.exe が無い環境")
    base = tempfile.mkdtemp(prefix="rvop-bat-")
    try:
        for i, val in enumerate((os.path.join(base, "no such dir", "python.exe"),
                                 "rv-no-such-python -3")):
            d = os.path.join(base, "l%d" % i)
            os.makedirs(d)
            _bat_dir(d)
            r, got = _run_bat(d, val)
            assert got is None and r.returncode == 9, (val, r.returncode, r.stdout[-200:])
            # 文言はコードページ次第で化けうるので、ASCII の部分だけで見る
            assert b"DUCKNET_PYTHON" in r.stderr and b"3.10" not in r.stderr, (val, r.stderr[-300:])
    finally:
        shutil.rmtree(base, True)


# ── #23 単体実行の test_sweep_r2_ipsource も状態dirを隔離する ─────────────────────
def test_rv23_r2_ipsource_runner_isolates_state_dir():
    """python tests/test_sweep_r2_ipsource.py(モジュール自身の __main__)でも run_all.py と同じく
    状態dirを一時dirへ向ける。HOME を捨てdirへ向けて走らせ、そこに何も書かれないこと。"""
    path = os.path.join(ROOT, "tests", "test_sweep_r2_ipsource.py")
    home = tempfile.mkdtemp(prefix="rvop-home-")
    env_dir = tempfile.mkdtemp(prefix="rvop-empty-env-",
                               dir=os.environ.get("DUCKNET_STATE_DIR") or None)
    try:
        env_file = os.path.join(env_dir, "none.env")
        with open(env_file, "w", encoding="utf-8"):
            pass
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("DUCKNET_")
               and k.upper() != "PYTHONPATH"}
        env.update({"HOME": home, "USERPROFILE": home, "PYTHONPATH": ROOT,
                    "DUCKNET_OFFLINE": "1", "DUCKNET_ENV_FILE": env_file,
                    "PYTHONIOENCODING": "utf-8"})
        code = ("import os, runpy, sys\n"
                "if os.path.expanduser('~') != sys.argv[1]:\n"
                "    print('RVOP-NOHOME'); raise SystemExit(0)\n"
                "sys.path.insert(0, os.path.dirname(sys.argv[2]))\n"
                "runpy.run_path(sys.argv[2], run_name='__main__')\n")
        r = subprocess.run([sys.executable, "-c", code, home, path], cwd=ROOT, env=env,
                           capture_output=True, timeout=300)
        out = r.stdout.decode("utf-8", "replace")
        if "RVOP-NOHOME" in out:
            raise SkipTest("ホームディレクトリを差し替えられない環境")
        assert r.returncode == 0, (r.returncode, r.stderr[-600:])
        m = re.search(r"--- (\d+)/(\d+) passed ---", out)
        assert m and m.group(1) == m.group(2), out[-800:]
        written = [os.path.relpath(os.path.join(dp, f), home)
                   for dp, _dn, fn in os.walk(home) for f in fn]
        assert not written, written
    finally:
        shutil.rmtree(home, True)
        shutil.rmtree(env_dir, True)


# ── #24 test_sweep_service_gui が開いたファイルを閉じていなかった ───────────────────
def _load_test_module(name):
    spec = importlib.util.spec_from_file_location("rvop_" + name,
                                                  os.path.join(ROOT, "tests", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_rv24_service_gui_tests_close_their_files():
    """run.ps1 を open(...).read() で読み捨て、redirect_stdout/redirect_stderr(open(os.devnull)) を
    閉じていなかった(-X dev / -W error::ResourceWarning で警告・Windows では GC まで run.ps1 を掴んだまま)。"""
    T = _load_test_module("test_sweep_service_gui")
    names = ("test_c21_run_ps1_has_utf8_bom", "test_c22_abbreviated_autostart_flags_are_stripped",
             "test_c94_tray_reads_admin_url_and_cover_after_app_env")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        for n in names:
            try:
                getattr(T, n)()
            except SkipTest:
                pass
            gc.collect()
    leaks = [str(x.message) for x in w if issubclass(x.category, ResourceWarning)
             and ("run.ps1" in str(x.message) or repr(os.devnull) in str(x.message))]
    assert not leaks, leaks


# ── #29/#30 ダッシュボード: node でスクリプトを動かす ───────────────────────────
# ブラウザの代わりの最小 DOM(要素は id ごとに 1 つ作り、書き込みを覚える)。
_PRELUDE = r"""
var __els={},__toasts=[],__routes={},__requests=[],__storage={},__prompts=[];
var __nodeCrypto=require("crypto");globalThis.crypto=__nodeCrypto.webcrypto;
var __instance="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
var location={href:"http://127.0.0.1:8081/"};
var history={replaceState(_a,_b,url){location.href="http://127.0.0.1:8081"+url;}};
var sessionStorage={getItem(k){return __storage[k]||null;},
 setItem(k,v){__storage[k]=String(v);},removeItem(k){delete __storage[k];}};
function prompt(message){__prompts.push(message);return "rv-browser-token";}
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
URL.createObjectURL=function(){return "blob:x";};
URL.revokeObjectURL=function(){};
async function fetch(p,opt){
 __requests.push({path:p,headers:{...((opt&&opt.headers)||{})}});
 const r=__routes[p];
 if(!r)throw new TypeError("Failed to fetch");
 const raw=Buffer.from(r.body,"utf8"),nonce=(opt&&opt.headers||{})["X-Admin-Auth-Nonce"]||"";
 const hash=__nodeCrypto.createHash("sha256").update(raw).digest("hex");
 const mac=(r.status===401||r.fake)?"":__nodeCrypto.createHmac("sha256","rv-browser-token")
  .update(__instance+"\n"+nonce+"\n"+r.status+"\n"+hash).digest("hex");
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
 __routes["/api/state"]={status:200,body:JSON.stringify(__input.state)};
 document.getElementById("adminTokenInput").value="rv-browser-token";
 await submitAdminAuth({preventDefault(){}});delete __routes["/api/state"];
 const T=async(name,fn)=>{try{out[name]=await fn();}catch(e){out[name+"_err"]=String(e&&e.stack||e);}};
 const bootstrapDeadline=Date.now()+2000;
 while(Date.now()<bootstrapDeadline&&!__requests.some(r=>r.headers?.["X-Admin-Auth-Mac"]))
  await new Promise(resolve=>require("timers").setTimeout(resolve,5));
 await T("auth_bootstrap",()=>({stored:__storage["ducknet-admin-token"]||null,
  memory:TOKEN,
  prompts:__prompts.length,hasMac:!!(__requests[0]||{}).headers?.["X-Admin-Auth-Mac"],
  raw:(__requests[0]||{}).headers?.["X-Token"]||null}));
 toast=function(m,k){__toasts.push([String(m),k]);};
 const W=async(lang,st)=>{
  __routes["/api/state"]={status:200,body:JSON.stringify(st)};
  LANG=lang;
  try{try{await refresh();}catch(e){}}finally{LANG="ja";delete __routes["/api/state"];}
  const el=document.getElementById("cfgwarn");
  return {html:el.innerHTML,display:el.style.display};};
 await T("warn_en",()=>W("en",__input.state));
 await T("warn_ja",()=>W("ja",__input.state));
 await T("more_en",()=>W("en",__input.state2));
 await T("more_ja",()=>W("ja",__input.state2));
 const P="/api/shield/paranoia";
 await T("paranoia",async()=>{__toasts.length=0;
  __routes[P]={status:200,body:JSON.stringify(__input.set)};
  try{const el=document.getElementById("paranoia");el.value="2";
   await el.onchange({target:el});}finally{delete __routes[P];}
  return __toasts.splice(0);});
 await T("undo",async()=>{__toasts.length=0;
  __routes[P]={status:200,body:JSON.stringify(__input.undo)};
  // revertAudit() は promise を返さない=トーストが出るまで回す
  try{revertAudit(__input.revert,null);
   for(let i=0;i<200&&!__toasts.length;i++)await new Promise(r=>setImmediate(r));}
  finally{delete __routes[P];}
  return __toasts.splice(0);});
 __emit(out);
})().catch(e=>__emit({fatal:String(e&&e.stack||e)}));
"""


def _script(A) -> str:
    page = A._HTML
    i = page.index("<script>") + len("<script>")
    return page[i:page.index("</script>", i)].replace("__AUTH_INSTANCE__", "a" * 32)


@contextlib.contextmanager
def _admin():
    """一時状態の NetShield / AppFirewall を差し込み、本物の管理サーバを 127.0.0.1:0 で立てる。"""
    import dataplane.engine.lifeform.pipeline as ND
    import dataplane.engine.lifeform.policy as FW
    from dataplane import admin as A
    ofw, osh = FW._FW, ND._SHIELD
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        FW._FW = FW.AppFirewall(state_dir=d)
        ND._SHIELD = ND.NetShield(state_dir=d)
        ND._SHIELD.cfg["persist_bans"] = False
        adm = A.AdminDashboard(host="127.0.0.1", port=0, state_dir=d)
        adm.start()
        try:
            yield A, adm, ND._SHIELD
        finally:
            try:
                adm.stop()
            finally:
                FW._FW, ND._SHIELD = ofw, osh


def _call(adm, method, path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", adm.port, timeout=10)
    try:
        h = {"X-Token": adm.token}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"null")
    finally:
        c.close()


def _paranoia_round_trip(adm, sh):
    """厳格度を 2 へ変え、監査ログの「元に戻す」の本文をそのまま送り返す(実サーバの応答を返す)。"""
    # 変更前に個別に点けた任意シグネチャ(#69: 元に戻すで復元される対象)を 1 つ用意する
    from dataplane.engine.lifeform import pipeline as ND
    opt = sorted(getattr(ND, "_OPTIONAL_SIGS", ()))
    if opt:
        sh.set_optional_signature(opt[-1], True)
    before = (sh.cfg.get("paranoia"), dict(sh.cfg.get("optional_sigs") or {}))
    st, set_r = _call(adm, "POST", "/api/shield/paranoia", {"level": 2})
    assert st == 200 and set_r.get("paranoia") == 2, (st, set_r)
    st, aud = _call(adm, "GET", "/api/admin_audit")
    revs = [e.get("revert") for e in (aud or {}).get("entries", [])
            if (e.get("revert") or {}).get("endpoint") == "/api/shield/paranoia"]
    assert revs, aud
    st, undo_r = _call(adm, "POST", "/api/shield/paranoia", revs[-1]["body"])
    assert st == 200, (st, undo_r)
    after = (sh.cfg.get("paranoia"), dict(sh.cfg.get("optional_sigs") or {}))
    assert {k for k, v in after[1].items() if v} == {k for k, v in before[1].items() if v}, (before, after)
    return set_r, undo_r, revs[-1]


def test_rv30_paranoia_route_reports_ok():
    """/api/shield/paranoia は set_paranoia()/paranoia_status() をそのまま返しており ok キーが無かった。
    ダッシュボードの postT() は ok が無い応答を失敗と見るので、成功した変更も元に戻すも『失敗』と出た。
    不正な値の拒否(ok:false)は従来どおり。"""
    with _admin() as (_A, adm, sh):
        set_r, undo_r, _rev = _paranoia_round_trip(adm, sh)
        assert set_r.get("ok") is True, set_r
        assert undo_r.get("ok") is True, undo_r
        st, bad = _call(adm, "POST", "/api/shield/paranoia", {"level": "max"})
        assert bad.get("ok") is False, (st, bad)
        st, bad = _call(adm, "POST", "/api/shield/paranoia", {})
        assert st == 400 and bad.get("ok") is False, (st, bad)


def _run_dashboard(A, data):
    node = shutil.which("node")
    if not node:
        raise SkipTest("node が無い環境")
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "dash.js")
        with open(p, "w", encoding="utf-8") as f:
            f.write(_PRELUDE + "\nconst __input=" + json.dumps(data) + ";\n"
                    + "__routes['/api/state']={status:200,body:JSON.stringify(__input.state)};\n"
                    + _script(A) + "\n" + _HARNESS)
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
    """実サーバの応答(/api/state・厳格度の変更と元に戻す)を node のダッシュボードへ流した結果。"""
    if "r" not in _RES:
        with _admin() as (A, adm, sh):
            set_r, undo_r, rev = _paranoia_round_trip(adm, sh)
            # 旧版が保存した site_mode=whitelist+空 の状態(設定の入口では拒否されるので直接置く)
            sh.cfg["site_mode"] = "whitelist"
            sh.cfg["site_whitelist"] = []
            st, state = _call(adm, "GET", "/api/state")
            assert st == 200 and state["shield"]["warnings"], (st, str(state)[:300])
            # 他の code の警告(画面側で英文を組む・サーバの message_en を優先・未知の code)
            state2 = json.loads(json.dumps(state))
            state2["shield"]["warnings"] = [
                {"code": "cfg_enum_normalized", "keys": ["mode"], "message": _RV_JA_ENUM},
                {"code": "site_whitelist_empty", "keys": ["site_mode"], "message": _RV_JA_ENUM,
                 "message_en": "RV note from the server"},
                {"code": "rv_unknown_code", "keys": [], "message": "rv plain note"}]
            _RES["mode"] = state2["shield"]["cfg"].get("mode")
            _RES["r"] = _run_dashboard(A, {"state": state, "state2": state2, "set": set_r,
                                           "undo": undo_r, "revert": rev})
    r = _RES["r"]
    for n in names:
        assert n + "_err" not in r, (n, r[n + "_err"][:1500])
        assert n in r, (n, sorted(r))
    return r


_JA = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uff00-\uffef]")


_RV_JA_ENUM = "以前の版で保存された設定の綴りを正規化しました"


def test_rv29_config_warning_badge_follows_language():
    """config_warnings() の message は日本語だけ。バッジはそれを tr() も通さず出していたので、
    英語表示でも日本語の文が出た。英語表示では既知の code を英文にし(サーバが message_en を付けて
    いればそれ)、日本語表示はサーバの message のまま。未知の code はサーバの message を出す。"""
    r = _dash("auth_bootstrap", "warn_en", "warn_ja", "more_en", "more_ja")
    assert r["auth_bootstrap"] == {"stored": None, "memory": "rv-browser-token", "prompts": 0,
                                   "hasMac": True, "raw": None}, r["auth_bootstrap"]
    en, ja = r["warn_en"], r["warn_ja"]
    assert en["display"] == "" and ja["display"] == "", (en, ja)
    assert "site_whitelist" in en["html"] and not _JA.search(en["html"]), en["html"]
    assert "site_whitelist" in ja["html"] and _JA.search(ja["html"]), ja["html"]
    more_en, more_ja = r["more_en"]["html"], r["more_ja"]["html"]
    parts = more_en.split("<br>")
    assert len(parts) == 3, more_en
    assert not _JA.search(parts[0]) and "mode=%s" % _RES["mode"] in parts[0], parts[0]
    assert parts[1] == "⚠ RV note from the server", parts[1]
    assert parts[2] == "⚠ rv plain note", parts[2]
    assert more_ja.count(_RV_JA_ENUM) == 2 and "RV note" not in more_ja, more_ja


def test_rv30_dashboard_shows_success_for_paranoia_change_and_undo():
    """実サーバの応答を postT() に通すと、厳格度の変更も監査ログの「元に戻す」も成功の表示になる。"""
    r = _dash("paranoia", "undo")
    assert [k for _m, k in r["paranoia"]] == ["ok"], r["paranoia"]
    assert [k for _m, k in r["undo"]] == ["ok"], r["undo"]
