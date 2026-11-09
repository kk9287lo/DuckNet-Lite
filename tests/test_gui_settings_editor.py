"""The dashboard must edit existing defense settings without losing drafts."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from unittest import SkipTest

from dataplane import admin
from dataplane.engine.lifeform.pipeline import _DEFAULTS
from test_sweep_admin_ui import _Admin


def _request(port, path, token=None):
    headers = {"X-Token": token} if token else {}
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read()


def test_settings_schema_requires_auth_and_covers_actual_configuration():
    with _Admin() as app:
        status, _body = _request(app.port, "/api/shield/config_schema")
        assert status == 401
        status, body = _request(app.port, "/api/shield/config_schema", app.token)
        assert status == 200, (status, body)
        schema = json.loads(body)
        assert schema["ok"] is True
        assert {field["key"] for field in schema["fields"]} == set(_DEFAULTS)
        assert len(schema["fields"]) == len(_DEFAULTS)
        assert all(field.get("label") and field.get("label_en") for field in schema["fields"])


def test_advanced_settings_panel_is_rendered_and_real_api_patch_is_atomic():
    with _Admin() as app:
        status, page = _request(app.port, "/", app.token)
        assert status == 200
        assert b'id="settingsdetail"' in page
        assert b'id="settingsfields"' in page
        assert b'id="shieldmode"' in page
        before = dict(app.sh.cfg)
        status, rejected = app.post("/api/shield/config", {
            "dlp_enabled": True, "private_paths": ["not-an-absolute-path"],
        })
        assert status == 400 and rejected["ok"] is False
        assert app.sh.cfg == before
        status, accepted = app.post("/api/shield/config", {
            "dlp_enabled": True, "mode": "audit", "private_paths": ["/private"],
            "private_path_allow": ["192.0.2.10/32"],
        })
        assert status == 200 and accepted["ok"] is True
        cfg = app.get("/api/state")["shield"]["cfg"]
        assert cfg["dlp_enabled"] is True and cfg["mode"] == "audit"
        assert cfg["private_paths"] == ["/private"]
        assert cfg["private_path_allow"] == ["192.0.2.10/32"]


def test_stale_configuration_revision_rejects_before_worker_or_audit_changes():
    with _Admin() as app:
        class Guard:
            _workers = [123]
            _cluster_policy_sync = True
            metrics = {}
            calls = 0

            def quiesce_cluster_for_mutation(self):
                self.calls += 1
                return {"ok": True, "cluster_downgraded": False}

        revision = app.get("/api/state")["shield"]["config_revision"]
        status, saved = app.post("/api/shield/config", {
            "rate_per_sec": 23, "_expected_revision": revision,
        })
        assert status == 200 and saved["ok"] is True
        assert saved["config_revision"] != revision
        app.adm.edge_guard = guard = Guard()
        before = Path(app.sh.path).read_bytes()
        audit = app.get("/api/admin_audit")["entries"]
        status, rejected = app.post("/api/shield/config", {
            "rate_per_sec": 99, "_expected_revision": revision,
        })
        assert status == 409 and rejected["ok"] is False, (status, rejected)
        assert app.sh.cfg["rate_per_sec"] == 23
        assert Path(app.sh.path).read_bytes() == before
        assert app.get("/api/admin_audit")["entries"] == audit
        assert guard.calls == 0 and guard._workers == [123]
        assert "_expected_revision" not in json.dumps(audit)
        for invalid in ("", "x" * 64, [], 3, None):
            status, rejected = app.post("/api/shield/config", {
                "rate_per_sec": 99, "_expected_revision": invalid,
            })
            assert status == 400 and rejected["ok"] is False, (invalid, status, rejected)
        assert guard.calls == 0 and Path(app.sh.path).read_bytes() == before


def test_saved_paranoia_response_contains_coupled_optional_signatures():
    with _Admin() as app:
        revision = app.get("/api/state")["shield"]["config_revision"]
        status, result = app.post("/api/shield/config", {
            "paranoia": 4, "_expected_revision": revision,
        })
        assert status == 200 and result["ok"] is True
        assert result["cfg"]["paranoia"] == 4
        assert result["cfg"]["optional_sigs"] == {"ssti": True, "ssrf_internal": True, "redirect": True}
        state = app.get("/api/state")["shield"]
        assert result["config_revision"] == state["config_revision"]
        assert result["cfg"] == state["cfg"]


_JS = r'''
const fs=require('fs'),vm=require('vm');
const source=fs.readFileSync(process.argv[2],'utf8'),fixture=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
const start=source.indexOf('function settingsClone('),end=source.indexOf('const settingsDetails=',start);
if(start<0||end<0)throw new Error('settings editor functions missing');
const code=source.slice(start,end),revision='a'.repeat(64),nextRevision='b'.repeat(64);
function make(){
 const elements={},calls=[],toasts=[];let schemaCalls=0;
 class Element{
  constructor(tag='div'){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.value='';this.checked=false;this.disabled=false;this.hidden=false;this.className='';this.style={};this.listeners={};this.classList={add(){},remove(){}};}
  set id(value){this._id=value;elements[value]=this;}get id(){return this._id;}
  set textContent(value){this._text=String(value);this.children=[];}get textContent(){return this._text||'';}
  set innerHTML(_value){throw new Error('settings must not use innerHTML');}
  appendChild(child){this.children.push(child);return child;}
  setAttribute(name,value){this[name]=value;}
  addEventListener(name,fn){this.listeners[name]=fn;}
  focus(){this.focused=true;}
 }
 const $=id=>elements[id]||(elements[id]=new Element());
 const ctx={console,Promise,Set,Number,JSON,Object,TextEncoder,LANG:'ja',tr:s=>s,$,
  settingsSchema:null,settingsSchemaPromise:null,settingsLatestConfig:null,settingsLatestRevision:null,
  settingsBaseConfig:{},settingsControls:{},settingsRows:{},settingsDirty:new Set(),settingsSavePending:false,settingsAvailable:false,settingsMessage:'',settingsMessageError:false,
  document:{createElement:tag=>new Element(tag)},
  busy:(button,on)=>{if(button)button.disabled=on;},toast:(m,k)=>toasts.push([m,k]),
  isAuthFail:e=>!!(e&&e.authFail),markAuthError:()=>ctx.settingsSetAvailable(false),confirmDialog:async()=>true,
  refresh:async()=>{},
  guardedFetch:async path=>{if(path==='/api/shield/config_schema'){schemaCalls++;return fixture.schema;}return {shield:{cfg:fixture.config,config_revision:revision}};},
  post:async(path,body)=>{calls.push({path,body:JSON.parse(JSON.stringify(body))});const cfg=JSON.parse(JSON.stringify(fixture.config));for(const key in body)if(key!=='_expected_revision')cfg[key]=body[key];return {ok:true,cfg,config_revision:nextRevision};}
 };
 vm.createContext(ctx);vm.runInContext(code,ctx);
 ctx.updateSettingsSnapshot(fixture.config,revision);
 const field=key=>ctx.settingsSchema.fields.find(f=>f.key===key);
 function edit(key,value){const f=field(key),control=ctx.settingsControls[key];if(f.choices)control.value=String(f.choices.findIndex(x=>JSON.stringify(x)===JSON.stringify(value)));else if(f.type==='boolean')control.checked=value;else control.value=typeof value==='string'?value:JSON.stringify(value);ctx.settingEdited(f);}
 return {ctx,elements,calls,toasts,field,edit,schemaCalls:()=>schemaCalls};
}
async function main(){
 const out={};let h=make();await Promise.all([h.ctx.loadSettingsSchema(),h.ctx.loadSettingsSchema()]);
 out.render={keys:Object.keys(h.ctx.settingsControls).sort(),schemaCalls:h.schemaCalls(),privateType:h.ctx.settingsControls.private_paths.tagName};
 h.ctx.LANG='en';h.ctx.renderSettingsLabels();out.hints={range:h.ctx.settingsRows.rate_per_sec.rangeHint.textContent,example:h.ctx.settingsRows.private_paths.exampleText.textContent,label:h.ctx.settingsRows.private_paths.label.textContent};h.ctx.LANG='ja';
 h.edit('private_paths','["/draft"]');h.edit('sec_headers_extra','{"broken":');
 const newer=JSON.parse(JSON.stringify(fixture.config));newer.rate_per_sec=77;h.ctx.updateSettingsSnapshot(newer,nextRevision);
 h.ctx.LANG='en';h.ctx.renderSettingsLabels();h.ctx.$('settingssearch').value='DLP';h.ctx.filterSettings();
 out.draft={paths:h.ctx.settingsControls.private_paths.value,invalid:h.ctx.settingsControls.sec_headers_extra.value,rate:h.ctx.settingsControls.rate_per_sec.value,dirty:[...h.ctx.settingsDirty].sort()};
 h=make();await h.ctx.loadSettingsSchema();h.edit('dlp_enabled',true);h.edit('private_paths','["/private"]');
 await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 out.save={calls:h.calls,dirty:[...h.ctx.settingsDirty],value:h.ctx.settingsControls.private_paths.value,available:h.ctx.settingsAvailable};
 h=make();await h.ctx.loadSettingsSchema();h.edit('paranoia',4);h.ctx.post=async()=>({ok:true,cfg:{...fixture.config,paranoia:4,optional_sigs:{ssti:true,ssrf_internal:true,redirect:true}},config_revision:nextRevision});await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 out.coupled={paranoia:h.ctx.settingsControls.paranoia.value,optional:JSON.parse(h.ctx.settingsControls.optional_sigs.value),dirty:[...h.ctx.settingsDirty]};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/active"]');h.ctx.post=async()=>({ok:false,published:true,applied_in_memory:true,persisted:false,cfg:{...fixture.config,private_paths:['/active']},config_revision:nextRevision});await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 out.appliedFailure={dirty:[...h.ctx.settingsDirty],value:h.ctx.settingsControls.private_paths.value,error:h.ctx.settingsMessageError,message:h.ctx.settingsMessage,toasts:h.toasts};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/unsaved"]');h.ctx.post=async()=>({ok:true,cfg:{enabled:true},config_revision:nextRevision});await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 out.badSuccess={dirty:[...h.ctx.settingsDirty],value:h.ctx.settingsControls.private_paths.value,available:h.ctx.settingsAvailable,disabled:h.ctx.settingsControls.private_paths.disabled,toasts:h.toasts};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/draft"]');h.ctx.post=async(path,body)=>{h.calls.push({path,body});return {ok:false,error:'configuration changed; reload settings'};};
 await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.rejected={draft:h.ctx.settingsControls.private_paths.value,dirty:[...h.ctx.settingsDirty],error:h.ctx.settingsMessage,toasts:h.toasts};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/draft"]');h.ctx.guardedFetch=async()=>({shield:{cfg:{...fixture.config,private_paths:['/external']},config_revision:nextRevision}});
 await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.conflict={calls:h.calls.length,draft:h.ctx.settingsControls.private_paths.value,dirty:[...h.ctx.settingsDirty]};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/draft"]');h.ctx.guardedFetch=async()=>{const e=new Error('auth');e.authFail=true;throw e;};
 await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.stale={available:h.ctx.settingsAvailable,disabled:h.ctx.settingsControls.private_paths.disabled,draft:h.ctx.settingsControls.private_paths.value,dirty:[...h.ctx.settingsDirty]};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/draft"]');let release;h.ctx.post=async(path,body)=>{h.calls.push({path,body});return new Promise(resolve=>release=resolve);};
 const first=h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));await new Promise(setImmediate);const second=h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 h.ctx.updateSettingsSnapshot(fixture.config,revision);const pendingDraft=h.ctx.settingsControls.private_paths.value;release({ok:true,cfg:{...fixture.config,private_paths:['/draft']},config_revision:nextRevision});await Promise.all([first,second]);
 out.pending={calls:h.calls.length,draft:pendingDraft,dirty:[...h.ctx.settingsDirty]};
 h=make();await h.ctx.loadSettingsSchema();h.edit('sec_headers_extra','{"x":"first","\u0078":"second"}');await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 const duplicate={calls:h.calls.length,draft:h.ctx.settingsControls.sec_headers_extra.value,error:h.ctx.settingsMessage};
 let unsafe=false;try{h.ctx.parseSettingsJson('{"n":1e999}');}catch(_e){unsafe=true;}
 let integer=false;try{h.ctx.parseSettingsJson('{"n":9007199254740993}');}catch(_e){integer=true;}
 h.edit('rate_per_sec','Infinity');await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));
 out.invalid={duplicate,unsafe,integer,calls:h.calls.length};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/draft"]');h.ctx.confirmDialog=async()=>false;await h.ctx.reloadAdvancedSettings(h.ctx.$('settingsreload'));const kept=h.ctx.settingsControls.private_paths.value;
 h.ctx.confirmDialog=async()=>true;await h.ctx.reloadAdvancedSettings(h.ctx.$('settingsreload'));out.reload={kept,dirty:[...h.ctx.settingsDirty],reset:h.ctx.settingsControls.private_paths.value};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/unsaved",');h.ctx.guardedFetch=async()=>({shield:{cfg:{enabled:true},config_revision:nextRevision}});await h.ctx.reloadAdvancedSettings(h.ctx.$('settingsreload'));h.ctx.updateSettingsSnapshot(fixture.config,revision);
 out.badReload={dirty:[...h.ctx.settingsDirty],value:h.ctx.settingsControls.private_paths.value};
 h=make();await h.ctx.loadSettingsSchema();h.edit('private_paths','["/discard"]');let reloadReply;h.ctx.guardedFetch=async()=>new Promise(resolve=>reloadReply=resolve);const reload=h.ctx.reloadAdvancedSettings(h.ctx.$('settingsreload'));await new Promise(setImmediate);const disabled=h.ctx.settingsControls.private_paths.disabled;reloadReply({shield:{cfg:fixture.config,config_revision:revision}});await reload;
 out.pendingReload={disabled,dirty:[...h.ctx.settingsDirty],value:h.ctx.settingsControls.private_paths.value};
 h=make();const altered=JSON.parse(JSON.stringify(fixture.schema));altered.fields[0].label='<img src=x onerror=1>';altered.fields[0].label_en=altered.fields[0].label;h.ctx.guardedFetch=async p=>p==='/api/shield/config_schema'?altered:{shield:{cfg:fixture.config,config_revision:revision}};await h.ctx.loadSettingsSchema();
 out.escape={label:h.ctx.settingsRows[altered.fields[0].key].label.textContent,children:h.ctx.settingsRows[altered.fields[0].key].label.children.length};
 process.stdout.write(JSON.stringify(out)+'\n');
}
main().catch(e=>{console.error(e&&e.stack||e);process.exitCode=1;});
'''


_RESULT = None


def _cases():
    global _RESULT
    if _RESULT is not None:
        return _RESULT
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for settings editor checks")
    from dataplane.gui.settings import settings_schema
    with tempfile.TemporaryDirectory(prefix="gui-settings-", dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        script = Path(directory) / "settings.js"
        fixture = Path(directory) / "fixture.json"
        script.write_text(_JS, encoding="utf-8")
        fixture.write_text(json.dumps({"schema": settings_schema(), "config": _DEFAULTS}), encoding="utf-8")
        result = subprocess.run([node, str(script), str(Path(admin.__file__).resolve()), str(fixture)],
                                capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-3000:]
    _RESULT = json.loads(result.stdout.decode("utf-8"))
    return _RESULT


def test_editor_lazily_renders_every_setting_without_clobbering_drafts():
    result = _cases()
    assert result["render"] == {"keys": sorted(_DEFAULTS), "schemaCalls": 1, "privateType": "TEXTAREA"}
    assert result["draft"]["paths"] == '["/draft"]'
    assert result["draft"]["invalid"] == '{"broken":'
    assert result["draft"]["rate"] == "77"
    assert result["draft"]["dirty"] == ["private_paths", "sec_headers_extra"]


def test_editor_saves_one_changed_key_patch_and_adopts_server_configuration():
    result = _cases()["save"]
    assert len(result["calls"]) == 1
    assert result["calls"][0] == {"path": "/api/shield/config", "body": {
        "dlp_enabled": True, "private_paths": ["/private"], "_expected_revision": "a" * 64,
    }}
    assert result["dirty"] == [] and result["available"] is True
    assert json.loads(result["value"]) == ["/private"]


def test_editor_rejection_conflict_and_auth_failure_preserve_unsaved_values():
    result = _cases()
    assert result["rejected"]["draft"] == '["/draft"]'
    assert result["rejected"]["dirty"] == ["private_paths"]
    assert not result["rejected"]["toasts"]
    assert result["conflict"] == {"calls": 0, "draft": '["/draft"]', "dirty": ["private_paths"]}
    assert result["stale"] == {"available": False, "disabled": True,
                                "draft": '["/draft"]', "dirty": ["private_paths"]}


def test_editor_pending_save_is_owned_and_cannot_lose_its_draft():
    assert _cases()["pending"] == {"calls": 1, "draft": '["/draft"]', "dirty": []}


def test_editor_rejects_duplicate_json_nonfinite_and_unsafe_numbers_locally():
    result = _cases()["invalid"]
    assert result["calls"] == 0 and result["duplicate"]["calls"] == 0
    assert "重複" in result["duplicate"]["error"]
    assert result["unsafe"] is True and result["integer"] is True


def test_editor_explicit_reload_and_metadata_rendering_are_safe():
    result = _cases()
    assert result["reload"] == {"kept": '["/draft"]', "dirty": [], "reset": "[]"}
    assert result["escape"] == {"label": "<img src=x onerror=1>", "children": 0}
    assert result["badReload"] == {"dirty": ["private_paths"], "value": '["/unsaved",'}
    assert result["pendingReload"] == {"disabled": True, "dirty": [], "value": "[]"}
    assert "Range" in result["hints"]["range"] or "範囲" in result["hints"]["range"]
    assert json.loads(result["hints"]["example"])
    from dataplane.gui.settings import settings_schema
    field = next(field for field in settings_schema()["fields"] if field["key"] == "private_paths")
    assert result["hints"]["label"] == field["label_en"]


def test_editor_adopts_implicit_changes_and_discloses_applied_but_unsaved_state():
    result = _cases()
    assert result["coupled"] == {"paranoia": "4", "optional": {
        "ssti": True, "ssrf_internal": True, "redirect": True}, "dirty": []}
    applied = result["appliedFailure"]
    assert applied["dirty"] == [] and json.loads(applied["value"]) == ["/active"]
    assert applied["error"] is True and "永続化" in applied["message"]
    assert applied["toasts"] and all(kind != "ok" for _text, kind in applied["toasts"])
    assert result["badSuccess"] == {"dirty": ["private_paths"], "value": '["/unsaved"]',
                                     "available": False, "disabled": True, "toasts": []}


def test_dlp_status_discloses_effective_global_audit_enforce_and_off_modes():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for effective DLP status checks")
    from test_gui_dashboard_edges import _JS as edge_script
    script = edge_script.replace("async function pendingRefreshCase(){",
                                 "async function pendingRefreshCase(mode,enabled){")
    script = script.replace(
        "const cfg={enabled:false,dlp_enabled:false,dlp_action:'audit',sec_headers_enabled:false,",
        "const cfg={enabled,mode,dlp_enabled:true,dlp_action:'block',sec_headers_enabled:false,",
    )
    script = script.replace("optional:h.ctx.$('optsigs').innerHTML};",
                            "optional:h.ctx.$('optsigs').innerHTML,status:h.ctx.$('dlpstat').textContent,mode:h.ctx.$('modestat').textContent};")
    script = script.replace("pendingRefresh:await pendingRefreshCase(),",
                            "pendingRefresh:await pendingRefreshCase('audit',true),enforce:await pendingRefreshCase('enforce',true),off:await pendingRefreshCase('enforce',false),")
    with tempfile.TemporaryDirectory(prefix="dlp-status-", dir=os.environ["DUCKNET_STATE_DIR"]) as directory:
        path = Path(directory) / "status.js"
        path.write_text(script, encoding="utf-8")
        result = subprocess.run([node, str(path), str(Path(admin.__file__).resolve())],
                                capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    states = json.loads(result.stdout)
    assert "監査" in states["pendingRefresh"]["status"] and "遮断" not in states["pendingRefresh"]["status"]
    assert "構文" in states["pendingRefresh"]["mode"]
    assert "遮断" in states["enforce"]["status"]
    assert "無効" in states["off"]["status"] and states["off"]["mode"] == "防御停止中"
