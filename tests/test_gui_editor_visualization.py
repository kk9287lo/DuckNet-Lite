"""Run the structured editor and investigation controls with hostile/benign data."""
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest

from dataplane import admin
from dataplane.engine.lifeform.pipeline import _DEFAULTS
from dataplane.gui.settings import settings_schema
from test_gui_settings_editor import _JS as _EDITOR_HARNESS


_CASES = r'''
async function main(){
 const out={};let h=make();await h.ctx.loadSettingsSchema();
 const tags=h.ctx.settingsControls.private_paths._structured;
 out.structured={tags:tags?tags.kind:null,paths:h.ctx.settingsControls.path_limits._structured?.kind||null,headers:h.ctx.settingsControls.sec_headers_extra._structured?.kind||null};
 if(tags){
  tags.entry.value='/safe';tags.add.onclick();
  tags.entry.value='<img src=x onerror=1>';tags.add.onclick();
  out.tags={value:JSON.parse(h.ctx.settingsControls.private_paths.value),dirty:[...h.ctx.settingsDirty],html:tags.host.children.map(x=>x.textContent).join('')};
  h.ctx.updateSettingsSnapshot(fixture.config,revision);
  out.tags.afterPoll=h.ctx.settingsControls.private_paths.value;
  const raw=h.ctx.settingsControls.private_paths;raw.value='["/raw",';raw.listeners.input();
  tags.raw.open=false;tags.raw.listeners.toggle();out.raw={value:raw.value,dirty:[...h.ctx.settingsDirty],reopened:tags.raw.open};
  raw.value='["/raw"]';raw.listeners.input();
  h.ctx.settingsSetAvailable(false);out.disabled=tags.inputs.every(c=>c.disabled);
 }
 h=make();await h.ctx.loadSettingsSchema();const rows=h.ctx.settingsControls.path_limits._structured;
 if(rows){rows.add.onclick();const entry=rows.rows[0];entry.path.value='/login';entry.rate.value='Infinity';entry.burst.value='2';entry.rate.listeners.input();
  await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.badPath={calls:h.calls.length,dirty:[...h.ctx.settingsDirty],invalid:!!rows.error};
  entry.rate.value='1.5';entry.rate.listeners.input();h.ctx.toggleSettingsDiff();
  out.goodPath={value:JSON.parse(h.ctx.settingsControls.path_limits.value),diff:h.ctx.$('settingsdiff').children.length};
  await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.goodPath.calls=h.calls;
 }
 h=make();await h.ctx.loadSettingsSchema();const dict=h.ctx.settingsControls.sec_headers_extra._structured;
 if(dict){dict.add.onclick();dict.rows[0].key.value='X-Test';dict.rows[0].value.value='<script>bad()</script>';dict.rows[0].value.listeners.input();
  dict.add.onclick();dict.rows[1].key.value='x-test';dict.rows[1].value.value='duplicate';dict.rows[1].key.listeners.input();
  await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.duplicate={calls:h.calls.length,error:!!dict.error};
 }
 h=make();await h.ctx.loadSettingsSchema();let state=h.ctx.settingsControls.private_paths._structured;
 if(state){state.entry.value='/unconfirmed';state.entry.listeners.input();await h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));out.unconfirmed={calls:h.calls.length,entry:state.entry.value,dirty:[...h.ctx.settingsDirty]};
  h.ctx.settingsControls.private_paths.value=JSON.stringify(Array(513).fill('/x'));h.ctx.settingsControls.private_paths.listeners.input();out.rowLimit={rendered:state.host.children.length,error:!!state.error};}
 h=make();await h.ctx.loadSettingsSchema();state=h.ctx.settingsControls.private_paths._structured;
 if(state){state.entry.value='/pending';state.add.onclick();let finish;h.ctx.post=async()=>new Promise(resolve=>finish=resolve);
  const save=h.ctx.saveAdvancedSettings(h.ctx.$('settingssave'));await new Promise(setImmediate);const disabled=state.inputs.every(x=>x.disabled);h.ctx.updateSettingsSnapshot(fixture.config,revision);
  const kept=h.ctx.settingsControls.private_paths.value;finish({ok:true,cfg:{...fixture.config,private_paths:['/pending']},config_revision:nextRevision});await save;out.structuredPending={disabled,kept,dirty:[...h.ctx.settingsDirty]};}
 process.stdout.write(JSON.stringify(out)+'\n');
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
'''


def _editor_cases():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for structured editor checks")
    script = _EDITOR_HARNESS[:_EDITOR_HARNESS.index("async function main(){")] + _CASES
    with tempfile.TemporaryDirectory(prefix="gui-visual-", dir=os.environ["DUCKNET_STATE_DIR"]) as tmp:
        path = Path(tmp) / "editor.js"
        fixture = Path(tmp) / "fixture.json"
        path.write_text(script, encoding="utf-8")
        fixture.write_text(json.dumps({"schema": settings_schema(), "config": _DEFAULTS}), encoding="utf-8")
        result = subprocess.run([node, str(path), str(Path(admin.__file__).resolve()), str(fixture)],
                                capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-3000:]
    return json.loads(result.stdout)


def test_structured_settings_render_tags_and_typed_rows_instead_of_raw_only():
    result = _editor_cases()
    assert result["structured"] == {"tags": "tags", "paths": "paths", "headers": "dictionary"}
    assert result["tags"]["value"] == ["/safe", "<img src=x onerror=1>"]
    assert json.loads(result["tags"]["afterPoll"]) == result["tags"]["value"]
    assert result["raw"]["value"] == '["/raw",' and "private_paths" in result["raw"]["dirty"]
    assert result["raw"]["reopened"] is True
    assert result["disabled"] is True


def test_structured_invalid_rows_are_not_posted_and_valid_rows_commit_atomically():
    result = _editor_cases()
    assert result["badPath"] == {"calls": 0, "dirty": ["path_limits"], "invalid": True}
    assert result["goodPath"]["value"] == [{"path": "/login", "rate": 1.5, "burst": 2}]
    assert result["goodPath"]["diff"] > 0
    assert len(result["goodPath"]["calls"]) == 1
    assert result["duplicate"] == {"calls": 0, "error": True}


def test_unconfirmed_tags_limits_and_pending_controls_preserve_the_draft():
    result = _editor_cases()
    assert result["unconfirmed"] == {"calls": 0, "entry": "/unconfirmed", "dirty": ["private_paths"]}
    assert result["rowLimit"]["rendered"] <= 512 and result["rowLimit"]["error"] is True
    assert result["structuredPending"]["disabled"] is True
    assert json.loads(result["structuredPending"]["kept"]) == ["/pending"]
    assert result["structuredPending"]["dirty"] == []


_VISUAL = r'''
function take(name){const match=source.match(new RegExp('^(?:async )?function '+name+'\\([^\\n]*\\)\\{[\\s\\S]*?^\\}','m'));if(!match)throw new Error(name+' missing');return match[0];}
async function main(){
 const h=make(),ctx=h.ctx;ctx.nf=n=>String(n);ctx.refreshPro=async()=>{};ctx.devicePixelRatio=1;ctx.cssv=()=>'#123456';ctx.tm=t=>'time '+t;
 vm.runInContext(['renderThreatTable','threatIPAction','renderDeceptionTable','drawChart','setChartWindow'].map(take).join('\n'),ctx);
 const text=el=>el.textContent+el.children.map(text).join(' '),tags=el=>[el.tagName,...el.children.flatMap(tags)];
 ctx.renderThreatTable('top',[{ip:'<img src=x onerror=1>',score:3,reqs_window:5,hits:2,banned:false},{ip:'192.0.2.1',score:NaN,reqs_window:1,hits:0,banned:true}]);
 const top=ctx.$('top');const out={table:{text:text(top),tags:tags(top)}};
 ctx.renderThreatTable('apt',[{ip:'192.0.2.2',apt_score:42,regular_beacon:true,low_and_slow:true,hits:4,banned:true}],true);out.apt=text(ctx.$('apt'));
 const sent=[],filtered=[];ctx.filterEventsForIP=ip=>filtered.push(ip);ctx.postT=async(path,body)=>{sent.push({path,body});return {ok:true};};
 top.children[0].children[2].children[4].children[0].onclick();await new Promise(setImmediate);
 top.children[0].children[2].children[4].children[1].onclick();out.actions={sent:JSON.parse(JSON.stringify(sent)),filtered};
 let finish;ctx.banFromEvent=async(ip)=>{sent.push({path:'/api/shield/ban',body:{ip}});await new Promise(resolve=>finish=resolve);};
 const button=top.children[0].children[1].children[4].children[0];const first=ctx.threatIPAction('192.0.2.3',false,button);await new Promise(setImmediate);await ctx.threatIPAction('192.0.2.3',false,button);const pending=button.disabled;finish();await first;out.pending={pending,calls:sent.filter(x=>x.path==='/api/shield/ban').length,released:!button.disabled};
 ctx.renderDeceptionTable({enabled:true,sample_seed:'203.0.113.1',preview:[{window:0,family:'<script>alert(1)</script>',server:'<img>',companions:['X-Test: <svg onload=1>']}]});out.deception={text:text(ctx.$('deception')),tags:tags(ctx.$('deception'))};
 const points=[],canvas={clientWidth:500,width:0,height:0,getBoundingClientRect:()=>({left:0,width:500})};
 const drawing={createLinearGradient:()=>({addColorStop(){}}),moveTo:(...p)=>points.push(p),lineTo:(...p)=>points.push(p)};
 for(const name of ['setTransform','clearRect','beginPath','stroke','closePath','fill'])drawing[name]=()=>{};
 canvas.getContext=()=>drawing;const original=ctx.$,legend={innerHTML:'',textContent:''};ctx.$=id=>id==='chart'?canvas:id==='chartleg'?legend:original(id);
 ctx.drawChart([{t:1,requests:1,block:0},{t:2,requests:2,block:0},{t:3,requests:NaN,block:Infinity},{t:4,requests:4,block:1},{t:4,requests:0,block:0}]);
 canvas.onpointermove({clientX:250});const hover=ctx.$('charttip').textContent;canvas.onkeydown({key:'ArrowLeft',preventDefault(){}});out.chart={finite:points.length>4&&points.flat().every(Number.isFinite),hover,keyboard:ctx.$('charttip').textContent};canvas.onpointerleave();out.chart.hidden=ctx.$('charttip').hidden;
 ctx.document.querySelectorAll=()=>[];ctx.chartWindow=Infinity;ctx.setChartWindow(60);ctx.setChartWindow(1800);out.chart.window=ctx.chartWindow;
 process.stdout.write(JSON.stringify(out)+'\n');
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
'''


def _visual_cases():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js is unavailable for visualization checks")
    script = _EDITOR_HARNESS[:_EDITOR_HARNESS.index("async function main(){")] + _VISUAL
    with tempfile.TemporaryDirectory(prefix="gui-tables-", dir=os.environ["DUCKNET_STATE_DIR"]) as tmp:
        path = Path(tmp) / "tables.js"
        fixture = Path(tmp) / "fixture.json"
        path.write_text(script, encoding="utf-8")
        fixture.write_text(json.dumps({"schema": settings_schema(), "config": _DEFAULTS}), encoding="utf-8")
        result = subprocess.run([node, str(path), str(Path(admin.__file__).resolve()), str(fixture)],
                                capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-3000:]
    return json.loads(result.stdout)


def test_threat_and_deception_tables_render_data_without_interpreting_html():
    result = _visual_cases()
    assert "TABLE" in result["table"]["tags"] and "IMG" not in result["table"]["tags"]
    assert "<img src=x onerror=1>" in result["table"]["text"]
    assert "規則的ビーコン" in result["apt"] and "低速持続" in result["apt"]
    assert "SCRIPT" not in result["deception"]["tags"] and "<script>" in result["deception"]["text"]
    assert "実通信の記録ではありません" in result["deception"]["text"]


def test_threat_actions_use_existing_api_and_keep_pending_ownership():
    result = _visual_cases()
    assert result["actions"] == {"sent": [{"path": "/api/shield/unban", "body": {"ip": "192.0.2.1"}}], "filtered": ["192.0.2.1"]}
    assert result["pending"] == {"pending": True, "calls": 1, "released": True}


def test_chart_rejects_nonfinite_points_and_exposes_hover_and_keyboard_values():
    result = _visual_cases()["chart"]
    assert result["finite"] is True and "req/s" in result["hover"] and "block/s" in result["keyboard"]
    assert result["hidden"] is True and result["window"] == 60
    assert 'data-sec="1800"' not in admin._HTML and 'data-sec="600"' in admin._HTML


def test_save_bar_is_outside_overflow_body_and_retains_its_sticky_controls():
    class Structure(HTMLParser):
        def __init__(self):
            super().__init__()
            self.stack = []
            self.bars = []
            self.controls = {}

        def handle_starttag(self, tag, attrs):
            attributes = dict(attrs)
            if "settings-savebar" in attributes.get("class", "").split():
                self.bars.append(list(self.stack))
            if attributes.get("id") in {"settingssave", "settingsreload", "settingsdiffbutton", "settingsstatus"}:
                self.controls[attributes["id"]] = list(self.stack)
            if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
                self.stack.append((tag, attributes))

        def handle_endtag(self, tag):
            for index in range(len(self.stack) - 1, -1, -1):
                if self.stack[index][0] == tag:
                    del self.stack[index:]
                    break

    parser = Structure()
    parser.feed(admin._HTML)
    assert len(parser.bars) == 1
    ancestors = parser.bars[0]
    assert ancestors[-1][0] == "details" and ancestors[-1][1].get("id") == "settingsdetail"
    assert all("pbody" not in attrs.get("class", "").split() for _tag, attrs in ancestors)
    assert set(parser.controls) == {"settingssave", "settingsreload", "settingsdiffbutton", "settingsstatus"}
    assert all(any("settings-savebar" in attrs.get("class", "").split() for _tag, attrs in chain)
               for chain in parser.controls.values())
    import re
    style = re.search(r"\.settings-savebar\s*\{([^}]+)\}", admin._HTML)
    assert style and re.search(r"\bposition\s*:\s*sticky\b", style.group(1))
    assert re.search(r"\bbottom\s*:", style.group(1))
