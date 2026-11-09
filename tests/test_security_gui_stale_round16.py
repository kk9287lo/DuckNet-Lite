"""Failed dashboard refresh must make previously rendered controls inert."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest

from dataplane.admin import AdminDashboard
from test_security_admin_gui_status_round13 import _get


_PROBE = r"""
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const start=html.indexOf('async function refresh(){');
const end=html.indexOf(' // 直すべき設定',start);
if(start<0||end<0)throw new Error('dashboard refresh prefix missing');
const prefix=html.slice(start,end)+'\n}';
const elements={};
const $=id=>elements[id]||(elements[id]={className:'',textContent:'',title:'',
  inert:false,checked:false,disabled:false});
const initialInert=html.includes('<div class="wrap state-stale" id="stateview" inert>');
$("stateview").inert=initialInert;
const good={firewall:{enabled:true},shield:{cfg:{enabled:true}},
  shield_metrics:{},events:[],top:[]};
let next=good;
const ctx={refreshGeneration:0,$,tr:s=>s,errText:()=>"unavailable",
  isAuthFail:()=>false,markAuthError:()=>{},guardedFetch:async()=>{
    if(next===null)throw new Error('network');return next;}};
vm.createContext(ctx);vm.runInContext(prefix,ctx);
(async()=>{
 const initial={inert:elements.stateview.inert};
 await ctx.refresh();
 const healthy={inert:elements.stateview.inert,conn:elements.conn.className,
                fw:elements.fw.checked};
 next=null;await ctx.refresh();
 const failed={inert:elements.stateview.inert,conn:elements.conn.className,
               fw:elements.fw.checked};
 next=good;await ctx.refresh();
 const recovered={inert:elements.stateview.inert,conn:elements.conn.className,
                  fw:elements.fw.checked};
 next={firewall:{enabled:true},shield:{error:'source unavailable'},
       shield_metrics:{},events:[],top:[]};await ctx.refresh();
 const invalid={inert:elements.stateview.inert,conn:elements.conn.className,
                fw:elements.fw.checked};
 next=good;await ctx.refresh();
 const recoveredAgain={inert:elements.stateview.inert,conn:elements.conn.className,
                       fw:elements.fw.checked};
 process.stdout.write(JSON.stringify({initial,healthy,failed,recovered,invalid,recoveredAgain}));
})().catch(e=>{console.error(e);process.exitCode=1});
"""


_MODAL_PROBE = r"""
const fs=require('fs'),vm=require('vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const modalStart=html.indexOf('let confirmActive=false;');
const modalEnd=html.indexOf('/* 初回ロード',modalStart);
const refreshStart=html.indexOf('async function refresh(){');
const refreshEnd=html.indexOf(' // 直すべき設定',refreshStart);
if(modalStart<0||modalEnd<0||refreshStart<0||refreshEnd<0)
 throw new Error('dashboard modal/refresh source missing');
const elements={};
const document={activeElement:null,addEventListener(){},removeEventListener(){}};
const $=id=>elements[id]||(elements[id]={className:'',textContent:'',title:'',
  inert:false,checked:false,disabled:false,style:{display:'none'},onclick:null,
  isConnected:true,focus(){document.activeElement=this;}});
$("stateview");$("help");
const good={firewall:{enabled:true},shield:{cfg:{enabled:true}},
  shield_metrics:{},events:[],top:[]};
let next=good;
const ctx={refreshGeneration:0,$,document,tr:s=>s,errText:()=>"unavailable",
  isAuthFail:()=>false,markAuthError:()=>{},guardedFetch:async()=>{
    if(next===null)throw new Error('network');return next;}};
vm.createContext(ctx);
vm.runInContext(html.slice(modalStart,modalEnd)+'\n'+
                html.slice(refreshStart,refreshEnd)+'\n}',ctx);
(async()=>{
 await ctx.refresh();
 const pending=ctx.confirmDialog('remove rule');
 const opened=elements.confirmOverlay.style.display;
 next=null;await ctx.refresh();
 const failed=elements.conn.className;
 const handlerAfterFailure=typeof elements.confirmOk.onclick;
 if(handlerAfterFailure==='function')elements.confirmOk.onclick();
 const decision=await Promise.race([pending,
  new Promise(resolve=>setTimeout(()=>resolve('timeout'),500))]);
 next=good;await ctx.refresh();
 const invalidPrompt=ctx.confirmDialog('invalid state action');
 next={firewall:{enabled:true},shield:{error:'source unavailable'},
       shield_metrics:{},events:[],top:[]};await ctx.refresh();
 if(typeof elements.confirmOk.onclick==='function')elements.confirmOk.onclick();
 const invalidDecision=await Promise.race([invalidPrompt,
  new Promise(resolve=>setTimeout(()=>resolve('timeout'),500))]);
 next=good;await ctx.refresh();
 const newPrompt=ctx.confirmDialog('new action');
 elements.confirmCancel.onclick();
 const newCanceled=await newPrompt;
 process.stdout.write(JSON.stringify({opened,failed,handlerAfterFailure,
                                      decision,invalidDecision,newCanceled}));
})().catch(e=>{console.error(e);process.exitCode=1});
"""


def test_failed_refresh_disables_stale_dashboard_then_recovers():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js unavailable for dashboard execution")
    base = os.environ["DUCKNET_STATE_DIR"]
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-gui-stale-", dir=base) as state:
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               token="gui-stale-probe", state_dir=state)
        try:
            assert admin.start()["ok"]
            status, html = _get(admin.port, "/")
            assert status == 200
        finally:
            admin.stop()
        html_path = Path(state, "dashboard.html")
        html_path.write_bytes(html)
        probe = subprocess.run([node, "-e", _PROBE, str(html_path)],
                               capture_output=True, timeout=15)
        assert probe.returncode == 0, probe.stderr.decode("utf-8", "replace")
        shown = json.loads(probe.stdout)
        assert shown["initial"] == {"inert": True}
        assert shown["healthy"] == {"inert": False, "conn": "pill ok", "fw": True}
        # Old runtime left a live, clickable checked control from the prior
        # successful refresh while only the tiny connection pill turned red.
        assert shown["failed"] == {"inert": True, "conn": "pill bad", "fw": True}
        assert shown["recovered"] == {"inert": False, "conn": "pill ok", "fw": True}
        assert shown["invalid"] == {"inert": True, "conn": "pill bad", "fw": True}
        assert shown["recoveredAgain"] == {"inert": False, "conn": "pill ok", "fw": True}
        assert b'<div class="wrap state-stale" id="stateview" inert>' in html


def test_failed_refresh_cancels_open_confirmation_before_mutation():
    node = shutil.which("node")
    if not node:
        raise SkipTest("Node.js unavailable for dashboard execution")
    base = os.environ["DUCKNET_STATE_DIR"]
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-modal-stale-", dir=base) as state:
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               token="gui-modal-probe", state_dir=state)
        try:
            assert admin.start()["ok"]
            status, html = _get(admin.port, "/")
            assert status == 200
        finally:
            admin.stop()
        html_path = Path(state, "dashboard.html")
        html_path.write_bytes(html)
        probe = subprocess.run([node, "-e", _MODAL_PROBE, str(html_path)],
                               capture_output=True, timeout=15)
        assert probe.returncode == 0, probe.stderr.decode("utf-8", "replace")
        shown = json.loads(probe.stdout)
        assert shown["opened"] == "flex"
        assert shown["failed"] == "pill bad"
        # Old runtime left the modal active and its confirm button returned true.
        assert shown["decision"] is False, shown
        assert shown["invalidDecision"] is False, shown
        assert shown["handlerAfterFailure"] == "object"  # null handler
        assert shown["newCanceled"] is False
