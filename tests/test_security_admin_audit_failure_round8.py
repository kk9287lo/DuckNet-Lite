"""A committed admin change must disclose an undurable audit append."""

import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import SkipTest
from unittest.mock import patch

import dataplane.admin as A
import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield
from test_falco_admin_boundaries import _Admin, _signed


def test_failed_audit_append_reports_partial_success_without_rollback():
    for browser, failure in ((False, False), (True, OSError("synthetic write failure"))):
        with _Admin() as admin:
            admin.sh.cfg["persist_bans"] = True
            assert admin.sh.enable()["ok"] is True
            assert NetShield(state_dir=admin.tmp.name).cfg["enabled"] is True
            body = b'{"on":false}'
            credentials = (_signed(admin, "POST", "/api/shield/toggle", body)
                           if browser else [("X-Token", admin.token)])
            kwargs = ({"side_effect": failure} if isinstance(failure, OSError)
                      else {"return_value": failure})
            with patch.object(A, "append_jsonl", **kwargs):
                status, headers, wire_body = admin.request(credentials, body=body)
            result = json.loads(wire_body)
            assert status == 200 and result["ok"] is True and result["enabled"] is False
            assert result.get("audit_recorded") is False and result.get("warning"), result
            assert admin.sh.is_enabled() is False
            assert NetShield(state_dir=admin.tmp.name).cfg["enabled"] is False
            assert not Path(admin.tmp.name, "admin_audit.jsonl").exists()
            if browser:
                nonce = dict(credentials)["X-Admin-Auth-Nonce"]
                message = (admin.adm._browser_instance_id + "\n" + nonce + "\n200\n"
                           + hashlib.sha256(wire_body).hexdigest())
                expected = hmac.new(admin.token.encode(), message.encode(), hashlib.sha256).hexdigest()
                assert headers.get("X-Admin-Response-Mac") == expected


def test_successful_audit_append_keeps_normal_response_and_saved_row():
    with _Admin() as admin:
        admin.sh.cfg["persist_bans"] = True
        assert admin.sh.enable()["ok"] is True
        assert NetShield(state_dir=admin.tmp.name).cfg["enabled"] is True
        status, _headers, wire_body = admin.request([("X-Token", admin.token)])
        result = json.loads(wire_body)
        assert status == 200 and result["ok"] is True and result["enabled"] is False
        assert result.get("audit_recorded") is not False and "warning" not in result
        assert admin.sh.is_enabled() is False
        assert NetShield(state_dir=admin.tmp.name).cfg["enabled"] is False
        path = Path(admin.tmp.name, "admin_audit.jsonl")
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        assert len(rows) == 1 and rows[0]["endpoint"] == "/api/shield/toggle"


def test_save_and_audit_failures_report_both_without_hiding_live_ban():
    with _Admin() as admin:
        admin.sh.cfg["persist_bans"] = True
        assert admin.sh.enable()["ok"] is True
        ip = "192.0.2.55"
        body = json.dumps({"ip": ip}).encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=3)
        try:
            with patch.object(P, "write_signed_json", return_value=False), \
                    patch.object(A, "append_jsonl", return_value=False):
                connection.request("POST", "/api/shield/ban", body=body,
                                   headers={"Host": "127.0.0.1", "X-Token": admin.token,
                                            "Content-Type": "application/json"})
                response = connection.getresponse()
                wire_status, wire_body = response.status, response.read()
        finally:
            connection.close()
        result = json.loads(wire_body)
        assert wire_status == 200 and result["ok"] is False
        assert result["applied_in_memory"] is True and result["persisted"] is False
        assert result.get("audit_recorded") is False and result.get("warning")
        assert admin.sh.is_banned_fast(ip) is True
        assert NetShield(state_dir=admin.tmp.name).is_banned_fast(ip) is False
        assert not Path(admin.tmp.name, "admin_audit.jsonl").exists()


def test_dashboard_warns_when_change_applied_but_audit_was_not_saved():
    node = shutil.which("node")
    if not node:
        raise SkipTest("node が無い環境")
    assert "async function postT(" in A._HTML
    source = ("async function postT(" + A._HTML.split("async function postT(", 1)[1]
              .split("/* 確認ダイアログ", 1)[0])
    script = ("const notices=[];let result={ok:true,audit_recorded:false,warning:'audit write failed'};"
              "function tr(s){return s;}function busy(){}"
              "function toast(m,k){notices.push([m,k]);}"
              "async function post(){return result;}\n"
              + source + "\n(async()=>{await postT('/api/shield/toggle',{on:false},null,'updated');"
              "result={ok:false,error:'state save failed',applied_in_memory:true,audit_recorded:false};"
              "await postT('/api/shield/ban',{ip:'192.0.2.55'},null,'updated');"
              "process.stdout.write(JSON.stringify(notices));})().catch(e=>{console.error(e);process.exit(1);});")
    with tempfile.TemporaryDirectory() as directory:
        probe = Path(directory, "probe.js")
        probe.write_text(script, encoding="utf-8")
        proc = subprocess.run([node, str(probe)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=10,
                              env={**os.environ, "NODE_OPTIONS": ""})
    assert proc.returncode == 0, proc.stderr
    notices = json.loads(proc.stdout)
    assert len(notices) == 3 and all(kind == "err" for _text, kind in notices), notices
    assert "監査ログ" in notices[0][0] and "state save failed" in notices[1][0]
    assert "監査ログ" in notices[2][0]


def test_bulk_admin_actions_warn_about_unaudited_applied_changes():
    node = shutil.which("node")
    if not node:
        raise SkipTest("node が無い環境")
    page = A._HTML
    selected = ("async function unbanSelected(" + page.split("async function unbanSelected(", 1)[1]
                .split("/* 一括操作の結果", 1)[0])
    report = ("function bulkReport(" + page.split("function bulkReport(", 1)[1]
              .split("async function unbanAll(", 1)[0])
    all_bans = ("async function unbanAll(" + page.split("async function unbanAll(", 1)[1]
                .split("/* 攻撃イベント", 1)[0])
    approve = ("async function approveAllPending(" + page.split("async function approveAllPending(", 1)[1]
               .split("async function denyAllPending(", 1)[0])
    deny = ("async function denyAllPending(" + page.split("async function denyAllPending(", 1)[1]
            .split('$("fw").onchange', 1)[0])
    script = ("const notices=[];const banSel=new Set(['192.0.2.1']);"
              "const curBans=[{ip:'192.0.2.2'}],curPending=[{id:'p1'}];"
              "function tr(s){return s;}function busy(){}function refresh(){}"
              "async function confirmDialog(){return true;}"
              "async function post(){return {ok:true,audit_recorded:false};}"
              "function toast(m,k){notices.push([m,k]);}\n"
              + selected + report + all_bans + approve + deny + "\n"
              "(async()=>{await unbanSelected(null);await unbanAll(null);"
              "await approveAllPending(null);await denyAllPending(null);"
              "process.stdout.write(JSON.stringify(notices));})().catch(e=>{console.error(e);process.exit(1);});")
    with tempfile.TemporaryDirectory() as directory:
        probe = Path(directory, "probe.js")
        probe.write_text(script, encoding="utf-8")
        proc = subprocess.run([node, str(probe)], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=10,
                              env={**os.environ, "NODE_OPTIONS": ""})
    assert proc.returncode == 0, proc.stderr
    notices = json.loads(proc.stdout)
    assert len(notices) == 4 and all(kind == "err" and "監査ログ" in text
                                     for text, kind in notices), notices
