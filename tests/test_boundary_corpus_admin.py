"""Benign mutation tables for strict management input and atomic rejection."""
import copy
import json
from pathlib import Path
from test_sweep_admin_ui import _Admin

_ROUTES=("/api/firewall/toggle","/api/shield/toggle","/api/global_block")
_WRONG=(None,0,1,"true","false",[],{})

def _snapshot(admin):
    return copy.deepcopy((admin.sh.cfg,admin.fw.enabled,admin.fw.policy,admin.fw.rules))

def _audit(admin):
    path=Path(admin.adm._audit_path)
    return path.read_bytes() if path.exists() else b""

def test_boolean_mutation_table_rejects_nonbooleans_without_partial_application():
    with _Admin() as admin:
        before,log=_snapshot(admin),_audit(admin)
        for route in _ROUTES:
            for value in _WRONG:
                code,result=admin.post(route,{"on":value})
                assert code==400 and result["ok"] is False,(route,type(value).__name__,code)
                assert _snapshot(admin)==before and _audit(admin)==log

def test_root_json_shape_table_cannot_be_coerced_into_a_mutation():
    with _Admin() as admin:
        before,log=_snapshot(admin),_audit(admin)
        for route in _ROUTES:
            for value in (None,[],[{}],"fixture",7,True):
                code,result=admin.post(route,raw=json.dumps(value).encode())
                assert code==400 and result["ok"] is False,(route,type(value).__name__,code)
                assert _snapshot(admin)==before and _audit(admin)==log

def test_invalid_json_table_does_not_become_an_empty_default_command():
    bodies=(b'{"on":',b'{"on":false} trailing',b'{"on":NaN}',
            b'{"on":false,"on":true}',b'\xff{"on":false}')
    with _Admin() as admin:
        before,log=_snapshot(admin),_audit(admin)
        for route in _ROUTES:
            for raw in bodies:
                code,result=admin.post(route,raw=raw)
                assert code==400 and result["ok"] is False,(route,code)
                assert _snapshot(admin)==before and _audit(admin)==log

def test_mixed_config_table_rejects_the_whole_replacement_before_publication():
    with _Admin() as admin:
        before,log=_snapshot(admin),_audit(admin)
        target=admin.sh.cfg["deny_score"]+1
        for value in (None,0,1,"false",[],{}):
            code,result=admin.post("/api/shield/config",{"deny_score":target,"enabled":value})
            # Invalid values are rejected before the cluster mutation gate.
            assert code==400 and result["ok"] is False,(type(value).__name__,code)
            assert _snapshot(admin)==before and _audit(admin)==log

def test_real_boolean_control_still_applies_and_records_the_matching_value():
    with _Admin() as admin:
        for value in (False,True):
            code,result=admin.post("/api/shield/toggle",{"on":value})
            assert code==200 and result["ok"] is True and admin.sh.is_enabled() is value
            entry=admin.get("/api/admin_audit")["entries"][0]
            assert entry["after"] is value
            assert entry["revert"]["body"]["on"] is (not value)

def test_unknown_config_keys_are_rejected_at_the_api_without_applying_known_peers():
    for body in ({"fixture_unknown_option":False},
                 {"fixture_unknown_option":False,"enabled":False}):
        with _Admin() as admin:
            before,log=_snapshot(admin),_audit(admin)
            code,result=admin.post("/api/shield/config",body)
            assert code==400 and result["ok"] is False
            assert _snapshot(admin)==before and _audit(admin)==log

def test_nonstandard_json_member_cannot_be_ignored_before_a_real_update():
    bodies=(b'{"on":false,"fixture":"\xff"}',
            b'{"on":false,"fixture":NaN}',b'{"on":false,"fixture":Infinity}',
            b'{"on":false,"fixture":1e999}')
    for raw in bodies:
        with _Admin() as admin:
            before,log=_snapshot(admin),_audit(admin)
            code,result=admin.post("/api/firewall/toggle",raw=raw)
            assert code==400 and result["ok"] is False
            assert _snapshot(admin)==before and _audit(admin)==log
