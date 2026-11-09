"""Management egress and durable audit logs must not echo incidental secrets."""
from __future__ import annotations

import http.client
import json
from pathlib import Path
from unittest import mock

from test_sweep_admin_ui import _Admin


_SECRET = "fixture_secret_admin_egress_20261102"


def _request(admin, method, path, *, body=None, headers=None):
    supplied = {"X-Token": admin.token}
    supplied.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        supplied["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
    try:
        conn.request(method, path, body=data, headers=supplied)
        response = conn.getresponse()
        return response.status, response.headers, response.read()
    finally:
        conn.close()


def test_internal_get_errors_do_not_reflect_exception_text_to_wire():
    with _Admin() as admin:
        with mock.patch.object(admin.adm, "state", side_effect=RuntimeError(_SECRET)):
            code, headers, body = _request(admin, "GET", "/api/state")
        assert code == 500 and _SECRET.encode() not in body
        assert json.loads(body)["ok"] is False
        assert headers.get("Cache-Control") == "no-store"
        with mock.patch.object(admin.sh, "status", side_effect=RuntimeError(_SECRET)):
            code, headers, body = _request(admin, "GET", "/api/state")
        state = json.loads(body)
        assert code == 200 and _SECRET.encode() not in body
        assert "error" in state["shield"] and "firewall" in state
        assert headers.get("Cache-Control") == "no-store"
        good = _request(admin, "GET", "/api/state")
        assert good[0] == 200 and "cfg" in json.loads(good[2])["shield"]


def test_internal_post_errors_do_not_reflect_exception_text_to_wire():
    with _Admin() as admin:
        with mock.patch.object(admin.sh, "set_config", side_effect=RuntimeError(_SECRET)):
            code, headers, body = _request(admin, "POST", "/api/shield/config",
                                           body={"dlp_enabled": True})
        assert code == 500 and json.loads(body)["ok"] is False
        assert _SECRET.encode() not in body and headers.get("Cache-Control") == "no-store"
        good = _request(admin, "POST", "/api/shield/config", body={"dlp_enabled": True})
        assert good[0] == 200 and json.loads(good[2])["ok"] is True


def test_audit_keeps_operation_but_not_signature_pattern_or_secret_url():
    with _Admin() as admin:
        name = "fixture_literal_rule"
        code, result = admin.post("/api/shield/sig_add", {"name": name, "pattern": _SECRET})
        assert code == 200 and result["ok"] is True
        code, result = admin.post("/api/shield/sig_remove", {"name": name})
        assert code == 200 and result["ok"] is True
        private_url = "/safe?access_token=" + _SECRET
        code, result = admin.post("/api/shield/config", {"open_redirect_safe_path": private_url})
        assert code == 200 and result["ok"] is True
        code, result = admin.post("/api/shield/config", {"open_redirect_safe_path": "/safe"})
        assert code == 200 and result["ok"] is True
        entries = admin.get("/api/admin_audit")["entries"]
        assert any(e["endpoint"] == "/api/shield/sig_add" for e in entries)
        assert any(e["endpoint"] == "/api/shield/config" for e in entries)
        raw = Path(admin.adm._audit_path).read_bytes()
        assert _SECRET.encode() not in raw
        assert _SECRET not in json.dumps(entries)
        current = admin.get("/api/shield/signatures")
        assert all(s.get("name") != name for s in current["custom"])


def test_simple_scalar_audit_revert_still_records_real_value():
    with _Admin() as admin:
        before = bool(admin.sh.cfg["dlp_enabled"])
        code, result = admin.post("/api/shield/config", {"dlp_enabled": not before})
        assert code == 200 and result["ok"] is True
        entry = admin.get("/api/admin_audit")["entries"][0]
        assert entry["endpoint"] == "/api/shield/config"
        assert entry["before"] == {"dlp_enabled": before}
        assert entry["after"] == {"dlp_enabled": not before}
        assert entry["revert"] == {"endpoint": "/api/shield/config",
                                   "body": {"dlp_enabled": before}}


def test_path_and_method_audit_keeps_counts_without_secondary_values():
    with _Admin() as admin:
        path = "/private/" + _SECRET
        code, result = admin.post("/api/shield/path_limits", {"rules": [
            {"path": path, "rate": 1, "burst": 2}]})
        assert code == 200 and result["ok"] is True
        method = "SECRETXYZ"
        code, result = admin.post("/api/shield/blocked_methods", {"methods": [method]})
        assert code == 200 and result["ok"] is True
        entries = admin.get("/api/admin_audit")["entries"]
        assert {row["endpoint"] for row in entries} == {
            "/api/shield/path_limits", "/api/shield/blocked_methods"}
        assert all(row["revert"] is None for row in entries)
        assert all(isinstance(row["after"], list) for row in entries)
        assert _SECRET not in json.dumps(entries) and method not in json.dumps(entries)
        raw = Path(admin.adm._audit_path).read_text(encoding="utf-8")
        assert _SECRET not in raw and method not in raw


def test_mixed_config_audit_disables_undo_if_any_value_is_freeform():
    with _Admin() as admin:
        code, result = admin.post("/api/shield/config", {
            "dlp_enabled": True, "open_redirect_safe_path": "/safe?token=" + _SECRET})
        assert code == 200 and result["ok"] is True
        entry = admin.get("/api/admin_audit")["entries"][0]
        assert entry["before"]["dlp_enabled"] is False
        assert entry["after"]["dlp_enabled"] is True
        assert entry["revert"] is None
        assert _SECRET not in json.dumps(entry)


def test_fixed_enum_and_numeric_config_undo_remain_available():
    with _Admin() as admin:
        for key, value in (("mode", "audit"), ("rate_per_sec", 13.0)):
            before = admin.sh.cfg[key]
            code, result = admin.post("/api/shield/config", {key: value})
            assert code == 200 and result["ok"] is True
            entry = admin.get("/api/admin_audit")["entries"][0]
            assert entry["before"] == {key: before}
            assert entry["after"] == {key: value}
            assert entry["revert"] == {"endpoint": "/api/shield/config",
                                       "body": {key: before}}


def test_rule_removal_audit_keeps_cidr_action_but_drops_freeform_note():
    with _Admin() as admin:
        net = "198.51.100.61/32"
        assert admin.fw.add_rule(net, "deny", note=_SECRET)["ok"]
        code, result = admin.post("/api/firewall/rule", {"op": "remove", "net": net})
        assert code == 200 and result["ok"] is True
        entries = admin.get("/api/admin_audit")["entries"]
        assert len(entries) == 1 and entries[0]["endpoint"] == "/api/firewall/rule"
        assert entries[0]["before"]["net"] == net
        assert entries[0]["before"]["action"] == "deny"
        assert "note" not in entries[0]["before"]
        assert _SECRET not in Path(admin.adm._audit_path).read_text(encoding="utf-8")
        assert _SECRET not in json.dumps(entries)
        # A legacy row is masked on API read without rewriting the old file.
        old = {"ts": 1, "endpoint": "/api/firewall/rule",
               "summary": "rule removed " + _SECRET,
               "before": {"net": net, "action": "deny", "note": _SECRET},
               "after": None, "revert": None}
        with Path(admin.adm._audit_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(old) + "\n")
        code, _headers, body = _request(admin, "GET", "/api/admin_audit")
        assert code == 200 and _SECRET.encode() not in body
        assert _SECRET in Path(admin.adm._audit_path).read_text(encoding="utf-8")


def test_unknown_legacy_audit_endpoint_keeps_no_untrusted_freeform_text():
    with _Admin() as admin:
        old = {"ts": 1, "endpoint": "/api/unknown?token=" + _SECRET,
               "summary": _SECRET, "before": {"secret": _SECRET},
               "after": _SECRET, "revert": {"endpoint": _SECRET, "body": _SECRET}}
        Path(admin.adm._audit_path).write_text(json.dumps(old) + "\n", encoding="utf-8")
        code, _headers, body = _request(admin, "GET", "/api/admin_audit")
        assert code == 200 and _SECRET.encode() not in body
        entry = json.loads(body)["entries"][0]
        assert entry["summary"] and entry["revert"] is None


def test_known_legacy_audit_rebuilds_summary_and_undo_without_extra_fields():
    with _Admin() as admin:
        old = {"ts": 1, "endpoint": "/api/shield/toggle", "summary": _SECRET,
               "before": True, "after": False,
               "revert": {"endpoint": "/api/shield/toggle",
                          "body": {"on": True, "token": _SECRET}}}
        Path(admin.adm._audit_path).write_text(json.dumps(old) + "\n", encoding="utf-8")
        code, _headers, body = _request(admin, "GET", "/api/admin_audit")
        assert code == 200 and _SECRET.encode() not in body
        row = json.loads(body)["entries"][0]
        assert row["before"] is True and row["after"] is False
        assert row["summary"] == "shield disabled"
        assert row["revert"] == {"endpoint": "/api/shield/toggle", "body": {"on": True}}


def test_scoped_ban_keeps_actual_result_but_not_scope_text_in_audit():
    with _Admin() as admin:
        raw_ip = "fe80::1%" + _SECRET
        code, result = admin.post("/api/shield/ban", {"ip": raw_ip})
        assert code == 200 and result["ok"] is True
        rows = admin.get("/api/admin_audit")["entries"]
        assert len(rows) == 1 and rows[0]["endpoint"] == "/api/shield/ban"
        assert rows[0]["after"]["ip"] == "fe80::1"
        assert _SECRET not in json.dumps(rows)
        assert _SECRET.encode() not in Path(admin.adm._audit_path).read_bytes()


def test_known_legacy_audit_schemas_strip_extra_fields_and_keep_typed_undo():
    scoped = "fe80::1%" + _SECRET
    rows = [
        ("/api/firewall/toggle", True, False,
         {"endpoint": "/api/firewall/toggle", "body": {"on": True, "extra": _SECRET}}),
        ("/api/firewall/policy", "allow", "deny", {"body": {"extra": _SECRET}}),
        ("/api/firewall/resolve", None,
         {"id": "p7", "approve": True, "remember": False, "ip": scoped,
          "extra": _SECRET}, {"body": {"extra": _SECRET}}),
        ("/api/shield/optional_sig", False, True,
         {"endpoint": "/api/shield/optional_sig",
          "body": {"name": "ssti", "on": False, "extra": _SECRET}}),
        ("/api/shield/paranoia", 1, 2,
         {"endpoint": "/api/shield/paranoia",
          "body": {"level": 1, "optional_sigs": {"ssti": True}, "extra": _SECRET}}),
        ("/api/shield/unban", {"ip": scoped, "extra": _SECRET},
         {"ip": scoped, "persisted": True, "applied_in_memory": True,
          "extra": _SECRET}, {"body": {"extra": _SECRET}}),
        ("/api/appeal/resolve", None,
         {"ip": scoped, "approve": True, "extra": _SECRET},
         {"body": {"extra": _SECRET}}),
        ("/api/global_block", "allow", "deny", {"body": {"extra": _SECRET}}),
    ]
    with _Admin() as admin:
        legacy = [{"ts": i + 1, "endpoint": endpoint, "summary": _SECRET,
                   "before": before, "after": after, "revert": revert}
                  for i, (endpoint, before, after, revert) in enumerate(rows)]
        Path(admin.adm._audit_path).write_text(
            "".join(json.dumps(row) + "\n" for row in legacy), encoding="utf-8")
        code, _headers, body = _request(admin, "GET", "/api/admin_audit")
        assert code == 200 and _SECRET.encode() not in body
        result = {row["endpoint"]: row for row in json.loads(body)["entries"]}
        assert set(result) == {row[0] for row in rows}
        assert result["/api/firewall/toggle"]["revert"] == {
            "endpoint": "/api/firewall/toggle", "body": {"on": True}}
        assert result["/api/shield/optional_sig"]["revert"] == {
            "endpoint": "/api/shield/optional_sig", "body": {"name": "ssti", "on": False}}
        assert result["/api/shield/paranoia"]["revert"] == {
            "endpoint": "/api/shield/paranoia",
            "body": {"level": 1, "optional_sigs": {"ssti": True}}}
        assert result["/api/global_block"]["before"] == "allow"
        assert result["/api/global_block"]["after"] == "deny"
        for endpoint in ("/api/firewall/resolve", "/api/shield/unban",
                         "/api/appeal/resolve"):
            assert result[endpoint]["after"]["ip"] == "fe80::1"


def test_audit_privacy_is_idempotent_for_known_schema_and_real_rule_counts():
    from dataplane.admin import _AUDIT_KNOWN_ENDPOINTS, _audit_privacy

    typed = {
        "/api/firewall/toggle": (True, False, None),
        "/api/firewall/policy": ("allow", "deny", None),
        "/api/firewall/rule": (None, {"net": "192.0.2.0/24", "action": "deny",
                                         "note": _SECRET}, None),
        "/api/firewall/resolve": (None, {"id": "p7", "approve": True,
                                          "remember": False, "ip": "192.0.2.3"}, None),
        "/api/shield/toggle": (True, False, None),
        "/api/shield/config": ({"mode": "enforce"}, {"mode": "audit"}, None),
        "/api/shield/optional_sig": (False, True,
                                      {"body": {"name": "ssti", "on": False}}),
        "/api/shield/paranoia": (1, 2,
                                  {"body": {"level": 1, "optional_sigs": {"ssti": True}}}),
        "/api/shield/path_limits": ([], [{"path": "/one"}, {"path": "/two"}], None),
        "/api/shield/blocked_methods": ([], ["TRACE", "TRACK"], None),
        "/api/shield/sig_add": (None, {"name": _SECRET, "pattern": _SECRET}, None),
        "/api/shield/sig_remove": ({"name": _SECRET}, None, None),
        "/api/shield/unban": ({"ip": "192.0.2.3"}, {"ip": "192.0.2.3"}, None),
        "/api/shield/ban": (None, {"ip": "192.0.2.3"}, None),
        "/api/appeal/resolve": (None, {"ip": "192.0.2.3", "approve": True}, None),
        "/api/global_block": ("allow", "deny", None),
    }
    assert set(typed) == _AUDIT_KNOWN_ENDPOINTS
    for endpoint, (before, after, revert) in typed.items():
        row = {"ts": 1, "endpoint": endpoint, "summary": _SECRET,
               "before": before, "after": after, "revert": revert}
        masked = _audit_privacy(row)
        assert _SECRET not in json.dumps(masked), endpoint
        assert _audit_privacy(masked) == masked, endpoint
    with _Admin() as admin:
        for endpoint, body in (("/api/shield/path_limits", {"rules": [
                                  {"path": "/one", "rate": 1, "burst": 1},
                                  {"path": "/two", "rate": 2, "burst": 2}]}),
                               ("/api/shield/blocked_methods",
                                {"methods": ["TRACE", "TRACK"]})):
            code, result = admin.post(endpoint, body)
            assert code == 200 and result["ok"] is True
            stored = json.loads(Path(admin.adm._audit_path).read_text(
                encoding="utf-8").splitlines()[-1])
            shown = admin.get("/api/admin_audit")["entries"][0]
            assert stored["summary"] == shown["summary"] and "(2" in shown["summary"]


def test_base_http_errors_have_no_referrer_or_cacheable_secret_context():
    with _Admin() as admin:
        for method in ("HEAD", "OPTIONS"):
            code, headers, body = _request(admin, method, "/api/state",
                                           headers={"Origin": "https://other.example.invalid"})
            assert code == 501 and headers.get("Cache-Control") == "no-store"
            assert headers.get("Referrer-Policy") == "no-referrer"
            assert headers.get("Access-Control-Allow-Origin") is None
            assert _SECRET.encode() not in body
        good = _request(admin, "GET", "/api/state")
        assert good[0] == 200 and good[1].get("Referrer-Policy") == "no-referrer"


def test_acl_log_drops_invalid_source_text_and_unknown_work_fields():
    with _Admin() as admin:
        bad = admin.fw.evaluate("X-Forwarded-For=token=" + _SECRET, port=8443)
        assert bad["action"] == "pending" and _SECRET not in json.dumps(bad)
        assert admin.fw.write_acl_log({"ts": 1, "ip": "192.0.2.61", "zone": "public",
                                       "action": "deny", "reason": "synthetic", "token": _SECRET})
        raw = Path(admin.fw.log_path).read_bytes()
        assert _SECRET.encode() not in raw
        good = admin.fw.evaluate("192.0.2.61", port=8443)
        assert good["ip"] == "192.0.2.61" and good["action"] == "pending", good
        assert b'"ip": "192.0.2.61"' in Path(admin.fw.log_path).read_bytes()


def test_legacy_audit_read_masks_old_freeform_values_and_disables_secret_undo():
    with _Admin() as admin:
        path = Path(admin.adm._audit_path)
        old = {"ts": 1, "endpoint": "/api/shield/config",
               "summary": "config: open_redirect_safe_path -> " + _SECRET,
               "before": {"open_redirect_safe_path": "/old?token=" + _SECRET},
               "after": {"open_redirect_safe_path": "/new?token=" + _SECRET},
               "revert": {"endpoint": "/api/shield/config",
                          "body": {"open_redirect_safe_path": "/old?token=" + _SECRET}}}
        path.write_text(json.dumps(old) + "\n", encoding="utf-8")
        code, _headers, body = _request(admin, "GET", "/api/admin_audit")
        assert code == 200 and _SECRET.encode() not in body
        entry = json.loads(body)["entries"][0]
        assert entry["endpoint"] == "/api/shield/config" and entry["revert"] is None
        assert _SECRET in path.read_text(encoding="utf-8")  # read masking does not rewrite evidence


def test_unknown_serialized_object_and_stop_exception_do_not_echo_secret():
    class Hidden:
        def __str__(self):
            return _SECRET

    with _Admin() as admin:
        with mock.patch.object(admin.adm, "state", return_value={"unexpected": Hidden()}):
            code, _headers, body = _request(admin, "GET", "/api/state")
        assert code == 200 and _SECRET.encode() not in body
    with _Admin() as admin:
        with mock.patch.object(admin.adm._server, "shutdown", side_effect=RuntimeError(_SECRET)):
            result = admin.adm.stop()
        assert result["ok"] is False and _SECRET not in json.dumps(result)
