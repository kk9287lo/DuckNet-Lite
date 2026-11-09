"""Admin ACL rule requests must not silently reinterpret a misspelled action."""

import copy
from unittest.mock import patch

from dataplane import admin as admin_module
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_admin_ui import _Admin


def test_rule_add_requires_explicit_action_and_rejects_unknown_fields_on_real_http():
    with _Admin() as admin:
        net = "8.8.8.8/32"
        status, added = admin.post("/api/firewall/rule", {"net": net, "action": "allow"})
        assert status == 200 and added["ok"] is True
        assert admin.fw.evaluate("8.8.8.8")["action"] == "allow"
        baseline_audit = admin.get("/api/admin_audit")["entries"]

        for body in ({"net": net, "actoin": "allow"},
                     {"net": net},
                     {"net": net, "action": "deny", "actoin": "allow"},
                     {"net": net, "action": False},
                     {"net": net, "action": []}):
            status, rejected = admin.post("/api/firewall/rule", body)
            assert status == 400 and rejected["ok"] is False, (body, status, rejected)
            assert admin.fw.evaluate("8.8.8.8")["action"] == "allow"
            assert AppFirewall(state_dir=admin.tmp.name).evaluate("8.8.8.8")["action"] == "allow"
            assert admin.get("/api/admin_audit")["entries"] == baseline_audit

        status, changed = admin.post("/api/firewall/rule", {"net": net, "action": "deny"})
        assert status == 200 and changed["ok"] is True
        assert admin.fw.evaluate("8.8.8.8")["action"] == "deny"
        assert AppFirewall(state_dir=admin.tmp.name).evaluate("8.8.8.8")["action"] == "deny"


def test_rule_remove_rejects_ignored_fields_before_live_or_signed_change():
    with _Admin() as admin:
        net = "1.1.1.1/32"
        status, added = admin.post("/api/firewall/rule", {"net": net, "action": "allow"})
        assert status == 200 and added["ok"] is True
        baseline_audit = admin.get("/api/admin_audit")["entries"]

        for body in ({"op": "remove", "net": net, "action": "deny"},
                     {"op": "remove", "net": net, "actoin": "deny"}):
            status, rejected = admin.post("/api/firewall/rule", body)
            assert status == 400 and rejected["ok"] is False, (body, status, rejected)
            assert admin.fw.evaluate("1.1.1.1")["action"] == "allow"
            assert AppFirewall(state_dir=admin.tmp.name).evaluate("1.1.1.1")["action"] == "allow"
            assert admin.get("/api/admin_audit")["entries"] == baseline_audit

        status, removed = admin.post("/api/firewall/rule", {"op": "remove", "net": net})
        assert status == 200 and removed["ok"] is True and removed["removed"] == 1
        assert not any(rule["net"] == net for rule in admin.fw.rules)
        assert not any(rule["net"] == net for rule in AppFirewall(state_dir=admin.tmp.name).rules)


def test_invalid_rule_operation_cannot_quiesce_live_cluster_before_rejection():
    with _Admin() as admin:
        net = "8.8.8.8/32"
        status, added = admin.post("/api/firewall/rule", {"net": net, "action": "allow"})
        assert status == 200 and added["ok"] is True
        quiesced = []

        class Guard:
            _workers = [123]

            def quiesce_cluster_for_mutation(self):
                quiesced.append(True)
                return {"ok": True, "cluster_downgraded": False}

        admin.adm.edge_guard = Guard()
        for body in ({"net": net, "action": "invalid"},
                     {"op": "remove", "net": net, "action": "deny"},
                     {"op": "invalid", "net": net, "action": "deny"}):
            status, rejected = admin.post("/api/firewall/rule", body)
            assert status == 400 and rejected["ok"] is False, (body, status, rejected)
            assert quiesced == [], (body, quiesced)
            assert admin.fw.evaluate("8.8.8.8")["action"] == "allow"

        status, changed = admin.post("/api/firewall/rule", {"net": net, "action": "deny"})
        assert status == 200 and changed["ok"] is True
        assert quiesced == [True]
        assert admin.fw.evaluate("8.8.8.8")["action"] == "deny"


def test_invalid_policy_and_signature_enums_cannot_quiesce_live_cluster():
    with _Admin() as admin:
        quiesced = []

        class Guard:
            _workers = [123]

            def quiesce_cluster_for_mutation(self):
                quiesced.append(True)
                return {"ok": True, "cluster_downgraded": False}

        admin.adm.edge_guard = Guard()
        prior_policy = copy.deepcopy(admin.fw.policy)
        prior_cfg = copy.deepcopy(admin.sh.cfg)
        bad = (
            ("/api/firewall/policy", {"zone": "public", "action": "alllow"}),
            ("/api/firewall/policy", {"zone": "publci", "action": "allow"}),
            ("/api/shield/optional_sig", {"name": "sstii", "on": True}),
            ("/api/shield/paranoia", {"level": "max"}),
            ("/api/shield/paranoia", {"level": 0}),
            ("/api/shield/paranoia", {"level": 999}),
            ("/api/shield/paranoia", {"level": 10 ** 400}),
            ("/api/shield/paranoia", {"level": 2,
                                      "optional_sigs": {"sstii": True}}),
        )
        for endpoint, body in bad:
            status, rejected = admin.post(endpoint, body)
            assert status == 400 and rejected["ok"] is False, (endpoint, body, status, rejected)
            assert quiesced == [], (endpoint, body, quiesced)
            assert admin.fw.policy == prior_policy
            assert admin.sh.cfg == prior_cfg

        status, accepted = admin.post("/api/firewall/policy",
                                      {"zone": "public", "action": "prompt"})
        assert status == 200 and accepted["ok"] is True
        assert quiesced == [True]
        assert admin.fw.policy["public"] == "prompt"
        status, accepted = admin.post("/api/shield/optional_sig",
                                      {"name": "ssti", "on": True})
        assert status == 200 and accepted["ok"] is True
        assert quiesced == [True, True]
        status, accepted = admin.post("/api/shield/paranoia", {"level": 2})
        assert status == 200 and accepted["ok"] is True and accepted["paranoia"] == 2
        assert quiesced == [True, True, True]


def test_invalid_config_patch_cannot_quiesce_cluster_before_existing_validator_rejects():
    with _Admin() as admin:
        quiesced = []

        class Guard:
            _workers = [123]

            def quiesce_cluster_for_mutation(self):
                quiesced.append(True)
                return {"ok": True, "cluster_downgraded": False}

        admin.adm.edge_guard = Guard()
        prior_cfg = copy.deepcopy(admin.sh.cfg)
        prior_audit = admin.get("/api/admin_audit")["entries"]
        for body in ({"body_scan_max_bytes": -1},
                     {"body_scan_max_bytes": 999999},
                     {"body_scan_max_bytes": True},
                     {"rate_per_sec": -1}):
            status, rejected = admin.post("/api/shield/config", body)
            assert status == 400 and rejected["ok"] is False, (body, status, rejected)
            assert quiesced == [], (body, quiesced)
            assert admin.sh.cfg == prior_cfg
            assert admin.get("/api/admin_audit")["entries"] == prior_audit

        with patch.object(admin.sh, "_coerce_cfg", side_effect=OSError("validator unavailable")):
            status, unavailable = admin.post("/api/shield/config",
                                              {"body_scan_max_bytes": 131072})
        assert status == 503 and unavailable["ok"] is False
        assert quiesced == [] and admin.sh.cfg == prior_cfg

        status, changed = admin.post("/api/shield/config", {"body_scan_max_bytes": 131072})
        assert status == 200 and changed["ok"] is True
        assert quiesced == [True]
        assert admin.sh.cfg["body_scan_max_bytes"] == 131072
        assert NetShield(state_dir=admin.tmp.name).cfg["body_scan_max_bytes"] == 131072


def test_every_admin_post_route_rejects_ignored_fields_without_mutation():
    # Keep the accepted schema in step with every implemented mutation route.
    assert set(admin_module._POST_FIELDS) == (
        admin_module._AUDIT_KNOWN_ENDPOINTS | {"/api/shield/sig_test"})
    with _Admin() as admin:
        cases = (
            ("/api/firewall/toggle", {"on": False}),
            ("/api/firewall/policy", {"zone": "public", "action": "allow"}),
            ("/api/firewall/rule", {"net": "8.8.8.8/32", "action": "allow"}),
            ("/api/firewall/resolve", {"id": "p1", "approve": True}),
            ("/api/shield/toggle", {"on": False}),
            ("/api/shield/config", {"body_scan_enabled": False}),
            ("/api/shield/optional_sig", {"name": "ssti", "on": True}),
            ("/api/shield/paranoia", {"level": 2}),
            ("/api/shield/path_limits", {"rules": []}),
            ("/api/shield/blocked_methods", {"methods": []}),
            ("/api/shield/sig_add", {"name": "round18", "pattern": "round18marker"}),
            ("/api/shield/sig_remove", {"name": "round18"}),
            ("/api/shield/unban", {"ip": "8.8.8.8"}),
            ("/api/shield/ban", {"ip": "8.8.8.8"}),
            ("/api/appeal/resolve", {"ip": "8.8.8.8", "approve": True}),
            ("/api/global_block", {"on": False}),
            ("/api/shield/sig_test", {"pattern": "round18marker", "sample": "round18marker"}),
        )
        fw = (admin.fw.enabled, copy.deepcopy(admin.fw.policy), copy.deepcopy(admin.fw.rules))
        cfg = copy.deepcopy(admin.sh.cfg)
        audit = admin.get("/api/admin_audit")["entries"]
        for endpoint, valid in cases:
            status, rejected = admin.post(endpoint, {**valid, "unused_field": "ignored"})
            assert status == 400 and rejected["ok"] is False, (endpoint, status, rejected)
            assert (admin.fw.enabled, admin.fw.policy, admin.fw.rules) == fw, endpoint
            assert admin.sh.cfg == cfg, endpoint
            assert not admin.sh.is_banned_fast("8.8.8.8"), endpoint
            assert admin.get("/api/admin_audit")["entries"] == audit, endpoint


def test_unsupported_manual_ban_options_cannot_claim_success():
    with _Admin() as admin:
        ip = "8.8.8.8"
        audit = admin.get("/api/admin_audit")["entries"]
        status, rejected = admin.post("/api/shield/ban", {"ip": ip, "permanent": True})
        assert status == 400 and rejected["ok"] is False, (status, rejected)
        assert not admin.sh.is_banned_fast(ip)
        assert admin.get("/api/admin_audit")["entries"] == audit
        status, banned = admin.post("/api/shield/ban", {"ip": ip})
        assert status == 200 and banned["ok"] is True and banned["permanent"] is False
        assert admin.sh.is_banned_fast(ip)


def test_misspelled_signature_weight_cannot_claim_success():
    with _Admin() as admin:
        audit = admin.get("/api/admin_audit")["entries"]
        name, pattern = "round18_weight", "round18weightmarker"
        status, rejected = admin.post("/api/shield/sig_add",
                                      {"name": name, "pattern": pattern, "weigth": 90})
        assert status == 400 and rejected["ok"] is False, (status, rejected)
        assert not any(rule["name"] == name for rule in admin.sh._custom)
        assert admin.get("/api/admin_audit")["entries"] == audit

        status, added = admin.post("/api/shield/sig_add",
                                   {"name": name, "pattern": pattern, "weight": 90})
        assert status == 200 and added["ok"] is True
        assert next(rule for rule in admin.sh._custom if rule["name"] == name)["weight"] == 90
