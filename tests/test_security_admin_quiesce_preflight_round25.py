"""Rejected admin replacements must not permanently demote fork workers."""

import copy
import http.client
import json
import os
from pathlib import Path

from dataplane.admin import AdminDashboard
from test_sweep_admin_ui import _Admin


_INVALID = (
    ("/api/shield/blocked_methods", {"methods": 42}),
    ("/api/shield/blocked_methods", {"methods": ["TRACE", 4]}),
    ("/api/shield/path_limits", {"rules": [{"path": "/login", "rate": -1}]}),
    ("/api/shield/path_limits", {"rules": [{"path": "/login", "rate": 1},
                                               {"path": "/ok", "rate": "fast"}]}),
)
_INVALID_OTHER = (
    ("/api/firewall/resolve", {"id": "missing-r25", "approve": True}),
    ("/api/firewall/rule", {"op": "remove", "net": "not-a-network"}),
    ("/api/firewall/rule", {"net": "not-a-network", "action": "allow"}),
    ("/api/shield/sig_add", {"name": "bad name!", "pattern": "r25marker"}),
    ("/api/shield/sig_add", {"name": "r25bad", "pattern": "(a+)+"}),
    ("/api/shield/sig_add", {"name": "r25bad", "pattern": "safe-r25", "weight": "NaN"}),
    ("/api/shield/sig_remove", {"name": []}),
    ("/api/shield/ban", {"ip": "not-an-ip"}),
    ("/api/shield/unban", {"ip": ""}),
    ("/api/appeal/resolve", {"ip": "127.0.0.1", "approve": True}),
    ("/api/appeal/resolve", {"ip": "127.0.0.1", "approve": True,
                              "note": 7}),
)
_NOOP_OTHER = (
    ("/api/shield/sig_remove", {"name": "missing-r25"}),
    ("/api/firewall/rule", {"op": "remove", "net": "198.51.100.42/32"}),
    ("/api/shield/unban", {"ip": "198.51.100.42"}),
    ("/api/shield/paranoia", {"level": 1}),
    ("/api/shield/optional_sig", {"name": "ssti", "on": False}),
    ("/api/global_block", {"on": False}),
)


def _post(port, token, path, body):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", path, body=json.dumps(body).encode("utf-8"),
                     headers={"X-Token": token, "Content-Type": "application/json"})
        reply = conn.getresponse()
        return reply.status, json.loads(reply.read())
    finally:
        conn.close()


def test_invalid_replacement_routes_do_not_quiesce_cluster_on_real_admin_http():
    with _Admin() as admin:
        class Guard:
            def __init__(self):
                self._workers = [123]
                self.quiesced = 0

            def quiesce_cluster_for_mutation(self):
                self.quiesced += 1
                self._workers.clear()
                return {"ok": True, "cluster_downgraded": True}

        guard = Guard()
        admin.adm.edge_guard = guard
        before = copy.deepcopy(admin.sh.cfg)
        saved = Path(admin.sh.path).read_bytes() if Path(admin.sh.path).exists() else None
        audit = admin.get("/api/admin_audit")["entries"]
        for path, body in _INVALID:
            guard._workers = [123]
            status, result = admin.post(path, body)
            assert result["ok"] is False, (path, status, result)
            assert guard.quiesced == 0 and guard._workers == [123], (path, guard.quiesced)
            assert admin.sh.cfg == before
            assert (Path(admin.sh.path).read_bytes() if Path(admin.sh.path).exists()
                    else None) == saved
            assert admin.get("/api/admin_audit")["entries"] == audit

        status, accepted = admin.post("/api/shield/blocked_methods",
                                      {"methods": ["TRACE"]})
        assert status == 200 and accepted["ok"] is True, (status, accepted)
        assert guard.quiesced == 1 and guard._workers == []
        assert admin.sh.cfg["blocked_methods"] == ["TRACE"]


def test_invalid_and_noop_mutation_routes_do_not_demote_cluster():
    with _Admin() as admin:
        assert admin.fw.enable()["ok"] is True
        assert admin.fw.set_policy("public", "allow")["ok"] is True
        class Guard:
            _cluster_policy_sync = True

            def __init__(self):
                self._workers = [123]
                self.quiesced = 0

            def quiesce_cluster_for_mutation(self):
                self.quiesced += 1
                self._workers.clear()
                return {"ok": True, "cluster_downgraded": True}

        guard = Guard()
        admin.adm.edge_guard = guard
        prior_cfg = copy.deepcopy(admin.sh.cfg)
        prior_policy = copy.deepcopy(admin.fw.policy)
        for path, body in (*_INVALID_OTHER, *_NOOP_OTHER):
            guard._workers = [123]
            before = guard.quiesced
            status, result = admin.post(path, body)
            if (path, body) in _INVALID_OTHER:
                assert result["ok"] is False, (path, status, result)
            else:
                assert result["ok"] is True, (path, status, result)
            assert guard.quiesced == before and guard._workers == [123], (path, result)
            if path == "/api/shield/optional_sig":
                assert body["on"] is False
                assert not bool(prior_cfg.get("optional_sigs", {}).get(body["name"]))
                assert not bool(admin.sh.cfg.get("optional_sigs", {}).get(body["name"]))
                prior_cfg = copy.deepcopy(admin.sh.cfg)
            assert admin.sh.cfg == prior_cfg and admin.fw.policy == prior_policy

        status, result = admin.post("/api/shield/sig_add",
                                    {"name": "r25valid", "pattern": "r25validmarker"})
        assert status == 200 and result["ok"] is True, (status, result)
        assert guard.quiesced == 1 and guard._workers == []


def test_sig_remove_malformed_name_is_not_a_successful_noop():
    with _Admin() as admin:
        added = admin.sh.add_signature("r25valid", "r25validmarker")
        assert added["ok"] is True, added

        class Guard:
            _cluster_policy_sync = True

            def __init__(self):
                self._workers = [123]
                self.quiesced = 0

            def quiesce_cluster_for_mutation(self):
                self.quiesced += 1
                self._workers.clear()
                return {"ok": True, "cluster_downgraded": True}

        guard = Guard()
        admin.adm.edge_guard = guard
        before = copy.deepcopy(admin.sh._custom)
        for name in ([], "", "bad name!", 7, "x" * 65):
            status, rejected = admin.post("/api/shield/sig_remove", {"name": name})
            assert status == 400 and rejected["ok"] is False, (name, status, rejected)
            assert guard.quiesced == 0 and guard._workers == [123]
            assert admin.sh._custom == before

        status, absent = admin.post("/api/shield/sig_remove", {"name": "r25missing"})
        assert status == 200 and absent["ok"] is True and absent["removed"] == 0
        assert guard.quiesced == 0 and guard._workers == [123]
        status, removed = admin.post("/api/shield/sig_remove", {"name": "r25valid"})
        assert status == 200 and removed["ok"] is True and removed["removed"] == 1
        assert guard.quiesced == 1 and guard._workers == []


def test_invalid_replacement_keeps_real_fork_workers_and_backend_wire():
    from test_security_cluster_direct_setter_round15 import _cluster, _received, _request

    with _cluster() as (shield, _firewall, edge, report_fd):
        workers = list(edge._workers)
        assert workers
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               state_dir=str(Path(shield.path).parent), edge_guard=edge)
        started = admin.start()
        assert started.get("ok") is True, started
        prior_cfg = copy.deepcopy(shield.cfg)
        saved = Path(shield.path).read_bytes()
        try:
            for index, (path, body) in enumerate(_INVALID):
                status, result = _post(admin.port, admin.token, path, body)
                assert result["ok"] is False, (status, result)
                assert edge._workers == workers and edge.is_alive(), (path, edge._workers)
                for pid in workers:
                    os.kill(pid, 0)
                assert shield.cfg == prior_cfg and Path(shield.path).read_bytes() == saved
                target = f"/after-r25-invalid-{index}".encode("ascii")
                wire = _request(edge.listen_port, target)
                assert wire.startswith(b"HTTP/1.1 200"), wire
                assert b"GET " + target in _received(report_fd)
            status, accepted = _post(admin.port, admin.token,
                                     "/api/shield/blocked_methods", {"methods": ["TRACE"]})
            assert status == 200 and accepted["ok"] is True, (status, accepted)
            assert edge._workers == [] and edge.is_alive()
            assert shield.cfg["blocked_methods"] == ["TRACE"]
            wire = _request(edge.listen_port, b"/after-r25-valid")
            assert wire.startswith(b"HTTP/1.1 200"), wire
            assert b"GET /after-r25-valid" in _received(report_fd)
        finally:
            admin.stop()


def test_other_invalid_and_noop_posts_keep_real_fork_workers_and_wire():
    from test_security_cluster_direct_setter_round15 import _cluster, _received, _request

    with _cluster() as (shield, firewall, edge, report_fd):
        workers = list(edge._workers)
        assert workers
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               state_dir=str(Path(shield.path).parent), edge_guard=edge)
        started = admin.start()
        assert started.get("ok") is True, started
        prior_cfg = copy.deepcopy(shield.cfg)
        prior_policy = copy.deepcopy(firewall.policy)
        try:
            real_noops = _NOOP_OTHER[:-1]  # global_block(false) enables this fixture's OFF firewall
            for index, (path, body) in enumerate((*_INVALID_OTHER, *real_noops)):
                status, result = _post(admin.port, admin.token, path, body)
                if (path, body) in _INVALID_OTHER:
                    assert result["ok"] is False, (path, status, result)
                else:
                    assert result["ok"] is True, (path, status, result)
                assert edge._workers == workers and edge.is_alive(), (path, edge._workers)
                for pid in workers:
                    os.kill(pid, 0)
                if path == "/api/shield/optional_sig":
                    assert body["on"] is False
                    assert not bool(prior_cfg.get("optional_sigs", {}).get(body["name"]))
                    assert not bool(shield.cfg.get("optional_sigs", {}).get(body["name"]))
                    prior_cfg = copy.deepcopy(shield.cfg)
                assert shield.cfg == prior_cfg and firewall.policy == prior_policy
                target = f"/after-r25-other-{index}".encode("ascii")
                wire = _request(edge.listen_port, target)
                assert wire.startswith(b"HTTP/1.1 200"), wire
                assert b"GET " + target in _received(report_fd)
            status, accepted = _post(admin.port, admin.token, "/api/shield/sig_add",
                                     {"name": "r25valid", "pattern": "r25validmarker"})
            assert status == 200 and accepted["ok"] is True, (status, accepted)
            assert edge._workers == [] and edge.is_alive()
        finally:
            admin.stop()
