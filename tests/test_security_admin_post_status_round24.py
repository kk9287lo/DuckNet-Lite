"""A failed management mutation must not look like HTTP success on the wire."""

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.admin import AdminDashboard


@contextmanager
def _isolated_admin():
    old_shield, old_firewall = pipeline._SHIELD, policy._FW
    with tempfile.TemporaryDirectory(prefix="ducknet-r24-admin-status-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        pipeline._SHIELD = pipeline.NetShield(state_dir=state)
        policy._FW = policy.AppFirewall(state_dir=state)
        admin = AdminDashboard(host="127.0.0.1", port=0,
                               token="round24-admin-status-token", state_dir=state)
        try:
            started = admin.start()
            assert started.get("ok") is True, started
            yield admin, policy._FW
        finally:
            admin.stop()
            pipeline._SHIELD, policy._FW = old_shield, old_firewall


def _post(admin, body):
    connection = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=5)
    try:
        connection.request("POST", "/api/firewall/policy", body=body,
                           headers={"X-Token": "round24-admin-status-token",
                                    "Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_failed_policy_setter_returns_http_error_without_state_mutation():
    with _isolated_admin() as (admin, firewall):
        path = Path(firewall.path)
        before = path.read_bytes() if path.exists() else None
        with patch.object(firewall, "set_policy", side_effect=RuntimeError("private detail")):
            status, result = _post(admin, b'{"zone":"private","action":"deny"}')
        assert status == 500, (status, result)
        assert result == {"ok": False, "error": "internal error"}, result
        assert (path.read_bytes() if path.exists() else None) == before
        assert firewall.policy["private"] != "deny"


def test_successful_policy_setter_still_reports_http_success_and_persists():
    with _isolated_admin() as (admin, firewall):
        status, result = _post(admin, b'{"zone":"private","action":"deny"}')
        assert status == 200 and result.get("ok") is True, (status, result)
        assert firewall.policy["private"] == "deny"
        loaded = policy.AppFirewall(state_dir=os.path.dirname(firewall.path))
        assert loaded.policy["private"] == "deny"
