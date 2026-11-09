"""A stalled audit append cannot make admin stop wait without a deadline."""

import hashlib
import hmac
import http.client
import json
import threading
import time
from unittest.mock import patch

import dataplane.admin as A
from test_falco_admin_boundaries import _Admin, _signed


def test_stalled_audit_append_reports_stop_incomplete_then_recovers():
    # The small patched limit keeps this regression fast. The production
    # deadline is longer; the old implementation ignores the limit entirely.
    with patch.object(A, "_ADMIN_STOP_DEADLINE_SEC", 0.3, create=True), _Admin() as admin:
        assert admin.sh.enable()["ok"] is True
        body = b'{"on":false}'
        credentials = _signed(admin, "POST", "/api/shield/toggle", body)
        nonce = dict(credentials)["X-Admin-Auth-Nonce"]
        old_server = admin.adm._server
        entered, release = threading.Event(), threading.Event()
        posts, stops = [], []

        def stuck_append(*_args, **_kwargs):
            entered.set()
            assert release.wait(8)
            return False

        def post():
            connection = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=8)
            try:
                connection.request("POST", "/api/shield/toggle", body=body,
                                   headers=dict(credentials))
                response = connection.getresponse()
                posts.append((response.status, dict(response.getheaders()), response.read()))
            finally:
                connection.close()

        with patch.object(A, "append_jsonl", side_effect=stuck_append):
            poster = threading.Thread(target=post, daemon=True)
            poster.start()
            stopper = None
            try:
                assert entered.wait(2)
                assert admin.sh.is_enabled() is False  # committed before audit append
                stopper = threading.Thread(target=lambda: stops.append(admin.adm.stop()), daemon=True)
                began = time.monotonic()
                stopper.start()
                stopper.join(1.2)
                assert not stopper.is_alive(), "stop waited past its audit deadline"
                assert time.monotonic() - began < 1.2
                assert stops == [{"ok": False, "error": "admin operation still in progress"}]
                assert admin.adm._server is old_server and admin.adm._thread.is_alive()
                assert admin.adm._stopping is False
                assert admin.sh.is_enabled() is False
            finally:
                release.set()
                if stopper is not None:
                    stopper.join(3)
                poster.join(3)

        assert not poster.is_alive() and len(posts) == 1
        status, headers, wire_body = posts[0]
        result = json.loads(wire_body)
        assert status == 200 and result["ok"] is True and result["enabled"] is False
        assert result["audit_recorded"] is False
        message = (admin.adm._browser_instance_id + "\n" + nonce + "\n200\n"
                   + hashlib.sha256(wire_body).hexdigest())
        expected = hmac.new(admin.token.encode(), message.encode(), hashlib.sha256).hexdigest()
        assert headers.get("X-Admin-Response-Mac") == expected
        assert admin.adm.stop()["ok"] is True
        assert admin.adm._server is None and admin.adm._thread is None


def test_normal_audited_post_and_stop_still_complete():
    with _Admin() as admin:
        assert admin.sh.enable()["ok"] is True
        status, _headers, wire_body = admin.request([("X-Token", admin.token)])
        assert status == 200 and json.loads(wire_body)["ok"] is True
        assert admin.adm.stop()["ok"] is True
