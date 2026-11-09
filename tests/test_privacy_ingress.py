"""Ingress privacy policy decisions and benign controls on real HTTP traffic."""
import tempfile

import dataplane.engine.lifeform.pipeline as ND
from dataplane.engine.core.signed_state import read_signed_json, write_signed_json
from test_sweep_proxy_request import _through


def _request(path: bytes, *, method=b"GET", body=b"", extra=b""):
    head = (method + b" " + path + b" HTTP/1.1\r\nHost: app.example\r\n"
            + extra + (b"Content-Length: " + str(len(body)).encode() + b"\r\n" if body else b"")
            + b"\r\n")
    return head + body


def test_internal_artifacts_are_denied_on_first_request_and_benign_routes_pass():
    for path in (b"/.env", b"/.env.production", b"/.git/config", b"/.svn/entries",
                 b"/.hg/store", b"/.aws/credentials", b"/.ssh/id_rsa",
                 b"/wp-config.php", b"/wp-config.php.bak", b"/%2egit/config",
                 b"/public/../.env", b"/.git%5cconfig", b"/public%5c..%5c.env",
                 b"/.env%2e", b"/wp-config.php%20", b"/.git.%5cconfig"):
        got, response, metrics = _through([_request(path)],
                                           deny_score=1000, block_score=1000)
        assert got == b"" and metrics["proxied"] == 0, path
        assert b"403" in response.split(b"\r\n", 1)[0], (path, response)
    for path in (b"/wp-login.php", b"/xmlrpc.php", b"/phpmyadmin/index.php",
                 b"/.well-known/acme-challenge/token", b"/download/report.csv",
                 b"/.env.example", b"/.gitignore", b"/docs/wp-config.php.example"):
        got, response, _ = _through([_request(path)],
                                    deny_score=1000, block_score=1000)
        assert got.startswith(b"GET " + path + b" HTTP/1.1\r\n"), path
        assert response.startswith(b"HTTP/1.1 200"), (path, response)


def test_exposure_policy_is_independent_of_signatures_but_master_off_is_passthrough():
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, mode="audit")["ok"]
        previous = ND._SIG_RE
        ND._SIG_RE = []
        try:
            result = shield.inspect("192.0.2.70", path="/.env")
        finally:
            ND._SIG_RE = previous
        assert result["action"] == "allow"
        assert any(e["kind"] == "audit" and e.get("would") == "block"
                   for e in shield.events())
        assert shield.set_config(mode="enforce")["ok"]
        assert shield.inspect("192.0.2.71", path="/.env")["action"] == "block"
        assert shield.disable()["ok"]
        assert shield.inspect("192.0.2.72", path="/.env")["action"] == "allow"


def test_private_path_audit_ip_allow_and_master_off_contract():
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, mode="audit", private_paths=["/exports"],
                                 private_path_allow=["192.0.2.0/24"])["ok"]
        assert shield.inspect("198.51.100.5", path="/exports/file")["action"] == "allow"
        assert any(e["kind"] == "audit" and e.get("would") == "block"
                   for e in shield.events())
        assert shield.set_config(mode="enforce")["ok"]
        assert shield.inspect("192.0.2.5", path="/exports/file")["action"] == "allow"
        assert shield.inspect("198.51.100.5", path="/exports/file")["action"] == "block"
        assert shield.disable()["ok"]
        assert shield.private_path_matches("/exports/file") is True
        assert shield.inspect("198.51.100.6", path="/exports/file")["action"] == "allow"


def test_exposure_toggle_does_not_disable_private_route_policy():
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, exposure_guard_enabled=False,
                                 private_paths=["/exports"], private_path_allow=[],
                                 deny_score=1000, block_score=1000)["ok"]
        assert shield.inspect("192.0.2.90", path="/.env")["action"] == "allow"
        assert shield.inspect("192.0.2.91", path="/exports/file")["action"] == "block"


def test_allowed_path_override_cannot_reach_private_route_unchecked():
    request = _request(b"/public", extra=b"X-Original-URL: /exports/file.csv\r\n")
    got, response, metrics = _through([request], path_override_block=False,
                                       private_paths=["/exports"], private_path_allow=[])
    assert got == b"" and metrics["proxied"] == 0
    assert b"403" in response.split(b"\r\n", 1)[0]
    later_alias = _request(b"/public", extra=(b"X-Original-URL: /public/new\r\n"
                                               b"X-Rewrite-URL: /exports/file.csv\r\n"))
    got, response, metrics = _through([later_alias], path_override_block=False,
                                       private_paths=["/exports"], private_path_allow=[])
    assert got == b"" and metrics["proxied"] == 0
    assert b"403" in response.split(b"\r\n", 1)[0]
    benign = _request(b"/public", extra=b"X-Original-URL: /public/new\r\n")
    got, response, _ = _through([benign], path_override_block=False,
                                private_paths=["/exports"], private_path_allow=[])
    assert got.startswith(b"GET /public HTTP/1.1\r\n")
    assert response.startswith(b"HTTP/1.1 200")
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, path_override_block=False,
                                 private_paths=["/exports"], private_path_allow=[])["ok"]
        assert shield.inspect("192.0.2.92", path="/public",
                              override_path=("/public/new", "/exports/file"))["action"] == "block"


def test_private_prefix_and_empty_allow_deny_before_backend_with_segment_control():
    for path in (b"/exports", b"/exports/file.csv", b"/%65xports/file.csv",
                 b"/public/../exports/file.csv", b"/exports;v=1/file.csv",
                 b"/public%5c..%5cexports%5cfile.csv"):
        got, response, metrics = _through([_request(path)],
                                           private_paths=["/exports"],
                                           private_path_allow=[])
        assert got == b"" and metrics["proxied"] == 0, path
        assert b"403" in response.split(b"\r\n", 1)[0], (path, response)
    for path in (b"/exports2/file.csv", b"/public/file.csv",
                 b"/exports2%5cfile.csv"):
        got, response, _ = _through([_request(path)],
                                    private_paths=["/exports"], private_path_allow=[])
        assert got.startswith(b"GET " + path + b" HTTP/1.1\r\n")
        assert response.startswith(b"HTTP/1.1 200")
    got, response, _ = _through([_request(b"/exports/file.csv")],
                                private_paths=["/exports"],
                                private_path_allow=["127.0.0.1"])
    assert got.startswith(b"GET /exports/file.csv HTTP/1.1\r\n")
    assert response.startswith(b"HTTP/1.1 200")


def test_private_config_is_strict_atomic_canonical_and_persistent():
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        assert shield.set_config(private_paths=["/Exports"],
                                 private_path_allow=["192.0.2.0/24", "2001:db8::1"])["ok"]
        assert shield.cfg["private_paths"] == ["/exports"]
        assert shield.private_path_matches("/exports/file") is True
        assert shield.private_path_matches("/exports2/file") is False
        assert shield.private_path_matches(r"/public%5c..%5cexports%5cfile") is True
        assert shield.private_path_matches("/exports?token=private") is True
        assert shield.private_path_matches("/public") is False
        before = shield.status()["cfg"]
        for invalid_paths in (["exports"], ["/exports/../public"], ["/a"] * 65,
                              ["/exports?token=x"], ["/exports", "/Exports"]):
            result = shield.set_config(private_paths=invalid_paths,
                                       rate_per_sec=17)
            assert result["ok"] is False and result["changed"] == {}
            assert shield.cfg == before
        for invalid_allow in (["192.0.2.1/24"], ["not-an-ip"], ["127.0.0.1"] * 257,
                              ["127.0.0.1 "]):
            result = shield.set_config(private_path_allow=invalid_allow,
                                       rate_per_sec=17)
            assert result["ok"] is False and result["changed"] == {}
            assert shield.cfg == before
        restarted = ND.NetShield(state_dir=directory)
        assert restarted.cfg["private_paths"] == ["/exports"]
        assert restarted.private_path_matches("/exports/file") is True


def test_upload_policy_denies_php_variants_and_exact_php_config_file():
    for filename in (b"sample.php8", b"sample.phps", b".user.ini"):
        body = (b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
                + filename + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                + b"safe data\r\n--x--\r\n")
        req = _request(b"/upload", method=b"POST", body=body,
                       extra=b"Content-Type: multipart/form-data; boundary=x\r\n")
        got, response, metrics = _through([req])
        assert got == b"" and metrics["proxied"] == 0, filename
        assert not response or b"403" in response.split(b"\r\n", 1)[0], filename
        assert metrics["dropped"] == 1
    for filename in (b"settings.ini", b"sample.txt"):
        body = (b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
                + filename + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                + b"safe data\r\n--x--\r\n")
        req = _request(b"/upload", method=b"POST", body=body,
                       extra=b"Content-Type: multipart/form-data; boundary=x\r\n")
        got, response, _ = _through([req])
        assert got.startswith(b"POST /upload HTTP/1.1\r\n"), filename
        assert response.startswith(b"HTTP/1.1 200"), (filename, response)


def test_upgrade_adds_new_upload_denials_only_to_exact_old_default():
    old = ["php", "php3", "php4", "php5", "php7", "phtml", "pht", "phar",
           "jsp", "jspx", "jspf", "asp", "aspx", "asa", "asax", "cer",
           "exe", "dll", "sh", "bash", "bat", "cmd", "com", "cgi", "pl",
           "py", "rb", "jar", "war", "ear", "htaccess"]
    with tempfile.TemporaryDirectory() as directory:
        seed = ND.NetShield(state_dir=directory)
        assert write_signed_json(seed.path,
                                 {"cfg": {"enabled": True, "upload_deny_ext": old,
                                          "cred_rate_score": 9}, "rev": 2}, seed._state_key)
        upgraded = ND.NetShield(state_dir=directory)
        for suffix in ("php8", "phps", "user.ini"):
            assert suffix in upgraded.cfg["upload_deny_ext"]
        assert upgraded.cfg["cred_rate_score"] == 9
        status, payload = read_signed_json(upgraded.path, upgraded._state_key)
        assert status == "ok" and payload["rev"] >= 3
    with tempfile.TemporaryDirectory() as directory:
        seed = ND.NetShield(state_dir=directory)
        custom = ["php", "phtml", "txt"]
        assert write_signed_json(seed.path,
                                 {"cfg": {"enabled": True, "upload_deny_ext": custom},
                                  "rev": 2}, seed._state_key)
        loaded = ND.NetShield(state_dir=directory)
        assert loaded.cfg["upload_deny_ext"] == custom


def test_usage_log_does_not_persist_query_or_fragment_secrets():
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        shield._record_usage("192.0.2.80", 12, 3, 0.1, "app.example", "GET",
                             "/exports/file.csv?token=PRIVACY_CANARY#fragment")
        rows = shield.usage_log()
        assert rows[0]["path"] == "/exports/file.csv"
        with open(shield._usage_log_path, "rb") as log:
            assert b"PRIVACY_CANARY" not in log.read()
        shield._record_usage("192.0.2.80", 12, 3, 0.1, "app.example", "GET", "/safe")
        assert shield.usage_log()[0]["path"] == "/safe"


def test_override_path_audit_does_not_record_query_credentials():
    with tempfile.TemporaryDirectory() as directory:
        shield = ND.NetShield(state_dir=directory)
        assert shield.set_config(enabled=True, mode="audit")["ok"]
        result = shield.inspect("192.0.2.81", path="/safe", method="GET",
                                override_path="/private?token=PRIVACY_CANARY")
        assert result["action"] == "allow"
        assert "PRIVACY_CANARY" not in str(shield.events())
