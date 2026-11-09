"""Synthetic-secret and accounting boundaries for the existing egress controls."""
import copy
import json
import tempfile
from pathlib import Path

from dataplane.engine.lifeform.pipeline import NetShield, scan_secret_leak
from test_sweep_det_response import _pipe
from test_sweep_proxy_request import _Backend, _guard, _exchange, _shield


_PAT = b"github_pat_" + b"A" * 82
_INSTALL = b"ghs_12345_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0." + b"A" * 43
_KEY_LABELS = (b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
               b"-----BEGIN PGP PRIVATE KEY BLOCK-----")


def _response(body, extra=b""):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + extra
            + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)


def test_encrypted_private_key_label_is_not_mistaken_for_public_material():
    assert scan_secret_leak(_KEY_LABELS[0] + b"\nfixture-no-key\n") == ["private_key"]
    assert scan_secret_leak(b"-----BEGIN PUBLIC KEY-----\nfixture\n") == []
    assert scan_secret_leak(b"-----BEGIN CERTIFICATE-----\nfixture\n") == []


def test_openpgp_private_key_block_uses_its_real_standard_label():
    assert scan_secret_leak(_KEY_LABELS[1] + b"\nfixture-no-key\n") == ["private_key"]
    assert scan_secret_leak(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n") == []
    assert scan_secret_leak(b"-----BEGIN RSA PRIVATE KEY-----") == ["private_key"]


def test_existing_github_category_covers_current_token_prefixes():
    actual = {"fine_grained": scan_secret_leak(_PAT), "stateless": scan_secret_leak(_INSTALL)}
    assert actual == {"fine_grained": ["github_token"], "stateless": ["github_token"]}, actual
    assert scan_secret_leak(b"ghp_" + b"a" * 36) == ["github_token"]
    assert scan_secret_leak(b"github_pat_YOUR_TOKEN_HERE") == []
    assert scan_secret_leak(b"ghs_APPID_JWT") == []


def test_current_private_key_and_token_forms_are_withheld_on_real_wire():
    request = b"GET /public HTTP/1.1\r\nHost: app.example\r\n\r\n"
    for marker in _KEY_LABELS + (_PAT, _INSTALL):
        body = b"public\n" * 70 + marker + b"\npublic trailer"
        response = _response(body)
        for mode, action in (("enforce", "block"), ("audit", "audit")):
            backend = _Backend(response)
            try:
                with _shield(dlp_enabled=True, dlp_action="block", mode=mode) as shield:
                    with _guard(backend) as guard:
                        received = _exchange(guard, [request])
                        assert b"GET /public HTTP/1.1\r\n" in backend.saw()
                    if action == "block":
                        assert marker[:12] not in received, (marker[:12], received)
                    else:
                        assert received == response
                    leaks = [e for e in shield.events() if e["kind"] == "dlp_leak"]
                    assert leaks and all(marker.decode() not in json.dumps(e) for e in leaks)
            finally:
                backend.close()


def test_current_token_prefixes_remain_detectable_across_small_read_windows():
    for marker in (_PAT, _INSTALL):
        body = b"public " * 70 + marker + b" public trailer" * 20
        response = _response(body)
        for size in (1, 17, 61):
            parts = [response[i:i + size] for i in range(0, len(response), size)]
            received, shield = _pipe(parts, dlp_enabled=True, dlp_action="block")
            assert marker[:12] not in received
            assert shield.metrics().get("dlp_leak", 0) == 1


def test_unscannable_events_do_not_copy_unknown_header_contents():
    marker = b"fixture_canary12"
    response = _response(b"ordinary", b"Content-Encoding: " + marker + b"\r\n")
    for mode in ("enforce", "audit"):
        received, shield = _pipe([response], dlp_enabled=True, dlp_action="block", mode=mode)
        if mode == "enforce":
            assert b"ordinary" not in received
        else:
            assert received == response
        events = [e for e in shield.events() if e["kind"] == "dlp_unscannable"]
        assert events and marker.decode() not in json.dumps(events)
        assert events[-1]["encoding"] == "unsupported-encoding"
    _, shield = _pipe([_response(b"ordinary", b"Content-Encoding: gzip\r\n")],
                      dlp_enabled=True, dlp_action="block")
    assert any(e.get("encoding") == "gzip" for e in shield.events())
    for reason in ("unicode-prefix", "multipart-media"):
        shield.note_unscannable("192.0.2.204", reason)
        assert shield.events()[-1]["encoding"] == reason


def _accounting_state(shield):
    return (copy.deepcopy(shield._usage), copy.deepcopy(shield._traffic), shield.bans(),
            {str(path): path.read_bytes() for path in Path(shield.path).parent.glob("*") if path.is_file()})


def test_invalid_traffic_values_cannot_poison_usage_or_quota_state():
    bad_values = (float("nan"), float("inf"), -1, True, "12", 1 << 1000)
    for field in ("out_bytes", "in_bytes", "conn_sec"):
        for bad in bad_values:
            with tempfile.TemporaryDirectory() as directory:
                shield = NetShield(state_dir=directory)
                assert shield.set_config(enabled=True, quota_enabled=True, usage_record=True)["ok"]
                shield.record_traffic("192.0.2.201", out_bytes=4, host="app.example", path="/safe")
                before = _accounting_state(shield)
                result = shield.record_traffic("192.0.2.201", **{field: bad})
                assert result.get("counted") is False and result.get("error"), (field, type(bad), result)
                assert _accounting_state(shield) == before


def test_invalid_direct_usage_values_leave_no_partial_saved_record():
    with tempfile.TemporaryDirectory() as directory:
        shield = NetShield(state_dir=directory)
        assert shield.set_config(usage_record=True)["ok"]
        before = _accounting_state(shield)
        shield._record_usage("192.0.2.202", float("nan"), 0, 0, "app.example", "GET", "/safe")
        assert _accounting_state(shield) == before


def test_rejected_invalid_accounting_preserves_real_quota_enforcement():
    for mode in ("enforce", "audit"):
        with tempfile.TemporaryDirectory() as directory:
            shield = NetShield(state_dir=directory)
            assert shield.set_config(enabled=True, quota_enabled=True, quota_max_gb=0.00000001,
                                     mode=mode, usage_record=True)["ok"]
            assert not shield.record_traffic("192.0.2.203", out_bytes=4).get("exceeded")
            shield.record_traffic("192.0.2.203", out_bytes=float("nan"))
            result = shield.record_traffic("192.0.2.203", out_bytes=8)
            assert result.get("exceeded"), result
            assert shield.is_banned_fast("192.0.2.203") == (mode == "enforce")
            assert shield.usage_list()["rows"][0]["conns"] == 2
