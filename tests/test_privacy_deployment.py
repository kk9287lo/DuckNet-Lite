"""Local end-to-end privacy policy and shipped deployment profile checks."""
import json
from pathlib import Path
import time

from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import app_firewall
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield, _through

_PROFILE = Path(__file__).resolve().parents[1] / "examples" / "privacy-protection.json"
_CSV = b"name,email\nFixture One,one@example.test\nFixture Two,two@example.test\n"


def _reply():
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/csv; charset=utf-8\r\n"
            b"Cache-Control: public, max-age=3600\r\nSurrogate-Control: max-age=3600\r\n"
            b"CDN-Cache-Control: public\r\nContent-Length: " + str(len(_CSV)).encode()
            + b"\r\nConnection: close\r\n\r\n" + _CSV)


def _request(path, extra=b""):
    return b"GET " + path + b" HTTP/1.1\r\nHost: app.example\r\n" + extra + b"\r\n"


def test_shipped_profile_is_fully_validated_and_persisted():
    profile = json.loads(_PROFILE.read_text(encoding="utf-8"))
    with _shield() as shield:
        result = shield.apply_config_file(str(_PROFILE))
        assert result["ok"] and set(result["applied"]) == set(profile), result
        restored = NetShield(state_dir=str(Path(shield.path).parent))
        assert restored.cfg["private_paths"] == shield.cfg["private_paths"]
        assert restored.cfg["private_path_allow"] == shield.cfg["private_path_allow"]
        assert restored.private_path_matches("/exports/customer-list.csv")
        assert not restored.private_path_matches("/exports-public/customer-list.csv")


def test_shipped_profile_denies_local_proxy_clients_until_reviewed():
    profile = json.loads(_PROFILE.read_text(encoding="utf-8"))
    request = _request(b"/exports/customer-list.csv", b"X-Forwarded-For: 198.51.100.9\r\n")
    got, response, _ = _through([request], backend_resp=_reply(), **profile)
    assert got == b"" and _CSV not in response
    assert response.startswith(b"HTTP/1.1 403"), response


def test_untrusted_forwarded_ip_cannot_read_private_export_but_trusted_proxy_can():
    profile = json.loads(_PROFILE.read_text(encoding="utf-8"))
    profile["private_path_allow"] = ["192.0.2.7/32"]
    request = _request(b"/exports/customer-list.csv", b"X-Forwarded-For: 192.0.2.7\r\n")
    got, response, _ = _through([request], backend_resp=_reply(), **profile)
    assert got == b"" and _CSV not in response
    assert response.startswith(b"HTTP/1.1 403"), response
    profile["trusted_proxies"] = ["127.0.0.1/32"]
    # Both independent policy layers must authorize the forwarded fixture peer.
    backend = _Backend(_reply())
    try:
        with _shield(**profile), _guard(backend) as guard:
            assert app_firewall().add_rule("192.0.2.7/32", "allow")["ok"]
            response = _exchange(guard, [request])
            got = backend.saw()
    finally:
        backend.close()
    assert request.split(b"\r\n", 1)[0] in got and response.endswith(_CSV)
    head = response.partition(b"\r\n\r\n")[0].lower()
    assert b"cache-control: private, no-store" in head, head
    assert b"surrogate-control:" not in head and b"cdn-cache-control:" not in head


def test_profile_allows_public_csv_and_keeps_query_only_on_the_wire():
    backend = _Backend(_reply())
    try:
        with _shield() as shield:
            assert shield.apply_config_file(str(_PROFILE))["ok"]
            assert shield.set_config(usage_record=True)["ok"]
            target = b"/public/report.csv?email=fixture@example.test&token=fixture-query-secret"
            with _guard(backend) as guard:
                response = _exchange(guard, [_request(target)])
                assert response.endswith(_CSV)
                assert target in backend.saw()
                deadline = time.monotonic() + 2
                while not shield.usage_log() and time.monotonic() < deadline:
                    time.sleep(0.01)
                records = shield.usage_log()
                assert records and records[0]["path"] == "/public/report.csv", records
                raw = Path(shield._usage_log_path).read_bytes()
                assert b"fixture-query-secret" not in raw and b"fixture@example.test" not in raw
    finally:
        backend.close()
