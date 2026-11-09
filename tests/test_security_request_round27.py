"""Ordinary request fields must retain their meaning after config updates."""

import copy
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline
from dataplane.engine.lifeform import policy
from dataplane.engine.core.signed_state import payload_fingerprint, write_signed_json
from dataplane.engine.services.proxy import _header_values
from test_security_request_round26 import _settings
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_REQUEST = (b"POST /public HTTP/1.1\r\nHost: example.test\r\n"
            b"Content-Type: text/plain\r\nContent-Length: 6\r\nX-Note: public\r\n\r\npublic")
_KEY = {"DUCKNET_ORIGIN_KEY": "ordinary-round27-local-fixture-key"}


def _disk(shield):
    return {name: Path(name).read_bytes() if Path(name).exists() else None
            for name in (shield.path, shield.path + ".hw")}


def _wire(shield):
    backend = _Backend()
    try:
        with patch.object(pipeline, "_SHIELD", shield), \
                patch.object(policy, "_FW", policy.AppFirewall(state_dir=str(Path(shield.path).parent))), \
                _guard(backend) as edge:
            response = _exchange(edge, [_REQUEST])
        return backend.saw(), response
    finally:
        backend.close()


def _update_case(mode, values):
    with patch.dict(os.environ, _KEY), _shield(**_settings(mode=mode)) as shield:
        assert shield.set_config(origin_header="X-Ordinary-Proof",
                                 origin_cloaking_enabled=True)["ok"] is True
        before, saved = copy.deepcopy(shield.cfg), _disk(shield)
        result = shield.set_config(**values)
        wire, response = _wire(shield)
        return {"mode": mode, "values": values,
                "result": {key: result[key] for key in ("ok", "rejected", "changed") if key in result},
                "unchanged": shield.cfg == before and _disk(shield) == saved,
                "host": _header_values(wire, b"host"),
                "length": _header_values(wire, b"content-length"),
                "ordinary_proof": bool(_header_values(wire, b"x-ordinary-proof")),
                "default_proof": bool(_header_values(wire, b"x-edge-token")),
                "body": wire.partition(b"\r\n\r\n")[2],
                "response_ok": response.endswith(b"\r\n\r\nok")}


def _assert_rejected(rows, key):
    for row in rows:
        assert row["result"]["ok"] is False, row
        assert row["result"].get("rejected") == [key], row
        assert row["unchanged"] is True, row
        assert row["host"] == ["example.test"] and row["length"] == ["6"], row
        assert row["ordinary_proof"] and not row["default_proof"], row
        assert row["body"] == b"public" and row["response_ok"], row


def test_origin_name_limit_cannot_silently_select_another_serialized_field():
    rows = [_update_case(mode, {"origin_header": "X-" + "ordinary" * 16})
            for mode in ("enforce", "audit")]
    _assert_rejected(rows, "origin_header")


def test_origin_reserved_fields_cannot_replace_ordinary_host_or_length():
    rows = [_update_case(mode, {"origin_header": name})
            for mode in ("enforce", "audit") for name in ("Host", "Content-Length")]
    _assert_rejected(rows, "origin_header")


def test_cache_strip_cannot_remove_ordinary_host_or_body_length():
    rows = [_update_case(mode, {"cache_poison_headers": ["X-Note", name]})
            for mode in ("enforce", "audit") for name in ("Host", "Content-Length")]
    _assert_rejected(rows, "cache_poison_headers")


def test_protected_aliases_and_invalid_field_names_are_atomic_api_rejections():
    origin_bad = ("Content_Type", "Transfer_Encoding", "Connection", "Authorization",
                  "Cookie", "X_Forwarded_For", "X-Real-IP", "X_API_Key", "Range",
                  "X-Original-URL", "X-Http-Method-Override", "Accept-Encoding")
    cache_bad = ("Content_Type", "Transfer_Encoding", "Connection", "Authorization",
                 "Cookie", "X_Forwarded_For", "X-Real-IP", "X_API_Key", "Range",
                 "Origin", "Content-Encoding", "Expect", "X-Ordinary-\u65e5\u672c", "X:Note",
                 "X-" + "ordinary" * 16)
    with _shield(**_settings()) as shield:
        assert shield.set_config(origin_header="X-Ordinary-Proof")["ok"]
        before, saved = copy.deepcopy(shield.cfg), _disk(shield)
        for name in origin_bad:
            result = shield.set_config(origin_header=name, origin_window_sec=31)
            assert result["ok"] is False and result.get("rejected") == ["origin_header"], (name, result)
            assert shield.cfg == before and _disk(shield) == saved
        for name in cache_bad:
            result = shield.set_config(cache_poison_headers=["X-Note", name], origin_window_sec=31)
            assert result["ok"] is False and result.get("rejected") == ["cache_poison_headers"], (name, result)
            assert shield.cfg == before and _disk(shield) == saved


def test_default_custom_and_maximum_names_keep_ordinary_request_semantics():
    for name in ("X-Edge-Token", "X-Ordinary-Proof", "X_Ordinary_Proof", "X-" + "a" * 126):
        with patch.dict(os.environ, _KEY), _shield(**_settings()) as shield:
            assert shield.set_config(origin_header=name, origin_cloaking_enabled=True,
                                     cache_poison_headers=["x-forwarded-host", "X-Note"])["ok"]
            wire, response = _wire(shield)
            assert response.endswith(b"\r\n\r\nok")
            assert _header_values(wire, name.lower().encode("ascii"))
            assert _header_values(wire, b"host") == ["example.test"]
            assert _header_values(wire, b"content-length") == ["6"]
            assert not _header_values(wire, b"x-note")
            assert wire.partition(b"\r\n\r\n")[2] == b"public"
            reloaded = pipeline.NetShield(state_dir=str(Path(shield.path).parent))
            assert reloaded.cfg["origin_header"] == name
            assert reloaded.cfg["cache_poison_headers"] == ["x-forwarded-host", "X-Note"]
            assert not reloaded._cfg_state_untrusted


def _legacy(state, **values):
    shield = pipeline.NetShield(state_dir=state)
    assert shield.set_config(**_settings(), origin_header="X-Ordinary-Proof")["ok"]
    payload = json.loads(Path(shield.path).read_text(encoding="utf-8"))["_payload"]
    replacement = {**payload, "rev": 1, "cfg": {**payload["cfg"], **values}}
    assert write_signed_json(shield.path, replacement, shield._state_key,
                             expected_fingerprint=payload_fingerprint(payload))
    return shield


def test_active_legacy_mutation_conflicts_keep_evidence_and_fail_closed():
    cases = ({"origin_cloaking_enabled": True, "origin_header": "Host"},
             {"origin_cloaking_enabled": True, "origin_header": "Content_Length"},
             {"origin_cloaking_enabled": True, "origin_header": "X-" + "ordinary" * 16},
             {"strip_cache_poison_headers": True, "cache_poison_headers": ["Content-Length"]},
             {"strip_cache_poison_headers": True, "cache_poison_headers": ["Content_Length"]})
    cases = tuple({**values, "mode": mode, "enabled": enabled}
                  for enabled in (True, False) for mode in ("enforce", "audit") for values in cases)
    for values in cases:
        with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            shield = _legacy(state, **values)
            saved = _disk(shield)
            reloaded = pipeline.NetShield(state_dir=state)
            assert reloaded.inspect("127.0.0.1", path="/public")["action"] == "block", values
            with patch.dict(os.environ, _KEY):
                wire, response = _wire(reloaded)
            assert reloaded._cfg_state_untrusted is True, values
            assert _disk(reloaded) == saved
            assert wire == b"" and b"\r\n\r\nok" not in response, (values, wire, response)
            assert any(event.get("kind") == "cfg_load_rejected" for event in reloaded.events(50))


def test_dormant_legacy_invalid_names_restore_safe_defaults_before_enable():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _legacy(state, origin_cloaking_enabled=False, origin_header="Host",
                         strip_cache_poison_headers=False, cache_poison_headers=["Content-Length"])
        saved = _disk(shield)
        reloaded = pipeline.NetShield(state_dir=state)
        assert not reloaded._cfg_state_untrusted
        assert reloaded.cfg["origin_header"] == pipeline._DEFAULTS["origin_header"]
        assert reloaded.cfg["cache_poison_headers"] == pipeline._DEFAULTS["cache_poison_headers"]
        assert _disk(reloaded) == saved
        with patch.dict(os.environ, _KEY):
            assert reloaded.set_config(origin_cloaking_enabled=True, strip_cache_poison_headers=True)["ok"]
            wire, response = _wire(reloaded)
        assert response.endswith(b"\r\n\r\nok")
        assert _header_values(wire, b"x-edge-token")
        assert _header_values(wire, b"host") == ["example.test"]
        assert _header_values(wire, b"content-length") == ["6"]


def test_safe_signed_legacy_names_remain_available_without_rewriting_state():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _legacy(state, origin_cloaking_enabled=True, origin_header="X_Ordinary_Proof",
                         cache_poison_headers=["x-forwarded-host", "X-Note"])
        saved = _disk(shield)
        reloaded = pipeline.NetShield(state_dir=state)
        assert not reloaded._cfg_state_untrusted
        assert reloaded.cfg["origin_header"] == "X_Ordinary_Proof"
        assert reloaded.cfg["cache_poison_headers"] == ["x-forwarded-host", "X-Note"]
        assert _disk(reloaded) == saved
        with patch.dict(os.environ, _KEY):
            wire, response = _wire(reloaded)
        assert response.endswith(b"\r\n\r\nok")
        assert _header_values(wire, b"x_ordinary_proof")
        assert _header_values(wire, b"host") == ["example.test"]
        assert _header_values(wire, b"content-length") == ["6"]
        assert wire.partition(b"\r\n\r\n")[2] == b"public"


def test_structural_latch_survives_rejected_or_failed_updates_until_safe_new_instance():
    with tempfile.TemporaryDirectory(dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = _legacy(state, enabled=False, mode="audit", origin_cloaking_enabled=True,
                         origin_header="Host")
        reloaded = pipeline.NetShield(state_dir=state)
        assert reloaded.inspect("127.0.0.1", path="/public")["action"] == "block"
        saved = _disk(reloaded)
        assert reloaded.set_config(origin_header="Host")["ok"] is False
        assert reloaded.set_config(origin_header="X-Ordinary-Proof")["ok"] is False
        assert reloaded._request_mutation_untrusted and _disk(reloaded) == saved
        payload = json.loads(Path(reloaded.path).read_text(encoding="utf-8"))["_payload"]
        replacement = {**payload, "cfg": {**payload["cfg"], "origin_header": "X-Ordinary-Proof"}}
        assert write_signed_json(reloaded.path, replacement, reloaded._state_key,
                                 expected_fingerprint=payload_fingerprint(payload))
        assert reloaded.inspect("127.0.0.1", path="/public")["action"] == "block"
        fresh = pipeline.NetShield(state_dir=state)
        assert fresh._request_mutation_untrusted is False
        assert fresh.inspect("127.0.0.1", path="/public")["action"] == "allow"
        with patch.dict(os.environ, _KEY):
            wire, response = _wire(fresh)
        assert response.endswith(b"\r\n\r\nok")
        assert _header_values(wire, b"host") == ["example.test"]
        assert _header_values(wire, b"content-length") == ["6"]
        assert _header_values(wire, b"x-ordinary-proof")
