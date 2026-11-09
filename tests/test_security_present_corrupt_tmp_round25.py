"""A present damaged signed state must not become a stale .tmp snapshot."""

import json
import os
from pathlib import Path
import tempfile

from dataplane.engine.core.signed_state import (
    payload_fingerprint, read_signed_json, sign_payload, write_signed_json,
)
from dataplane.engine.lifeform.pipeline import NetShield


_IP = "198.51.100.9"
_ACTIVE = {"bans": {_IP: {"permanent": True, "until": 9999999999}}}
_STALE = {"bans": {}}


def _case():
    return tempfile.TemporaryDirectory(prefix="ducknet-r25-state-",
                                       dir=os.environ["DUCKNET_STATE_DIR"])


def _envelope(payload, key):
    return json.dumps({"_sv": 1, "_sig": sign_payload(payload, key),
                       "_payload": payload})


def _seed(directory, *, main_payload=_ACTIVE, tmp_payload=_STALE):
    state = Path(directory)
    key = NetShield(state_dir=str(state))._state_key
    main = state / "blocklist.json"
    tmp = state / "blocklist.json.tmp"
    if main_payload is not None:
        main.write_text(_envelope(main_payload, key), encoding="utf-8")
    if tmp_payload is not None:
        tmp.write_text(_envelope(tmp_payload, key), encoding="utf-8")
    return state, key, main, tmp


def _admission(state):
    shield = NetShield(state_dir=str(state))
    shield.cfg.update(persist_bans=True, enabled=True)
    shield._load_bans()
    return {"banned": shield.is_banned_fast(_IP),
            "untrusted": shield._ban_state_untrusted,
            "action": shield.inspect(_IP, path="/clean")["action"]}


def test_corrupt_present_main_with_old_tmp_denies_ban_bypass():
    with _case() as directory:
        state, key, main, tmp = _seed(directory)
        assert _admission(state) == {"banned": True, "untrusted": False,
                                     "action": "block"}
        tmp_before = tmp.read_bytes()
        main.write_text("{bad JSON", encoding="ascii")
        assert read_signed_json(str(main), key, {}) == ("tampered", {})
        after = _admission(state)
        assert after["untrusted"] is True and after["action"] == "block", after
        assert main.read_bytes() == b"{bad JSON" and tmp.read_bytes() == tmp_before


def test_truly_absent_main_recovers_valid_tmp_and_keeps_ban():
    with _case() as directory:
        state, key, main, _tmp = _seed(directory, main_payload=None,
                                      tmp_payload=_ACTIVE)
        assert not main.exists()
        assert read_signed_json(str(main), key, {}) == ("ok", _ACTIVE)
        assert _admission(state) == {"banned": True, "untrusted": False,
                                     "action": "block"}


def test_absent_main_with_corrupt_tmp_is_not_a_clean_first_boot():
    with _case() as directory:
        state, key, main, tmp = _seed(directory, main_payload=None,
                                     tmp_payload=None)
        tmp.write_text("{bad JSON", encoding="ascii")
        assert read_signed_json(str(main), key, {}) == ("tampered", {})
        after = _admission(state)
        assert after["untrusted"] is True and after["action"] == "block", after
        before_tmp = tmp.read_bytes()
        status = {}
        assert write_signed_json(str(main), _STALE, key, status=status) is False
        assert not main.exists() and tmp.read_bytes() == before_tmp


def test_corrupt_present_main_cannot_satisfy_stale_tmp_cas():
    with _case() as directory:
        state, key, main, tmp = _seed(directory)
        main.write_text("{bad JSON", encoding="ascii")
        before_main, before_tmp = main.read_bytes(), tmp.read_bytes()
        status = {}
        ok = write_signed_json(str(main), _ACTIVE, key, status=status,
                               expected_fingerprint=payload_fingerprint(_STALE))
        assert ok is False and status.get("conflict") is True, status
        assert main.read_bytes() == before_main and tmp.read_bytes() == before_tmp
        assert not (state / "blocklist.json.hw").exists()


def test_corrupt_present_main_cannot_be_overwritten_without_cas():
    with _case() as directory:
        state, key, main, tmp = _seed(directory)
        main.write_text("{bad JSON", encoding="ascii")
        before_main, before_tmp = main.read_bytes(), tmp.read_bytes()
        status = {}
        ok = write_signed_json(str(main), _ACTIVE, key, status=status)
        assert ok is False and status.get("published") is False, status
        assert main.read_bytes() == before_main and tmp.read_bytes() == before_tmp
        assert not (state / "blocklist.json.hw").exists()


def test_no_cas_fresh_and_valid_signed_updates_still_work():
    with _case() as directory:
        _state, key, main, _tmp = _seed(directory, main_payload=None,
                                       tmp_payload=None)
        assert write_signed_json(str(main), _STALE, key)
        assert write_signed_json(str(main), _ACTIVE, key)
        assert read_signed_json(str(main), key, {}) == ("ok", _ACTIVE)
