"""The settings form must describe the API's real, complete configuration."""

import copy
import json
import os
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline
from dataplane.gui import settings


def _validator():
    # The coercion path is pure: no key, state directory, singleton, or socket.
    shield = pipeline.NetShield.__new__(pipeline.NetShield)
    shield.cfg = copy.deepcopy(pipeline._DEFAULTS)
    return shield


def test_schema_covers_every_public_setting_with_bilingual_text():
    schema = settings.settings_schema()
    fields = schema["fields"]
    assert len(fields) == len(pipeline._DEFAULTS)
    assert len({field["key"] for field in fields}) == len(fields)
    assert {field["key"] for field in fields} == set(pipeline._DEFAULTS)
    groups = {group["id"] for group in schema["groups"]}
    assert {field["group"] for field in fields} == groups
    for field in fields:
        assert field["group"] in groups
        assert all(isinstance(field[key], str) and field[key].strip()
                   for key in ("label", "label_en", "description", "description_en"))
        assert field["default"] == pipeline._DEFAULTS[field["key"]]
        assert field["type"] in ("boolean", "integer", "number", "string", "array", "object")
    json.dumps(schema, ensure_ascii=False, allow_nan=False)


def test_schema_defaults_and_structured_examples_pass_real_api_coercion():
    shield = _validator()
    types = {bool: "boolean", int: "integer", float: "number", str: "string",
             list: "array", dict: "object"}
    for field in settings.settings_schema()["fields"]:
        key = field["key"]
        assert field["type"] == types[type(pipeline._DEFAULTS[key])], field
        accepted, _ = shield._coerce_cfg(key, copy.deepcopy(field["default"]))
        assert accepted, (key, field["default"])
        if field["type"] in ("array", "object"):
            assert field["format"] == "json"
            accepted, _ = shield._coerce_cfg(key, copy.deepcopy(field["example"]))
            assert accepted, (key, field["example"])


def test_schema_bounds_and_choices_match_the_live_validator():
    shield = _validator()
    fields = {field["key"]: field for field in settings.settings_schema()["fields"]}
    for key, (lower, upper) in pipeline._HARD_BOUNDS.items():
        field = fields[key]
        assert (field["minimum"], field["maximum"]) == (lower, upper)
        assert shield._coerce_cfg(key, lower)[0], (key, lower)
        assert shield._coerce_cfg(key, upper)[0], (key, upper)
        assert not shield._coerce_cfg(key, lower - 1)[0], (key, lower - 1)
        assert not shield._coerce_cfg(key, upper + 1)[0], (key, upper + 1)
    for key, choices in pipeline._ENUM_KEYS.items():
        assert fields[key]["choices"] == list(choices)
        for value in choices:
            accepted, normalized = shield._coerce_cfg(key, value)
            assert accepted and normalized == value, (key, value)
        assert shield._coerce_cfg(key, "invalid-choice")[0] is False
    for key in pipeline._RATE_COUNT_KEYS:
        assert fields[key]["maximum"] == pipeline._RATE_COUNT_MAX
        assert not shield._coerce_cfg(key, pipeline._RATE_COUNT_MAX + 1)[0]
    assert fields["paranoia"]["minimum"] == 1 and fields["paranoia"]["maximum"] == 4


def test_schema_returns_independent_defaults_examples_choices_and_groups():
    original = copy.deepcopy(pipeline._DEFAULTS)
    one = settings.settings_schema()
    by_key = {field["key"]: field for field in one["fields"]}
    by_key["private_paths"]["default"].append("/injected")
    by_key["private_paths"]["example"].append("/injected")
    by_key["optional_sigs"]["default"]["ssti"] = True
    by_key["mode"]["choices"].append("invalid")
    one["groups"][0]["label"] = "injected"
    two = settings.settings_schema()
    assert pipeline._DEFAULTS == original
    assert "injected" not in json.dumps(two, ensure_ascii=False)


def test_schema_refuses_new_backend_setting_without_gui_metadata():
    with patch.dict(pipeline._DEFAULTS, {"new_unlisted_setting": False}):
        try:
            settings.settings_schema()
        except RuntimeError as exc:
            assert "incomplete" in str(exc)
        else:
            raise AssertionError("a new setting silently disappeared from the GUI")
    assert len(settings.settings_schema()["fields"]) == len(pipeline._DEFAULTS)


def test_schema_never_reads_operator_secrets_or_runtime_state():
    with patch.dict(os.environ, {"DUCKNET_ADMIN_TOKEN": "operator-secret-schema-probe",
                                 "DUCKNET_STATE_KEY": "state-secret-schema-probe"}):
        encoded = json.dumps(settings.settings_schema(), ensure_ascii=False)
    assert "operator-secret-schema-probe" not in encoded
    assert "state-secret-schema-probe" not in encoded
    assert "DUCKNET_STATE_KEY" not in encoded
