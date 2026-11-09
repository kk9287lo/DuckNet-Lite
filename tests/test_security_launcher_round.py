"""Startup addresses and browser targets reject ambiguous operator input."""

from dataplane import service
from dataplane.gui import __main__ as gui


def test_explicit_empty_backend_port_never_selects_a_default_service():
    for spec in ("backend.example:", "127.0.0.1:", "[::1]:", ":"):
        try:
            service._split_hostport(spec, 80)
        except SystemExit:
            continue
        raise AssertionError("ambiguous backend address was accepted: " + repr(spec))


def test_omitted_backend_port_and_valid_literal_controls_still_work():
    for spec, expected in (("backend.example", ("backend.example", 80)),
                           ("backend.example:8080", ("backend.example", 8080)),
                           ("[::1]", ("::1", 80)),
                           ("[::1]:8080", ("::1", 8080)),
                           ("::1", ("::1", 80))):
        assert service._split_hostport(spec, 80) == expected
    assert service._split_hostport("", 80) == ("127.0.0.1", 80)


def test_empty_backend_setting_cannot_start_a_different_default_service():
    from unittest.mock import patch

    # The captured old implementation reaches construction with localhost:80.
    # Raise before any bind so the test cannot expose a live listener.
    with patch.object(service, "AsyncEdgeGuard",
                      side_effect=RuntimeError("unexpected backend startup")):
        try:
            service.run(backend="", defaults_on=False)
        except SystemExit:
            return
    raise AssertionError("empty backend setting was accepted")


def test_dashboard_target_removes_every_case_alias_of_legacy_token():
    target = gui._dashboard_url(
        "http://127.0.0.1:8081/?token=a&ToKeN=b&%54OKEN=c&tab=overview#panel")
    assert target == "http://127.0.0.1:8081/?tab=overview#panel", target


def test_dashboard_target_preserves_public_query_and_rejects_malformed_url():
    target = gui._dashboard_url(
        "https://admin.example.test:8443/dashboard?tokenizer=public&csrf_token=public#panel")
    assert target == ("https://admin.example.test:8443/dashboard?tokenizer=public"
                      "&csrf_token=public#panel"), target
    for bad in ("javascript://admin.example.test/p", "https://user@admin.example.test/p",
                "http://admin.example.test\\@other.test/p"):
        try:
            gui._dashboard_url(bad)
        except ValueError:
            continue
        raise AssertionError("invalid dashboard URL was accepted: " + repr(bad))
