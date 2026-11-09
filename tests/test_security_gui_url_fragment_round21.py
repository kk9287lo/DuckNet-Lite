"""Tray-opened dashboard URLs must not copy legacy fragment credentials."""

import os
from unittest.mock import patch

from dataplane.gui import __main__ as gui
from test_gui_launcher import _launcher


def test_tray_browser_drops_legacy_fragment_secret_but_keeps_benign_query():
    secret = "SYNTHETIC_FRAGMENT_TOKEN_R21"
    opened = gui._dashboard_url(
        "http://127.0.0.1:18081/?token=OLD_TOKEN&mode=dark#token=" + secret)
    assert secret not in opened, opened
    assert opened == "http://127.0.0.1:18081/?mode=dark", opened


def test_tray_browser_keeps_a_benign_fragment_for_dashboard_root():
    opened = gui._dashboard_url("http://127.0.0.1:18081/#panel")
    assert opened == "http://127.0.0.1:18081/#panel", opened


def test_actual_tray_action_opens_a_url_without_fragment_secret():
    secret = "SYNTHETIC_FRAGMENT_TOKEN_R21"

    def actions(callback):
        callback("dash")
        callback("quit")
        return True

    with _launcher(actions) as (seen, _child), patch.dict(os.environ, {
            "DUCKNET_ADMIN_URL":
            "http://127.0.0.1:18081/?token=stale&mode=dark#token=" + secret}):
        assert gui.main([]) == 0
    assert seen["opened"] == ["http://127.0.0.1:18081/?mode=dark"]


def test_tray_browser_drops_nested_query_key_aliases_before_open():
    secret = "SYNTHETIC_QUERY_TOKEN_R21"
    opened = gui._dashboard_url(
        "http://127.0.0.1:18081/?%2574oken=" + secret +
        "&access%255Ftoken=ALSO_SECRET&mode=dark&tokenized=public")
    assert secret not in opened and "ALSO_SECRET" not in opened, opened
    assert opened == ("http://127.0.0.1:18081/?mode=dark&tokenized=public"), opened


def test_actual_tray_action_never_opens_nested_query_credential():
    def actions(callback):
        callback("dash")
        callback("quit")
        return True

    with _launcher(actions) as (seen, _child), patch.dict(os.environ, {
            "DUCKNET_ADMIN_URL":
            "http://127.0.0.1:18081/?%2574oken=SYNTHETIC_QUERY_TOKEN_R21&mode=dark"}):
        assert gui.main([]) == 0
    assert seen["opened"] == ["http://127.0.0.1:18081/?mode=dark"]
