"""A malformed direct setter value must not silently disable response headers."""

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from dataplane.engine.lifeform import pipeline as ND
from dataplane.engine.lifeform import policy as FW
from dataplane.engine.lifeform.policy import AppFirewall
from dataplane.engine.lifeform.pipeline import NetShield
from test_sweep_proxy_request import _Backend, _exchange, _guard


@contextmanager
def _running_edge():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-header-bool-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]) as state:
        shield = NetShield(state_dir=state)
        assert shield.set_config(enabled=True, block_page=False,
                                 dlp_enabled=False,
                                 sec_headers_enabled=True)["ok"]
        backend = _Backend()
        try:
            with patch.object(ND, "_SHIELD", shield), \
                    patch.object(FW, "_FW", AppFirewall(state_dir=state)), \
                    _guard(backend) as edge:
                yield shield, edge, backend
        finally:
            backend.close()


def _wire(edge, backend, path):
    request = b"GET " + path + b" HTTP/1.1\r\nHost: local.test\r\n\r\n"
    response = _exchange(edge, [request])
    assert response.startswith(b"HTTP/1.1 200"), response
    assert b"GET " + path in backend.saw(), backend.got
    return response


def test_invalid_direct_header_toggle_preserves_signed_config_and_wire():
    with _running_edge() as (shield, edge, backend):
        assert b"X-Content-Type-Options: nosniff" in _wire(
            edge, backend, b"/before-invalid-header-toggle")
        for index, value in enumerate((None, "false", 0)):
            previous = Path(shield.path).read_bytes()
            result = shield.set_sec_headers_enabled(value)
            response = _wire(edge, backend,
                             f"/invalid-header-toggle-{index}".encode("ascii"))
            # The old runtime returned ok:true, persisted OFF and omitted this
            # header on the actual client wire after receiving None or 0.
            assert b"X-Content-Type-Options: nosniff" in response, response
            assert result.get("ok") is False, result
            assert result.get("sec_headers_enabled") is True, result
            assert shield.cfg["sec_headers_enabled"] is True
            assert Path(shield.path).read_bytes() == previous


def test_boolean_direct_header_toggle_updates_client_wire_and_signed_state():
    with _running_edge() as (shield, edge, backend):
        off = shield.set_sec_headers_enabled(False)
        assert off.get("ok") is True and off["sec_headers_enabled"] is False, off
        assert b"X-Content-Type-Options: nosniff" not in _wire(
            edge, backend, b"/valid-header-off")
        assert NetShield(state_dir=os.path.dirname(shield.path)).cfg[
            "sec_headers_enabled"] is False
        on = shield.set_sec_headers_enabled(True)
        assert on.get("ok") is True and on["sec_headers_enabled"] is True, on
        assert b"X-Content-Type-Options: nosniff" in _wire(
            edge, backend, b"/valid-header-on")
        assert NetShield(state_dir=os.path.dirname(shield.path)).cfg[
            "sec_headers_enabled"] is True
