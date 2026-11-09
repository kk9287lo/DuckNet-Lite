"""Trusted proxy XFF hop budget must retain the appended client identity.

The local socket peer represents an explicitly trusted append-style proxy.
All product state is isolated by the test runner before this module is imported.
"""

from dataplane.engine.services.proxy import _real_client_ip
from test_sweep_r2_ipsource import (
    _Backend, _exchange, _guard, _shield, _xff_req,
)
import dataplane.engine.lifeform.policy as FW


_REAL = "203.0.113.7"
_FORGED = "198.51.100.9"
_OTHER = "203.0.113.8"
_TRUSTED = ["127.0.0.1/32"]


def _long_chain():
    # Sixteen client-controlled entries precede the one trusted proxy appends.
    return ", ".join(["192.0.2.1"] * 15 + [_FORGED, _REAL])


def test_xff_hop_budget_keeps_rightmost_appended_identity():
    assert _real_client_ip("127.0.0.1", _xff_req("/short", _FORGED + ", " + _REAL),
                           _TRUSTED) == _REAL
    assert _real_client_ip("127.0.0.1", _xff_req("/long", _long_chain()),
                           _TRUSTED) == _REAL
    # The same overlong chain can arrive as repeated wire fields.
    multi = (b"GET /long HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: "
             + ", ".join(["192.0.2.1"] * 15 + [_FORGED]).encode("ascii")
             + b"\r\nX-Forwarded-For: " + _REAL.encode("ascii") + b"\r\n\r\n")
    assert _real_client_ip("127.0.0.1", multi, _TRUSTED) == _REAL
    assert _real_client_ip("127.0.0.1", _xff_req("/long", _long_chain()),
                           ["10.0.0.0/8"]) == "127.0.0.1"
    # A broken nearest hop must not expose an earlier client-controlled value.
    for malformed in ("unknown", "", "not-an-ip"):
        assert _real_client_ip("127.0.0.1",
                               _xff_req("/invalid", _FORGED + ", " + malformed),
                               _TRUSTED) == "127.0.0.1"
    # A malformed value left of a complete untrusted appended IP is irrelevant.
    assert _real_client_ip("127.0.0.1", _xff_req("/good", "unknown, " + _OTHER),
                           _TRUSTED) == _OTHER


def test_xff_long_chain_cannot_bypass_real_client_ban_on_wire():
    backend = _Backend()
    try:
        with _shield(trusted_proxies=list(_TRUSTED)) as sh, _guard(backend) as guard:
            # Permit both identities at the ACL layer so the ban alone decides.
            assert FW._FW.add_rule(_REAL + "/32", "allow")["ok"]
            assert FW._FW.add_rule(_FORGED + "/32", "allow")["ok"]
            assert FW._FW.add_rule(_OTHER + "/32", "allow")["ok"]
            assert sh.ban(_REAL, ttl_sec=600)["ok"]
            _exchange(guard, _xff_req("/short", _FORGED + ", " + _REAL))
            _exchange(guard, _xff_req("/long", _long_chain()))
            _exchange(guard, _xff_req("/good", _FORGED + ", " + _OTHER))
        received = backend.saw().lower()
        assert b"/short" not in received
        assert b"/long" not in received, received
        assert b"get /good http/1.1\r\n" in received, received
        assert b"x-forwarded-for: 203.0.113.8\r\n" in received, received
        assert b"x-real-ip: 203.0.113.8\r\n" in received, received
        assert b"198.51.100.9" not in received, received
    finally:
        backend.close()
