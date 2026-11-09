"""A Win32 file alias must not bypass a private route checked by the edge."""

import os
from types import SimpleNamespace
from unittest import SkipTest

from test_security_request_target_ctl_round7 import (
    _PRIVATE, _PUBLIC, _backend, _direct, _request,
)
from test_sweep_proxy_request import _exchange, _guard, _shield


_ALIASES = (
    b"/admin.", b"/admin%2e", b"/admin%20", b"/admin%20%2e",
    b"/admin::$DATA", b"/admin%3A%3A%24DATA",
)


def test_win32_private_file_aliases_never_reach_backend_in_enforce():
    if os.name != "nt":
        raise SkipTest("Win32 filesystem path aliases require a Windows backend")
    with _backend() as (port, seen):
        public = _request(b"/public.")
        with _shield(mode="enforce", private_paths=["/admin"]) as _sh, \
                _guard(SimpleNamespace(port=port)) as guard:
            benign = _exchange(guard, [public])
            assert benign.startswith(b"HTTP/1.0 200") and _PUBLIC in benign
            assert seen == [(b"GET /public. HTTP/1.1\r\n", "/public.")]
            assert guard.metrics["proxied"] == 1

        for target in _ALIASES:
            direct = _direct(port, _request(target))
            assert direct.startswith(b"HTTP/1.0 200") and _PRIVATE in direct, target
            seen.clear()
            with _shield(mode="enforce", private_paths=["/admin"]) as _sh, \
                    _guard(SimpleNamespace(port=port)) as guard:
                response = _exchange(guard, [_request(target)])
                assert response.startswith(b"HTTP/1.1 403"), (target, response)
                assert _PRIVATE not in response and seen == []
                assert guard.metrics["proxied"] == 0


def test_win32_private_alias_audit_records_while_forwarding_exact_request():
    if os.name != "nt":
        raise SkipTest("Win32 filesystem path aliases require a Windows backend")
    with _backend() as (port, seen):
        target = b"/admin%20"
        with _shield(mode="audit", private_paths=["/admin"]) as sh, \
                _guard(SimpleNamespace(port=port)) as guard:
            response = _exchange(guard, [_request(target)])
            assert response.startswith(b"HTTP/1.0 200") and _PRIVATE in response
            assert seen == [(b"GET /admin%20 HTTP/1.1\r\n", "/admin%20")]
            assert guard.metrics["proxied"] == 1
            assert any(e.get("kind") == "audit" and e.get("would") == "block"
                       for e in sh.events(40)), sh.events(40)


def test_private_path_matches_win32_aliases_without_widening_other_paths():
    with _shield(private_paths=["/admin"]) as sh:
        for target in _ALIASES:
            assert sh.private_path_matches(target.decode("ascii")), target
        for benign in ("/public", "/public.", "/admin-extra.", "/x/admin"):
            assert not sh.private_path_matches(benign), benign
