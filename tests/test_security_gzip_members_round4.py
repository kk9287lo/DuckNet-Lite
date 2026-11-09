"""Excessive empty gzip members cannot consume unbounded inspection work."""

import gzip

from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_security_deflate_graphql_round4 import _SAFE_FORM, _request, _transit


def test_excessive_gzip_members_fail_closed_without_changing_audit_wire():
    # Empty members make decoded-byte limits ineffective.  The final member
    # contains a normal GraphQL query, so only the member count is suspect.
    attack = gzip.compress(b"", mtime=0) * 256 + gzip.compress(_SAFE_FORM, mtime=0)
    for chunked in (False, True):
        request, wire_body = _request(attack, chunked=chunked, encoding=b"gzip")
        upstream, response, metrics, _ = _transit(request, mode="enforce")
        assert upstream == b"" and metrics["proxied"] == 0, (chunked, len(upstream))
        assert response.startswith(b"HTTP/1.1 415"), (chunked, response)

        upstream, response, metrics, events = _transit(request, mode="audit")
        assert upstream.partition(b"\r\n\r\n")[2] == wire_body
        assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
        assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
                   for e in events), (chunked, events)


def test_two_gzip_members_keep_exact_backend_bytes_in_both_modes():
    good = (gzip.compress(_SAFE_FORM[:10], mtime=0)
            + gzip.compress(_SAFE_FORM[10:], mtime=0))
    for chunked in (False, True):
        request, wire_body = _request(good, chunked=chunked, encoding=b"gzip")
        for mode in ("enforce", "audit"):
            upstream, response, metrics, events = _transit(request, mode=mode)
            assert upstream.partition(b"\r\n\r\n")[2] == wire_body
            assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
            assert not any(e.get("rule") == "body_unscannable" for e in events)


def test_each_gzip_decoder_bounds_empty_member_iterations():
    member = gzip.compress(b"", mtime=0)
    at_limit = member * 256
    over_limit = at_limit + member
    for encoding in ("gzip", "x-gzip"):
        assert AsyncEdgeGuard._decompress_bounded(at_limit, encoding, 262145) == b""
        assert AsyncEdgeGuard._decompress_complete_bounded(at_limit, encoding, 262145) == b""
        assert AsyncEdgeGuard._empty_stream_ok(at_limit, encoding) is True
        assert AsyncEdgeGuard._decompress_bounded(over_limit, encoding, 262145) is None
        assert AsyncEdgeGuard._decompress_complete_bounded(over_limit, encoding, 262145) is None
        assert AsyncEdgeGuard._empty_stream_ok(over_limit, encoding) is False
