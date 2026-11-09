"""A deflate wire entity must not hide a second backend interpretation."""

import struct
import zlib
from urllib.parse import parse_qs

from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_CFG = {"body_scan_enabled": True, "body_scan_max_bytes": 65536,
        "block_score": 20, "sec_headers_enabled": False,
        "cookie_harden_enabled": False, "cors_harden_enabled": False,
        "open_redirect_enabled": False, "dlp_enabled": False}
_ATTACK = b"' UNION SELECT password FROM users--"


def _stored_polyglot(prefix, later, *, raw_length=None):
    # RFC 1950 bytes 78 9c head a zlib stream. Seen as raw deflate, the
    # same bytes start a 412-byte stored block. Its next block header sits
    # inside zlib's 65,123-byte stored payload. Python's raw decoder accepts
    # this alternate reading and ignores the bytes after its final block.
    raw_length = len(later) if raw_length is None else raw_length
    raw_second = (b"\x01" + struct.pack("<H", raw_length)
                  + struct.pack("<H", raw_length ^ 0xffff) + later)
    assert len(prefix) == 410
    zdata = prefix + raw_second + b"B" * (65123 - len(prefix) - len(raw_second))
    wire = b"\x78\x9c\x01\x63\xfe\x9c\x01" + zdata + struct.pack(">I", zlib.adler32(zdata))
    raw_decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    wrapped, raw = zlib.decompress(wire), raw_decoder.decompress(wire)
    return wire, wrapped, raw


def _polyglot():
    # The raw reading joins UNION and SELECT; zlib's raw-block header splits
    # the words in the scanner's reading.
    wire, wrapped, raw = _stored_polyglot(
        b"&q=" + b"A" * 399 + b"' UNION ", b"SELECT password FROM users--")
    assert zlib.decompress(wire, -zlib.MAX_WBITS) == raw
    assert b"UNION SELECT" not in wrapped and _ATTACK in raw
    assert _ATTACK in parse_qs(raw.decode("latin-1"))["q"][0].encode("latin-1")
    return wire, wrapped, raw


def _graphql_polyglot():
    safe = b"query=%7Bme%7Bid%7D%7D"
    late = b"query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
    prefix = b"&" + safe + b"&pad="
    prefix += b"A" * (409 - len(prefix)) + b"&"
    wire, wrapped, raw = _stored_polyglot(prefix, late)
    assert b"&" + late not in wrapped and b"&" + late in raw
    return wire


def _streaming_polyglot():
    # The alternate raw reading declares more bytes than the wire contains.
    # A streaming backend still produces a different, actionable prefix.
    wire, wrapped, _ = _stored_polyglot(
        b"&q=" + b"A" * 399 + b"' UNION ",
        b"SELECT password FROM users--", raw_length=65535)
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    partial = d.decompress(wire, 65537)
    assert not d.eof and _ATTACK in partial and _ATTACK not in wrapped
    return wire


def _late_error_polyglot():
    # Raw decoding yields the attack through its second stored block, then
    # raises on a deliberately invalid third block. Streaming consumers may
    # already have acted on the earlier output.
    prefix = b"&q=" + b"A" * 399 + b"' UNION "
    later = b"SELECT password FROM users--"
    raw_second = (b"\x00" + struct.pack("<H", len(later))
                  + struct.pack("<H", len(later) ^ 0xffff) + later + b"\x06")
    zdata = prefix + raw_second + b"B" * (65123 - len(prefix) - len(raw_second))
    wire = b"\x78\x9c\x01\x63\xfe\x9c\x01" + zdata + struct.pack(">I", zlib.adler32(zdata))
    assert _ATTACK not in zlib.decompress(wire)
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    split = 7 + len(prefix) + 5 + len(later)
    assert _ATTACK in d.decompress(wire[:split])
    try:
        d.decompress(wire[split:])
    except zlib.error:
        pass
    else:
        raise AssertionError("raw decoder must fail after yielding the attack")
    return wire


def _request(body, *, encoded=True, chunked=False, path=b"/login"):
    head = (b"POST " + path + b" HTTP/1.1\r\nHost: local.test\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n")
    if encoded:
        head += b"Content-Encoding: deflate\r\n"
    if chunked:
        wire_body = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
        return head + b"Transfer-Encoding: chunked\r\n\r\n" + wire_body
    return head + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _transit(request, mode, **overrides):
    backend = _Backend()
    try:
        with _shield(mode=mode, **{**_CFG, **overrides}) as shield, _guard(backend) as guard:
            response = _exchange(guard, [request])
            metrics, events = dict(guard.metrics), shield.events(40)
        return backend.saw(), response, metrics, events
    finally:
        backend.close()


def test_dual_view_deflate_is_rejected_before_backend_in_enforce_mode():
    wire, _, _ = _polyglot()
    for chunked in (False, True):
        received, response, metrics, _ = _transit(_request(wire, chunked=chunked), "enforce")
        assert received == b"" and metrics["proxied"] == 0
        assert response.startswith(b"HTTP/1.1 415"), response


def test_dual_view_deflate_audit_records_and_preserves_exact_wire():
    wire, _, _ = _polyglot()
    for chunked in (False, True):
        request = _request(wire, chunked=chunked)
        received, response, metrics, events = _transit(request, "audit")
        assert received.partition(b"\r\n\r\n")[2] == request.partition(b"\r\n\r\n")[2]
        assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
        assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
                   and e.get("encoding") == "deflate" for e in events), events


def test_graphql_only_dual_view_deflate_checks_complete_entity():
    wire = _graphql_polyglot()
    request = _request(wire, path=b"/graphql")
    cfg = {"body_scan_enabled": False, "graphql_enabled": True,
           "graphql_block_introspection": True}
    received, response, metrics, _ = _transit(request, "enforce", **cfg)
    assert received == b"" and metrics["proxied"] == 0
    assert response.startswith(b"HTTP/1.1 415"), response
    received, response, metrics, events = _transit(request, "audit", **cfg)
    assert received.partition(b"\r\n\r\n")[2] == wire
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
               for e in events), events


def test_streaming_alternate_deflate_view_cannot_hide_sql_injection():
    wire = _streaming_polyglot()
    assert AsyncEdgeGuard._decompress_bounded(wire, "deflate", 65536) is None
    assert AsyncEdgeGuard._decompress_complete_bounded(wire, "deflate", 65536) is None
    for mode in ("enforce", "audit"):
        request = _request(wire)
        received, response, metrics, events = _transit(request, mode)
        if mode == "enforce":
            assert received == b"" and metrics["proxied"] == 0
            assert response.startswith(b"HTTP/1.1 415"), response
        else:
            assert received.partition(b"\r\n\r\n")[2] == wire
            assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
            assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
                       for e in events), events


def test_streaming_raw_view_before_late_decode_error_is_not_forwarded_unchecked():
    wire = _late_error_polyglot()
    assert AsyncEdgeGuard._decompress_bounded(wire, "deflate", 65536) is None
    assert AsyncEdgeGuard._decompress_complete_bounded(wire, "deflate", 65536) is None
    request = _request(wire)
    received, response, metrics, _ = _transit(request, "enforce")
    assert received == b"" and metrics["proxied"] == 0
    assert response.startswith(b"HTTP/1.1 415"), response
    received, response, metrics, events = _transit(request, "audit")
    assert received.partition(b"\r\n\r\n")[2] == wire
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    assert any(e.get("kind") == "audit" and e.get("rule") == "body_unscannable"
               for e in events), events


def test_deflate_helpers_bound_both_readings_and_require_complete_single_view():
    wire, _, _ = _polyglot()
    for cap in (128, 65536):
        assert AsyncEdgeGuard._decompress_bounded(wire, "deflate", cap) is None
        assert AsyncEdgeGuard._decompress_complete_bounded(wire, "deflate", cap) is None
    wrapped = zlib.compress(b"&q=safe")
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw = compressor.compress(b"&q=safe") + compressor.flush()
    for entity in (wrapped, raw):
        assert AsyncEdgeGuard._decompress_bounded(entity, "deflate", 1024) == b"&q=safe"
        assert AsyncEdgeGuard._decompress_complete_bounded(entity, "deflate", 1024) == b"&q=safe"
    assert AsyncEdgeGuard._decompress_complete_bounded(wrapped[:-2], "deflate", 1024) is None
    assert AsyncEdgeGuard._decompress_complete_bounded(wrapped + b"junk", "deflate", 1024) is None
    assert AsyncEdgeGuard._decompress_complete_bounded(
        zlib.compress(b"A" * 1025), "deflate", 1024) is None


def test_single_view_deflate_passes_and_visible_raw_attack_is_blocked():
    _, wrapped, raw_attack = _polyglot()
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_only_attack = compressor.compress(raw_attack) + compressor.flush()
    for request in (_request(raw_attack, encoded=False), _request(raw_only_attack)):
        received, _, metrics, _ = _transit(request, "enforce")
        assert received == b"" and metrics["proxied"] == 0
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_good = compressor.compress(b"&q=safe") + compressor.flush()
    for body in (zlib.compress(b"&q=safe"), raw_good):
        received, response, metrics, _ = _transit(_request(body), "enforce")
        assert received.partition(b"\r\n\r\n")[2] == body
        assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    received, response, metrics, _ = _transit(_request(wrapped, encoded=False), "enforce")
    assert received.partition(b"\r\n\r\n")[2] == wrapped
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
