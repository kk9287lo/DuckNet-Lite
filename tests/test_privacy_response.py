"""Response DLP and private-response cache boundaries (benign local fixtures)."""

import gzip
import json
import asyncio
import bz2
import io
import lzma
import tarfile
import zipfile

from dataplane.engine.services.proxy import AsyncEdgeGuard, _reject_response
from test_sweep_det_response import _pipe, _shield, _Reads, _Sink
from test_sweep_proxy_request import _through


_DUMMY = b"ghp_" + b"a" * 36  # inert test marker matching the existing DLP signature


def _response(body, *headers):
    return (b"HTTP/1.1 200 OK\r\n"
            + (b"\r\n".join(headers) + b"\r\n" if headers else b"")
            + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def test_folded_content_encoding_is_unscannable_before_head_publication():
    body = gzip.compress(_DUMMY)
    folded = _response(body, b"Content-Encoding:", b" gzip")
    out, sh = _pipe([folded], dlp_enabled=True, dlp_action="block")
    assert out == b""
    assert sh.metrics().get("dlp_unscannable", 0) == 1

    normal = _response(body, b"Content-Encoding: gzip")
    out, sh = _pipe([normal], dlp_enabled=True, dlp_action="block")
    assert body not in out
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    out, sh = _pipe([folded], dlp_enabled=True, dlp_action="audit")
    assert out == b""  # Invalid HTTP syntax is rejected independently of DLP mode.
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    out, sh = _pipe([normal], dlp_enabled=True, dlp_action="audit")
    assert out == normal  # Valid opaque representation still follows audit policy.
    assert sh.metrics().get("dlp_unscannable", 0) == 1


def test_malformed_response_header_is_unscannable_before_head_publication():
    malformed = _response(b"public", b"Content-Type: text/plain", b"X-\x00Bad: value")
    out, sh = _pipe([malformed], dlp_enabled=True, dlp_action="block")
    assert out == b""
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    normal = _response(b"public", b"Content-Type: text/plain", b"X-Good: value")
    out, sh = _pipe([normal], dlp_enabled=True, dlp_action="block")
    assert out == normal
    assert sh.metrics().get("dlp_unscannable", 0) == 0


def test_lf_only_encoded_head_is_unscannable_at_eof():
    body = gzip.compress(_DUMMY)
    malformed = (b"HTTP/1.1 200 OK\nContent-Encoding: gzip\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\n\n" + body)
    out, sh = _pipe([malformed], dlp_enabled=True, dlp_action="block")
    assert out == b""
    assert sh.metrics().get("dlp_unscannable", 0) == 1


def test_utf16_utf32_declared_text_cannot_pass_dlp_as_identity():
    for charset in (b"UTF-16LE", b"UTF-32LE"):
        body = _DUMMY.decode("ascii").encode(charset.decode("ascii"))
        resp = _response(body, b"Content-Type: text/plain; charset=" + charset)
        out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block")
        assert out == b"", charset
        assert sh.metrics().get("dlp_unscannable", 0) == 1, charset
    plain = _response(_DUMMY, b"Content-Type: text/plain; charset=utf-8")
    out, sh = _pipe([plain], dlp_enabled=True, dlp_action="block")
    assert _DUMMY not in out
    assert sh.metrics().get("dlp_leak", 0) == 1

    bom = _DUMMY.decode("ascii").encode("utf-16")
    out, sh = _pipe([_response(bom, b"Content-Type: text/plain")],
                    dlp_enabled=True, dlp_action="block")
    assert bom not in out
    assert sh.metrics().get("dlp_unscannable", 0) == 1


def test_ambiguous_charset_is_unscannable_and_utf8_plain_is_preserved():
    bad = _response(b"safe", b"Content-Type: text/plain; charset=utf-8; charset=utf-16le")
    out, sh = _pipe([bad], dlp_enabled=True, dlp_action="block")
    assert out == b""
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    good = _response("東京の正常な応答".encode(), b"Content-Type: text/plain; charset=utf-8")
    out, sh = _pipe([good], dlp_enabled=True, dlp_action="block")
    assert out == good and sh.metrics().get("dlp_unscannable", 0) == 0


def test_json_unicode_escape_cannot_bypass_dlp_at_any_packet_boundary():
    escaped = b'{"token":"gh\\u0070_' + b"a" * 36 + b'"}'
    assert json.loads(escaped)["token"].encode() == _DUMMY
    for headers in ((b"Content-Type: application/json",),
                    (b"Content-Type: text/plain",), ()):
        resp = _response(escaped, *headers)
        for chunks in ([resp], [resp[i:i + 1] for i in range(len(resp))]):
            out, sh = _pipe(chunks, dlp_enabled=True, dlp_action="block")
            assert escaped not in out
            assert sh.metrics().get("dlp_leak", 0) == 1
    resp = _response(escaped, b"Content-Type: application/json")
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="audit")
    assert out == resp
    assert sh.metrics().get("dlp_leak", 0) == 1

    # The JSON value below contains a literal backslash-u sequence, not a secret.
    double_escaped = b'{"literal":"gh\\\\u0070_' + b"a" * 36 + b'"}'
    assert json.loads(double_escaped)["literal"].startswith("gh\\u0070_")
    benign = _response(double_escaped, b"Content-Type: application/json")
    out, sh = _pipe([benign[i:i + 1] for i in range(len(benign))],
                    dlp_enabled=True, dlp_action="block")
    assert out == benign
    assert sh.metrics().get("dlp_leak", 0) == 0

    malformed_text = _response(b'{"example":"hello\\q"}', b"Content-Type: text/plain")
    out, sh = _pipe([malformed_text], dlp_enabled=True, dlp_action="block")
    assert out == malformed_text
    assert sh.metrics().get("dlp_unscannable", 0) == 0

    bom_json = _response(b"\xef\xbb\xbf" + escaped)
    out, sh = _pipe([bom_json[i:i + 1] for i in range(len(bom_json))],
                    dlp_enabled=True, dlp_action="block")
    assert escaped not in out and sh.metrics().get("dlp_leak", 0) == 1


def test_json_escape_scan_keeps_secret_prefix_unsent_after_long_stream():
    escaped = b"".join(b"\\u%04x" % c for c in _DUMMY)
    body = b'{"pad":"' + b"x" * 800 + b'","token":"' + escaped + b'"}'
    assert json.loads(body)["token"].encode() == _DUMMY
    resp = _response(body, b"Content-Type: application/json")
    for step in (1, 13, 65536):
        out, sh = _pipe([resp[i:i + step] for i in range(0, len(resp), step)],
                        dlp_enabled=True, dlp_action="block")
        assert escaped[:18] not in out, step  # no undecided beginning of the token
        assert sh.metrics().get("dlp_leak", 0) == 1, step

    # Chunk metadata may be much larger than the decoded JSON character runs.
    chunks = [b'{"token":"'] + [b"\\u%04x" % c for c in _DUMMY] + [b'"}']
    wire = b"".join((b"%x;pad=" % len(c) + b"y" * 100 + b"\r\n" + c + b"\r\n")
                    for c in chunks)
    wire += b"0\r\n\r\n"
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    out, sh = _pipe([head + wire], dlp_enabled=True, dlp_action="block")
    assert chunks[1] not in out
    assert sh.metrics().get("dlp_leak", 0) == 1


def test_generated_json_rejection_has_no_store():
    out = _reject_response("403 Forbidden", '{"error":"blocked"}')
    assert b"Cache-Control: no-store\r\n" in out


def test_private_backend_response_replaces_public_cache_directives():
    backend = _response(b"private-content", b"Content-Type: text/plain",
                        b"Cache-Control: public, s-maxage=3600", b"Pragma: cache",
                        b"Expires: Thu, 01 Jan 2099 00:00:00 GMT",
                        b"Surrogate-Control: max-age=3600",
                        b"CDN-Cache-Control: public, max-age=3600",
                        b"Cloudflare-CDN-Cache-Control: public, max-age=3600",
                        b"X-Accel-Expires: 3600")
    request = b"GET /private/item HTTP/1.1\r\nHost: app.example\r\n\r\n"
    saw, out, _ = _through([request], backend_resp=backend,
                           private_paths=["/private"], private_path_allow=["127.0.0.1/32"],
                           enabled=False)  # no-store survives master shield OFF
    assert saw.startswith(request.split(b"\r\n", 1)[0])
    assert out.endswith(b"private-content")
    head = out.partition(b"\r\n\r\n")[0]
    assert head.count(b"Cache-Control:") == 1
    assert b"Cache-Control: private, no-store" in head
    assert b"Pragma: no-cache" in head and b"Expires: 0" in head
    for marker in (b"public", b"s-maxage", b"Surrogate-Control", b"CDN-Cache-Control",
                   b"X-Accel-Expires"):
        assert marker not in head, marker

    public = b"GET /public/item HTTP/1.1\r\nHost: app.example\r\n\r\n"
    _, out, _ = _through([public], backend_resp=backend,
                         private_paths=["/private"], private_path_allow=["127.0.0.1/32"],
                         enabled=False)
    assert b"Cache-Control: public, s-maxage=3600" in out


def test_private_cache_latch_survives_rule_removal_and_bad_head_drops():
    with _shield(private_paths=[]) as sh:
        sh.cfg["enabled"] = False
        for response in (_response(b"ok", b"Cache-Control: public"),
                         b"HTTP/1.1 200 OK\nCache-Control: public\n\nok"):
            sink = _Sink()
            asyncio.run(AsyncEdgeGuard()._pipe(
                _Reads([response]), sink, scan=True, ip="192.0.2.2",
                req_paths=("/private/item",), private_response=True))
            if b"\r\n\r\n" in response:
                assert b"Cache-Control: private, no-store" in sink.buf
            else:
                assert sink.buf == b""


def test_private_path_policy_checks_every_override_header_value():
    request = (b"GET /public HTTP/1.1\r\nHost: app.example\r\n"
               b"X-Original-URL: /public\r\nX-Rewrite-URL: /private/export\r\n\r\n")
    saw, _, _ = _through([request], private_paths=["/private"],
                         private_path_allow=[], path_override_block=False)
    assert saw == b""           # the later override still cannot reach the backend

    saw, out, _ = _through([request], private_paths=["/private"],
                           private_path_allow=["127.0.0.1/32"], path_override_block=False)
    assert saw.startswith(b"GET /public HTTP/1.1")
    assert b"Cache-Control: private, no-store" in out


def test_archive_mime_is_unscannable_without_decompressing_download():
    with io.BytesIO() as buffer:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("sample.txt", _DUMMY)
        body = buffer.getvalue()
    resp = _response(body, b"Content-Type: application/zip",
                     b"Content-Disposition: attachment; filename=sample.zip")
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block")
    assert out == b""
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="audit")
    assert out == resp and sh.metrics().get("dlp_unscannable", 0) == 1


def test_archive_magic_stops_mislabeled_download_across_splits():
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            data = b"safe example"
            info = tarfile.TarInfo("sample.txt")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        tar_body = buffer.getvalue()
    examples = (gzip.compress(_DUMMY), bz2.compress(_DUMMY), lzma.compress(_DUMMY),
                tar_body, b"7z\xbc\xaf\x27\x1c" + b"safe", b"Rar!\x1a\x07\x00" + b"safe")
    for body in examples:
        resp = _response(body, b"Content-Type: text/plain")  # MIME may be misleading
        for step in (1, 65536):
            out, sh = _pipe([resp[i:i + step] for i in range(0, len(resp), step)],
                            dlp_enabled=True, dlp_action="block")
            assert body not in out, (body[:8], step)
            assert sh.metrics().get("dlp_unscannable", 0) == 1, (body[:8], step)

    zipped = gzip.compress(_DUMMY)
    wire = (b"1;note=" + b"x" * 100 + b"\r\n" + zipped[:1] + b"\r\n"
            + b"%x\r\n" % (len(zipped) - 1) + zipped[1:] + b"\r\n0\r\n\r\n")
    chunked = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n" + wire)
    out, sh = _pipe([chunked[:75], chunked[75:]], dlp_enabled=True, dlp_action="block")
    assert zipped not in out and sh.metrics().get("dlp_unscannable", 0) == 1
    out, sh = _pipe([chunked], dlp_enabled=True, dlp_action="audit")
    assert out == chunked and sh.metrics().get("dlp_unscannable", 0) == 1

    # Ordinary images and CSV attachments remain eligible for raw DLP scanning.
    for body, headers in ((b"\x89PNG\r\n\x1a\n" + b"safe", (b"Content-Type: image/png",)),
                          (b"name,value\nexample,safe\n",
                           (b"Content-Type: text/csv", b"Content-Disposition: attachment"))):
        resp = _response(body, *headers)
        out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block")
        assert out == resp and sh.metrics().get("dlp_unscannable", 0) == 0


def test_ambiguous_response_framing_is_unscannable_before_head_publication():
    invalid = (
        b"Content-Length: 2\r\nContent-Length: 2",
        b"Content-Length: -2",
        b"Content-Length: 2, 2",
        b"Content-Length: " + b"9" * 40,
        b"Transfer-Encoding: chunked\r\nContent-Length: 2",
        b"Transfer-Encoding: gzip, chunked",
    )
    for headers in invalid:
        resp = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n\r\nok"
        out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block")
        assert out == b"", headers
        assert sh.metrics().get("dlp_unscannable", 0) == 1, headers
        out, sh = _pipe([resp], dlp_enabled=True, dlp_action="audit")
        assert out == b"" and sh.metrics().get("dlp_unscannable", 0) == 1

    normal = b"HTTP/1.1 200 OK\r\nContent-Length: 002\r\n\r\nok"
    out, sh = _pipe([normal], dlp_enabled=True, dlp_action="block")
    assert out == normal and sh.metrics().get("dlp_unscannable", 0) == 0
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
    out, sh = _pipe([chunked], dlp_enabled=True, dlp_action="block")
    assert out == chunked and sh.metrics().get("dlp_unscannable", 0) == 0
