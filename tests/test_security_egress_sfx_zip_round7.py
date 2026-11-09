"""A ZIP with a harmless-looking preamble is still opaque to egress DLP."""

import io
import zipfile

from test_sweep_det_response import _pipe
from test_sweep_proxy_request import _through


_MARKER = b"ghp_" + b"a" * 36  # inert synthetic credential marker
_REQUEST = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
_REQUEST_LINE = b"GET /public/report HTTP/1.1\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _archive():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("private.txt", _MARKER)
    body = stream.getvalue()
    assert _MARKER not in body
    assert zipfile.ZipFile(io.BytesIO(body)).read("private.txt") == _MARKER
    return body


def _response(body, disposition=b""):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + (b"Content-Disposition: " + disposition + b"\r\n" if disposition else b"")
            + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def test_disguised_zip_download_never_reaches_real_client_in_enforce():
    body = b"MZ" + b"A" * 300 + _archive()
    assert zipfile.ZipFile(io.BytesIO(body)).read("private.txt") == _MARKER
    for disposition in (b'attachment; filename="report.zip"',
                        b"attachment; filename*=UTF-8''report%2Ezip",
                        b'inline; filename="report;v1.zip"'):
        response = _response(body, disposition)
        received, out, _ = _through([_REQUEST], backend_resp=response,
                                    dlp_enabled=True, dlp_action="block", **_QUIET)
        assert received.startswith(_REQUEST_LINE)
        assert out == b"", (disposition, len(out))

        received, out, _ = _through([_REQUEST], backend_resp=response,
                                    dlp_enabled=True, dlp_action="audit", **_QUIET)
        assert received.startswith(_REQUEST_LINE) and out == response
        checked, shield = _pipe([response], dlp_enabled=True, dlp_action="audit", **_QUIET)
        assert checked == response and shield.metrics().get("dlp_unscannable", 0) == 1


def test_zip_magic_after_preamble_is_caught_across_chunk_boundaries():
    body = b"public " + b"A" * 300 + _archive()
    response = _response(body)
    split = response.index(b"PK\x03\x04") + 2
    chunks = [response[:split], response[split:split + 1], response[split + 1:]]
    for variant in (chunks, [response]):
        out, shield = _pipe(variant, dlp_enabled=True, dlp_action="block", **_QUIET)
        assert b"PK\x03\x04" not in out and body not in out
        assert shield.metrics().get("dlp_unscannable", 0) == 1
        out, shield = _pipe(variant, dlp_enabled=True, dlp_action="audit", **_QUIET)
        assert out == response and shield.metrics().get("dlp_unscannable", 0) == 1
    received, out, _ = _through([_REQUEST], backend_resp=response,
                                dlp_enabled=True, dlp_action="block", **_QUIET)
    assert received.startswith(_REQUEST_LINE) and b"PK\x03\x04" not in out


def test_benign_downloads_keep_wire_bytes_and_initial_zip_stays_blocked():
    for body, disposition in ((b"public sample", b""),
                              (b"name,value\nexample,safe\n", b"attachment; filename=report.csv"),
                              (b"public sample", b"attachment; filename=report.zip.txt")):
        response = _response(body, disposition)
        received, out, _ = _through([_REQUEST], backend_resp=response,
                                    dlp_enabled=True, dlp_action="block", **_QUIET)
        assert received.startswith(_REQUEST_LINE) and out == response
    response = _response(_archive())
    _, out, _ = _through([_REQUEST], backend_resp=response,
                         dlp_enabled=True, dlp_action="block", **_QUIET)
    assert b"PK\x03\x04" not in out
