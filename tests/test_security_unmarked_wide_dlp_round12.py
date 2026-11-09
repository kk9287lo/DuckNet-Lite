"""Unlabelled wide text must not turn a DLP block into exact secret delivery."""

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield
from test_sweep_det_response import _pipe


_TOKEN = "ghp_" + "a" * 36  # inert synthetic credential-shaped marker
_REQUEST = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(body, media=b"text/plain"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + media +
            b"\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\nConnection: close\r\n\r\n" + body)


def _wire(response, *, mode="enforce"):
    backend = _Backend(response)
    try:
        with _shield(dlp_enabled=True, dlp_action="block", mode=mode,
                     **_QUIET) as shield, _guard(backend) as edge:
            received = _exchange(edge, [_REQUEST])
            metrics, events = shield.metrics(), shield.events(20)
        return backend.saw(), received, metrics, events
    finally:
        backend.close()


def test_unmarked_wide_credential_with_ordinary_text_prefix_never_reaches_client():
    # A recipient can decode these raw bytes even without a charset header.
    # The first character is deliberately not JSON/XML punctuation.
    for encoding in ("utf-16le", "utf-16be", "utf-32le", "utf-32be"):
        body = ("x" + _TOKEN).encode(encoding)
        assert _TOKEN in body.decode(encoding)
        upstream, client, metrics, events = _wire(_response(body))
        assert upstream.startswith(_REQUEST[:-2]), encoding
        assert body not in client, (encoding, client)
        assert metrics.get("dlp_unscannable", 0) == 1, (encoding, metrics)
        assert any(e.get("kind") == "dlp_unscannable" for e in events), encoding


def test_unmarked_wide_audit_preserves_exact_wire_and_records_block_intent():
    body = ("x" + _TOKEN).encode("utf-16le")
    response = _response(body)
    upstream, client, metrics, events = _wire(response, mode="audit")
    assert upstream.startswith(_REQUEST[:-2]) and client == response
    assert metrics.get("dlp_unscannable", 0) == 1
    assert any(e.get("kind") == "dlp_unscannable" and e.get("would") == "block"
               for e in events)


def test_non_ascii_leading_wide_text_does_not_hide_later_ascii_token():
    # The whole body is valid wide text. Sniffing only the first ASCII
    # punctuation/space codepoint misses a Japanese title before the token.
    for encoding in ("utf-16le", "utf-16be", "utf-32le", "utf-32be"):
        body = ("東京" + _TOKEN).encode(encoding)
        assert _TOKEN in body.decode(encoding)
        upstream, client, metrics, _ = _wire(_response(body))
        assert upstream.startswith(_REQUEST[:-2]), encoding
        assert body not in client, (encoding, client)
        assert metrics.get("dlp_unscannable", 0) == 1, (encoding, metrics)


def test_wide_token_after_long_non_ascii_text_is_withheld_before_prefix_release():
    # The first 262 bytes contain no ASCII-wide token cue. The body remains a
    # single valid UTF-16/32 string, and an ordinary recipient decodes it.
    for encoding in ("utf-16le", "utf-16be", "utf-32le", "utf-32be"):
        body = ("東京" * 160 + _TOKEN).encode(encoding)
        wide_prefix = _TOKEN[:3].encode(encoding)
        assert _TOKEN in body.decode(encoding)
        assert body.find(wide_prefix) > 262
        upstream, client, metrics, _ = _wire(_response(body))
        assert upstream.startswith(_REQUEST[:-2]), encoding
        assert wide_prefix not in client, (encoding, client)
        assert metrics.get("dlp_unscannable", 0) == 1, (encoding, metrics)


def test_split_wide_prefix_is_not_released_before_detection():
    body = ("東京" * 160 + _TOKEN).encode("utf-16le")
    response = _response(body)
    head, _, _ = response.partition(b"\r\n\r\n")
    split_at = len(head) + 4 + body.find(_TOKEN[:3].encode("utf-16le"))
    for cut in (1, 3, 5, 11):
        parts = [response[:split_at + cut], response[split_at + cut:]]
        client, shield = _pipe(parts, dlp_enabled=True, dlp_action="block", **_QUIET)
        assert _TOKEN[:3].encode("utf-16le") not in client, cut
        assert shield.metrics().get("dlp_unscannable", 0) == 1, cut


def test_wide_bom_and_ordinary_utf8_binary_controls_keep_their_meaning():
    # Existing BOM rejection remains in force; ordinary text and a binary
    # payload without a wide-text prefix remain byte-identical on the wire.
    for encoding in ("utf-16", "utf-32"):
        body = ("x" + _TOKEN).encode(encoding)
        _, client, metrics, _ = _wire(_response(body))
        assert body not in client and metrics.get("dlp_unscannable", 0) == 1
    for body, media in ((b"xpublic report", b"text/plain"),
                        (b"\x89PNG\r\n\x1a\n" + b"x\x00y\x00\xff" + b"\x00" * 24,
                         b"image/png")):
        response = _response(body, media)
        upstream, client, metrics, _ = _wire(response)
        assert upstream.startswith(_REQUEST[:-2]) and client == response
        assert metrics.get("dlp_unscannable", 0) == 0
