"""Percent-decoded response metadata must not hide an egress DLP token."""

from html.parser import HTMLParser
from urllib.parse import unquote_to_bytes
from xml.etree import ElementTree

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_TOKEN = b"ghp_" + b"a" * 36  # inert marker matching the existing DLP rule
_REQUEST = b"GET /view HTTP/1.1\r\nHost: local.test\r\n\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(field, value):
    return (b"HTTP/1.1 302 Found\r\n" + field + b": " + value
            + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def _document_response(body, media=b"text/html"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + media
            + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)


def _transit(response, action):
    backend = _Backend(response)
    try:
        with _shield(dlp_enabled=True, dlp_action=action, **_QUIET) as shield, \
                _guard(backend) as guard:
            client = _exchange(guard, [_REQUEST])
            metrics, events = shield.metrics(), shield.events(100)
        return backend.saw(), client, metrics, events
    finally:
        backend.close()


def test_percent_encoded_location_secret_is_blocked_before_client_head():
    value = b"/next?token=gh%70_" + b"a" * 36
    response = _response(b"Location", value)
    assert _TOKEN not in response and _TOKEN in unquote_to_bytes(value)

    backend, client, metrics, _ = _transit(response, "block")
    assert backend.startswith(b"GET /view HTTP/1.1\r\n")
    assert client == b"" and metrics.get("dlp_leak") == 1

    backend, client, metrics, events = _transit(response, "audit")
    assert backend.startswith(b"GET /view HTTP/1.1\r\n")
    assert client == response and metrics.get("dlp_leak") == 1
    assert any(event.get("kind") == "dlp_leak" for event in events)


def test_percent_encoded_metadata_and_benign_redirect_keep_distinct_decisions():
    value = b"/next?token=gh%70_" + b"a" * 36
    for field, prefix, suffix in ((b"Content-Location", b"", b""),
                                  (b"Refresh", b"0; url=", b""),
                                  (b"Link", b"<", b">; rel=next"),
                                  (b"Location", b"https://", b"@local.test/")):
        response = _response(field, prefix + value + suffix)
        assert _TOKEN not in response and _TOKEN in unquote_to_bytes(response)
        _, client, metrics, _ = _transit(response, "block")
        assert client == b"" and metrics.get("dlp_leak") == 1, field
        _, client, metrics, events = _transit(response, "audit")
        assert client == response and metrics.get("dlp_leak") == 1, field
        assert any(event.get("kind") == "dlp_leak" for event in events)

    for value in (b"/next?message=public%20value", b"/next?message=%GG",
                  b"/next?token=gh%2570_" + b"a" * 36):
        # One URLSearchParams decode of %25 leaves literal %70. A second
        # application-specific decode is outside the browser's URL view.
        assert _TOKEN not in unquote_to_bytes(value)
        benign = _response(b"Location", value)
        _, client, metrics, _ = _transit(benign, "block")
        assert client == benign and not metrics.get("dlp_leak")
        assert not metrics.get("dlp_unscannable")


def test_percent_encoded_markup_url_targets_are_scanned_before_body_release():
    class UrlAttrs(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.values = []

        def handle_starttag(self, tag, attrs):
            self.values.extend(value for name, value in attrs
                               if name in ("href", "content") and value)

    url = b"/next?token=gh%70_" + b"a" * 36
    bodies = (b'<a href="' + url + b'">next</a>',
              b'<meta http-equiv="refresh" content="0; url=' + url + b'">')
    for body in bodies:
        parser = UrlAttrs()
        parser.feed(body.decode("ascii"))
        assert _TOKEN not in body
        assert any(_TOKEN in unquote_to_bytes(value) for value in parser.values)
        response = _document_response(body)
        backend, client, metrics, _ = _transit(response, "block")
        assert backend.startswith(b"GET /view HTTP/1.1\r\n")
        assert client.partition(b"\r\n\r\n")[2] == b""
        assert metrics.get("dlp_leak") == 1
        _, client, metrics, events = _transit(response, "audit")
        assert client == response and metrics.get("dlp_leak") == 1
        assert any(event.get("kind") == "dlp_leak" for event in events)

    benign = _document_response(b'<a href="/next?message=public%20value">next</a>')
    _, client, metrics, _ = _transit(benign, "block")
    assert client == benign and not metrics.get("dlp_leak")
    assert not metrics.get("dlp_unscannable")


def test_percent_encoded_svg_link_uses_xml_attribute_view():
    url = b"/next?token=gh%70_" + b"a" * 36
    body = (b'<svg xmlns:xlink="http://www.w3.org/1999/xlink">'
            b'<a xlink:href="' + url + b'"><text>next</text></a></svg>')
    node = ElementTree.fromstring(body)
    attr = next(value for element in node.iter() for value in element.attrib.values()
                if value.startswith("/next?"))
    assert _TOKEN not in body and _TOKEN in unquote_to_bytes(attr)
    response = _document_response(body, b"image/svg+xml")
    _, client, metrics, _ = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_leak") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1
    assert any(event.get("kind") == "dlp_leak" for event in events)
