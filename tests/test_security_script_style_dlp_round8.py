"""Script and CSS representations cannot be normalized by static response DLP."""

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_REQUEST = b"GET /asset HTTP/1.1\r\nHost: local.test\r\n\r\n"
_TOKEN = b"ghp_" + b"a" * 36
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(body, media):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + media
            + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)


def _transit(response, *, enabled=True, action="block", mode="enforce"):
    backend = _Backend(response)
    try:
        with _shield(dlp_enabled=enabled, dlp_action=action, mode=mode,
                     **_QUIET) as shield, _guard(backend) as guard:
            client = _exchange(guard, [_REQUEST])
            metrics, events = shield.metrics(), shield.events(100)
        return backend.saw(), client, metrics, events
    finally:
        backend.close()


def _assert_dlp_media(response, reason):
    backend, client, metrics, events = _transit(response)
    assert backend.startswith(b"GET /asset HTTP/1.1\r\n")
    assert client == b"" and metrics.get("dlp_unscannable") == 1
    assert any(e.get("kind") == "dlp_unscannable" and e.get("encoding") == reason
               for e in events)

    _, client, metrics, events = _transit(response, action="audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == reason for e in events)

    _, client, metrics, events = _transit(response, mode="audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == reason and e.get("would") == "block"
               for e in events)


def test_javascript_escape_secret_is_unscannable_before_any_client_head():
    body = b'const key="gh\\x70_' + b"a" * 36 + b'";'
    assert _TOKEN not in body and _TOKEN in body.replace(b"\\x70", b"p")
    for media in (
        b"application/ecmascript", b"application/javascript",
        b"application/x-ecmascript", b"application/x-javascript",
        b"text/ecmascript", b"text/javascript", b"text/javascript1.0",
        b"text/javascript1.1", b"text/javascript1.2", b"text/javascript1.3",
        b"text/javascript1.4", b"text/javascript1.5", b"text/jscript",
        b"text/livescript", b"text/x-ecmascript", b"text/x-javascript",
    ):
        _assert_dlp_media(_response(body, media), "js-media")


def test_css_escape_secret_is_unscannable_before_any_client_head():
    body = b'body::before{content:"gh\\70_' + b"a" * 36 + b'"}'
    assert _TOKEN not in body and _TOKEN in body.replace(b"\\70", b"p")
    _assert_dlp_media(_response(body, b"text/css"), "css-media")


def test_benign_script_and_css_keep_exact_wire_in_audit_and_dlp_off():
    for media, body, reason in (
        (b"text/javascript", b"const ok = true;", "js-media"),
        (b"text/css", b"body { color: blue; }", "css-media"),
    ):
        response = _response(body, media)
        _, client, metrics, events = _transit(response, action="audit")
        assert client == response and metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == reason for e in events)
        _, client, metrics, _ = _transit(response, enabled=False)
        assert client == response and not metrics.get("dlp_unscannable")


def test_bodyless_script_and_css_metadata_has_no_interpretable_payload():
    for media in (b"text/javascript", b"application/javascript", b"text/css"):
        response = _response(b"", media)
        for action in ("block", "audit"):
            _, client, metrics, _ = _transit(response, action=action)
            assert client == response
            assert not metrics.get("dlp_unscannable")
