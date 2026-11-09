"""Private-response trailers cannot undo the cache policy on the wire."""
from test_sweep_proxy_request import _through


_REQUEST = b"GET /private/item HTTP/1.1\r\nHost: app.example\r\n\r\n"
_HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
_CHUNK = b"5\r\nhello\r\n0\r\n"
_CFG = {"private_paths": ["/private"],
        "private_path_allow": ["127.0.0.1/32"], "enabled": False,
        "dlp_enabled": False, "sec_headers_enabled": False,
        "cookie_harden_enabled": False, "cors_harden_enabled": False,
        "open_redirect_enabled": False}


def test_private_cache_directives_in_trailers_never_override_no_store():
    for name, value in ((b"Cache-Control", b"public, max-age=3600"),
                        (b"Surrogate-Control", b"max-age=3600"),
                        (b"CDN-Cache-Control", b"public, max-age=3600"),
                        (b"Cloudflare-CDN-Cache-Control", b"public, max-age=3600"),
                        (b"X-Accel-Expires", b"3600")):
        response = _HEAD + _CHUNK + name + b": " + value + b"\r\n\r\n"
        for mode in ("enforce", "audit"):
            upstream, downstream, metrics = _through(
                [_REQUEST], backend_resp=response, mode=mode, **_CFG)
            assert upstream.startswith(b"GET /private/item HTTP/1.1\r\n")
            assert b"Cache-Control: private, no-store\r\n" in downstream
            assert name + b": " + value not in downstream, (name, mode, downstream)
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_private_public_trailer_still_keeps_exact_body_bytes():
    response = _HEAD + _CHUNK + b"X-Note: public\r\n\r\n"
    for mode in ("enforce", "audit"):
        upstream, downstream, metrics = _through(
            [_REQUEST], backend_resp=response, mode=mode, **_CFG)
        assert upstream.startswith(b"GET /private/item HTTP/1.1\r\n")
        assert b"Cache-Control: private, no-store\r\n" in downstream
        assert downstream.endswith(_CHUNK + b"X-Note: public\r\n\r\n"), downstream
        assert metrics.get("backend_invalid_response", 0) == 0, metrics


def test_late_cookie_cors_and_navigation_fields_cannot_escape_head_policies():
    request = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
    for name, value in ((b"Set-Cookie", b"sid=public-marker"),
                        (b"Access-Control-Allow-Origin", b"*"),
                        (b"Access-Control-Allow-Credentials", b"true"),
                        (b"Location", b"https://elsewhere.example/"),
                        (b"Refresh", b"0; URL=https://elsewhere.example/")):
        response = _HEAD + _CHUNK + name + b": " + value + b"\r\n\r\n"
        for mode in ("audit", "enforce"):
            _, downstream, metrics = _through(
                [request], backend_resp=response, mode=mode,
                cookie_harden_enabled=True, cors_harden_enabled=True,
                open_redirect_enabled=True, open_redirect_mode=mode,
                sec_headers_enabled=False, dlp_enabled=False)
            assert name + b": " + value not in downstream, (mode, name, downstream)
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_configured_response_header_strip_and_override_cover_trailers():
    request = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
    cfg = dict(_CFG, sec_headers_enabled=True,
               sec_headers_strip=["X-Public-Secret"],
               sec_headers_extra={"X-Extra": "safe"})
    for name in (b"X-Public-Secret", b"X-Extra"):
        response = _HEAD + _CHUNK + name + b": private-marker\r\n\r\n"
        _, downstream, metrics = _through([request], backend_resp=response, **cfg)
        assert b"private-marker" not in downstream, downstream
        assert metrics.get("backend_invalid_response") == 1, metrics
        if name == b"X-Extra":
            assert b"X-Extra: safe\r\n" in downstream


def test_refreshed_200_cannot_bypass_external_redirect_policy():
    request = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
    body = b"<html><body>public</body></html>"
    response = (b"HTTP/1.1 200 OK\r\n"
                b"Refresh: 0; URL=https://elsewhere.example/public\r\n"
                b"Content-Type: text/html\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
    for mode in ("enforce", "audit"):
        upstream, downstream, metrics = _through(
            [request], backend_resp=response, open_redirect_enabled=True,
            open_redirect_mode=mode, open_redirect_allow=[],
            cookie_harden_enabled=False, cors_harden_enabled=False,
            sec_headers_enabled=False, dlp_enabled=False)
        assert upstream.startswith(b"GET /public/report HTTP/1.1\r\n")
        assert metrics.get("open_redirect") == 1, (mode, downstream, metrics)
        if mode == "enforce":
            assert b"elsewhere.example" not in downstream
            assert b"Refresh: 0; URL=/\r\n" in downstream
        else:
            assert downstream == response


def test_benign_refresh_target_and_timer_remain_byte_exact():
    request = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
    body = b"<html><body>public</body></html>"
    for field in (b"Refresh: 5; URL=/local", b"Refresh: 5; URL=https://app.example/local",
                  b"Refresh: 5"):
        response = (b"HTTP/1.1 200 OK\r\n" + field
                    + b"\r\nContent-Type: text/html\r\nContent-Length: "
                    + str(len(body)).encode() + b"\r\n\r\n" + body)
        _, downstream, metrics = _through(
            [request], backend_resp=response, open_redirect_enabled=True,
            open_redirect_mode="enforce", open_redirect_allow=[],
            cookie_harden_enabled=False, cors_harden_enabled=False,
            sec_headers_enabled=False, dlp_enabled=False)
        assert downstream == response and metrics.get("open_redirect", 0) == 0


def test_invalid_legacy_response_header_config_cannot_publish_bytes():
    request = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    bad = ({"X-Public": "safe\r\nX-Marker: injected"},
           {"X-Public\r\nX-Marker": "injected"},
           {"X-Public": "value\x00tail"},
           {"Content-Length": "99"},
           {"Transfer-Encoding": "chunked"},
           {"Content-Type": "application/json"},
           {"X-Origin-IP": "private-origin.example"},
           {"X-Public": "A" * 16385})
    for extra in bad:
        cfg = dict(_CFG, sec_headers_enabled=True, sec_headers_extra=extra)
        upstream, downstream, metrics = _through([request], backend_resp=response, **cfg)
        assert upstream.startswith(b"GET /public/report HTTP/1.1\r\n")
        assert downstream == b"", (extra.keys(), downstream)
        assert metrics.get("response_config_invalid") == 1, metrics

    cfg = dict(_CFG, sec_headers_enabled=True,
               sec_headers_extra={"X-Public": "safe"})
    _, downstream, metrics = _through([request], backend_resp=response, **cfg)
    assert downstream.endswith(b"\r\n\r\nok")
    assert b"X-Public: safe\r\n" in downstream
    assert metrics.get("response_config_invalid", 0) == 0


def test_cookie_name_or_spaced_attribute_cannot_downgrade_samesite():
    request = b"GET /public/report HTTP/1.1\r\nHost: app.example\r\n\r\n"
    cases = ((b"Set-Cookie: samesite=1; Path=/", b"SameSite=Lax", 2),
             (b"Set-Cookie: sid=1; SameSite = Strict", b"SameSite = Strict", 1),
             (b"Set-Cookie: sid=1; SameSite=bogus", b"SameSite=Lax", 2),
             (b"Set-Cookie: sid=1; SameSite=Strict; SameSite=bogus", b"SameSite=Lax", 3),
             (b"Set-Cookie: sid=1; SameSite=Strict", b"SameSite=Strict", 1))
    for field, expected, count in cases:
        backend = b"HTTP/1.1 200 OK\r\n" + field + b"\r\nContent-Length: 2\r\n\r\nok"
        _, downstream, _ = _through(
            [request], backend_resp=backend, cookie_harden_enabled=True,
            cookie_samesite="Lax", sec_headers_enabled=False,
            cors_harden_enabled=False, open_redirect_enabled=False, dlp_enabled=False)
        cookie_line = next(line for line in downstream.split(b"\r\n") if line.lower().startswith(b"set-cookie:"))
        assert expected in cookie_line and cookie_line.lower().count(b"samesite") == count, cookie_line
