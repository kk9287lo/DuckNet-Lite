"""A response Connection option cannot remove edge-added protection downstream."""

from test_sweep_proxy_request import _through


_REQUEST = b"GET /private/item HTTP/1.1\r\nHost: app.example\r\n\r\n"
_PUBLIC = b"GET /public/item HTTP/1.1\r\nHost: app.example\r\n\r\n"
_QUIET = {"dlp_enabled": False, "sec_headers_enabled": False,
          "cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _hop_stripped(response):
    """Model the next compliant intermediary's Connection-field removal."""
    head, sep, body = response.partition(b"\r\n\r\n")
    if not sep:
        return response
    lines = head.split(b"\r\n")
    nominated = {part.strip().lower()
                 for line in lines[1:] if line.lower().startswith(
                     (b"connection:", b"proxy-connection:"))
                 for part in line.partition(b":")[2].split(b",")}
    kept = [lines[0]] + [line for line in lines[1:]
                         if line.partition(b":")[0].lower() not in
                         nominated | {b"connection", b"proxy-connection"}]
    return b"\r\n".join(kept) + sep + body


def test_private_cache_directives_cannot_be_nominated_out_of_the_next_hop():
    for field in (b"Connection", b"Proxy-Connection"):
        response = (b"HTTP/1.1 200 OK\r\n" + field
                    + b": Cache-Control, Pragma, Expires\r\n"
                    b"Cache-Control: public, max-age=3600\r\n"
                    b"Content-Length: 2\r\n\r\nok")
        for mode in ("enforce", "audit"):
            upstream, downstream, metrics = _through(
                [_REQUEST], backend_resp=response, mode=mode,
                private_paths=["/private"], private_path_allow=["127.0.0.1/32"],
                **_QUIET)
            assert upstream.startswith(_REQUEST.partition(b"\r\n\r\n")[0])
            assert downstream == b"", (mode, field, _hop_stripped(downstream))
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_configured_security_header_cannot_be_nominated_out_of_the_next_hop():
    for field in (b"Connection", b"Proxy-Connection"):
        response = (b"HTTP/1.1 200 OK\r\n" + field + b": X-Extra\r\n"
                    b"Content-Length: 2\r\n\r\nok")
        for mode in ("enforce", "audit"):
            upstream, downstream, metrics = _through(
                [_PUBLIC], backend_resp=response, mode=mode,
                sec_headers_enabled=True, sec_headers_extra={"X-Extra": "safe"},
                dlp_enabled=False, cookie_harden_enabled=False,
                cors_harden_enabled=False, open_redirect_enabled=False)
            assert upstream.startswith(_PUBLIC.partition(b"\r\n\r\n")[0])
            assert downstream == b"", (mode, field, _hop_stripped(downstream))
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_default_security_header_cannot_be_nominated_out_of_the_next_hop():
    for field in (b"Connection", b"Proxy-Connection"):
        response = (b"HTTP/1.1 200 OK\r\n" + field + b": X-Frame-Options\r\n"
                    b"Content-Length: 2\r\n\r\nok")
        for mode in ("enforce", "audit"):
            _, downstream, metrics = _through(
                [_PUBLIC], backend_resp=response, mode=mode,
                sec_headers_enabled=True, dlp_enabled=False,
                cookie_harden_enabled=False, cors_harden_enabled=False,
                open_redirect_enabled=False)
            assert downstream == b"", (mode, field, _hop_stripped(downstream))
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_cache_variant_and_download_semantics_survive_the_next_hop():
    for field in (b"Connection", b"Proxy-Connection"):
        for name, value in ((b"Vary", b"Accept-Encoding"),
                            (b"Content-Disposition", b"attachment; filename=public.txt")):
            response = (b"HTTP/1.1 200 OK\r\n" + field + b": " + name + b"\r\n"
                        + name + b": " + value + b"\r\nContent-Length: 2\r\n\r\nok")
            for mode in ("enforce", "audit"):
                _, downstream, metrics = _through(
                    [_PUBLIC], backend_resp=response, mode=mode, **_QUIET)
                assert downstream == b"", (mode, field, name, _hop_stripped(downstream))
                assert metrics.get("backend_invalid_response") == 1, metrics


def test_browser_isolation_header_cannot_be_nominated_out_of_the_next_hop():
    cases = ((b"Connection", b"Permissions-Policy", b"geolocation=()"),
             (b"Proxy-Connection", b"Cross-Origin-Opener-Policy", b"same-origin"))
    for field, name, value in cases:
        response = (b"HTTP/1.1 200 OK\r\n" + field + b": " + name + b"\r\n"
                    + name + b": " + value + b"\r\nContent-Length: 2\r\n\r\nok")
        for mode in ("enforce", "audit"):
            _, downstream, metrics = _through(
                [_PUBLIC], backend_resp=response, mode=mode, **_QUIET)
            assert downstream == b"", (mode, field, name, _hop_stripped(downstream))
            assert metrics.get("backend_invalid_response") == 1, metrics


def test_safe_connection_options_preserve_benign_response_bytes():
    for field, option, header in (
            (b"Connection", b"close", b""),
            (b"Connection", b"X-Hop", b"X-Hop: public\r\n"),
            (b"Proxy-Connection", b"X-Hop", b"X-Hop: public\r\n")):
        response = (b"HTTP/1.1 200 OK\r\n" + field + b": " + option + b"\r\n"
                    + header + b"Content-Length: 2\r\n\r\nok")
        for mode in ("enforce", "audit"):
            upstream, downstream, metrics = _through(
                [_PUBLIC], backend_resp=response, mode=mode, **_QUIET)
            assert upstream.startswith(_PUBLIC.partition(b"\r\n\r\n")[0])
            assert downstream == response, (mode, field, option, downstream)
            assert metrics.get("backend_invalid_response", 0) == 0, metrics
