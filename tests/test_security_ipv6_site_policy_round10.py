"""Bracketed IPv6 Host policies must inspect the same authority sent upstream."""

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


def _transit(host: bytes, *, mode="enforce", policy="blacklist", entries=None):
    backend = _Backend()
    try:
        with _shield() as shield, _guard(backend) as guard:
            values = entries if entries is not None else ["[::1]"]
            settings = {"mode": mode, "site_mode": policy, "block_page": False,
                        "site_blacklist" if policy == "blacklist" else "site_whitelist": values}
            result = shield.set_config(**settings)
            assert result.get("ok") is True, result
            request = b"GET /public HTTP/1.1\r\nHost: " + host + b"\r\n\r\n"
            client = _exchange(guard, [request])
            events = shield.events(100)
        return request, backend.saw(), client, events
    finally:
        backend.close()


def test_blacklisted_bracketed_ipv6_host_never_reaches_real_backend():
    for host, entries in ((b"[::1]", ["[::1]"]),
                          (b"[0:0:0:0:0:0:0:1]", ["[::1]"]),
                          (b"[::1]:8080", ["::1"])):
        request, upstream, client, _ = _transit(host, entries=entries)
        assert request.startswith(b"GET /public HTTP/1.1\r\n")
        assert upstream == b"" and client == b"", (host, upstream, client)


def test_ipv6_site_blacklist_audit_records_and_forwards_exact_host():
    request, upstream, client, events = _transit(b"[::1]", mode="audit")
    assert upstream.startswith(request[:-2])
    assert client.startswith(b"HTTP/1.1 200 OK\r\n")
    assert any(e.get("kind") == "audit" for e in events)


def test_ipv6_site_policy_keeps_other_ipv6_and_domain_controls():
    request, upstream, client, _ = _transit(b"[::2]")
    assert upstream.startswith(request[:-2]) and client.startswith(b"HTTP/1.1 200 OK\r\n")
    _, upstream, client, _ = _transit(b"blocked.example", entries=["blocked.example"])
    assert upstream == b"" and client == b""


def test_whitelisted_bracketed_ipv6_host_is_allowed_but_other_is_blocked():
    _, upstream, client, _ = _transit(b"[::1]", policy="whitelist")
    assert upstream and client.startswith(b"HTTP/1.1 200 OK\r\n")
    _, upstream, client, _ = _transit(b"[::2]", policy="whitelist")
    assert upstream == b"" and client == b""
