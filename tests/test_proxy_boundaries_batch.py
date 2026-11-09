"""Real-wire regressions for proxy trust and resource boundaries."""

import asyncio
import gzip
import socket
import threading

import dataplane.engine.services.proxy as P
from test_sweep_proxy_request import _guard, _run_pipe, _shield, _through


_LEAK = b"AKIAIOSFODNN7EXAMPLE"
_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def test_dlp_checks_chunk_extension_wire_bytes_before_release():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    body = b"1;note=" + _LEAK + b"\r\nx\r\n0\r\n\r\n"
    out, shield = _run_pipe([head + body], dlp_enabled=True, dlp_action="block")
    assert _LEAK not in out and shield.metrics().get("dlp_leak", 0) >= 1

    # A read boundary inside the extension cannot release the secret prefix.
    out, shield = _run_pipe([head + b"1;note=AKIAIOS", b"FODNN7EXAMPLE\r\nx\r\n0\r\n\r\n"],
                            dlp_enabled=True, dlp_action="block")
    assert _LEAK not in out and shield.metrics().get("dlp_leak", 0) >= 1

    out, shield = _run_pipe([head + body], dlp_enabled=True, dlp_action="audit")
    assert out == head + body and shield.metrics().get("dlp_leak", 0) >= 1

    benign = head + b"1;note=ok\r\nx\r\n0\r\n\r\n"
    out, shield = _run_pipe([benign], dlp_enabled=True, dlp_action="block")
    assert out == benign and shield.metrics().get("dlp_leak", 0) == 0


def test_body_is_validated_before_backend_accepts_a_connection():
    class Backend:
        def __init__(self):
            self.socket = socket.socket()
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(1)
            self.socket.settimeout(0.1)
            self.port = self.socket.getsockname()[1]
            self.accepted = threading.Event()
            self.stopping = threading.Event()
            self.got = b""
            self.worker = threading.Thread(target=self.serve, daemon=True)
            self.worker.start()

        def serve(self):
            while not self.stopping.is_set():
                try:
                    conn, _ = self.socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                self.accepted.set()
                with conn:
                    conn.settimeout(2)
                    parts = []
                    while True:
                        try:
                            part = conn.recv(4096)
                        except OSError:
                            break
                        if not part:
                            break
                        parts.append(part)
                    self.got = b"".join(parts)
                    try:
                        conn.sendall(_OK)
                    except OSError:
                        pass
                return

        def close(self):
            self.stopping.set()
            self.socket.close()
            self.worker.join(2)

    backend = Backend()
    try:
        with _shield(body_scan_max_bytes=1024), _guard(backend) as guard:
            with socket.create_connection(("127.0.0.1", guard.listen_port), timeout=2) as client:
                client.settimeout(3)
                client.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n"
                               b"Content-Length: 5\r\n\r\n")
                assert not backend.accepted.wait(0.15)
                client.sendall(b"hello")
                assert client.recv(4096).startswith(b"HTTP/1.1 200")
        assert backend.accepted.is_set() and backend.got.endswith(b"hello")
    finally:
        backend.close()

    attack = b"user=admin' or 1=1-- -"
    head = (b"POST /login HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(attack)).encode() + b"\r\n\r\n")
    received, _, metrics = _through([head, attack], body_scan_max_bytes=1024,
                                     block_score=20)
    assert received == b"" and metrics["proxied"] == 0


def test_backend_connect_has_a_deadline():
    async def stalled(*args, **kwargs):
        await asyncio.sleep(10)

    old_connect, old_limit = asyncio.open_connection, P._BACKEND_CONNECT_TIMEOUT
    asyncio.open_connection, P._BACKEND_CONNECT_TIMEOUT = stalled, 0.02
    try:
        guard = P.AsyncEdgeGuard()
        try:
            asyncio.run(guard._open_backend())
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("backend connect did not time out")
    finally:
        asyncio.open_connection, P._BACKEND_CONNECT_TIMEOUT = old_connect, old_limit


def test_host_authority_is_unambiguous_before_site_whitelist():
    for value in (b"allow.example:443@evil.example", b"allow.example/bad",
                  b"allow.example:bad", b"allow.example:65536",
                  b"allow.example,evil.example", b"::1", b"[::1]evil"):
        raw = b"GET / HTTP/1.1\r\nHost: " + value + b"\r\n\r\n"
        received, response, _ = _through([raw], site_mode="whitelist",
                                          site_whitelist=["allow.example"])
        assert received == b"" and response.startswith(b"HTTP/1.1 400"), value
    good = b"GET / HTTP/1.1\r\nHost: allow.example:443\r\n\r\n"
    received, response, _ = _through([good], site_mode="whitelist",
                                      site_whitelist=["allow.example"])
    assert b"Host: allow.example:443" in received and response.startswith(b"HTTP/1.1 200")
    ipv6 = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n"
    received, response, _ = _through([ipv6])
    assert b"Host: [::1]:8080" in received and response.startswith(b"HTTP/1.1 200")


def test_hostless_http10_cannot_skip_active_site_policy():
    hostless = b"GET / HTTP/1.0\r\n\r\n"
    assert P._framing_ambiguous(hostless) is False   # HTTP/1.0 itself permits no Host
    for cfg in ({"site_mode": "blacklist", "site_blacklist": ["default.example"]},
                {"site_mode": "whitelist", "site_whitelist": ["clean.example"]}):
        received, response, metrics = _through([hostless], **cfg)
        assert received == b"" and response.startswith(b"HTTP/1.1 400"), cfg
        assert metrics["proxied"] == 0

    # Without site policy, old HTTP/1.0 clients can still use the backend default vhost.
    received, response, metrics = _through([hostless], site_mode="off")
    assert received.startswith(hostless.split(b"\r\n", 1)[0])
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1
    with_host = b"GET / HTTP/1.0\r\nHost: clean.example\r\n\r\n"
    received, response, metrics = _through([with_host], site_mode="blacklist",
                                            site_blacklist=["default.example"])
    assert b"Host: clean.example" in received
    assert response.startswith(b"HTTP/1.1 200") and metrics["proxied"] == 1


def test_missing_peername_is_not_treated_as_loopback():
    class Reader:
        async def read(self, n):
            raise AssertionError("request should be rejected before body read")

    class Writer:
        closed = False

        def get_extra_info(self, name):
            return None

        def close(self):
            self.closed = True

    guard, writer = P.AsyncEdgeGuard(), Writer()
    asyncio.run(guard._handle_conn(Reader(), writer))
    assert writer.closed and guard.metrics["dropped"] == 1


def test_graphql_guard_rejects_encoded_body_when_decoder_is_disabled():
    query = b'{"query":"{ __schema { types { name } } }"}'
    compressed = gzip.compress(query)
    head = (b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: " + str(len(compressed)).encode()
            + b"\r\n\r\n")
    received, response, metrics = _through([head, compressed], graphql_enabled=True,
        graphql_paths=["/graphql"], body_scan_enabled=False, body_decode_enabled=False,
        body_reject_unscannable_encoding=False)
    assert received == b"" and metrics["proxied"] == 0
    assert metrics["dropped"] == 1 and (not response or response.startswith(b"HTTP/1.1 415"))

    chunked = (b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n")
    framed = b"%x\r\n" % len(query) + query + b"\r\n0\r\n\r\n"
    received, response, metrics = _through([chunked, framed], graphql_enabled=True,
        graphql_paths=["/graphql"], body_scan_enabled=False, body_decode_enabled=False)
    assert received == b"" and metrics["proxied"] == 0
    assert metrics["dropped"] == 1 and (not response or response.startswith(b"HTTP/1.1 415"))

    good = b'{"query":"{ hello }"}'
    plain_head = (b"POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                  b"Content-Length: " + str(len(good)).encode() + b"\r\n\r\n")
    received, response, _ = _through([plain_head, good], graphql_enabled=True,
        graphql_paths=["/graphql"], body_scan_enabled=False, body_decode_enabled=False)
    assert received.endswith(good) and response.startswith(b"HTTP/1.1 200")


def test_shield_off_keeps_body_passthrough_but_structural_framing_stays_on():
    head = (b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Encoding: br\r\n"
            b"Content-Length: 1\r\n\r\n")
    received, response, metrics = _through([head, b"x"], enabled=False)
    assert received.endswith(b"x") and response.startswith(b"HTTP/1.1 200")
    assert metrics["dropped"] == 0

    received, response, metrics = _through([head, b"x"], enabled=True)
    assert received == b"" and metrics["dropped"] == 1
    assert not response or response.startswith(b"HTTP/1.1 415")

    ambiguous = (b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Encoding: identity\r\n"
                 b"Content-Encoding: br\r\nContent-Length: 1\r\n\r\n")
    received, response, metrics = _through([ambiguous, b"x"], enabled=False)
    assert received == b"" and metrics["dropped"] == 1
    assert not response or response.startswith(b"HTTP/1.1 400")

    # Response cookie/CORS flags remain independent of the NetShield switch.
    backend_response = (b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=1\r\n"
                        b"Access-Control-Allow-Origin: *\r\n"
                        b"Access-Control-Allow-Credentials: true\r\n"
                        b"Content-Length: 2\r\n\r\nok")
    _, response, _ = _through([b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"],
                              enabled=False, backend_resp=backend_response)
    assert b"SameSite=Lax" in response
    assert b"Access-Control-Allow-Credentials" not in response
