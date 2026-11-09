"""Frontend/backend HTTP parsing must agree before any request reaches the backend."""

import socket
import threading
import tempfile
import gzip
from contextlib import contextmanager

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import AsyncEdgeGuard, _ChunkedEnd, _framing_ambiguous
from guard_support import stop_guard_owned
from test_sweep_proxy_request import _read_framed_request, _through


def _request(*headers, body=b""):
    return b"POST / HTTP/1.1\r\nHost: example.test\r\n" + b"\r\n".join(headers) + b"\r\n\r\n" + body


@contextmanager
def _isolated_shield():
    old_shield, old_firewall = ND._SHIELD, FW._FW
    with tempfile.TemporaryDirectory() as state_dir:
        shield = ND.NetShield(state_dir=state_dir)
        shield.cfg["enabled"] = True
        ND._SHIELD = shield
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        try:
            yield
        finally:
            ND._SHIELD, FW._FW = old_shield, old_firewall


def test_unsupported_transfer_codings_do_not_bypass_body_scan():
    # The scanner only removes chunk framing. It cannot decode a prior TE coding
    # that an upstream server may decode before parsing the application body.
    for value in (
        b"gzip, chunked",
        b"deflate, chunked",
        b"identity, chunked",
        b",chunked",
        b"chunked,chunked",
        b"chunked;foo=bar",
    ):
        assert _framing_ambiguous(_request(b"Transfer-Encoding: " + value)), value
    assert not _framing_ambiguous(_request(b"Transfer-Encoding: Chunked"))
    assert not _framing_ambiguous(_request(b"Transfer-Encoding:\tchunked \t"))
    assert _framing_ambiguous(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")


def test_duplicate_or_multi_content_encoding_cannot_bypass_body_scan():
    payload = b"user=admin' or 1=1-- -"
    compressed = gzip.compress(payload)
    base = (b"POST /login HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n")
    length = b"Content-Length: " + str(len(compressed)).encode() + b"\r\n\r\n"
    for coding in (b"Content-Encoding: identity\r\nContent-Encoding: gzip\r\n",
                   b"Content-Encoding: gzip\r\nContent-Encoding: identity\r\n",
                   b"Content-Encoding: identity, gzip\r\n",
                   b"Content-Encoding: gzip, identity\r\n",
                   b"Content-Encoding: gzip;ignored\r\n"):
        head = base + coding + length
        received, response, metrics = _through([head, compressed],
            body_reject_unscannable_encoding=False, body_scan_max_bytes=1024,
            block_score=20)
        assert _framing_ambiguous(head) and received == b"", coding
        assert metrics["dropped"] == 1 and metrics["proxied"] == 0
        assert not response or response.startswith(b"HTTP/1.1 400")

    # A single supported coding still reaches the decoder and blocks the payload.
    head = base + b"Content-Encoding: gzip\r\n" + length
    received, _, metrics = _through([head, compressed],
        body_reject_unscannable_encoding=False, body_scan_max_bytes=1024,
        block_score=20)
    assert received == b"" and metrics["dropped"] == 1

    benign = gzip.compress(b"safe=1")
    good_head = (base + b"Content-Encoding: gzip\r\nContent-Length: "
                 + str(len(benign)).encode() + b"\r\n\r\n")
    received, response, metrics = _through([good_head, benign],
        body_reject_unscannable_encoding=False, body_scan_max_bytes=1024,
        block_score=20)
    assert received.endswith(benign) and response.startswith(b"HTTP/1.1 200")
    assert metrics["dropped"] == 0


def test_duplicate_content_type_cannot_select_a_different_multipart_boundary():
    def multipart(name):
        return (b'--b\r\nContent-Disposition: form-data; name="f"; filename="'
                + name + b'"\r\n\r\nx\r\n--b--\r\n')

    bad = multipart(b"evil.xyz")
    base = b"POST /upload HTTP/1.1\r\nHost: x\r\n"
    length = b"Content-Length: " + str(len(bad)).encode() + b"\r\n\r\n"
    for types in (b"Content-Type: multipart/form-data; boundary=a\r\n"
                  b"Content-Type: multipart/form-data; boundary=b\r\n",
                  b"Content-Type: application/octet-stream\r\n"
                  b"Content-Type: multipart/form-data; boundary=b\r\n"):
        head = base + types + length
        received, response, metrics = _through([head, bad], upload_deny_ext=["xyz"],
                                                body_scan_enabled=False)
        assert _framing_ambiguous(head) and received == b"", types
        assert metrics["dropped"] == 1 and metrics["proxied"] == 0
        assert not response or response.startswith(b"HTTP/1.1 400")

    single = b"Content-Type: multipart/form-data; boundary=b\r\n"
    received, _, metrics = _through([base + single + length, bad],
                                     upload_deny_ext=["xyz"], body_scan_enabled=False)
    assert received == b"" and metrics["dropped"] == 1
    good = multipart(b"notes.txt")
    good_head = (base + single + b"Content-Length: " + str(len(good)).encode()
                 + b"\r\n\r\n")
    received, response, metrics = _through([good_head, good],
                                            upload_deny_ext=["xyz"], body_scan_enabled=False)
    assert received.endswith(good) and response.startswith(b"HTTP/1.1 200")
    assert metrics["dropped"] == 0


def test_leading_dot_host_cannot_match_a_site_whitelist_suffix():
    attack = b"GET / HTTP/1.1\r\nHost: .allow.example\r\n\r\n"
    received, response, metrics = _through([attack], site_mode="whitelist",
                                            site_whitelist=["allow.example"])
    assert _framing_ambiguous(attack) and received == b""
    assert response.startswith(b"HTTP/1.1 400") and metrics["proxied"] == 0

    control = b"GET / HTTP/1.1\r\nHost: allow.example.\r\n\r\n"
    received, response, metrics = _through([control], site_mode="whitelist",
                                            site_whitelist=["allow.example"])
    assert not _framing_ambiguous(control)
    assert b"Host: allow.example." in received and response.startswith(b"HTTP/1.1 200")
    assert metrics["proxied"] == 1


def test_malformed_header_syntax_cannot_reach_different_backend_parser():
    for raw in (
        b"Host : example.test",       # the frontend used to strip the name
        b"X-Role : admin",             # any field can affect upstream policy
        b"Transfer-Encoding chunked", # missing colon
        b"X\tRole: admin",
        b"X@Role: admin",
        b"X-Role: admin\x01",
        b"Host: \t",                  # no authority for routing/policy
    ):
        # Replace the canonical Host where testing malformed Host itself.
        req = (b"POST / HTTP/1.1\r\n" + raw + b"\r\n\r\n"
               if raw.startswith(b"Host") else _request(raw))
        assert _framing_ambiguous(req), raw
    assert not _framing_ambiguous(_request(b"X_Valid!Name: \tvalue\xe9"))


def test_rejected_transfer_coding_never_opens_backend_connection():
    with _isolated_shield():
        guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=1,
                               listen_host="127.0.0.1", listen_port=0)
        assert guard.start()["ok"]
        try:
            with socket.create_connection(("127.0.0.1", guard.listen_port), timeout=2) as client:
                client.settimeout(2)
                client.sendall(_request(b"Transfer-Encoding: gzip, chunked", body=b"0\r\n\r\n"))
                response = client.recv(1024)
            assert response.startswith(b"HTTP/1.1 400 Bad Request")
            assert guard.metrics["proxied"] == 0
        finally:
            stop_guard_owned(guard)


def test_chunk_extensions_are_parsed_and_request_trailers_fail_closed():
    for body in (b"3;name=value\r\nabc\r\n0\r\n\r\n",
                 b'3;name="a;b"\r\nabc\r\n0\r\n\r\n'):
        trk = _ChunkedEnd()
        assert trk.feed(body) == len(body)
        assert trk.done and not trk.bad
    for body in (b"1;=value\r\na\r\n0\r\n\r\n",
                 b"1;name=\r\na\r\n0\r\n\r\n",
                 b"1;name=\"unterminated\r\na\r\n0\r\n\r\n",
                 b"1 \r\na\r\n0\r\n\r\n",
                 b"1\r\na\r\n0\r\nHost: internal\r\n\r\n",
                 b"1\r\na\r\n0\r\nGET /secret HTTP/1.1\r\n\r\n"):
        trk = _ChunkedEnd()
        trk.feed(body)
        assert trk.bad and not trk.done, body


def test_chunked_trailer_rejected_before_backend_and_clean_body_forwarded():
    backend = socket.socket()
    backend.bind(("127.0.0.1", 0))
    backend.listen(1)
    backend.settimeout(3)
    got = []

    def serve_once():
        with backend.accept()[0] as conn:
            conn.settimeout(3)
            # A valid last chunk is the request boundary. Waiting for a TCP
            # half-close rejects Nginx-compatible forwarding after staging.
            got.append(_read_framed_request(conn, limit=65536))
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass

    worker = threading.Thread(target=serve_once, daemon=True)
    worker.start()
    with _isolated_shield():
        guard = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.getsockname()[1],
                               listen_host="127.0.0.1", listen_port=0)
        assert guard.start()["ok"]
        try:
            head = b"Transfer-Encoding: chunked"
            with socket.create_connection(("127.0.0.1", guard.listen_port), timeout=2) as client:
                client.settimeout(2)
                client.sendall(_request(head, body=b"1\r\na\r\n0\r\nAuthorization: secret\r\n\r\n"))
                assert client.recv(1024).startswith(b"HTTP/1.1 400 Bad Request")
            assert guard.metrics["proxied"] == 0
            with socket.create_connection(("127.0.0.1", guard.listen_port), timeout=2) as client:
                client.settimeout(3)
                client.sendall(_request(head, body=b"3;name=value\r\nabc\r\n0\r\n\r\n"))
                assert client.recv(1024).startswith(b"HTTP/1.1 200 OK")
            worker.join(3)
            assert len(got) == 1
            assert b"3;name=value\r\nabc\r\n0\r\n\r\n" in got[0]
        finally:
            try:
                stop_guard_owned(guard)
            finally:
                backend.close()
