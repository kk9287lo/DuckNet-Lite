"""Bounded protocol-conformance tables using only harmless local markers.

These are grammar and stream-invariant checks, not a CVE payload corpus. Each
network case uses a single disposable loopback frontend and backend.
"""
import asyncio

from dataplane.engine.services.proxy import (
    AsyncEdgeGuard, _ChunkedEnd, _dlp_head_problem, _framing_ambiguous)
from test_sweep_det_response import _pipe, _shield
from test_sweep_proxy_request import _through


_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}
_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsample"


def _request(fields=(), body=b"", version=b"1.1", method=b"POST", host=True):
    lines = [method + b" /public HTTP/" + version]
    if host:
        lines.append(b"Host: example.test")
    lines.extend(fields)
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _bad_request_rows():
    rows = []
    for raw in (b"", b"-1", b"+1", b"1.0", b"1, 1", b"1 0", b"0x1", b"one"):
        rows.append(("length-" + repr(raw), _request([b"Content-Length: " + raw])))
    for field in (b"Content-Length: 0\r\nContent-Length: 0",
                  b"Host: second.test", b"Content-Type: text/plain\r\nContent-Type: text/plain",
                  b"Transfer-Encoding: chunked\r\nContent-Length: 0",
                  b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
                  b"Content-Encoding: identity\r\nContent-Encoding: identity"):
        rows.append(("duplicate-" + repr(field), _request([field])))
    for field in (b"X-Color : blue", b"X-Color\t: blue", b"X Color: blue",
                  b"X-Color blue", b" X-Color: blue", b"\tX-Color: blue",
                  b"X-Color: blue\x00", b"X-Color: blue\x7f", b"X-Color: blue\x01"):
        rows.append(("field-" + repr(field), _request([field])))
    for host in (b"", b".", b".example.test", b"a..test", b"example.test:",
                 b"example.test:65536", b"example.test:no", b"[]", b"[127.0.0.1]", b"[::1]:no"):
        rows.append(("authority-" + repr(host), _request([b"Host: " + host], host=False)))
    for coding in (b"", b"identity", b"chunked,chunked", b"chunked;flag=sample"):
        rows.append(("transfer-" + repr(coding), _request([b"Transfer-Encoding: " + coding])))
    for first in (b"POST  /public HTTP/1.1", b"POST\t/public HTTP/1.1",
                  b"POST /public HTTP/1.2", b"POST /public HTTP/2.0"):
        rows.append(("request-line-" + repr(first), first + b"\r\nHost: example.test\r\n\r\n"))
    return rows


def test_request_grammar_matrix_rejects_ambiguous_fields_and_lengths():
    rows = _bad_request_rows()
    assert len(rows) == 41
    failures = [name for name, request in rows if not _framing_ambiguous(request)]
    assert failures == [], failures


def test_valid_request_grammar_matrix_keeps_standard_whitespace_and_tokens():
    rows = [_request([b"Content-Length: " + value], b"sample")
            for value in (b"6", b"06", b"000006", b"\t6\t")]
    rows += [_request([b"Transfer-Encoding: " + value], b"6\r\nsample\r\n0\r\n\r\n")
             for value in (b"chunked", b"Chunked", b"\tchunked\t")]
    rows += [_request([b"X-Color: \tblue\t"], method=method)
             for method in (b"GET", b"HEAD", b"OPTIONS", b"POST")]
    rows += [_request([b"X_Valid!Name: value\xe9"], version=b"1.0", host=False)]
    rows += [_request([b"Host: " + host], host=False)
             for host in (b"example.test.", b"example.test:00080", b"[::1]", b"[2001:db8::1]:8080")]
    assert len(rows) == 16
    assert all(not _framing_ambiguous(request) for request in rows)


def test_rejected_grammar_never_reaches_backend_in_enforce_or_audit():
    indices = (0, 8, 14, 24, 34, 38)
    rows = _bad_request_rows()
    results = []
    for mode in ("enforce", "audit"):
        for index in indices:
            name, request = rows[index]
            received, response, metrics = _through(
                [request], backend_resp=_OK, mode=mode, **_QUIET)
            results.append((name, mode, received, response, metrics))
    assert all(not received and metrics["proxied"] == 0
               and (not response or response.startswith(b"HTTP/1.1 400"))
               for _, _, received, response, metrics in results), results


def test_benign_requests_and_chunked_entities_keep_exact_backend_bytes():
    bodies = (b"6\r\nsample\r\n0\r\n\r\n",
              b'6;label="public;sample"\r\nsample\r\n0\r\n\r\n',
              b"1\r\ns\r\n2\r\nam\r\n3\r\nple\r\n0\r\n\r\n")
    rows = [_request([b"Content-Type: text/plain", b"Content-Length: 6"], b"sample"),
            _request([b"Content-Length: 0"], method=b"GET")]
    rows += [_request([b"Transfer-Encoding: chunked"], body) for body in bodies]
    for body in bodies:
        tracker = _ChunkedEnd()
        for byte in body:
            assert tracker.feed(bytes([byte])) == 1
        assert tracker.done and not tracker.bad
        assert AsyncEdgeGuard._dechunk_bounded(body, 32) == b"sample"
    for request in rows:
        for mode in ("enforce", "audit"):
            received, response, metrics = _through(
                [request], backend_resp=_OK, mode=mode, **_QUIET)
            head, separator, payload = request.partition(b"\r\n\r\n")
            expected = (head + b"\r\nX-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1"
                        + separator + payload)
            assert received == expected, (mode, expected, received)
            assert response == _OK and metrics["proxied"] == 1


def _bodyless_length_rows():
    return [(status, field) for status in (100, 102, 103, 199, 204)
            for field in (b"Content-Length: 0", b"Content-Length: 6", b"Transfer-Encoding: chunked")]


def test_response_bodyless_status_cannot_advertise_a_conflicting_body_boundary():
    failures = []
    for status, field in _bodyless_length_rows():
        head = b"HTTP/1.1 " + str(status).encode() + b" Sample\r\n" + field
        if not _dlp_head_problem(head):
            failures.append((status, field))
    assert failures == [], failures


def test_bodyless_response_conflicts_are_withheld_or_audited_before_publication():
    failures = []
    for status, field in _bodyless_length_rows():
        response = b"HTTP/1.1 " + str(status).encode() + b" Sample\r\n" + field + b"\r\n\r\n"
        if status < 200:
            response += _OK
        for step in (1, 17, 65536):
            pieces = [response[i:i+step] for i in range(0, len(response), step)]
            out, shield = _pipe(pieces, dlp_enabled=True, dlp_action="block", **_QUIET)
            if out or shield.metrics().get("dlp_unscannable", 0) != 1:
                failures.append((status, field, step))
        for cfg in ({"dlp_action": "audit"}, {"dlp_action": "block", "mode": "audit"}):
            out, shield = _pipe([response], dlp_enabled=True, **cfg, **_QUIET)
            if out or shield.metrics().get("dlp_unscannable", 0) != 1:
                failures.append((status, field, "audit"))
    assert failures == [], failures


def test_conflicting_bodyless_response_is_withheld_from_real_client():
    request = _request([b"Content-Length: 0"], method=b"GET")
    for status, field in ((100, b"Content-Length: 0"), (103, b"Content-Length: 6"),
                          (204, b"Transfer-Encoding: chunked")):
        response = b"HTTP/1.1 " + str(status).encode() + b" Sample\r\n" + field + b"\r\n\r\n"
        if status < 200:
            response += _OK
        received, out, _ = _through([request], backend_resp=response,
                                    dlp_enabled=True, dlp_action="block", **_QUIET)
        assert received.startswith(b"GET /public HTTP/1.1\r\n") and out == b""
        _, out, _ = _through([request], backend_resp=response,
                              dlp_enabled=True, dlp_action="audit", **_QUIET)
        assert out == b""


def test_valid_interim_and_empty_responses_keep_exact_bytes():
    final = _OK
    rows = [b"HTTP/1.1 " + str(status).encode() + b" Sample\r\nX-Color: blue\r\n\r\n" + final
            for status in (100, 102, 103, 199)]
    rows += [b"HTTP/1.1 204 No Content\r\nX-Color: blue\r\n\r\n",
             b"HTTP/1.1 304 Not Modified\r\nContent-Length: 600\r\n\r\n",
             b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]
    for response in rows:
        for step in (1, 17, 65536):
            out, shield = _pipe([response[i:i+step] for i in range(0, len(response), step)],
                                dlp_enabled=True, dlp_action="block", **_QUIET)
            assert out == response
            assert shield.metrics().get("dlp_unscannable", 0) == 0


class _LimitedReader:
    def __init__(self, data):
        self.data = data
    async def read(self, count):
        part, self.data = self.data[:count], self.data[count:]
        return part


class _BodySink:
    def __init__(self):
        self.data = bytearray()
        self.finished = self.closed = self.aborted = False
        self.transport = self
    def write(self, data): self.data += data
    async def drain(self): pass
    def can_write_eof(self): return True
    def write_eof(self): self.finished = True
    def close(self): self.closed = True
    def abort(self): self.aborted = self.closed = True


def test_request_body_release_matrix_respects_exact_end_and_abort_ownership():
    async def run():
        for size in (0, 1, 6, 17):
            body = b"s" * size
            reader, sink = _LimitedReader(body + b"UNRELATED"), _BodySink()
            count = await AsyncEdgeGuard()._pipe_body_bounded(reader, sink, size, False, None)
            assert count == size and sink.data == body and reader.data == b"UNRELATED"
            assert sink.finished and not sink.aborted
        for body in (b"", b"s", b"sampl"):
            sink = _BodySink()
            count = await AsyncEdgeGuard()._pipe_body_bounded(_LimitedReader(body), sink, 6, False, None)
            assert count == len(body) and sink.data == body
            assert sink.aborted and not sink.finished
        for body in (b"6\r\nsample\r\n0\r\n\r\n", b'6;label="public"\r\nsample\r\n0\r\n\r\n'):
            sink = _BodySink()
            count = await AsyncEdgeGuard()._pipe_body_bounded(
                _LimitedReader(body + b"UNRELATED"), sink, None, True, None)
            assert count == len(body) and sink.data == body
            assert sink.finished and not sink.aborted
    with _shield():
        asyncio.run(run())
