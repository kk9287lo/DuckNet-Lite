"""HTML character references must not hide a response secret from DLP."""

import asyncio
import contextlib
import html
from html.parser import HTMLParser
from unittest import mock
from xml.etree import ElementTree
from urllib.parse import unquote_to_bytes

import dataplane.engine.services.proxy as proxy
from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield
from test_sweep_det_response import _pipe, _Sink, _stream


_TOKEN = b"ghp_" + b"a" * 36  # inert marker matching the existing DLP rule
_REQUEST = b"GET /view HTTP/1.1\r\nHost: local.test\r\n\r\n"
_QUIET = {"cookie_harden_enabled": False, "cors_harden_enabled": False,
          "open_redirect_enabled": False}


def _response(body, media=b"text/html"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + media
            + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)


def _visible(body):
    return html.unescape(body.decode("ascii")).encode("ascii")


def _dom_text(body):
    class Text(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts = []

        def handle_data(self, data):
            self.parts.append(data)

    parser = Text()
    parser.feed(body.decode("ascii"))
    parser.close()
    return "".join(parser.parts).encode("ascii")


def _chunked_response(parts):
    wire = b"".join(f"{len(part):X}\r\n".encode() + part + b"\r\n" for part in parts)
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            + wire + b"0\r\n\r\n")


def _transit(response, action, *, enabled=True, **cfg):
    backend = _Backend(response)
    try:
        with _shield(dlp_enabled=enabled, dlp_action=action, **_QUIET, **cfg) as shield, \
                _guard(backend) as guard:
            client = _exchange(guard, [_REQUEST])
            metrics, events = shield.metrics(), shield.events(100)
        return backend.saw(), client, metrics, events
    finally:
        backend.close()


def test_html_numeric_reference_secret_is_blocked_on_real_client_wire():
    bodies = (
        b"<p>gh&#112;_" + b"a" * 36 + b"</p>",
        b"<p>gh&#112_" + b"a" * 36 + b"</p>",  # HTML5 numeric reference without ';'
        b"<p>ghp&UnderBar;" + b"a" * 36 + b"</p>",
        b"<p>" + b"".join(f"&#x{byte:x};".encode() for byte in _TOKEN) + b"</p>",
    )
    for body in bodies:
        assert _TOKEN not in body and _TOKEN in _visible(body)
        response = _response(body)
        backend_request, client, metrics, _ = _transit(response, "block")
        assert backend_request.startswith(b"GET /view HTTP/1.1\r\n")
        assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_leak") == 1, (client, metrics)

        backend_request, client, metrics, events = _transit(response, "audit")
        assert backend_request.startswith(b"GET /view HTTP/1.1\r\n")
        assert client == response and metrics.get("dlp_leak") == 1
        assert any(e.get("kind") == "dlp_leak" for e in events)


def test_benign_html_entities_and_plain_token_keep_distinct_decisions():
    benign = _response(b"<p>A &amp; B &#112;ublic</p>")
    _, client, metrics, _ = _transit(benign, "block")
    assert client == benign and not metrics.get("dlp_leak")

    plain = _response(b"<p>" + _TOKEN + b"</p>")
    _, client, metrics, _ = _transit(plain, "block")
    assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_leak") == 1


def test_html_reference_across_chunk_frames_and_packet_cuts_is_still_blocked():
    parts = (b"<p>gh&#", b"112;_" + b"a" * 36 + b"</p>")
    assert _TOKEN in _visible(b"".join(parts))
    response = _chunked_response(parts)
    _, client, metrics, _ = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_leak") == 1
    _, client, metrics, _ = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1
    for step in (1, 5, 17):
        chunks = [response[i:i + step] for i in range(0, len(response), step)]
        out, shield = _pipe(chunks, dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out.partition(b"\r\n\r\n")[2] == b"" and shield.metrics().get("dlp_leak") == 1


def test_long_html_stream_waits_for_completion_before_any_body():
    encoded = b"".join(f"&#{byte:012d};".encode() for byte in _TOKEN)
    body = b"<p>" + b"A" * 1600 + b" " + encoded + b"</p>"
    assert _TOKEN in _visible(body)
    response = _response(body)
    head, _, pay = response.partition(b"\r\n\r\n")
    snapshots = _stream(head + b"\r\n\r\n", [pay[:1500], pay[1500:1700], pay[1700:]],
                        .003, dlp_enabled=True, dlp_action="block", **_QUIET)
    assert snapshots == [b"", b"", b"", b""]
    benign_body = b"<p>" + b"A" * 1600 + b" public</p>"
    benign = _response(benign_body)
    benign_head, _, benign_pay = benign.partition(b"\r\n\r\n")
    snapshots = _stream(benign_head + b"\r\n\r\n",
                        [benign_pay[:1500], benign_pay[1500:]], .003,
                        dlp_enabled=True, dlp_action="block", **_QUIET)
    assert snapshots == [b"", benign_body, benign_body]


def test_overlong_html_reference_fails_closed_and_audit_preserves_wire():
    body = b"<p>gh&#000000000000000000112;_" + b"a" * 36 + b"</p>"
    assert _TOKEN in _visible(body)
    response = _response(body)
    _, client, metrics, _ = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_unscannable") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("kind") == "dlp_unscannable" and e.get("encoding") == "html-entity"
               for e in events)


def test_non_html_entity_text_and_sse_keep_exact_wire():
    body = b"gh&#112;_" + b"a" * 36
    for media in (b"text/plain", b"text/event-stream"):
        response = _response(body, media)
        _, client, metrics, _ = _transit(response, "block")
        assert client == response and not metrics.get("dlp_leak")


def test_long_benign_html_named_reference_is_not_rejected():
    body = b"<p>&CounterClockwiseContourIntegral; public</p>"
    assert "\u2233" in html.unescape(body.decode("ascii"))
    response = _response(body)
    _, client, metrics, _ = _transit(response, "block")
    assert client == response
    assert not metrics.get("dlp_leak") and not metrics.get("dlp_unscannable")
    for step in (1, 7):
        chunks = [response[i:i + step] for i in range(0, len(response), step)]
        out, shield = _pipe(chunks, dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out == response
        assert not shield.metrics().get("dlp_leak")
        assert not shield.metrics().get("dlp_unscannable")


def test_ambiguous_content_type_cannot_hide_html_view():
    body = b"<p>gh&#112;_" + b"a" * 36 + b"</p>"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Type: text/html\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
    for action in ("block", "audit"):
        _, client, metrics, _ = _transit(response, action)
        # Duplicate representation fields are rejected at the mandatory
        # response-head boundary in both modes, before any body reaches users.
        assert client == b"" and metrics.get("dlp_unscannable") == 1


def test_adjacent_html_text_nodes_cannot_hide_secret_from_dlp():
    bodies = (
        b"<span>gh</span><span>p_" + b"a" * 36 + b"</span>",
        b"<span>gh&#112;</span><span>_" + b"a" * 36 + b"</span>",
    )
    for body in bodies:
        assert _TOKEN not in body and _TOKEN in _dom_text(body)
        response = _response(body)
        _, client, metrics, _ = _transit(response, "block")
        assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_leak") == 1
        _, client, metrics, events = _transit(response, "audit")
        assert client == response and metrics.get("dlp_leak") == 1
        assert any(e.get("kind") == "dlp_leak" for e in events)


def test_benign_adjacent_html_text_nodes_keep_exact_wire():
    body = b"<span>pub</span><span>lic</span><em> &amp; safe</em>"
    response = _response(body)
    _, client, metrics, _ = _transit(response, "block")
    assert client == response and not metrics.get("dlp_leak")


def test_chunked_dom_join_secret_is_blocked_at_every_packet_cut():
    parts = (b"<span>gh</span>", b"<span>p_" + b"a" * 36 + b"</span>")
    assert _TOKEN in _dom_text(b"".join(parts))
    response = _chunked_response(parts)
    for step in (1, 3, 19):
        chunks = [response[i:i + step] for i in range(0, len(response), step)]
        out, shield = _pipe(chunks, dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out.partition(b"\r\n\r\n")[2] == b""
        assert shield.metrics().get("dlp_leak") == 1
    _, client, metrics, _ = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1


def test_incomplete_overlong_reference_cannot_outlive_scan_budget():
    body = b"<p>gh&#" + b"0" * 30 + b"112_" + b"a" * 36
    response = _response(body)
    for action in ("block", "audit"):
        _, client, metrics, _ = _transit(response, action)
        if action == "block":
            assert client.partition(b"\r\n\r\n")[2] == b""
        else:
            assert client == response
        assert metrics.get("dlp_unscannable") == 1
    out, shield = _pipe([response[:100], response[100:]],
                        dlp_enabled=True, dlp_action="block",
                        dlp_max_scan_bytes=len(body) - 1, **_QUIET)
    assert out.partition(b"\r\n\r\n")[2] == b""
    assert shield.metrics().get("dlp_unscannable") == 1


def test_dom_attribute_entity_and_many_benign_tags_use_browser_view():
    body = b'<div title="gh&#112;_' + b"a" * 36 + b'">public</div>'
    assert _TOKEN not in body
    response = _response(body)
    _, client, metrics, _ = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_leak") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1
    assert any(e.get("kind") == "dlp_leak" for e in events)
    for step in (1, 7):
        out, sh = _pipe([response[i:i + step] for i in range(0, len(response), step)],
                        dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out.partition(b"\r\n\r\n")[2] == b"" and sh.metrics().get("dlp_leak") == 1

    benign = _response(b"<i>public</i>" * 1200)
    _, client, metrics, _ = _transit(benign, "block")
    assert client == benign and not metrics.get("dlp_unscannable")


def test_html_body_framing_modes_preserve_benign_wire_exactly():
    body = b"<div>public &amp; safe</div>"
    responses = (
        _response(body),
        _chunked_response((body[:8], body[8:])),
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" + body,
    )
    for response in responses:
        _, client, metrics, _ = _transit(response, "block")
        assert client == response and not metrics.get("dlp_leak")
        assert not metrics.get("dlp_unscannable")


def test_html_scan_budget_overflow_blocks_and_audits_exact_wire():
    body = b"<span>public</span>" * 10
    response = _response(body)
    _, client, metrics, events = _transit(response, "block", dlp_max_scan_bytes=64)
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_unscannable") == 1
    assert any(e.get("kind") == "dlp_unscannable" and e.get("encoding") == "scan-budget"
               for e in events)
    _, client, metrics, events = _transit(response, "audit", dlp_max_scan_bytes=64)
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("kind") == "dlp_unscannable" and e.get("encoding") == "scan-budget"
               for e in events)


def test_overlong_tag_is_bounded_with_precise_audit_reason():
    body = b'<div title="' + b"A" * (proxy._DLP_HTML_PARSE_TAIL_MAX + 1) + b'">public</div>'
    response = _response(body)
    for action in ("block", "audit"):
        _, client, metrics, events = _transit(response, action)
        if action == "block":
            assert client.partition(b"\r\n\r\n")[2] == b""
        else:
            assert client == response
        assert metrics.get("dlp_unscannable") == 1
        assert any(e.get("kind") == "dlp_unscannable" and e.get("encoding") == "html-parse"
                   for e in events)


def test_global_html_hold_budget_blocks_second_client_and_releases_on_eof():
    first_body = b"<p>" + b"A" * 44 + b"</p>"
    second_body = b"<p>" + b"B" * 33 + b"</p>"
    first = _response(first_body)
    second = _response(second_body)
    head, _, pay = first.partition(b"\r\n\r\n")

    async def go(sh):
        guard = proxy.AsyncEdgeGuard()
        src1, dst1 = asyncio.StreamReader(), _Sink()
        task1 = asyncio.create_task(guard._pipe(src1, dst1, scan=True, ip="192.0.2.90"))
        src1.feed_data(head + b"\r\n\r\n" + pay[:35])
        await asyncio.sleep(.01)
        assert proxy._DLP_HTML_HOLD_USED == 35
        src2, dst2 = asyncio.StreamReader(), _Sink()
        src2.feed_data(second)
        src2.feed_eof()
        await guard._pipe(src2, dst2, scan=True, ip="192.0.2.91")
        assert bytes(dst2.buf).partition(b"\r\n\r\n")[2] == b""
        assert proxy._DLP_HTML_HOLD_USED == 35
        src1.feed_data(pay[35:])
        src1.feed_eof()
        await task1
        assert bytes(dst1.buf) == first

    with mock.patch.object(proxy, "_DLP_HTML_HOLD_MAX", 64), \
            _shield(dlp_enabled=True, dlp_action="block", **_QUIET) as sh:
        assert proxy._DLP_HTML_HOLD_USED == 0
        asyncio.run(go(sh))
        assert sh.metrics().get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-memory" for e in sh.events(100))
        assert proxy._DLP_HTML_HOLD_USED == 0


def test_html_reservation_stays_held_through_slow_client_drain():
    first_body = b"<p>" + b"A" * 44 + b"</p>"
    second_body = b"<p>" + b"B" * 33 + b"</p>"
    first, second = _response(first_body), _response(second_body)

    async def go():
        started, release = asyncio.Event(), asyncio.Event()

        class SlowSink(_Sink):
            async def drain(self):
                if self.buf.partition(b"\r\n\r\n")[2]:
                    started.set()
                    await release.wait()

        guard = proxy.AsyncEdgeGuard()
        src1, dst1 = asyncio.StreamReader(), SlowSink()
        src1.feed_data(first)
        src1.feed_eof()
        task = asyncio.create_task(guard._pipe(src1, dst1, scan=True, ip="192.0.2.96"))
        await asyncio.wait_for(started.wait(), 1)
        assert proxy._DLP_HTML_HOLD_USED == len(first_body)
        src2, dst2 = asyncio.StreamReader(), _Sink()
        src2.feed_data(second)
        src2.feed_eof()
        await guard._pipe(src2, dst2, scan=True, ip="192.0.2.97")
        assert bytes(dst2.buf).partition(b"\r\n\r\n")[2] == b""
        assert proxy._DLP_HTML_HOLD_USED == len(first_body)
        release.set()
        await task
        assert bytes(dst1.buf) == first

    with mock.patch.object(proxy, "_DLP_HTML_HOLD_MAX", 64), \
            _shield(dlp_enabled=True, dlp_action="block", **_QUIET) as sh:
        asyncio.run(go())
        assert sh.metrics().get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-memory" for e in sh.events(100))
        assert proxy._DLP_HTML_HOLD_USED == 0


def test_html_deadline_blocks_stalled_backend_and_audits_later_bytes():
    body = b"<p>public</p>"
    response = _response(body)
    head, _, pay = response.partition(b"\r\n\r\n")

    async def go(action, sh):
        src, dst = asyncio.StreamReader(), _Sink()
        task = asyncio.create_task(proxy.AsyncEdgeGuard()._pipe(
            src, dst, scan=True, ip="192.0.2.92"))
        src.feed_data(head + b"\r\n\r\n" + pay[:3])
        # The DLP deadline is 25 ms, but a busy Windows test host can resume
        # this task later than an unconditional 50 ms sleep. Wait for the
        # actual timeout/audit state with a separate bounded test deadline.
        deadline = asyncio.get_running_loop().time() + 1.0
        while (sh.metrics().get("dlp_unscannable") != 1
               or not any(e.get("encoding") == "html-timeout" for e in sh.events(100))
               or proxy._DLP_HTML_HOLD_USED != 0):
            if asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(.005)
        assert sh.metrics().get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-timeout" for e in sh.events(100))
        assert proxy._DLP_HTML_HOLD_USED == 0
        src.feed_data(pay[3:])
        src.feed_eof()
        await asyncio.wait_for(task, 1)
        return bytes(dst.buf)

    with mock.patch.object(proxy, "_DLP_HTML_RESPONSE_SEC", .025):
        for action in ("block", "audit"):
            with _shield(dlp_enabled=True, dlp_action=action, **_QUIET) as sh:
                client = asyncio.run(go(action, sh))
                if action == "block":
                    assert client.partition(b"\r\n\r\n")[2] == b""
                else:
                    assert client == response
                assert proxy._DLP_HTML_HOLD_USED == 0


def test_html_hold_releases_on_cancel_and_truncated_length():
    body = b"<p>public</p>"
    response = _response(body)
    head, _, pay = response.partition(b"\r\n\r\n")

    async def cancel():
        src, dst = asyncio.StreamReader(), _Sink()
        task = asyncio.create_task(proxy.AsyncEdgeGuard()._pipe(
            src, dst, scan=True, ip="192.0.2.93"))
        src.feed_data(head + b"\r\n\r\n" + pay[:3])
        await asyncio.sleep(.01)
        assert proxy._DLP_HTML_HOLD_USED == 3
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert proxy._DLP_HTML_HOLD_USED == 0

    with _shield(dlp_enabled=True, dlp_action="block", **_QUIET):
        asyncio.run(cancel())
    truncated = head + b"\r\n\r\n" + pay[:3]
    with _shield(dlp_enabled=True, dlp_action="block", **_QUIET) as sh:
        async def run():
            src, dst = asyncio.StreamReader(), _Sink()
            src.feed_data(truncated)
            src.feed_eof()
            await proxy.AsyncEdgeGuard()._pipe(src, dst, scan=True, ip="192.0.2.94")
            return bytes(dst.buf)

        assert asyncio.run(run()).partition(b"\r\n\r\n")[2] == b""
        assert sh.metrics().get("dlp_unscannable") == 1
        assert proxy._DLP_HTML_HOLD_USED == 0


def test_mid_response_mode_change_keeps_exact_wire_and_releases_hold():
    body = b"<span>gh</span><span>p_" + b"a" * 36 + b"</span>"
    response = _response(body)
    head, _, pay = response.partition(b"\r\n\r\n")

    async def go(sh):
        src, dst = asyncio.StreamReader(), _Sink()
        task = asyncio.create_task(proxy.AsyncEdgeGuard()._pipe(
            src, dst, scan=True, ip="192.0.2.95"))
        src.feed_data(head + b"\r\n\r\n" + pay[:15])
        await asyncio.sleep(.01)
        assert proxy._DLP_HTML_HOLD_USED == 15
        sh.cfg["mode"] = "audit"
        src.feed_data(pay[15:])
        src.feed_eof()
        await task
        assert proxy._DLP_HTML_HOLD_USED == 0
        return bytes(dst.buf)

    with _shield(dlp_enabled=True, dlp_action="block", **_QUIET) as sh:
        assert asyncio.run(go(sh)) == response
        assert sh.metrics().get("dlp_leak") == 1


def test_xhtml_cdata_text_nodes_cannot_hide_xml_dom_secret():
    body = b"<root><![CDATA[gh]]><![CDATA[p_" + b"a" * 36 + b"]]></root>"
    assert _TOKEN not in body
    assert _TOKEN in b"".join(x.encode() for x in ElementTree.fromstring(body).itertext())
    response = _response(body, b"application/xhtml+xml")
    _, client, metrics, _ = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_leak") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1
    assert any(e.get("kind") == "dlp_leak" for e in events)


def test_benign_xhtml_stays_byte_exact():
    body = b"<root><span>public</span><span> &amp; safe</span></root>"
    response = _response(body, b"application/xhtml+xml")
    _, client, metrics, _ = _transit(response, "block")
    assert client == response and not metrics.get("dlp_leak")
    assert not metrics.get("dlp_unscannable")


def test_xhtml_custom_dtd_entities_fail_closed_before_expansion():
    body = (b'<!DOCTYPE root [<!ENTITY x "gh"><!ENTITY y "p_' + b"a" * 36
            + b'">]><root>&x;&y;</root>')
    assert _TOKEN not in body
    assert _TOKEN in b"".join(x.encode() for x in ElementTree.fromstring(body).itertext())
    response = _response(body, b"application/xhtml+xml")
    _, client, metrics, events = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)


def test_xhtml_parser_rejects_transform_and_malformed_xml():
    bodies = (
        b'<?xml-stylesheet type="text/xsl" href="/transform.xsl"?><root>public</root>',
        b"<root><span>public</root>",
    )
    for body in bodies:
        response = _response(body, b"application/xhtml+xml")
        _, client, metrics, events = _transit(response, "block")
        assert client.partition(b"\r\n\r\n")[2] == b""
        assert metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-parse" for e in events)
        _, client, metrics, events = _transit(response, "audit")
        assert client == response and metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-parse" for e in events)


def test_xhtml_cdata_split_across_chunk_frames_and_single_byte_reads():
    parts = (b"<root><![CDATA[gh]]>", b"<![CDATA[p_" + b"a" * 36 + b"]]></root>")
    body = b"".join(parts)
    assert _TOKEN in b"".join(x.encode() for x in ElementTree.fromstring(body).itertext())
    response = _chunked_response(parts).replace(b"text/html", b"application/xhtml+xml", 1)
    for step in (1, 7, 64):
        out, sh = _pipe([response[i:i + step] for i in range(0, len(response), step)],
                        dlp_enabled=True, dlp_action="block", **_QUIET)
        assert out.partition(b"\r\n\r\n")[2] == b""
        assert sh.metrics().get("dlp_leak") == 1
    _, client, metrics, _ = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1


def test_xml_family_numeric_reference_secret_uses_xml_dom_view_on_real_wire():
    for media in (b"application/xml", b"text/xml", b"image/svg+xml",
                  b"application/atom+xml"):
        if media == b"image/svg+xml":
            body = (b'<svg xmlns="http://www.w3.org/2000/svg"><text>gh&#112;_'
                    + b"a" * 36 + b"</text></svg>")
        else:
            body = b"<root><item>gh&#112;_" + b"a" * 36 + b"</item></root>"
        assert _TOKEN not in body
        assert _TOKEN in b"".join(x.encode() for x in ElementTree.fromstring(body).itertext())
        response = _response(body, media)
        backend_request, client, metrics, _ = _transit(response, "block")
        assert backend_request.startswith(b"GET /view HTTP/1.1\r\n")
        assert client.partition(b"\r\n\r\n")[2] == b"" and metrics.get("dlp_leak") == 1
        _, client, metrics, events = _transit(response, "audit")
        assert client == response and metrics.get("dlp_leak") == 1
        assert any(e.get("kind") == "dlp_leak" for e in events)


def test_benign_xml_and_svg_media_stay_byte_exact():
    for media, body in (
        (b"application/xml", b"<root><item>public &amp; safe</item></root>"),
        (b"text/xml", b"<root>public</root>"),
        (b"image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"><text>safe</text></svg>'),
        (b"application/atom+xml", b"<feed><title>public</title></feed>"),
    ):
        response = _response(body, media)
        _, client, metrics, _ = _transit(response, "block")
        assert client == response and not metrics.get("dlp_leak")
        assert not metrics.get("dlp_unscannable")


def test_iframe_srcdoc_nested_html_is_unscannable_before_release():
    body = (b'<iframe srcdoc="&lt;span&gt;gh&lt;/span&gt;&lt;span&gt;p_'
            + b"a" * 36 + b'&lt;/span&gt;"></iframe>')
    assert _TOKEN not in body

    class InnerText(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts = []

        def handle_data(self, data):
            self.parts.append(data)

    class Outer(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.srcdoc = ""

        def handle_starttag(self, tag, attrs):
            if tag == "iframe":
                self.srcdoc = dict(attrs)["srcdoc"]

    outer = Outer()
    outer.feed(body.decode("ascii"))
    inner = InnerText()
    inner.feed(outer.srcdoc)
    inner.close()
    assert _TOKEN in "".join(inner.parts).encode("ascii")

    response = _response(body)
    _, client, metrics, events = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)


def test_benign_srcdoc_availability_is_explicit():
    response = _response(b'<iframe srcdoc="&lt;p&gt;public&lt;/p&gt;"></iframe>')
    _, client, metrics, events = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)
    _, client, metrics, _ = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    _, client, metrics, _ = _transit(response, "block", enabled=False)
    assert client == response and not metrics.get("dlp_unscannable")


def test_nested_data_url_markup_is_unscannable_before_release():
    inner = b"<span>gh</span><span>p_" + b"a" * 36 + b"</span>"
    encoded = b"".join((b"%%%02X" % byte if byte in b"<>/" else bytes((byte,)))
                       for byte in inner)
    body = b'<object data="data:text/html,' + encoded + b'"></object>'
    assert _TOKEN not in body
    nested = _dom_text(unquote_to_bytes(encoded))
    assert _TOKEN in nested
    response = _response(body)
    _, client, metrics, events = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)


def test_inline_script_and_style_escapes_are_unscannable():
    bodies = (
        b'<script>const key="gh\\x70_' + b"a" * 36 + b'";</script>',
        b'<style>body::before{content:"gh\\70_' + b"a" * 36 + b'"}</style>',
        b'<p style="--key: gh\\70_' + b"a" * 36 + b'">public</p>',
    )
    for body in bodies:
        assert _TOKEN not in body
        response = _response(body)
        _, client, metrics, events = _transit(response, "block")
        assert client.partition(b"\r\n\r\n")[2] == b""
        assert metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-parse" for e in events)
        _, client, metrics, _ = _transit(response, "audit")
        assert client == response and metrics.get("dlp_unscannable") == 1


def test_uri_scheme_whitespace_and_benign_active_markup_availability():
    bodies = (
        b'<iframe src=" \tDaTa:text/html,public"></iframe>',
        b'<a href=" JaVa\nScRiPt:alert(1)">public</a>',
        b'<script>const ok = true;</script>',
        b'<style>body { color: blue; }</style>',
        b'<p style="color: blue">public</p>',
        b'<object data="data:text/plain,public"></object>',
    )
    for body in bodies:
        response = _response(body)
        _, client, metrics, events = _transit(response, "block")
        assert client.partition(b"\r\n\r\n")[2] == b""
        assert metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-parse" for e in events)
        _, client, metrics, _ = _transit(response, "audit")
        assert client == response and metrics.get("dlp_unscannable") == 1
        _, client, metrics, _ = _transit(response, "block", enabled=False)
        assert client == response and not metrics.get("dlp_unscannable")


def test_xhtml_and_svg_active_markup_share_fail_closed_boundary():
    cases = (
        (b"application/xhtml+xml",
         b'<html xmlns="http://www.w3.org/1999/xhtml"><script>const x="gh\\x70_'
         + b"a" * 36 + b'";</script></html>'),
        (b"image/svg+xml",
         b'<svg xmlns="http://www.w3.org/2000/svg"><style>text{fill:blue}</style></svg>'),
        (b"image/svg+xml",
         b'<svg xmlns="http://www.w3.org/2000/svg"><a href="data:text/html,public">x</a></svg>'),
    )
    for media, body in cases:
        response = _response(body, media)
        _, client, metrics, events = _transit(response, "block")
        assert client.partition(b"\r\n\r\n")[2] == b""
        assert metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-parse" for e in events)
        _, client, metrics, _ = _transit(response, "audit")
        assert client == response and metrics.get("dlp_unscannable") == 1


def test_inline_event_handler_escape_is_unscannable():
    body = (b'<button onclick="window.t=\'gh\\x70_' + b"a" * 36
            + b'\';">click</button>')
    assert _TOKEN not in body and _TOKEN in body.replace(b"\\x70", b"p")
    response = _response(body)
    _, client, metrics, events = _transit(response, "block")
    assert client.partition(b"\r\n\r\n")[2] == b""
    assert metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(e.get("encoding") == "html-parse" for e in events)


def test_benign_event_handler_availability_and_plain_html_control():
    ordinary = _response(b"<button>public</button>")
    _, client, metrics, _ = _transit(ordinary, "block")
    assert client == ordinary and not metrics.get("dlp_unscannable")
    for media, body in (
        (b"text/html", b'<button onclick="return false">public</button>'),
        (b"application/xhtml+xml",
         b'<button xmlns="http://www.w3.org/1999/xhtml" onclick="return false">public</button>'),
        (b"image/svg+xml",
         b'<svg xmlns="http://www.w3.org/2000/svg"><text onload="return false">public</text></svg>'),
    ):
        response = _response(body, media)
        _, client, metrics, events = _transit(response, "block")
        assert client.partition(b"\r\n\r\n")[2] == b""
        assert metrics.get("dlp_unscannable") == 1
        assert any(e.get("encoding") == "html-parse" for e in events)
        _, client, metrics, _ = _transit(response, "audit")
        assert client == response and metrics.get("dlp_unscannable") == 1
        _, client, metrics, _ = _transit(response, "block", enabled=False)
        assert client == response and not metrics.get("dlp_unscannable")


def test_bodyless_markup_metadata_keeps_exact_wire_only_after_strict_framing():
    for media in (b"text/html", b"application/xml", b"application/xhtml+xml",
                  b"image/svg+xml"):
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: " + media
                    + b"; charset=utf-16le\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        for action in ("block", "audit"):
            backend, client, metrics, _ = _transit(response, action)
            assert backend.startswith(b"GET /view HTTP/1.1\r\n")
            assert client == response and not metrics.get("dlp_unscannable")
            assert not metrics.get("dlp_leak")

    malformed = (b"HTTP/1.1 200 OK\r\nContent-Type: application/xml; charset=utf-16le\r\n"
                 b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n")
    _, client, metrics, _ = _transit(malformed, "block")
    assert client == b"" and metrics.get("dlp_unscannable") == 1

    nonempty = _response(b"<root>public</root>", b"application/xml; charset=utf-16le")
    _, client, metrics, _ = _transit(nonempty, "block")
    assert client == b"" and metrics.get("dlp_unscannable") == 1
