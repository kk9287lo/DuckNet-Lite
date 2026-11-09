"""An early wait_for wakeup must not bypass the HTML DLP deadline audit."""

import asyncio
import os
import tempfile
from unittest import mock

import dataplane.engine.services.proxy as proxy
from test_security_html_entity_dlp_round8 import _QUIET, _Sink, _response
from test_sweep_proxy_request import _shield


def test_early_timeout_rechecks_html_deadline_before_classifying_failure():
    with tempfile.TemporaryDirectory(prefix="ducknet-r16-dlp-early-",
                                     dir=os.environ["DUCKNET_STATE_DIR"]):
        async def run(shield):
            response = _response(b"<p>public</p>")
            head, _, body = response.partition(b"\r\n\r\n")
            src, dst = asyncio.StreamReader(), _Sink()
            guard = proxy.AsyncEdgeGuard()
            real_wait_for = asyncio.wait_for
            early = [False]

            async def early_once(awaitable, timeout):
                if not early[0] and 0 < timeout < .1:
                    early[0] = True
                    awaitable.close()  # wait_for was not called: no reader task owns it
                    raise asyncio.TimeoutError()
                return await real_wait_for(awaitable, timeout)

            with mock.patch.object(proxy.asyncio, "wait_for", early_once):
                task = asyncio.create_task(guard._pipe(
                    src, dst, scan=True, ip="192.0.2.92"))
                src.feed_data(head + b"\r\n\r\n" + body[:3])
                deadline = asyncio.get_running_loop().time() + 1.0
                while shield.metrics().get("dlp_unscannable") != 1:
                    if asyncio.get_running_loop().time() >= deadline:
                        break
                    await asyncio.sleep(.005)
                src.feed_data(body[3:])
                src.feed_eof()
                await real_wait_for(task, 1)

            assert early[0], "the short HTML read deadline was not exercised"
            assert shield.metrics().get("dlp_unscannable") == 1, shield.metrics()
            assert guard.metrics.get("response_head_timeout", 0) == 0, guard.metrics
            assert any(e.get("encoding") == "html-timeout"
                       for e in shield.events(100)), shield.events(100)
            assert bytes(dst.buf).partition(b"\r\n\r\n")[2] == b"", bytes(dst.buf)
            assert proxy._DLP_HTML_HOLD_USED == 0

        with mock.patch.object(proxy, "_DLP_HTML_RESPONSE_SEC", .025), \
                _shield(dlp_enabled=True, dlp_action="block", **_QUIET) as shield:
            asyncio.run(run(shield))
