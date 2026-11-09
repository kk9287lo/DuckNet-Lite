"""An early origin rejection must not hold a fully staged upload until write timeout."""

import os
import socket
import tempfile
import threading
import time
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
import dataplane.engine.lifeform.policy as policy
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.lifeform.policy import AppFirewall
from test_sweep_proxy_request import _guard


_EARLY_413 = (b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n"
              b"X-Origin-Secret: must-not-escape\r\nConnection: close\r\n\r\n")
_EARLY_401 = (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n"
              b"X-Origin-Secret: must-not-escape\r\nConnection: close\r\n\r\n")
_EARLY_503 = (b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
              b"X-Origin-Secret: must-not-escape\r\nConnection: close\r\n\r\n")
_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class _Origin:
    def __init__(self, action):
        self.action = action
        self.sent = threading.Event()
        self.finished = threading.Event()
        self.body_bytes = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                if self.action in ("stall", "reject", "reject401", "reject503",
                                   "interim-reject", "invalid", "early-success-stall"):
                    # Force backpressure only in the adversarial cases. A tiny
                    # Linux receive window makes even a benign 256 KiB body
                    # take several seconds and tests the fixture, not DuckNet.
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                raw = bytearray()
                while b"\r\n\r\n" not in raw:
                    part = conn.recv(4096)
                    if not part:
                        return
                    raw.extend(part)
                head, _, body = bytes(raw).partition(b"\r\n\r\n")
                size = int(next(line.split(b":", 1)[1].strip()
                                for line in head.split(b"\r\n")
                                if line.lower().startswith(b"content-length:")))
                self.body_bytes = len(body)
                if self.action == "stall":
                    self.sent.set()
                    time.sleep(2)  # watcher stays in readuntil during guard.stop()
                    return
                if self.action in ("early-success", "early-success-stall"):
                    conn.sendall(_OK)
                    self.sent.set()
                    if self.action == "early-success-stall":
                        time.sleep(1.5)  # A final 200 is not proof that upload was read.
                        return
                if self.action == "split-success":
                    conn.sendall(_OK[:16])  # watcher has an incomplete head
                    self.sent.set()
                if self.action in ("reject", "reject401", "reject503",
                                   "interim-reject", "invalid"):
                    if self.action == "interim-reject":
                        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                    if self.action == "invalid":
                        conn.sendall(b"HTTP/1.1 413 Payload Too Large\r\n"
                                     b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n")
                    else:
                        conn.sendall(_EARLY_401 if self.action == "reject401" else
                                     _EARLY_503 if self.action == "reject503" else _EARLY_413)
                    self.sent.set()
                    time.sleep(1.5)  # Do not read the rest of the request.
                    return
                if self.action == "interim-success":
                    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                    self.sent.set()
                while self.body_bytes < size:
                    part = conn.recv(min(65536, size - self.body_bytes))
                    if not part:
                        return
                    self.body_bytes += len(part)
                if self.action == "early-success":
                    pass  # One early 200 only; keep reading until the CL boundary.
                elif self.action == "split-success":
                    conn.sendall(_OK[16:])
                else:
                    conn.sendall(_EARLY_401 if self.action == "complete401" else _OK)
                self.sent.set()
        except OSError:
            pass
        finally:
            self.finished.set()

    def close(self):
        self.listener.close()
        self.thread.join(3)


def _case(action, payload_bytes, *, include_score=False, include_ban=False,
          include_diagnostics=False,
          **extra_config):
    origin = _Origin(action)
    try:
        with tempfile.TemporaryDirectory(prefix="ducknet-r24-early-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            shield = NetShield(state_dir=state)
            firewall = AppFirewall(state_dir=state)
            assert shield.set_config(enabled=True, body_scan_enabled=False,
                                     upload_scan_enabled=False, graphql_enabled=False,
                                     block_page=False, **extra_config)["ok"]
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    _guard(origin, write_timeout=0.5) as guard:
                payload = b"Q" * payload_bytes
                head = (b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n")
                started = time.monotonic()
                with socket.create_connection(("127.0.0.1", guard.listen_port), 4) as client:
                    client.settimeout(4)
                    client.sendall(head + payload)
                    reply = bytearray()
                    while True:
                        try:
                            part = client.recv(65536)
                        except OSError:
                            break
                        if not part:
                            break
                        reply.extend(part)
                client_elapsed = time.monotonic() - started
                if action in ("complete", "complete401", "early-success",
                              "interim-success", "split-success"):
                    assert origin.finished.wait(3), "origin did not finish the benign body"
                end = time.monotonic() + 2
                while guard._body_stage_bytes and time.monotonic() < end:
                    time.sleep(0.01)
                result = (bytes(reply), client_elapsed,
                          origin.sent.is_set(), origin.body_bytes,
                          guard._body_stage_bytes)
                if include_score:
                    return result + (shield.metrics()["resp_code_hits"].get("4xx", 0),
                                     shield._decayed_score(shield._state("127.0.0.1")))
                if include_ban:
                    return result + (shield.is_banned_fast("127.0.0.1"),)
                if include_diagnostics:
                    return result + (guard.metrics.copy(), shield.metrics())
                return result
    finally:
        origin.close()


def test_early_413_releases_staging_and_returns_gateway_owned_error():
    reply, elapsed, sent, body_bytes, reserved = _case("reject", 8 * 1024 * 1024)
    assert sent and body_bytes < 8 * 1024 * 1024
    assert reply.startswith(b"HTTP/1.1 413 Payload Too Large\r\n"), reply[:120]
    assert b"must-not-escape" not in reply
    assert elapsed < 0.5, elapsed  # old runtime waits for backend write timeout
    assert reserved == 0


def test_interim_then_early_413_is_not_mistaken_for_success():
    reply, elapsed, sent, body_bytes, reserved = _case("interim-reject", 8 * 1024 * 1024)
    assert sent and body_bytes < 8 * 1024 * 1024
    assert reply.startswith(b"HTTP/1.1 413 Payload Too Large\r\n"), reply[:120]
    assert b"100 Continue" not in reply
    assert elapsed < 0.5, elapsed
    assert reserved == 0


def test_audit_mode_still_reports_strict_early_rejection_without_origin_bytes():
    reply, _elapsed, sent, body_bytes, reserved = _case(
        "reject", 8 * 1024 * 1024, mode="audit")
    assert sent and body_bytes < 8 * 1024 * 1024
    assert reply.startswith(b"HTTP/1.1 413 Payload Too Large\r\n"), reply[:120]
    assert b"must-not-escape" not in reply
    assert reserved == 0


def test_finite_response_quota_also_applies_to_local_early_error():
    reply, _elapsed, sent, _body_bytes, reserved = _case(
        "reject", 8 * 1024 * 1024,
        quota_enabled=True, quota_max_gb=32 / 1e9)
    assert sent and reply == b"", reply[:120]
    assert reserved == 0


def test_generated_early_error_obeys_dlp_block_and_audit_policies():
    for action in ("block", "audit"):
        reply, _elapsed, sent, _body_bytes, reserved = _case(
            "reject", 8 * 1024 * 1024,
            dlp_enabled=True, dlp_action=action)
        assert sent and reserved == 0
        assert reply.startswith(b"HTTP/1.1 413 Payload Too Large\r\n"), (action, reply[:120])
        assert b"must-not-escape" not in reply


def test_early_5xx_becomes_local_502_without_origin_header():
    reply, _elapsed, sent, _body_bytes, reserved = _case(
        "reject503", 8 * 1024 * 1024)
    assert sent and reserved == 0
    assert reply.startswith(b"HTTP/1.1 502 Bad Gateway\r\n"), reply[:120]
    assert b"must-not-escape" not in reply


def test_early_401_preserves_response_scoring_and_origin_bytes_are_not_relayed():
    cfg = {"resp_error_threshold": 1, "resp_error_score": 50,
           "block_score": 100}
    early = _case("reject401", 8 * 1024 * 1024,
                  include_score=True, **cfg)
    normal = _case("complete401", 256 * 1024,
                   include_score=True, **cfg)
    assert early[0].startswith(b"HTTP/1.1 401 "), early[0][:120]
    assert b"must-not-escape" not in early[0]
    assert normal[0].startswith(b"HTTP/1.1 401 "), normal[0][:120]
    assert early[-2] == normal[-2] == 1, (early, normal)
    # Scores decay continuously; a real network request can consume a few
    # clock ticks between the event and this observation.
    assert early[-1] >= 49 and normal[-1] >= 49, (early, normal)


def test_early_401_can_publish_a_response_scored_ban_without_losing_its_error():
    reply, _elapsed, sent, _body_bytes, reserved, banned = _case(
        "reject401", 8 * 1024 * 1024, include_ban=True,
        resp_error_threshold=1, resp_error_score=50, block_score=40)
    assert sent and reserved == 0 and banned
    assert reply.startswith(b"HTTP/1.1 401 "), reply[:120]
    assert b"must-not-escape" not in reply


def test_malformed_early_response_is_not_relayed():
    reply, _elapsed, sent, body_bytes, reserved, guard_metrics, shield_metrics = _case(
        "invalid", 8 * 1024 * 1024, include_diagnostics=True,
        dlp_enabled=True, dlp_action="audit")
    assert sent and body_bytes < 8 * 1024 * 1024
    assert reply == b"", reply[:120]
    assert reserved == 0
    assert guard_metrics.get("backend_invalid_response") == 1, guard_metrics
    assert shield_metrics.get("dlp_unscannable") == 1, shield_metrics


def test_complete_request_still_gets_origin_success_and_exact_body():
    reply, _elapsed, sent, body_bytes, reserved = _case("complete", 256 * 1024)
    assert sent and body_bytes == 256 * 1024
    assert reply == _OK, reply[:120]
    assert reserved == 0


def test_interim_success_waits_for_complete_replay_and_preserves_final():
    reply, _elapsed, sent, body_bytes, reserved = _case("interim-success", 256 * 1024)
    assert sent and body_bytes == 256 * 1024
    assert reply == b"HTTP/1.1 100 Continue\r\n\r\n" + _OK, reply[:120]
    assert reserved == 0


def test_early_positive_reply_still_waits_for_complete_body_replay():
    reply, _elapsed, sent, body_bytes, reserved = _case(
        "early-success", 256 * 1024)
    assert sent and body_bytes == 256 * 1024
    assert reply == _OK, reply[:120]
    assert reserved == 0


def test_partial_early_head_is_not_lost_when_watcher_is_canceled():
    reply, _elapsed, sent, body_bytes, reserved = _case(
        "split-success", 256 * 1024)
    assert sent and body_bytes == 256 * 1024
    assert reply == _OK, reply[:120]
    assert reserved == 0


def test_early_positive_reply_from_nonreading_origin_fails_closed_and_bounded():
    reply, elapsed, sent, body_bytes, reserved = _case(
        "early-success-stall", 8 * 1024 * 1024)
    assert sent and body_bytes < 8 * 1024 * 1024
    assert reply == b"", reply[:120]  # never claim the upload succeeded
    assert elapsed < 1.5, elapsed  # configured 0.5s write timeout still applies
    assert reserved == 0


def test_stop_cancels_pending_early_response_watch_and_releases_stage():
    origin = _Origin("stall")
    try:
        with tempfile.TemporaryDirectory(prefix="ducknet-r24-stop-",
                                         dir=os.environ["DUCKNET_STATE_DIR"]) as state:
            shield = NetShield(state_dir=state)
            firewall = AppFirewall(state_dir=state)
            assert shield.set_config(enabled=True, body_scan_enabled=False,
                                     upload_scan_enabled=False, graphql_enabled=False,
                                     block_page=False)["ok"]
            with patch.object(pipeline, "_SHIELD", shield), \
                    patch.object(policy, "_FW", firewall), \
                    _guard(origin, write_timeout=5) as guard:
                payload = b"Q" * (8 * 1024 * 1024)
                head = (b"POST /upload HTTP/1.1\r\nHost: app.example\r\n"
                        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n")
                with socket.create_connection(("127.0.0.1", guard.listen_port), 4) as client:
                    client.sendall(head + payload)
                    assert origin.sent.wait(3), "origin did not receive request head"
                    end = time.monotonic() + 2
                    while guard._body_stage_bytes == 0 and time.monotonic() < end:
                        time.sleep(0.01)
                    assert guard._body_stage_bytes == len(payload)
                    stopped = guard.stop(grace=0)
                    assert stopped["stopped"] is True, stopped
                    assert guard._body_stage_bytes == 0
    finally:
        origin.close()
