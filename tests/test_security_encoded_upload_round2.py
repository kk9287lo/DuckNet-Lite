"""Enforced upload scanning must not pass an oversized encoded multipart body."""

import gzip
import socket
import threading

import dataplane.engine.lifeform.policy as FW
from test_sweep_r2_ipsource import _exchange, _guard, _shield


_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class _BodyBackend:
    def __init__(self):
        self.got = []
        self._stop = threading.Event()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        part = conn.recv(65536)
                        if not part:
                            break
                        data += part
                    if b"\r\n\r\n" not in data:
                        continue
                    head, _, body = data.partition(b"\r\n\r\n")
                    length = int(next(line.split(b":", 1)[1].strip()
                                      for line in head.split(b"\r\n")[1:]
                                      if line.lower().startswith(b"content-length:")))
                    while len(body) < length:
                        part = conn.recv(length - len(body))
                        if not part:
                            break
                        body += part
                    self.got.append(head + b"\r\n\r\n" + body[:length])
                    conn.sendall(_OK)
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self._thread.join(2)
        self._sock.close()


def _multipart(filename: str, *, padded=False):
    first = (b"--b\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n"
             + (b"A" * 1300 if padded else b"hello"))
    second = (b"\r\n--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
              + filename.encode("ascii")
              + b"\"\r\nContent-Type: application/octet-stream\r\n\r\nSAFE\r\n--b--\r\n")
    return first + second


def _request(path: bytes, compressed: bytes):
    return (b"POST " + path + b" HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: multipart/form-data; boundary=b\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: "
            + str(len(compressed)).encode("ascii") + b"\r\n\r\n" + compressed)


def test_encoded_multipart_over_scan_cap_is_not_forwarded_in_enforce_mode():
    backend = _BodyBackend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=True,
                     body_decode_enabled=True, body_scan_max_bytes=1024,
                     mode="enforce") as sh, _guard(backend) as guard:
            assert FW._FW.add_rule("127.0.0.1/32", "allow")["ok"]
            large = gzip.compress(_multipart("shell.php", padded=True))
            assert len(large) < 1024
            assert b'filename="shell.php"' in gzip.decompress(large)
            small = gzip.compress(_multipart("avatar.png"))
            good_response = _exchange(guard, _request(b"/upload-good", small))
            response = _exchange(guard, _request(b"/upload-mal", large))
            small_bad = gzip.compress(_multipart("shell.php"))
            _exchange(guard, _request(b"/upload-small-mal", small_bad))
            assert b"200 OK" in good_response, good_response
            assert b"415 Unsupported Media Type" in response, response
            assert sh.cfg["upload_scan_enabled"] is True
        received = b"".join(backend.got)
        assert b"/upload-mal" not in received, (response, received)
        assert b"/upload-small-mal" not in received, received
        assert b"/upload-good" in received, received
        good_wire_body = next(data.partition(b"\r\n\r\n")[2]
                              for data in backend.got if b"/upload-good" in data)
        assert good_wire_body == small
        assert gzip.decompress(good_wire_body) == _multipart("avatar.png")
    finally:
        backend.close()


def test_encoded_multipart_over_cap_is_logged_and_forwarded_in_audit_mode():
    backend = _BodyBackend()
    try:
        with _shield(body_scan_enabled=False, upload_scan_enabled=True,
                     body_decode_enabled=True, body_scan_max_bytes=1024,
                     mode="audit") as sh, _guard(backend) as guard:
            assert FW._FW.add_rule("127.0.0.1/32", "allow")["ok"]
            body = gzip.compress(_multipart("shell.php", padded=True))
            response = _exchange(guard, _request(b"/upload-audit", body))
            events = sh.events(20)
        assert b"200 OK" in response, response
        assert any(e.get("kind") == "audit" and e.get("rule") == "upload_unscannable"
                   for e in events), events
        delivered = next(data.partition(b"\r\n\r\n")[2]
                         for data in backend.got if b"/upload-audit" in data)
        assert delivered == body
        assert b'filename="shell.php"' in gzip.decompress(delivered)
    finally:
        backend.close()
