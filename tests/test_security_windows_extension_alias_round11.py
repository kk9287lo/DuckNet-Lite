"""A Win32 file alias must retain the blocked extension at the edge."""

import os
import tempfile
from pathlib import Path
from unittest import SkipTest
from urllib.parse import unquote_to_bytes

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_PRIVATE = b"private-php-fixture"
_PUBLIC = b"public-file-fixture"
_NESTED = b"private-nested-fixture"


class _Win32FileBackend(_Backend):
    """Serve an actual temporary file through Win32's trailing-dot/space aliases."""

    def __init__(self, root):
        self.root = Path(root)
        self.routes = []
        super().__init__()

    def _one(self, conn):
        conn.settimeout(1.0)
        wire = b""
        try:
            while len(wire) < 262144:
                part = conn.recv(65536)
                if not part:
                    break
                wire += part
        except OSError:
            pass
        self.got.append(wire)
        fields = wire.split(b"\r\n", 1)[0].split(b" ")
        target = fields[1] if len(fields) > 1 else b"/"
        route = unquote_to_bytes(target).split(b"?", 1)[0].decode("ascii")
        self.routes.append(route)
        try:
            body = (self.root / route.lstrip("/")).read_bytes()
        except OSError:
            body = b"not-found-fixture"
        response = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + body)
        try:
            conn.sendall(response)
        except OSError:
            pass
        finally:
            conn.close()


def _request(target):
    return b"GET " + target + b" HTTP/1.1\r\nHost: local.test\r\n\r\n"


def _files(root):
    (Path(root) / "shell.php").write_bytes(_PRIVATE)
    (Path(root) / "public.txt").write_bytes(_PUBLIC)
    (Path(root) / "foo").mkdir()
    (Path(root) / "foo" / "bar").write_bytes(_NESTED)


def test_win32_blocked_php_extension_aliases_never_reach_backend():
    if os.name != "nt":
        raise SkipTest("Win32 trailing component aliases require a Windows file backend")
    with tempfile.TemporaryDirectory() as root:
        _files(root)
        backend = _Win32FileBackend(root)
        try:
            with _shield(mode="enforce", blocked_extensions=[".php"],
                         block_page=False), _guard(backend) as guard:
                for target in (b"/shell.php.", b"/shell.php%20"):
                    response = _exchange(guard, [_request(target)])
                    assert backend.got == [] and backend.routes == [], \
                        (target, backend.got, backend.routes)
                    assert _PRIVATE not in response
                response = _exchange(guard, [_request(b"/public.txt.")])
                assert backend.routes == ["/public.txt."] and len(backend.got) == 1
                assert response.startswith(b"HTTP/1.1 200") and response.endswith(_PUBLIC)
        finally:
            backend.close()


def test_win32_blocked_php_alias_audit_forwards_and_records():
    if os.name != "nt":
        raise SkipTest("Win32 trailing component aliases require a Windows file backend")
    with tempfile.TemporaryDirectory() as root:
        _files(root)
        backend = _Win32FileBackend(root)
        try:
            with _shield(mode="audit", blocked_extensions=[".php"],
                         block_page=False) as sh, _guard(backend) as guard:
                response = _exchange(guard, [_request(b"/shell.php.")])
                assert backend.routes == ["/shell.php."] and len(backend.got) == 1
                assert response.startswith(b"HTTP/1.1 200") and response.endswith(_PRIVATE)
                assert any(e.get("kind") == "audit" and e.get("would") == "block"
                           for e in sh.events(40)), sh.events(40)
        finally:
            backend.close()


def test_win32_public_file_alias_remains_usable():
    if os.name != "nt":
        raise SkipTest("Win32 trailing component aliases require a Windows file backend")
    with tempfile.TemporaryDirectory() as root:
        _files(root)
        backend = _Win32FileBackend(root)
        try:
            with _shield(mode="enforce", blocked_extensions=[".php"],
                         blocked_urls=["/foo/bar"], block_page=False), \
                    _guard(backend) as guard:
                response = _exchange(guard, [_request(b"/public.txt.")])
                assert backend.routes == ["/public.txt."] and len(backend.got) == 1
                assert response.startswith(b"HTTP/1.1 200") and response.endswith(_PUBLIC)
        finally:
            backend.close()


def test_win32_directory_alias_cannot_bypass_blocked_url():
    if os.name != "nt":
        raise SkipTest("Win32 trailing component aliases require a Windows file backend")
    with tempfile.TemporaryDirectory() as root:
        _files(root)
        backend = _Win32FileBackend(root)
        try:
            with _shield(mode="enforce", blocked_urls=["/foo/bar"],
                         block_page=False), _guard(backend) as guard:
                for target in (b"/foo./bar", b"/foo/bar"):
                    response = _exchange(guard, [_request(target)])
                    assert backend.got == [] and backend.routes == [], \
                        (target, backend.got, backend.routes)
                    assert _NESTED not in response
                response = _exchange(guard, [_request(b"/public.txt.")])
                assert backend.routes == ["/public.txt."] and len(backend.got) == 1
                assert response.endswith(_PUBLIC)
        finally:
            backend.close()


def test_win32_directory_alias_shares_path_rate_bucket():
    if os.name != "nt":
        raise SkipTest("Win32 trailing component aliases require a Windows file backend")
    with tempfile.TemporaryDirectory() as root:
        _files(root)
        backend = _Win32FileBackend(root)
        try:
            rule = {"path": "/foo/bar", "rate": 0.001, "burst": 1}
            with _shield(mode="enforce", path_limits=[rule], block_page=False), \
                    _guard(backend) as guard:
                first = _exchange(guard, [_request(b"/foo./bar")])
                second = _exchange(guard, [_request(b"/foo./bar")])
                assert first.endswith(_NESTED)
                assert second.startswith(b"HTTP/1.1 429"), second
                assert backend.routes == ["/foo./bar"] and len(backend.got) == 1
        finally:
            backend.close()


def test_graphql_route_recognizes_win32_trailing_dot_view():
    from dataplane.engine.lifeform.pipeline import _graphql_path

    assert _graphql_path("/graphql.", ["/graphql"])
    assert not _graphql_path("/public.", ["/graphql"])
