"""Decoded URL delimiters cannot hide a backend route from edge policies."""

import socket
from urllib.parse import unquote_to_bytes

from test_sweep_proxy_request import _Backend, _exchange, _guard, _shield


_INTERNAL = b"internal-route-fixture"
_PUBLIC = b"public-route-fixture"


class _DecodeFirstBackend(_Backend):
    """A backend that decodes its request target before separating URL fields."""

    def __init__(self, rounds=1):
        self.rounds, self.routes = rounds, []
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
        line = wire.split(b"\r\n", 1)[0].split(b" ")
        target = line[1] if len(line) > 1 else b"/"
        for _ in range(self.rounds):
            target = unquote_to_bytes(target)
        route = target.split(b"?", 1)[0].split(b"#", 1)[0]
        self.routes.append(route)
        body = (_INTERNAL if route in (b"/admin", b"/.env", b"/shell.php", b"/graphql")
                else _PUBLIC)
        response = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n" + body)
        try:
            conn.sendall(response)
        except OSError:
            pass
        finally:
            conn.close()


def _transit(path, *, cfg=None, mode="enforce", rounds=1, body=b""):
    backend = _DecodeFirstBackend(rounds)
    try:
        with _shield() as shield, _guard(backend) as guard:
            settings = dict(mode=mode, block_page=False)
            settings.update(cfg or {})
            assert shield.set_config(**settings).get("ok") is True
            method = b"POST" if body else b"GET"
            request = method + b" " + path + b" HTTP/1.1\r\nHost: local.test\r\n"
            if body:
                request += (b"Content-Type: application/json\r\nContent-Length: "
                            + str(len(body)).encode() + b"\r\n")
            request += b"\r\n" + body
            client = _exchange(guard, [request])
            return request, backend.saw(), client, tuple(backend.routes), shield.events(100)
    finally:
        backend.close()


def test_private_path_rejects_decode_first_question_fragment_and_double_encoding():
    cfg = {"private_paths": ["/admin"], "private_path_allow": []}
    for path, rounds in ((b"/admin%3Fview", 1), (b"/admin%23view", 1),
                         (b"/admin%253Fview", 2)):
        request, upstream, client, routes, _ = _transit(path, cfg=cfg, rounds=rounds)
        assert request.startswith(b"GET " + path + b" HTTP/1.1\r\n")
        assert upstream == b"" and client == b"" and routes == (), \
            (path, upstream, client, routes)


def test_private_path_audit_preserves_backend_and_client_wire():
    cfg = {"private_paths": ["/admin"], "private_path_allow": []}
    request, upstream, client, routes, events = _transit(
        b"/admin%3Fview", cfg=cfg, mode="audit")
    assert upstream.startswith(request[:-2]) and routes == (b"/admin",)
    assert client.endswith(_INTERNAL)
    assert any(event.get("kind") == "audit" for event in events)

def test_plain_private_and_encoded_public_controls_remain_distinct():
    cfg = {"private_paths": ["/admin"], "private_path_allow": []}
    _, upstream, client, routes, _ = _transit(b"/admin", cfg=cfg)
    assert upstream == b"" and client == b"" and routes == ()
    request, upstream, client, routes, _ = _transit(b"/public%3Fview", cfg=cfg)
    assert upstream.startswith(request[:-2]) and routes == (b"/public",)
    assert client.endswith(_PUBLIC)


def test_exposed_artifact_uses_decode_first_path():
    path = b"/.env%3Fview"
    _, upstream, client, routes, _ = _transit(path)
    assert upstream == b"" and client == b"" and routes == (), \
        (path, upstream, client, routes)


def test_blocked_extension_uses_decode_first_path():
    path = b"/shell.php%3Fview"
    _, upstream, client, routes, _ = _transit(path, cfg={"blocked_extensions": [".php"]})
    assert upstream == b"" and client == b"" and routes == (), \
        (path, upstream, client, routes)


def test_graphql_guard_sees_decode_first_route_but_not_unrelated_json():
    cfg = {"graphql_enabled": True, "body_scan_enabled": False}
    body = b'{"query":"{ __schema { types { name } } }"}'
    _, upstream, client, routes, _ = _transit(b"/graphql%3Fview", cfg=cfg, body=body)
    assert upstream == b"" and routes == (), (upstream, client, routes)


def test_graphql_unrelated_json_control_is_forwarded():
    cfg = {"graphql_enabled": True, "body_scan_enabled": False}
    body = b'{"query":"{ __schema { types { name } } }"}'
    _, upstream, client, routes, _ = _transit(b"/api/data%3Fview", cfg=cfg, body=body)
    assert upstream and routes == (b"/api/data",) and client.endswith(_PUBLIC)
