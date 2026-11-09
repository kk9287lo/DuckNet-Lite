"""Repeated URL decoding must not make the backend route narrower than the edge view."""

from test_security_encoded_delimiter_path_round11 import (
    _INTERNAL, _PUBLIC, _transit,
)


def test_private_path_rejects_three_decode_delimiter_route():
    cfg = {"private_paths": ["/admin"], "private_path_allow": []}
    _, upstream, client, routes, _ = _transit(
        b"/admin%25253Fview", cfg=cfg, rounds=3)
    assert upstream == b"" and client == b"" and routes == (), \
        (upstream, client, routes)


def test_exposed_env_rejects_three_and_four_decode_route():
    for path, rounds in ((b"/%25252eenv", 3),
                         (b"/%2525252eenv", 4)):
        _, upstream, client, routes, _ = _transit(path, rounds=rounds)
        assert upstream == b"" and client == b"" and routes == (), \
            (path, upstream, client, routes)


def test_blocked_extension_rejects_three_decode_route():
    _, upstream, client, routes, _ = _transit(
        b"/shell%25252ephp", cfg={"blocked_extensions": [".php"]}, rounds=3)
    assert upstream == b"" and client == b"" and routes == (), \
        (upstream, client, routes)


def test_public_route_remains_usable_after_three_decodes():
    request, upstream, client, routes, _ = _transit(
        b"/public%25253Fview", cfg={"private_paths": ["/admin"],
                                      "private_path_allow": []}, rounds=3)
    assert upstream.startswith(request[:-2]) and routes == (b"/public",)
    assert client.endswith(_PUBLIC) and _INTERNAL not in client


def test_intermediate_decoding_route_remains_inspected():
    # A two-layer origin still sees the literal "%3F" path component. A
    # later decoding layer would turn it into a query delimiter and hide the
    # protected suffix. Both interpretations must remain in the edge view.
    _, upstream, client, routes, _ = _transit(
        b"/foo%25253F/bar/admin", cfg={"blocked_urls": ["/bar/admin"]}, rounds=2)
    assert upstream == b"" and client == b"" and routes == (), \
        (upstream, client, routes)

    request, upstream, client, routes, _ = _transit(
        b"/foo%25253F/bar/public", cfg={"blocked_urls": ["/bar/admin"]}, rounds=2)
    assert upstream.startswith(request[:-2]) and routes == (b"/foo%3F/bar/public",)
    assert client.endswith(_PUBLIC)


def test_path_still_decodable_after_five_layers_fails_closed():
    # An origin with a sixth decoding layer would route these to protected
    # resources. Once the edge's bounded reading budget is exhausted, it
    # cannot prove the forwarded target stays on the inspected path.
    cases = (
        (b"/%25252525252eenv", {}),
        (b"/admin%25252525253Fview",
         {"private_paths": ["/admin"], "private_path_allow": []}),
    )
    for path, cfg in cases:
        _, upstream, client, routes, _ = _transit(path, cfg=cfg, rounds=6)
        assert upstream == b"" and routes == () and _INTERNAL not in client, \
            (path, upstream, client, routes)


def test_public_path_that_finishes_decoding_at_five_layers_passes():
    request, upstream, client, routes, _ = _transit(
        b"/public%252525253Fview", cfg={"private_paths": ["/admin"],
                                        "private_path_allow": []}, rounds=5)
    assert upstream.startswith(request[:-2]) and routes == (b"/public",)
    assert client.endswith(_PUBLIC)


def test_six_decode_budget_audit_forwards_exact_wire_and_records():
    path = b"/%25252525252eenv"
    request, upstream, client, routes, events = _transit(
        path, mode="audit", rounds=6)
    assert upstream.startswith(request[:-2]) and routes == (b"/.env",)
    assert client.endswith(_INTERNAL)
    assert any(e.get("kind") == "audit" and e.get("would") == "block"
               for e in events), events


def test_audit_still_forwards_three_decode_private_route_with_event():
    cfg = {"private_paths": ["/admin"], "private_path_allow": []}
    request, upstream, client, routes, events = _transit(
        b"/admin%25253Fview", cfg=cfg, mode="audit", rounds=3)
    assert upstream.startswith(request[:-2]) and routes == (b"/admin",)
    assert client.endswith(_INTERNAL)
    assert any(event.get("kind") == "audit" for event in events)
