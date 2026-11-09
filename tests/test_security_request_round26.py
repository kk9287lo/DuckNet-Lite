"""Normal Bearer SP/HTAB readings must share inspection and credential identity."""

from unittest.mock import patch

from dataplane.engine.lifeform import pipeline
from dataplane.engine.services.proxy import _framing_ambiguous
from test_sweep_proxy_request import (
    _Backend, _exchange, _guard, _read_framed_request, _shield, _through,
)


_SEPARATORS = (b" ", b"\t", b"\t ", b" \t", b"  \t ")
_TOKEN = "ROUND26_DUMMY_TOKEN"


def _request(token=_TOKEN, separator=b" "):
    return (b"GET /api HTTP/1.1\r\nHost: origin.test\r\nAuthorization: bEaReR"
            + separator + token.encode("ascii") + b"\r\n\r\n")


class _BearerOrigin(_Backend):
    """A real loopback HTTP origin with whitespace-splitting authentication."""

    def __init__(self):
        self.tokens = []
        super().__init__()

    def _one(self, connection):
        with connection:
            connection.settimeout(2)
            wire = _read_framed_request(connection)
            self.got.append(wire)
            authorization = next(line.partition(b":")[2].strip()
                                 for line in wire.partition(b"\r\n\r\n")[0].split(b"\r\n")
                                 if line.lower().startswith(b"authorization:"))
            parts = authorization.split()
            if len(parts) < 2 or parts[0].lower() != b"bearer":
                return
            self.tokens.append(parts[1])
            body = b"ordinary-authentication"
            connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                               + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


def _settings(**changes):
    values = dict(block_page=False, block_score=1000, deny_score=1000,
                  rate_per_sec=1000, burst=1000, flood_threshold=1000,
                  resp_score_enabled=False, dlp_enabled=False,
                  sec_headers_enabled=False, cors_harden_enabled=False,
                  cookie_harden_enabled=False, open_redirect_enabled=False)
    values.update(changes)
    return values


def test_bearer_extraction_uses_ascii_separators_without_accepting_invalid_values():
    from dataplane.engine.lifeform.pipeline import _bearer_token
    for separator in _SEPARATORS:
        assert _bearer_token("\t bEaReR" + separator.decode("ascii") + _TOKEN + "\t ") == _TOKEN
    for value in (None, b"Bearer TOKEN", "Bearer", "Bearer\t ", "Basic TOKEN", "BearerX TOKEN",
                  "Bearer\u00a0TOKEN", "\u2003Bearer TOKEN", "Bearer TOKEN SECOND",
                  "Bearer TOKEN\tSECOND", "Bearer TOKEN\x01", "Bearer TOKEN\r\n",
                  "Bearer TOKEN,SECOND", "Bearer TOKEN, Bearer SECOND", "Bearer\t TOKEN,\t "):
        assert _bearer_token(value) == "", repr(value)


def test_inspection_receives_the_same_ordinary_token_for_each_separator():
    observed = []
    with patch.object(pipeline, "_jwt_alg", side_effect=lambda token: observed.append(token) or "RS256"):
        for separator in _SEPARATORS:
            assert pipeline._jwt_violation("bEaReR" + separator.decode("ascii") + _TOKEN, ["RS256"]) == ""
    assert observed == [_TOKEN] * len(_SEPARATORS)


def test_normal_bearer_is_inspected_identically_and_preserves_the_real_wire():
    for mode in ("enforce", "audit"):
        for separator in _SEPARATORS:
            origin = _BearerOrigin()
            observed = []
            try:
                with _shield(**_settings(mode=mode)), _guard(origin) as edge, \
                        patch.object(pipeline, "_jwt_alg", side_effect=lambda token: observed.append(token) or "RS256"):
                    response = _exchange(edge, [_request(separator=separator)])
                    assert response.endswith(b"ordinary-authentication") and edge.metrics["proxied"] == 1
                assert observed == [_TOKEN] and origin.tokens == [_TOKEN.encode("ascii")]
                assert b"Authorization: bEaReR" + separator + _TOKEN.encode("ascii") + b"\r\n" in origin.saw()
            finally:
                origin.close()


def test_bearer_separator_changes_share_one_credential_rate_identity():
    for mode in ("enforce", "audit"):
        origin = _BearerOrigin()
        try:
            with _shield(**_settings(mode=mode, cred_rate_enabled=True,
                                    cred_rate_limit=1, cred_rate_window_sec=60)) as shield, _guard(origin) as edge:
                for separator in _SEPARATORS:
                    _exchange(edge, [_request(separator=separator)])
                assert shield.metrics().get("cred_rate_hit", 0) == len(_SEPARATORS) - 1
                assert len(shield._cred_rate) == 1
                assert _TOKEN.encode() not in b"".join(shield._cred_rate)
                expected = len(_SEPARATORS) if mode == "audit" else 1
                assert edge.metrics["proxied"] == expected
            assert origin.tokens == [_TOKEN.encode()] * expected
        finally:
            origin.close()


def test_multiple_bearer_values_are_rejected_before_a_backend_selects_one():
    for mode in ("enforce", "audit"):
        for value in ("TOKEN SECOND", "TOKEN\tSECOND", "TOKEN \t SECOND", "TOKEN,SECOND",
                      "TOKEN, SECOND", "TOKEN, Bearer SECOND", "\t TOKEN,SECOND \t", "TOKEN,"):
            request = _request(value, b"\t").replace(b"Authorization: bEaReR", b"Authorization:\t bEaReR")
            origin = _BearerOrigin()
            try:
                with _shield(**_settings(mode=mode)), _guard(origin) as edge:
                    response = _exchange(edge, [request])
                    assert response.startswith(b"HTTP/1.1 400") and edge.metrics["proxied"] == 0
                assert origin.got == [] and origin.tokens == []
            finally:
                origin.close()


def test_invalid_authorization_controls_are_rejected_but_other_header_tabs_remain_valid():
    for control in (b"\x00", b"\x01", b"\x0b", b"\x0c", b"\x1f", b"\x7f", b"\x85", b"\xa0"):
        request = b"GET / HTTP/1.1\r\nHost: origin.test\r\nAuthorization: Bearer" + control + b"TOKEN\r\n\r\n"
        assert _framing_ambiguous(request)
        received, response, metrics = _through([request], **_settings())
        assert received == b"" and response.startswith(b"HTTP/1.1 400") and metrics["proxied"] == 0
    benign = b"GET / HTTP/1.1\r\nHost: origin.test\r\nX-Note: ordinary\ttext\r\n\r\n"
    received, response, metrics = _through([benign], **_settings())
    assert response.startswith(b"HTTP/1.1 200") and b"X-Note: ordinary\ttext\r\n" in received
    assert metrics["proxied"] == 1
    digest = (b'GET / HTTP/1.1\r\nHost: origin.test\r\nAuthorization: Digest username="user", '
              b'realm="zone", nonce="TOKEN", uri="/", response="00000000000000000000000000000000"\r\n\r\n')
    received, response, metrics = _through([digest], **_settings())
    assert response.startswith(b"HTTP/1.1 200") and digest.partition(b"\r\n\r\n")[0] in received
    assert metrics["proxied"] == 1
