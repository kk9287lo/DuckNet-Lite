"""Encoded download filenames must use the same DLP view as recipients."""

from email.message import Message
from email.header import decode_header
import re
from urllib.parse import unquote_to_bytes

from test_security_response_head_percent_dlp_round9 import _TOKEN, _transit


def _response(value):
    return (b"HTTP/1.1 200 OK\r\nContent-Disposition: " + value
            + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def _filename(value):
    header = Message()
    header["Content-Disposition"] = value.decode("ascii")
    return header.get_filename().encode("ascii")


def test_encoded_download_filename_secret_is_blocked_before_client_head():
    value = b"attachment; filename*=UTF-8''gh%70_" + b"a" * 36 + b".txt"
    response = _response(value)
    assert _TOKEN not in response and _TOKEN in _filename(value)

    backend, client, metrics, _ = _transit(response, "block")
    assert backend.startswith(b"GET /view HTTP/1.1\r\n")
    assert client == b"" and metrics.get("dlp_leak") == 1

    backend, client, metrics, events = _transit(response, "audit")
    assert backend.startswith(b"GET /view HTTP/1.1\r\n")
    assert client == response and metrics.get("dlp_leak") == 1
    assert any(event.get("kind") == "dlp_leak" for event in events)


def test_benign_encoded_download_filename_keeps_exact_wire():
    value = b"attachment; filename*=UTF-8''public%20report.txt"
    response = _response(value)
    assert _filename(value) == b"public report.txt"
    _, client, metrics, _ = _transit(response, "block")
    assert client == response
    assert not metrics.get("dlp_leak") and not metrics.get("dlp_unscannable")


def test_rfc2231_filename_continuations_cannot_split_a_secret():
    value = (b"attachment; filename*0*=UTF-8''gh; filename*1*=%70_"
             + b"a" * 36 + b".txt")
    response = _response(value)
    assert _TOKEN not in response and _TOKEN in _filename(value)
    _, client, metrics, _ = _transit(response, "block")
    assert client == b"" and metrics.get("dlp_leak") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_leak") == 1
    assert any(event.get("kind") == "dlp_leak" for event in events)


def test_ambiguous_filename_continuation_fails_closed_and_audits():
    value = (b"attachment; filename*0*=UTF-8''gh; filename*1*=%70_"
             + b"a" * 36 + b".txt; filename*1*=public")
    response = _response(value)
    assert _TOKEN not in response and _TOKEN in _filename(value)
    _, client, metrics, _ = _transit(response, "block")
    assert client == b"" and metrics.get("dlp_unscannable") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(event.get("encoding") == "response-disposition" for event in events)


def test_benign_rfc2231_filename_continuation_keeps_exact_wire():
    value = b"attachment; filename*0*=UTF-8''public; filename*1*=%20report.txt"
    response = _response(value)
    assert _filename(value) == b"public report.txt"
    _, client, metrics, _ = _transit(response, "block")
    assert client == response
    assert not metrics.get("dlp_leak") and not metrics.get("dlp_unscannable")


def test_ordinary_filename_percent_and_quoted_pair_views_cannot_hide_secret():
    encoded = b'attachment; filename="gh%70_' + b"a" * 36 + b'.txt"'
    quoted = b'attachment; filename="gh\\p_' + b"a" * 36 + b'.txt"'
    for value, recipient in ((encoded, unquote_to_bytes(_filename(encoded))),
                             (quoted, re.sub(rb"\\(.)", rb"\1", _filename(quoted)))):
        response = _response(value)
        assert _TOKEN not in response and _TOKEN in recipient
        _, client, metrics, _ = _transit(response, "block")
        assert client == b"" and metrics.get("dlp_leak") == 1
        _, client, metrics, events = _transit(response, "audit")
        assert client == response and metrics.get("dlp_leak") == 1
        assert any(event.get("kind") == "dlp_leak" for event in events)


def test_benign_ordinary_filename_percent_and_backslash_keep_exact_wire():
    for value in (b'attachment; filename="public%20report.txt"',
                  b'attachment; filename="public\\ report.txt"'):
        response = _response(value)
        _, client, metrics, _ = _transit(response, "block")
        assert client == response
        assert not metrics.get("dlp_leak") and not metrics.get("dlp_unscannable")


def test_legacy_encoded_word_filename_is_unscannable_before_client_head():
    value = (b'attachment; filename="=?UTF-8?Q?gh=70=5F'
             + b"a" * 36 + b'.txt?="')
    response = _response(value)
    decoded = decode_header(_filename(value).decode("ascii"))[0][0]
    assert _TOKEN not in response and _TOKEN in decoded
    _, client, metrics, _ = _transit(response, "block")
    assert client == b"" and metrics.get("dlp_unscannable") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(event.get("encoding") == "response-disposition" for event in events)


def test_benign_legacy_encoded_word_is_also_bounded_fail_closed():
    response = _response(b'attachment; filename="=?UTF-8?Q?public=20report.txt?="')
    _, client, metrics, _ = _transit(response, "block")
    assert client == b"" and metrics.get("dlp_unscannable") == 1
    _, client, metrics, events = _transit(response, "audit")
    assert client == response and metrics.get("dlp_unscannable") == 1
    assert any(event.get("encoding") == "response-disposition" for event in events)
