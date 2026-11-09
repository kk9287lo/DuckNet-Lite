"""The upload policy and MIME receiver must inspect the same stored filename."""

import base64
from email import policy
from email.header import Header
from email.parser import BytesParser

from dataplane.engine.lifeform.pipeline import (_dangerous_upload_filename,
                                               _disposition_upload_filename)
from test_sweep_proxy_request import _through

_TYPE = b"multipart/form-data; boundary=round26-filename"
_BOUNDARY = b"round26-filename"


def _part(name, *, content=b"public", field=b"upload"):
    return (b"--" + _BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + field
            + b"\"; filename=\"" + name.encode("ascii") + b"\"\r\n\r\n" + content + b"\r\n")


def _body(name):
    return _part(name) + b"--" + _BOUNDARY + b"--\r\n"


def _names(name):
    return (Header(name, "utf-8").encode(),
            "=?utf-8?b?" + base64.b64encode(name.encode()).decode() + "?=")


def _receiver_name(body):
    message = BytesParser(policy=policy.default).parsebytes(b"Content-Type: " + _TYPE + b"\r\n\r\n" + body)
    return list(message.iter_parts())[-1].get_filename()


def _wire(body, *, mode="enforce", enabled=True, disposition=None, raw_disposition=None, split=0,
          content_encoding=None):
    content_type = b"application/octet-stream" if disposition or raw_disposition else _TYPE
    head = (b"POST /upload HTTP/1.1\r\nHost: app.example\r\nContent-Type: " + content_type
            + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n")
    if disposition:
        head += b"Content-Disposition: attachment; filename=\"" + disposition.encode("ascii") + b"\"\r\n"
    if raw_disposition:
        head += b"Content-Disposition: " + raw_disposition.encode("ascii") + b"\r\n"
    if content_encoding:
        head += b"Content-Encoding: " + content_encoding.encode("ascii") + b"\r\n"
    request = head + b"\r\n" + body
    pieces = [request] if not split else [head + b"\r\n"] + [body[i:i + split] for i in range(0, len(body), split)]
    return _through(pieces, mode=mode, body_scan_enabled=False, upload_scan_enabled=enabled,
                    body_scan_max_bytes=128, upload_deny_ext=["blocked"])


def test_encoded_names_match_receiver_and_are_checked_by_both_upload_entrypoints():
    for name in _names("report.blocked"):
        body = _body(name)
        assert _receiver_name(body) == "report.blocked"
        hit = _dangerous_upload_filename(body, ["blocked"], content_type=_TYPE.decode())
        assert hit and hit[1] == "blocked", name
        hit = _disposition_upload_filename('attachment; filename="' + name + '"', ["blocked"])
        assert hit and hit[1] == "blocked", name


def test_encoded_disallowed_filename_has_no_backend_bytes_in_multipart_and_raw_uploads():
    for name in _names("report.blocked"):
        for body, disposition in ((_body(name), None), (b"public", name)):
            sent, reply, _metrics = _wire(body, disposition=disposition)
            assert sent == b"" and b"200 OK" not in reply, (name, disposition, sent)


def test_normal_encoded_unicode_filenames_preserve_complete_backend_wire():
    for name in ("report.txt", *_names("report.txt"), *_names("r\u00e9sum\u00e9.txt")):
        body = _body(name)
        assert _dangerous_upload_filename(body, ["blocked"], content_type=_TYPE.decode()) is None
        sent, reply, _metrics = _wire(body)
        assert sent.endswith(body) and b"200 OK" in reply, (name, reply)
        assert (b'filename="' + name.encode("ascii") + b'"') in sent


def test_audit_and_explicitly_disabled_upload_policy_preserve_the_original_body():
    for name in _names("report.blocked"):
        body = _body(name)
        for mode, enabled in (("audit", True), ("enforce", False)):
            sent, reply, _metrics = _wire(body, mode=mode, enabled=enabled)
            assert sent.endswith(body) and b"200 OK" in reply, (mode, enabled, reply)


def test_encoded_name_after_small_inspection_prefix_and_split_headers_is_still_checked():
    name = _names("report.blocked")[1]
    body = (_part("report.txt", content=b"A" * 1024, field=b"notes") + _part(name)
            + b"--" + _BOUNDARY + b"--\r\n")
    assert _receiver_name(body) == "report.blocked"
    for split in (0, 31):
        sent, reply, _metrics = _wire(body, split=split)
        assert not sent and b"200 OK" not in reply
    sent, reply, _metrics = _wire(body, mode="audit", split=31)
    assert sent.endswith(body) and b"200 OK" in reply


def test_unknown_or_nontext_filename_encoding_is_not_reported_as_clean():
    value = base64.b64encode(b"report.txt").decode()
    for charset in ("x-unknown-round26", "base64_codec", "x" * 101):
        filename = "=?" + charset + "?b?" + value + "?="
        hit = _dangerous_upload_filename(_body(filename), ["blocked"], content_type=_TYPE.decode())
        assert hit is not None and hit[1] == "", charset


def _extended_body(parameters):
    return (b"--" + _BOUNDARY + b"\r\nContent-Disposition: form-data; name=upload; "
            + parameters.encode("ascii") + b"\r\n\r\npublic\r\n--" + _BOUNDARY + b"--\r\n")


def test_declared_extended_filename_charsets_match_the_saved_filename_on_real_wire():
    from urllib.parse import quote_from_bytes
    for charset in ("utf-8", "utf-16-le", "utf-32-le", "cp037"):
        for filename in ("report.blocked", "report.txt"):
            parameters = "filename*=" + charset + "''" + quote_from_bytes(filename.encode(charset))
            body = _extended_body(parameters)
            assert _receiver_name(body) == filename
            hit = _disposition_upload_filename("attachment; " + parameters, ["blocked"])
            sent, reply, _metrics = _wire(body)
            raw_sent, raw_reply, _metrics = _wire(b"public", raw_disposition="attachment; " + parameters)
            if filename.endswith(".blocked"):
                assert hit and hit[1] == "blocked", charset
                assert not sent and not raw_sent
                assert b"200 OK" not in reply and b"200 OK" not in raw_reply
            else:
                assert hit is None and sent.endswith(body) and raw_sent.endswith(b"public")
                assert b"200 OK" in reply and b"200 OK" in raw_reply


def test_filename_continuations_follow_the_declared_charset():
    from urllib.parse import quote_from_bytes
    for charset in ("utf-8", "utf-16-le", "utf-32-le", "cp037"):
        for filename in ("report.blocked", "report.txt"):
            raw = filename.encode(charset)
            split = 8 if charset.startswith(("utf-16", "utf-32")) else 5
            parameters = ("filename*0*=" + charset + "''" + quote_from_bytes(raw[:split])
                          + "; filename*1*=" + quote_from_bytes(raw[split:]))
            body = _extended_body(parameters)
            assert _receiver_name(body) == filename
            hit = _dangerous_upload_filename(body, ["blocked"], content_type=_TYPE.decode())
            assert (hit is not None) == filename.endswith(".blocked"), charset
            if hit:
                assert hit[1] == "blocked"
            sent, reply, _metrics = _wire(body, mode="audit")
            assert sent.endswith(body) and b"200 OK" in reply


def test_untrusted_filename_charset_labels_cannot_grow_the_global_codec_negative_cache():
    import encodings
    import uuid
    prefix = "r26filename" + uuid.uuid4().hex
    encoded = base64.b64encode(b"report.txt").decode()
    for number in range(32):
        label = prefix + str(number)
        for parameters in ('filename="=?' + label + '?b?' + encoded + '?="',
                           "filename*=" + label + "''report.txt"):
            hit = _disposition_upload_filename("attachment; " + parameters, ["blocked"])
            assert hit is not None and hit[1] == ""
    assert not any(name.startswith(prefix) for name in encodings._cache)


def test_comment_obscured_filename_parameters_cannot_change_the_backend_name():
    for parameters in ("(note)filename=report.blocked", "filename(note)=report.blocked",
                       "filename (note) = report.blocked"):
        body = _extended_body(parameters)
        assert _receiver_name(body) == "report.blocked"
        hit = _dangerous_upload_filename(body, ["blocked"], content_type=_TYPE.decode())
        assert hit is not None and hit[1] == ""
        sent, reply, _metrics = _wire(body)
        raw_sent, raw_reply, _metrics = _wire(b"public", raw_disposition="attachment; " + parameters)
        assert not sent and not raw_sent and b"200 OK" not in reply and b"200 OK" not in raw_reply
        sent, reply, _metrics = _wire(body, mode="audit")
        assert sent.endswith(body) and b"200 OK" in reply


def test_parentheses_inside_a_quoted_filename_or_note_remain_ordinary_data():
    for parameters in ('filename="report(1).txt"',
                       'note="(ordinary)"; filename="report.txt"',
                       'note="filename(note)=ordinary"; filename="report.txt"'):
        body = _extended_body(parameters)
        assert _dangerous_upload_filename(body, ["blocked"], content_type=_TYPE.decode()) is None
        sent, reply, _metrics = _wire(body)
        assert sent.endswith(body) and b"200 OK" in reply


def test_folded_quoted_filename_is_validated_only_after_its_header_is_complete():
    for ending, blocked in (("(1).txt", False), (".blocked", True)):
        parameters = 'filename="report\r\n ' + ending + '"'
        body = _extended_body(parameters)
        assert _receiver_name(body) == "report " + ending
        for split in (0, 31):
            sent, reply, _metrics = _wire(body, split=split)
            if blocked:
                assert not sent and b"200 OK" not in reply
            else:
                assert sent.endswith(body) and b"200 OK" in reply


def test_unfinished_filename_header_is_rejected_at_body_completion():
    import gzip
    body = (b"--" + _BOUNDARY
            + b'\r\nContent-Disposition: form-data; name=upload; filename="report.txt\r\n')
    for data, encoding in ((body, None), (gzip.compress(body, mtime=0), "gzip")):
        sent, reply, _metrics = _wire(data, content_encoding=encoding)
        assert not sent and b"200 OK" not in reply
        sent, reply, _metrics = _wire(data, mode="audit", content_encoding=encoding)
        assert sent.endswith(data) and b"200 OK" in reply


def test_windows_stream_aliases_are_checked_at_both_upload_entrypoints():
    for name in ("report.blocked::$DATA", "report.blocked:notes.txt", "report.blocked. :notes.txt"):
        body = _body(name)
        hit = _disposition_upload_filename('attachment; filename="' + name + '"', ["blocked"])
        assert hit and hit[1] == "blocked", name
        for data, disposition in ((body, None), (b"public", name)):
            sent, reply, _metrics = _wire(data, disposition=disposition)
            assert not sent and b"200 OK" not in reply, name
            for mode, enabled in (("audit", True), ("enforce", False)):
                sent, reply, _metrics = _wire(data, disposition=disposition, mode=mode, enabled=enabled)
                assert sent.endswith(data) and b"200 OK" in reply
    for name in ("report.txt::$DATA", "report.txt:notes.txt", "report:notes.txt"):
        body = _body(name)
        assert _disposition_upload_filename('attachment; filename="' + name + '"', ["blocked"]) is None
        sent, reply, _metrics = _wire(body)
        assert sent.endswith(body) and b"200 OK" in reply
    assert _disposition_upload_filename('attachment; filename=".user.ini::$DATA"', ["user.ini"])


def test_windows_saved_stream_alias_matches_the_inspected_base_file():
    import os
    from pathlib import Path
    import tempfile
    from unittest import SkipTest
    if os.name != "nt":
        raise SkipTest("actual Win32 stream alias saving requires Windows")
    with tempfile.TemporaryDirectory(prefix="r26-filename-alias-", dir=os.environ["DUCKNET_STATE_DIR"]) as folder:
        for index, (name, blocked) in enumerate((("report.blocked::$DATA", True), ("report.txt::$DATA", False))):
            case = Path(folder) / str(index)
            case.mkdir()
            (case / name).write_bytes(b"ordinary local fixture")
            basename = name.split(":", 1)[0]
            assert sorted(path.name for path in case.iterdir()) == [basename]
            assert (case / basename).read_bytes() == b"ordinary local fixture"
            hit = _disposition_upload_filename('attachment; filename="' + name + '"', ["blocked"])
            assert bool(hit) == blocked, (name, hit)
