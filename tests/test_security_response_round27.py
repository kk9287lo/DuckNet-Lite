"""Response MIME metadata must describe the same view inspected by DLP."""

from email import policy
from email.parser import BytesParser

from test_sweep_det_response import _pipe
from test_sweep_proxy_request import _through

_MARKER = b"ghp_" + b"a" * 36  # inert value matching an existing DLP rule
_PARAMETERS = ("charset*=us-ascii''IBM037", "charset*0*=us-ascii''IBM; charset*1*=037",
               "(note)charset=IBM037", "charset(note)=IBM037", "charset (note) = IBM037")
_QUIET = dict(block_page=False, sec_headers_enabled=False, cookie_harden_enabled=False,
              cors_harden_enabled=False, open_redirect_enabled=False, resp_score_enabled=False)


def _response(body=b"public", *, parameters="charset=utf-8", disposition=None):
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; " + parameters.encode("ascii")
            + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n")
    if disposition is not None:
        head += b"Content-Disposition: attachment; " + disposition.encode("ascii") + b"\r\n"
    return head + b"\r\n" + body


def _receiver(response):
    return BytesParser(policy=policy.default).parsebytes(response.partition(b"\r\n")[2])


def test_unsupported_mime_charset_readings_are_refused_before_client_head_publication():
    body = _MARKER.decode().encode("cp037")
    for parameters in _PARAMETERS:
        response = _response(body, parameters=parameters)
        receiver = _receiver(response)
        assert receiver.get_content_charset() == "ibm037"
        assert receiver.get_payload(decode=True).decode(receiver.get_content_charset()).encode() == _MARKER
        for pieces in ([response], [response[i:i + 1] for i in range(len(response))]):
            delivered, shield = _pipe(pieces, dlp_enabled=True, dlp_action="block", **_QUIET)
            assert delivered == b"", (parameters, delivered)
            assert shield.metrics().get("dlp_unscannable", 0) == 1


def test_real_gateway_does_not_forward_an_unscannable_response_charset_to_the_client():
    body = _MARKER.decode().encode("cp037")
    for parameters in _PARAMETERS:
        response = _response(body, parameters=parameters)
        upstream, delivered, metrics = _through(
            [b"GET /public HTTP/1.1\r\nHost: origin.test\r\n\r\n"], backend_resp=response,
            dlp_enabled=True, dlp_action="block", **_QUIET)
        assert upstream.startswith(b"GET /public HTTP/1.1\r\n")
        assert delivered == b"", (parameters, delivered)
        assert metrics.get("proxied") == 1


def test_unsupported_charset_audit_records_the_problem_and_keeps_exact_response_bytes():
    body = _MARKER.decode().encode("cp037")
    for parameters in _PARAMETERS:
        response = _response(body, parameters=parameters)
        for mode, action in (("enforce", "audit"), ("audit", "block")):
            delivered, shield = _pipe([response], mode=mode, dlp_enabled=True, dlp_action=action, **_QUIET)
            assert delivered == response
            assert shield.metrics().get("dlp_unscannable", 0) == 1


def test_quoted_charset_text_and_quoted_pairs_do_not_change_the_actual_charset():
    for parameters in ('note="ordinary;charset=IBM037"; charset=utf-8',
                       'note="ordinary;charset*=IBM037"; charset="utf-8"',
                       'note="(ordinary)"; charset=utf-8', 'charset="ut\\f-8"'):
        response = _response("ordinary public text".encode(), parameters=parameters)
        assert _receiver(response).get_content_charset() == "utf-8"
        for pieces in ([response], [response[i:i + 1] for i in range(len(response))]):
            delivered, shield = _pipe(pieces, dlp_enabled=True, dlp_action="block", **_QUIET)
            assert delivered == response, parameters
            assert shield.metrics().get("dlp_unscannable", 0) == 0


def test_comment_obscured_download_name_is_not_a_clean_dlp_view():
    for parameter in ("filename(note)*=",):
        disposition = parameter + "utf-8''gh%70_" + "a" * 36
        response = _response(disposition=disposition)
        assert _receiver(response).get_filename().encode() == _MARKER
        delivered, shield = _pipe([response], dlp_enabled=True, dlp_action="block", **_QUIET)
        assert delivered == b"", (parameter, delivered)
        assert shield.metrics().get("dlp_unscannable", 0) == 1
        delivered, shield = _pipe([response], dlp_enabled=True, dlp_action="audit", **_QUIET)
        assert delivered == response
        assert shield.metrics().get("dlp_unscannable", 0) == 1


def test_quoted_parentheses_in_download_filename_and_note_are_ordinary_metadata():
    for disposition in ('filename="report(1).txt"',
                        'note="(ordinary;filename*=example)"; filename="report.txt"'):
        response = _response(disposition=disposition)
        delivered, shield = _pipe([response], dlp_enabled=True, dlp_action="block", **_QUIET)
        assert delivered == response
        assert shield.metrics().get("dlp_unscannable", 0) == 0


def test_bodyless_responses_do_not_need_to_decode_unused_charset_metadata():
    for status in (b"204 No Content", b"304 Not Modified"):
        for parameters in _PARAMETERS:
            response = (b"HTTP/1.1 " + status + b"\r\nContent-Type: text/plain; "
                        + parameters.encode() + b"\r\n\r\n")
            delivered, shield = _pipe([response], dlp_enabled=True, dlp_action="block", **_QUIET)
            assert delivered == response
            assert shield.metrics().get("dlp_unscannable", 0) == 0


def test_present_but_empty_charset_metadata_keeps_the_existing_refusal():
    for parameters in ("charset", "charset=", 'charset=""'):
        response = _response(parameters=parameters)
        delivered, shield = _pipe([response], dlp_enabled=True, dlp_action="block", **_QUIET)
        assert delivered == b""
        assert shield.metrics().get("dlp_unscannable", 0) == 1
