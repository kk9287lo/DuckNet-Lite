"""Log-safe URL helpers must not reflect untrusted credentials or tokens."""

from dataplane.engine.lifeform.monitor import NetGuard, redact_url, safe_url, strip_userinfo


def test_malformed_url_cannot_echo_credentials_or_query_secret():
    malformed = "https://user:SECRET_PASSWORD@[bad?token=SECRET_QUERY"
    for output in (strip_userinfo(malformed), redact_url(malformed), safe_url(malformed)):
        assert "SECRET_PASSWORD" not in output, output
        assert "SECRET_QUERY" not in output, output


def test_fragment_token_is_not_reflected_in_safe_log_url():
    output = safe_url("https://example.test/p?page=2#access_token=SECRET_FRAGMENT")
    assert "SECRET_FRAGMENT" not in output, output
    assert output.startswith("https://example.test/p?page=2"), output


def test_nonabsolute_userinfo_like_text_is_not_logged_verbatim():
    output = safe_url("user:SECRET_PASSWORD@host?token=SECRET_QUERY")
    assert "SECRET_PASSWORD" not in output, output
    assert "SECRET_QUERY" not in output, output


def test_encoded_authority_userinfo_is_not_logged_verbatim():
    for authority in ("user%3ASECRET_PASSWORD%40example.test",
                      "user%253ASECRET_PASSWORD%2540example.test"):
        output = safe_url("https://" + authority + "/p")
        assert "SECRET_PASSWORD" not in output, output


def test_guard_request_rejects_encoded_authority_without_echoing_secret():
    result = NetGuard().guard_request(
        "https://user%3ASECRET_PASSWORD%40example.test/p", resolve=False
    )
    assert result["ok"] is False and result["allowed"] is False, result
    assert "SECRET_PASSWORD" not in repr(result), result


def test_unicode_line_separator_cannot_forge_a_second_log_line():
    output = safe_url("https://example.test/p\u2028X-Admin: ok?x=1")
    assert len(output.splitlines()) == 1, output


def test_multiply_encoded_query_key_cannot_hide_a_secret_value():
    output = safe_url(
        "https://example.test/p?%252574%25256f%25256b%252565%25256e=SECRET_ENCODED"
    )
    assert "SECRET_ENCODED" not in output, output


def test_semicolon_query_separator_cannot_hide_token():
    output = safe_url("https://example.test/p?page=2;token=SECRET_SEMICOLON")
    assert "SECRET_SEMICOLON" not in output, output


def test_html_escaped_query_separator_cannot_hide_token():
    output = safe_url("https://example.test/p?page=2&amp;token=SECRET_HTML")
    assert "SECRET_HTML" not in output, output


def test_nested_encoded_url_value_cannot_carry_token_into_log():
    output = safe_url(
        "https://example.test/p?next=https%3A%2F%2Fidp.test%2F%3Faccess_token%3DSECRET_NESTED"
    )
    assert "SECRET_NESTED" not in output, output


def test_double_encoded_nested_query_value_cannot_carry_token():
    output = safe_url("https://example.test/p?redirect=%252Flogin%253Ftoken%253DSECRET_DOUBLE")
    assert "SECRET_DOUBLE" not in output, output


def test_benign_url_and_regular_sensitive_key_keep_expected_shape():
    assert safe_url("https://u:pw@example.test/p?page=2") == (
        "https://example.test/p?page=2"
    )
    output = safe_url("https://example.test/p?token=SECRET_DIRECT&page=2")
    assert "SECRET_DIRECT" not in output, output
    assert "page=2" in output, output
    permitted = NetGuard().guard_request("https://example.test/p?page=2", resolve=False)
    assert permitted["ok"] is True and permitted["host"] == "example.test", permitted
    assert safe_url("https://example.test/こんにちは") == "https://example.test/こんにちは"
