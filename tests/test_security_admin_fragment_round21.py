"""Legacy tokens in dashboard URL fragments leave no browser-history copy."""

from test_gui_url_scrub_round3 import _bootstrap


def test_fragment_token_and_encoded_case_alias_are_scrubbed_before_prompt():
    for fragment in ("#token=FRAGMENT_SECRET",
                     "#%54oKeN%3dFRAGMENT_SECRET",
                     "#panel?access%5Ftoken=FRAGMENT_SECRET",
                     "#%2574oken%253DFRAGMENT_SECRET"):
        result = _bootstrap("http://127.0.0.1:8081/" + fragment)
        assert result["changes"] == ["/"], (fragment, result)
        assert result["href"] == "http://127.0.0.1:8081/", (fragment, result)
        assert result["memory"] == "" and result["prompts"] == 0


def test_query_and_fragment_tokens_are_removed_together_without_reuse():
    result = _bootstrap("http://127.0.0.1:8081/?ToKeN=QUERY_SECRET&tab=overview"
                        "#panel?admin_token=FRAGMENT_SECRET")
    assert result["changes"] == ["/?tab=overview"], result
    assert result["href"] == "http://127.0.0.1:8081/?tab=overview", result
    assert result["memory"] == "" and result["prompts"] == 0


def test_benign_fragment_and_tokenized_word_remain_untouched():
    for fragment in ("#panel", "#tokenized", "#panel%20view"):
        url = "http://127.0.0.1:8081/?tab=overview" + fragment
        result = _bootstrap(url)
        assert result["changes"] == [] and result["href"] == url, result
        assert result["memory"] == "" and result["prompts"] == 0


def test_overencoded_fragment_cannot_outlast_bounded_scrub():
    result = _bootstrap("http://127.0.0.1:8081/"
                        "#%2525252574oken%252525253DFRAGMENT_SECRET")
    assert result["changes"] == ["/"], result
    assert result["href"] == "http://127.0.0.1:8081/", result
    assert result["memory"] == "" and result["prompts"] == 0


def test_double_encoded_query_token_and_aliases_leave_no_history_copy():
    for key in ("%2574oken", "%54oKeN", "access%5Ftoken",
                "admin_token", "ducknet-admin-token"):
        result = _bootstrap("http://127.0.0.1:8081/?" + key
                            + "=QUERY_SECRET&tab=overview#panel")
        assert result["changes"] == ["/?tab=overview#panel"], (key, result)
        assert result["href"] == "http://127.0.0.1:8081/?tab=overview#panel", (key, result)
        assert result["memory"] == "" and result["prompts"] == 0


def test_overencoded_query_key_fails_closed_but_benign_encoded_key_remains():
    result = _bootstrap("http://127.0.0.1:8081/"
                        "?%2525252574oken=QUERY_SECRET&tab=overview#panel")
    assert result["changes"] == ["/?tab=overview#panel"], result
    assert result["href"] == "http://127.0.0.1:8081/?tab=overview#panel", result
    benign = "http://127.0.0.1:8081/?tab%2520name=overview&tokenized=public#panel"
    allowed = _bootstrap(benign)
    assert allowed["changes"] == [] and allowed["href"] == benign, allowed


def test_benign_suffix_token_query_key_is_preserved():
    url = "http://127.0.0.1:8081/?csrf_token=public&tab=overview#panel"
    result = _bootstrap(url)
    assert result["changes"] == [] and result["href"] == url, result
    assert result["memory"] == "" and result["prompts"] == 0


def test_nested_query_and_fragment_tokens_scrub_in_one_history_replacement():
    result = _bootstrap("http://127.0.0.1:8081/?%2574oken=QUERY_SECRET&tab=overview"
                        "#%2574oken%253DFRAGMENT_SECRET")
    assert result["changes"] == ["/?tab=overview"], result
    assert result["href"] == "http://127.0.0.1:8081/?tab=overview", result
    assert result["memory"] == "" and result["prompts"] == 0
