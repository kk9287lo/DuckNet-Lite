"""
test_sweep_enterprise.py — URL 秘匿(monitor.py)の回帰テスト(Lite)。
====================================================================================
テスト名の cNN は検出候補の番号。修正前のコードで落ちることを確認してから直した。
フル版の同名モジュールのうち、Lite にも存在するモジュールの分だけを持つ。
"""
from dataplane.engine.lifeform.monitor import safe_url, strip_userinfo


# ── #76 URL 秘匿: ハイフン付き機微パラメータ / IPv6 の角括弧 ─────────────────────
def test_c76_redact_hyphenated_secret_params():
    """'-' を先に消してから '-'→'_' していたため、X-Amz-Signature 等が秘匿されなかった。"""
    out = safe_url("https://h/p?access-token=SECRET1&X-Amz-Signature=SECRET2"
                   "&client-secret=SECRET3&X-Amz-Security-Token=SECRET4&api_key=SECRET5"
                   "&Refresh-Token=SECRET6&page=2")
    for s in ("SECRET1", "SECRET2", "SECRET3", "SECRET4", "SECRET5", "SECRET6"):
        assert s not in out, out
    assert "page=2" in out


def test_c76_strip_userinfo_keeps_ipv6_brackets():
    """資格情報を除くと IPv6 の角括弧が落ち 'https://::1:8080/p' という不正 URL になっていた。"""
    assert strip_userinfo("https://u:pw@[::1]:8080/p") == "https://[::1]:8080/p"
    out = safe_url("https://u:pw@[2001:db8::1]/p?token=x")
    assert out.startswith("https://[2001:db8::1]/p?token=") and "pw" not in out, out
    assert "token=x" not in out
    assert strip_userinfo("https://u:pw@Example.com:8443/") == "https://Example.com:8443/"
