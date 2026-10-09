"""
test_sweep_det3_docs.py — カスタムシグネチャの改行警告の文言(掃討パス: det3_docs)。
====================================================================================
· T1 カスタム規則に改行(\\r \\n)を書いたときの警告が『改行は走査前に ';' へ置き換えられる』
     とだけ言っていた。要求本文では改行は ';' ではなく空白になる(det_normalize #0)ので、本文向けの
     規則を書く運用者を誤った書き方へ導いていた。URL/ヘッダと本文の両方の扱いを書く。
入力は普通の文字列と無害な目印だけを使う。
"""
from dataplane.engine.lifeform import pipeline as P


def _crlf_warning(pattern):
    """改行についての警告文(無ければ None)。"""
    hits = [m for m in P._custom_pattern_warnings(pattern) if "改行" in m]
    assert len(hits) <= 1, hits
    return hits[0] if hits else None


def test_t1_crlf_lint_describes_head_and_body():
    """警告は URL/ヘッダでは ';'、本文では空白になることを両方書く(実際の正規化と一致)。"""
    for pat in (r"zzmarker\r\nzzother", r"zzmarker\nzzother", "zzmarker\nzzother"):
        msg = _crlf_warning(pat)
        assert msg, pat
        assert "';'" in msg and "URL" in msg and "ヘッダ" in msg, msg
        assert "本文" in msg and "空白" in msg, msg
    # 文言が実際の正規化と食い違っていないこと(head は ';'、本文は空白)
    assert P._normalize_full("zzmarker\r\nzzother") == "zzmarker;zzother"
    assert P._normalize_full("zzmarker\r\nzzother", body=True) == "zzmarker zzother"


def test_t1_lint_silent_without_line_breaks():
    """改行を含まない規則には改行の警告を出さない(従来どおり)。"""
    assert _crlf_warning(r"zzmarker\s+zzother") is None
    assert _crlf_warning("zzmarker;zzother") is None
