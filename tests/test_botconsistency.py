"""
test_botconsistency.py — ヘッダ整合性ボット検知(evolution #63)。
====================================================================================
UA はブラウザを名乗るのに実ブラウザが常時送るヘッダ(Accept-Language/Encoding)を欠く=ツールの
UA 偽装、を低FPで加点する。単独では落とさず(challenge_score 未満)、flood/scan 等と合算で escalation。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import (
    NetShield, _looks_like_browser_ua, _ua_header_inconsistent,
)

_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


def test_looks_like_browser_ua():
    assert _looks_like_browser_ua(_CHROME)
    assert _looks_like_browser_ua("Mozilla/5.0 ... Firefox/121.0")
    assert not _looks_like_browser_ua("curl/8.4.0")
    assert not _looks_like_browser_ua("python-requests/2.31")
    assert not _looks_like_browser_ua("")


def test_ua_header_inconsistent():
    full = ["host", "user-agent", "accept", "accept-language", "accept-encoding"]
    assert not _ua_header_inconsistent(_CHROME, full)            # 完全なブラウザ=整合
    assert _ua_header_inconsistent(_CHROME, ["host", "user-agent"])   # 言語/圧縮欠落=不整合
    assert _ua_header_inconsistent(_CHROME, ["host", "user-agent", "accept-encoding"])  # 言語欠落
    # 非ブラウザ UA は対象外(curl が最小ヘッダでも加点しない=ここは UA署名側の役割)
    assert not _ua_header_inconsistent("curl/8.4", ["host"])
    # header_names 不明(None)は判定不能=False
    assert not _ua_header_inconsistent(_CHROME, None)


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_inspect_scores_spoofed_browser():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, bot_inconsistency_score=20, challenge_score=40)
        # ブラウザ UA を名乗るが Accept-Language/Encoding 欠落=偽装の疑い→加点(単独では allow)
        r = sh.inspect("9.9.9.9", path="/", user_agent=_CHROME,
                       header_names=["host", "user-agent"])
        assert r["action"] == "allow"                           # 単独では落とさない
        # でも加点される(加点直後の微小 decay を許容して閾より僅か下まで OK)
        assert sh._decayed_score(sh._state("9.9.9.9")) >= 19
        assert sh.metrics().get("bot_inconsistency", 0) >= 1


def test_inspect_real_browser_not_scored():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect("1.1.1.1", path="/", user_agent=_CHROME,
                       header_names=["host", "user-agent", "accept",
                                     "accept-language", "accept-encoding"])
        assert r["action"] == "allow"
        assert sh._decayed_score(sh._state("1.1.1.1")) == 0.0    # 整合=非加点


def test_inspect_no_header_names_skips():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.inspect("2.2.2.2", path="/", user_agent=_CHROME)      # header_names 未指定
        assert sh._decayed_score(sh._state("2.2.2.2")) == 0.0    # 判定不能=非加点


def test_inconsistency_escalates_with_repetition():
    # 単発は allow だが、偽装ブラウザが連射すれば加点が積もり challenge/block へ。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, bot_inconsistency_score=20, challenge_score=40, block_score=100)
        acts = set()
        for _ in range(8):
            r = sh.inspect("6.6.6.6", path="/", user_agent=_CHROME,
                           header_names=["host", "user-agent"])
            acts.add(r["action"])
        assert acts & {"challenge", "block", "throttle"}         # 反復で escalation


def test_disabled_no_scoring():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, bot_consistency_enabled=False)
        sh.inspect("7.7.7.7", path="/", user_agent=_CHROME, header_names=["host"])
        assert sh._decayed_score(sh._state("7.7.7.7")) == 0.0
