"""
test_respscore.py — 応答アウェア脅威スコア(エラーレート検知・evolution #60)。
====================================================================================
バックエンド応答の 4xx 連射を *列挙(404)/ブルートフォース(401/403)* の足跡として検知し、
保守的に加点→チャレンジ、反復で BAN へ。5xx は加点しない(バックエンド起因の誤遮断回避)。
リクエスト署名では捕まらない攻撃を応答の足跡で捉えることを回帰から守る。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield, _now


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg.update(cfg)
    return sh


def test_below_threshold_only_tracks():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_error_threshold=10, resp_error_window_sec=60)
        for _ in range(9):
            r = sh.note_response("1.2.3.4", 404)
        assert r["action"] == "track" and r["errors"] == 9
        assert sh._decayed_score(sh._state("1.2.3.4")) == 0.0    # 未加点


def test_threshold_breach_adds_score_and_challenges():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_error_threshold=10, resp_error_score=50,
                     challenge_score=40, block_score=100)
        r = None
        for _ in range(10):
            r = sh.note_response("9.9.9.9", 401)        # ブルートフォースの足跡
        assert r["action"] == "score" and not r["banned"]
        score = sh._decayed_score(sh._state("9.9.9.9"))
        assert score >= 40                               # challenge_score 以上=次要求でチャレンジ
        # window はリセットされる(二重加点しない)
        assert not sh._state("9.9.9.9")["resp_err"]


def test_repeated_bursts_escalate_to_ban():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_error_threshold=5, resp_error_score=40, block_score=100)
        banned = False
        for _ in range(40):                              # 複数バースト分の 404 連射
            res = sh.note_response("6.6.6.6", 404)
            if res.get("banned"):
                banned = True
                break
        assert banned and sh.is_banned_fast("6.6.6.6")


def test_5xx_not_scored_but_tracked():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_error_threshold=3)
        for _ in range(20):
            r = sh.note_response("5.5.5.5", 500)         # バックエンド起因=加点しない
        assert r["action"] == "track"
        assert sh._decayed_score(sh._state("5.5.5.5")) == 0.0
        assert sh.metrics()["resp_code_hits"].get("5xx", 0) == 20   # 集計はする


def test_2xx_ignored():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_error_threshold=2)
        for _ in range(50):
            r = sh.note_response("8.8.8.8", 200)
        assert r["action"] == "ignore"
        assert sh._decayed_score(sh._state("8.8.8.8")) == 0.0


def test_disabled_tracks_but_no_score():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_score_enabled=False, resp_error_threshold=2)
        for _ in range(20):
            r = sh.note_response("7.7.7.7", 404)
        assert r["action"] == "track"
        assert sh._decayed_score(sh._state("7.7.7.7")) == 0.0
        assert sh.metrics()["resp_code_hits"].get("4xx", 0) == 20   # テレメトリは維持


def test_window_expiry_prevents_false_positive():
    # 窓外に流れた古いエラーは数えない(低頻度の散発 404 で誤遮断しない)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, resp_error_threshold=5, resp_error_window_sec=60)
        st = sh._state("4.4.4.4")
        from collections import deque
        # 70秒前の古い 404 を4件仕込む(窓外)
        st["resp_err"] = deque([_now() - 70] * 4, maxlen=1024)
        r = sh.note_response("4.4.4.4", 404)             # 新規1件=窓内は1件のみ
        assert r["action"] == "track" and r["errors"] == 1
