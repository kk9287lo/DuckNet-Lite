"""
test_sweep_det_inspect_checks.py — inspect() の個別チェックの回帰(2026-10 検知エンジン総点検)。
====================================================================================
JWT 検査 / 規則性(cadence)検知。どれも修正を外すと落ちることを確認済み。
入力は無害な目印(普通の語・文書用 IP 192.0.2.x)と、既存テストにある値だけを使う。
"""
import base64
import contextlib
import json
import tempfile

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield, _jwt_alg, _jwt_violation


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _banned(sh, ip) -> bool:
    st = sh._ips.get(ip)
    return bool(st and st["ban_until"] > P._now())


# ── #17 JWT: alg を持たない 3 セグメントのトークン ─────────────────────────────
def _b64u(obj) -> str:                      # tests/test_jwt.py と同じ
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(alg: str) -> str:                  # tests/test_jwt.py と同じ
    return f"{_b64u({'alg': alg, 'typ': 'JWT'})}.{_b64u({'sub': 'admin'})}.sig"


def _signed_token_without_alg() -> str:
    """JWT ではない署名付きトークン(itsdangerous の payload.timestamp.signature 形)。
    1 段目は base64url(JSON) だが JOSE header ではない(alg メンバーが無い)。"""
    return _b64u({"id": 1}) + ".ZVxXAA." + "c2lnbmF0dXJl"


def test_d17_jwt_header_without_alg_is_not_flagged():
    """alg の無い header を alg=none 扱いし、itsdangerous 等の署名付きトークンを使う API
    利用者を最初の認証要求で即時BANしていた(JWT でない=対象外のはず)。"""
    tok = _signed_token_without_alg()
    assert _jwt_alg(tok) is None
    assert _jwt_violation("Bearer " + tok, []) == ""
    assert _jwt_violation("Bearer " + tok, ["RS256"]) == ""
    # 本物の alg:none(明示した空 alg も)は従来どおり検知する
    assert _jwt_violation("Bearer " + _jwt("none"), []) == "jwt:alg=none"
    assert _jwt_violation("Bearer " + _jwt("None"), []) == "jwt:alg=none"
    assert _jwt_violation("Bearer " + _jwt(""), []) == "jwt:alg=none"
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect("192.0.2.120", path="/api/me", auth="Bearer " + tok)
        assert r["action"] == "allow", r["reason"]
        assert not _banned(sh, "192.0.2.120")
        assert sh.inspect("192.0.2.120", path="/")["action"] == "allow"
        r = sh.inspect("192.0.2.121", path="/api", auth="Bearer " + _jwt("none"))
        assert r["action"] == "block" and _banned(sh, "192.0.2.121")


# ── #18 cadence: 規則的なポーリングへの加点 ────────────────────────────────────
_JITTER = (0.004, -0.004, 0.007, -0.002, 0.0, -0.006, 0.003, -0.001)   # ±10ms 以内の揺らぎ


@contextlib.contextmanager
def _fake_clock(t0=1_000_000.0):
    clock = [t0]
    orig = P._now
    P._now = lambda: clock[0]
    try:
        yield clock
    finally:
        P._now = orig


def _poll(sh, ip, clock, n, interval=1.0):
    out = []
    for i in range(n):
        out.append(sh.inspect(ip, path="/api/notifications", method="GET", zone="public"))
        clock[0] += interval + _JITTER[i % len(_JITTER)]
    return out


def _cadence_hits(rs) -> int:
    return sum("cadence:botlike" in r["reason"] for r in rs)


def test_d18_cadence_regular_poller_scored_once_per_episode():
    """1 秒間隔のポーリング(通知取得等)が 8 間隔以降 *毎要求* 規則性の加点を受け、約 10 秒で
    単発拒否(→反復で BAN)になっていた。加点は検知エピソードにつき 1 回(リズムが崩れたら再武装)。"""
    with tempfile.TemporaryDirectory() as d, _fake_clock() as clock:
        sh = _shield(d)
        ip = "192.0.2.80"
        rs = _poll(sh, ip, clock, 40)
        assert all(r["action"] == "allow" for r in rs), [r["reason"] for r in rs]
        assert _cadence_hits(rs) == 1                 # 検知そのものは残る
        assert not _banned(sh, ip)
        # 短い休止(タブの切替等)を挟んで規則的なポーリングを繰り返しても、加点が積み上がって
        # deny_score に届かない(前回の加点が減衰するまで次のエピソードを加点しない)
        rs2 = []
        for _ in range(6):
            clock[0] += 20.0
            rs2 += _poll(sh, ip, clock, 30)
        assert all(r["action"] == "allow" for r in rs2), [r["reason"] for r in rs2]
        # 十分に間が空いた後に再び規則的になれば、新しいエピソードとして 1 回だけ加点
        clock[0] += 200.0
        rs3 = _poll(sh, ip, clock, 40)
        assert all(r["action"] == "allow" for r in rs3), [r["reason"] for r in rs3]
        assert _cadence_hits(rs3) == 1
