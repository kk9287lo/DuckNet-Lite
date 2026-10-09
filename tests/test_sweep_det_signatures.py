"""
test_sweep_det_signatures.py — 侵入シグネチャ(組込/カスタム)と厳格度設定の回帰テスト。
====================================================================================
· weight=0(監視のみ)のカスタム署名が 30 点(名前が組込と同じならその weight)で加点され、
  数回の正規アクセスで BAN されていた。body_sig_weight_factor=0 も 1.0 扱いだった。
· カスタム署名は正規化(%デコード・小文字化)後の面で照合されるのに、大文字/%XX のまま
  コンパイルされて永久に不発。ドライランは生サンプルで照合して「一致」と表示していた。
· 組込署名が先に当たると、より重いカスタム署名が評価されなかった(先着 1 件のみ加点)。
· 重複判定が読込時に無効化した ReDoS パターンを実行して数秒停止/同名の編集を自分自身との
  重複として拒否していた。
· rules.json の壊れた要素で起動不能・inspect 例外。不正 weight の規則が黙って消えていた。
· paranoia の不正値が 1 に落ちて「適用」と報告、optional_sigs の "false" が ON になっていた。
· カスタム署名の件数に上限が無かった。docs の paranoia 範囲が 1–3 だった。
"""
import json
import os
import tempfile
import time
import urllib.error
import urllib.request

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.admin import AdminDashboard
from dataplane.engine.lifeform.pipeline import NetShield

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_UA = "Mozilla/5.0"
# 既存フィクスチャ(pipeline._DEDUP_CORPUS / test_paranoia)。新しい攻撃文字列は作らない。
_TRAVERSAL = "../../etc/passwd"
_REDIRECT_Q = "next=//evil.example/path"


def _shield(d):
    sh = NetShield(state_dir=d)
    sh.enable()
    sh.cfg["auto_under_attack"] = False     # 異常検知由来の challenge を排除
    return sh


def _write_plain_rules(d, payload):
    """署名前の旧形式 rules.json を直接置く(旧版/手書きの種ファイル=移行経路)。"""
    with open(os.path.join(d, "rules.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f)


def _post(url, token, body):
    r = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                               headers={"Content-Type": "application/json", "X-Token": token})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")


class _Admin:
    """実ダッシュボードを一時 state で立てる(偽シングルトンで実 state を汚さない)。"""

    def __init__(self, d):
        self._saved = (FW._FW, ND._SHIELD)
        FW._FW = FW.AppFirewall(state_dir=d)
        ND._SHIELD = ND.NetShield(state_dir=d)
        self.adm = AdminDashboard(host="127.0.0.1", port=0)
        info = self.adm.start()
        self.url, self.token = info["url"], self.adm.token

    def close(self):
        try:
            self.adm.stop()
        finally:
            FW._FW, ND._SHIELD = self._saved


# ── #22 / #29: weight=0 が「未設定」扱いで 30 点 ──
def test_d22_weight_zero_signature_adds_zero():
    """weight=0(監視のみ)の規則が 1 ヒット 30 点で加点され、4 回目で BAN されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.add_signature("observe-marker", r"zzqq\d", weight=0)["ok"] is True
        for _ in range(4):
            r = sh.inspect("192.0.2.10", path="/zzqq1", user_agent=_UA)
            assert r["action"] == "allow" and r["score"] == 0, r
        assert sh.metrics()["sig_hits"].get("observe-marker") == 4     # 記録はされる


def test_d22_weight_zero_signature_in_body_adds_zero():
    """本文でも weight=0 が 30×係数 で加点されていた(inspect_body の `or` フォールバック)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.add_signature("observe-marker", r"zzqq\d", weight=0)
        r = sh.inspect_body("192.0.2.11", b"x=zzqq1")
        assert r.get("signature") == "observe-marker" and r.get("score") == 0, r


def test_d29_custom_name_cannot_take_builtin_name():
    """組込と同名(rce 等)のカスタム規則が組込の weight で採点され、ヒット数も混ざっていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for name in ("rce", "RCE", "sqli-tautology"):
            assert sh.add_signature(name, r"zzqq\d", weight=0)["ok"] is False, name
        assert sh.list_signatures()["custom"] == []


def test_d22_watch_rule_does_not_hide_builtin_in_other_field():
    """監視用の weight=0 規則が主走査面で当たると、他フィールドの組込検知が走査されなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.add_signature("watch-marker", r"zzqq\d", weight=0)
        r = sh.inspect("192.0.2.12", path="/zzqq1", headers=_TRAVERSAL, user_agent=_UA)
        assert r["score"] == ND._SIG_WEIGHT["traversal"], r


# ── #36: body_sig_weight_factor=0 が 1.0 扱い ──
def test_d36_body_factor_zero_means_record_only():
    """係数 0(本文ヒットは記録のみ)が `0.0 or 1.0` で満額加点になっていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.add_signature("body-marker", r"zzqq\d", weight=50)
        assert sh.set_config(body_sig_weight_factor=0.0)["ok"] is True
        r = sh.inspect_body("192.0.2.13", b"x=zzqq1")
        assert r.get("signature") == "body-marker" and r.get("score") == 0, r
        sh.set_config(body_sig_weight_factor=0.1)
        r = sh.inspect_body("192.0.2.14", b"x=zzqq1")
        assert abs(r.get("score") - 5.0) < 0.01, r


# ── #30: 大文字/%XX のカスタム署名が永久に不発・ドライランは「一致」 ──
def test_d30_custom_pattern_matches_case_insensitively():
    """走査面は小文字化済みなので、大文字を含む規則がどの要求にも当たらなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.add_signature("token-rule", "EvilToken", weight=50)["ok"] is True
        r = sh.inspect("192.0.2.15", path="/", headers="EvilToken", user_agent=_UA)
        assert r["score"] == 50 and "token-rule" in r.get("reason", ""), r


def test_d30_dry_run_uses_scanner_normalization():
    """ドライランが生サンプルで照合し、実際には当たらない %XX 規則を「一致」と表示していた。"""
    with tempfile.TemporaryDirectory() as d:
        a = _Admin(d)
        try:
            url = a.url + "/api/shield/sig_test"
            code, r = _post(url, a.token, {"pattern": "zz%41qq", "sample": "zz%41qq"})
            assert code == 200 and r["ok"] is True and r["matches"] is False, r
            assert r.get("warnings"), r                    # なぜ当たらないかを知らせる
            code, r = _post(url, a.token, {"pattern": "EvilToken", "sample": "x EvilToken"})
            assert r["matches"] is True and r["error"] is None, r
            code, r = _post(url, a.token, {"pattern": "hello", "sample": "say hello"})
            assert r["matches"] is True and not r.get("warnings"), r
        finally:
            a.close()


def test_d30_add_warns_about_literals_rewritten_by_normalization():
    """%XX を含む規則は追加できても不発。追加時に警告を返す(拒否はしない)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.add_signature("pct-rule", "zz%41qq", weight=40)
        assert r["ok"] is True and r.get("warnings"), r
        assert not sh.add_signature("plain-rule", "zzqqplain", weight=40).get("warnings")


# ── #31: 組込ヒットがより重いカスタム署名を隠す ──
def test_d31_heavier_custom_not_hidden_by_builtin_same_field():
    """weight 200 の規則と組込 traversal が同じ値に当たると、組込の 50 点しか入らなかった。"""
    assert _TRAVERSAL in ND._DEDUP_CORPUS
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.add_signature("hard-block-passwd", r"etc/passwd", weight=200)["ok"] is True
        r = sh.inspect("192.0.2.16", path="/", query="f=" + _TRAVERSAL, user_agent=_UA)
        assert r["action"] == "block" and r["score"] >= 200, r


def test_d31_heavier_custom_in_other_field_counts():
    """クエリの組込ヒットで走査が止まり、ヘッダ内の weight 1000 の規則が評価されなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.add_signature("marker", r"zzqq\d", weight=1000)
        r = sh.inspect("192.0.2.17", path="/", query="f=" + _TRAVERSAL, headers="zzqq1",
                       user_agent=_UA)
        assert r["score"] >= 1000, r


def test_d31_lighter_custom_keeps_builtin_weight():
    """最大 weight を採る: 組込より軽いカスタム規則が組込の採点を下げない(組込のみの採点は不変)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.add_signature("light-passwd", r"etc/passwd", weight=10)
        r = sh.inspect("192.0.2.18", path="/", query="f=" + _TRAVERSAL, user_agent=_UA)
        assert r["score"] == ND._SIG_WEIGHT["traversal"], r
        assert "signature:traversal" in r.get("reason", ""), r


# ── #32: 読込時に無効化したパターンを重複判定が実行する ──
def test_d32_dedup_ignores_rules_inactive_at_load():
    """長すぎて無効化された規則と挙動が同じ、というだけで新規の規則が「重複」で拒否されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        _write_plain_rules(d, {"signatures": [
            {"name": "long-hello", "pattern": "hello" + "(?:)" * 100, "weight": 40},
            {"name": "good", "pattern": "evilbot", "weight": 40}]})
        sh._load_sigs()
        assert [c[0] for c in sh._custom_re] == ["good"]
        assert sh.add_signature("hello-rule", "hello", weight=40)["ok"] is True


def test_d32_dedup_does_not_run_redos_rule_blocked_at_load():
    """test_core の ReDoS フィクスチャ (.*)*x が読込で無効化されても、次の追加時の重複判定で
    実行され、プロセスが数秒止まっていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        _write_plain_rules(d, {"signatures": [
            {"name": "evil2", "pattern": r"(.*)*x", "weight": 40, "enabled": True},
            {"name": "good", "pattern": r"evilbot", "weight": 40, "enabled": True}]})
        sh._load_sigs()
        t0 = time.monotonic()
        r = sh.add_signature("hello-rule", "hello", weight=40)
        dt = time.monotonic() - t0
        assert r["ok"] is True, r
        assert dt < 2.0, dt


# ── #54 / #55: 壊れた rules.json で起動不能・不正 weight が黙って消える ──
def test_d54_malformed_rules_file_does_not_crash():
    """name 欠落/非配列/リスト名などの 1 要素で NetShield() が例外、または inspect() が例外だった。"""
    good = {"name": "good", "pattern": r"zzqq\d", "weight": 40}
    variants = [
        {"signatures": 5},
        {"signatures": {"name": "x"}},
        {"signatures": [{"pattern": r"yyqq\d", "weight": 40}, good]},
        {"signatures": [{"name": ["x"], "pattern": r"yyqq\d", "weight": 40}, good]},
        {"signatures": [{"name": 7, "pattern": r"yyqq\d"}, good]},
        {"signatures": ["plain-string", None, good]},
        {"signatures": [{"name": "nopat", "pattern": 5}, good]},
        {"signatures": [{"name": "a b<c", "pattern": r"yyqq\d"}, good]},
    ]
    for payload in variants:
        with tempfile.TemporaryDirectory() as d:
            _write_plain_rules(d, payload)
            sh = _shield(d)                                  # 起動できる
            json.dumps(sh.list_signatures(), allow_nan=False)
            for p in ("/zzqq1", "/yyqq1"):
                sh.inspect("192.0.2.19", path=p, user_agent=_UA)   # 例外にならない
            if isinstance(payload["signatures"], list):
                assert [c[0] for c in sh._custom_re] == ["good"], payload


def test_d55_rejected_rules_are_named_and_kept():
    """不正 weight の規則は読込で黙って消え、次の保存で rules.json からも消えていた。無効化された
    規則は件数しか分からず、どれが効いていないのか運用者に分からなかった。"""
    with tempfile.TemporaryDirectory() as d:
        _write_plain_rules(d, {"signatures": [
            {"name": "ok", "pattern": r"zzqq\d", "weight": 40},
            {"name": "long", "pattern": "zz" + "q" * 450, "weight": 40},
            {"name": "badw", "pattern": r"yyqq\d", "weight": -5}]})
        sh = _shield(d)
        listed = {c["name"]: c for c in sh.list_signatures()["custom"]}
        assert set(listed) == {"ok", "long", "badw"}, sorted(listed)
        assert listed["ok"]["active"] is True
        for name in ("long", "badw"):
            assert listed[name]["active"] is False and listed[name]["reason"], listed[name]
        json.dumps(sh.list_signatures(), allow_nan=False)
        named = json.dumps([e for e in sh.events(500) if e.get("kind") == "custom_sig_rejected"],
                           ensure_ascii=False)
        assert "long" in named and "badw" in named, named
        assert sh.inspect("192.0.2.20", path="/yyqq1", user_agent=_UA)["score"] == 0
        # 別の規則を追加しても不正 weight の規則は rules.json から消えない
        assert sh.add_signature("another", r"xxqq\d", weight=40)["ok"] is True
        names = {c["name"] for c in NetShield(state_dir=d).list_signatures()["custom"]}
        assert {"ok", "long", "badw", "another"} <= names, names
        # 同名で正しい weight を入れ直せば有効になる(#58 の編集経路)
        assert sh.add_signature("badw", r"yyqq\d", weight=30)["ok"] is True
        assert sh.inspect("192.0.2.21", path="/yyqq1", user_agent=_UA)["score"] == 30


# ── #56 / #57: paranoia の不正値・optional_sigs の文字列 ──
def test_d56_invalid_paranoia_rejected_and_level_kept():
    """apply_config({"paranoia": "max"}) が 1 に落として applied と報告し、任意署名も全 OFF にした。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_paranoia(4)
        want = ["redirect", "ssrf_internal", "ssti"]
        for bad in ("max", "high", None, [4], 3.7, True, "3"):
            r = sh.apply_config({"paranoia": bad})
            assert "paranoia" not in r["applied"], (bad, r)
            assert "paranoia" in r.get("rejected", []), (bad, r)
            st = sh.paranoia_status()
            assert st["paranoia"] == 4 and st["enabled_optional"] == want, (bad, st)
        r = sh.set_paranoia("x")
        assert r.get("ok") is False and r.get("paranoia") == 4, r
        assert sh.apply_config({"paranoia": 2})["applied"] == ["paranoia"]
        assert sh.paranoia_status()["enabled_optional"] == ["redirect"]


def test_d57_optional_sigs_values_must_be_bool():
    """optional_sigs={"redirect": "false"} が受理され、文字列の真偽で redirect が ON になっていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for bad in ({"redirect": "false"}, {"redirect": "off"}, {"redirect": 0},
                    {"nosuch": True}):
            r = sh.set_config(optional_sigs=bad)
            assert "optional_sigs" in r.get("rejected", []), (bad, r.get("changed"))
        assert sh.paranoia_status()["enabled_optional"] == []
        assert sh.set_optional_signature("redirect", "false")["ok"] is False
        sh.inspect("192.0.2.22", path="/r", query=_REDIRECT_Q, user_agent=_UA)
        assert sh.metrics()["sig_hits"].get("redirect", 0) == 0
        r = sh.set_config(optional_sigs={"redirect": True})
        assert "optional_sigs" in r["changed"], r.get("rejected")
        assert sh.paranoia_status()["enabled_optional"] == ["redirect"]


def test_d57_saved_string_optional_sig_does_not_turn_on_at_load():
    """保存済みの {"redirect": "false"} が再起動後に ON として読まれていた(_load も同じ検証)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["optional_sigs"] = {"redirect": "false", "ssti": "true", "nosuch": True}
        sh._save()
        sh2 = _shield(d)
        assert sh2.paranoia_status()["enabled_optional"] == ["ssti"]
        assert set(sh2.cfg["optional_sigs"]) <= set(ND._OPTIONAL_SIGS)


# ── #58: 同名の規則を編集できない ──
def test_d58_add_signature_edits_existing_rule_by_name():
    """同名で入れ直すと、置換される自分自身と「重複」判定されて編集できなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.add_signature("greeting", "hello", weight=40)["ok"] is True
        assert sh.add_signature("greeting", r"hello\b", weight=40)["ok"] is True
        assert sh.add_signature("greeting", r"hello\b", weight=80)["ok"] is True
        got = [(c["name"], c["pattern"], c["weight"]) for c in sh.list_signatures()["custom"]]
        assert got == [("greeting", r"hello\b", 80.0)], got
        # 別名で同じ挙動の規則は従来どおり重複として拒否
        assert sh.add_signature("greeting2", r"hello\b", weight=40)["ok"] is False


# ── #59: カスタム署名の件数上限 ──
def test_d59_custom_signature_count_is_capped():
    """件数無制限で、全規則が全要求の全窓で評価され、件数に比例して全要求が遅くなっていた。"""
    cap = getattr(ND, "_CUSTOM_SIG_MAX", None)
    assert isinstance(cap, int) and cap > 0, cap
    saved = cap
    ND._CUSTOM_SIG_MAX = 3
    try:
        with tempfile.TemporaryDirectory() as d:
            sh = _shield(d)
            for i in range(3):
                assert sh.add_signature(f"r{i}", f"zzq{i}x", weight=40)["ok"] is True
            r = sh.add_signature("r3", "zzq3x", weight=40)
            assert r["ok"] is False and "3" in r.get("error", ""), r
            assert sh.add_signature("r0", "zzq0y", weight=50)["ok"] is True   # 置換は可
            assert sh.remove_signature("r1")["removed"] == 1
            assert sh.add_signature("r3", "zzq3x", weight=40)["ok"] is True
        with tempfile.TemporaryDirectory() as d:
            _write_plain_rules(d, {"signatures": [
                {"name": f"s{i}", "pattern": f"zzs{i}x", "weight": 40} for i in range(5)]})
            sh = _shield(d)
            info = sh.list_signatures()
            assert info["custom_active"] == 3 and len(info["custom"]) == 5, info
            assert [c["active"] for c in info["custom"]] == [True] * 3 + [False] * 2
    finally:
        ND._CUSTOM_SIG_MAX = saved


# ── #60: docs の paranoia 範囲 ──
def test_d60_docs_paranoia_range_matches_code():
    """docs/options.md が 1–3 と書いており、レベル 4(SSTI)が運用者に知られていなかった。"""
    with open(os.path.join(_ROOT, "docs", "options.md"), encoding="utf-8") as f:
        rows = [ln for ln in f.read().splitlines() if ln.startswith("| `paranoia`")]
    assert rows, "paranoia の行が無い"
    assert f"1–{max(ND._PARANOIA_TIERS)}" in rows[0], rows[0]
