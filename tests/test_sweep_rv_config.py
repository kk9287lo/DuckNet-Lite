"""
test_sweep_rv_config.py — 以前の版が保存した設定・状態の意味を、更新後も保つ(sweep: rv_config 群・Lite)。
====================================================================================
· #5  旧版が上限なしで受理した巨大な resp_error_threshold / cred_rate_limit(=実質無効)は、
      読込時に既定値(50 / 600)へ戻っていた。上限 1048576 へ丸めて読む(API は従来どおり拒否)。
· #6/#15 weight が 1000 を超えるカスタムシグネチャは読込時に無効化され、追加も拒否されていた。
      有限の値は 1000 へ丸めて有効のまま扱う(NaN/inf/負の値は従来どおり無効・拒否)。
· #16 (フル版の囮パスと同じ扱い)保存値のリストから一部の要素だけ捨てたときも cfg_load_rejected に記録する。
· #17 IPv6 のゾーンID付き(fe80::1%eth0)の白/黒リスト項目・保存済み BAN・手動 BAN が、ゾーンを
      外して届く peer と一致しなかった。設定側もゾーンを外して照合する。
· #18 旧版では効いていなかった大文字小文字違いの列挙値(ip_mode='Whitelist' 等)が、更新で黙って
      有効になっていた。正規化は保ちつつ、status の warnings とイベントでキーを名指しして知らせる。
· #19 署名実績のある状態ファイルを消すと、起動のたびに改竄警報を出し続けていた。警報した起動で
      fail-safe 値を署名保存し、同じ削除では 1 回だけにする(再び消されれば再び警報)。
入力は普通の文字列・文書用 IP(RFC 3849/5737)・無害な目印だけを使う。
"""
import json
import os
import tempfile

from dataplane.engine.core.signed_state import write_signed_json
from dataplane.engine.lifeform import pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["auto_under_attack"] = False       # 自動防御強化で判定が揺れないように
    sh.cfg.update(cfg)
    return sh


def _saved_by_old_release(sh, **cfg):
    """旧版の set_config が検証せずに保存した値を再現する(署名は正しい)。"""
    with sh._lock:
        sh.cfg.update(cfg)
        sh._save()


def _events(sh, kind):
    return [e for e in sh.events(500) if e.get("kind") == kind]


# ── #5: 巨大な件数閾値は上限へ丸めて読む ─────────────────────────────────
def test_rv5_saved_rate_counts_above_cap_are_clamped_not_reset_to_defaults():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        _saved_by_old_release(sh, enabled=True, resp_error_threshold=100000000,
                              cred_rate_limit=100000000, cred_rate_enabled=True)
        sh2 = NetShield(state_dir=d)
        assert sh2.cfg["resp_error_threshold"] == P._RATE_COUNT_MAX, sh2.cfg["resp_error_threshold"]
        assert sh2.cfg["cred_rate_limit"] == P._RATE_COUNT_MAX, sh2.cfg["cred_rate_limit"]
        assert not _events(sh2, "cfg_load_rejected"), _events(sh2, "cfg_load_rejected")
        acts = {sh2.note_response("203.0.113.20", 404).get("action") for _ in range(80)}
        assert acts == {"track"}, acts


def test_rv5_api_still_rejects_rate_counts_above_cap_and_accepts_the_cap():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.set_config(resp_error_threshold=P._RATE_COUNT_MAX + 1)
        assert r["ok"] is False and r.get("rejected") == ["resp_error_threshold"], r
        assert sh.cfg["resp_error_threshold"] == 50
        r = sh.set_config(cred_rate_limit=P._RATE_COUNT_MAX)
        assert r["changed"] == {"cred_rate_limit": P._RATE_COUNT_MAX}, r
        _saved_by_old_release(sh, resp_error_threshold=0)
        sh2 = NetShield(state_dir=d)
        assert sh2.cfg["resp_error_threshold"] == 50
        ev = _events(sh2, "cfg_load_rejected")
        assert ev and "resp_error_threshold" in ev[0]["keys"], ev


# ── #6/#15: weight の上限超えは 1000 へ丸めて有効のまま ──────────────────
def test_rv6_saved_custom_sig_heavier_than_cap_stays_active_at_cap():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        with sh._lock:
            sh._custom = [
                {"name": "heavy-marker", "category": "custom", "pattern": "zzheavymarkerzz",
                 "weight": 5000, "enabled": True, "source": "user"},
                {"name": "negative-marker", "category": "custom", "pattern": "zznegmarkerzz",
                 "weight": -5, "enabled": True, "source": "user"}]
            sh._save_sigs()
        sh2 = _shield(d)
        sh2.enable()
        view = {v["name"]: v for v in sh2.list_signatures()["custom"]}
        assert view["heavy-marker"]["active"] is True, view["heavy-marker"]
        assert view["heavy-marker"]["weight"] == P._SIG_WEIGHT_MAX, view["heavy-marker"]
        assert view["negative-marker"]["active"] is False, view["negative-marker"]
        rej = _events(sh2, "custom_sig_rejected")
        assert rej and [r["name"] for r in rej[0]["rules"]] == ["negative-marker"], rej
        res = sh2.inspect("203.0.113.31", path="/search", query="q=zzheavymarkerzz")
        assert res["action"] == "block", res


def test_rv6_add_signature_clamps_finite_weight_and_rejects_non_finite_or_negative():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.add_signature("heavy-add", "zzheavyaddzz", weight=1500)
        assert r["ok"] is True, r
        assert any("1000" in w for w in r.get("warnings") or []), r
        stored = [s for s in sh._custom if s["name"] == "heavy-add"][0]
        assert stored["weight"] == P._SIG_WEIGHT_MAX, stored
        for bad in (-1, "nan", "inf", float("inf"), True, "abc"):
            r = sh.add_signature("bad-weight", "zzbadweightzz", weight=bad)
            assert r["ok"] is False, (bad, r)
        r = sh.add_signature("normal-add", "zznormaladdzz", weight=40)
        assert r["ok"] is True and "warnings" not in r, r


# ── #16: 保存値のリストから一部の要素だけ捨てたら記録する ───────────────────
def test_rv16_partially_dropped_list_keys_are_counted():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        _saved_by_old_release(sh, blocked_urls=["/admin", 3, None, "/old"],
                              blocked_methods=["TRACE", "TR ACE", "CONNECT", "trace"])
        sh2 = _shield(d)
        assert sh2.cfg["blocked_urls"] == ["/admin", "/old"]
        assert sh2.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
        ev = _events(sh2, "cfg_load_rejected")
        assert len(ev) == 1 and ev[0]["elements"] == {"blocked_urls": 2, "blocked_methods": 1}, ev
        assert ev[0]["keys"] == [], ev


# ── #17: ゾーンID付きの設定項目・BAN ────────────────────────────────────
def test_rv17_ip_lists_with_zone_id_match_the_zone_stripped_peer():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.enable()
        sh.cfg.update(ip_mode="whitelist", ip_whitelist=["fe80::1%eth0", "2001:db8::7"])
        assert sh._ip_list_block("fe80::1") == ""
        assert sh._ip_list_block("fe80::2") != ""
        sh.cfg.update(ip_mode="blacklist", ip_blacklist=["fe80::3%eth0"])
        assert sh._ip_list_block("fe80::3") != ""
        assert sh._ip_list_block("fe80::4") == ""
        sh.cfg.update(ip_mode="blacklist", ip_blacklist=["192.0.2.9%eth0"])
        assert sh._ip_list_block("192.0.2.9") == ""


def test_rv17_manual_ban_and_unban_with_zone_id():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.enable()
        r = sh.ban("fe80::1%eth0")
        assert r["ok"] is True and r["banned"] == "fe80::1", r
        assert sh.is_banned_fast("fe80::1") is True
        assert sh.inspect("fe80::1", path="/")["action"] == "block"
        r = sh.unban("fe80::1%eth0")
        assert r["ok"] is True and sh.is_banned_fast("fe80::1") is False, r
        for raw in ("203.0.113.0/24", "not-an-ip", "", "a'b<c", "192.0.2.9%eth0"):
            assert sh.ban(raw).get("ok") is False, raw


def test_rv17_saved_ban_with_zone_id_applies_to_the_peer():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        now = P._now()
        assert write_signed_json(sh._bans_path, {"bans": {
            "fe80::5%eth0": {"until": now + 3600, "started": now, "permanent": False,
                             "count": 1}}, "saved": now}, sh._state_key)
        sh2 = _shield(d)
        assert sh2.is_banned_fast("fe80::5") is True
        assert [b["ip"] for b in sh2.bans()] == ["fe80::5"], sh2.bans()


# ── #18: 旧版で効いていなかった列挙値の綴りは、正規化したうえで知らせる ──────
def test_rv18_case_variant_enums_from_old_release_are_flagged():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        _saved_by_old_release(sh, ip_mode="Whitelist", geo_mode="Allow", mode="Enforce",
                              cookie_samesite="lax", dlp_action="audit")
        sh2 = _shield(d)
        assert sh2.cfg["ip_mode"] == "whitelist" and sh2.cfg["geo_mode"] == "allow"
        w = [x for x in sh2.config_warnings() if x["code"] == "cfg_enum_normalized"]
        assert len(w) == 1, sh2.config_warnings()
        assert w[0]["keys"] == ["geo_mode", "ip_mode"], w
        assert "ip_whitelist" in w[0]["message"] and "geo_cidrs" in w[0]["message"], w
        assert w[0] in sh2.status()["warnings"]
        ev = _events(sh2, "cfg_enum_normalized")
        assert len(ev) == 1 and ev[0].get("keys") == ["geo_mode", "ip_mode"], ev
        sh2.set_config(ip_mode="off")
        w = [x for x in sh2.config_warnings() if x["code"] == "cfg_enum_normalized"]
        assert w and w[0]["keys"] == ["geo_mode"], w
        sh2.set_config(geo_mode="off")
        sh3 = _shield(d)
        assert not [x for x in sh3.config_warnings() if x["code"] == "cfg_enum_normalized"]
        assert not _events(sh3, "cfg_enum_normalized")


def test_rv18_open_redirect_and_dlp_variants_report_only_real_changes():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        _saved_by_old_release(sh, open_redirect_mode="Enforce", dlp_action="Audit")
        sh2 = _shield(d)
        w = [x for x in sh2.config_warnings() if x["code"] == "cfg_enum_normalized"]
        assert len(w) == 1 and w[0]["keys"] == ["open_redirect_mode"], w


def _assert_bilingual(warnings):
    """英語表示のダッシュボードは message_en を優先する。全警告に ASCII だけの英文が付き、
    日本語の message はそのまま残る。"""
    assert warnings, warnings
    for w in warnings:
        en = w.get("message_en")
        assert isinstance(en, str) and en.strip(), w
        assert all(ord(c) < 128 for c in en), (w["code"], en)
        assert isinstance(w.get("message"), str) and any(ord(c) > 127 for c in w["message"]), w


def test_rv18_every_config_warning_has_english_message():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        # 旧版が保存し得た state: site whitelist+空・空の許可リストへ効き始める ip_mode・mode
        _saved_by_old_release(sh, site_mode="Whitelist", site_whitelist=[], ip_mode="Whitelist",
                              ip_whitelist=[], mode="Audit")
        sh2 = _shield(d)
        ws = sh2.config_warnings()
        assert sorted(x["code"] for x in ws) == ["cfg_enum_normalized", "site_whitelist_empty"], ws
        _assert_bilingual(ws)
        _assert_bilingual(sh2.status()["warnings"])
        en = [x for x in ws if x["code"] == "cfg_enum_normalized"][0]["message_en"]
        # 日本語の文と同じ情報(今の値・旧版での動作・空の許可リスト)を載せる
        for frag in ("ip_mode=whitelist", "mode=audit", "site_mode=whitelist",
                     "ip_mode=off", "mode=enforce", "ip_whitelist"):
            assert frag in en, (frag, en)
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        _saved_by_old_release(sh, geo_mode="Allow", geo_cidrs=["192.0.2.0/24"])
        sh2 = _shield(d)
        ws = sh2.config_warnings()
        assert [x["code"] for x in ws] == ["cfg_enum_normalized"], ws
        _assert_bilingual(ws)
        en = ws[0]["message_en"]
        assert "geo_mode=allow" in en and "geo_mode=off" in en, en
        assert "geo_cidrs" not in en, en                # 許可リストが空でなければ全遮断の注記は無い


# ── #19: 削除された署名付き状態ファイルの警報は削除 1 回につき 1 回 ─────────
def _tamper_count(sh):
    return sh._tamper["by_kind"].get("state_tamper", 0)


def test_rv19_deleted_state_json_alarms_once_and_stays_fail_closed():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.set_config(rate_per_sec=33.0)["ok"] is True
        os.remove(sh.path)
        sh2 = _shield(d)
        assert _tamper_count(sh2) == 1 and sh2.cfg["enabled"] is True
        assert _events(sh2, "cfg_fail_closed")
        sh3 = _shield(d)
        assert _tamper_count(sh3) == 0, sh3.events(50)
        assert not _events(sh3, "cfg_fail_closed")
        assert sh3.cfg["enabled"] is True
        os.remove(sh3.path)
        sh4 = _shield(d)
        assert _tamper_count(sh4) == 1 and sh4.cfg["enabled"] is True


def test_rv19_deleted_rules_and_bans_alarm_once():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.enable()
        assert sh.add_signature("rule-a", "zzrulemarkerzz", weight=50)["ok"] is True
        assert sh.ban("203.0.113.40")["ok"] is True
        for name in ("rules.json", "blocklist.json"):
            os.remove(os.path.join(d, name))
        sh2 = _shield(d)
        files = sorted(e.get("file") for e in _events(sh2, "state_tamper"))
        assert files == ["blocklist.json", "rules.json"], sh2.events(50)
        sh3 = _shield(d)
        assert _tamper_count(sh3) == 0, sh3.events(50)


def test_rv19_tampered_file_that_still_exists_keeps_alarming():
    """中身の改竄(ファイルは残っている)は証拠を上書きせず、従来どおり起動のたびに警報する。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.add_signature("rule-b", "zzrulebmarkerzz", weight=50)["ok"] is True
        p = os.path.join(d, "rules.json")
        raw = json.load(open(p, encoding="utf-8"))
        raw["_payload"]["signatures"][0]["weight"] = 0
        with open(p, "w", encoding="utf-8") as f:
            json.dump(raw, f)
        before = open(p, encoding="utf-8").read()
        for _ in range(2):
            sh2 = _shield(d)
            assert _tamper_count(sh2) == 1, sh2.events(50)
        assert open(p, encoding="utf-8").read() == before
