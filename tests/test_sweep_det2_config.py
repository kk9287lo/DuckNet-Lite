"""
test_sweep_det2_config.py — 設定値の検証と改竄時の復元(掃討パス: det2_config)。
====================================================================================
· T1 state.json とメモリ上の cfg を同時に改竄されると、整合チェックの復元が既定値
     (enabled=False)へ倒れて WAF が止まっていた。稼働中は最後に MAC が一致した cfg を保ち、
     起動時は(初回起動でなければ)既定値のうえで shield を有効にして起動する(fail-closed)。
· T2 body_sig_weight_factor の負値を受理していた(0 以上のみ有効)。
· T3 列挙値の文字列キー(mode / open_redirect_mode / geo_mode / site_mode / ip_mode /
     cookie_samesite)が任意の文字列を受理していた。
(set_posmodel の拒否件数・GUI スキーマは Full のみ=Full 側の同名モジュールで検証)
"""
import json
import os
import shutil
import tempfile

from dataplane.engine.core import signed_state as ss
from dataplane.engine.lifeform import pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield

_FULL = "posmodel_mode" in P._DEFAULTS


def _restart(d):
    """再起動相当(プロセス内に残る版の高水位を捨ててから作り直す)。"""
    ss._MEM_HW.clear()
    return NetShield(state_dir=d)


def _tamper_count(sh, kind=None):
    t = sh.metrics()["tamper"]
    return t["count"] if kind is None else t["by_kind"].get(kind, 0)


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _write(p, text):
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


def _break_state(sh, how, old_text):
    """state.json を『検証済みとして読めない』状態にする。old_text=1 つ前の正署名の中身。"""
    p, d = sh.path, os.path.dirname(sh.path)
    if how == "tampered":                       # 署名はそのまま中身だけ書換
        env = json.loads(_read(p))
        env["_payload"]["cfg"]["enabled"] = False
        _write(p, json.dumps(env))
    elif how == "missing":                      # 削除(署名実績 .hw は残る)
        os.remove(p)
    elif how == "rolled_back":                  # 古い正署名ファイルへの巻き戻し
        _write(p, old_text)
    elif how == "unsigned":                     # 平文すり替え(マーカーあり)
        _write(p, json.dumps({"cfg": {"enabled": False, "mode": "audit"}}))
    elif how == "unsigned_no_marker":           # マーカーも消して平文(.hw は残る)
        os.remove(os.path.join(d, ".state_signed"))
        _write(p, json.dumps({"cfg": {"enabled": False, "mode": "audit"}}))
    else:
        raise AssertionError(how)


# ── T1: 稼働中の復元 ───────────────────────────────────────────────────────
def test_t1_runtime_restore_keeps_last_verified_cfg_when_disk_unreadable():
    """メモリとディスクを同時に改竄されると、復元が既定値(enabled=False)へ倒れて WAF が止まっていた。"""
    for how in ("tampered", "missing", "rolled_back"):
        with tempfile.TemporaryDirectory() as d:
            sh = NetShield(state_dir=d)
            sh.enable()
            assert sh.set_config(block_score=120)["ok"]
            old = _read(sh.path)
            assert sh.set_config(flood_threshold=155)["changed"]   # 最後の正規変更(MAC の基準)
            _break_state(sh, how, old)
            sh.cfg["enabled"] = False                           # API を通さないメモリ改変
            sh.cfg["block_score"] = 10 ** 9
            r = sh.verify_cfg_integrity()
            assert r.get("tampered") is True and r.get("restored") is True, (how, r)
            assert sh.is_enabled(), how
            assert sh.cfg["block_score"] == 120 and sh.cfg["flood_threshold"] == 155, (how, sh.cfg)
            assert sh.verify_cfg_integrity()["tampered"] is False, how
            assert _tamper_count(sh, "memory_tamper") == 1, how
            assert _tamper_count(sh, "state_tamper") >= 1, how


def test_t1_runtime_restore_prefers_verified_disk_cfg():
    """ディスクが正しく読めるときは従来どおりディスクの正規値へ戻す。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.enable()
        assert sh.set_config(block_score=120)["ok"]
        sh.cfg["block_score"] = 7
        r = sh.verify_cfg_integrity()
        assert r.get("tampered") is True and sh.cfg["block_score"] == 120, r
        assert sh.is_enabled() and _tamper_count(sh, "state_tamper") == 0


def test_t1_runtime_restore_without_any_verified_cfg_keeps_shield_on():
    """ディスクも保持中の正規 cfg も検証できない(両方すり替え)ときは、既定値のうえで
    shield を有効に保つ(止めない)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.enable()
        assert sh.set_config(block_score=120)["ok"]
        os.remove(sh.path)
        sh._cfg_good = b'{"enabled":false}'                     # 保持中の正規 cfg も偽造
        sh.cfg["enabled"] = False
        r = sh.verify_cfg_integrity()
        assert r.get("tampered") is True, r
        assert sh.is_enabled(), sh.cfg["enabled"]
        assert sh.cfg["block_score"] == P._DEFAULTS["block_score"]
        assert sh.verify_cfg_integrity()["tampered"] is False


# ── T1: 起動時 ─────────────────────────────────────────────────────────────
def test_t1_startup_with_broken_state_and_signed_history_starts_enabled():
    """署名で保存した実績があるのに state.json が改竄/削除/巻き戻し/平文すり替えだと、既定値
    (enabled=False)で起動して WAF が止まっていた。既定値+shield 有効で起動し、警報を出す。"""
    for how in ("tampered", "missing", "rolled_back", "unsigned", "unsigned_no_marker"):
        with tempfile.TemporaryDirectory() as d:
            sh = NetShield(state_dir=d)
            sh.enable()
            assert sh.set_config(block_score=120)["ok"]
            old = _read(sh.path)
            assert sh.set_config(flood_threshold=155)["changed"]
            _break_state(sh, how, old)
            s2 = _restart(d)
            assert s2.is_enabled(), how
            assert s2.cfg["block_score"] == P._DEFAULTS["block_score"], how   # 改竄値は採らない
            assert s2.cfg["mode"] == "enforce", how
            assert _tamper_count(s2, "state_tamper") >= 1, how
            assert s2.verify_cfg_integrity()["tampered"] is False, how


def test_t1_startup_fail_closed_even_if_operator_had_disabled():
    """直前が OFF でも、改竄で読めない以上は分からない=有効で起動する(利用者判断の fail-closed)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        assert sh.set_config(block_score=120)["ok"]            # enabled=False のまま保存
        os.remove(sh.path)
        s2 = _restart(d)
        assert s2.is_enabled() and _tamper_count(s2, "state_tamper") >= 1


def test_t1_first_start_keeps_today_behaviour():
    """初回起動・設定を一度も保存していない再起動・署名導入前の平文 state の移行・別鍵の
    state を持ち込んだ初回起動は従来どおり(既定=OFF のまま。誤警報を出さない)。"""
    with tempfile.TemporaryDirectory() as d:
        s1 = NetShield(state_dir=d)
        assert not s1.is_enabled() and _tamper_count(s1) == 0
        s2 = _restart(d)                     # マーカーはあるが state.json は一度も保存していない
        assert not s2.is_enabled() and _tamper_count(s2) == 0, s2.metrics()["tamper"]
    with tempfile.TemporaryDirectory() as d:  # 署名導入前の平文 state(マーカー・.hw 無し)
        _write(os.path.join(d, "state.json"),
               json.dumps({"cfg": {"enabled": True, "block_score": 150}}))
        s = _restart(d)
        assert s.is_enabled() and s.cfg["block_score"] == 150 and _tamper_count(s) == 0
        s2 = _restart(d)                     # 移行後(署名済み)の再起動も正常
        assert s2.is_enabled() and s2.cfg["block_score"] == 150 and _tamper_count(s2) == 0
    if os.environ.get("DUCKNET_STATE_KEY"):
        return                               # 共有鍵の環境では『別鍵』を作れない
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        sa = NetShield(state_dir=a)
        sa.enable()
        shutil.copy(os.path.join(a, "state.json"), os.path.join(b, "state.json"))
        sb = _restart(b)                     # 署名実績の無い初回起動=従来どおり(警報+既定)
        assert not sb.is_enabled() and _tamper_count(sb, "state_tamper") >= 1


# ── T2: body_sig_weight_factor ─────────────────────────────────────────────
def test_t2_negative_body_sig_weight_factor_rejected():
    """負の係数を受理していた(0=記録のみ・1 超も可。負値は拒否して現状を保つ)。"""
    k = "body_sig_weight_factor"
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        before = sh.cfg[k]
        for v in (-0.5, -1, -1e-9):
            r = sh.set_config(**{k: v})
            assert k in r.get("rejected", []), (v, r.get("changed"))
            assert sh.cfg[k] == before, v
            r = sh.apply_config({k: v})
            assert k not in r["applied"] and k in r.get("rejected", []), (v, r)
            assert sh.cfg[k] == before, v
        for v in (0, 0.0, 0.25, 1, 2.5):
            assert sh.set_config(**{k: v})["ok"], v
            assert sh.cfg[k] == float(v), v
        assert k in sh.apply_config({k: 0})["applied"] and sh.cfg[k] == 0.0
        # 旧版が保存した負値は 0(記録のみ)として読む(inspect_body の扱い #36 と同じ)
        sh.cfg[k] = -2.0
        sh._save()
        s2 = _restart(d)
        assert s2.cfg[k] == 0.0, s2.cfg[k]
        assert _tamper_count(s2) == 0


# ── T3: 列挙値キー ─────────────────────────────────────────────────────────
_ENUMS = {
    "mode": ("enforce", "audit"),
    "open_redirect_mode": ("enforce", "audit"),
    "site_mode": ("off", "whitelist", "blacklist"),
    "ip_mode": ("off", "whitelist", "blacklist"),
    "geo_mode": ("off", "allow", "block") + (("country_allow", "country_block") if _FULL else ()),
    "cookie_samesite": ("Lax", "Strict", "None", ""),
    "dlp_action": ("audit", "block"),
}
if _FULL:
    _ENUMS["posmodel_mode"] = ("enforce", "audit")


def test_t3_enum_keys_accept_only_known_values():
    """綴り違い('Monitor' 'deny' 等)や他キーの値を ok で受理し、意図と違うモードで動いていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        assert sh.set_config(site_whitelist=["good.example"])["ok"]   # whitelist は空リスト不可
        every = {x for vs in _ENUMS.values() for x in vs}
        for k, allowed in _ENUMS.items():
            for v in allowed:
                for spelled in (v, v.upper(), " %s " % v.lower()):
                    r = sh.set_config(**{k: spelled})
                    assert r["ok"] and not r.get("rejected"), (k, spelled, r.get("error"))
                    assert sh.cfg[k] == v, (k, spelled, sh.cfg[k])
            low = {a.lower() for a in allowed}
            bad = ["deny", "monitor", "whitelisted", "Laxx", 1, True, ["audit"], {"m": "audit"}]
            bad += sorted(x for x in every if x.lower() not in low)       # 他キーの値・空文字
            before = sh.cfg[k]
            for v in bad:
                r = sh.set_config(**{k: v})
                assert k in r.get("rejected", []), (k, v, r.get("changed"))
                assert sh.cfg[k] == before, (k, v)
                r = sh.apply_config({k: v})
                assert k not in r["applied"], (k, v, r)
                assert sh.cfg[k] == before, (k, v)
        if not _FULL:                        # Lite は GeoIP 国判定を持たない
            for v in ("country_allow", "country_block"):
                assert "geo_mode" in sh.set_config(geo_mode=v).get("rejected", []), v


def test_t3_saved_enum_values_still_load():
    """保存済みの正しい値はそのまま読み込む。綴り違いは正規の綴りへ、不正値は既定へ倒す。"""
    want = {"mode": "audit", "open_redirect_mode": "audit", "site_mode": "blacklist",
            "ip_mode": "whitelist", "geo_mode": "block", "cookie_samesite": "Strict",
            "dlp_action": "block"}
    if _FULL:
        want.update(posmodel_mode="audit", geo_mode="country_block")
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        r = sh.set_config(**want)
        assert r["ok"] and not r.get("rejected"), (r.get("rejected"), r.get("error"))
        s2 = _restart(d)
        assert {k: s2.cfg[k] for k in want} == want
        assert _tamper_count(s2) == 0
    with tempfile.TemporaryDirectory() as d:  # 旧版が保存し得た綴り違い・不正値(署名は正しい)
        sh = NetShield(state_dir=d)
        sh.cfg.update({"mode": " Audit ", "site_mode": "BLACKLIST", "cookie_samesite": "strict",
                       "ip_mode": "deny", "geo_mode": "everywhere", "open_redirect_mode": 3})
        sh._save()
        s2 = _restart(d)
        got = {k: s2.cfg[k] for k in ("mode", "site_mode", "cookie_samesite", "ip_mode",
                                      "geo_mode", "open_redirect_mode")}
        assert got == {"mode": "audit", "site_mode": "blacklist", "cookie_samesite": "Strict",
                       "ip_mode": "off", "geo_mode": "off", "open_redirect_mode": "enforce"}, got
    with tempfile.TemporaryDirectory() as d:  # 署名導入前の平文 state(旧来の正しい値)
        _write(os.path.join(d, "state.json"),
               json.dumps({"cfg": {"mode": "audit", "site_mode": "blacklist",
                                   "cookie_samesite": ""}}))
        s = _restart(d)
        assert (s.cfg["mode"], s.cfg["site_mode"], s.cfg["cookie_samesite"]) == \
            ("audit", "blacklist", ""), s.cfg
