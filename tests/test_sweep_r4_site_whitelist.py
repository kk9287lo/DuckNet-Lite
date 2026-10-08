"""
test_sweep_r4_site_whitelist.py — site_mode=whitelist と空の site_whitelist(#85 の製品判断・Lite 版)。
====================================================================================
site_mode="whitelist" で site_whitelist が空だと、_site_block は許可リストを評価せず *全 Host を
許可* していた(fail-open。ip_mode / geo_mode の許可リストは空=全遮断)。製品判断として:
· 結果が「whitelist + 空リスト」になる設定変更は、入口(/api/shield/config=set_config・
  edit_list・宣言的設定 apply_config)を問わず拒否する(ok:False・何も適用しない)。
· ディスクに保存済みの whitelist + 空 は従来どおり全許可のまま(更新で誰も締め出さない)。
  代わりに status の warnings と、起動時 1 回だけの system イベントで知らせる。
"""
import json
import os
import tempfile
import urllib.error
import urllib.request

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.admin import AdminDashboard
from dataplane.engine.lifeform.pipeline import NetShield

_WARN = "site_whitelist_empty"


def _shield(d):
    sh = NetShield(state_dir=d)
    sh.enable()
    if "auto_under_attack" in sh.cfg:   # Lite には無い(Full と同じテストを流用)
        sh.cfg["auto_under_attack"] = False
    return sh


def _act(sh, ip, host):
    return sh.inspect(ip, path="/", host=host)["action"]


def _brief(r):
    """失敗表示用に cfg 全体(長大)を落とした応答。"""
    return {k: v for k, v in (r or {}).items() if k != "cfg"}


def _legacy_state(d):
    """旧版が保存し得た whitelist + 空リストの state を作る(検証を通さず直接書いて署名保存)。"""
    sh = _shield(d)
    with sh._lock:
        sh.cfg["site_mode"] = "whitelist"
        sh.cfg["site_whitelist"] = []
        sh._save()


def _warn_events(sh):
    return [e for e in sh.events(200) if e.get("kind") == _WARN]


def _post(url, token, body: dict):
    r = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                               headers={"Content-Type": "application/json",
                                        "X-Token": token})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, _brief(json.loads(resp.read().decode("utf-8")))
    except urllib.error.HTTPError as e:
        return e.code, {}


def _get(url, token):
    r = urllib.request.Request(url, headers={"X-Token": token})
    with urllib.request.urlopen(r, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


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


def test_r4_site_whitelist_switch_to_whitelist_with_empty_list_rejected():
    """リストが空のまま site_mode=whitelist にすると ok:True で受理され、全 Host が素通しになっていた。
    同じ呼び出しの他キーも含め何も適用せず、保存もしない。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for kw in ({"site_mode": "whitelist"},
                   {"site_mode": "whitelist", "site_whitelist": []},
                   {"site_mode": "whitelist", "site_whitelist": ["  ", ""]},   # 空白だけ=空
                   {"site_mode": "whitelist", "rate_per_sec": 33}):
            r = _brief(sh.set_config(**kw))
            assert r.get("ok") is False, (kw, r)
            assert r.get("changed") == {}, (kw, r)
            assert "site_whitelist" in (r.get("error") or ""), (kw, r)
            assert "site_mode" in (r.get("rejected") or []), (kw, r)
        assert sh.cfg["site_mode"] == "off" and sh.cfg["rate_per_sec"] == 20.0
        assert _act(sh, "192.0.2.1", "evil.example") == "allow"       # off のまま=従来どおり
        sh2 = NetShield(state_dir=d)
        assert sh2.cfg["site_mode"] == "off" and sh2.cfg["rate_per_sec"] == 20.0


def test_r4_site_whitelist_emptying_list_in_whitelist_mode_rejected():
    """whitelist 運用中に site_whitelist=[] を受理し、以後 全 Host が素通しになっていた。
    非空リストと whitelist の同時指定(1 回の呼び出し)は受理する。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = _brief(sh.set_config(site_mode="whitelist", site_whitelist=["good.example"]))
        assert r.get("ok") is True, r
        assert set(r["changed"]) == {"site_mode", "site_whitelist"}, r
        r = _brief(sh.set_config(site_whitelist=[]))
        assert r.get("ok") is False and r.get("changed") == {}, r
        assert sh.cfg["site_whitelist"] == ["good.example"]
        assert _act(sh, "192.0.2.2", "good.example") == "allow"
        assert _act(sh, "192.0.2.3", "evil.example") == "block"
        assert NetShield(state_dir=d).cfg["site_whitelist"] == ["good.example"]
        # モードを外すのと同時なら空にしてよい(結果が whitelist+空 ではない)
        r = _brief(sh.set_config(site_mode="off", site_whitelist=[]))
        assert r.get("ok") is True, r
        assert sh.cfg["site_mode"] == "off" and sh.cfg["site_whitelist"] == []


def test_r4_site_whitelist_edit_list_cannot_empty_in_whitelist_mode():
    """edit_list の clear / 最後の 1 件の remove / set [] が whitelist 運用中でも ok:True で通り、
    全 Host 許可へ落ちていた(set_config の結果も見ていなかった)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(site_mode="whitelist", site_whitelist=["good.example"])
        for op, ents in (("clear", None), ("remove", ["good.example"]), ("set", []),
                         ("set", ["   "])):
            r = sh.edit_list("domain", "white", op, ents)
            assert r.get("ok") is False and r.get("error"), (op, r)
            assert sh.cfg["site_whitelist"] == ["good.example"], (op, sh.cfg["site_whitelist"])
        assert _act(sh, "192.0.2.4", "evil.example") == "block"
        # 1 件でも残るなら削除できる / モードを外せば空にできる
        assert sh.edit_list("domain", "white", "add", ["b.example"])["ok"] is True
        assert sh.edit_list("domain", "white", "remove", ["good.example"])["ok"] is True
        assert sh.cfg["site_whitelist"] == ["b.example"]
        assert sh.set_config(site_mode="off")["ok"] is True
        assert sh.edit_list("domain", "white", "clear")["ok"] is True
        assert sh.cfg["site_whitelist"] == []


def test_r4_site_whitelist_bootstrap_rejects_empty_whitelist():
    """宣言的設定に site_mode=whitelist だけ書く(リスト無し)と applied に入り、全 Host 許可で
    起動していた。他のキーは従来どおり適用し、site 系だけを拒否キーとして報告する。"""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "decl.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"site_mode": "whitelist", "rate_per_sec": 30}, f)
        sh = _shield(d)
        res = sh.apply_config_file(p)
        assert res.get("ok") is True, res
        assert "site_mode" not in res["applied"] and "rate_per_sec" in res["applied"], res
        assert "site_mode" in (res.get("rejected") or []), res
        assert sh.cfg["site_mode"] == "off" and sh.cfg["rate_per_sec"] == 30.0
        # whitelist 運用中に空リストを宣言しても同じ(他キーは適用)
        assert sh.set_config(site_mode="whitelist", site_whitelist=["good.example"])["ok"]
        res = sh.apply_config({"site_whitelist": [], "burst": 50})
        assert "site_whitelist" in (res.get("rejected") or []), res
        assert "burst" in res["applied"] and "site_whitelist" not in res["applied"], res
        assert sh.cfg["site_whitelist"] == ["good.example"] and sh.cfg["burst"] == 50
        # 非空リストとの同時宣言は受理
        sh2 = _shield(tempfile.mkdtemp(dir=d))
        res = sh2.apply_config({"site_mode": "whitelist", "site_whitelist": ["a.example"]})
        assert set(res["applied"]) >= {"site_mode", "site_whitelist"}, res
        assert not res.get("rejected"), res


def test_r4_site_whitelist_saved_empty_whitelist_keeps_allow_and_warns():
    """保存済みの whitelist+空 は従来どおり全許可(更新で締め出さない)。代わりに status の
    warnings と、起動時 1 回だけの system イベントで知らせる。"""
    with tempfile.TemporaryDirectory() as d:
        _legacy_state(d)
        sh = NetShield(state_dir=d)
        assert sh.cfg["site_mode"] == "whitelist" and sh.cfg["site_whitelist"] == []
        assert _act(sh, "192.0.2.20", "evil.example") == "allow"      # 挙動は据え置き
        w = sh.status().get("warnings")
        assert isinstance(w, list) and [x.get("code") for x in w] == [_WARN], w
        assert w[0].get("message"), w
        assert len(_warn_events(sh)) == 1, sh.events(200)
        sh.status()
        sh.verify_cfg_integrity()
        assert len(_warn_events(sh)) == 1, sh.events(200)               # 起動時 1 回だけ
        # 既存の誤設定が無関係な設定変更を巻き込まない
        assert sh.set_config(rate_per_sec=25)["ok"] is True
        assert sh.cfg["site_mode"] == "whitelist" and sh.cfg["rate_per_sec"] == 25.0
        # 直せば警告は消える
        assert sh.set_config(site_mode="off")["ok"] is True
        assert sh.status()["warnings"] == []
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.status().get("warnings") == []                      # 既定では警告なし
        assert not _warn_events(NetShield(state_dir=d))


def test_r4_site_whitelist_admin_api_rejects_and_state_shows_warning():
    """管理 API(/api/shield/config)でも拒否し、保存済み whitelist+空 は /api/state の
    shield.warnings に出す。"""
    with tempfile.TemporaryDirectory() as d:
        _legacy_state(d)
        a = _Admin(d)
        try:
            st = _get(a.url + "/api/state", a.token)
            codes = [x.get("code") for x in st["shield"].get("warnings") or []]
            assert codes == [_WARN], st["shield"].get("warnings")
            for body in ({"site_whitelist": []}, {"site_mode": "whitelist"}):
                code, r = _post(a.url + "/api/shield/config", a.token, body)
                assert code == 200 and r.get("ok") is False and r.get("error"), (body, r)
            code, r = _post(a.url + "/api/shield/config", a.token,
                            {"site_whitelist": ["good.example"]})
            assert code == 200 and r.get("ok") is True, r
            st = _get(a.url + "/api/state", a.token)
            assert st["shield"].get("warnings") == [], st["shield"].get("warnings")
        finally:
            a.close()
