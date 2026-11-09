"""
test_config_bootstrap.py — 宣言的設定ブートストラップ(evolution #27)。
====================================================================================
運用者が宣言した JSON(ファイル/ConfigMap)を全件検証し、一度の保存で起動時に適用する。
構造/段階キー(path_limits/blocked_methods/paranoia)は専用バリデータを共有し、未知キーは拒否。
ファイル読込・不正/欠損の安全な失敗・永続化を回帰から守る。
"""
import json
import os
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def test_apply_config_scalar_and_bool():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        res = sh.apply_config({"enabled": True, "subnet_defense": True,
                               "subnet_threshold": 5, "rate_per_sec": 50})
        assert res["ok"] and set(res["applied"]) >= {"enabled", "subnet_defense",
                                                      "subnet_threshold", "rate_per_sec"}
        assert sh.cfg["enabled"] is True and sh.cfg["subnet_defense"] is True
        assert sh.cfg["subnet_threshold"] == 5 and sh.cfg["rate_per_sec"] == 50.0  # int→float


def test_apply_config_routes_structured_keys_through_validators():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        previous_methods = list(sh.cfg["blocked_methods"])
        previous_paranoia = sh.cfg["paranoia"]
        result = sh.apply_config({
            "path_limits": [{"path": "/login", "rate": 0.5, "burst": 5},
                            {"path": "", "rate": 1}],          # 不正を混ぜた置換は全件拒否
            "blocked_methods": ["trace", "TRACE", "connect"],  # 大文字化+重複除去
            "paranoia": 3})
        assert "path_limits" in result["rejected"]
        assert result["ok"] is False and result["applied"] == []
        assert sh.cfg["path_limits"] == []
        assert sh.cfg["blocked_methods"] == previous_methods
        assert sh.cfg["paranoia"] == previous_paranoia
        assert sh.apply_config({"path_limits": [{"path": "/login", "rate": 0.5,
                                                  "burst": 5}],
                                "blocked_methods": ["trace", "TRACE", "connect"],
                                "paranoia": 3})["ok"]
        assert [r["path"] for r in sh.cfg["path_limits"]] == ["/login"]
        assert sh.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
        assert sh.cfg["paranoia"] == 3 and sh.cfg["optional_sigs"].get("ssrf_internal")


def test_apply_config_rejects_unknown_keys_atomically():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        before = dict(sh.cfg)
        res = sh.apply_config({"enabled": True, "totally_unknown_key": 123})
        assert res["ok"] is False and res["applied"] == []
        assert "totally_unknown_key" in res["rejected"]
        assert sh.cfg == before
        assert "totally_unknown_key" not in sh.cfg


def test_apply_config_rejects_non_dict():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        assert sh.apply_config(["not", "a", "dict"])["ok"] is False


def test_apply_config_file_reads_json_and_persists():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "decl.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"enabled": True, "blocked_methods": ["TRACE"],
                       "path_limits": [{"path": "/api/", "rate": 2}]}, f)
        sh = NetShield(state_dir=tmp)
        res = sh.apply_config_file(cfg_path)
        assert res["ok"] and "enabled" in res["applied"]
        # 別インスタンス(再起動相当)で永続化を確認
        sh2 = NetShield(state_dir=tmp)
        assert sh2.cfg["enabled"] is True and sh2.cfg["blocked_methods"] == ["TRACE"]
        assert [r["path"] for r in sh2.cfg["path_limits"]] == ["/api/"]


def test_apply_config_file_missing_or_invalid_is_safe():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        assert sh.apply_config_file("")["applied"] == []                  # no-op
        assert sh.apply_config_file(os.path.join(tmp, "nope.json"))["ok"] is False
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("{ this is not json ")
        assert sh.apply_config_file(bad)["ok"] is False                   # 落ちない
