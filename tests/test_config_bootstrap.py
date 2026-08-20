"""
test_config_bootstrap.py — 宣言的設定ブートストラップ(evolution #27)。
====================================================================================
運用者が宣言した JSON(ファイル/ConfigMap)を起動時に既存の検証済みセッター経由で適用する。
スカラ/bool は set_config(型一致)、構造/段階キー(path_limits/blocked_methods/paranoia)は専用
バリデータ、未知キーは無視。ファイル読込・不正/欠損の安全な失敗・永続化を回帰から守る。
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
        sh.apply_config({
            "path_limits": [{"path": "/login", "rate": 0.5, "burst": 5},
                            {"path": "", "rate": 1}],          # 空 path は検証で除去
            "blocked_methods": ["trace", "TRACE", "connect"],  # 大文字化+重複除去
            "paranoia": 3})
        assert [r["path"] for r in sh.cfg["path_limits"]] == ["/login"]
        assert sh.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
        assert sh.cfg["paranoia"] == 3 and sh.cfg["optional_sigs"].get("ssrf_internal")


def test_apply_config_ignores_unknown_keys():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        res = sh.apply_config({"enabled": True, "totally_unknown_key": 123})
        assert "totally_unknown_key" not in res["applied"]
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
