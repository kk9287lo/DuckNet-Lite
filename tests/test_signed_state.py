"""
test_signed_state.py — 可変状態ファイルの改竄耐性(HMAC署名・evolution #52)。
====================================================================================
攻撃者がホスト上で blocklist.json を書き換えて自分を unban したり、rules.json を空にして
検知を無効化しても、署名不一致で『改竄』として弾き安全側へフェイルセーフすることを回帰から守る。
旧来の無署名ファイルは生値を使いつつ署名済みへ自動移行する。
"""
import json
import os
import tempfile

from dataplane.engine.core.signed_state import (
    persistent_key, sign_payload, verify_payload, write_signed_json, read_signed_json,
)


def test_persistent_key_env_and_generated():
    with tempfile.TemporaryDirectory() as d:
        os.environ["DUCKNET_STATE_KEY"] = "envkey"
        try:
            assert persistent_key(d) == b"envkey"
        finally:
            del os.environ["DUCKNET_STATE_KEY"]
        k1 = persistent_key(d)                       # 生成+永続
        k2 = persistent_key(d)                       # 同ディレクトリ=同じ鍵(再起動跨ぎ検証可)
        assert k1 == k2 and len(k1) == 32


def test_sign_verify_roundtrip():
    obj = {"bans": {"1.2.3.4": {"until": 999}}}
    sig = sign_payload(obj, b"k")
    assert verify_payload(obj, sig, b"k")
    assert not verify_payload(obj, sig, b"other")    # 鍵違い
    obj2 = {"bans": {"1.2.3.4": {"until": 0}}}        # 攻撃者が unban に書き換え
    assert not verify_payload(obj2, sig, b"k")


def test_write_read_signed_ok():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        payload = {"bans": {"9.9.9.9": {"until": 123}}}
        assert write_signed_json(p, payload, b"k")
        status, val = read_signed_json(p, b"k")
        assert status == "ok" and val == payload


def test_read_detects_tampered_payload():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        write_signed_json(p, {"bans": {"9.9.9.9": {"until": 123}}}, b"k")
        # 攻撃者がエンベロープ内の payload を書き換え(署名はそのまま=持っていない)
        with open(p, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"] = {"bans": {}}               # 全 unban を狙う
        with open(p, "w", encoding="utf-8") as f:
            json.dump(env, f)
        status, val = read_signed_json(p, b"k", default="SAFE")
        assert status == "tampered" and val == "SAFE"   # 改竄→フェイルセーフ


def test_read_legacy_unsigned():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "rules.json")
        with open(p, "w", encoding="utf-8") as f:     # 旧来の無署名プレーン
            json.dump({"signatures": [{"pattern": "x"}]}, f)
        status, val = read_signed_json(p, b"k")
        assert status == "unsigned" and val["signatures"][0]["pattern"] == "x"


def test_read_missing():
    with tempfile.TemporaryDirectory() as d:
        status, val = read_signed_json(os.path.join(d, "nope.json"), b"k", default={})
        assert status == "missing" and val == {}


# ── NetShield 統合 ──────────────────────────────────────────────────────
def _fresh_shield(d):
    from dataplane.engine.lifeform.pipeline import NetShield
    sh = NetShield(state_dir=d)
    sh.cfg["persist_bans"] = True
    return sh


def test_netshield_saved_bans_are_signed_and_reload_ok():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.ban("203.0.113.7", permanent=True)
        sh._save_bans()
        with open(sh._bans_path, encoding="utf-8") as f:
            env = json.load(f)
        assert "_sig" in env and "_payload" in env    # 署名エンベロープ
        # 新インスタンス(再起動相当)が同じ鍵で検証して BAN を復元
        sh2 = _fresh_shield(d)
        sh2._load_bans()
        assert sh2.is_banned_fast("203.0.113.7")


def test_netshield_rejects_tampered_blocklist():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.ban("203.0.113.7", permanent=True)         # 正規BAN
        sh._save_bans()
        # 攻撃者が blocklist を改竄: 自分(攻撃者IP)を BAN から外し、被害者IPを注入
        with open(sh._bans_path, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"]["bans"] = {"10.0.0.5": {"until": None, "permanent": True,
                                                 "started": 0, "count": 1}}
        with open(sh._bans_path, "w", encoding="utf-8") as f:
            json.dump(env, f)
        # 再起動相当: 署名不一致でフェイルセーフ=改竄 blocklist を一切信頼しない
        sh2 = _fresh_shield(d)
        sh2._load_bans()
        assert not sh2.is_banned_fast("10.0.0.5")     # 注入された偽BANを採用しない
        assert not sh2.is_banned_fast("203.0.113.7")  # 改竄ファイルは丸ごと破棄(安全側)


def test_netshield_migrates_legacy_unsigned_bans():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        # 旧来の無署名 blocklist を直接設置
        with open(sh._bans_path, "w", encoding="utf-8") as f:
            json.dump({"bans": {"203.0.113.7": {"until": None, "permanent": True,
                                                "started": 0, "count": 1}}}, f)
        sh._load_bans()                               # 無署名→使用しつつ署名済みへ移行
        assert sh.is_banned_fast("203.0.113.7")
        with open(sh._bans_path, encoding="utf-8") as f:
            assert "_sig" in json.load(f)             # 移行後は署名済み


def test_netshield_rejects_plaintext_swap_after_signing():
    # #53: 署名運用が始まった後(マーカー有)に攻撃者が *平文ファイルで丸ごとすり替え* ても、
    #   無署名出現=改竄として弾く(移行受理は初回/レガシーのみ)。
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.ban("203.0.113.7", permanent=True)
        sh._save_bans()                               # 署名保存(マーカーは init で既設)
        # 攻撃者が署名エンベロープごと捨てて平文 blocklist を設置(自分仕様のBAN)
        with open(sh._bans_path, "w", encoding="utf-8") as f:
            json.dump({"bans": {"10.0.0.5": {"until": None, "permanent": True,
                                             "started": 0, "count": 1}}}, f)
        sh2 = _fresh_shield(d)                         # マーカー有=signed_before True
        sh2._load_bans()
        assert not sh2.is_banned_fast("10.0.0.5")     # 平文すり替えを信頼しない
        assert not sh2.is_banned_fast("203.0.113.7")


def test_netshield_traffic_signed_and_tamper_rejected():
    # traffic.json(DLP egress クォータの素)も署名。改竄で攻撃者のegress計上をリセットさせない。
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.record_traffic("198.51.100.9", out_bytes=5_000_000, in_bytes=1000, conn_sec=2.0)
        sh._save_traffic(force=True)
        with open(sh._traffic_path, encoding="utf-8") as f:
            assert "_sig" in json.load(f)             # 署名済み
        # 改竄: payload を空に(攻撃者が自分の集計を消す)
        with open(sh._traffic_path, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"]["traffic"] = {}
        with open(sh._traffic_path, "w", encoding="utf-8") as f:
            json.dump(env, f)
        sh2 = _fresh_shield(d)                         # 署名不一致→空(安全側)で起動・警報
        assert sh2._traffic == {}


def test_tamper_is_visualized_and_forwarded():
    # #55: 改竄検知が metrics.tamper / tamper_report に出る(ダッシュボードでの可視化)。
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.report_tamper("state_tamper", "bans", "fail-safe(default)",
                         {"file": "blocklist.json"})
        sh.report_tamper("memory_tamper", "cfg", "restored-from-disk")
        m = sh.metrics()["tamper"]
        assert m["count"] == 2
        assert m["by_kind"]["state_tamper"] == 1 and m["by_kind"]["memory_tamper"] == 1
        assert m["last"]["kind"] == "memory_tamper"
        rep = sh.tamper_report()
        assert rep["summary"]["count"] == 2
        kinds = {e["kind"] for e in rep["events"]}
        assert {"state_tamper", "memory_tamper"} <= kinds


def test_netshield_rejects_tampered_config():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh._save()
        base_score = sh.cfg["flood_threshold"]
        # 攻撃者が state.json を改竄: flood_threshold を巨大化して flood 検知を実質無効化
        with open(sh.path, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"]["cfg"]["flood_threshold"] = 10 ** 9
        with open(sh.path, "w", encoding="utf-8") as f:
            json.dump(env, f)
        sh2 = _fresh_shield(d)
        sh2._load()
        assert sh2.cfg["flood_threshold"] == base_score   # 改竄設定を採らず既定を維持


# ── ロールバック攻撃対策(#102): 古い正署名ファイルへの巻き戻しを拒否 ──
def test_rollback_old_signed_file_rejected():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        # v1: 攻撃者IPが BAN されている最新状態
        write_signed_json(p, {"bans": {"6.6.6.6": {"until": 9999}}}, b"k")
        with open(p, encoding="utf-8") as f:
            old_env = json.load(f)                  # 攻撃者がこの『正署名の現行』を退避…ではなく
        # v2: さらに更新(版が前進)
        write_signed_json(p, {"bans": {"6.6.6.6": {"until": 9999}, "7.7.7.7": {"until": 1}}}, b"k")
        s2, _ = read_signed_json(p, b"k")
        assert s2 == "ok"
        # 攻撃者が『古い正署名ファイル(v1)』で上書き=自分の BAN が無い頃へ巻き戻し
        with open(p, "w", encoding="utf-8") as f:
            json.dump(old_env, f)
        status, val = read_signed_json(p, b"k", default="SAFE")
        assert status == "rolled_back" and val == "SAFE"   # 署名は正しいが版後退=拒否


def test_legacy_unversioned_envelope_still_ok():
    # 旧 _sv:1(バージョン無し)エンベロープは後方互換で読める。
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.json")
        payload = {"a": 1}
        env = {"_sv": 1, "_sig": sign_payload(payload, b"k"), "_payload": payload}
        with open(p, "w", encoding="utf-8") as f:
            json.dump(env, f)
        status, val = read_signed_json(p, b"k")
        assert status == "ok" and val == payload


def test_version_monotonic_increases():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "y.json")
        write_signed_json(p, {"n": 1}, b"k")
        v1 = json.load(open(p, encoding="utf-8"))["_ver"]
        write_signed_json(p, {"n": 2}, b"k")
        v2 = json.load(open(p, encoding="utf-8"))["_ver"]
        assert v2 > v1                              # 版は必ず前進
