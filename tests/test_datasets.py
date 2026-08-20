"""
test_datasets.py — 本命囮のハニーファイル生成 + 参照トークン台帳追跡(evolution #9)
====================================================================================
大容量の『本物に見える』囮データをストリーム生成(保存しない)し、各ファイルに仕込んだ
参照トークン台帳・トークンで持ち出し(exfil)と外部での開封(trigger)を記録できることを検証する。
"""
import os
import tempfile

from dataplane.engine.lifeform import datasets as H


def test_manifest_size_options_and_reshuffle():
    m = H.build_manifest(200 * 1024, seed=1)
    assert sum(f["size"] for f in m) == 200 * 1024          # 合計が指定サイズ丁度
    assert {f["protected"] for f in m} == {True, False}     # 保護/未保護が混在
    assert all(f["token"].startswith("fnct_") for f in m)   # 各ファイルに一意トークン
    assert all(any(f["path"].startswith(p) for p in H._PLACES) for f in m)  # 本物風の設置場所
    # 既定名 vs ランダム名
    default = H.build_manifest(50000, seed=2)
    rand = H.build_manifest(50000, randomize_names=True, seed=2)
    assert any(f["name"].endswith(".csv") for f in default)
    assert [f["name"] for f in default] != [f["name"] for f in rand]
    # 同 seed で設置場所が再現(ランダムに組み直せるが決定論)
    assert ([f["path"] for f in H.build_manifest(9999, seed=7)]
            == [f["path"] for f in H.build_manifest(9999, seed=7)])


def test_streamed_content_is_realistic_with_token():
    m = H.build_manifest(120 * 1024, seed=3)
    csv = next(f for f in m if f["kind"] == "csv")
    data = b"".join(H.iter_content(csv, chunk=8192))
    assert len(data) == csv["size"]                          # ストリームが指定サイズに一致
    assert csv["token"].encode() in data[:300]               # トークンが先頭付近
    assert b"@corp.local" in data                            # 本物そっくりの構造化データ
    sql = next(f for f in m if f["kind"] == "sql")
    assert b"INSERT INTO users" in b"".join(H.iter_content(sql, chunk=4096))
    vault = next(f for f in m if f["kind"] == "vault")       # 高エントロピー(暗号化に見える)
    assert len(b"".join(H.iter_content(vault, chunk=4096))) == vault["size"]


def test_token_url_base_absolute_when_env_set():
    m = H.build_manifest(40000, seed=4)
    csv = next(f for f in m if f["kind"] == "csv")
    os.environ["CHICKENNET_TOKEN_URL"] = "https://cdn.corp.example"
    try:
        head = b"".join(H.iter_content(csv, chunk=4096))[:300]
        assert b"https://cdn.corp.example/c/" + csv["token"].encode() in head
    finally:
        os.environ.pop("CHICKENNET_TOKEN_URL", None)


def test_canary_records_exfil_and_trigger():
    m = H.build_manifest(60000, seed=5)
    csv = next(f for f in m if f["kind"] == "csv")
    with tempfile.TemporaryDirectory() as tmp:
        cb = H.TokenLedger(state_dir=tmp)
        cb.register(m)
        cb.record_pull("45.146.0.3", csv)                     # 持ち出し
        r = cb.record_hit(csv["token"], "203.0.113.9", ua="python-requests/2.31")  # 外部で開封
        assert r.get("action") == "alert"
        met = cb.status()["metrics"]
        assert met.get("pull") == 1 and met.get("hit") == 1
        # 既知トークンは『どのファイルが』を辿れる(高度な分析)
        rec = [e for e in cb.log() if e.get("token") == csv["token"]]
        assert rec and rec[-1]["file"]["name"] == csv["name"] and rec[-1]["known"] is True


def test_token_ledger_singleton():
    assert H.token_ledger() is H.token_ledger()
