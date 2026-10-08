"""
test_sweep_r2_misc.py — 掃討 2 巡目(r2_misc)の回帰: オリジントークン比較・使用量ログの
孤立サロゲート・管理 API の非標準 JSON・承認待ち解決の既定。
====================================================================================
各テストは「修正前のコードで落ちる」ことを確かめてある(完全性検査の終了コードは Full のみ)。
"""
import json
import tempfile


def _strict_json(raw: bytes):
    """ブラウザの JSON.parse 相当の厳格な解析。NaN/Infinity(Python は既定で受理する)と
    不正な UTF-8 を拒否する。"""
    def _bad(c):
        raise ValueError("non-standard JSON constant: " + c)
    return json.loads(raw.decode("utf-8"), parse_constant=_bad)


# ── T1: オリジントークンの比較が非 ASCII で TypeError ─────────────────────────
def test_r2_origin_token_non_ascii_is_rejected_not_typeerror():
    """ヘッダ値は latin-1 で復号されるので X-Edge-Token に é 等が来得る。hmac.compare_digest は
    非 ASCII の str で TypeError を投げ、バックエンドの検証が『拒否(False)』ではなく例外で
    落ちていた(呼び出し側の例外処理次第では 500 や素通しに化ける)。"""
    from dataplane.engine.core.origin import origin_token, verify_origin_token
    tok = origin_token("k", now=1000.0, window=30.0)
    for bad in ("é", tok[:-1] + "é", tok + "ÿ", "a'b<cé"):
        assert verify_origin_token(bad, "k", now=1000.0, window=30.0) is False, bad
    assert verify_origin_token(tok, "k", now=1000.0, window=30.0) is True   # 正規は従来どおり


def test_r2_origin_token_accepts_raw_header_bytes():
    """ASGI 等は生ヘッダを bytes で渡す。str(b"..") は "b'..'" になり、正しいトークンでも
    常に不一致=正規のエッジ経由トラフィックを全部拒否していた。非 ASCII の bytes は不一致。"""
    from dataplane.engine.core.origin import origin_token, verify_origin_token
    tok = origin_token("k", now=1000.0, window=30.0)
    assert verify_origin_token(tok.encode("ascii"), "k", now=1000.0, window=30.0) is True
    assert verify_origin_token(bytearray(tok.encode("ascii")), "k", now=1000.0,
                               window=30.0) is True
    assert verify_origin_token(b"\xe9" + tok.encode("ascii")[1:], "k", now=1000.0,
                               window=30.0) is False
    assert verify_origin_token(b"", "k", now=1000.0, window=30.0) is False


# ── T2: 使用量ログ(usage_log.jsonl)が孤立サロゲートで 1 行丸ごと消える ───────────
def test_r2_usage_log_keeps_line_with_lone_surrogate():
    """_open_state_write は厳格な UTF-8 で開いていたため、host/path に孤立サロゲート
    ('\\udc80' 等。surrogateescape 復号や JSON の \\udXXX から入る)が 1 文字あるだけで
    UnicodeEncodeError になり、その接続の記録が黙って捨てられていた(ログ回避)。"""
    from dataplane.engine.lifeform.pipeline import NetShield
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["usage_record"] = True
        sh.cfg["persist_bans"] = False
        path = "/a'b<c\udc80"
        sh.record_traffic("192.0.2.20", out_bytes=10, in_bytes=5, conn_sec=0.1,
                          host="example.test", method="GET", path=path)
        rows = sh.usage_log(10)
        assert len(rows) == 1, rows
        assert rows[0]["ip"] == "192.0.2.20" and rows[0]["path"] == path, rows[0]
        with open(sh._usage_log_path, "rb") as f:
            f.read().decode("utf-8")        # ファイル自体は正しい UTF-8 のまま


# ── T3: 管理 API の JSON に NaN/Infinity が出てダッシュボード全体が「切断」になる ──
def test_r2_admin_json_never_emits_nan_or_infinity():
    """json.dumps は既定で NaN/Infinity を出すが、ブラウザの JSON.parse はそれを拒否する。
    状態のどこか 1 つに非有限の float が入るだけで /api/state 等の応答全体が解析不能になり、
    ダッシュボードが『切断』表示のまま戻らなかった。非有限は null にする(再帰)。"""
    from dataplane.admin import _j
    nan, inf = float("nan"), float("inf")
    obj = {"a": nan, "b": [1.5, inf, {"c": -inf}], "t": (nan, 2), "ok": 2.5,
           "n": None, "s": "a'b<c", nan: 1}
    got = _strict_json(_j(obj))
    assert got["a"] is None and got["b"] == [1.5, None, {"c": None}], got
    assert got["t"] == [None, 2] and got["ok"] == 2.5 and got["s"] == "a'b<c", got
    assert got["NaN"] == 1, got             # 非有限のキーは従来どおり文字列 "NaN"
    # 有限値だけなら従来の出力と同一(速い経路)
    plain = {"x": [1, 2.5, "é"], "y": {"z": None}}
    assert _j(plain) == json.dumps(plain, ensure_ascii=False).encode("utf-8")


def test_r2_admin_json_lone_surrogate_does_not_break_response():
    """管理 API の本文は json.loads で読むため "\\udc80" の値(署名名・メモ等)が入り得る。
    _j は ensure_ascii=False の結果を厳格 UTF-8 で encode しており、その値を含む状態の
    応答が毎回 UnicodeEncodeError=500 になった。JSON の \\udXXX エスケープで出す。"""
    from dataplane.admin import _j
    v = "a'b<c\udc80"
    got = _strict_json(_j({"note": v, "list": [v]}))
    assert got == {"note": v, "list": [v]}, got


# ── T4: 承認待ちの解決は既定で恒久ルールを書かない ─────────────────────────────
def test_r2_pending_resolve_defaults_to_one_off():
    """AppFirewall.approve()/deny_pending() は remember の既定が True で、remember を渡し
    忘れた呼び出し 1 回が /32 の恒久 allow/deny を acl.json へ黙って積んだ(#111 の原則
    『クリック 1 回で恒久ルールを黙って書かない』に反する)。既定は一時、恒久化は明示のみ。"""
    from dataplane.engine.lifeform.policy import AppFirewall, _zone_of
    with tempfile.TemporaryDirectory() as d:
        fw = AppFirewall(state_dir=d)
        fw.enable()
        ips = ["192.0.2.31", "192.0.2.32", "192.0.2.33"]
        for ip in ips:
            fw.set_policy(_zone_of(ip), "prompt")
        pids = [fw.evaluate(ip)["pending_id"] for ip in ips]
        assert all(pids), pids
        r1 = fw.approve(pids[0])
        r2 = fw.deny_pending(pids[1])
        assert r1["ok"] and r1["remembered"] is False, r1
        assert r2["ok"] and r2["remembered"] is False, r2
        assert fw.rules == [], fw.rules
        assert AppFirewall(state_dir=d).rules == []          # acl.json にも書かれていない
        r3 = fw.deny_pending(pids[2], remember=True)          # 明示すれば従来どおり恒久化
        assert r3["remembered"] is True
        assert [r["net"] for r in fw.rules] == ["192.0.2.33/32"], fw.rules
