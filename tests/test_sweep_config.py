"""
test_sweep_config.py — 設定の入口(set_config / _load / apply_config / sig_add)と
設定変更の排他・内部カウンタ上限の回帰テスト(Lite 版)。
====================================================================================
· /api/shield/config(= set_config)が構造キーを専用バリデータに通さず、NaN/inf も素通しして
  いた。1 回の呼び出しで inspect() が毎回例外(=全断)・レート制限無効化・ダッシュボード
  JSON 破損が起き、しかも永続化されて再起動後も残った。
· カスタムシグネチャの weight=NaN で、触れた IP のスコアが永久に NaN(=BAN されない)。
· set_path_limits が非配列で既存ルールを黙って全消去・apply_config が拒否キーを applied と報告。
· disable() がロック外で cfg を書き、整合チェックが割り込むと変更が巻き戻る。
· cred_rate_limit / resp_error_threshold が内部 deque の上限を超えると永久に発火しない。
"""
import json
import tempfile
import threading
import urllib.error
import urllib.request

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.admin import AdminDashboard
from dataplane.engine.lifeform.pipeline import NetShield


def _shield(d):
    sh = NetShield(state_dir=d)
    sh.enable()
    return sh


def _strict_json(raw: bytes):
    """ブラウザの JSON.parse 相当(NaN/Infinity を受け付けない)でパースする。"""
    def _bad(c):
        raise ValueError("non-standard JSON constant: " + c)
    return json.loads(raw.decode("utf-8"), parse_constant=_bad)


def _post_raw(url, token, raw: bytes):
    r = urllib.request.Request(url, data=raw, method="POST",
                               headers={"Content-Type": "application/json",
                                        "X-Token": token})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _get(url, token):
    r = urllib.request.Request(url, headers={"X-Token": token})
    with urllib.request.urlopen(r, timeout=5) as resp:
        return resp.status, resp.read()


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


# ── #0 / #46: 構造キーが専用バリデータを通らない ──
def test_c0_config_path_limits_strings_do_not_break_inspect():
    """path_limits に文字列の配列を渡すと受理され、以後すべての inspect() が例外で落ちていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_path_limits([{"path": "/login", "rate": 5, "burst": 5}])
        r = sh.set_config(path_limits=["/login"])
        assert "path_limits" not in r["changed"]
        assert sh.cfg["path_limits"] == [{"path": "/login", "rate": 5.0, "burst": 5.0}]
        assert sh.inspect("198.51.100.7", path="/", user_agent="Mozilla/5.0")["action"] == "allow"
        # 再起動後も壊れた値は戻ってこない
        assert NetShield(state_dir=d).cfg["path_limits"] == sh.cfg["path_limits"]


def test_c0_config_list_elements_must_be_strings():
    """blocked_urls / blocked_extensions に dict 要素が入ると inspect() が例外で落ちていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for key in ("blocked_urls", "blocked_extensions"):
            r = sh.set_config(**{key: [{}]})
            assert key not in r["changed"], key
            assert sh.cfg[key] == []
        assert sh.inspect("198.51.100.8", path="/", user_agent="Mozilla/5.0")["action"] == "allow"


def test_c0_persisted_malformed_values_are_not_reloaded():
    """旧版で保存されてしまった壊れた値(署名は正しい)を再起動時にそのまま読み込み、
    起動直後から全リクエストが落ちる状態が続いていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg["path_limits"] = ["/login", {"path": "/api/", "rate": 2}]
        sh.cfg["blocked_urls"] = [{}, "/no-entry"]
        sh.cfg["rate_per_sec"] = float("nan")
        sh._save()                                  # 旧版の set_config が書いたのと同じ状態
        sh2 = NetShield(state_dir=d)
        assert [r["path"] for r in sh2.cfg["path_limits"]] == ["/api/"]
        assert sh2.cfg["blocked_urls"] == ["/no-entry"]       # 正しい要素は残す
        assert sh2.cfg["rate_per_sec"] == 20.0
        assert sh2.inspect("198.51.100.9", path="/", user_agent="Mozilla/5.0")["action"] == "allow"
        assert sh2.inspect("198.51.100.9", path="/no-entry/x")["action"] == "block"


def test_c46_config_blocked_methods_are_normalized():
    """小文字の blocked_methods がそのまま保存され、TRACE が素通りしていた(fail-open)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(blocked_methods=["trace"])
        assert sh.cfg["blocked_methods"] == ["TRACE"]
        assert sh.inspect("198.51.100.10", path="/", method="TRACE")["action"] == "block"


def test_c46_config_path_limits_rate_null_does_not_break_inspect():
    """rate:null のルールが保存され、その prefix への要求がすべて例外で落ちていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(path_limits=[{"path": "/x", "rate": None}])
        assert sh.cfg["path_limits"] == []
        assert sh.inspect("198.51.100.11", path="/x/y")["action"] == "allow"


def test_c46_config_paranoia_matches_dedicated_setter():
    """set_config(paranoia=3) は数値だけ変わり、任意シグネチャが有効化されなかった
    (専用 API / 宣言的設定と食い違う)。範囲外の値もそのまま保存されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(paranoia=3)
        assert sh.cfg["paranoia"] == 3
        assert sh.cfg["optional_sigs"].get("ssrf_internal") is True
        sh.set_config(paranoia=9)
        assert sh.cfg["paranoia"] == 4


# ── #28: NaN / inf ──
def test_c28_config_rejects_non_finite_floats():
    """rate_per_sec=NaN が受理され、トークンバケツが空にならず(レート制限無効化)永続化されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for bad in (float("nan"), float("inf"), float("-inf")):
            r = sh.set_config(rate_per_sec=bad)
            assert "rate_per_sec" not in r["changed"]
            assert r.get("ok") is False and "rate_per_sec" in r.get("rejected", [])
        assert sh.cfg["rate_per_sec"] == 20.0
        assert NetShield(state_dir=d).cfg["rate_per_sec"] == 20.0


def test_c28_config_rejects_int_too_large_for_float():
    """float に変換できない巨大整数(JSON で書ける)を受理すると inspect() が OverflowError で落ちる。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.set_config(burst=10 ** 400)
        assert "burst" not in r["changed"]
        assert sh.inspect("198.51.100.12", path="/")["action"] == "allow"


def test_c28_admin_config_nan_keeps_dashboard_json_valid():
    """管理 API に {"rate_per_sec": NaN} を送ると受理され、/api/state が NaN を含んで
    ブラウザの JSON.parse が失敗(ダッシュボード全体が「接続不可」)していた。"""
    with tempfile.TemporaryDirectory() as d:
        a = _Admin(d)
        try:
            code, body = _post_raw(a.url + "/api/shield/config", a.token,
                                   b'{"rate_per_sec": NaN}')
            assert code == 200
            assert _strict_json(body).get("ok") is False
            _, st = _get(a.url + "/api/state", a.token)
            assert _strict_json(st)["shield"]["cfg"]["rate_per_sec"] == 20.0
        finally:
            a.close()


# ── #27: シグネチャ weight=NaN ──
def test_c27_signature_weight_must_be_finite():
    """weight=NaN のカスタムシグネチャに一度触れた IP はスコアが NaN になり、以後 BAN されなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for bad in (float("nan"), float("inf"), -40, "abc"):
            r = sh.add_signature("probe-sig", r"zzqq\d", weight=bad)
            assert r.get("ok") is False, bad
        assert sh.list_signatures()["custom"] == []
        assert sh.add_signature("probe-sig", r"zzqq\d", weight=30).get("ok") is True


def test_c27_admin_sig_add_nan_weight_rejected():
    """管理 API の sig_add が weight "nan" を受理し、/api/shield/signatures が NaN を返して
    カスタムシグネチャ一覧が描画できなく(=UI から削除もできなく)なっていた。"""
    with tempfile.TemporaryDirectory() as d:
        a = _Admin(d)
        try:
            body = json.dumps({"name": "probe-sig", "pattern": "zzqq[0-9]",
                               "weight": "nan"}).encode()
            code, r = _post_raw(a.url + "/api/shield/sig_add", a.token, body)
            assert code == 200 and _strict_json(r).get("ok") is False
            _, s = _get(a.url + "/api/shield/signatures", a.token)
            assert _strict_json(s)["custom"] == []
        finally:
            a.close()


def test_c27_persisted_nan_weight_signature_is_dropped():
    """旧版で保存された weight=NaN のシグネチャが再起動後も有効で、スコアを NaN にしていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh._custom = [{"name": "bad", "category": "custom", "pattern": r"zzqq\d",
                       "weight": float("nan"), "enabled": True, "source": "user"},
                      {"name": "good", "category": "custom", "pattern": r"yyqq\d",
                       "weight": 30.0, "enabled": True, "source": "user"}]
        sh._save_sigs()
        sh2 = _shield(d)
        # 不正 weight の規則は稼働させないが、黙って消さず無効(active=false)として一覧に残す
        # (det_signatures #55: 旧版は読み捨てて次の保存で rules.json からも消していた)
        listed = {s["name"]: s for s in sh2.list_signatures()["custom"]}
        assert [n for n, s in listed.items() if s["active"]] == ["good"]
        assert listed["bad"]["active"] is False and listed["bad"]["weight"] is None
        json.dumps(sh2.list_signatures(), allow_nan=False)      # UI が読める
        r = sh2.inspect("198.51.100.13", path="/zzqq1")
        assert r["score"] == r["score"]                          # NaN ではない


# ── #47: set_path_limits の全消去 / apply_config の applied 誤報 ──
def test_c47_set_path_limits_non_list_keeps_rules():
    """配列以外(オブジェクト/文字列/None)を渡すと既存ルールが [] に置換され ok:True だった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_path_limits([{"path": "/login", "rate": 0.001, "burst": 1}])
        keep = list(sh.cfg["path_limits"])
        for bad in ({"path": "/login", "rate": 0.001}, "/login", None, ["/login"]):
            r = sh.set_path_limits(bad)
            assert r.get("ok") is False, bad
            assert sh.cfg["path_limits"] == keep, bad
        assert sh.set_path_limits([]).get("ok") is True          # 空配列=明示的な無効化は可
        assert sh.cfg["path_limits"] == []


def test_c47_apply_config_does_not_report_rejected_keys_as_applied():
    """拒否された blocked_methods / path_limits も applied に入り、反映済みと誤報していた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_path_limits([{"path": "/login", "rate": 0.001, "burst": 1}])
        sh.set_blocked_methods(["TRACE"])
        r = sh.apply_config({"path_limits": {"path": "/login", "rate": 0.001},
                             "blocked_methods": 123, "enabled": True})
        assert "path_limits" not in r["applied"]
        assert "blocked_methods" not in r["applied"]
        assert "enabled" in r["applied"]
        assert [x["path"] for x in sh.cfg["path_limits"]] == ["/login"]
        assert sh.cfg["blocked_methods"] == ["TRACE"]


# ── #80 / #83: ロック外の cfg 書換と整合チェックの競合 ──
def _race_integrity_check_inside_save(sh):
    """_save の直前(=cfg は書換済み・MAC は未更新)に、別スレッドの整合チェックが
    ロックを取れるなら割り込ませる。正しくロック下で書いていれば取れずに何もしない。"""
    orig = sh._save
    ran = []

    def checker():
        if sh._lock.acquire(blocking=False):
            try:
                ran.append(sh.verify_cfg_integrity())
            finally:
                sh._lock.release()

    def patched():
        t = threading.Thread(target=checker)
        t.start()
        t.join(5)
        return orig()
    sh._save = patched
    return orig, ran


def test_c80_disable_is_not_reverted_by_concurrent_integrity_check():
    """disable() がロック外で enabled=False を書くため、整合チェックが割り込むと
    「改竄」とみなして enabled=True に戻し、偽の memory_tamper 警報まで出ていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        orig, ran = _race_integrity_check_inside_save(sh)
        try:
            r = sh.disable()
        finally:
            sh._save = orig
        assert r == {"ok": True, "enabled": False}
        assert sh.cfg["enabled"] is False, ran
        assert sh.metrics()["tamper"]["by_kind"].get("memory_tamper", 0) == 0
        assert NetShield(state_dir=d).cfg["enabled"] is False


# ── #86: 内部 deque の上限で閾値が永久に発火しない ──
def test_c86_cred_rate_limit_above_internal_cap_still_fires():
    """cred_rate_limit を 8192 超にすると窓内カウントが 8192 で頭打ちになり、永久に発火しなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(cred_rate_enabled=True, cred_rate_limit=9000)
        assert sh.cfg["cred_rate_limit"] == 9000
        with sh._lock:
            for _ in range(9000):              # 上限 9000 件までは通す(#38: 超えた 9001 件目で遮断)
                sh._credential_rate("tok-busy")
        r = sh.inspect("198.51.100.14", path="/", cred="tok-busy")
        assert r["action"] == "block", r


def test_c86_resp_error_threshold_above_internal_cap_still_fires():
    """resp_error_threshold を 1024 超にすると 4xx の窓内カウントが 1024 で頭打ちになり、
    応答エラー連射の加点が永久に起きなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(resp_error_threshold=2000)
        assert sh.cfg["resp_error_threshold"] == 2000
        last = None
        for _ in range(2000):
            last = sh.note_response("198.51.100.15", 404)
        assert last["action"] != "track", last


def test_c86_count_limit_beyond_supported_range_is_rejected():
    """上限を超える値は黙って『効かない設定』にせず、拒否して現状を保つ。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for key in ("cred_rate_limit", "resp_error_threshold"):
            before = sh.cfg[key]
            r = sh.set_config(**{key: 10 ** 9})
            assert key in r.get("rejected", []), key
            assert sh.cfg[key] == before
