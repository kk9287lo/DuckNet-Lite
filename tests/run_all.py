"""tests/run_all.py — DuckNet-Lite 全テスト(依存ゼロ・pytest不要)。

実行:
    python tests/run_all.py        # リポジトリ直下から
外部リポジトリには依存しない(バンドル内の vendored サブセットのみを使う)。
"""
from __future__ import annotations

import importlib
import os
import sys
import traceback
from unittest import SkipTest     # 環境依存テストの明示スキップ(標準ライブラリのみ)


def _force_utf8_stdio() -> None:
    """ランナー自身の出力を UTF-8 かつ行バッファへ(失敗しても無害に継続)。

    SKIP/FAIL の説明文は日本語なので、非 UTF-8 コンソール(英語版 Windows の cp1252
    や ASCII ロケール)では print した瞬間に UnicodeEncodeError で落ちる。しかも
    落ちる場所が結果表示なので、**要約行すら出ないまま exit 1** になり、
    「何が失敗したのか分からない」という最悪の壊れ方をする(実際 CI の
    windows-latest がこれで落ちていた)。
    製品側(dataplane.service)にも同じ処理があるが、ランナーは製品が壊れていても
    動けるべきなので import せずここで完結させる。"""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if reconfig is None:
            continue
        try:
            reconfig(encoding="utf-8", errors="backslashreplace", line_buffering=True)
        except Exception:
            try:
                reconfig(encoding="utf-8", errors="backslashreplace")
            except Exception:
                pass


_force_utf8_stdio()

def _isolate_state_dir() -> str:
    """テストが **利用者の本物の状態ディレクトリ**(~/.cache/dataplane)に一切触れないよう、
    使い捨ての一時ディレクトリへ向ける。製品コードを import する *前* に行うこと。

    以前はこれが無く、テストを回すたびに実際の DuckNet の BAN リスト・管理監査ログ・
    使用量・ACL へ書き込んでいた(実測: 127.0.0.1 の BAN が実 blocklist.json へ入り、
    実 admin_audit.jsonl にはテストの操作が 1449 行溜まっていた)。さらに、そこに残った
    状態(acl.json の有効化)を次の実行が読み込み、テスト 3 件が決定的に落ちる、という
    *自己汚染* にもなっていた。この機で製品を実際に使っている利用者ほど壊れる。
    DUCKNET_KEEP_TEST_STATE=1 なら終了後も消さずに場所を表示する(調査用)。"""
    import atexit
    import shutil
    import tempfile
    d = tempfile.mkdtemp(prefix="ducknet-test-state-")
    os.environ["DUCKNET_STATE_DIR"] = d
    if os.environ.get("DUCKNET_KEEP_TEST_STATE") == "1":
        atexit.register(lambda: print("test state kept at: " + d))
    else:
        atexit.register(shutil.rmtree, d, True)
    return d


_TEST_STATE_DIR = _isolate_state_dir()

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)   # dataplane / dataplane.engine を import 可能に
sys.path.insert(0, _HERE)   # test_*.py を import 可能に
os.environ.setdefault("DUCKNET_OFFLINE", "1")

MODULES = [
    "test_core",                # 管理ダッシュボード制御API
    "test_logio",               # 追記ログのローテーション(肥大防止)
    "test_banner",              # 動的デセプション(偽Serverバナーで指紋攪乱)
    "test_hardening",           # ReDoS/脆弱性・未知攻撃ファズ・資源境界・ホットパス健全性
    "test_secheaders",          # 応答セキュリティヘッダ注入
    "test_paranoia",            # 検知の段階的厳格度(paranoia レベル)
    "test_health",              # データプレーンのヘルスチェック(LB/オーケストレータ用)
    "test_bans",                # 累犯BANエスカレーション(常習攻撃者を重く罰する)
    "test_shutdown",            # SIGTERM graceful shutdown(コンテナ/k8s の停止に応答)
    "test_pathrate",            # パス別レート制限(認証/高コスト経路を構造的に厳格化)
    "test_throttle",            # レート超過応答(HTTP 429 + Retry-After)
    "test_subnet",              # サブネット集約防御(分散攻撃を /24・/64 で束ねて捉える)
    "test_method",              # HTTPメソッドポリシー(XST/プロキシ濫用メソッドを遮断)
    "test_config_bootstrap",    # 宣言的設定ブートストラップ(JSON/ConfigMap を起動時適用)
    "test_connlimit",           # per-IP 同時接続上限(接続枯渇/slowloris 増幅対策)
    "test_keepalive",           # keep-alive 越しの検査回避を封じる(Connection: close 強制)
    "test_realip",              # 信頼proxy背後の実クライアントIP解決(XFF・既定は信頼しない)
    "test_signed_state",        # 自己防衛: 可変状態ファイルの HMAC 署名による改竄耐性
    "test_autostart",           # 自己防衛: 起動時自動起動の登録(透明・公認の場所のみ)
    "test_respscore",           # 応答アウェア脅威スコア(4xx連射=列挙/ブルートフォース検知)
    "test_bodyscan",            # 要求ボディ検査(POST/JSON 本文の SQLi/XSS/RCE/SSTI=head死角)
    "test_botconsistency",      # ヘッダ整合性ボット検知(UA偽装ツールを低FP加点)
    "test_slowbody",            # スロー POST(R-U-Dead-Yet)対策(ボディ総受信時間に上限)
    "test_cookieharden",        # Set-Cookie ハードニング(SameSite/Secure/HttpOnly 補完)
    "test_upload",              # ファイルアップロード検査(危険拡張子=webshell 投入対策)
    "test_graphql",             # GraphQL クエリ防御(深さ/複雑度/イントロスペクション/バッチ)
    "test_jwt",                 # JWT 検査(alg:none/許可外alg=認証バイパス・alg混同を遮断)
    "test_cors",                # CORS 誤設定の無害化(ACAO:*/null + 資格情報の危険併存)
    "test_credrate",            # クレデンシャル単位レート制限(IP横断の盗用キー濫用を絞る)
    "test_openredirect",        # オープンリダイレクト無害化(外部許可外への3xxを書換/記録)
    "test_methodoverride",      # メソッドオーバーライド悪用対策(override先にもmethodポリシー適用)
    "test_pathoverride",        # パスオーバーライド ACL バイパス対策(X-Original-URL 等を遮断)
    "test_bodydecode",          # 圧縮ボディの解凍走査(gzip/deflate での署名回避を封じる)
    "test_cachepoison",         # キャッシュ汚染ヘッダ除去(非信頼の X-Forwarded-Host 等を落とす)
    "test_rangedos",            # Range ヘッダ DoS 対策(多数レンジ=Apache Killer を遮断)
    "test_origin",              # バックエンド・バイパス防止(エッジ経由を証明する時間有界トークン)
    "test_buttonmash",          # ボタン連打(並行/二重送信)スキャン: スレッド安全・更新取りこぼし無し
    "test_memtamper",           # in-memory cfg すり替え検知+署名ディスクからの復元
    "test_stall",               # 迂回検知(busy→突然ゼロ=バイパスの疑いを警報)
    "test_connlimit_global",    # グローバル同時接続上限(FD/ソケット枯渇のロードシェッド)
    "test_saferegex",           # ReDoS 耐性(lint/入力上限/線形リテラル照合)・組込sig安全性
    "test_smuggling",           # HTTP リクエストスマグリング/デシンク拒否(CL.TE/裸LF/obs-fold等)
    "test_scanwindow",          # 走査面のバイパス封じ(パディング/NFKC展開/窓予算)と資源境界
    "test_vulnfix",             # 脆弱性修正の回帰(CSRF/トークン配布/署名束縛)
    "test_complexity",          # 二次コスト(O(N^2))の再発防止(間引きの低水位・走査量削減の非回帰)
    "test_startup_seams",       # 起動部と繋ぎ目の潜在バグ(設定ミス耐性/起動診断/停止経路/fail-closed)
    # 2026-10 細心のバグ総点検(95 候補)の回帰テスト。どれも修正を外すと落ちることを確認済み。
    "test_sweep_admin_ui",      # 管理画面: inline JS へのデータ埋込/不正本文/CSRF のポート
    "test_sweep_config",        # 設定検証: 構造キー・非有限値・設定変更とロック
    "test_sweep_bans",          # BAN: 恒久BANの短縮/追い出し/IP 正規化/永続化の取りこぼし
    "test_sweep_proxy_request", # 要求/応答: 重複ヘッダ/パイプライン/多重 gzip/1xx/DLP/リダイレクト
    "test_sweep_proxy_lifecycle",  # 停止/ドレイン
    "test_sweep_core",          # 自己防衛の基盤: 署名状態/原子的書込/ReDoS lint/ロケール
    "test_sweep_ldap_edge",     # エッジ設定出力
    "test_sweep_enterprise",    # 監視 URL の秘匿
    "test_sweep_service_gui",   # サービス/トレイ/自動起動/起動スクリプト
    "test_sweep_r2_ipsource",   # 取込時点の IP 正規化(XFF/接続元)・複数クレデンシャルのレート
    "test_sweep_r2_misc",       # 非 ASCII トークン比較/使用量ログ/応答 JSON の非有限値/一時承認の既定
    "test_sweep_r3_proxy",      # 使用量の宛先記録
    "test_sweep_r3_net",        # IPv4-mapped の CIDR 照合
    "test_sweep_followups",     # XFF のゾーンID/使用量の IPv6 Host/FW の IPv4-mapped
    "test_sweep_r4_site_whitelist",  # 空の site_whitelist を whitelist モードにする設定を拒否
    # 2026-10 検知エンジン本体の点検の回帰テスト
    "test_sweep_det_normalize",       # 正規化/走査窓/本文専用の正規化(multipart の誤検知)
    "test_sweep_det_signatures",      # シグネチャ: 重み 0/独自規則の照合面/組込との優先/読込の堅牢性
    "test_sweep_det_inspect_state",   # 状態と採点: 追い出し/早期拒否の計上/減衰/各種設定の境界
    "test_sweep_det_inspect_checks",  # 個別検査: JWT/周期判定
    "test_sweep_det_body",            # GraphQL/アップロード/本文検査の配線
    "test_sweep_det_response",        # 出口 DLP/応答採点
    "test_sweep_det_periphery",       # ブルームフィルタ
    "test_sweep_det2_signatures",     # 本文の ';' は文脈必須/管理 API の入力検証/シグネチャ画面
    "test_sweep_det2_body",           # バイナリ本文/要求ヘッダのファイル名
    "test_sweep_det2_config",         # 設定改ざん時も保護を止めない/列挙値と係数の検証
    "test_sweep_det2_path",           # 照合用パスのドットセグメント/'//'/';' の解決
    "test_sweep_det3_crlf",           # 本文の値に符号化された改行+応答ヘッダの検知(誤検知は戻さない)
    "test_sweep_det3_docs",           # カスタム規則の注意文言と文書の整合
    "test_sweep_det3_misc",           # ヘッダに書く設定値の検証
    # 2026-10 人に向けた表示: JSON の垂れ流しをやめ『何が起きたか+次にすること』を出す
    "test_sweep_ux_proxy_pages",      # 訪問者向けの拒否ページ(API には従来の JSON)
    "test_sweep_ux_dashboard_gui",    # ダッシュボードの詳細分析/エラー表示
    "test_sweep_ux_cli",              # CLI の要約表示と --json
    "test_sweep_lite_tray_status",    # トレイのアイコン/ツールチップで防御 ON/OFF を表示
    # 2026-10 全差分の独立レビューで見つかった回帰の修正
    "test_sweep_rv_autostart",        # 自動起動: XML 登録で /TR 261 文字制限を回避
    "test_sweep_rv_bodynorm",         # 本文: 全角記号を記号へ畳まない/符号化改行の文区切り
    "test_sweep_rv_multipart",        # multipart: 部ヘッダ走査を線形に/行数上限/カード IIN
    "test_sweep_rv_config",           # 旧版の設定・状態を更新後も同じ意味で読む
    "test_sweep_rv_proxy",            # 100-continue/IPv6 リダイレクト/API 判定/監査
    "test_sweep_rv_runtime",          # ログ回転で待たない
    "test_sweep_rv_operator",         # run.bat の py -3/表示の言語
    "test_sweep_rv_lite_tray",        # トレイ: 他プロセスへトークンを送らない/監査モード表示
    "test_sweep_dec_headfold",        # URL/ヘッダでも全角の ｜＄（）；｀ をメタ文字にしない
    "test_sweep_dec_runbat",          # run.bat の注釈を ASCII に(日本語版 Windows の誤ったエラー行)
    "test_sweep_rem_jsonesc",         # JSON 本文の \r\n エスケープ後のヘッダ注入/文区切り
    "test_sweep_rem_tray",            # Explorer 再起動(TaskbarCreated)でトレイのアイコンを付け直す
    "test_sweep_rem_fwfold",          # fold_fullwidth_punct(既定 OFF)で全角記号も畳む運用
    "test_sweep_upd_integrity",       # 同じ場所で更新したとき完全性監視が中核を旧版へ戻さない
    "test_sweep_rem_charset",         # 本文を宣言された charset でも読む・GraphQL のフラグメントを展開して数える
    "test_sweep_rem_geoip",           # GeoIP: 入れ子の CIDR・IPv6 の行・IPv4-mapped で国判定が外れない
    "test_sweep_rem_cover",           # 表示名の制御文字・空の DUCKNET_COVER・Tomcat の偽バナーに PHP を付けない
]


def main() -> int:
    total = passed = 0
    skipped = []
    for name in MODULES:
        mod = importlib.import_module(name)
        fns = [v for k, v in sorted(vars(mod).items())
               if k.startswith("test_") and callable(v)]
        for fn in fns:
            total += 1
            try:
                fn()
                passed += 1
                print(f"PASS {name}.{fn.__name__}")
            except SkipTest as e:   # 環境を満たせないテスト(Tk 無しのサーバ等)
                skipped.append(f"{name}.{fn.__name__}")
                print(f"SKIP {name}.{fn.__name__} -> {e}")
            except Exception as e:  # noqa: BLE001 (テストランナー)
                print(f"FAIL {name}.{fn.__name__} -> {e!r}")
                traceback.print_exc()
                if os.environ.get("GITHUB_ACTIONS") == "true":
                    # CI では失敗を注釈として出す。ログを開かなくても、どのテストが
                    # どう落ちたかが run の一覧から分かる(ログは権限が要る)。
                    _d = " ".join(repr(e).split())[:400]   # 注釈は 1 行に畳む
                    print(f"::error title={name}.{fn.__name__}::{_d}", flush=True)
    failed = total - passed - len(skipped)
    tail = f" ({len(skipped)} skipped)" if skipped else ""
    print(f"\n=== {passed}/{total} passed{tail} ===")
    if skipped:
        # 飛ばしたテストは *必ず* 名前を出す。黙って素通りさせると「全部緑」に見えて
        # 実際には走っていない、という最悪の読み違いが起きる(以前はそうなっていた)。
        print("skipped: " + ", ".join(skipped))
    _cleanup()
    return 0 if failed == 0 else 1


def _cleanup():
    """ビルド/テスト後に余計なデータ(__pycache__ 等)を毎回掃除する。"""
    try:
        sys.path.insert(0, os.path.join(_ROOT, "tools"))
        import clean
        n = clean.clean(_ROOT)
        print(f"cleanup: removed {n} build artifact(s)")
    except Exception as e:        # 掃除失敗はテスト結果に影響させない
        print(f"cleanup: skipped ({e!r})")


if __name__ == "__main__":
    sys.exit(main())
