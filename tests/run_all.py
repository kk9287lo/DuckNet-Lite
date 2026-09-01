"""tests/run_all.py — DuckNet L7 Security 全テスト(依存ゼロ・pytest不要)。

実行:
    python tests/run_all.py        # リポジトリ直下から
外部リポジトリには依存しない(バンドル内の vendored サブセットのみを使う)。
"""
from __future__ import annotations

import importlib
import os
import sys
import traceback

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
]


def main() -> int:
    total = passed = 0
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
            except Exception as e:  # noqa: BLE001 (テストランナー)
                print(f"FAIL {name}.{fn.__name__} -> {e!r}")
                traceback.print_exc()
    print(f"\n=== {passed}/{total} passed ===")
    _cleanup()
    return 0 if passed == total else 1


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
