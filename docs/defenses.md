# 防御リファレンス — 機能 / 設定キー / 既定値

DuckNet L7 の防御と、それを制御する設定キー(`NetShield.cfg` / 管理API `/api/shield/config` /
宣言的設定 JSON で変更可)。**既定ON** は配備直後から効く低誤検知のもの。**opt-in** は配備依存・
誤検知リスクがあるため有効化が必要なもの。

> 設定例(管理API): `POST /api/shield/config {"sec_headers_enabled": true}`
> または宣言的設定ファイル(`--config config.json` / `DUCKNET_CONFIG`)。

## リクエスト検査

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 侵入シグネチャ | （常時・`paranoia` で厳格度） | ON | SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI/SSI/OGNL/proto/CRLF/NoSQLi/LFI/scanner。多層正規化(多重デコード/Unicode/Log4j入れ子)付き |
| 要求ボディ検査 | `body_scan_enabled`, `body_scan_max_bytes` | ON | POST/JSON/GraphQL 本文を有界・重複ウィンドウで走査 |
| 圧縮ボディ解凍 | `body_decode_enabled` | ON | gzip/deflate を有界解凍してから走査(圧縮回避封じ) |
| アップロード検査 | `upload_scan_enabled`, `upload_deny_ext` | ON | multipart の危険拡張子(webshell)を拒否。二重拡張子/NUL 切り対応 |
| メソッドポリシー | `blocked_methods` | ON | TRACE/TRACK/CONNECT 等。`method_override_check`/`method_override_block` で override も |
| パスオーバーライド | `path_override_block` | ON | `X-Original-URL`/`X-Rewrite-URL` 等の ACL 回避を遮断 |
| Range DoS | `range_check_enabled`, `range_max_ranges` | ON | 多数レンジ(Apache Killer)を遮断 |
| スマグリング/フレーミング | （常時） | ON | CL.TE/TE.CL/裸改行/origin-form 強制/パイプライン遮断 |
| GraphQL 防御 | `graphql_enabled`, `graphql_paths`, `graphql_max_depth` ほか | **opt-in** | 深さ/複雑度/イントロスペクション/バッチの上限 |
| JWT 検査 | `jwt_inspect_enabled`, `jwt_allowed_algs` | ON | `alg:none` 遮断。`jwt_allowed_algs` 指定で alg 混同も遮断 |
| ボット整合性 | `bot_consistency_enabled`, `bot_inconsistency_score` | ON | ブラウザ UA 偽装ツールを低FP加点 |

## レート / フラッド / DoS

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| IP レート/フラッド | `flood_threshold`, `window_sec`, `deny_score`, `block_score` | ON | スコア: `deny_score` 以上で単発拒否・`block_score` 以上で自動BAN(累犯エスカレーション) |
| パス別レート | `path_limits`（`set_path_limits`） | opt-in | 認証/高コスト経路を厳格化 |
| per-IP 同時接続 | `max_conn_per_ip` | opt-in | 接続枯渇/slowloris 増幅対策 |
| クレデンシャル単位レート | `cred_rate_enabled`, `cred_rate_limit`, `cred_rate_window_sec` | **opt-in** | トークン/API キー単位(IP ローテーション濫用対策) |
| 応答エラーレート | `resp_score_enabled`, `resp_error_threshold` | ON | 4xx 連射(列挙/ブルートフォース)を脅威スコアへ |
| スロー POST | `body_timeout_enabled`, `body_max_sec` | ON | 要求ボディの総受信時間上限(R-U-Dead-Yet) |
| サブネット集約 | `subnet_defense`, `subnet_threshold` | opt-in | 分散攻撃を /24・/64 で束ねる |
| データ量クォータ | `quota_max_gb`, `quota_max_conn_sec` | opt-in | egress 持ち出し量/接続時間で遮断 |

## レスポンス側

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 出口 DLP | `dlp_enabled`, `dlp_action`, `dlp_max_scan_bytes` | opt-in | 応答先頭を走査し秘密情報漏洩を検出/遮断 |
| セキュリティヘッダ注入 | `sec_headers_enabled`, `sec_headers_extra`, `sec_headers_strip` | opt-in | X-Content-Type-Options/Frame-Options/Referrer-Policy ほか |
| Set-Cookie ハードニング | `cookie_harden_enabled`, `cookie_samesite`, `cookie_httponly` | ON | SameSite/Secure(TLS時)/HttpOnly(opt-in)を補完 |
| CORS 無害化 | `cors_harden_enabled` | ON | `ACAO:*`/`null` + 資格情報の危険併存を無害化 |
| オープンリダイレクト | `open_redirect_enabled`, `open_redirect_allow`, `open_redirect_mode` | **opt-in** | 外部許可外への 3xx を安全パスへ書換/記録 |
| キャッシュ汚染ヘッダ除去 | `strip_cache_poison_headers`, `cache_poison_headers` | ON | 非信頼クライアントの `X-Forwarded-Host` 等を除去 |

## 認証情報 / 信頼 / その他

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 信頼 proxy / 実IP | `trusted_proxies` | opt-in | 背後構成で XFF/XFP を信頼(未設定=一切信頼しない) |
| サイト allowlist | `site_mode`, `site_whitelist` | opt-in | Host(ドメイン)許可。Host インジェクション対策 |

## 自己防衛 / 改竄耐性

[docs/hardening.md](hardening.md) を参照(状態 HMAC 署名・自動起動登録・OS 公認の
クラッシュ自動再起動・ハードニング)。関連環境変数: `DUCKNET_STATE_KEY`(外部署名鍵)。

## 段階導入の勧め
1. 既定ON のまま **監査**(`mode=audit`)で運用し誤検知を観察。
2. 配備に合う opt-in を **audit モード**から(`open_redirect_mode=audit`)。
3. 問題なければ enforce へ。`paranoia` で全体の厳格度も調整可。
