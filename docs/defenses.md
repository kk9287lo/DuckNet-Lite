# 防御リファレンス — 機能 / 設定キー / 既定値

DuckNet L7 の防御と、それを制御する設定キーの一覧です(`NetShield.cfg` / 管理 API `/api/shield/config` /
宣言的設定 JSON で変更できます)。既定 ON は配備直後から効く低誤検知のもの、opt-in は配備依存で誤検知リスクが
あるため有効化が要るものです。

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
| GraphQL 防御 | `graphql_enabled`, `graphql_paths`, `graphql_max_depth` ほか | opt-in | 深さ/複雑度/イントロスペクション/バッチの上限 |
| JWT 検査 | `jwt_inspect_enabled`, `jwt_allowed_algs` | ON | `alg:none` 遮断。`jwt_allowed_algs` 指定で alg 混同も遮断 |
| ボット整合性 | `bot_consistency_enabled`, `bot_inconsistency_score` | ON | ブラウザ UA 偽装ツールを低FP加点 |

## レート / フラッド / DoS

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| IP レート/フラッド | `flood_threshold`, `window_sec`, `deny_score`, `block_score` | ON | スコア: `deny_score` 以上で単発拒否・`block_score` 以上で自動BAN(累犯エスカレーション) |
| パス別レート | `path_limits`（`set_path_limits`） | opt-in | 認証/高コスト経路を厳格化 |
| per-IP 同時接続 | `max_conn_per_ip` | opt-in | 接続枯渇/slowloris 増幅対策 |
| クレデンシャル単位レート | `cred_rate_enabled`, `cred_rate_limit`, `cred_rate_window_sec` | opt-in | トークン/API キー単位(IP ローテーション濫用対策) |
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
| オープンリダイレクト | `open_redirect_enabled`, `open_redirect_allow`, `open_redirect_mode` | opt-in | 外部許可外への 3xx を安全パスへ書換/記録 |
| キャッシュ汚染ヘッダ除去 | `strip_cache_poison_headers`, `cache_poison_headers` | ON | 非信頼クライアントの `X-Forwarded-Host` 等を除去 |

## 認証情報 / 信頼 / その他

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 信頼 proxy / 実IP | `trusted_proxies` | opt-in | 背後構成で XFF/XFP を信頼(未設定=一切信頼しない) |
| サイト allowlist | `site_mode`, `site_whitelist` | opt-in | Host(ドメイン)許可。Host インジェクション対策 |

## 自己防衛 / 改竄耐性

[docs/hardening.md](hardening.md) を参照(状態 HMAC 署名・自動起動登録・OS 公認の
クラッシュ自動再起動・ハードニング)。関連環境変数: `DUCKNET_STATE_KEY`(外部署名鍵)。

## 段階的な導入
1. まず既定 ON のまま監査(`mode=audit`)で運用し、誤検知を観察します。
2. 配備に合う opt-in を audit モードから入れます(`open_redirect_mode=audit`)。
3. 問題なければ enforce へ。全体の厳格度は `paranoia` で調整できます。

## 設定キー全一覧(補遺)

上の表で触れていない設定キーです。既定値は `NetShield._DEFAULTS`(唯一の真実)から取っています。
値の意味が上の表と重なるものは、そちらの説明を優先してください。

| 設定キー | 既定 | 概要 |
|---|---|---|
| `rate_per_sec` | `20.0` | IP毎の定常許容レート |
| `burst` | `40` | バースト許容 |
| `force_conn_close` | `True` | 応答へ `Connection: close` を強制し、keep-alive 越しの検査回避を防ぐ |
| `throttle_response` | `True` | throttle時に 429 を返す(False=即時切断・無応答) |
| `throttle_retry_after` | `1` | 429 の Retry-After 秒(クライアントへの再試行目安) |
| `subnet_window_sec` | `3600` | BAN を集計する時間窓(秒) |
| `subnet_score` | `30` | hot サブネットの新規IPへ一度だけ加える score(deny_score未満=ソフト) |
| `origin_header` | `"X-Edge-Token"` | トークンを載せるヘッダ名(中立名・バックエンドと合わせる) |
| `origin_window_sec` | `30` | トークンの時間バケット幅(リプレイ窓・時計ずれ吸収) |
| `stall_min_rate` | `1.0` | 「直近 busy」とみなす最小レート(req/s)。これ未満は静観 |
| `slowloris_score` | `50` | ヘッダ未完(slowloris)1回あたりの加点(反復でBAN) |
| `resp_error_window_sec` | `60` | 4xx 集計窓 |
| `resp_error_score` | `50` | 閾超過1回あたりの加点(note_response は block_score のみ判定= |
| `cred_rate_score` | `40` | 超過時の加点(既定=deny_score 相当→次要求で単発拒否) |
| `resp_stall_sec` | `0.0` | 迂回検知: 直近まで busy だったのに応答が途絶えた状態を疑う秒数 |
| `open_redirect_safe_path` | `"/"` | enforce 時に書き換える安全な遷移先 |
| `graphql_max_complexity` | `100` | 選択セット数の上限(エイリアス/フィールド増幅対策) |
| `graphql_block_introspection` | `True` | __schema/__type を遮断(本番のスキーマ漏洩防止) |
| `graphql_max_batch` | `10` | バッチ(配列)オペレーション数の上限 |
| `ban_escalation_retain_sec` | `86400` | 累犯回数(ban_count)を再起動越しに覚えておく窓(BAN期限切れ後) |
| `block_page` | `True` | 遮断時に HTML の説明ページを返す(False=最小 JSON) |
| `appeal_enabled` | `True` | 遮断ページに『解除リクエスト(異議申立)』を表示 |
| `appeal_after_sec` | `120` | BANから この秒数 経過後にのみ解除リクエストを表示(数分後) |
| `mode` | `"enforce"` | `enforce`(遮断)/ `audit`(遮断せず記録のみ) |
| `blocked_extensions` | `(空)` | 遮断する拡張子(例 .env .sql .bak .git .ini) |
| `blocked_urls` | `(空)` | 遮断するURL部分文字列(例 /admin /wp-admin) |
| `require_tls` | `False` | 正規TLS以外(平文)を遮断(X-Forwarded-Proto=https 必須) |
| `geo_mode` | `"off"` | `off` / `allow` / `block` — `geo_cidrs` による地域判定の動作 |
| `geo_cidrs` | `(空)` | 地域判定に使う CIDR 一覧(GeoIP DB 不要) |
| `quota_enabled` | `False` | 送出量/接続時間クォータの集計と超過判定を有効化 |
| `quota_window_days` | `1` | 集計窓(1〜N日) |
| `site_blacklist` | `(空)` | `site_mode=block` のときに拒否する Host(ドメイン)の一覧 |
| `ip_mode` | `"off"` | `off` / `allow` / `block` — IP/CIDR リストの動作 |
| `ip_whitelist` | `(空)` | `ip_mode=allow` のときに通す IP/CIDR の一覧 |
| `ip_blacklist` | `(空)` | `ip_mode=block` のときに拒否する IP/CIDR の一覧 |
| `usage_record` | `True` | ホスト別の利用状況(リクエスト数等)を記録する |
| `score_halflife_sec` | `30.0` | スコア半減期 |
| `cadence_score` | `35` | 機械的規則性を検知した時の加点 |
| `cadence_min_samples` | `8` | 判定に要する最小サンプル数 |
| `cadence_cv_threshold` | `0.15` | 変動係数(これ未満=規則正しすぎ=機械) |
| `cadence_max_mean_interval` | `3.0` | 平均間隔がこれ超なら対象外(遅い正規ポーラを誤検知しない) |
| `cadence_min_mean_interval` | `0.01` | これ未満=バースト(µs〜ms)はビーコンでなく flood/レート制限の |
| `optional_sigs` | `(空)` | 高FPシグネチャの個別 ON/OFF(`paranoia` を上げると自動で入る) |
