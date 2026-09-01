# オプション一覧(環境変数 / 設定キー)— v1.2.0

DuckNet の挙動は **CLI 引数**・**環境変数**・**設定キー(cfg)** で制御します。設定キーは管理
ダッシュボード / 宣言的ブートストラップ(JSON)から変更でき、`NetShield._DEFAULTS`
が唯一の真実です。防御の詳細・既定値(ON / opt-in)は [defenses.md](defenses.md) を参照。

## 環境変数

| 変数 | 既定 | 説明 |
| --- | --- | --- |
| `DUCKNET_LANG` | (自動) | サーバ生成文言の言語 `ja`/`en`。未設定なら OS ロケールに追随(英語環境は自動 en、それ以外 ja)。 |
| `DUCKNET_STATE_DIR` | OS 既定 | 状態ファイル(BAN/設定/署名/テレメトリ)の保存先。 |
| `DUCKNET_STATE_KEY` | (生成) | 状態ファイル署名の HMAC 鍵。**外部鍵推奨**(未設定時は state_dir に 0600 で生成=同ディスク root には弱い)。 |
| `DUCKNET_OFFLINE` | (空) | 外部接続を一切しない(テスト/隔離環境)。 |
| `DUCKNET_DRAIN_TIMEOUT` | `60` | 応答転送の書込み(drain)デッドライン秒(#9 slow-read/zero-window 対策)。 |
| `DUCKNET_HEALTH_PATH` | (空) | LB 死活監視用に即 200 を返す予約パス(WAF/バックエンド非経由)。 |

## 主な設定キー(cfg)

| キー | 既定 | 説明 |
| --- | --- | --- |
| `enabled` | `False` | 防御全体の ON/OFF(既定 OFF=完全パススルー)。 |
| `paranoia` | `1` | 検知の厳格度 1–3。 |
| `deny_score` / `block_score` | `40` / `100` | 単発拒否(BANなし) / 遮断+自動BAN の脅威スコア閾値。 |
| `ban_ttl_sec` | `300` | 自動BAN の継続秒(累犯は `ban_escalation`/`ban_escalation_cap` で延長)。 |
| `body_scan_enabled` / `body_scan_max_bytes` | `True` / `65536` | 要求ボディのシグネチャ走査と上限バイト。 |
| `body_sig_weight_factor` | `0.7` | **本文由来シグネチャのスコア係数**(誤BAN低減。1.0=従来)。 |
| `body_max_sec` | `60` | ボディ受信の総許容秒(slow POST 対策)。 |
| `flood_threshold` / `window_sec` | `150` / `10` | フラッド閾(窓内要求数)と窓秒。 |
| `max_conn_per_ip` / `max_total_conn` | `0` / `20000` | IP毎 / 全体の同時接続上限(枯渇/slowloris 増幅対策)。 |
| `conn_rate_per_ip` | `0` | IP毎の**接続レート**上限(毎秒)。接続→即RST を高速反復する churn フラッドを head 解析前に安価に shed。0=無効(NAT 巻添え回避)。ロックダウンで自動有効。 |
| `subnet_defense` | `False` | サブネット(/24・/64)集約防御(opt-in)。 |
| `jwt_inspect_enabled` | `True` | JWT(`alg:none`/許可外 alg)遮断。 |
| `cookie_harden_enabled` / `cors_harden_enabled` | `True` / `True` | Set-Cookie 補完 / CORS 無害化。 |
| `graphql_enabled` | `False` | GraphQL 深さ/複雑度/イントロスペクション制限。 |
| `upload_scan_enabled` | `True` | アップロード危険拡張子検査。 |
| `path_override_block` / `method_override_block` | `True` / `False` | ACL バイパス(X-Original-URL 等)/ メソッドオーバーライド遮断。 |
| `range_check_enabled` | `True` | Range DoS(Apache Killer)対策。 |
| `sec_headers_enabled` | `False` | 応答セキュリティヘッダ注入。 |
| `dlp_enabled` / `dlp_action` | `False` / `audit` | 出口 DLP と audit/block。 |
| `open_redirect_enabled` | `False` | オープンリダイレクト無害化。 |
| `strip_cache_poison_headers` | `True` | 非信頼 `X-Forwarded-Host` 等の除去。 |
| `cred_rate_enabled` | `False` | クレデンシャル単位レート制限。 |
| `origin_cloaking_enabled` | `False` | バックエンド・バイパス防止(時間有界トークン)。 |
| `stall_detect_enabled` | `True` | 迂回検知(busy→突然ゼロ)。 |
| `persist_bans` | `True` | BAN を再起動を跨いで永続化(署名付き・ロールバック耐性)。 |
| `trusted_proxies` | `[]` | 信頼 proxy の CIDR(背後で XFF から実IPを採用。既定は XFF 不信)。 |
