# オプション一覧(環境変数 / 設定キー)— v1.2.0

ChickenNet の挙動は **CLI 引数**・**環境変数**・**設定キー(cfg)** で制御します。設定キーは管理
ダッシュボード / 宣言的ブートストラップ(JSON)から変更でき、`NetShield._DEFAULTS`
が唯一の真実です。防御の詳細・既定値(ON / opt-in)は [defenses.md](defenses.md) を参照。

## 環境変数

| 変数 | 既定 | 説明 |
| --- | --- | --- |
| `CHICKENNET_LANG` | (自動) | サーバ生成文言の言語 `ja`/`en`。未設定なら OS ロケールに追随(英語環境は自動 en、それ以外 ja)。 |
| `CHICKENNET_COVER` | (空) | **ステルス名**。設定すると製品名(ログ/スレッド名/起動バナー/管理ダッシュボードのタイトル・ヘッダ/生成設定コメント)を露出させず、この名前で偽装。 |
| `CHICKENNET_STATE_DIR` | OS 既定 | 状態ファイル(BAN/設定/署名/テレメトリ)の保存先。 |
| `CHICKENNET_STATE_KEY` | (生成) | 状態ファイル署名の HMAC 鍵。**外部鍵推奨**(未設定時は state_dir に 0600 で生成=同ディスク root には弱い)。 |
| `CHICKENNET_OFFLINE` | (空) | 外部接続を一切しない(テスト/隔離環境)。 |
| `CHICKENNET_DRAIN_TIMEOUT` | `60` | 応答転送の書込み(drain)デッドライン秒(#9 slow-read/zero-window 対策)。 |
| `CHICKENNET_ALERT_QPS` | `20` | SIEM/Webhook 転送の最大送信レート(毎秒)。0 で無効。 |
| `CHICKENNET_ALERT_CAP` | `1024` | アラート転送キューの容量(超過は drop-oldest・抑制サマリで可視化)。 |
| `CHICKENNET_SYSLOG` | (空) | Syslog 転送先 `udp://h:514` / `tcp://h:601` / `h:port`。 |
| `CHICKENNET_SYSLOG_FACILITY` | `16` | Syslog ファシリティ(0–23・既定 local0)。 |
| `CHICKENNET_WEBHOOK` | (空) | Webhook 転送先 URL(`{"text":...}` 形式で POST)。 |
| `CHICKENNET_HEALTH_PATH` | (空) | LB 死活監視用に即 200 を返す予約パス(WAF/バックエンド非経由)。 |
| `CHICKENNET_DNS_UPSTREAM` | — | `dns` サブコマンドの上流リゾルバ(既定 `1.1.1.1:53`)。 |

## 主な設定キー(cfg)

| キー | 既定 | 説明 |
| --- | --- | --- |
| `enabled` | `False` | 防御全体の ON/OFF(既定 OFF=完全パススルー)。 |
| `under_attack` | `False` | Under Attack モード(全員に追加チャレンジ・最大強度)。 |
| `paranoia` | `1` | 検知の厳格度 1–3。 |
| `challenge_score` / `block_score` | `40` / `100` | チャレンジ発行 / 遮断+自動BAN の脅威スコア閾値。 |
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
| `posmodel_enabled` / `posmodel_mode` | `False` / `enforce` | 正のセキュリティモデル(allowlist)と enforce/audit。 |
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

> **DNS 検知**(`python -m dataplane dns`)は別途 `rrl_max_per_sec`(既定 30・応答レート制限)など
> DNS 専用の設定を持ちます。

## サブコマンド

| コマンド | 説明 |
| --- | --- |
| `python -m dataplane …` | ゲートウェイ(前衛 + 管理 API)。既定。 |
| `python -m dataplane dns` | DNS の L7 検知(別プロセス)。 |
