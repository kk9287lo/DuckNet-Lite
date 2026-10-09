# オプション一覧(環境変数 / 設定キー)— v1.3.0

DuckNet の挙動は CLI 引数・環境変数・設定キー(cfg)で制御します。設定キーは管理ダッシュボード /
宣言的ブートストラップ(JSON)から変更でき、`NetShield._DEFAULTS` が唯一の真実です。防御の詳細・既定値
(ON / opt-in)は [defenses.md](defenses.md) を参照してください。

## 環境変数

| 変数 | 既定 | 説明 |
| --- | --- | --- |
| `DUCKNET_LANG` | (自動) | サーバ生成文言の言語 `ja`/`en`。未設定なら OS ロケールに追随(英語環境は自動 en、それ以外 ja)。 |
| `DUCKNET_STATE_DIR` | OS 既定 | 状態ファイル(BAN/設定/署名/テレメトリ)の保存先。 |
| `DUCKNET_STATE_KEY` | (生成) | 状態ファイル署名の HMAC 鍵。外部鍵を推奨(未設定時は state_dir に 0600 で生成するため、同ディスクの root には弱い)。 |
| `DUCKNET_DRAIN_TIMEOUT` | `60` | 応答転送の書込み(drain)デッドライン秒(#9 slow-read/zero-window 対策)。 |
| `DUCKNET_HEALTH_PATH` | (空) | LB 死活監視用に即 200 を返す予約パス(WAF/バックエンド非経由)。 |
| `DUCKNET_ADMIN_ALLOWED_HOSTS` | (空) | 管理面で許可する追加ホスト名(カンマ区切り)。DNS リバインディング対策の例外指定。IP リテラルと localhost は常に許可。 |
| `DUCKNET_ADMIN_TOKEN` | (生成) | 管理トークン。`--token` より env が推奨(argv は他ユーザーから読める)。本体を別に起動していてもトレイが防御 ON/OFF を表示できるよう、両方が読む `app.env` に書くとよい([dashboard.md](dashboard.md#トレイ表示windows))。 |
| `DUCKNET_ADMIN_URL` | `http://127.0.0.1:8081` | トレイ/GUI が開く管理ダッシュボードの URL。 |
| `DUCKNET_BACKEND` | `127.0.0.1:8080` | トレイから本体を起動するときの保護対象(HOST:PORT)。 |
| `DUCKNET_CONFIG` | (空) | 起動時に適用する宣言的設定 JSON のパス(`--config` と同じ)。 |
| `DUCKNET_COVER` | (空) | ステルス運用の偽装名。管理画面/遮断ページ/Server ヘッダの表示名を差し替える。 |
| `DUCKNET_DECEPTION` | (空) | 動的デセプション(偽 Server バナー)の有効化。`1`/`true`/`yes`/`on` で ON。 |
| `DUCKNET_DRAIN_GRACE` | `5` | 停止時に進行中リクエストを捌く最大秒数(`--drain-grace` と同じ)。数値として読めない値は警告して既定へ。 |
| `DUCKNET_ICON_DIR` | (空) | トレイアイコンの探索ディレクトリ(同梱 assets より優先)。防御 OFF / 接続不可の淡色アイコン `DuckNet-off.ico` は `DuckNet.ico` と同じ場所から探す(無ければ通常アイコンのまま)。 |
| `DUCKNET_LISTEN` | `8443` | トレイから本体を起動するときの前衛ガード待受ポート。 |
| `DUCKNET_ORIGIN_KEY` | (生成) | バックエンド・バイパス防止トークン(エッジ経由を証明する時間有界トークン)の鍵。バックエンド側と揃える。 |

> 管理 API の状態変更 POST は、CSRF 対策として `Origin`(無ければ `Referer`)を `Host` と **ホスト名とポートの両方** で
> 照合し、不一致は 403 にします。前段のリバースプロキシが `Host` をポート抜きに書き換える構成(例: `https://admin.example:8443`
> で公開し `Host: admin.example` で転送)では、公開ホスト名を `DUCKNET_ADMIN_ALLOWED_HOSTS` に加えてください。
> また Cookie 認証(ブラウザ)の POST は `Content-Type: application/json` 必須です(それ以外は 415)。
> `X-Token` / `Authorization: Bearer` で認証するクライアントは対象外です。

## 主な設定キー(cfg)

| キー | 既定 | 説明 |
| --- | --- | --- |
| `enabled` | `False` | 防御全体の ON/OFF(既定 OFF=完全パススルー)。 |
| `paranoia` | `1` | 検知の厳格度 1–4。上げるほど誤検知しやすい任意シグネチャを段階的に有効化(2: オープンリダイレクト、3: +内部宛て SSRF、4: +テンプレート注入)。整数以外は拒否(現状維持)。 |
| `deny_score` / `block_score` | `40` / `100` | 単発拒否(BANなし) / 遮断+自動BAN の脅威スコア閾値。 |
| `ban_ttl_sec` | `300` | 自動BAN の継続秒(累犯は `ban_escalation`/`ban_escalation_cap` で延長)。 |
| `body_scan_enabled` / `body_scan_max_bytes` | `True` / `65536` | 要求ボディのシグネチャ走査と上限バイト。multipart でない本文のうち、`Content-Type` がバイナリ型 *かつ* 中身もバイナリ(タブ/CR/LF 以外の制御バイトを含む)のものは署名走査せず、metrics の `body_binary_skipped` に数える([defenses.md](defenses.md) の「要求ボディ検査の範囲」)。 |
| `body_sig_weight_factor` | `0.7` | 本文由来シグネチャのスコア係数(誤 BAN 低減。1.0=従来、0=記録のみで加点しない)。負の値は拒否(以前の版で保存された負の値は 0 として読む)。 |
| `body_max_sec` | `60` | ボディ受信の総許容秒(slow POST 対策)。本文の走査中に超えた要求は backend へ送らず切断。 |
| `flood_threshold` / `window_sec` | `150` / `10` | フラッド閾(窓内要求数)と窓秒。 |
| `max_conn_per_ip` / `max_total_conn` | `0` / `20000` | IP毎 / 全体の同時接続上限(枯渇/slowloris 増幅対策)。 |
| `conn_rate_per_ip` | `0` | IP 毎の接続レート上限(毎秒)。接続→即 RST を高速反復する churn フラッドを、head 解析前に安価に shed する。0=無効(NAT の巻き添え回避)。ロックダウンで自動有効。 |
| `subnet_defense` | `False` | サブネット(/24・/64)集約防御(opt-in)。 |
| `jwt_inspect_enabled` | `True` | JWT(`alg:none`/許可外 alg)遮断。 |
| `cookie_harden_enabled` / `cors_harden_enabled` | `True` / `True` | Set-Cookie 補完 / CORS 無害化。 |
| `graphql_enabled` / `graphql_max_bytes` | `False` / `262144` | GraphQL 深さ/複雑度/イントロスペクション/バッチ制限(POST 本文と GET `?query=`)。本文は `graphql_max_bytes` まで全体を解析し、超える本文は 413 で拒否。複雑度の上限 `graphql_max_complexity` は既定 1000(選択したフィールドの数。旧版で保存した 100 はそのまま残る)。`body_scan_enabled` とは独立。 |
| `upload_scan_enabled` | `True` | multipart のパートヘッダ(`filename=` / `filename*=`)の危険拡張子検査。本文の先頭を超えた後続パートも転送しながら検査。生本文アップロードは要求ヘッダ `Content-Disposition` の `filename` / `filename*` で、本文を読む前に検査する。`body_scan_enabled` とは独立。 |
| `path_override_block` / `method_override_block` | `True` / `False` | ACL バイパス(X-Original-URL 等)/ メソッドオーバーライド遮断。 |
| `range_check_enabled` | `True` | Range DoS(Apache Killer)対策。 |
| `sec_headers_enabled` | `False` | 応答セキュリティヘッダ注入。 |
| `dlp_enabled` / `dlp_action` | `False` / `audit` | 出口 DLP と動作。`dlp_action` は `audit`(記録のみ)/ `block`(その応答を送らず切断)だけを受け付ける。 |
| `open_redirect_enabled` | `False` | オープンリダイレクト無害化。 |
| `strip_cache_poison_headers` | `True` | 非信頼 `X-Forwarded-Host` 等の除去。 |
| `cred_rate_enabled` | `False` | クレデンシャル単位レート制限。 |
| `origin_cloaking_enabled` | `False` | バックエンド・バイパス防止(時間有界トークン)。 |
| `stall_detect_enabled` | `True` | 迂回検知(busy→突然ゼロ)。 |
| `persist_bans` | `True` | BAN を再起動を跨いで永続化(署名付き・ロールバック耐性)。 |
| `trusted_proxies` | `[]` | 信頼 proxy の CIDR(背後で XFF から実IPを採用。既定は XFF 不信)。 |

> 列挙値のキー(`mode` / `open_redirect_mode` / `geo_mode` / `site_mode` / `ip_mode` / `cookie_samesite` /
> `dlp_action`)は決まった値だけを受け付けます(前後の空白と大小文字は正規化。値の一覧は
> [defenses.md](defenses.md))。それ以外の値は拒否して現在の値を保ち(管理 API・宣言的設定は `rejected` で
> 返す)、以前の版で保存された不正な値は既定値として読みます。
