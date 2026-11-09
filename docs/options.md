# オプション一覧(環境変数 / 設定キー)— v1.3.0

DuckNet の挙動は CLI 引数・環境変数・設定キー(cfg)で制御します。設定キーは管理ダッシュボード /
宣言的ブートストラップ(JSON)から変更でき、`NetShield._DEFAULTS` が唯一の真実です。防御の詳細・既定値
(ON / opt-in)は [defenses.md](defenses.md) を参照してください。

情報流出対策では `exposure_guard_enabled`（既定true）、`private_paths`（最大64経路）、
`private_path_allow`（最大256 IP/CIDR）を使用できます。非公開経路の指定方法、PHP更新と
ストレージ公開禁止の適用物は [privacy-protection.md](privacy-protection.md) にまとめています。

要求・応答で走査する通常の文字列リストは、管理API・宣言的設定では各512件、
1要素のUTF-8表現512バイト、全要素の合計65536バイトまでです。空要素、制御文字、
前後空白、大小文字を無視した重複も拒否し、更新前の設定を保持します。
IP/CIDRの4リスト（`ip_whitelist`・`ip_blacklist`・`geo_cidrs`・`trusted_proxies`）は、
従来の入力互換性のため外側のASCII spaceを除去してから検証します。除去前にも長さ・
制御文字を検査し、空要素や正規化後の重複を受理しません。
`private_paths`・`private_path_allow`・`path_limits`・`blocked_methods` は個別の検証規則を使います。
`path_limits` は実際の照合で同一になる大小文字違いの前方一致を重ねず、各パスはUTF-8で512バイトまでです。
パス別レートのプロセス内バケツは合計262144件が上限です。満杯時は現役バケツを消さず、
新しい制限対象パスを遮断します（監査モードでは遮断相当を記録）。制限対象外のパスはこの上限の影響を受けません。
`blocked_methods` は従来のASCII英字・16文字以下という規則で全項目検証し、1項目でも不正なら全体を拒否します。
入力は最大512件・合計65536バイトで、正規化後のメソッド名の重複は従来どおりまとめます。
旧版の保存済みリストがこの上限を超える場合は遮断・許可の意味を維持し、
`cfg_legacy_list_budget` 警告を表示します。整理して保存すると警告を解消できます。

## `--cluster` の実行条件

既定では NetShield とアプリ層ファイアウォールが有効で、`max_total_conn` も 20000 です。
これらの採点・BAN・レート・保留承認・接続数・監査集計はまだワーカー間で共有しないため、
`--cluster` を指定しても `mode: single`, `workers: 1`, `cluster_downgraded: true` と理由を返します。
NetShield とアプリ層ファイアウォールを無効にし、`max_total_conn`・`max_conn_per_ip`・
`conn_rate_per_ip` をすべて 0 にした POSIX 環境だけで複数ワーカーを起動できます。
その場合も proxy の集計値は親ワーカー分だけなので `telemetry_complete: false` と報告し、
管理APIは全体値として表示しません。実行中の外部署名済み設定が共有されない防御を有効にしたら、
ワーカーは backend 転送前に拒否し、正常なヘルス応答も返しません。
単一ワーカーへ切り替えるには通常の停止・起動を使います。Windows 自体の再起動は不要です。
本文退避中のforkワーカーが強制終了した場合、次に共有容量が逼迫した要求で専用の所有ロックを確認し、終了が証明できたワーカーの予約だけを回収します。容量逼迫時の再確認は全ワーカー共通で最大0.2秒間隔なので、その間は503になることがあります。共有ロックと所有ロックの元のファイル識別子を固定し、差し替えや容量記録の不整合を確認した場合は、推測で予約を消さず503で拒否します。元のロックファイルが復旧すれば再試行できます。Windows自体の再起動は不要です。

## 環境変数

| 変数 | 既定 | 説明 |
| --- | --- | --- |
| `DUCKNET_LANG` | (自動) | サーバ生成文言の言語 `ja`/`en`。未設定なら OS ロケールに追随(英語環境は自動 en、それ以外 ja)。 |
| `DUCKNET_STATE_DIR` | `~/.cache/ducknet-lite` | 状態ファイル(BAN/設定/署名/テレメトリ)の専用保存先。旧共用 `~/.cache/dataplane` に署名状態や監査記録が残る場合は、既定起動を拒否して明示選択を求める。旧ファイルは自動移動しない。POSIX では実行 UID 所有・他 UID が書けないディレクトリと安全な祖先が必要。 |
| `DUCKNET_STATE_KEY` | (生成) | 状態ファイル署名の HMAC 鍵。未設定時は state_dir に 32 ランダムバイトを生成して 0600 で保存。明示した外部鍵は UTF-8 で 32 バイト以上のランダム値が必要で、空値・短い値は起動を拒否する。長さだけでは推測耐性を保証しない。鍵を読み取れない・永続化できない場合も一時鍵で続けない。ローカル鍵は実行ユーザー本人の所有が必要。 |
| `DUCKNET_DRAIN_TIMEOUT` | `60` | backend・クライアントへの各書込み(drain)期限秒。有限の正値を指定し、不正値・OS待機上限以上は60秒へ戻す。検証済み要求本文のbackend転送には、各書込みの期限に加えて独立した総期限300秒がある。 |
| `DUCKNET_HEALTH_PATH` | (空) | LB 死活監視用に即 200 を返す予約パス(WAF/バックエンド非経由)。 |
| `DUCKNET_ADMIN_ALLOWED_HOSTS` | (空) | 管理面で許可する追加ホスト名(カンマ区切り)。DNS リバインディング対策の例外指定。IP リテラルと localhost は常に許可。 |
| `DUCKNET_ADMIN_TOKEN` | (生成) | 管理トークン。`--token` より env が推奨(argv は他ユーザーから読める)。トレイが本体を起動する場合は、`app.env` に書いた値を子へ渡す。別に起動した本体へは、トレイから自動送信しない([dashboard.md](dashboard.md#トレイ表示windows))。 |
| `DUCKNET_ADMIN_URL` | `http://127.0.0.1:8081` | トレイ/GUI が開く管理ダッシュボードの URL。旧形式の `token` クエリは大小文字やURLエスケープを問わず、ブラウザで開く前に除く。 |
| `DUCKNET_BACKEND` | `127.0.0.1:8080` | トレイから本体を起動するときの保護対象(HOST:PORT)。明示した空のアドレス・ポートは起動時に拒否する。ポート自体の省略は従来どおり許容する。 |
| `DUCKNET_CONFIG` | (空) | 起動時に適用する宣言的設定 JSON のパス(`--config` と同じ)。 |
| `DUCKNET_COVER` | (空) | ステルス運用の偽装名。管理画面/遮断ページ/Server ヘッダの表示名を差し替える。 |
| `DUCKNET_DECEPTION` | (空) | 動的デセプション(偽 Server バナー)の有効化。`1`/`true`/`yes`/`on` で ON。 |
| `DUCKNET_DRAIN_GRACE` | `5` | 停止時に進行中リクエストを捌く最大秒数(`--drain-grace` と同じ)。数値として読めない値は警告して既定へ。 |
| `DUCKNET_ICON_DIR` | (空) | トレイアイコンの探索ディレクトリ(同梱 assets より優先)。防御 OFF / 接続不可の淡色アイコン `DuckNet-off.ico` は `DuckNet.ico` と同じ場所から探す(無ければ通常アイコンのまま)。 |
| `DUCKNET_LISTEN` | `8443` | トレイから本体を起動するときの前衛ガード待受ポート。 |
| `DUCKNET_ORIGIN_KEY` | (生成) | バックエンド・バイパス防止トークン(エッジ経由を証明する時間有界トークン)の鍵。バックエンド側と揃える。 |

> 管理 API の状態変更 POST は、CSRF 対策として送られた `Origin` と `Referer` の両方を `Host` と **ホスト名とポートの両方** で
> 照合し、不一致は 403 にします。前段のリバースプロキシが `Host` をポート抜きに書き換える構成(例: `https://admin.example:8443`
> で公開し `Host: admin.example` で転送)では、公開ホスト名を `DUCKNET_ADMIN_ALLOWED_HOSTS` に加えてください。
> ブラウザは管理トークンをページのメモリだけに保持し、要求と応答を HMAC で認証します。生トークンをヘッダ/Cookieに送りません。再読込時は再入力が必要で、WebCryptoを使えるlocalhost/HTTPSが必要です。
> `X-Token` / `Authorization: Bearer` を使うクライアントにも同じ `Origin` / `Referer` 照合を適用します。
> Origin・Refererは各1個とし、両方ある場合はHTTP/HTTPSのscheme・ホスト・有効ポートも一致させます。userinfoや不正なURLは拒否します。
> Host・X-Token・Authorizationも重複を拒否します。明示した資格情報が空・不正形式・互いに不一致なら認証を拒否し、ブラウザHMACへフォールバックしません。同じ値のX-TokenとBearerの組合せは許可します。
> 管理APIの本文には最大1MiBに加えて総受信30秒の期限があります。少量ずつ送り続けても期限を延長せず、未完了・期限超過の本文を設定へ適用しません。
> 管理APIは `Content-Length` を最大1個・20桁以下のASCII十進数として受け付け、`Transfer-Encoding` は受け付けません。曖昧な指定はブラウザHMACのnonceや防御設定を更新する前にHTTP 400で拒否します。

## 主な設定キー(cfg)

| キー | 既定 | 説明 |
| --- | --- | --- |
| `enabled` | `True`（状態欠落時） | NetShield の要求検知・採点・本文検査・DLP の ON/OFF。初回起動・状態欠落では ON、正しく署名された明示 OFF は保持する。HTTP の構造検査、別のアプリ層ファイアウォール、個別設定の Cookie/CORS 応答加工は独立して動く。 |
| `paranoia` | `1` | 検知の厳格度 1–4。上げるほど誤検知しやすい任意シグネチャを段階的に有効化(2: オープンリダイレクト、3: +内部宛て SSRF、4: +テンプレート注入)。整数以外は拒否(現状維持)。 |
| `fold_fullwidth_punct` | `False` | 全角の `｜` `＄` `（` `）` `；` `｀` を、URL・ヘッダ・本文のどれでも ASCII の `\|` `$` `(` `)` `;` `` ` `` へ畳んで照合する(前の版の NFKC と同じ)。既定 OFF では日本語の文の記号として空白に読む。**ON にするのは**、保護するバックエンド自身が全角を ASCII へ変換する場合だけ(入力へ NFKC を掛けるアプリ、Windows の best-fit 変換で全角を ANSI へ落とす部品など。全角のまま書いた `｜` がシェル/SQL で本物のメタ文字になる)。ON にすると `データ分析の基礎｜Python` のような題名が前の版と同じく rce 等に当たる(検索 1 回で 60 点=単発拒否の `deny_score` 超)。true/false 以外は拒否(現状維持)。 |
| `deny_score` / `block_score` | `40` / `100` | 単発拒否(BANなし) / 遮断+自動BAN の脅威スコア閾値。 |
| `ban_ttl_sec` | `300` | 自動BAN の継続秒(1〜2592000。累犯は `ban_escalation`/`ban_escalation_cap` で延長)。 |
| `body_scan_enabled` / `body_scan_max_bytes` | `True` / `65536` | 要求ボディの署名走査と復号後の全体サイズ上限(設定範囲 1024〜262144)。NetShield の遮断モードで全体が上限を超える要求は backend 接続前に 413、復号できない要求は 415 で拒否。監査モードは超過・検査不能を記録して従来の先頭走査と転送を続ける。chunked の枠や gzip/deflate のヘッダは復号後サイズに数えず、生の読取量にも別の上限を課す。バイナリ型や制御バイトだけでは走査を省かない。 |
| `body_sig_weight_factor` | `0.7` | 本文由来シグネチャのスコア係数(誤 BAN 低減。1.0=従来、0=記録のみで加点しない)。設定範囲は0〜1000。負の値は拒否(以前の版で保存された負の値は 0 として読む)。 |
| `body_max_sec` | `60` | ボディ受信の総許容秒(slow POST 対策)。設定APIでは1〜3600の整数。本文の走査中に超えた要求は backend へ送らず切断。途中で間が空いても、この総時間内なら切らずに待つ。ただし、本文全体の検証・退避には独立した300秒の上限があり、設定が300秒超でも延長されない。 |
| `flood_threshold` / `window_sec` | `150` / `10` | フラッド閾は 1〜10000 件、窓は 1〜3600 秒。監査モードでも履歴は閾値+1 件に制限。flood・資格情報・4xx の時刻履歴はプロセス合計 200 万件を上限とし、満杯時は現役窓を消さず新規要求を拒否（監査モードでは遮断相当を記録）する。 |
| `max_conn_per_ip` / `max_total_conn` | `0` / `20000` | IP毎 / 全体の同時接続上限(枯渇/slowloris 増幅対策)。 |
| `conn_rate_per_ip` | `0` | IP 毎の接続レート上限(毎秒)。接続→即 RST を高速反復する churn フラッドを、head 解析前に安価に shed する。0=無効(NAT の巻き添え回避)。ロックダウンで自動有効。 |
| `subnet_defense` | `False` | サブネット(/24・/64)集約防御(opt-in)。追跡は最大 4096 サブネット・各 256 IP。窓内の現役記録を容量回収で消さず、未知サブネットの追跡が満杯なら新規要求を拒否（監査モードは記録）する。`subnet_threshold` は 1〜256、`subnet_window_sec` は 1〜2592000 秒。 |
| `jwt_inspect_enabled` | `True` | JWT(`alg:none`/許可外 alg)遮断。 |
| `cookie_harden_enabled` / `cors_harden_enabled` | `True` / `True` | Set-Cookie 補完 / CORS 無害化。 |
| `graphql_enabled` / `graphql_max_bytes` | `False` / `262144` | GraphQL 深さ/複雑度/イントロスペクション/バッチ制限(POST 本文と GET `?query=`)。本文は `graphql_max_bytes` まで全体を解析し、超える本文は 413 で拒否。設定範囲は本文 1〜1048576 バイト、深さ 1〜64、複雑度 1〜10000、バッチ 1〜100。旧版で保存した範囲外の値は安全な範囲へ補正して警告する。UTF-16/32 の JSON 本文と、宣言された `charset` の読み方も照合する。`body_scan_enabled` とは独立。 |
| `upload_scan_enabled` | `True` | multipart のパートヘッダ(`filename=` / `filename*=`)の危険拡張子検査。署名走査 OFF の非圧縮本文も、後続パートを含めて検査・本文終端を確認してから backend に転送。圧縮 multipart は遮断モードで全体を復号でき、復号後サイズが `body_scan_max_bytes` 以下の場合だけ転送する。監査モードの検査不能は記録して通す。内側にさらに `multipart/*` を入れる形も検査不能として遮断モードで拒否。生本文アップロードは要求ヘッダ `Content-Disposition` のファイル名を本文前に検査する。`body_scan_enabled` とは独立。 |
| `path_override_block` / `method_override_block` | `True` / `False` | ACL バイパス(X-Original-URL 等)/ メソッドオーバーライド遮断。 |
| `range_check_enabled` | `True` | Range DoS(Apache Killer)対策。 |
| `sec_headers_enabled` | `False` | 応答セキュリティヘッダ注入。 |
| `dlp_enabled` / `dlp_action` | `False` / `audit` | 出口 DLP と動作。`dlp_action` は `audit`(記録のみ)/ `block`(漏洩を検出、または走査不能になった時点で残りを送らず切断)だけを受け付ける。`dlp_max_scan_bytes` は 1〜8388608 バイト。 |
| `open_redirect_enabled` | `False` | オープンリダイレクト無害化。 |
| `strip_cache_poison_headers` | `True` | 非信頼 `X-Forwarded-Host` 等の除去。 |
| `cred_rate_enabled` | `False` | クレデンシャル単位レート制限。 |
| `origin_cloaking_enabled` | `False` | バックエンド・バイパス防止(時間有界トークン)。 |
| `stall_detect_enabled` | `True` | 迂回検知(busy→突然ゼロ)。 |
| `persist_bans` | `True` | BAN を再起動を跨いで永続化(署名付き・ロールバック耐性)。 |
| `trusted_proxies` | `[]` | 信頼 proxy の CIDR(背後で XFF から実IPを採用。既定は XFF 不信)。実際の proxy IP だけに絞る。クライアントも含む範囲は、自己申告 XFF を信頼済み hop と誤認し得る。 |

防御を無効化・過剰延長し得る数値は入力時に拒否します。主な範囲は `range_max_ranges` 1〜64、
`resp_stall_sec` 0〜300、`stall_min_rate` 0 より大きく1000000以下、
`ban_escalation_cap` 1〜1024、`ban_escalation_retain_sec` 0〜2592000、
`cadence_min_samples` 2〜24、`throttle_retry_after` 0〜3600、`appeal_after_sec` 0〜2592000です。
0 が明示的な無効・即時を意味する設定（応答停滞、本文スコア係数、申立待機など）は0を引き続き受け付けます。
署名済みの旧状態に範囲外の値があれば、保護を弱める大きな値は既定値に戻し、
`cfg_load_rejected` に補正したキーを記録します。

> 列挙値のキー(`mode` / `open_redirect_mode` / `geo_mode` / `site_mode` / `ip_mode` / `cookie_samesite` /
> `dlp_action`)は決まった値だけを受け付けます(前後の空白と大小文字は正規化。値の一覧は
> [defenses.md](defenses.md))。それ以外の値は拒否して現在の値を保ち(管理 API・宣言的設定は `rejected` で
> 返す)、以前の版で保存された不正な値は既定値として読みます。

宣言的設定は全項目の検証後に一度だけ保存・公開します。不正な値・未知キー・保存失敗があれば
`ok:false, applied:[]` を返し、以前の設定を保ちます。指定ファイルを適用できない起動は、
前衛ポートを開く前に失敗します。旧版の保存状態を読む互換処理は別に維持します。
指定ファイルは厳格な UTF-8 JSON として読み、重複キー・非有限数を拒否します。主ファイルが欠損・破損しても、
古い `.tmp` を宣言的設定として適用しません(状態ファイルの回復処理とは別)。

HTTP管理APIの `/api/shield/config` と直接の設定APIも、未知キーを拒否します。
既知キーの明示的な `null` や不正なリスト要素を含む更新は、他の正常項目も適用しません。
管理APIの本文は厳格なUTF-8 JSON objectとし、重複キー、非有限数、浮動小数点で表せない数値を拒否します。
旧版の保存状態の読込・移行処理は、新しいAPI入力の検証とは別に扱います。
保存状態の `cfg` 自体が辞書でない場合は警告して既定の防御有効で起動し、破損ファイルを上書きしません。
