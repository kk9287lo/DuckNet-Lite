# 防御リファレンス — 機能 / 設定キー / 既定値

DuckNet L7 の防御と、それを制御する設定キーの一覧です(`NetShield.cfg` / 管理 API `/api/shield/config` /
宣言的設定 JSON で変更できます)。既定 ON は配備直後から効く低誤検知のもの、opt-in は配備依存で誤検知リスクが
あるため有効化が要るものです。

> 設定例(管理API): `POST /api/shield/config {"sec_headers_enabled": true}`
> または宣言的設定ファイル(`--config config.json` / `DUCKNET_CONFIG`)。

## リクエスト検査

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 侵入シグネチャ | （常時・`paranoia` で厳格度） | ON | SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI/SSI/OGNL/proto/CRLF/NoSQLi/LFI/scanner。多層正規化(多重デコード/Unicode/Log4j入れ子)付き。全角英字や全角の `＜` `＞` などは ASCII へ畳んで照合し、日本語の文で普通に使う全角の `｜` `＄` `（` `）` `；` `｀` は URL・ヘッダ・本文のどれでも記号へ畳まず空白として読む |
| 要求ボディ検査 | `body_scan_enabled`, `body_scan_max_bytes` | ON | POST/JSON/GraphQL 本文を有界・重複ウィンドウで走査(下の注記) |
| 圧縮ボディ解凍 | `body_decode_enabled` | ON | gzip/deflate を有界解凍してから走査(圧縮回避封じ) |
| アップロード検査 | `upload_scan_enabled`, `upload_deny_ext` | ON | multipart のパートと生本文アップロード(要求ヘッダの `Content-Disposition`)の危険拡張子(webshell)を拒否。二重拡張子/NUL 切り/`filename*` 対応(下の注記) |
| メソッドポリシー | `blocked_methods` | ON | TRACE/TRACK/CONNECT 等。`method_override_check`/`method_override_block` で override も |
| パスオーバーライド | `path_override_block` | ON | `X-Original-URL`/`X-Rewrite-URL` 等の ACL 回避を遮断 |
| Range DoS | `range_check_enabled`, `range_max_ranges` | ON | 多数レンジ(Apache Killer)を遮断 |
| スマグリング/フレーミング | （常時） | ON | CL.TE/TE.CL/裸改行/origin-form 強制/パイプライン遮断 |
| GraphQL 防御 | `graphql_enabled`, `graphql_paths`, `graphql_max_depth` ほか | opt-in | 深さ/複雑度/イントロスペクション/バッチの上限(下の注記) |
| JWT 検査 | `jwt_inspect_enabled`, `jwt_allowed_algs` | ON | `alg:none` 遮断。`jwt_allowed_algs` 指定で alg 混同も遮断 |
| ボット整合性 | `bot_consistency_enabled`, `bot_inconsistency_score` | ON | ブラウザ UA 偽装ツールを低FP加点 |

> **要求ボディ検査の範囲**: 本文は UTF-8 として読みます(UTF-8 として不正なバイトだけを latin-1 で
> 1 バイト 1 文字に読み、どのバイトも走査面から消しません)。本文では改行を空白として扱います(head 側=
> パス/クエリ/ヘッダは従来どおり改行を `;` に読み替えます)。本文の `;` は CSV の区切りや地の文の句読点
> でもあるので、`;` を手がかりにする検知は本文では文脈が揃うときだけ当てます: スタック複文(`sqli-stacked`)
> は `;` の後に SQL 文の構文(`update 名前 set` / `delete from` / `insert into` / `select … from` /
> `drop`・`create`・`alter` + `table` など / `truncate table` / `exec xp_…` / `union select` /
> `grant … on … to`)が続くとき、コマンド連結(`rce` の `;` 分岐)は `;` の後のコマンドが引数(`-` で始まる
> フラグ・パス・`$` 変数・リダイレクト・URL・IPv4・`host.tld/`)を伴うとき、`crlf` は既知の応答ヘッダ名と
> その値の形(`set-cookie:名前=` / `location:URL` / `to:宛先@…` など)の直前に `;` があるときだけです。
> この 3 つ(`sqli-stacked`・`rce` の `;` 分岐・`crlf`)の照合では、値に符号化して入れた改行(`%0D%0A`・
> `&#10;`・`\u000a`・JSON 本文の短いエスケープ `\r\n` / `\n` など、復号で現れた改行。urlencoded・JSON・
> multipart のフォーム値のどれでも)も字面の
> `;` と同じに読みます(値がリダイレクト先・Cookie・コマンド・SQL 文に入るときの注入で、URL/ヘッダ側と
> 同じ形)。JSON の短いエスケープ(`JSON.stringify` が改行を書く形。`\t` は空白)を値の改行として読むのは
> JSON 本文(`Content-Type` が JSON か、先頭が `{` / `[` の本文。本文全体で決めるので後ろの窓も同じ)だけで、
> 他の検知が見る本文の走査面は変えません。JSON で二重にエスケープされた `\\n`(コード片の文字列リテラル)と、
> フォーム・multipart・テキストの本文に書かれた `\n` は字面のままです(正直な限界: multipart の部の中身や
> フォーム値に入れた JSON の短いエスケープは、値の改行として読みません)。URL/ヘッダの走査は従来どおりです。本文の生の改行(YAML/テキストの行・multipart の枠と
> パートヘッダの区切り)は文書の構造とみなし、この 3 つの照合でも空白のまま読みます(正直な限界: フォーム値に
> 符号化せず生の改行で入れた後のヘッダ・コマンド・SQL 文の形は当たりません)。
> カスタムシグネチャを含む他の検知が見る本文の走査面では、改行はどれも空白です。
> 本文でも URL/ヘッダと同じく、日本語・中国語の地の文や題名で普通に使う全角の `｜` `＄` `（` `）` `；` `｀` を
> ASCII の記号へ畳まず、空白として読みます(`データ分析の基礎｜Python` のような題名が rce に当たらないように。
> 生の UTF-8・`\uXXXX`・`%XX` のどの送り方でも同じ)。全角英字や全角の `＜` `＞` は ASCII へ畳んで照合します。
> 正直な残余: バックエンド自身が全角を ASCII へ変換する構成(入力へ NFKC を掛けるアプリ、Windows の best-fit
> 変換で全角を ANSI へ落とす部品など)では、これらの全角記号が本物のメタ文字として読まれます。その構成では
> 設定 `fold_fullwidth_punct` を ON にすると、URL・ヘッダ・本文のどれでも前の版と同じく ASCII の記号へ畳んで
> 照合します(既定 OFF。ON では日本語の題名なども前の版と同じく加点されます・[options.md](options.md))。
> multipart(先頭行が
> `--境界` の本文)は枠を外し、各パートの中身とパートヘッダ(`name` / `filename` など)を別々に走査します。
> 署名走査しないのは
> 次の 2 つだけです: (1) multipart の *ファイル* パート(`filename` 付き)で中身に制御バイトを含むもの、
> (2) multipart でない本文のうち、`Content-Type` がバイナリ型(`application/octet-stream`・protobuf/gRPC・
> `image/*`・`audio/*`・`video/*`・`font/*`・zip/gzip/tar などの圧縮/書庫形式・`application/pdf` など)で、
> *かつ* 走査する先頭(`body_scan_max_bytes`)にタブ/CR/LF 以外の制御バイトを含むもの(`metrics` の
> `body_binary_skipped` に数えます)。テキスト型(JSON・フォーム・`text/*`・`image/svg+xml` などの
> `+xml` / `+json`)の本文と、`Content-Type` が無い/重複している本文は中身に関わらず走査し、バイナリ型
> でも中身がテキストなら走査します。署名走査しない本文/パートでも、アップロード検査はファイル名を見ます。
> 正直な限界: バイナリ型を宣言し制御バイトを混ぜた本文は署名走査されません(その本文を backend が
> テキストとして解釈する構成では死角になります)。

> **アップロード検査の範囲**: `Content-Type: multipart/*` の要求では各パートの *パートヘッダ*
> (`Content-Disposition` の `filename=` / `filename*=`(RFC 5987 を復号)/ RFC 2231 の継続)を見ます。
> 本文がファイルそのものの生本文アップロード(WordPress REST の `/wp/v2/media` など)では、*要求ヘッダ*
> の `Content-Disposition` のファイル名を同じ読み方・同じ規則で見ます(`Content-Type` は問わず、本文を
> 読む前に検査し、拒否なら backend へ何も送りません)。
> フォームの値や本文中の `filename=` という文字列は対象外です。拒否するのは最終拡張子が
> `upload_deny_ext` に入る名前と、Apache の多重拡張子のように中間セグメントでも実行され得る既知の
> 拡張子(php 系・phtml・phar・cgi・py・asp/aspx・jsp 系・shtml)を中間に含む名前(`shell.php.jpg`)です。
> `www.example.com.har` の `com` のような中間セグメントは見ません。本文が `body_scan_max_bytes` を超える
> 場合も、残りを転送しながら全パートのヘッダを検査し、危険なパートを見つけた時点で転送を止めて
> backend 接続を切ります(パート数 10000・1 パートのヘッダ 64KiB または 100 行を超える multipart は検査
> できないので遮断。検査の時間はヘッダと本文の長さに比例します)。
> 正直な限界: `Content-Encoding`(gzip 等)で圧縮された multipart は、解凍できた先頭だけを検査します。
> `body_scan_enabled` を OFF にしてもアップロード検査は止まりません(止めるのは `upload_scan_enabled`)。

> **GraphQL 防御の範囲**: `graphql_paths` は正規化したパス(下の「経路制御のパス照合」)で前方一致します。
> POST 本文(JSON / `application/graphql` / `application/x-www-form-urlencoded` の `query` 欄 /
> multipart の `operations` 欄)と GET の `?query=` の両方を照合します。本文は `graphql_max_bytes`(既定
> 262144)まで読み切って *全体* を解析し、これを超える本文(multipart は `operations` 欄)は検査できない
> ので 413 で拒否します(加点/BAN はしません。監査モードは記録のみ)。JSON の封筒なのに読めない本文は
> 違反として遮断します。複雑度(`graphql_max_complexity`・既定 1000)は文書に書かれた選択の数(フィールド。エイリアス
> 付きも 1 個ずつ、`...Fragment` 展開も 1)で、深さは選択セットの入れ子です。引数の入力オブジェクト
> (`where: {a: {b: 1}}`)・文字列・`#` コメントは数えません。イントロスペクションはフィールド名が
> `__schema` / `__type` のときだけで、クライアントが全選択に付ける `__typename` は対象外です。
> `body_scan_enabled` を OFF にしても GraphQL 防御は止まりません。

> **経路制御のパス照合**: `blocked_urls` / `blocked_extensions` / `path_limits` / `graphql_paths` は、どれも
> 同じ正規化をしたパスで照合します。query/fragment を除き、%エンコードを(二重まで)復号して小文字化し、
> 各セグメントの `;` 以降(パスパラメータ)を除き、`/` の連続を 1 個に畳み、ドットセグメントを解決します
> (根より上へは戻らず、末尾の `/` は残します)。`/%61dmin`・`//admin`・`/admin;x=1`・`/public/../admin` は
> どれも `/admin` として照合されます。nginx・Apache・servlet コンテナのように backend がこの形へ解決して
> 配信する構成で、書き方を変えただけの照合外しを防ぐためです。照合専用で、backend へ転送する要求そのものは
> 変えません。設定値も解決後の形で書いてください。`blocked_urls` / `path_limits` の値は小文字化だけして
> 比べるので、`..`・`//`・`;` を含む値は当たりません(`graphql_paths` は値にも同じ正規化をします)。最後の
> セグメントの `;` より後ろに置いた拡張子は `blocked_extensions` で見ません。正直な限界: backend がドット
> セグメントや `;` を解決せず生のパスで経路を決める構成(Node/Express など)でも、照合は解決後の形で
> 行います。遮断/経路レート/GraphQL の対象パスの後ろに `..` を置いたパス(`/admin/../x`)は解決後の `/x` で
> 照合されて対象を外れます。

## レート / フラッド / DoS

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| IP レート/フラッド | `flood_threshold`, `window_sec`, `deny_score`, `block_score` | ON | スコア: `deny_score` 以上で単発拒否・`block_score` 以上で自動BAN(累犯エスカレーション) |
| パス別レート | `path_limits`（`set_path_limits`） | opt-in | 認証/高コスト経路を厳格化 |
| per-IP 同時接続 | `max_conn_per_ip` | opt-in | 接続枯渇/slowloris 増幅対策 |
| クレデンシャル単位レート | `cred_rate_enabled`, `cred_rate_limit`, `cred_rate_window_sec` | opt-in | トークン/API キー単位(IP ローテーション濫用対策)。窓内 `cred_rate_limit` 件までは通し、超えた要求だけを遮断(既定は加点・BAN なし)。`cred_rate_limit` は 1048576 以下(超える値は拒否。以前の版で保存した上限超えの値は 1048576 として読む) |
| 応答エラーレート | `resp_score_enabled`, `resp_error_threshold` | ON | 4xx 連射(列挙/ブルートフォース)を脅威スコアへ。`resp_error_threshold` は 1〜1048576(範囲外は拒否。以前の版で保存した上限超えの値は 1048576 として読む=実質発火しない)。シールド OFF の間は集計のみで加点しない |
| スロー POST | `body_timeout_enabled`, `body_max_sec` | ON | 要求ボディの総受信時間上限(R-U-Dead-Yet)。本文の走査中に超えた要求は backend へ送らず切断(途中で間が空いても総時間内なら待つ)。本文を読む前に `Expect: 100-continue` で待っている要求には DuckNet が `100 Continue` を返し、backend へは `Expect` を外して渡す |
| サブネット集約 | `subnet_defense`, `subnet_threshold` | opt-in | 分散攻撃を /24・/64 で束ねる |
| データ量クォータ | `quota_max_gb`, `quota_max_conn_sec` | opt-in | egress 持ち出し量/接続時間で遮断 |

## レスポンス側

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 出口 DLP | `dlp_enabled`, `dlp_action`, `dlp_max_scan_bytes` | opt-in | 応答 head と本文先頭 `dlp_max_scan_bytes`(1 以上)を走査し、秘密情報(鍵/トークン/カード番号)の漏洩を検出。`dlp_action` は `audit`(記録のみ)/ `block`(その応答を送らず切断)。伏字化(マスク)はしない。全体 `mode=audit` の間は `block` も記録のみ。有効時は backend へ `Accept-Encoding: identity` を渡して無圧縮で返させ、それでも圧縮で返った本文は `dlp_unscannable` として `dlp_action` どおりに扱う。chunked は枠を外して走査する。カード番号は 14〜19 桁+主要ブランドの IIN+Luhn(13 桁の JAN/EAN は対象外)。`block` は判定前の末尾(最大 64B)を次の読取まで保留し、backend が 0.2 秒黙れば放出する(SSE は保留しない) |
| セキュリティヘッダ注入 | `sec_headers_enabled`, `sec_headers_extra`, `sec_headers_strip` | opt-in | X-Content-Type-Options/Frame-Options/Referrer-Policy ほか |
| Set-Cookie ハードニング | `cookie_harden_enabled`, `cookie_samesite`, `cookie_httponly` | ON | SameSite/Secure(TLS時)/HttpOnly(opt-in)を補完 |
| CORS 無害化 | `cors_harden_enabled` | ON | `ACAO:*`/`null` + 資格情報の危険併存を無害化 |
| オープンリダイレクト | `open_redirect_enabled`, `open_redirect_allow`, `open_redirect_mode` | opt-in | 外部許可外への 3xx を安全パスへ書換/記録。ホストはポートを除いて比べ、IPv6 リテラルは角括弧の有無・表記の揺れを問わない(`[2001:db8::1]:8080` と `2001:db8::1` は同じ) |
| キャッシュ汚染ヘッダ除去 | `strip_cache_poison_headers`, `cache_poison_headers` | ON | 非信頼クライアントの `X-Forwarded-Host` 等を除去 |

## 認証情報 / 信頼 / その他

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 信頼 proxy / 実IP | `trusted_proxies` | opt-in | 背後構成で XFF/XFP を信頼(未設定=一切信頼しない) |
| サイト allowlist | `site_mode`, `site_whitelist` | opt-in | Host(ドメイン)許可。Host インジェクション対策。`site_mode` は `off` / `whitelist` / `blacklist`。`whitelist` には `site_whitelist` が 1 件以上必要(下の注記) |

> **サイト allowlist の空リスト**: `site_mode=whitelist` で `site_whitelist` が空になる変更(リストが空のまま
> `whitelist` に切り替える・`whitelist` 運用中に最後の 1 件を消す/`[]` にする/全消去する)は、管理 API
> (`/api/shield/config`)・リスト編集(`NetShield.edit_list`)・宣言的設定(`--config` / `DUCKNET_CONFIG`)の
> どこからでも拒否され、何も適用されません(`ok:false` と理由を返します。宣言的設定では site 系のキーだけが
> `rejected` に入り、他のキーは通常どおり適用されます)。空白だけの項目は空とみなします。非空のリストと
> `site_mode=whitelist` を同じ変更で指定すれば受理されます。
> 以前の版で保存済みの「`whitelist` + 空リスト」は、更新で締め出さないよう従来どおり **全 Host を許可** したまま
> 動作します(`ip_mode=whitelist` / `geo_mode=allow` の空リストは全遮断なので、ここだけ逆です)。この状態は
> `/api/state` の `shield.warnings`(`code: site_whitelist_empty`)と、起動時 1 回のシステムイベント
> (`site_whitelist_empty`)で通知されます。許可する Host を `site_whitelist` に追加するか、`site_mode` を `off`
> にしてください。

## 自己防衛 / 改竄耐性

[docs/hardening.md](hardening.md) を参照(状態 HMAC 署名・自動起動登録・OS 公認の
クラッシュ自動再起動・ハードニング)。関連環境変数: `DUCKNET_STATE_KEY`(外部署名鍵)。

> **設定の改竄と fail-closed**: 稼働中は in-memory の cfg を MAC で周期照合し、API を通らない書換えを
> 見つけると署名検証済みの `state.json` から復元します。`state.json` も同時に改竄・削除・巻き戻しされて
> いて検証できないときは、最後に MAC が一致した cfg を保ち、それも照合できなければ既定値+シールド ON に
> 倒します(どれも `memory_tamper` を記録。`verify_cfg_integrity()` の `source` は `disk` / `memory` /
> `defaults`)。起動時に `state.json` が改竄・巻き戻し・削除・平文すり替えで読めず、この鍵で署名保存した
> 実績(`.hw` サイドカーか `.state_signed` マーカー)があるときは、既定値+シールド ON で起動し、
> `state_tamper` とシステムイベント `cfg_fail_closed` を記録します(直前の値は分からないので、直前が
> OFF でも ON で起動します)。初回起動と、設定を一度も保存していない `state.json` の欠損は従来どおり
> 既定値(OFF)で、改竄の記録もしません。既存の state dir で `DUCKNET_STATE_KEY` を替えると旧鍵の署名を
> 検証できないので、同じく既定値+ON と改竄の記録つきで起動します(設定を入れ直してください)。正直な
> 限界: `state.json` と `.hw` の両方を消されると、設定を一度も保存していない状態と区別できず既定値(OFF)
> で記録なしに起動します。署名実績のある状態ファイルの *削除* は、その起動で記録したうえで既定値(`state.json`
> は既定値+シールド ON)を署名して保存し直すので、同じ削除を起動のたびに記録し続けることはありません(再び
> 消されれば再び記録します。中身の改竄・すり替え・巻き戻しはファイルを残したまま起動のたびに記録します)。

## 訪問者に返す応答(ブラウザ / API)

拒否したときの応答本文は、要求の `Accept` で切り替えます。ブラウザの画面遷移(`Accept` に `text/html` があり、
`application/json` などの JSON 型より優先し、さらに画面遷移らしい要求=`Accept` に `application/xhtml+xml` がある・
`Sec-Fetch-Mode: navigate` / `Sec-Fetch-Dest: document`・ブラウザの `User-Agent`(`Mozilla/…`)のどれか)には、
何が起きたか・次に何をすればよいかを書いた短い HTML ページを返します。API クライアント(`Accept: application/json`・
`*/*`・`Accept` 無し・Java `HttpURLConnection` の既定 `Accept` など)には従来どおりの JSON を返します(本文は同じ)。
状態コード・`Retry-After`・デセプションのヘッダはどちらでも同じで、HTML には `Cache-Control: no-store` が付きます。
ページの言語は遮断ページと同じく `DUCKNET_LANG`(未設定なら OS ロケール)で選び、表示名は `DUCKNET_COVER` で
差し替えられます。判定理由・規則名・スコアは出しません。ページの末尾に発生時刻(UTC)を出すので、訪問者からの
問い合わせをイベントの時刻と突き合わせられます。

| 状態 | 場面 | ブラウザに表示する内容 |
|---|---|---|
| 429 | レート超過(`throttle_response`) | 約 N 秒後(`throttle_retry_after`、最短 1 秒)にまた使えること。N 秒後に元の URL を自動で再読み込みし(JS 無効でも meta refresh)、「今すぐ再試行」ボタンも出す |
| 502 | バックエンド不達 | サイトに一時的に接続できない・しばらく待って再試行・続くなら管理者へ |
| 400 | 本文境界が曖昧/単一値ヘッダの食い違い/壊れた chunked 本文 | 処理できなかった理由を一文で・再読み込み(または再送信) |
| 413 | `graphql_max_bytes` を超える GraphQL 本文 | データが大きすぎる(上限も表示)・小さくして再送信 |
| 415 | 解けない `Content-Encoding` | 圧縮形式に対応していない・圧縮せずに再送信 |
| 431 | ヘッダ過大 | Cookie などが大きすぎる・このサイトの Cookie を削除して再試行 |
| 403 | `/__ducknet_appeal__`(BAN されていない) | ブロックされていない・前のページに戻って再読み込み |

## 段階的な導入
1. まず既定 ON のまま監査(`mode=audit`)で運用し、誤検知を観察します。
2. 配備に合う opt-in を audit モードから入れます(`open_redirect_mode=audit`)。
3. 問題なければ enforce へ。全体の厳格度は `paranoia` で調整できます。

## 設定キー全一覧(補遺)

上の表で触れていない設定キーです。既定値は `NetShield._DEFAULTS`(唯一の真実)から取っています。
値の意味が上の表と重なるものは、そちらの説明を優先してください。
列挙値のキー(`mode` / `open_redirect_mode` / `geo_mode` / `site_mode` / `ip_mode` / `cookie_samesite` /
`dlp_action`)は、ここと上の表に書いた値だけを受け付けます(前後の空白と大小文字は正規化します。
`open_redirect_mode` は `enforce` / `audit`、`cookie_samesite` は `Lax` / `Strict` / `None` / 空文字=付けない)。
それ以外の値は拒否して現在の値を保ち、以前の版で保存された不正な値は既定値として読みます。

| 設定キー | 既定 | 概要 |
|---|---|---|
| `rate_per_sec` | `20.0` | IP毎の定常許容レート |
| `burst` | `40` | バースト許容 |
| `force_conn_close` | `True` | 応答へ `Connection: close` を強制し、keep-alive 越しの検査回避を防ぐ |
| `throttle_response` | `True` | throttle時に 429 を返す(ブラウザには自動で再試行する案内ページ。False=即時切断・無応答) |
| `throttle_retry_after` | `1` | 429 の Retry-After 秒(クライアントへの再試行目安) |
| `subnet_window_sec` | `3600` | BAN を集計する時間窓(秒) |
| `subnet_score` | `30` | hot サブネットの新規IPへ一度だけ加える score(deny_score未満=ソフト) |
| `origin_header` | `"X-Edge-Token"` | トークンを載せるヘッダ名(中立名・バックエンドと合わせる)。ヘッダ名に使える文字(RFC 9110 の token)だけを受け付け、前後の空白は落とす(以前の版で保存された不正な値は既定値として読む) |
| `origin_window_sec` | `30` | トークンの時間バケット幅(リプレイ窓・時計ずれ吸収) |
| `stall_min_rate` | `1.0` | 「直近 busy」とみなす最小レート(req/s)。これ未満は静観 |
| `slowloris_score` | `50` | ヘッダ未完(slowloris)1回あたりの加点(反復でBAN) |
| `resp_error_window_sec` | `60` | 4xx 集計窓 |
| `resp_error_score` | `50` | 閾超過1回あたりの加点(note_response は block_score のみ判定=1 バーストはスコア記録に留め即 BAN しない)。2 バーストで block_score(100)→BAN |
| `cred_rate_score` | `0` | 上限を超えた要求の送信元 IP への加点(0=加点しない)。共有キー(アプリ埋込・公開キー)では、攻撃者が窓を超えさせ続けると同じキーを使う正規利用者の IP に加点が乗り拒否/BAN させられるため、キーが利用者ごとに固有の配備でのみ設定してください。以前の版で保存された値は読み込まず 0 として扱います(この版で設定し直した値は保存されます) |
| `resp_stall_sec` | `0.0` | 応答方向の slow-read 対策: 1 応答の転送中に client の受信(drain)を待った *累積* 秒の上限。超えたら切断+加点。0=無効(SSE/長時間ストリーム/低速回線の大容量 DL を壊さない) |
| `open_redirect_safe_path` | `"/"` | enforce 時に書き換える安全な遷移先(`Location` にそのまま書くので、改行などの制御文字を含む値は拒否。以前の版で保存された不正な値は既定値として読む) |
| `graphql_max_complexity` | `1000` | 選択(フィールド。エイリアス付きも 1 個ずつ)数の上限(エイリアス/フィールド増幅対策)。旧版は `{` の数を数えていた(既定 100)。旧版で保存した 100 はそのまま残るので、大きな正規クエリを遮断しないよう見直してください |
| `graphql_block_introspection` | `True` | フィールド `__schema`/`__type` を遮断(本番のスキーマ漏洩防止。`__typename` は対象外) |
| `graphql_max_batch` | `10` | バッチ(配列)オペレーション数の上限 |
| `graphql_max_bytes` | `262144` | GraphQL 本文を全体解析する上限バイト。超える本文は 413 で拒否(加点しない) |
| `ban_escalation_retain_sec` | `86400` | 累犯回数(ban_count)を再起動越しに覚えておく窓(BAN期限切れ後) |
| `block_page` | `True` | 遮断時に HTML の説明ページを返す(False=応答せずに接続を切る) |
| `appeal_enabled` | `True` | 遮断ページに『解除リクエスト(異議申立)』を表示 |
| `appeal_after_sec` | `120` | BANから この秒数 経過後にのみ解除リクエストを表示(数分後) |
| `mode` | `"enforce"` | `enforce`(遮断)/ `audit`(遮断せず記録のみ。出口 DLP の `block` と、単一値ヘッダの重複(enforce では 400)も記録のみになる) |
| `blocked_extensions` | `(空)` | 遮断する拡張子(例 .env .sql .bak .git .ini) |
| `blocked_urls` | `(空)` | 遮断するURL部分文字列(例 /admin /wp-admin) |
| `require_tls` | `False` | 正規TLS以外(平文)を遮断(X-Forwarded-Proto=https 必須) |
| `geo_mode` | `"off"` | `off` / `allow` / `block` — `geo_cidrs` による地域判定の動作 |
| `geo_cidrs` | `(空)` | 地域判定に使う CIDR 一覧(GeoIP DB 不要) |
| `quota_enabled` | `False` | 送出量/接続時間クォータの集計と超過判定を有効化 |
| `quota_window_days` | `1` | 集計窓(1〜N日) |
| `site_blacklist` | `(空)` | `site_mode=blacklist` のときに拒否する Host(ドメイン)の一覧 |
| `ip_mode` | `"off"` | `off` / `whitelist` / `blacklist` — IP/CIDR リストの動作 |
| `ip_whitelist` | `(空)` | `ip_mode=whitelist` のときに通す IP/CIDR の一覧(空=全遮断) |
| `ip_blacklist` | `(空)` | `ip_mode=blacklist` のときに拒否する IP/CIDR の一覧 |
| `usage_record` | `True` | ホスト別の利用状況(リクエスト数等)を記録する |
| `score_halflife_sec` | `30.0` | スコア半減期 |
| `cadence_score` | `35` | 機械的規則性を検知した時の加点 |
| `cadence_min_samples` | `8` | 判定に要する最小サンプル数(上限 24=IP ごとに保持する間隔の数。超える値は拒否し、以前の版で保存された値は 24 に丸めます) |
| `cadence_cv_threshold` | `0.15` | 変動係数(これ未満=規則正しすぎ=機械) |
| `cadence_max_mean_interval` | `3.0` | 平均間隔がこれ超なら対象外(遅い正規ポーラを誤検知しない) |
| `cadence_min_mean_interval` | `0.01` | これ未満=バースト(µs〜ms)はビーコンでなく flood/レート制限の |
| `optional_sigs` | `(空)` | 高FPシグネチャの個別 ON/OFF(`paranoia` を上げると自動で入る) |
