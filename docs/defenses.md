# 防御リファレンス — 機能 / 設定キー / 既定値

DuckNet L7 の防御と、それを制御する設定キーの一覧です(`NetShield.cfg` / 管理 API `/api/shield/config` /
宣言的設定 JSON で変更できます)。既定 ON は配備直後から効く低誤検知のもの、opt-in は配備依存で誤検知リスクが
あるため有効化が要るものです。

> 設定例(管理API): `POST /api/shield/config {"sec_headers_enabled": true}`
> または宣言的設定ファイル(`--config config.json` / `DUCKNET_CONFIG`)。

## リクエスト検査

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 内部ファイル公開防止 | `exposure_guard_enabled` | ON | `.env`・VCS内部ディレクトリ・既知のPHP設定等を、初回からスコア閾値に依存せず拒否。通常のログイン画面や公開CSVは一律拒否しない。シールド全体OFFは停止、auditは記録のみ |
| 非公開経路の認可 | `private_paths`, `private_path_allow` | opt-in | 経路prefixを区切り単位で照合し、指定した送信元IP/CIDRだけ許可。空の許可表は全拒否。信頼していない転送IPは使わない。対象応答は共有キャッシュ禁止。配備例は [privacy-protection.md](privacy-protection.md) |
| 侵入シグネチャ | （常時・`paranoia` で厳格度） | ON | SQLi/XSS/RCE/traversal/XXE/SSRF/JNDI/SSI/OGNL/proto/CRLF/NoSQLi/LFI/scanner。多層正規化(多重デコード/Unicode/Log4j入れ子)付き。全角英字や全角の `＜` `＞` などは ASCII へ畳んで照合し、日本語の文で普通に使う全角の `｜` `＄` `（` `）` `；` `｀` は URL・ヘッダ・本文のどれでも記号へ畳まず空白として読む |
| 要求ボディ検査 | `body_scan_enabled`, `body_scan_max_bytes` | ON | POST/JSON/GraphQL 本文を有界・重複ウィンドウで走査(下の注記) |
| 圧縮ボディ解凍 | `body_decode_enabled` | ON | 単一の gzip/deflate を有界解凍してから走査。重複・複数指定の `Content-Encoding` は backend との解釈差を避けるため拒否。GraphQL/アップロード検査が必要な圧縮本文は、復号を無効にした設定でも通さない |
| アップロード検査 | `upload_scan_enabled`, `upload_deny_ext` | ON | multipart のパートと生本文アップロード(要求ヘッダの `Content-Disposition`)の危険拡張子(webshell)を拒否。二重拡張子/NUL 切り/`filename*` 対応(下の注記) |
| メソッドポリシー | `blocked_methods` | ON | TRACE/TRACK/CONNECT 等。`method_override_check`/`method_override_block` で override も |
| パスオーバーライド | `path_override_block` | ON | `X-Original-URL`/`X-Rewrite-URL` 等の ACL 回避を遮断 |
| Range DoS | `range_check_enabled`, `range_max_ranges` | ON | 多数レンジ(Apache Killer)を遮断 |
| スマグリング/フレーミング | （常時） | ON | CL.TE/TE.CL/裸改行/origin-form 強制/パイプライン遮断。重複 User-Agent・Range、および `Connection` が検査・転送上重要なヘッダを接続固有として指名する要求は、audit/enforce と接続クローズ設定にかかわらず拒否。通常の接続指定は許可 |
| GraphQL 防御 | `graphql_enabled`, `graphql_paths`, `graphql_max_depth` ほか | opt-in | 深さ/複雑度/イントロスペクション/バッチの上限(下の注記) |
| JWT 検査 | `jwt_inspect_enabled`, `jwt_allowed_algs` | ON | `alg:none` 遮断。`jwt_allowed_algs` 指定で alg 混同も遮断 |
| ボット整合性 | `bot_consistency_enabled`, `bot_inconsistency_score` | ON | ブラウザ UA 偽装ツールを低FP加点 |

中継者は`Connection`で指名されたヘッダを転送前に除く規則です([RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1))。前衛が検査した値や転送時に付ける値がbackendで欠けるのを避けるため、それらを指名した要求を構造検査で拒否します。

> **要求ボディ検査の範囲**: 本文は UTF-8 として読みます(UTF-8 として不正なバイトだけを latin-1 で
> 1 バイト 1 文字に読み、どのバイトも走査面から消しません)。要求と multipart 各パートの `Content-Type` で
> UTF-8 以外の `charset` が宣言されていれば、その charset で読んだ値も走査します(本文を宣言どおりに読む backend 向け。EBCDIC の
> IBM037 / IBM500 / IBM1047 など、UTF-7、UTF-16/32(BOM が無ければ両方のバイト順)、Shift_JIS・GBK・Big5
> など)。重複した `Content-Type`、同一型内の重複 `charset`、multipart の重複・拡張 `boundary` は
> backend との解釈差を避けるため本文の転送前に HTTP 400 で拒否します。署名走査 ON で読めない
> 要求の `charset`(未知の名前や本文用でない `punycode` など)は遮断モードでは 415、監査モードでは記録して通します。
> パートの宣言が重複・未対応・検査上限外なら本文検査側で遮断します。
> 正直な残余: EBCDIC の本文は UTF-8/latin-1 で読んだ字面も走査するので、
> `-`(0x60)がバッククォートに見えて `rce` に当たることがあります(宣言を無視して ASCII で読む backend に
> 備えて、この読み方は外しません)。本文では改行を空白として扱います(head 側=
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
> JSON 本文(`Content-Type` が JSON か、先頭が `{` / `[` の本文。本文全体で決めるので後ろの窓も同じ)と、
> multipart 中で有効な JSON として読める `operations` / JSON 型のパートだけです。
> 他の検知が見る本文の走査面は変えません。JSON で二重にエスケープされた `\\n`(コード片の文字列リテラル)と、
> フォーム・通常の multipart 値・テキストの本文に書かれた `\n` は字面のままです。URL/ヘッダの走査は従来どおりです。
> 本文の生の改行は通常の走査面では空白として読みます。ただしフォーム形式の値と multipart の通常の
> フォーム値では、改行の直後が既知のヘッダ名・コマンド・SQL 文の形なら、追加の見え方でこの 3 規則を照合します。
> YAML/テキストの行、multipart の枠とパートヘッダ、ファイル部の改行は文書の構造として扱います。
> カスタムシグネチャを含む他の検知が見る本文の走査面では、改行はどれも空白です。
> 本文でも URL/ヘッダと同じく、日本語・中国語の地の文や題名で普通に使う全角の `｜` `＄` `（` `）` `；` `｀` を
> ASCII の記号へ畳まず、空白として読みます(`データ分析の基礎｜Python` のような題名が rce に当たらないように。
> 生の UTF-8・`\uXXXX`・`%XX` のどの送り方でも同じ)。全角英字や全角の `＜` `＞` は ASCII へ畳んで照合します。
> 正直な残余: バックエンド自身が全角を ASCII へ変換する構成(入力へ NFKC を掛けるアプリ、Windows の best-fit
> 変換で全角を ANSI へ落とす部品など)では、これらの全角記号が本物のメタ文字として読まれます。その構成では
> 設定 `fold_fullwidth_punct` を ON にすると、URL・ヘッダ・本文のどれでも前の版と同じく ASCII の記号へ畳んで
> 照合します(既定 OFF。ON では日本語の題名なども前の版と同じく加点されます・[options.md](options.md))。
> multipart(先頭行が `--境界` の本文)は枠を外し、各パートの中身とパートヘッダ(`name` / `filename` など)を別々に走査します。
> `Content-Type`・`filename`・制御バイトはクライアントが選べるため、それだけで署名走査を省略しません。
> 通常の画像や書庫も同じ署名エンジンを通るので、偶然一致による加点の可能性があります。

> **アップロード検査の範囲**: `Content-Type: multipart/*` の要求では各パートの *パートヘッダ*
> (`Content-Disposition` の `filename=` / `filename*=`(RFC 5987 を復号)/ RFC 2231 の継続)を見ます。
> 本文がファイルそのものの生本文アップロード(WordPress REST の `/wp/v2/media` など)では、*要求ヘッダ*
> の `Content-Disposition` のファイル名を同じ読み方・同じ規則で見ます(`Content-Type` は問わず、本文を
> 読む前に検査し、拒否なら backend へ何も送りません)。
> フォームの値や本文中の `filename=` という文字列は対象外です。拒否するのは最終拡張子が
> `upload_deny_ext` に入る名前と、Apache の多重拡張子のように中間セグメントでも実行され得る既知の
> 拡張子(php 系・phtml・phar・cgi・py・asp/aspx・jsp 系・shtml)を中間に含む名前(`shell.php.jpg`)です。
> `www.example.com.har` の `com` のような中間セグメントは見ません。`body_scan_enabled` を OFF に
> した場合も、非圧縮本文の全パートのヘッダと本文終端を backend 接続前に検査します。
> 危険なパートを見つけた時点で拒否します(パート数 10000・1 パートのヘッダ 64KiB または 100 行を超える multipart は遮断)。
> 署名走査 ON・遮断モードでは、復号後の本文全体が `body_scan_max_bytes` 以下の要求だけを転送します。
> 超過は backend 接続前に 413 で拒否します。監査モードでは超過を記録し、従来どおり先頭を走査して通します。
> chunked の枠や gzip/deflate のヘッダは復号後サイズに数えず、生の読取量も別途有界にします。
> `Content-Encoding` で圧縮された multipart は、遮断モードでは圧縮ストリームの終端まで完全に復号でき、
> 復号後の全体が `body_scan_max_bytes` 以下の場合だけパート名を検査して転送します。超過・破損・
> 未対応の符号化は遮断し、監査モードでは検査不能を記録して転送します。非圧縮 multipart の後続パートの逐次検査は署名走査 OFF 時に継続しますが、転送開始前に本文全体の構文を確認します。
> パート内にさらに `multipart/*` が入る形は内側の境界とファイル名を検査し切れないため、遮断モードで拒否し、監査モードでは記録します。
> `body_scan_enabled` を OFF にしてもアップロード検査は止まりません(止めるのは `upload_scan_enabled`)。

> **要求本文の転送境界**: 本文を持つ要求は監査・遮断モード、本文走査のON/OFFを問わず、宣言された `Content-Length` またはchunkedの終端・trailerまでを受信・検証してからbackendへ接続します。wire上限は1要求64MiB、同時進行分の合計256MiB、受信とbackendへの転送にはそれぞれ独立した絶対期限300秒があります。上限超過は413、合計容量を確保できない場合は503で拒否します。POSIXでは256KiBを超える本文を私有の状態ディレクトリに一時退避するため、容量・I/Oを確保してください。Windowsでは本文をメモリに保持します。大容量・対話型アップロードの遅延と最大サイズに影響します。本文長が確定した後のbackend接続は早期に半切断せず、宣言された境界で正確に転送を止めます。HTTPの本文境界を無視してTCPのEOFだけを待つbackendは応答できない場合があります。backendが本文の一部だけで処理を確定する場合、その副作用は転送失敗時にも取り消せません。これを防ぐにはbackend側で全量受信・検証後にトランザクションを確定し、再試行には冪等性を持たせる必要があります。別のHTTPプロキシで要求をバッファするだけではbackend自身の確定時点を制御できません。

> **GraphQL 防御の範囲**: `graphql_paths` は正規化したパス(下の「経路制御のパス照合」)で前方一致します。
> POST 本文(JSON / `application/graphql` / `application/x-www-form-urlencoded` の `query` 欄 /
> multipart の `operations` 欄)と GET の `?query=` の両方を照合します。本文は `graphql_max_bytes`(既定
> 262144)まで読み切って *全体* を解析し、これを超える本文(multipart は `operations` 欄)は検査できない
> ので 413 で拒否します(加点/BAN はしません。監査モードは記録のみ)。JSON の封筒なのに読めない本文や
> 重複キーを含む本文も違反として遮断し、先勝ち・後勝ちのパーサ差で未検査の query が選ばれるのを防ぎます。
> JSON のトップレベルでは `query` の大小文字別名(`Query`・`QUERY`・エスケープしたキーも含む)をすべて検査します。
> 同じ操作の別名はバッチ件数に加算せず、JSON 配列の各要素を1操作として数えます。
> 別名を含む読み方の総数には512件の独立上限があり、超過を検査済みとして通しません。
> `extensions.persistedQuery` を含む要求は、見える `query` の SHA-256 と指定ハッシュが
> すべての大小文字別名で一致するときだけ通常の文書検査へ進みます。文書が無い・空・ハッシュが
> 食い違う場合、保存済み文書をエッジで検査できないため enforce では BAN せず拒否し、audit では
> 記録して転送します。GET の `?extensions=` とフォーム本文にも同じ扱いを適用します。
> `variables` 内の `query` はアプリケーションの入力値として扱い、GraphQL 文書には数えません。
> 本文の符号化は JSON の仕様どおりに判定し(BOM、無ければ先頭 4 バイトの NUL の並び=
> Python の `json.loads` や Jackson と同じ。UTF-16/32 の JSON も読みます)、`Content-Type` で `charset` が
> 宣言されていればその読み方でも照合して、どれか 1 つでも上限を超えるか読めなければ遮断します(backend には
> 判定で読むものと宣言で読むものがあるため)。multipart の `operations` 欄は、パートの `Content-Type` の
> `charset` でも読みます。パートの重複・未対応 `charset`、同名の `operations` パートの重複、
> `operations` パートの不完結も検査不能として遮断します。
> 複雑度(`graphql_max_complexity`・既定 1000)は文書に書かれた選択の数(フィールド。エイリアス
> 付きも 1 個ずつ、`...Fragment` 展開も 1)で、深さは選択セットの入れ子です。引数の入力オブジェクト
> (`where: {a: {b: 1}}`)・文字列・`#` コメントは数えません。名前付きフラグメント(`fragment F on T {…}`)は
> 展開した先まで数えた実効の深さ・選択数(操作ごと)でも照合し、書かれた数と大きい方を上限と比べます
> (2 回ずつ次のフラグメントを展開する連鎖は、書かれた選択が数十個でも実行時には 2^段数 個になります)。
> フラグメントの循環(`F` → `G` → `F`。GraphQL の仕様では無効な文書)は `fragment-cycle` として遮断します。イントロスペクションはフィールド名が
> `__schema` / `__type` のときだけで、クライアントが全選択に付ける `__typename` は対象外です。
> `body_scan_enabled` を OFF にしても GraphQL 防御は止まりません。

> **経路制御のパス照合**: `blocked_urls` / `blocked_extensions` / `path_limits` / `graphql_paths` は、どれも
> 同じ最大72通りのパスで照合します。query/fragment を除き、%エンコードの復号前から最大5段階まで小文字化した形と、
> さらに各セグメントの `;` 以降(パスパラメータ)を除き、`/` の連続を 1 個に畳み、ドットセグメントを解決した形です
> (根より上へは戻らず、末尾の `/` は残します)。`/%61dmin`・`//admin`・`/admin;x=1`・`/public/../admin` は
> どれも `/admin` として照合されます。nginx・Apache・servlet コンテナのように backend がこの形へ解決して
> 配信する構成と、解決前の経路を扱う構成の双方で照合外しを防ぐためです。照合専用で、backend へ転送する要求そのものは
> 変えません。`/admin/../x` は `/admin` の遮断・経路レートを外さず、最後のセグメントの `;` より後ろに
> 置いた拡張子も検査します。経路レートは各解釈で最初に一致した規則を適用し、同じ規則は二重消費しません。
> バックエンドが先に%復号してから `?` / `#` を区切る場合に備え、各復号段階で区切り前後の解釈も照合します。
> 5段階後も経路をさらに%復号できる要求は、backend の解釈を確定できないため遮断します(監査モードでは転送と記録)。
> Windows バックエンドの末尾ドット・空白・代替データストリームの別名も各経路制御で照合します。
> 設定値は通常の解決後の形を推奨します。`blocked_urls` / `path_limits` の設定値は小文字化だけし、
> `graphql_paths` の設定値はセグメントも解決して比較します。

> **外部前衛の遮断リスト**: BAN/ACL の取得や保存が失敗したときは更新失敗を返し、以前の出力を保持します。
> 出力は原子的に置換します。POSIX では既存ファイルの所有者・グループ・モードを保持し、新規ファイルは `0644` です。
> 前衛ユーザーが親ディレクトリを通過できる権限も必要です。生成する Lua は読み込み・容量・上限超過の失敗時に旧遮断を保持し、
> 8 MiB・10万行・1行4096バイトを上限にし、共有辞書は64 MiBです。更新開始時に原子的な試行番号を進め、
> 世代別のBANキーを完成させてから公開します。初回未読・更新中・更新失敗は全要求を444で拒否します。
> 更新担当が途中で停止しても共有ロックは残らず、次の10秒周期で再試行します。後着した旧担当は新世代のBANを消せません。
> 無変更のリストはバイト一致を確認して準備済み世代を更新し、大量のキーを毎回作り直しません。
> 完全一致では表せない CIDR deny がある場合は `ok:false` と `skipped_networks` を返し、以前のファイルを保持します。
> `write_bundle` は両生成物を準備してから、単体のリスト更新と同じ出力ロックで公開します。後段の保存失敗では旧ファイルを復元し、復元も失敗した場合は `ok:false, partial:true` を返します。
> 固定パス2個の置換なので、電源断や出力ロックに参加しない外部の読み手に対する一括commitは保証しません。
> 無効な防御レイヤーのルールは出力しません。監査モードでも登録済みの手動 BAN は本体と同じく遮断対象として出力します。
> 外部前衛の backend は DuckNet に向けて ACL を適用し、アプリ本体を未検査で公開しないでください。

## レート / フラッド / DoS

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| IP レート/フラッド | `flood_threshold`, `window_sec`, `deny_score`, `block_score` | ON | スコア: `deny_score` 以上で単発拒否・`block_score` 以上で自動BAN(累犯エスカレーション) |
| パス別レート | `path_limits`（`set_path_limits`） | opt-in | 認証/高コスト経路を厳格化。プロセス内の合計262144バケツを上限とし、満杯時は現役の制限をリセットせず新しい制限対象を拒否する（監査モードは記録） |
| per-IP 同時接続 | `max_conn_per_ip` | opt-in | 接続枯渇/slowloris 増幅対策 |
| クレデンシャル単位レート | `cred_rate_enabled`, `cred_rate_limit`, `cred_rate_window_sec` | opt-in | トークン/API キー単位(IP ローテーション濫用対策)。窓内 `cred_rate_limit` 件までは通し、超えた要求だけを遮断(既定は加点・BAN なし)。`cred_rate_limit` は 1048576 以下(超える値は拒否。以前の版で保存した上限超えの値は 1048576 として読む) |
| 応答エラーレート | `resp_score_enabled`, `resp_error_threshold` | ON | 4xx 連射(列挙/ブルートフォース)を脅威スコアへ。`resp_error_threshold` は 1〜1048576(範囲外は拒否。以前の版で保存した上限超えの値は 1048576 として読む=実質発火しない)。シールド OFF の間は集計のみで加点しない |
| スロー POST | `body_timeout_enabled`, `body_max_sec` | ON | 要求ボディの総受信時間上限(R-U-Dead-Yet)。本文の走査中に超えた要求は backend へ送らず切断(途中で間が空いても総時間内なら待つ)。本文を読む前に `Expect: 100-continue` で待っている要求には DuckNet が `100 Continue` を返し、backend へは `Expect` を外して渡す |
| サブネット集約 | `subnet_defense`, `subnet_threshold` | opt-in | 分散攻撃を /24・/64 で束ねる |
| データ量クォータ | `quota_max_gb`, `quota_max_conn_sec` | opt-in | 応答中の送出量/接続時間を含めて遮断 |

有限クォータの enforce は同一IPの進行中応答を合算する。送出量には HTTP 応答ヘッダも含め、ヘッダ全体を送れる余地がない場合はヘッダを送らず切断し、本文中に達した場合は上限まで送って接続を切る。このため `Content-Length` や chunked の応答が途中で終わる場合がある。接続時間も応答の読取・送出待ちに適用する。audit は応答を変更せず、超過を記録する。

`--cluster` の複数ワーカー間では Shield の採点・レート・BAN・資格情報窓、ACL の保留承認と監査、proxy の接続数・接続レート、有限クォータの予約をまだ統合していない。これらが有効なら fork 前に理由、`mode: single`、`workers: 1` を返し、単一プロセスで防御する。既定設定はこの条件に該当する。両防御を明示的に OFF にし、接続上限をすべて 0 にした POSIX 配備だけで複数ワーカーを使えるが、集計テレメトリは `telemetry_complete: false` として全体値を表示しない。複数ワーカー稼働中の管理API変更は子ワーカーを停止・回収してから適用し、結果に `cluster_downgraded: true` / `cluster_mode: single` を示す。直接の Python API は共有されない防御への変更を拒否する。外部から署名済み設定が変更された場合は、検証後に転送前で遮断し、ヘルス確認を失敗させる。共有状態所有者が実装・検証されるまで、複数ワーカーで防御を有効にしたまま稼働することはできない。

## レスポンス側

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 出口 DLP | `dlp_enabled`, `dlp_action`, `dlp_max_scan_bytes` | opt-in | 応答headと有界の本文から鍵・トークン・カード番号を検出。`audit`は記録、`block`は漏洩または検査不能時に未判定部分を送らず切断。既に送った部分は取り消さない。折返し等の曖昧head、未対応charset・符号化・アーカイブ、走査上限超過、101切替は検査不能として扱う。JSON文字列のエスケープも逐次復号し、chunkedは枠を外して走査。通常の継続窓64B、先頭アーカイブ識別は262本文B、JSONは384本文Bを保留し、chunk枠行は完結まで保留する。全体auditなら遮断しない。カードは14〜19桁・IIN・Luhnで検証。任意の個人情報全般を識別するものではなく、非公開経路の認可と併用する |
| 応答のHTTP構造検証 | （常時） | ON | HTTP前衛で非HTTP応答、重複本文長、CL/TE併存、不正ヘッダ、過大・未完ヘッダを公開前に拒否。DLP・シールドのOFFや監査モードでも適用。HEAD・204・304等の本文境界を越えた余剰バイトは転送しない |
| origin内部情報の除去 | （常時） | ON | 応答の `X-Origin-IP`、`X-Backend-Server`、`X-Upstream`、`X-Original-IP`、`X-Remote-IP`、`X-Remote-Addr`、`X-Forwarded-Server`、`X-Rewrite-URL`、`X-Original-URL` を除去。中間応答・101にも適用。これらの値をtrailersで送る応答は値の公開前に切断 |
| セキュリティヘッダ注入 | `sec_headers_enabled`, `sec_headers_extra`, `sec_headers_strip` | opt-in | X-Content-Type-Options/Frame-Options/Referrer-Policy ほか |
| Set-Cookie ハードニング | `cookie_harden_enabled`, `cookie_samesite`, `cookie_httponly` | ON | SameSite/Secure(TLS時)/HttpOnly(opt-in)を補完。Cookie名と属性を分け、属性名の空白と最後に指定したSameSite値を[Cookie仕様の解析順序](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-22#section-5.7)で扱う。無効な値で終わる場合は設定したSameSiteを末尾に補う |
| CORS 無害化 | `cors_harden_enabled` | ON | `ACAO:*`/`null` と資格情報の危険併存、重複・連結した Origin 値の解釈差を無害化 |
| オープンリダイレクト | `open_redirect_enabled`, `open_redirect_allow`, `open_redirect_mode` | opt-in | 外部許可外への3xx `Location` と、200などの `Refresh` を安全パスへ書換/記録。複数指定は全件判定する。許可リストのホストはそのサブドメインも許容するため、信頼する親ドメインだけを指定する。IPv6リテラルは角括弧の有無・表記の揺れを問わない。HTTP `Refresh` もブラウザの時間指定遷移に使われる([HTML標準](https://html.spec.whatwg.org/multipage/semantics.html#refresh-state)) |
| キャッシュ汚染ヘッダ除去 | `strip_cache_poison_headers`, `cache_poison_headers` | ON | 非信頼クライアントの `X-Forwarded-Host` 等を除去。CGI/WSGIで同名になる `_`・`-` の保護ヘッダ別名は要求段階で拒否し、除去・差替え時にも同じ別名を扱う |

HTTP応答ヘッダが64KiBを超える場合や構造が曖昧な場合は、任意防御の設定にかかわらず未加工の応答を流さず切断します。NEL/NBSPを含む応答ヘッダ値も下流の空白解釈が割れるため拒否します。DLP有効時は `dlp_unscannable` にも記録します。正しいHTTP構造を持つ本文の未対応charset・符号化・メディア型は、従来どおりDLPのaudit/block設定に従います。
chunked 応答の拡張行は本文の復号後には含まれませんが、通信上には残るため DLP が別途走査します。
応答headの `Location`・`Content-Location`・`Refresh`・`Link` に含まれるURL対象は、ブラウザや受信側が読む1回のパーセント復号後の値も、head公開前にDLPで検査します。監査モードでは元のheadのバイト列を保持します。アプリ固有の2回目以降の復号や任意のヘッダ値の独自解釈までは保証しません。
HTML/XHTML/SVGのURL属性とHTMLのmeta refreshのURL対象も、1回のパーセント復号後を本文公開前に検査します。良性の符号化URLは元のバイト列で転送します。
応答 `Content-Disposition` の保存名は、`filename*`・RFC 2231 の分割パラメータ・受信側によって復号される通常の `filename` をhead公開前にDLPで検査します。重複・欠番・非対応charsetや旧式のencoded-wordなど、保存名の解釈が一意でない場合は検査不能として扱います。遮断モードでは良性の曖昧な保存名も切断し、監査モードでは理由を記録して元のheadを転送します。
本文を持つ `206 Partial Content` は、複数の応答からクライアントが秘密を再構成できるため、DLP有効時に検査不能としてhead公開前に判定します。遮断モードでは良性の部分ダウンロードも切断し、監査モードでは理由を記録して元の通信を転送します。HEADなど本文を持たない応答はこの理由だけで遮断しません。
本文を持つ `226 IM Used` も、[インスタンス操作](https://www.rfc-editor.org/rfc/rfc3229.html#section-10.4.1)の復元後に秘密が現れるため同様に検査不能とします。`IM: deflate` などの元のwireでは「漏れなし」と判定しません。
HTML/XML応答の遮断モードはタグ・文字参照をまたぐ検査のため本文を応答完了まで保留します。保留は応答ごとの `dlp_max_scan_bytes`、全プロセス合計16MiB、応答時間30秒で制限し、上限超過は検査不能として扱います。
HTMLの`srcdoc`属性は別のHTML文書として再解釈されるため、DLP有効時は検査不能として扱います。遮断モードでは良性の`srcdoc`を含む応答も本文を送らず切断し、監査モードでは理由を記録して元の通信を転送します。
HTML（および実行可能なXHTML/SVG）の`script`・`style`要素、`style`属性、`on*`イベント属性、URL属性の`data:`・`javascript:`も、静的走査後に別の解釈で秘密を組み立て得るため同様に検査不能とします。遮断モードではこれらを含む通常のページも本文を読めません。
JavaScript/ECMAScript と `text/css` の応答は、実行時の文字列連結やエスケープを静的DLPで同じ意味へ復元できないため、DLP有効時に検査不能として応答head公開前に判定します。`dlp_action=block` では良性のスクリプト・スタイル資産も読み込めなくなります。`audit` または全体の `mode=audit` では理由を記録して元の通信を転送し、DLP無効時は従来どおりです。HTML内のスクリプト実行や他の不透明なメディア形式まで完全に評価するものではありません。
非公開経路の `Cache-Control: private, no-store` を後続のtrailerで覆すことはできません。キャッシュ制御、Cookie、CORS、リダイレクト、セキュリティヘッダの制御に使うtrailerは、任意の監査/遮断設定でも値を公開する前に切断します。通常の公開データのtrailerはそのまま転送します。
`sec_headers_extra` は最大128件、名前はASCII tokenの128文字以内、値はLatin-1で16KiB以内、総量32KiB以内です。改行・HTAB以外の制御文字、構造やorigin内部情報に使う予約名、大小文字だけ異なる重複名は設定全体を拒否します。旧署名状態の無効要素は読まずに警告を記録し、不正な追加ヘッダを使う設定では応答headを公開しません。

## 認証情報 / 信頼 / その他

| 防御 | 主な設定キー | 既定 | 概要 |
|---|---|---|---|
| 信頼 proxy / 実IP | `trusted_proxies` | opt-in | 背後構成で XFF/XFP を信頼(未設定=一切信頼しない) |
| サイト allowlist | `site_mode`, `site_whitelist` | opt-in | Host(ドメイン)許可。Host インジェクション対策。`site_mode` は `off` / `whitelist` / `blacklist`。`whitelist` には `site_whitelist` が 1 件以上必要(下の注記) |

> **サイト allowlist の空リスト**: `site_mode=whitelist` で `site_whitelist` が空になる変更(リストが空のまま
> `whitelist` に切り替える・`whitelist` 運用中に最後の 1 件を消す/`[]` にする/全消去する)は、管理 API
> (`/api/shield/config`)・リスト編集(`NetShield.edit_list`)・宣言的設定(`--config` / `DUCKNET_CONFIG`)の
> どこからでも拒否され、何も適用されません(`ok:false` と理由を返します。宣言的設定も全項目を検証し、
> 不正項目があれば全体を拒否します)。空白だけの項目は空とみなします。非空のリストと
> `site_mode=whitelist` を同じ変更で指定すれば受理されます。
> 以前の版で保存済みの「`whitelist` + 空リスト」は、更新で締め出さないよう従来どおり **全 Host を許可** したまま
> 動作します(`ip_mode=whitelist` / `geo_mode=allow` の空リストは全遮断なので、ここだけ逆です)。この状態は
> `/api/state` の `shield.warnings`(`code: site_whitelist_empty`)と、起動時 1 回のシステムイベント
> (`site_whitelist_empty`)で通知されます。許可する Host を `site_whitelist` に追加するか、`site_mode` を `off`
> にしてください。

## 自己防衛 / 改竄耐性

[docs/hardening.md](hardening.md) を参照(状態 HMAC 署名・自動起動登録・OS 公認の
クラッシュ自動再起動・ハードニング)。関連環境変数: `DUCKNET_STATE_KEY`(外部署名鍵)。

> **署名状態の改竄と fail-closed**: 稼働中の cfg は MAC で周期照合し、API を通らない書換えを
> 見つけると署名済み状態か最後に検証済みのメモリ値へ復元します。起動時に署名済みの
> `state.json`・`rules.json`・`blocklist.json` を検証できない場合は、失われた私有経路・
> カスタム規則・BAN を復元できないため、enforce では backend への転送を拒否します。
> `traffic.json` を検証できない場合も、有限の送出量・接続時間クォータが有効なら同様に拒否します。
> 署名済みの監査設定が読める場合は転送と would-block 記録を行います。検証不能な状態を
> 空・既定値で自動再署名せず、`flush_state` も成功を報告しません。破損した `.hw` や古い
> `.hw.tmp` で高水位を下げず、復元した正署名状態は DuckNet **アプリの再起動**で読み直します
> (BAN は検証済み `reload_bans` でも回復)。初回起動の欠損と旧版の無署名状態は別に扱います。
> 本体と有効な `.hw` の整合的な巻き戻し、または全履歴の完全削除は、外部の単調な信頼源なしに
> 初回状態と区別できません。

> **ACL の署名実績**: `acl.json` は Shield の `.state_signed` とは別に `.acl_signed` を持ちます。
> 正署名 ACL の読込時にこのマーカーを確保できない場合や、既存のマーカーが通常ファイルでない場合は、
> ACL を適用せずファイアウォール ON・全ゾーン拒否で起動します。ACL の保存時もマーカーの確保に失敗すれば
> 更新を公開せず失敗を返します。

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

backend が要求本文を読み切る前に厳格なHTTP形式の最終4xx/5xxを返した場合、DuckNetは残りの本文転送を止めます。backend の応答ヘッダ・本文は転送せず、4xxは同じ数値、5xxは502のDuckNet生成応答に置き換え、通常の応答検査・4xx採点・有限クォータに通します。壊れた早期応答は成功として返しません。早期の2xx/3xxは本文転送が終わるまで成功として公開しません。backendが早期2xx/3xxを返して本文を読まなくなった場合は、backend書込み期限（最大でも本文転送の総期限300秒）まで待って切断することがあり、成功とは報告しません。

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
| `rate_per_sec` | `20.0` | IP毎の定常許容レート。0〜1000000 の有限値。負値は拒否し、旧署名済み状態の範囲外値は安全な範囲へ補正する |
| `burst` | `40` | バースト許容。1〜1000000 の整数 |
| `force_conn_close` | `True` | backendへ転送する要求の`Connection`を`close`へ書き換える。Falseでも要求本文の終端で転送を止め、パイプラインの2本目は送らない。保護対象のヘッダを`Connection`で接続固有に指定した要求は拒否する |
| `throttle_response` | `True` | throttle時に 429 を返す(ブラウザには自動で再試行する案内ページ。False=即時切断・無応答) |
| `throttle_retry_after` | `1` | 429 の Retry-After 秒(クライアントへの再試行目安) |
| `subnet_window_sec` | `3600` | BAN を集計する時間窓(秒) |
| `subnet_score` | `30` | hot サブネットの新規IPへ一度だけ加える score(deny_score未満=ソフト) |
| `origin_header` | `"X-Edge-Token"` | トークンを載せるヘッダ名(中立名・バックエンドと合わせる)。ヘッダ名に使える文字(RFC 9110 の token)だけを受け付け、前後の空白は落とす(以前の版で保存された不正な値は既定値として読む) |
| `origin_window_sec` | `30` | トークンの時間バケット幅(リプレイ窓・時計ずれ吸収)。設定範囲 1〜3600 秒。 |
| `stall_min_rate` | `1.0` | 「直近 busy」とみなす最小レート(req/s)。これ未満は静観 |
| `slowloris_score` | `50` | ヘッダ未完(slowloris)1回あたりの加点(反復でBAN) |
| `resp_error_window_sec` | `60` | 4xx 集計窓(1〜3600 秒)。`cred_rate_window_sec` も同じ範囲。 |
| `resp_error_score` | `50` | 閾超過1回あたりの加点(note_response は block_score のみ判定=1 バーストはスコア記録に留め即 BAN しない)。2 バーストで block_score(100)→BAN |
| `cred_rate_score` | `0` | 上限を超えた要求の送信元 IP への加点(0=加点しない)。共有キー(アプリ埋込・公開キー)では、攻撃者が窓を超えさせ続けると同じキーを使う正規利用者の IP に加点が乗り拒否/BAN させられるため、キーが利用者ごとに固有の配備でのみ設定してください。以前の版で保存された値は読み込まず 0 として扱います(この版で設定し直した値は保存されます) |
| `resp_stall_sec` | `0.0` | 応答方向の slow-read 対策: 1 応答の転送中に client の受信(drain)を待った *累積* 秒の上限。超えたら切断+加点。0=無効(SSE/長時間ストリーム/低速回線の大容量 DL を壊さない) |
| `open_redirect_safe_path` | `"/"` | enforce 時に書き換える同一オリジンのパス。単一 `/` で始まり、`//`・逆斜線・制御文字を含まない値だけ受け付ける(旧版の不正値は既定値として読む)。 |
| `graphql_max_complexity` | `1000` | 選択(フィールド。エイリアス付きも 1 個ずつ)数の上限(エイリアス/フィールド増幅対策)。名前付きフラグメントは展開した先まで数える。旧版は `{` の数を数えていた(既定 100)。旧版で保存した 100 はそのまま残るので、大きな正規クエリを遮断しないよう見直してください |
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
| `quota_window_days` | `1` | 集計窓(1〜30日。0・負数・巨大値は設定全体を拒否) |
| `site_blacklist` | `(空)` | `site_mode=blacklist` のときに拒否する Host(ドメイン)の一覧 |
| `ip_mode` | `"off"` | `off` / `whitelist` / `blacklist` — IP/CIDR リストの動作 |
| `ip_whitelist` | `(空)` | `ip_mode=whitelist` のときに通す IP/CIDR の一覧(空=全遮断) |
| `ip_blacklist` | `(空)` | `ip_mode=blacklist` のときに拒否する IP/CIDR の一覧 |
| `usage_record` | `True` | ホスト別の利用状況(リクエスト数等)を記録する |
| `score_halflife_sec` | `30.0` | スコア半減期 |
| `cadence_score` | `35` | 機械的規則性を検知した時の加点 |
| `cadence_min_samples` | `8` | 判定に要する最小サンプル数(上限 24=IP ごとに保持する間隔の数。超える値は拒否し、以前の版で保存された値は 24 に丸めます) |
| `cadence_cv_threshold` | `0.15` | 変動係数(これ未満=規則正しすぎ=機械)。0 より大きく 1 以下、負値・ゼロは拒否 |
| `cadence_max_mean_interval` | `3.0` | 平均間隔がこれ超なら対象外(遅い正規ポーラを誤検知しない)。0.01〜3600、かつ最小平均間隔より大きい値だけ受理 |
| `cadence_min_mean_interval` | `0.01` | これ未満=バースト(µs〜ms)はビーコンでなく flood/レート制限の対象。0〜3600、かつ最大平均間隔より小さい値だけ受理 |
| `optional_sigs` | `(空)` | 高FPシグネチャの個別 ON/OFF(`paranoia` を上げると自動で入る) |

クォータの数値は `quota_max_gb` が 0〜1,000,000 GB、`quota_max_conn_sec` が
0〜1,000,000,000 秒、`quota_window_days` が 1〜30 日。上限値 0 はその軸を無制限にする
明示設定であり、負数・NaN・無限大・範囲外の更新は以前の設定を保って拒否する。
旧版が署名保存した不正値は、クォータ有効時にはそのファイルを自動再署名せず設定状態を
検証不能として扱う(enforce は遮断、audit は転送し「遮断予定」を記録)。
クォータ無効時には旧版の実効値(負の上限=0、非正の日数=1)へ正規化し警告する。
