# Changelog

本プロジェクトの主要な変更点。日付は概ねの目安。詳細は各コミット(`evolution #N`)を参照。

## [Unreleased] — 細心のバグ総点検(2026-10)

### 管理設定画面の対応更新(2026-11-10)

- ACL一覧・削除とゾーン別ポリシーを既存APIへ接続し、ネットワーク図のBAN/解除を対称にした。
- イベント理由・署名・監査動作の詳細と出力、上位送信元等の操作表、保持範囲に合うチャートを追加。
- 認証をマスク入力のロック画面へ変更。メモリ保持を維持し、再入力と起動ID更新、応答のサイズ・総期限を検証する。
- トレイの別起動本体検証、明示確認付きトークンコピー、操作不能な状態表示を既存認証へ接続。
- 配列・辞書を構造化編集し、追従保存バーと変更前後の比較を追加。cover表示へ固定の製品名を出さない。
- 既存の全113設定を14分類の詳細設定画面へ接続。日英の説明、型、入力例、実際の許容範囲を表示する。
- 未保存の入力を自動更新から保護し、変更項目だけを一括保存。設定の版が変わった場合は競合として拒否する。
- 全体の遮断・監査モードを画面に表示・設定できるようにし、DLPの表示を実効動作に合わせる。
- 設定項目を追加した際にGUIメタデータの不足を検出する試験と、画面の保存・再表示・競合の回帰試験を追加。

フル版と Lite を横断した総点検で挙がった候補のうち、Lite に該当するものを修正した。すべて回帰
テスト付きで、修正を外すとそのテストが落ちることを 1 本ずつ確認している(`tests/test_sweep_*.py`)。

### 運用者に見える挙動の変化
- **トレイで防御の ON/OFF が分かる**: 5秒ごとに管理API(`/api/state`)のHMAC応答を検証する。
  自分で起動した子は専用内部鍵、別起動した数値loopbackの本体は設定済み管理トークンによる要求署名と
  応答MACを使い、生トークンは送らない。単なる401や製品名だけでは本人確認しない。
  ONは通常アイコン、OFF・監査・未確認は淡色アイコンにし、ツールチップと右クリックに状態を表示する。
  監査中は検知による遮断を記録に替えるが、曖昧なHTTP構文や検証不能な内容の拒否は継続する。
  防御の切替はダッシュボードで行う。手順と表示は [docs/dashboard.md](docs/dashboard.md) を参照。
- **Explorer が再起動してもトレイアイコンが消えたままにならない**: Explorer が再起動する(異常終了・Windows の
  更新・手動の再起動)と通知領域は作り直され、以前はトレイを起動し直すまでアイコンが消えていた。Windows が送る
  `TaskbarCreated` を受けてアイコンを追加し直す。出すのはその時点の最新の表示(防御 OFF なら淡色アイコンと
  OFF のツールチップ)で、起動時の表示には戻らない。ログオン直後など Explorer より先に起動して追加に失敗して
  いたトレイも、このときに出る。管理者として起動している場合に備え、このメッセージだけは通常権限の Explorer
  からも受け取る(UIPI の受信許可。管理者での起動はテストでは確かめていない)。
- **自動起動の結果表示**: `--install-autostart` / `--uninstall-autostart` は結果を JSON のまま出さず、成否の
  1 行・登録先・確認方法・取り消し方・失敗時の「次の手順」を平文で出す(表示言語は `DUCKNET_LANG`、未設定なら
  OS のロケール)。結果をスクリプトで読む場合は **`--json` を付ける** と従来とまったく同じ JSON を出す
  (終了コードは従来どおり)。
- **`run.bat` の `DUCKNET_PYTHON`**: 引用符を外した値が既存のファイルなら 1 つの実行ファイルとして起動する
  (`C:\Program Files\Python312\python.exe` のような空白入りのパスを、引用符の有無を問わず書ける)。それ以外は
  従来どおり `py -3` / `py -3.12` や「引用符付きのパス+引数」のようなコマンド行として起動する。`app.env` の値は
  `load_env_file` と同じく前後の空白と 1 組の引用符を外してから使う。指定の Python を起動できないときは
  「Python 3.10 以上が必要です」ではなく `DUCKNET_PYTHON` の値を確かめるよう案内する(終了コードは従来どおり 9)。
- **`run.bat` の余計なエラー表示**: 日本語版 Windows(cp932 のコンソール)で `run.bat` を起動するたびに
  「'...' は、内部コマンドまたは外部コマンド、…として認識されていません。」が 1 回出ていた(UTF-8 の日本語の
  注釈で cmd が読み位置を誤り、注釈の切れ端をコマンドとして実行していた。起動そのものは続いていた)。注釈を
  英語(ASCII)にした。コマンド・表示する文言・`chcp 65001` の扱いは変えていない。
- **Windows の自動起動は登録し直す(ソースツリー配置)**: 旧版の `--install-autostart` が pip install なしの
  ソースツリー(解凍・clone したフォルダ)から登録したタスク/Run キーは、System32 で起動して `dataplane` を
  import できず、**サインイン時・起動時に一度もゲートウェイを起動していなかった**(登録は成功と表示)。
  更新しても既存の登録は書き換わらないので、`--install-autostart`(Run キーなら `--install-autostart runkey`。
  `onstart`・`--autostart-name` も前回と同じ指定)をもう一度実行して上書きする。タスクスケジューラへは
  タスク定義(XML)で登録し、開始位置(配置先)を渡す。`schtasks /tr` の 261 文字の上限が無くなり、
  python.org 既定のユーザー単位 Python や `--config` 付きのふつうの指定でも登録できる。常駐向けに、
  既定の「72 時間で停止」「バッテリー駆動では起動しない/止める」は外した(旧版で登録したタスクには残っている
  ので、pip install の配置でも登録し直すとよい)。
- **訪問者に返す画面**: レート超過(429)・サイト側の一時障害(502)・送信内容の不備(400/413/415/431)・
  異議申し立ては、ブラウザには「何が起きたか+次にすること」(何秒後に再試行するか、再読み込み、ファイルを
  小さく、Cookie の削除、管理者への連絡など)の画面を返す。API クライアント(`Accept` が HTML を優先しない
  要求)には従来と同じ JSON を返す。HTML を返すのは画面遷移らしい要求(`Accept` に `application/xhtml+xml`・
  `Sec-Fetch-Mode: navigate` / `Sec-Fetch-Dest: document`・ブラウザの `User-Agent` のどれか)だけで、
  Java `HttpURLConnection` の既定 `Accept`(`text/html, image/gif, …`)は JSON のまま。
- **ダッシュボードの表示**: 「詳細分析」は JSON の羅列ではなく見出し付きの集計で表示する。通信断・認証切れ・
  操作の失敗は、原因と次の一手を平文で出す。検知の厳格度の変更と、監査ログからのその「元に戻す」は、成功しても
  「失敗」と表示されていた(`/api/shield/paranoia` は成功時に `ok: true` を返す)。設定の警告バッジは英語表示
  では英語で出す。
- **管理 API**: Cookie 認証の POST は `Content-Type: application/json` 必須(それ以外は 415)。
  Origin/Referer はホストに加えて **ポートも** 照合する(Host をポート抜きに書き換えるリバース
  プロキシは `DUCKNET_ADMIN_ALLOWED_HOSTS` へ登録)。読めない本文(chunked・上限超・途中切れ・
  JSON object 以外)は 400 でルートを実行しない。`on` / `approve` は真偽値必須。
- **承認待ちの `approve()` / `deny_pending()` の既定は一時扱い**。恒久ルールは `remember: true` を
  明示したときだけ書く。
- **重複した単一値ヘッダは 400**(`Authorization` / `X-API-Key` / `X-HTTP-Method-Override` 系など)。
  重複を `, ` で連結して読むと JWT 検査やメソッド制限をすり抜けられた。`mode=audit` では拒否せず、
  audit イベント(`rule: dup_header`)に記録して転送する。
- **`Expect: 100-continue`**: 本文を検査する要求では DuckNet が `100 Continue` を返し、backend へは
  `Expect` を外して渡す。本文の検査中は、途中で間が空いても `body_max_sec` の総時間内なら待つ(この版の
  途中では、100 を待つクライアントや 10 秒の間が空いた送信が黙って切断されていた)。
- **空の `site_whitelist` で `site_mode=whitelist` にする設定は拒否**(管理 API・リスト編集・
  宣言的設定のすべて)。旧版が保存した whitelist+空 は締め出さないよう全 Host 許可のまま維持し、
  status の `warnings`・起動表示・ダッシュボードで警告する。
- **署名付き状態ファイルの手動削除**: 署名済みサイドカー(`.hw`)が残っていると、次の起動で改竄警報
  (`state_tamper`)を出し、既定値(`state.json` は既定値+シールド ON)を署名して保存し直す。同じ削除で
  起動のたびに警報し続けることはない(再び消されれば再び警報する)。中身の改竄・平文すり替え・巻き戻しは
  ファイルを残したまま起動のたびに警報する。警報なしで初期化するときは `.hw` も消す。
- **`--cluster` を systemd で使う場合は `KillMode=mixed` を推奨**([docs/hardening.md](docs/hardening.md))。
- **ログのローテーションが要求処理を止めない(Windows)**: 読み手がログを開いている間(PowerShell の
  `Get-Content -Wait` など)はローテーションを見送り、5 秒後以降の追記で試し直す(それまでは上限を超えて
  追記を続ける・世代は削らない)。以前は要求ごとに約 0.43 秒待ち、その間要求処理が止まっていた。
  アプリ層 FW の記録は、ログを開けなければ待たずにその 1 行を諦める。管理 API の監査ログは従来どおり
  短く待って行を残す。
- **前衛向け BAN リスト(`edge_banlist.txt`)の形式**: 1 行 1 個の単一 IP(正規形。`/32`・`/128` は単一 IP
  へ寄せる)だけを有効行にする。ファイアウォールの CIDR の deny 規則(`198.51.100.0/24` など)は `#` で
  始まるコメント行として末尾に列挙し(生成した前衛設定の Lua は完全一致なので、以前の版でも CIDR には
  当たっていなかった)、`export_banlist()` の戻り値 `skipped_networks` でも返す(`count` は単一 IP の数)。
  このファイルを geo/deny など CIDR を扱える仕組みで読んでいた場合は、コメント行の CIDR を別途その設定へ入れる。
- **要求ボディの読み方**: 本文は UTF-8 として読み(不正なバイトだけ latin-1 で 1:1)、改行は `;` ではなく
  空白として扱う(パス/クエリ/ヘッダは従来どおり `;`)。multipart は枠を外し、パートの中身とパートヘッダを
  別々に走査する。普通のブラウザのアップロードやフォームの改行が crlf/sqli/rce に当たって加点・BAN されて
  いた誤検知が無くなる([docs/defenses.md](docs/defenses.md))。
- **本文の全角記号はメタ文字にしない**: 要求本文では、日本語・中国語の地の文や題名で普通に使う全角の
  `｜` `＄` `（` `）` `；` `｀` を ASCII の `|` `$` `(` `)` `;` `` ` `` へ畳まず、空白として読む(生の UTF-8・
  `\uXXXX`・`%XX` のどの送り方でも同じ)。`データ分析の基礎｜Python` のような題名を保存するたびに rce に
  当たって 42 点(単発拒否の `deny_score` 超)が入り、続けて 3 回保存すると BAN されていた(以前の版でも
  フォーム送信の `%XX` や `\uXXXX` で送った値は当たり、この版の途中では本文を UTF-8 として読むようにした
  ことで生の UTF-8 の JSON も当たっていた)。全角英字や全角の `＜` `＞` は従来どおり ASCII へ畳んで検知する。パス/クエリ/ヘッダも同じに読む(次項)。
- **URL/ヘッダの全角記号もメタ文字にしない**: パス・クエリ・ヘッダ値の走査でも、上と同じ全角の `｜` `＄`
  `（` `）` `；` `｀` を記号へ畳まず空白として読む(`%XX`・`\uXXXX`・数値文字参照・生のどの送り方でも同じ)。
  ブラウザが送る検索 `?q=データ分析の基礎｜Python` や、その検索ページから来た `Referer` は、以前の版から
  1 回で rce 等に当たって 60 点(単発拒否の `deny_score` 超)になっていた。全角英字や全角の `＜` `＞` は
  従来どおり ASCII へ畳んで検知する([docs/defenses.md](docs/defenses.md))。
- **新しい設定 `fold_fullwidth_punct`(既定 OFF)**: ON にすると、上の 2 項の全角 `｜` `＄` `（` `）` `；` `｀` を
  URL・ヘッダ・本文のどれでも前の版と同じく ASCII の記号へ畳んで照合する(題名などの加点も前の版と同じに戻る)。
  **ON にするのは**、保護するバックエンド自身が全角を ASCII へ変換する場合だけ(入力へ NFKC を掛けるアプリ、
  Windows の best-fit 変換で全角を ANSI へ落とす部品など)。既定の挙動は変わらない。管理 API・宣言的設定から
  変更でき、true/false 以外は拒否する([docs/options.md](docs/options.md))。
- **バイナリ本文は署名走査しない**: バイナリのファイルパートと、`Content-Type` がバイナリ型
  (`application/octet-stream`・protobuf・`image/*`・`audio/*`・`video/*`・zip・pdf など)*かつ* 中身もバイナリ
  (タブ/CR/LF 以外の制御バイトを含む)の本文。ランダムなバイト列が rce に当たり、64KB で約 42 点(単発拒否の
  `deny_score` 超)になっていた。省いた本文は metrics の `body_binary_skipped` に数える。テキスト型・型が無い/
  重複・中身がテキストの本文は従来どおり走査する。
- **アップロード検査**: 生本文アップロード(要求ヘッダ `Content-Disposition` の `filename` / `filename*`。
  WordPress REST の media など)にも拡張子ポリシーを掛け、拒否なら backend へ何も送らない。multipart では
  `filename*`(RFC 5987)と RFC 2231 の継続を復号し、本文先頭 64KiB より後ろのパートも転送しながら検査する。
  二重拡張子は最終拡張子と既知の実行拡張子(php 系など)だけを見る(`www.example.com.har` を `.com` で遮断
  しない)。パートヘッダ以外の `filename=` という文字列では遮断しない。`body_scan_enabled=false` でも
  アップロード検査と GraphQL 防御は止まらない。
- **multipart の検査時間**: 上のパートヘッダの検査と、本文の署名走査で multipart をパートに分ける処理は、
  どちらも入力の長さに比例する時間で済む(この版の途中では、`Content-Disposition` の行が揃うたびにヘッダ塊
  全体を読み直して行数の 2 乗で時間が延び、害の無い行を 1500 回繰り返した小さな要求 1 本でイベントループが
  約 2.6 秒止まった。パートに分ける処理も `body_scan_max_bytes` を 1 MiB に上げた構成で約 5.5 秒かかった)。
  **1 パートのヘッダが 100 行を超える multipart** は、ヘッダ 64KiB 超と同じく検査できないものとして遮断する
  (実在のパートは折り返し込みでも十数行)([docs/defenses.md](docs/defenses.md))。
- **GraphQL**: 本文は新設の `graphql_max_bytes`(既定 262144)まで全体を解析し、超える本文は 413(加点・
  BAN なし)。`graphql_max_complexity` は選択したフィールド(エイリアス込み)の数で数え、既定を 1000 に
  上げた(旧版で保存した 100 はそのまま残るので見直す)。GET の `?query=`・urlencoded の `query=`・
  multipart の `operations` も検査する。`__typename` はイントロスペクション扱いしない。`graphql_paths` は
  正規化したパスで照合する。
- **GraphQL(符号化とフラグメント)**: 本文の符号化を JSON の仕様どおりに判定する(BOM、無ければ先頭の NUL の
  並び=Python の `json.loads` や Jackson と同じ)。以前は本文を常に latin-1 で読み、UTF-16/32 の JSON 本文を
  「GraphQL でない」か深さ 1 の文書と見て、深さ・複雑度の上限を素通りさせていた(backend はその本文を読む)。
  `Content-Type` で `charset` が宣言されていればその読み方(EBCDIC・Shift_JIS など。BOM の無い UTF-16/32 は
  両方のバイト順)でも照合し、どれか 1 つでも上限を超えるか読めなければ遮断する(multipart の `operations` 欄は
  パートの `Content-Type` の `charset` でも読む)。名前付きフラグメントは展開した
  先まで数えた実効の深さ・選択数(操作ごと)でも照合する。以前は `...F` を 1 選択と数えるだけで、2 回ずつ次の
  フラグメントを展開する 16 段の連鎖(実行時は 65536 選択)を 34 選択として通していた。フラグメントの循環は
  `fragment-cycle` として遮断する。解決は再帰しない(5 万段の連鎖も入力長に比例する時間で数える)
  ([docs/defenses.md](docs/defenses.md))。
- **地域判定(`geo_cidrs`)**: `::ffff:a.b.c.d` を IPv4 として `geo_cidrs` と照合する(proxy は以前から正規化して
  渡すので、`NetShield.inspect` を直接呼ぶ使い方だけが該当。以前は `geo_mode=block` が効かず、`allow` では
  許可した地域の IPv4 クライアントも遮断した)。
- **表示名(`DUCKNET_COVER`)**: 管理画面の Server ヘッダ・題名と遮断ページへ入れる前に制御文字を除く(CRLF の
  env ファイルから読むと末尾に CR が残り、Server ヘッダの行がそのまま壊れていた)。空・空白だけの値は未設定として
  製品名を出す(以前はアイコンの判定と食い違い、空の名前を出していた)。
- **偽バナー(`DUCKNET_DECEPTION`)**: Tomcat(`Apache-Coyote`)の偽バナーに PHP の `X-Powered-By` を付けない
  (系統を Apache と数えていたため、嘘が内部で矛盾していた)。
- **本文の署名走査(宣言された charset)**: `Content-Type` で UTF-8 以外の `charset` が宣言された本文は、その
  charset で読んだ字面も走査する(EBCDIC の IBM037/IBM500/IBM1047・UTF-7・UTF-16/32・Shift_JIS 等。Python に
  無い IBM1047 は IBM037 との差の 6 字を置き換えて読む)。以前は本文を UTF-8/latin-1 でしか読まず、宣言どおりに
  読む backend(Java の Servlet/Spring 等)には EBCDIC や UTF-7 で書いた本文が素通りだった。`Content-Type` が
  重複していても、どれの `charset` でも読む。charset の名前は別名表と実在する codec で確かめてから引く
  (未知の名前をそのまま引くと Python の codec の表に 1 件ずつ溜まり続ける)。
- **出口 DLP**: 有効時は backend へ `Accept-Encoding: identity` を渡す(それでも圧縮で返った本文は
  `dlp_unscannable` として `dlp_action` どおり)。chunked は枠を外し、読取の切れ目をまたいで走査する。
  カード番号は主要ブランド(Maestro・RuPay は登録された番号範囲)の IIN+14〜19 桁+Luhn(13 桁の JAN/EAN
  や、どのブランドの範囲にも入らない注文番号などは対象外)。全体 `mode=audit` の間は
  `block` も記録のみ。audit では応答を保留しない(block でも SSE/101 は保留せず、他も backend が 0.2 秒
  黙れば送る)。`dlp_action` は `audit` / `block` だけ、`dlp_max_scan_bytes` は 1 以上だけを受け付ける。
- **シールド OFF の間は応答側で加点しない**: 4xx 連射の採点と penalize(slowloris・slow-read など)は何も
  しない(OFF の間に溜まった BAN で、ON に戻した直後の正規の利用者が 403 になっていた)。
  `resp_error_threshold` は 1 以上。
- **件数閾値の上限**: `resp_error_threshold` と `cred_rate_limit` は 1048576 以下だけを受け付ける(超える値は
  拒否)。以前の版で「実質無効」として保存した巨大な値(1 億など)は 1048576 として読む(既定値の 50 / 600 には
  戻さないので、更新で 4xx の加点や API キーの遮断が突然始まることはない)。
- **誤検知の修正(cadence / JWT)**: 規則的なポーリングへの加点は検知エピソードごとに 1 回にした(毎要求
  加点して約 10 秒で拒否/BAN になっていた)。`alg` を持たない 3 区切りトークン(itsdangerous 形式など)は
  JWT とみなさない(本物の `alg:none` は従来どおり即時 BAN)。`cadence_min_samples` は 24 以下(旧版の
  保存値は 24 に丸める)。
- **カスタムシグネチャ**: 大小を区別せずに照合し、組込シグネチャが先に当たっても評価して最も重い weight で
  採点する。weight 0 は記録のみ(加点しない)。件数は最大 256(超える追加は拒否、読込時の超過分は無効として
  残す)。組込と同名の規則は拒否し、同名で追加すると編集(置き換え)になる。無効化された規則は一覧に
  `active=false` と理由で残る。`body_sig_weight_factor=0` は本文ヒットを記録のみにする。
  weight は 0〜1000: 1000 を超える有限の値は 1000 として扱う(追加は受け付けて `warnings` で知らせ、以前の版で
  保存した weight 5000 などの規則も有効のまま。1000 でも 1 回の一致で BAN 閾値を大きく超える)。NaN・無限大・
  負の値は拒否し、保存済みなら無効(`active=false`)として一覧に残す。
- **`paranoia` / `optional_sigs` の検証**: `paranoia` は 1〜4、`optional_sigs` は任意シグネチャ名と真偽値
  だけを受け付け、不正な値は拒否して現在の設定を保つ(`apply_config` は rejected と報告)。
- **クレデンシャル単位レート**: `cred_rate_score` が効くようになった(既定 0=加点なし。旧版の保存値 40 は
  読み込まない)。上限 N に対して N 件まで通し、N+1 件目から遮断する(1 件ずれていた)。
- **ダッシュボードの集計**: メソッド別は既知メソッドと遮断設定したメソッドだけを個別に数え、他は OTHER に
  まとめる。全体レートは同じ時刻に届いた要求も数える(Windows の粗い時計で過小表示されていた)。
- **経路制御のパス照合**: `blocked_urls` / `blocked_extensions` / `path_limits` / `graphql_paths` は、
  %デコード・小文字化に加えて `;` のパスパラメータを除き、`/` の連続を畳み、ドットセグメントを解決した
  パスで照合する(`//admin`・`/admin;x=1`・`/public/../admin` も `/admin` として当たる)。照合専用で、転送する
  要求は変えない。設定値も解決後の形で書く(`..`・`//`・`;` を含む `blocked_urls` / `path_limits` の値は
  当たらない)。生のパスで経路を決める backend(Node/Express など)でも照合は解決後の形になる
  ([docs/defenses.md](docs/defenses.md))。
- **保存済み設定の一部要素の読み捨て**: 以前の版で保存したリスト/辞書の設定から読まなかった要素(文字列で
  ない `blocked_urls` の項目など)は、システムイベント `cfg_load_rejected` の `elements` にキーごとの件数で
  記録する(以前は記録が無く、次の保存で設定ファイルからも黙って消えていた)。
- **ゾーンID付きの IPv6**: `ip_whitelist` / `ip_blacklist` の項目、手動 BAN/解除、保存済みの BAN の
  `fe80::1%eth0` はゾーンを外した `fe80::1` として扱う(proxy が接続元のゾーンを外して判定するので、以前の版で
  書いたゾーン付きの項目が一致せず、許可リストでは締め出し・遮断リストと BAN では素通りになっていた)。
- **設定の改竄で防御を止めない(fail-closed)**: `state.json` とメモリ上の cfg を同時に改竄されると、整合
  チェックの復元が既定値(シールド OFF)に倒れて WAF が止まっていた。稼働中は最後に検証できた cfg を保ち
  (それも照合できなければ既定値+シールド ON)、起動時は署名保存の実績があるのに `state.json` が改竄・
  巻き戻し・削除されていれば、既定値+シールド ON で起動して `state_tamper` 警報と `cfg_fail_closed`
  イベントを出す。初回起動と、一度も保存していない `state.json` の欠損は従来どおり OFF。既存の state dir で
  `DUCKNET_STATE_KEY` を替えた起動も ON+警報になる([docs/hardening.md](docs/hardening.md) 1.4)。
- **列挙値キーの検証**: `mode` / `open_redirect_mode` / `geo_mode` / `site_mode` / `ip_mode` /
  `cookie_samesite` も決まった値だけを受け付ける(前後の空白と大小文字は正規化。綴り違いを黙って受理し、
  意図と違うモードで動いていた)。保存済みの不正な値は既定値として読む。以前の版が保存した大文字小文字違いの
  綴り(`ip_mode=Whitelist`・`geo_mode=Allow` など)は以前は効いていなかったので、正規化して読んだ結果この版で
  効き始めるキーは、status の `warnings`・起動表示・ダッシュボード・システムイベント `cfg_enum_normalized` で
  名指しする(許可リストが空なら全遮断になることも添える)。`body_sig_weight_factor` の負の値は
  拒否する(保存済みの負の値は 0=記録のみとして読む)。HTTP ヘッダへそのまま書く `origin_header` はヘッダ名の
  token だけ、`open_redirect_safe_path` は改行などの制御文字を含まない値だけを受け付ける。
- **本文の `;` を手がかりにする検知**: 要求本文では、スタック複文(`sqli-stacked`)は `;` の後に SQL 文の構文が
  続くとき、`rce` の `;` 連結はコマンドが引数を伴うとき、`crlf` は既知の応答ヘッダ名とその値の形が続くとき
  だけ当てる(`Looks good; update the changelog` のような地の文や CSV の区切りが加点されていた)。この 3 つ
  (`crlf`・`rce` の `;` 連結・`sqli-stacked`)は、値に符号化して入れた改行(`%0D%0A`・`&#10;`・`\u000a` など、
  復号で現れた改行)を `;` と同じに読み、その後に続くヘッダの形・引数を伴うコマンド・SQL 文の構文も数える
  (本文の改行を空白にした修正で見えなくなっていた。例: フォーム値の `%0a%0aselect a from b` は `sqli-stacked`)。
  他の検知(カスタムシグネチャを含む)は値の改行も空白として読む。生の改行(YAML/テキストの行・multipart の枠)は
  文書の構造として数えず、空白のまま読む。URL/ヘッダの走査は従来どおり([docs/defenses.md](docs/defenses.md))。
- **JSON 本文の `\r\n`(短いエスケープ)も値の改行**: 上の 3 つの照合は、JSON 本文(`Content-Type` が JSON か、
  先頭が `{` / `[` の本文)では `JSON.stringify` が改行を書く形 `\r\n` / `\n` も `%0D%0A`・`\u000a` と同じ値の改行
  として読む(以前は `\u000a` の形だけが当たり、同じ値を標準の形で送ると数えなかった)。他の検知が見る本文の
  走査面は変えない。JSON の文章の改行(複数行のコメント・住所・コード片)、二重にエスケープされた `\\n`、
  フォーム・multipart・テキストの本文に書かれた `\n` は従来どおり 0 点。

## [Lite] — ライセンスを GNU AGPL-3.0-or-later に変更

DuckNet-Lite 自体のライセンスを、従来のテンプレート的な商用ライセンス文言(「評価利用のみ許諾・
商用再配布/SaaS提供には別途契約」)から、正式な **GNU Affero General Public License v3.0 以降**
へ変更した。上位(商用)エディションの DuckNet 本体はこの変更の対象外(従来の商用ライセンス
モデルのまま)。

- `LICENSE.txt` を GNU AGPL-3.0 の公式全文(gnu.org 配布のもの)に差し替え、本製品への適用ヘッダを
  先頭に付与。
- `pyproject.toml` に `License :: OSI Approved :: GNU Affero General Public License v3 or later
  (AGPLv3+)` 分類子を追加(`license = {file = "LICENSE.txt"}` は既存のまま有効)。
- `THIRD_PARTY_NOTICES.txt`: 本製品自体のライセンスへの参照節を追加。ついでに、round-1 の
  enterprise/ 削除後も残っていた `dataplane/enterprise/ed25519.py` への古い参照(既に存在しない
  パス)を除去。
- `tools/gen_sbom.py`/`sbom.cdx.json`: コンポーネントのライセンスを `AGPL-3.0-or-later`
  (SPDX識別子)に更新し、SBOM を再生成。
- `README.md`: ライセンス節を AGPL の内容(特に第13条のネットワーク経由利用時のソース提供義務)
  を明記する形に更新。
- `NEXT_STEPS.md`: 「LICENSE.txt がテンプレート文言のまま」という既知の未解消項目を解消済みとして
  更新。

## [Lite-5] — 第5次縮小: ハニーポット(囮URLパス)を削除

free / trial ティアから、偵察AI/スキャナ向けの **囮URLパス**(隠し管理フォルダ・バックアップ・
資格情報・期限切れ特権アカウントを匂わせる名前を運用者が登録し、命中したら一発即時BANする
仕組み)を削除。侵入シグネチャ・レート制限・脅威スコア・自動BAN・サブネット集約など他の検知系は
無関係な別機構のため一切変更していない。

- **削除(`engine/lifeform/pipeline.py`)**: 設定キー `honeypots`(既定値の囮URL一覧を含む)、
  `add_honeypot()`/`remove_honeypot()`(evolution #84 のアトミック追加/削除)、`_is_honeypot()`、
  `inspect()` 内のハニーポット命中チェック(`kind="honeypot_ban", do_ban=True` 分岐)。
- **削除(`admin.py`)**: 管理API `POST /api/shield/honeypot`(add/remove)、ダッシュボードの
  囮URL追加フォーム(`#hp` 入力・追加ボタン)、関連 JS(`honeypot()`)・i18n
  (`ルール / ハニーポット`→`アクセスルール` へ見出しを整理・`囮URL 例:...` の対訳を削除)。
  同じパネル内の IP allow/deny ルールとエッジ前衛設定DLは無関係機能のため維持。
- **コメント整合**: `engine/services/proxy.py` の origin-form 強制コメントから、削除済みの
  `honeypot` 経路への言及を除去(`path_limits`/`sensitive_path` の言及は維持=現存する別機構)。
- **削除(テスト)**: `tests/test_buttonmash.py` の `test_concurrent_honeypot_add_no_lost_updates`/
  `test_concurrent_add_same_path_dedups`(ハニーポット専用の並行更新テスト)、`tests/test_core.py`
  の `test_attractive_honeypot_bait_is_zero_fp_oneshot_ban`。
- **テスト置き換え(honeypotを「決定論的一発BANの手段」として流用していた箇所)**:
  `tests/test_bans.py`(累犯BANエスカレーション)・`tests/test_subnet.py`(サブネット集約防御)・
  `tests/test_hardening.py`(appeals有界性・eviction下でのBAN温存)・`tests/test_shutdown.py`
  (BAN回数の永続化)は、`sh.inspect(ip, path="/.env")` によるハニーポット命中誘発を
  `sh.penalize(ip, weight=sh.cfg["block_score"], ...)` の直接呼び出しへ置換。どちらも
  `_enforce_or_audit(..., do_ban=True)` へ同じ経路で到達するため、各テストの検証意図
  (BANカウント/TTLエスカレーション/サブネット記録/appeals/永続化)は変更していない。
  `tests/test_buttonmash.py::test_button_mash_stress_no_corruption` からは
  `add_honeypot` 操作枝を除去し、残る操作(inspect/ban/unban/set_config)へ比率を再配分。
  `tests/test_core.py::test_dashboard_controls` からは `/api/shield/honeypot` 呼び出しを削除
  (他の管理API操作の検証は維持)。
- ドキュメント: README(「含まれない機能」にハニーポットを追加・適用機能一覧から削除)、
  docs/defenses.md(該当行を削除)、NEXT_STEPS.md を更新。
- テスト: **344/344 件緑**(347 件からハニーポット専用テスト3件を削除)。

## [Lite-4] — 第4次縮小: PoW チャレンジ段を削除

free / trial ティアから、脅威スコアの中間防御ティアだった **チャレンジ(Proof-of-Work・自作)**
を削除。パズルを解けば通過できる段そのものを無くし、`allow`/`throttle`/`block` の3段構成へ
単純化(上位/商用エディションのみ PoW チャレンジを提供)。

- **スコア判定の統合(`engine/lifeform/pipeline.py` `inspect()`)**: 旧 `challenge_score` 以上
  (score ≧ 40 帯・従来はチャレンジ発行)を `block` へ統合した。新設の `deny_score`(既定 `40`
  =旧 `challenge_score` と同値)が単発拒否(**BAN はしない**)の閾値、`block_score`(既定 `100`・
  変更なし)が自動BANの閾値。中間の『パズルを解けば通す』余地を無くし、フェイルセーフ側(=より
  厳格)に倒した。`block_score` 自体(および `inspect_body`/`scan_upload`/`inspect_graphql`/
  `note_response`/JWT/ハニーポットの各 do_ban=True 判定)は一切変更していない——単発の疑わしい
  signal(本文シグネチャ・UA/ヘッダ不整合・クレデンシャルレート超過 等)が誤って即時BANされる
  ことを防ぐ既存の低FP設計(`body_sig_weight_factor` 等)をそのまま維持するため。
- **Under Attack モードを丸ごと削除**: `under_attack`(手動)・`auto_under_attack`(EWMA
  ベースの自動検知・既定 `True`)・`_anomaly()` は、このチャレンジ段を開閉するためだけの仕組み
  だったため撤去した(フォールドではなく単純削除)。理由: `auto_under_attack` は既定ONで、
  これを「未検証の public/unknown トラフィックは block」へフォールドすると、通常のアクセス
  急増(セール/バズり等)だけで新規訪問者が軒並み自動BANされる自爆的な既定挙動になり、
  free/trialティアの安全な既定として不適切と判断した。全体レートのEWMA自体
  (`_tick_ewma`/`global_rate_ewma`)はダッシュボードのテレメトリとして維持。
- **削除(`engine/lifeform/pipeline.py`)**: `_issue_challenge()`/`solve_challenge()`/
  `_dynamic_difficulty()`、`set_under_attack()`、`_anomaly()`。設定キー `challenge_score`/
  `challenge_difficulty`/`max_difficulty`/`verify_ttl_sec`/`under_attack`/`auto_under_attack`。
  状態 `_nonces`/`verified_until`(付与箇所が無くなったため)。`_out()`/`metrics()`/
  `sample_series()`/`analysis()` から `challenge`/`anomaly` 系フィールドを除去。
  `absorb_suspend()`(OSスリープ吸収)は BAN タイマーの補正だけを残し、nonce/検証セッションの
  補正ロジックを削除。
- **削除(`engine/services/proxy.py`)**: `_CHALLENGE_PATH`
  (`/__ducknet_challenge__`)定数、`_handle_challenge()`、`if act == "challenge":` の
  503+PoW 応答分岐、`AsyncEdgeGuard.metrics` の `challenged` カウンタ。
- **削除(`admin.py`)**: ダッシュボードの `🚨 Under Attack` トグルと
  `/api/shield/under_attack` エンドポイント、`challenge_total` メトリクス露出、
  KPIカード/棒グラフ/折れ線グラフ/凡例/i18n の `チャレンジ`/`challenge` 系表示一式。
- **その他**: `bloom.py`/`edge_config.py`/`service.py` のコメント中の PoW 言及を、実態
  (後段の inspect() が拾う・PoW 前提でないアクセス制御である旨)に合わせて訂正。
- **削除(テスト)**: `tests/test_core.py` の `test_pow_challenge_solution_grants_verification`
  (PoW 発行/検証そのものを検証するテスト)を削除。`test_botconsistency.py`/`test_credrate.py`
  (キー/IPローテーション濫用の escalation テスト)・`test_respscore.py`・`test_memtamper.py`・
  `test_signed_state.py`・`test_buttonmash.py` は `challenge_score` 参照を `deny_score` へ
  差し替え、または改竄検知テスト用の別の既存 cfg キー(`flood_threshold`)へ差し替えて意図を
  維持。`test_hardening.py`/`test_method.py`/`test_pathrate.py`/`test_subnet.py`/
  `test_throttle.py` の `auto_under_attack = False`(異常検知由来のチャレンジ除外用の
  お膳立て)は不要になったため削除。
- ドキュメント: README(「含まれない機能」に PoW チャレンジを追加)・docs/defenses.md・
  docs/options.md・NEXT_STEPS.md から `challenge_score`/`under_attack`/PoW の記述を
  `deny_score`/2段のスコア閾値の説明へ更新。
- テスト: **347/347 件緑**(348 件から PoW 検証テスト1件を削除)。

## [Lite-3] — 第3次縮小: 自己防衛の watchdog/親プロセス監督を削除

free / trial ティアから、常駐サービス層の *自動復旧*(auto-recovery/self-healing)機構を削除。
状態ファイルの HMAC 署名(#52–#54)・in-memory cfg 改竄検知(#85)・迂回検知(#78)は**無関係な
別機構のため維持**——落ちた/ハングした前衛スレッドを自前で検知・強制再起動する層だけを外す。

- **削除**:
  - **常駐内 Watchdog** — `AsyncEdgeGuard.serve_forever()`(`engine/services/proxy.py`)から
    Watchdog(生存監視・ハング検出・強制再起動・OSスリープ吸収)の配線を除去。`serve_forever()`
    は「起動して `is_alive()` を見張り、スレッドが死んだらプロセスごと終了する」だけの元の
    素朴な形に戻した。ハートビート専用の周期タスク(`_heartbeat_loop`/`heartbeat()`)、
    suspend 通知(`_absorb_suspend`)、watchdog 周期タスク閉包(`_make_period_tick`)を削除。
    `is_alive()`/`restart()` は基本のスレッド状態操作として維持(手動/テストから直接使用可)。
  - **`engine/core/resilience.py` を削除** — `Watchdog`/`Supervisor`/`measure_skew`/`assess`/
    `backoff_delay`/`restart_decision` 一式。他モジュールからの参照なし(watchdog/supervisor
    以外の用途では未使用だったため丸ごと削除可能と確認)。
  - **親プロセス監督 `--supervise`** — `dataplane/service.py` の CLI フラグと、`Supervisor` を
    起動するディスパッチ分岐を削除。クラッシュからの自動再起動は OS 層(systemd `Restart=`/
    Windows サービス回復/launchd `KeepAlive`)にのみ委ねる。
  - `engine/core/autostart.py` の `build_command()`/`install()` から `supervise` 引数を削除
    (自動起動登録コマンドに `--supervise` を付与しなくなった)。OS レベルの自動起動登録
    (ログオン/ブート時の再起動)自体は変更なし。
  - **迂回検知(#78)/cfg 改竄検知(#85)の呼び出し口を独立**: 従来 watchdog の周期タスクに
    便乗していた `traffic_stall_check()`/`verify_cfg_integrity()` の定期実行を、watchdog とは
    無関係な独立の軽量ループ(`AsyncEdgeGuard._periodic_checks_loop`)へ切り離した。どちらも
    自動復旧とは別物のセキュリティ機能のため、機能自体は維持。
- **削除(テスト)**: `tests/test_resilience.py` を削除(Watchdog/Supervisor/skew/heartbeat/
  restart_decision 等、resilience.py 一式のテスト)。`tests/test_autostart.py` の
  `test_build_command_adds_supervise` を `--supervise` を付与しないことを確認するテストへ
  差し替え。`tests/run_all.py` の MODULES から `test_resilience` を除去。`test_stall.py`/
  `test_memtamper.py`(迂回検知/cfg改竄検知の直接テスト)は無関係な独立機能のため変更なし。
- ドキュメント: README/CHANGELOG/docs/hardening.md/docs/options.md/docs/defenses.md/
  docs/apt-threat-model.md から `--supervise`/watchdog の記述を除去し、クラッシュ復旧は
  OS 層の責務であることを明記。`NEXT_STEPS.md` を DuckNet-Lite の現状に合わせて全面刷新
  (商用版前提の古い引き継ぎメモを置き換え)。
- コード品質: `engine/lifeform/pipeline.py` の `inspect()` に残っていたカナリアトークン
  照合の死コード(`canary.py` は第1次縮小で既に削除済み・常に except 分岐に落ちるだけの無害な
  残骸)を除去。シグネチャ走査(`sig_hit`)ロジックは変更なし。
- テスト: **348/348 件緑**(372 件から Watchdog/Supervisor 関連 24 件を削除)。

## [Lite-2] — 第2次縮小: コアの L7 WAF/DDoS + 最小限の可視化のみへ

free / trial ティアを **さらに** 絞り込み、コアの L7 WAF/DDoS リバースプロキシ・エンジン
(スコアリング/自動BAN/PoWチャレンジ/シグネチャ照合)+ それを操作する最小限の Web 管理
ダッシュボード(ON/OFF・基本指標・BAN管理)だけを残した。**依存ゼロ**は維持。

- **削除(価値付加機能・上位エディションのみ)**:
  - **DNS フィルタ(L7検知)** — `engine/lifeform/dns.py`。`dns` サブコマンド・
    `ducknet-dns` Docker サービス・`docs/dns.md` を削除。
  - **囮ファイルのダウンロード追跡(ビーコン)** — `engine/lifeform/datasets.py`
    (参照トークン台帳)。`/c/<token>.png` ビーコン経路・`/api/ledger` を削除。
  - **SIEM/Webhook 転送** — `engine/lifeform/forwarders.py`(Syslog/Webhook Fanout)・
    `engine/lifeform/alerts.py`(AlertSink。datasets.py 以外に利用者がいないため同時削除)。
    `pipeline.py`/`proxy.py`/`service.py` の転送配線(`_forward`/`_txn` の SIEM 経路)を除去。
    ローカルの改竄可視化(`/api/shield/tamper`)自体は維持。
  - **構造化トランザクションログ** — `engine/services/txnlog.py`。`txnlog_enabled`/
    `txnlog_forward` cfg・`proxy.py` の `_txn()` 記録経路・ダッシュボードのトグルを削除。
  - **自己完全性監視 + 自動修復** — `engine/core/integrity.py`(`SelfIntegrity`)。
    `--integrity-baseline`/`--integrity-check` CLI フラグと watchdog 周期タイマーへの
    配線を削除。in-memory cfg 改竄検知(`verify_cfg_integrity`・#85)と状態ファイルの
    HMAC 署名(#52–#54)は **無関係な別機構のため維持**。
  - **GeoIP 国別判定** — `engine/lifeform/geoip.py`。`geo_mode=country_allow/country_block`・
    `geo_countries` cfg・国別テレメトリ(`country_hits`)を削除。CIDR ベースの `geo_mode=allow/block`
    は維持。
  - **正のセキュリティモデル(allowlist)** — `engine/lifeform/posmodel.py`。`NetShield.__init__`
    で無条件生成されていたハード依存(`self._posmodel`)・`inspect()` ホットパスの照合・
    `reload_posmodel`/`set_posmodel`/`posmodel_status`・`/api/shield/posmodel` を除去。
  - **ステルス運用(プロセス名偽装)** — `dataplane/profile.py` を削除。`--stealth` CLI フラグと
    `service.py`(`run()`)の cover 変数配線を除去。`proxy.py`/`edge_config.py` の
    `profile.cover_thread_name`/`cover_brand` 呼び出しは固定文字列に置換(機能自体は
    `DUCKNET_COVER` 環境変数を直接参照するブランド表示のみ残置=後方互換)。
- **維持(意図的)**: `--supervise`(Watchdog/Supervisor)、`--install-autostart`/
  `--uninstall-autostart`、`--cluster`(マルチコア待受)、`atomic_io`/`signed_state`
  (状態永続化の署名整合性)、`origin.py`(バックエンド・バイパス防止)、`accel.py`、`i18n.py`。
  これらは基本的な信頼性/正当性であり、削ぎ落とす「付加価値機能」ではないと判断。
- 管理ダッシュボードから該当パネル/API(DNS検知欄・参照トークン台帳欄・国別内訳・
  トランザクションログ トグル・`/api/detections`・`/api/ledger`・`/api/shield/posmodel`)を除去。
  ON/OFF・基本 BAN 管理・基本指標は維持(完全な blackbox 化はしない)。
- ドキュメント: `docs/dns.md` を削除。README/options.md/defenses.md/hardening.md/
  apt-threat-model.md から該当節を整理。`pyproject.toml` の `geoip` optional-dependency
  (未使用の `maxminddb` extra)と SBOM/第三者表示を同期。
- テスト: `test_dns.py`/`test_ops.py`/`test_alertflood.py`/`test_datasets.py`/
  `test_txnlog.py`/`test_integrity.py`/`test_posmodel.py`/`test_profile.py` を削除、
  `test_core.py`/`test_hardening.py`/`test_saferegex.py`/`test_memtamper.py`/
  `test_signed_state.py` から該当ケースを整理。**372/372 件緑**。

## [Lite] — DuckNet-Lite(free / trial エディション)分岐

上位(商用)エディションから、コアの L7 WAF/DDoS リバースプロキシ・ゲートウェイ + 最小限の
管理ダッシュボード + DNS フィルタだけを残した無償/試用ティアを切り出し。**依存ゼロ**は維持。

- **含まれる**: スコアリング/BAN/チャレンジ・エンジン、正のセキュリティモデル(allowlist)、
  GeoIP、Web 管理ダッシュボード、DNS フィルタ(L7検知)、囮ファイルのダウンロード追跡
  (ビーコン・`/api/ledger`)、SIEM/Webhook 転送、自己完全性監視、署名付き状態永続化。
- **削除(上位エディションのみ)**: デスクトップ GUI(`dataplane/gui`)、カナリアトークン
  (`engine/lifeform/canary.py`)、LDAP/SMB/Kerberos の横展開デコイ(`engine/lifeform/listeners.py`)、
  LDAP 列挙検知プロキシ(`engine/lifeform/ldap_proxy.py`、自作 BER パーサ `ber.py` を含む)、
  脅威インテリジェンス(IoC)照合(`engine/lifeform/intel.py`)、MITRE ATT&CK 対応の脅威検知
  コンテンツ配備(`engine/lifeform/content.py`)、クラスタ間の分散BAN同期(gossip・
  `engine/services/gossip.py`)、商用ライセンス管理(`dataplane/enterprise`)。
- 対応する CLI サブコマンド(`gui` / `canary` / `decoy` / `ldap-proxy` / `content`)と
  ライセンス関連の起動フラグ・env は同時に削除。`dns` サブコマンドと本体ゲートウェイは変更なし。
- 管理ダッシュボードから該当機能の UI/API(`/api/gossip`、`/api/shield/intel_reload` 等)を除去。
- ドキュメント: `docs/listeners.md` / `docs/ldap-proxy.md` / `docs/content.md` /
  `LICENSING.md` / `RELEASING.md` を削除し、README/options.md/defenses.md から該当節を整理。

## [1.3.0] — 脅威検知コンテンツ(ATT&CK / Detection-as-Code)+ SOC テーマ

検知を「コンテンツ」として管理・配備する層と、SOC 風の UI テーマを追加。すべて **依存ゼロ**・
後方互換・テスト付き(**579 件緑**)。

- **脅威検知コンテンツ `engine/lifeform/content.py`**: 組込検知を MITRE ATT&CK 技術 / 深刻度 /
  分類 / 参照つきの可搬ルールとして列挙(`catalog`)。`attack_coverage` / `search` / `stats`。
- **可搬変換(Uncoder 相当・自前実装)**: 1ルールを **Sigma / ModSecurity / Suricata / nginx / JSON**
  へ翻訳して他 SIEM/WAF/IDS へ配備可能(`export`)。可搬 JSON の取り込み(`import_rules`)。
  出力する正規表現も ReDoS lint を通る(配備先の自己 DoS を防ぐ)。
- **CLI `python -m dataplane content`**: `list` / `stats` / `coverage` / `export -f <fmt>`。
- **GUI「脅威コンテンツ」タブ**: ATT&CK 対応カタログの閲覧・検索と、形式選択での配備出力。
- **サイバーテーマ(SOC 風)**: 深紺 + ネオンのシアン/バイオレット。ヘッダにグラデーション帯。
  テーマは 自動 / ダーク / ライト / **サイバー** から選択可。
- 詳細は [docs/content.md](../docs/content.md)。

### 監査強化(極限レビューへの追加対応)
- **接続レート上限 `conn_rate_per_ip`**(既定 0=無効・ロックダウンで自動 50/s): 接続→即RST を
  高速反復する churn フラッドを head 解析や backend 接続より手前で安価に shed(CPython/asyncio の
  接続生成コストへの頭打ち)。
- **セキュリティ比較の bytes 化**: 管理 API トークン・GUI ロック・cfg-MAC の照合を `bytes` での
  `hmac.compare_digest` に統一(非ASCII入力での TypeError と長さ依存タイミングの懸念を排除)。
- **奇形入力の堅牢性をテストで担保**: 乱バイト/未エンコ多byte URI/巨大ヘッダ/0x プレフィクス
  chunk への framing 判定が例外を出さないこと、SMB/LDAP の 0xFFFFFFFF 長フィールドでも分類器が
  クラッシュ/情報漏洩しないこと(Python のスライス安全性)を回帰テスト化。バイト透過 +
  `force_conn_close` によりチャンク・トレーラ経由のデシンクは構造的に不成立。

## [1.2.0] — 耐 APT 監査強化 + デスクトップ GUI(完成版)

1.1.0 を土台に、国家背景クラスの監査(レッドチーム視点)で洗い出した構造的弱点を塞ぎ、
プロ仕様のデスクトップ・コントロールパネルを追加。すべて **依存ゼロ(標準ライブラリのみ)**・
後方互換・テスト付き(**570 件緑**)。

### 耐性強化(極限監査への対応)
- **ReDoS 耐性ライブラリ `engine/core/saferegex.py`**: 危険パターン(ネスト量化子)を *載せる前に*
  lint で拒否、走査前に入力長を上限化、線形時間の Aho-Corasick リテラル照合。`validate_pattern`/
  DNS 規則/シグネチャ照合に差し込み。組込シグネチャ全てが lint を通過(WAF の自己 DoS を防ぐ)。
- **JSON 再帰爆弾**対策: `safe_json_loads`(深さ・サイズで事前足切り)を GraphQL 本文・管理 API へ。
- **状態ファイルのロールバック耐性**: 署名エンベロープに単調バージョン `_ver`(署名対象)+ 高水位
  サイドカー `.hw` を追加。古い正署名ファイルへの巻き戻しを `rolled_back` として拒否。
- **slow-read / TCP zero-window 兵糧攻め**対策: 応答転送の `drain` を全て期限付きにし、滞留時は
  両端(クライアント/バックエンド)を強制解放(バックエンド道連れの阻止)。
- **SIEM アラート洪水 / 盲目化**対策: 転送を容量固定 drop-oldest キュー + レート配分 + 失敗バックオフ化。
  取りこぼし時は「N 件抑制」のメタアラートを必ず送り、*静かな盲目化* を防ぐ。
- **HTTP リクエストスマグリング**の回帰テスト整備(CL.TE/TE.TE/裸LF/obs-fold/非 origin 等の拒否)。
- **IPv4-mapped IPv6 正規化**(`::ffff:` を純 IPv4 化)= dual-stack 束縛時の BAN すり抜けを阻止。
- **DNS UDP 応答レート制限(RRL)** = 送信元詐称による反射増幅の踏み台化を防止。
- **誤検知(誤 BAN)低減**: 要求ボディ由来シグネチャのスコア係数 `body_sig_weight_factor`(既定 0.7)。
- 定数時間比較・例外フレーム非保持・解凍出力上限・gossip のタイムスタンプ署名+鮮度窓+リプレイ
  キャッシュ等を監査で確認。

### デスクトップ GUI(コントロールパネル)
- **角丸カード/ボタンのプロ向け UI**(Canvas 自作・依存ゼロ)。ダッシュボード(KPI・トラフィック
  構成バー・スループット折れ線・稼働時間)、簡易/詳細設定、クレジット、スプラッシュ。
- **ライト/ダーク 2 テーマ**(`auto`=Windows 追随 / 手動)+ **日本語/英語の即時切替**(設定は保存)。
- **おすすめプリセット 10 種**(監視のみ〜ロックダウン、レベル順・誤 BAN 安全側)。
- **各設定項目のホバー説明(ツールチップ)**・設定の **検索/フィルタ**・マウスホイールスクロール。
- **システムトレイ常駐・グローバルホットキー召喚**(ステルス/通常で個別 ON/OFF)・**設定変更パスワード
  ロック(pbkdf2)**・**単一インスタンスガード**(二重起動は既存窓を前面化)。
- **ダブルクリック起動ランチャ**: `DuckNet.bat` / `DuckNet.ps1`(Windows・pythonw)/
  `DuckNet.command`(macOS)/ `DuckNet.sh`(Linux)。アイコンは差し替え可能な `ico/` フォルダから。

### 運用 / その他
- **ステルス強化**: GUI タイトル/ヘッダ/スプラッシュ/生成設定コメントも `DUCKNET_COVER` に追従。
- **ビルド後の自動クリーンアップ**(`tools/clean.py`・テスト実行で自動)。
- 環境変数 / 設定キーの一覧は **[docs/options.md](docs/options.md)**。

## [1.1.0] — 防御カバレッジ拡張 + 自己防衛

1.0.0 を土台に、双方向(リクエスト/レスポンス)の検査・認証層・DoS 耐性・自己防衛を大幅に拡張。
すべて **依存ゼロ(標準ライブラリのみ)**・後方互換・テスト付き(491 件緑)。

### 新しい防御(リクエスト側)
- **要求ボディ検査**: POST/JSON/GraphQL 本文を有界・重複ウィンドウで署名走査(head-only の死角)。
  `Content-Encoding: gzip/deflate` は有界解凍してから走査(圧縮による回避封じ)。
- **ファイルアップロード検査**: multipart の危険拡張子(php/jsp/exe/sh 等)を拒否。二重拡張子・NUL 切りも捕捉。
- **正のセキュリティモデル**: 許可した (パス, メソッド) だけ通す allowlist(opt-in)。
- **GraphQL 防御**: 深さ/複雑度/イントロスペクション/バッチの上限(opt-in)。
- **JWT 検査**: `alg:none`(認証バイパス)/ 許可外 alg(alg 混同)を鍵無しで遮断。
- **メソッド/パスオーバーライド対策**: `X-HTTP-Method-Override`・`X-Original-URL` 等での ACL 回避を遮断。
- **クレデンシャル単位レート制限**: トークン/API キー識別子単位(IP ローテーション濫用対策・opt-in)。
- **ヘッダ整合性ボット検知**: ブラウザ UA を名乗るのにブラウザ標準ヘッダを欠くツールを低FP加点。
- **Range DoS(Apache Killer)対策**・**スロー POST(R-U-Dead-Yet)対策**。
- **HTTP リクエストスマグリング**強化(パイプライン第2要求の遮断)。

### 新しい防御(レスポンス側)
- **Set-Cookie ハードニング**(SameSite/Secure[TLS時]/HttpOnly)。
- **CORS 誤設定の無害化**(`ACAO:*`/`null` + 資格情報)。
- **オープンリダイレクト無害化**(外部許可外への 3xx を安全パスへ書換・opt-in)。
- **キャッシュ汚染ヘッダ除去**(非信頼クライアントの `X-Forwarded-Host` 等)。

### 応答アウェア / 可視化
- **応答エラーレート検知**: 4xx 連射(列挙/ブルートフォース)を脅威スコアへ還元。
- **改竄イベントの SIEM 転送 + ダッシュボード**(`/api/shield/tamper`)。

### 対 APT(迂回・下層攻撃への射程内対抗策)
- **バックエンド・バイパス防止**(オリジントークン): エッジ経由を証明する時間有界 HMAC を付与し、
  backend が無トークン(=迂回直叩き/再ルーティング)を拒否。
- **迂回の能動検知**(dead-man's switch): トラフィックが busy→突然ゼロ になったら警報。
- **グローバル同時接続上限** + FD ソフト上限引き上げ(資源枯渇のロードシェッド)。
- 配備ガイド [docs/apt-threat-model.md](docs/apt-threat-model.md)(WAF 外の層=RPKI/DNSSEC/IAM/cgroup の
  責任分担 + 外部鍵運用を4フェーズに対応づけ)。**線引き**: ハイパーバイザ全権・BGP/DNS・CPython
  ゼロデイは WAF では原理的に防げない=多層防御で正しい層に装備する、と明記。

### 自己防衛 / レジリエンス(正当・透明な範囲のみ)
- **watchdog**: 生存監視・ハング/死亡時の強制再起動・**一時停止(OSスリープ等)からの安定復帰**。
- **親プロセス監督**(`--supervise`)・**起動時自動起動の登録**(`--install-autostart`、公認の場所のみ)。
- **ファイルすり替え検知 + 強制修復**(署名付きマニフェスト・バックアップ多重化・`--integrity-baseline`)。
- **可変状態の HMAC 署名**(BAN/署名/設定/テレメトリ/IoC の改竄耐性・移行マーカー)。
- watchdog の周期ランダム化。配備ハードニング手順 [docs/hardening.md](docs/hardening.md)。
- **線引き**: プロセス隠蔽・終了妨害・隠れ起動等の rootkit 手法は実装しない(透明な OS 公認保護のみ)。

### 修正・堅牢化
- 時刻巻き戻し(NTP補正)でのスコア膨張防止・eviction による BAN 回避の阻止・各種メモリ上限化・
  DLP 境界跨ぎ秘密の保留・スキャン面パディング回避の封じ込め 等(`evolution #36`〜)。

### 命名
- ファイル名は低プロファイル(保護露見名を避ける)。`graphql_guard.py` → `graphql.py`。

## [1.0.0] — 初版
L7 レート制限・侵入シグネチャ(SQLi/XSS/traversal/scanner 等)・脅威スコア・動的 PoW チャレンジ・
自動BAN/累犯エスカレーション・ハニーポット・カナリア・出口 DLP・脅威インテリジェンス(IoC)・
応答セキュリティヘッダ注入・サブネット集約防御・Web 管理ダッシュボード・SIEM 転送・
DNS/LDAP/デコイの補助検知・宣言的設定・graceful shutdown・クラスタ待受。依存ゼロ。
