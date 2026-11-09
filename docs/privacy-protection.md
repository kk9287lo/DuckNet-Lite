# 情報流出と PHP バックエンドの防御

GMOトラスト・ログインの2026年10月30日の報告では、公開ストレージに業務用の一時ファイル等が
混在し、一覧と個別ファイルを外部から取得できる設計が原因でした。
公開画像と個人情報の保存先を分け、個人情報は非公開の保存先と認可済みの配信経路で扱ってください。
DuckNetを通らない公開ストレージや、直接公開したバックエンドのアクセス制御は、ゲートウェイで代行できません。
[GMO公式報告](https://news.trustlogin.com/20261030)

PHP2Shell（CVE-2026-109618 / CVE-2026-109619）はPHP本体のメモリ安全性の問題です。
PHP公式が2026年10月21日に公開した修正版は8.2.35・8.3.36・8.4.27・8.5.12です。
利用系列の最新のセキュリティ修正、または配布元の修正済みパッケージを適用し、PHPワーカーを再起動してください。
バージョン文字列だけではディストリビューションの修正バックポートを判定できません。
WAFのパターン検知や要求サイズ制限でPHP本体の修正を代替できるとは扱いません。
[PHP公式説明](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)

## DuckNet の設定

通常の起動では、シールドが有効な間、高確度の内部ファイル公開を `exposure_guard_enabled` で拒否します。
管理者がシールド全体をOFFにすれば拒否は停止し、`mode=audit` では記録して通します。
公開ログイン画面や通常のCSV配信を、名前だけで一律に非公開と判断するものではありません。

[privacy-protection.json](../examples/privacy-protection.json) は、非公開経路・DLP・アップロード検査を
まとめて有効にする適用用の例です。実際の非公開経路と、配信を許可するネットワークに合わせて編集してください。
例の `/private`・`/exports`・`/backups` は、許可表を編集するまで全送信元から拒否します。

```console
python -m dataplane --config examples/privacy-protection.json --backend 127.0.0.1:8080
```

`private_paths` は経路の区切り単位の前方一致、`private_path_allow` は送信元IP/CIDRの許可表です。
空の許可表は対象経路を全拒否します。利用者・組織・ファイル所有者ごとの認可はアプリ側でも必要です。
`X-Forwarded-For` を許可の根拠にするのは、到達元と上書き規則を確認した信頼proxyだけに限定してください。
前段にローカルproxyがある場合、外部利用者もDuckNetからはループバック接続に見えます。
ループバックを安易に許可せず、proxyで外部の転送ヘッダを除去・上書きし、実際の利用者の認可を確認してください。
許可された非公開経路の応答にも `private, no-store` を付け、共有キャッシュへの保存を防ぎます。
名前・メールアドレスを含む任意のデータ全般をDLPが識別するという保証はありません。
私有ファイルを公開経路へ置かず、アクセス認可を先に適用することが基本です。

DLPの遮断モードは先頭のアーカイブ識別に最大262本文バイト、JSONのエスケープ検査に
最大384本文バイトの有界な保留窓を使います。少量の逐次応答は次の入力またはEOFまで遅れる場合があります。
HTML/XML応答はタグ・文字参照をまたぐ検査のため本文を応答完了まで保留します。保留は
`dlp_max_scan_bytes`（応答ごと）、全プロセス合計16MiB、応答時間30秒で制限され、
遮断モードで上限に達した場合は未検査本文を送らず切断します。
応答headの `Location`・`Content-Location`・`Refresh`・`Link` のURL対象は、
1回のパーセント復号後の値も公開前に検査します。アプリ固有の多重復号は検査保証の対象外です。
HTML/XHTML/SVGのURL属性とHTMLのmeta refreshも同じように検査し、良性の符号化URLは元のバイト列で転送します。
ダウンロード応答の`Content-Disposition`保存名も、`filename*`、分割されたRFC 2231名、通常の`filename`の復号後を検査します。重複・欠番・非対応の符号化・旧式encoded-wordは検査不能として扱い、遮断モードでは良性でも応答headを出しません。監査モードでは理由を記録して元の通信を転送します。
本文のある `206 Partial Content` は、複数レンジを組み立てた内容を一応答のDLPでは検査できないため、検査不能と記録します。遮断モードでは良性の部分応答もhead公開前に切断し、監査モードでは元の通信を転送します。
本文のある `226 IM Used` も、クライアントが `IM` 操作を復元するまで本文の意味が分からないため、同じく検査不能と記録します。良性のデルタ応答も遮断モードではheadを送りません。
HTMLの`srcdoc`属性は入れ子の文書となるため、DLP有効時は検査不能と記録します。
遮断モードでは良性の`srcdoc`を含む応答も本文を送らず、監査モードは元の通信を転送します。
HTML/XHTML/SVGの`script`・`style`要素、`style`属性、`on*`イベント属性、URL属性の`data:`・`javascript:`も
検査不能として扱うため、遮断モードではそれらを含む通常のページも表示できません。
JavaScript/ECMAScriptと`text/css`は実行・表示時の文字列復元を静的に検査し切れないため、
DLP有効時は検査不能と記録します。遮断モードでは応答headを出さずに切断し、通常のJS/CSS資産も
読み込めません。監査モードは元の通信を転送し、DLP無効時は従来どおりです。
既知のアーカイブは解凍せず検査不能として扱います。未知・暗号化形式やPDF等の内容は検査保証の対象外です。

multipart応答も、部品の符号化や範囲の再構成を解釈しないため検査不能として扱います。
保護対象の応答検査では、本文を持たない1xx・204に禁止されたContent-LengthやTransfer-Encodingが
付いている場合も、正常に検査できた応答とは扱いません。304の表現長メタデータは維持します。
BOM・charset指定がなくても、UTF-16/32の既知のJSON/XML等の先頭や、本文途中にある
ASCII文字3字以上のNUL交互配置を認めた場合は同じ扱いです。これは有界な検査不能判定で、
同じバイト配置を持つ良性のバイナリも遮断モードでは止まることがあります。
応答ヘッダ値のNEL/NBSPは下流の空白解釈が割れるため、本文公開前に拒否します。
`dlp_action=block` では未検査の内容を送らず、`audit` では記録して送ります。DLPは既定OFFで、
全体の `mode=audit` も記録のみです。利用者の実運用設定はコード更新だけでは変更しません。

既存の秘密情報カテゴリでは、現在のアクセストークン形式と標準の秘密鍵ラベルを判定します。
検知イベントには種別・固定理由を残し、未知の応答ヘッダ値そのものを複製しません。
管理APIの内部例外も本文へ反射せず、監査では自由文字列の値とそれを含む取り消しデータを秘匿します。
診断用の使用量ログはクエリ・フラグメントを保存しませんが、経路名や送信元等の運用情報は残るため、
保存先の権限と保管期間も管理してください。旧ログファイルの機密情報を自動消去する処理はありません。

FalcoNetのログ最小化・検査対象の文脈分離も設計比較に使っています。コマンド注入とスキャナーUAは
既存のHTTP検査経路で確認し、ツール名の言及だけを本文・クエリの攻撃と扱いません。
NmapのOSポート走査全体や、ARTEX等が利用するアプリケーション固有の認可不備を、HTTPゲートウェイ
だけで防げるという意味ではありません。PHP本体の修正やアプリ側の認可も必要です。

設計参考: [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)、
[OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)、
[RFC 7468](https://www.rfc-editor.org/rfc/rfc7468.html)、[RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html)、
[Nmap HTTP UA仕様](https://nmap.org/nsedoc/lib/http.html)、
[ARTEXの調査と推奨対策](https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/)。

## PHP・ストレージへの適用物

[php-backend-security.ini](../examples/php-backend-security.ini) は、修正済みPHPへ適用する追加設定です。
エラー表示・不要なアップロード進捗・URL経由のセッションIDを無効化します。
アップロード進捗やURLセッションに依存するアプリでは、利用箇所を確認してから適用してください。
このファイルの適用だけではPHP2Shellを修正できません。

[storage-public-access-block.json](../examples/storage-public-access-block.json) は、AWS S3の非公開バケット用です。
個人情報・エクスポート・バックアップ専用の保存先へ、アカウントとバケット双方の公開禁止を設定します。
公開画像用のバケットへ混在させず、アプリ側の認可後に短時間の署名付きURL等で配信してください。
このJSONはローカルの適用物で、クラウドアカウントや実バケットへの変更は実施していません。
[AWS公式設定仕様](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PublicAccessBlockConfiguration.html)、
[PHPセッション設定](https://www.php.net/manual/en/session.security.ini.php)
