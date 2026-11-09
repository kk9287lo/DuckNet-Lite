"""Public dashboard metadata for the existing NetShield configuration.

Values and limits come from the same defaults/validators as the management API.
This module exposes no runtime state, credentials, or additional defense feature.
"""
from __future__ import annotations

import copy

from dataplane.engine.lifeform.pipeline import (
    _DEFAULTS, _ENUM_KEYS, _HARD_BOUNDS, _NONNEG_KEYS, _POSITIVE_KEYS,
    _RATE_COUNT_KEYS, _RATE_COUNT_MAX,
)


_GROUPS = (
    ("general", "基本動作", "General behavior"),
    ("rate", "レート・接続数", "Rate and connections"),
    ("score", "検知・採点", "Detection and scoring"),
    ("ban", "BAN・解除申立", "BAN and appeals"),
    ("request", "HTTP要求の保護", "HTTP request protection"),
    ("body", "本文・アップロード", "Body and uploads"),
    ("graphql", "GraphQL", "GraphQL"),
    ("response", "HTTP応答の保護", "HTTP response protection"),
    ("privacy", "非公開経路・情報流出", "Private paths and exposure"),
    ("dlp", "出口DLP", "Response DLP"),
    ("quota", "送出量・接続時間", "Egress quotas"),
    ("access", "サイト・IP・地域", "Sites, IPs and networks"),
    ("proxy", "信頼proxy・TLS・origin", "Trusted proxies, TLS and origin"),
    ("cadence", "周期的なアクセス", "Periodic access"),
)

# key, Japanese label, English label, Japanese help, English help.
# Every public key is explicit: adding a backend setting without dashboard text
# fails schema construction instead of silently leaving the GUI behind again.
_TEXT = {
    "general": (
        ("enabled", "DDoS / 侵入防御", "DDoS / intrusion protection", "OFFではシールドの検知と採点を停止します。HTTP構文の検証とファイアウォールは別に動作します。", "OFF stops Shield detection and scoring. Mandatory HTTP validation and the application firewall operate separately."),
        ("mode", "遮断・監査モード", "Enforce or audit", "enforceは検知に基づいて遮断し、auditは代わりに記録します。HTTP構文や状態検証の失敗は監査中も拒否します。DLPのblockも監査中は記録のみです。", "enforce blocks on detections; audit records them instead. HTTP syntax or state-verification failures are still rejected in audit mode. DLP block also becomes record-only."),
        ("usage_record", "使用量を記録", "Record usage", "送信元・サイト・送出量などの診断用使用量を記録します。保存先の権限と保持期間も管理してください。", "Record diagnostic source, site and traffic usage. Protect the storage location and retention period."),
    ),
    "rate": (
        ("rate_per_sec", "IPごとの要求数/秒", "Requests per second per IP", "IPごとの定常レートです。0では新しいトークンを補充しません。", "Steady token refill rate per IP. Zero does not refill tokens."),
        ("burst", "IPごとのバースト件数", "Burst requests per IP", "短時間にまとめて許す要求数です。定常レートと併用します。", "Requests allowed in a short burst, in addition to the steady rate."),
        ("path_limits", "パス別レート制限", "Per-path rate limits", "JSON配列 {path, rate, burst}。最大64件。pathは前方一致、burst省略時はrateを使います。空配列で無効です。", "JSON array of {path, rate, burst}, at most 64 rules. Paths use prefix matching; omitted burst uses rate. Empty disables it."),
        ("max_conn_per_ip", "IPごとの同時接続上限", "Concurrent connections per IP", "超過接続を要求解析前に閉じます。0は無制限。共有NATの利用者数を考慮してください。", "Close excess connections before request parsing. Zero is unlimited; account for users sharing a NAT."),
        ("conn_rate_per_ip", "IPごとの新規接続/秒", "New connections per second per IP", "接続と切断を反復する攻撃への上限です。0で無効です。", "Limit repeated connection churn. Zero disables this limit."),
        ("max_total_conn", "全体の同時接続上限", "Total concurrent connections", "全体のFD・ソケット・メモリを保護します。0は無制限です。", "Protect the total FD, socket and memory budget. Zero is unlimited."),
        ("window_sec", "フラッド集計窓(秒)", "Flood window (seconds)", "要求数を数える時間窓です。フラッド件数しきい値と合わせて設定します。", "Time window for counting requests; use with the flood request threshold."),
        ("flood_threshold", "フラッド件数しきい値", "Flood request threshold", "集計窓内の要求数がこの値に達するとフラッドとして扱います。", "Treat request counts reaching this value in the window as a flood."),
        ("throttle_response", "レート超過に429を返す", "Return 429 on rate limit", "ONでは429とRetry-Afterを返します。OFFでは応答せず接続を閉じます。", "ON returns 429 and Retry-After. OFF closes the connection without a response."),
        ("throttle_retry_after", "Retry-After(秒)", "Retry-After (seconds)", "429応答でクライアントへ伝える再試行待機秒数です。", "Suggested retry delay sent to the client in a 429 response."),
        ("subnet_defense", "サブネット集約防御", "Subnet aggregation defense", "同じIPv4 /24・IPv6 /64で多数の別IPがBANされると、新規IPへ加点します。共有NATの巻き添えに注意してください。", "Add a score to new IPs when many distinct IPs in one IPv4 /24 or IPv6 /64 are banned. Consider shared NAT users."),
        ("subnet_threshold", "サブネットの別IPしきい値", "Distinct banned IPs per subnet", "集計窓内でhotと判定する別IP数です。サブネット防御がONのときに使います。", "Distinct banned IPs needed to mark a subnet hot while subnet defense is ON."),
        ("subnet_window_sec", "サブネット集計窓(秒)", "Subnet window (seconds)", "サブネットのBANを集計する時間窓です。", "Time window used to aggregate banned IPs in a subnet."),
        ("subnet_score", "hotサブネットへの加点", "Hot-subnet score", "hotサブネットの新規IPへ一度加える点数です。大きい値は正規利用者も遮断し得ます。", "Score added once to a new IP in a hot subnet. High values can block legitimate users."),
    ),
    "score": (
        ("deny_score", "単発拒否の点数", "Single-request deny score", "この点数以上の疑わしい要求を拒否します。BANの点数は別に設定します。", "Deny a suspicious request at this score. The BAN threshold is configured separately."),
        ("block_score", "自動BANの点数", "Automatic BAN score", "累積点数がこの値以上になると期限付きBANを適用します。", "Apply a timed BAN when the accumulated score reaches this value."),
        ("score_halflife_sec", "点数の半減期(秒)", "Score half-life (seconds)", "検知点数が時間とともに半分になる時間です。短すぎる値は反復攻撃の記憶を弱めます。", "Time for a detection score to halve. Very short values forget repeated attacks quickly."),
        ("slowloris_score", "未完ヘッダへの加点", "Incomplete-header score", "ヘッダを完了しないslowloris要求1回あたりの加点です。", "Score added for each slowloris request that does not finish its headers."),
        ("bot_consistency_enabled", "ブラウザヘッダ整合性検査", "Browser-header consistency", "ブラウザを名乗るUAと要求ヘッダの不一致を加点します。単独での遮断を意図した設定ではありません。", "Score inconsistencies between a browser User-Agent and request headers; intended as a combined signal."),
        ("bot_inconsistency_score", "ヘッダ不整合への加点", "Header-inconsistency score", "ブラウザヘッダの不一致1回あたりの点数です。", "Score added for one browser-header inconsistency."),
        ("resp_score_enabled", "4xx応答による採点", "Score repeated 4xx responses", "検証済みのbackend 4xx応答を列挙・認証試行の兆候として数えます。5xxは加点しません。", "Count validated backend 4xx responses as enumeration or authentication-abuse signals. Do not score 5xx."),
        ("resp_error_window_sec", "4xx集計窓(秒)", "4xx window (seconds)", "応答採点で4xxを数える時間窓です。", "Time window for counting 4xx responses."),
        ("resp_error_threshold", "4xx件数しきい値", "4xx count threshold", "集計窓内でこの件数に達すると応答エラー加点を行います。", "Add the response-error score when this many 4xx responses occur in the window."),
        ("resp_error_score", "4xxしきい値超過の加点", "Response-error score", "4xx件数しきい値を超えたときの加点です。block_scoreに達するとBANします。", "Score added when the 4xx threshold is exceeded. Reaching block_score results in a BAN."),
        ("optional_sigs", "任意シグネチャの個別設定", "Optional signatures", "JSON objectでssti・ssrf_internal・redirectをtrue/falseにします。厳格度の変更でプリセットも更新されます。", "JSON object mapping ssti, ssrf_internal and redirect to true/false. Changing paranoia also updates the preset."),
        ("paranoia", "検知の厳格度", "Detection strictness", "1から4で任意シグネチャのプリセットを選びます。高いほど誤検知しやすくなります。", "Select the optional-signature preset from 1 to 4. Higher values increase false-positive risk."),
        ("fold_fullwidth_punct", "全角記号をASCIIへ畳む", "Fold fullwidth punctuation", "backendがNFKCやWindows best-fitで全角記号をASCIIにする場合に使います。日本語の通常文での誤検知も増えます。", "Use when the backend folds fullwidth punctuation via NFKC or Windows best-fit. This can flag ordinary Japanese text."),
    ),
    "ban": (
        ("ban_ttl_sec", "自動BANの基本時間(秒)", "Base automatic BAN duration", "自動BANと通常の手動BANの基本有効期間です。", "Base duration for automatic and ordinary manual BANs, in seconds."),
        ("ban_escalation", "累犯BANを延長", "Escalate repeat BANs", "同じIPの再BANで有効期間を延ばします。", "Extend the duration when the same IP is banned repeatedly."),
        ("ban_escalation_cap", "BAN延長倍率の上限", "Maximum BAN multiplier", "基本BAN時間に掛ける累犯倍率の上限です。", "Maximum repeat-offender multiplier applied to the base BAN duration."),
        ("ban_escalation_retain_sec", "累犯履歴の保持時間(秒)", "Repeat-BAN history retention", "BAN期限切れ後も累犯回数を覚える時間です。0では履歴を保持しません。", "Seconds to retain repeat-offender history after a BAN expires. Zero does not retain it."),
        ("persist_bans", "BANを永続化", "Persist BANs", "署名付き状態へBANを保存します。OFFにすると再起動後にBANを復元できません。", "Save BANs in signed state. OFF prevents restoring BANs after restart."),
        ("block_page", "遮断ページを表示", "Show block page", "HTMLを希望する要求に遮断理由のページを返します。", "Return a block-reason page to requests that accept HTML."),
        ("appeal_enabled", "解除申立を許可", "Allow BAN appeals", "BANされた利用者の解除リクエストを受け付けます。管理者の承認が必要です。", "Accept appeal requests from banned users; administrator approval is required."),
        ("appeal_after_sec", "解除申立までの待機(秒)", "Delay before appeal", "BAN後に解除リクエストを表示するまでの秒数です。0で即時です。", "Seconds after a BAN before offering an appeal. Zero offers it immediately."),
    ),
    "request": (
        ("blocked_methods", "遮断HTTPメソッド", "Blocked HTTP methods", "JSON文字列配列。例: TRACE・TRACK・CONNECT。空配列でメソッドによる遮断を無効にします。", "JSON string array, such as TRACE, TRACK and CONNECT. Empty disables method-based blocking."),
        ("method_override_check", "上書き先メソッドも検査", "Inspect overridden method", "X-HTTP-Method-Overrideなどの上書き先にも遮断メソッドを適用します。", "Apply blocked methods to targets of X-HTTP-Method-Override and similar headers."),
        ("method_override_block", "メソッド上書きヘッダを拒否", "Reject method override headers", "上書き先に関係なくヘッダ自体を拒否します。利用するアプリでは正規通信も止まります。", "Reject override headers regardless of target. Applications that use them will also be blocked."),
        ("path_override_block", "パス上書きヘッダを拒否", "Reject path override headers", "クライアント由来のX-Original-URL・X-Rewrite-URL等による経路認可の迂回を防ぎます。", "Reject client-supplied X-Original-URL, X-Rewrite-URL and similar path-authorization bypass headers."),
        ("range_check_enabled", "多数Range要求を検査", "Inspect excessive ranges", "多数のRange指定でbackendの資源を消費する要求を拒否します。", "Reject requests with too many ranges that can consume backend resources."),
        ("range_max_ranges", "許可するRange数", "Maximum ranges", "一つのRangeヘッダで許可する範囲指定の数です。", "Maximum range specifications accepted in one Range header."),
        ("jwt_inspect_enabled", "JWTの構造を検査", "Inspect JWT structure", "Bearer JWTのalg:noneや許可外algを拒否します。暗号署名の検証はアプリ側で必要です。", "Reject Bearer JWT alg:none or disallowed algorithms. The application must still verify the cryptographic signature."),
        ("jwt_allowed_algs", "許可するJWTアルゴリズム", "Allowed JWT algorithms", "JSON文字列配列。空配列はnoneだけを拒否します。利用する認証基盤の方式に合わせます。", "JSON string array. Empty rejects only none. Match the algorithms used by the authentication service."),
        ("cred_rate_enabled", "資格情報単位のレート制限", "Credential rate limiting", "同じBearer/APIキーの利用を送信元IPをまたいで集計します。共有キーは全利用者で同じ上限です。", "Count uses of the same Bearer/API key across source IPs. Users of a shared key share the same limit."),
        ("cred_rate_window_sec", "資格情報の集計窓(秒)", "Credential window (seconds)", "資格情報ごとの要求数を数える時間窓です。", "Time window for counting requests per credential."),
        ("cred_rate_limit", "資格情報ごとの要求上限", "Requests per credential", "集計窓内で許可する要求数です。上限を超えた要求を拒否します。", "Requests allowed per credential in the window; reject requests exceeding this count."),
        ("cred_rate_score", "資格情報超過のIP加点", "Credential-limit IP score", "0はIPへの加点なし。共有キーでは正規利用者へBANを転嫁し得るため、利用者ごとの固有キー構成でだけ使ってください。", "Zero adds no IP score. Use only with per-user keys; shared keys can transfer BAN penalties to legitimate users."),
    ),
    "body": (
        ("body_scan_enabled", "要求本文の署名検査", "Inspect request body signatures", "POST・JSON等の本文を署名で検査します。アップロード種別・GraphQL検査は別に有効化できます。", "Scan POST, JSON and other bodies for signatures. Upload-type and GraphQL checks can be enabled independently."),
        ("body_scan_max_bytes", "復号後本文の検査上限(バイト)", "Decoded body scan limit (bytes)", "遮断モードでは上限を超えた検査対象本文を拒否します。通常アップロードの大きさも考慮してください。", "In enforce mode reject inspectable bodies above this limit. Account for normal upload sizes."),
        ("body_sig_weight_factor", "本文シグネチャの点数係数", "Body signature score factor", "本文の検知点数に掛ける係数です。0は署名由来の加点をなくします。", "Multiplier for body-signature scores. Zero removes score contributions from body signatures."),
        ("body_decode_enabled", "gzip/deflate本文を復号", "Decode gzip/deflate bodies", "圧縮本文を有界に復号して検査します。backendと異なる見え方で検査しないための設定です。", "Decode compressed bodies within bounds before inspection, matching the backend view."),
        ("body_reject_unscannable_encoding", "未対応本文符号化を拒否", "Reject uninspectable encoding", "ONでは読めないContent-Encodingを拒否します。OFFは圧縮されたままの本文が検査をすり抜ける余地を残します。", "ON rejects unsupported Content-Encoding. OFF can let compressed content pass without meaningful inspection."),
        ("body_timeout_enabled", "本文受信の総時間を制限", "Limit total body receive time", "小出しのPOSTで接続を保持し続ける要求を止めます。", "Stop slow POSTs from retaining connections indefinitely."),
        ("body_max_sec", "本文受信の総期限(秒)", "Total body receive deadline", "本文全体を受信する秒数の上限です。独立した内部退避期限300秒もあります。", "Seconds allowed to receive the complete body. An independent internal staging deadline of 300 seconds also applies."),
        ("upload_scan_enabled", "危険なアップロード種別を拒否", "Reject dangerous upload types", "multipartと生本文のファイル名を検査します。本文署名検査のON/OFFとは独立です。", "Inspect multipart and raw-body upload filenames, independently of body-signature scanning."),
        ("upload_deny_ext", "拒否するアップロード拡張子", "Denied upload extensions", "JSON文字列配列。小文字・先頭のドットなし。既知の二重拡張子も検査します。", "JSON string array in lowercase without a leading dot. Known double-extension forms are inspected too."),
    ),
    "graphql": (
        ("graphql_enabled", "GraphQL検査", "GraphQL inspection", "指定したGraphQL経路だけで有効になります。本文署名検査とは独立です。", "Inspect only configured GraphQL paths, independently of body-signature scanning."),
        ("graphql_paths", "GraphQL経路", "GraphQL paths", "JSON文字列配列。GraphQLとして検査するパスの前方一致です。", "JSON string array of path prefixes to inspect as GraphQL."),
        ("graphql_max_depth", "GraphQLの最大深さ", "Maximum GraphQL depth", "選択セットとフラグメント展開後のネスト深さを制限します。", "Limit selection-set nesting after fragment expansion."),
        ("graphql_max_complexity", "GraphQLの最大複雑度", "Maximum GraphQL complexity", "エイリアスとフラグメント展開を含むフィールド数を制限します。", "Limit fields, including aliases and expanded fragments."),
        ("graphql_block_introspection", "GraphQL内省を拒否", "Reject GraphQL introspection", "__schema・__typeを拒否します。通常の__typenameは対象外です。", "Reject __schema and __type; ordinary __typename is allowed."),
        ("graphql_max_batch", "GraphQLの最大バッチ件数", "Maximum GraphQL batch size", "一要求で受けるGraphQLオペレーション配列の件数上限です。", "Maximum operations in a GraphQL request batch."),
        ("graphql_max_bytes", "GraphQL本文上限(バイト)", "GraphQL body limit (bytes)", "本文全体をこの上限まで解析します。超過時は413で拒否します。", "Parse the complete GraphQL body up to this limit; reject larger bodies with 413."),
    ),
    "response": (
        ("force_conn_close", "要求のConnectionをcloseへ", "Forward Connection: close", "OFFでも一接続内の二つ目の要求は転送しません。", "Even when OFF, a second pipelined request on one connection is not forwarded."),
        ("resp_stall_sec", "応答drain待機の累積上限(秒)", "Accumulated response-drain wait", "0で無効。遅い受信者への書込み待機の累積だけを制限します。通常の無通信SSE待機とは別です。", "Zero disables it. Limit accumulated write-backpressure time to slow clients, not ordinary idle SSE time."),
        ("cookie_harden_enabled", "Cookie保護属性を補完", "Harden response cookies", "不足しているSameSiteやTLS時のSecureを補います。", "Add missing SameSite and, for TLS requests, Secure attributes."),
        ("cookie_samesite", "補完するSameSite", "Default SameSite", "CookieのSameSiteがない場合の値です。空文字列は補完を無効にします。", "Value added when SameSite is missing. An empty string disables supplementation."),
        ("cookie_httponly", "CookieにHttpOnlyを補完", "Add missing HttpOnly", "JavaScriptで読むCookieを壊すことがあるため、必要な構成でだけ使ってください。", "Can break cookies read by JavaScript; enable only where appropriate."),
        ("cors_harden_enabled", "危険なCORSを無害化", "Harden unsafe CORS", "ワイルドカードまたはnull Originと資格情報許可の危険な組合せから資格情報ヘッダを除きます。", "Remove credentials permission from unsafe wildcard/null Origin combinations."),
        ("open_redirect_enabled", "外部リダイレクトを検査", "Inspect external redirects", "要求先Host以外への3xxを許可表と照合します。OAuth等の正規外部遷移を許可表に登録してください。", "Check external 3xx redirects against the allowlist. Include legitimate OAuth and other external destinations."),
        ("open_redirect_mode", "リダイレクト検査の動作", "Redirect protection action", "enforceは安全パスへ書換、auditは記録のみ。全体auditの間も書換しません。", "enforce rewrites to the safe path; audit only records. Global audit also prevents rewriting."),
        ("open_redirect_allow", "外部リダイレクト許可先", "Allowed redirect hosts", "JSON文字列配列。外部遷移を許可するホスト名です。", "JSON string array of allowed external redirect hostnames."),
        ("open_redirect_safe_path", "安全なリダイレクト先", "Safe redirect path", "同じoriginの / で始まるパスです。//やバックスラッシュは指定できません。", "Same-origin path beginning with /. Network-path references and backslashes are rejected."),
        ("sec_headers_enabled", "応答セキュリティヘッダ", "Response security headers", "保守的な防御ヘッダを補い、指定ヘッダの追加・除去を行います。", "Add conservative defense headers and apply configured additions/removals."),
        ("sec_headers_extra", "追加・上書きする応答ヘッダ", "Additional response headers", "JSON object。最大128件・総量32KiB。HTTP構造やorigin内部情報に使う予約名は指定できません。", "JSON object, at most 128 fields and 32 KiB total. Framing and internal-origin reserved names are rejected."),
        ("sec_headers_strip", "除去する応答ヘッダ名", "Response headers to remove", "JSON文字列配列。Server・X-Powered-By等の不要な情報を削れます。", "JSON string array, for example Server or X-Powered-By, to remove unwanted information."),
    ),
    "privacy": (
        ("exposure_guard_enabled", "内部ファイルの公開を拒否", "Reject exposed internal files", "設定・鍵・リポジトリartifact等の高確度な公開経路を拒否します。シールドOFF・全体auditでは遮断しません。", "Reject high-confidence exposed config, key and repository artifacts. Shield OFF or global audit does not block."),
        ("private_paths", "送信元の認可が必要な経路", "Private path prefixes", "JSON文字列配列、最大64件。区切り単位の前方一致で照合します。対象応答は共有キャッシュ禁止になります。", "JSON string array, at most 64 segment-aware prefixes. Matching responses are marked against shared caching."),
        ("private_path_allow", "非公開経路の送信元許可表", "Private-path source allowlist", "JSON IP/CIDR配列、最大256件。空なら対象経路を全拒否。proxy背後でループバックを安易に許可しないでください。", "JSON IP/CIDR array, at most 256 entries. Empty denies all private-path access. Do not blindly allow loopback behind a proxy."),
        ("blocked_extensions", "遮断するURL拡張子", "Blocked URL extensions", "JSON文字列配列。例: .sql・.bak。公開する必要のあるファイルを含めないでください。", "JSON string array, such as .sql and .bak. Exclude files that must remain public."),
        ("blocked_urls", "遮断するURL部分文字列", "Blocked URL substrings", "JSON文字列配列。前方一致ではなく部分文字列として照合します。", "JSON string array matched as substrings rather than only prefixes."),
    ),
    "dlp": (
        ("dlp_enabled", "秘密情報の応答検査", "Inspect responses for secrets", "シールドONの間だけ動作します。既定OFF。任意の個人情報全般を識別する機能ではありません。", "Runs only while Shield is ON; default OFF. It does not identify every form of personal data."),
        ("dlp_action", "DLPの動作", "DLP action", "auditは記録のみ、blockは漏洩や検査不能時に送出を止めます。全体mode=auditならblockでも記録のみです。", "audit records; block stops output on leaks or uninspectable content. Global mode=audit overrides block to record only."),
        ("dlp_max_scan_bytes", "応答の走査上限(バイト)", "Response scan limit (bytes)", "上限を超えると検査不能として扱います。HTML/XMLのblockは完了まで保留し、通常のページも止まる場合があります。", "Exceeding the limit is uninspectable. HTML/XML in block mode is held to completion and may block ordinary pages."),
    ),
    "quota": (
        ("quota_enabled", "送出量・接続時間の上限", "Enable egress quotas", "送信元IPごとの窓内送出量と接続時間を制限します。0の軸は無制限です。", "Limit sent bytes and connection time per source IP in the window. A zero limit leaves that axis unlimited."),
        ("quota_window_days", "クォータ集計日数", "Quota window (days)", "送出量と接続時間を合計する日数です。", "Number of days used to aggregate egress and connection time."),
        ("quota_max_gb", "IPごとの送出上限(GB)", "Sent data per IP (GB)", "1GBは10億バイト。0は無制限です。", "One GB is one billion bytes. Zero is unlimited."),
        ("quota_max_conn_sec", "IPごとの合計接続上限(秒)", "Total connection seconds per IP", "窓内の合計接続時間です。0は無制限です。", "Total connection time in the window, in seconds. Zero is unlimited."),
    ),
    "access": (
        ("site_mode", "Host許可・遮断の方式", "Host allow/block mode", "whitelistは許可表以外を拒否、blacklistは遮断表を拒否。whitelistには空でない許可表が必要です。", "whitelist denies hosts outside its list; blacklist denies listed hosts. whitelist requires a nonempty allowlist."),
        ("site_whitelist", "Host許可表", "Allowed hosts", "JSONホスト名配列。site_mode=whitelistと一緒に保存します。例: app.example.com。", "JSON hostname array. Save together with site_mode=whitelist; for example app.example.com."),
        ("site_blacklist", "Host遮断表", "Blocked hosts", "JSONホスト名配列。site_mode=blacklistのときに使います。", "JSON hostname array used when site_mode=blacklist."),
        ("ip_mode", "送信元IP許可・遮断の方式", "Source-IP allow/block mode", "whitelistは許可表以外を拒否、blacklistは遮断表を拒否します。", "whitelist denies sources outside its list; blacklist denies listed sources."),
        ("ip_whitelist", "送信元IP許可表", "Allowed source IPs", "JSON IP/CIDR配列。ip_mode=whitelistの空表は全送信元を拒否します。", "JSON IP/CIDR array. An empty list with ip_mode=whitelist denies every source."),
        ("ip_blacklist", "送信元IP遮断表", "Blocked source IPs", "JSON IP/CIDR配列。ip_mode=blacklistのときに使います。", "JSON IP/CIDR array used when ip_mode=blacklist."),
        ("geo_mode", "CIDR地域判定の方式", "CIDR region mode", "allowは指定CIDRだけ許可、blockは指定CIDRを拒否します。GeoIPデータベースは使いません。", "allow permits only listed CIDRs; block denies listed CIDRs. No GeoIP database is used."),
        ("geo_cidrs", "地域判定用CIDR", "Region CIDRs", "JSON IP/CIDR配列。geo_modeと一緒に保存します。allowの空表は全送信元を拒否します。", "JSON IP/CIDR array. Save with geo_mode. An empty allow list denies every source."),
    ),
    "proxy": (
        ("trusted_proxies", "信頼するproxyのIP/CIDR", "Trusted proxy IPs/CIDRs", "JSON配列。実際の前段proxyだけを指定し、その接続からのX-Forwarded-Forだけを信頼します。広すぎる範囲はIP偽装を招きます。", "JSON array of actual upstream proxies. Trust X-Forwarded-For only from them; broad ranges allow source-IP spoofing."),
        ("require_tls", "TLS終端済み要求だけ許可", "Require verified TLS indication", "実際のTLS終端を行う信頼proxyからのHTTPS情報が必要です。任意のX-Forwarded-Protoは信頼しません。trusted_proxiesを先に確認してください。", "Require HTTPS information from a trusted proxy that actually terminates TLS. Arbitrary X-Forwarded-Proto is not trusted. Verify trusted_proxies first."),
        ("strip_cache_poison_headers", "キャッシュ汚染ヘッダを除去", "Strip cache-poisoning headers", "非信頼クライアント由来の転送ホスト等をbackendへ渡す前に除去します。", "Remove forwarded-host and related client headers before forwarding requests from untrusted sources."),
        ("cache_poison_headers", "除去する要求ヘッダ名", "Request headers to strip", "JSON文字列配列。信頼proxyが設定した値は既存の信頼規則に従います。", "JSON string array; values supplied by trusted proxies follow the existing trust policy."),
        ("origin_cloaking_enabled", "origin到達トークンを付与", "Add origin proof token", "backend側の検証と同じDUCKNET_ORIGIN_KEYが必要です。ここには鍵そのものを入力しません。", "Requires backend verification and the same DUCKNET_ORIGIN_KEY. Do not enter the key in this form."),
        ("origin_header", "originトークンのヘッダ名", "Origin token header name", "backend側の検証設定と一致させます。HTTP token形式のヘッダ名だけを指定できます。", "Match backend verification; use only a valid HTTP token header name."),
        ("origin_window_sec", "originトークン時間窓(秒)", "Origin token window (seconds)", "時間バケット幅です。backendの時計と検証設定を合わせます。", "Token time-bucket size; align backend clocks and verification settings."),
        ("stall_detect_enabled", "通信急停止を警告", "Warn on sudden traffic stop", "活発だった通信が突然ゼロになる迂回の兆候を警告します。自動修復や遮断は行いません。", "Warn when active traffic suddenly stops, which may indicate bypass. Does not repair routing or block traffic."),
        ("stall_min_rate", "急停止前の最小要求数/秒", "Minimum active rate before stall", "このレート未満の低トラフィックは急停止警告の対象にしません。", "Do not issue traffic-stop warnings when prior traffic was below this rate."),
    ),
    "cadence": (
        ("cadence_score", "周期的アクセスへの加点", "Periodic-access score", "機械的に規則正しいアクセスへの加点です。正規のポーリングも考慮してください。", "Score added for mechanically regular access. Account for legitimate polling."),
        ("cadence_min_samples", "周期判定の最小サンプル数", "Minimum cadence samples", "周期判定に必要な間隔サンプル数です。", "Number of interval samples required before judging periodicity."),
        ("cadence_cv_threshold", "周期判定の変動係数", "Cadence variation threshold", "間隔の変動係数がこの値未満なら規則的と判定します。", "Treat intervals as regular when their coefficient of variation is below this value."),
        ("cadence_min_mean_interval", "対象平均間隔の最小秒数", "Minimum mean interval", "これ未満の高速バーストは周期判定の対象外です。最大平均間隔より小さくします。", "Exclude faster bursts from cadence detection. Must be below the maximum mean interval."),
        ("cadence_max_mean_interval", "対象平均間隔の最大秒数", "Maximum mean interval", "これより遅い正規ポーリングを周期判定の対象外にします。最小平均間隔より大きくします。", "Exclude slower legitimate polling. Must exceed the minimum mean interval."),
    ),
}

_EXAMPLES = {
    "trusted_proxies": ["192.0.2.10/32"],
    "path_limits": [{"path": "/login", "rate": 1.0, "burst": 2.0}],
    "blocked_methods": ["TRACE", "TRACK", "CONNECT"],
    "cache_poison_headers": ["x-forwarded-host", "x-forwarded-scheme"],
    "jwt_allowed_algs": ["RS256", "ES256"],
    "open_redirect_allow": ["accounts.example.com"],
    "graphql_paths": ["/graphql"],
    "upload_deny_ext": ["php", "phtml", "exe"],
    "blocked_extensions": [".sql", ".bak"],
    "blocked_urls": ["/internal", "/admin"],
    "private_paths": ["/private", "/exports"],
    "private_path_allow": ["192.0.2.10/32"],
    "geo_cidrs": ["192.0.2.0/24"],
    "site_whitelist": ["app.example.com"],
    "site_blacklist": ["blocked.example.com"],
    "ip_whitelist": ["192.0.2.0/24"],
    "ip_blacklist": ["198.51.100.0/24"],
    "optional_sigs": {"ssti": False, "ssrf_internal": False, "redirect": False},
    "sec_headers_extra": {"Content-Security-Policy": "default-src 'self'"},
    "sec_headers_strip": ["Server", "X-Powered-By"],
}


def settings_schema() -> dict:
    """Return fresh, bilingual metadata for every currently supported setting."""
    groups = [{"id": key, "label": ja, "label_en": en} for key, ja, en in _GROUPS]
    fields, seen = [], set()
    kinds = {bool: "boolean", int: "integer", float: "number", str: "string",
             list: "array", dict: "object"}
    for group in groups:
        for key, label, label_en, description, description_en in _TEXT[group["id"]]:
            if key in seen or key not in _DEFAULTS:
                raise RuntimeError("dashboard settings metadata is inconsistent")
            seen.add(key)
            default = _DEFAULTS[key]
            kind = kinds.get(type(default))
            if kind is None:
                raise RuntimeError("dashboard setting has unsupported type")
            field = {"key": key, "group": group["id"], "label": label,
                     "label_en": label_en, "description": description,
                     "description_en": description_en, "type": kind,
                     "default": copy.deepcopy(default)}
            if key in _HARD_BOUNDS:
                field["minimum"], field["maximum"] = _HARD_BOUNDS[key]
            elif key == "paranoia":
                field.update(minimum=1, maximum=4)
            if key in _RATE_COUNT_KEYS:
                field["maximum"] = _RATE_COUNT_MAX
            if key in _POSITIVE_KEYS and kind == "integer":
                field.setdefault("minimum", 1)
            if key in _NONNEG_KEYS:
                field.setdefault("minimum", 0)
            if key in _ENUM_KEYS:
                field["choices"] = list(_ENUM_KEYS[key])
            if kind in ("array", "object"):
                field["format"] = "json"
                field["example"] = copy.deepcopy(_EXAMPLES.get(key, default))
            fields.append(field)
    if seen != set(_DEFAULTS):
        raise RuntimeError("dashboard settings metadata is incomplete")
    return {"groups": groups, "fields": fields}
