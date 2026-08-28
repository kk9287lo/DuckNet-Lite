"""
pipeline.py — 高度なL7 DDoS / ネット侵入防御(アプリ層・OS非侵襲・ON/OFF)
====================================================================================
クラウド級WAF/DDoS防御の中核概念を **クリーンルームで自作** したもの(特定製品の模倣でも
コードの流用でもない・固有名なし)。先の app_firewall(送信元ゾーン制御)の上に、L7の
レート制限・侵入シグネチャ・脅威スコア・自動BAN・異常検知を積む。

正直な線引き(誇張しない):
  · これは **L7(アプリ層)** 防御=本アプリのサーバが受理したHTTP要求を検査して弾く。
  · **L3/L4 のボリューメトリック攻撃**(回線/OSを飽和させる UDP/SYN flood 等)は本層では
    止められない(ISP/ネットワーク機器/Anycastの領域)。これを止められると誇張しない。
  · 防御専用: 反撃・増幅・スキャンはしない。自分のリスナーを守るだけ。OS非侵襲・可逆。

規模の天井(商用WAFとの差・正直に):
  · 単一Pythonプロセス+ロックなので、数百万同時接続級では GIL/ロック競合が頭打ちになる。
    本気の超大規模は別アーキ(C/Go/Rust・Redis等のKVS・Nginx+Lua・eBPF/カーネル層・Anycast)。
    → 本実装は『中小規模の自衛+多層防御の一枚』として正直に位置づける。ロック保持時間は
      正規表現走査をロック外に出して縮小し、入力は正規化+長さ上限(_MAX_SCAN)で ReDoS と
      CPU枯渇を抑える。それでも正規表現WAFは原理的に完全ではない(難読化で擦り抜け得る)。
  · 将来の高速化は本PJの Rust 継ぎ目([[project-self-transpile]])でホットパスを native 化する
    余地がある(検証つき・可逆)。今は誠実に『純Python・有界』のまま。

構成要素:
  · トークンバケット レート制限(IP毎・rate/burst)。
  · スライディングウィンドウ flood 検知(window秒で閾値超過)。
  · 侵入シグネチャ(SQLi/XSS/traversal/RCE/スキャナUA/機微パス)= L7 WAF。
  · 脅威スコア(各寄与を加算・時間で半減減衰)→ allow/throttle/block(deny_score 以上は単発拒否、
    block_score 以上は自動BAN。中間の『チャレンジ(PoW)』段は本エディションには無い=上位版のみ)。
  · 自動BAN(TTL付き)・解除。全体レートのEWMAはテレメトリとしてダッシュボードに出す。
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import unicodedata
from collections import deque

from ..core.atomic_io import default_state_dir, atomic_write_json, safe_read_json
from ..core.signed_state import persistent_key, write_signed_json, read_signed_json
from .bloom import BloomFilter
from ..core import saferegex

# ── 侵入シグネチャ(L7 WAF・カテゴリ別・原創パターン) ──
# シグネチャは ReDoS を避けるため貪欲な .+ を使わず、境界を有界(lazy {0,N}?)にする。
# 入力も走査前に正規化+長さ上限([[_MAX_SCAN]])するので、巧妙な難読化と巨大入力の
# 両方を抑える(ただし正規表現WAFは原理的に完全ではない=多層防御の一枚と明記)。
_SIGNATURES = [
    ("sqli", r"(?i)(\bunion\b[\s(;]*(?:(?:all|distinct)[\s(;]+)?\bselect\b|\bor\b[\s;]+1\s*=\s*1|'[\s;]*--|\bselect\b.{0,120}?\bfrom\b.{0,120}?\bwhere\b|\bdrop\b[\s;]+\btable\b)"),
    # F7(検討・不採用): document.cookie 単独をエクスフィル文脈(fetch(/XHR/sendBeacon/img src等)
    # との近接必須にする案を検証したが、既存の回帰テスト test_prescan_is_a_true_superset_of_signatures
    # (tests/test_logio.py)が bare "document.cookie" を xss の代表的真陽性サンプルとして明示的に
    # 要求しており、これを崩すと既存の確立された真陽性検知を弱める(タスク方針=既存の真陽性検知を
    # 犠牲にする narrowing はしない、に反する)。安全な絞り込みが見つからなかったため据え置き
    # (既知の限界として文書化。F7参照)。
    ("xss", r"(?i)(<\s*script|onerror\s*=|javascript:|vbscript:|data:text/html|<\s*img[^>]{0,200}?onerror|document\.cookie)"),
    ("traversal", r"(?i)((?:\.\./){2,}|(?:\.\.\\){2,}|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|c:\\windows\\|\bwin\.ini\b|\bboot\.ini\b|\.\.;)"),
    ("rce", r"(?i)((?:;|\|\||&&)\s*(cat|wget|curl|bash|sh|nc|powershell)\b|\$\([^)]*\)|`[^`]*`|\|\s*(nc|bash|sh|curl|wget|python)\b|\(\)\s\{|<\?php\b|<\?=)"),
    ("scanner_ua", r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zgrab|nuclei|httpx)\b"),
    ("sensitive_path", r"(?i)(/\.env\b|/wp-login|/xmlrpc\.php|/phpmyadmin|/\.git/|/\.aws/|/actuator/|/\.ssh/)"),
    # ブラインド/時間/エラーベース SQLi: union/恒真式に出ない別系統(関数呼び・遅延・メタ表)。
    # information_schema はスキーマ修飾参照(information_schema.tables 等)必須=地の文の
    # 単発言及(「information_schemaを調べたい」等)を誤検知しない(実SQLiは常にドット修飾で使う)。
    ("sqli_blind", r"(?i)(\bsleep\s*\(|\bbenchmark\s*\(|\bpg_sleep\s*\(|\bwaitfor[\s;]+delay\b|\bextractvalue\s*\(|\bupdatexml\s*\(|\bload_file\s*\(|\binto[\s;]+(?:out|dump)file\b|\binformation_schema\.\w+)"),
    # NoSQL(Mongo)演算子注入: id[$ne]=1 / $where(配列添字形)、または {"$ne": ...} / $gt: ...
    # (JSONネイティブのキー形・コロン付き)。配列添字 filter[name] とは $ 接頭で区別=低誤検知。
    ("nosqli", r"(?i)(\[\$(?:ne|gt|lt|gte|lte|eq|in|nin|regex|where|exists|or|and|not|nor|all|elemmatch|mod|size|type)\b|\$where\b|[\"']?\$(?:ne|gt|lt|gte|lte|eq|in|nin|regex|where|exists|or|and|not|nor|all|elemmatch|mod|size|type)\b\s*[\"']?\s*:)"),
    # SSRF/LFI ラッパー: php://filter, gopher://, dict:// 等の危険スキーム(http/https は対象外)。
    # file:// のみ、地の文のファイル共有リンク言及(「file://server/share/x.pdf」等)が多いので
    # パラメータ値位置(= の直後)限定にして誤検知を減らす。他スキームはほぼ常に悪性=無条件。
    ("lfi", r"(?i)((?:php|gopher|dict|expect|phar|netdoc)://|=file://)"),
    # Log4Shell(JNDI ルックアップ): ${jndi:ldap://…}。直接形を捕捉(深い ${lower:} 入れ子は対象外)。
    ("jndi", r"(?i)(\$\{jndi:|\bjndi:(?:ldap|ldaps|rmi|dns|iiop|nis|corba)\b)"),
    # SSRF クラウドメタデータ: IMDS(169.254.169.254 等)/メタデータホスト。資格情報窃取の的。
    # これらはユーザー入力にまず現れない=ほぼ誤検知ゼロ(部分一致 169.254 や /latest/news は非該当)。
    # 10進(2852039166)/16進(0xa9fea9fe)表記の IMDS IP も同一ホストに解決される=バイパスになる
    # ため追加。ただし裸の大数値(注文合計/タイムスタンプ/ハッシュ等)を誤検知しないよう、URL
    # authority 位置(:// または @ の直後)限定にする。パスも /latest/dynamic・/latest/user-data
    # (末尾 / 任意)まで拡張(旧は /latest/meta-data/ の末尾 / 必須・このパスのみだった)。
    ("ssrf", r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|/latest/(?:meta-data|dynamic|user-data)\b|/computemetadata/|(?:://|@)2852039166\b|(?:://|@)0xa9fea9fe\b)"),
    # プロトタイプ汚染(Node.js)+ クラスローダ汚染(Spring4Shell)。ユーザー入力にまず現れない。
    ("proto", r"(?i)(__proto__|constructor\W{0,4}prototype|class\W{0,4}module\W{0,4}classloader)"),
    # CRLF/レスポンスヘッダ注入: %0d%0a は正規化で ; になる(step5)。; に続くレスポンスヘッダ名は
    # 応答分割/ヘッダ注入の企図。;location 等は ; 付きで照合するので ?location=x は誤検知しない。
    # CRLF/レスポンスヘッダ注入 + メールヘッダ注入(%0a 後の bcc/cc/to/mime-version 等)。
    ("crlf", r"(?i);(set-cookie|location|refresh|content-type|content-length|content-disposition|bcc|cc|to|mime-version|content-transfer-encoding):"),
    # XXE: <!ENTITY 定義、外部 SYSTEM 付き DOCTYPE、または PUBLIC 外部識別子形(公開識別子+
    # 取得可能な system 識別子URIの2連続引用符=外部サブセットの時のみ出現)。良性 <!doctype html>
    # は引用符が無いので非該当。
    ("xxe", r"(?i)(<!entity|<!doctype[^>]{0,120}?system|<!doctype[^>]{0,120}?public\s+[\"'][^\"']*[\"']\s+[\"'])"),
    # OGNL/Struts2(S2-*)・式言語経由 RCE の核語。ユーザー入力にまず現れない=低FP。
    ("ognl", r"(?i)(_memberaccess|@java\.lang\.runtime|@java\.lang\.processbuilder|#context\[|ognl\.)"),
    # SSI(Server Side Includes)注入: <!--#exec / #include 等。ユーザー入力にまず現れない=低FP。
    ("ssi", r"(?i)<!--#[\s;]*(exec|include|echo|config|fsize|flastmod|printenv|set)\b"),
    # LDAP インジェクション: フィルタメタ文字の注入形 )(| / *)( / )(uid= 等。良性 (a)(b) は非該当。
    ("ldapi", r"(?i)(\)\(\||\)\(&|\*\)\(|\)\([a-z]+=)"),
    # ── 以下はオプション(_OPTIONAL_SIGS・既定OFF)。コンパイルは常時・評価は cfg で個別ON時のみ ──
    # SSTI(テンプレート注入): {{...}} / <%= / #{...} / ${...演算子...}。テンプレ利用アプリで正規にも出る=高FP。
    ("ssti", r"(\{\{.{0,100}?\}\}|<%=|#\{.{0,100}?\}|\$\{[^}]{0,80}?[-+*/%][^}]{0,80}?\})"),
    # 内部/プライベート宛 SSRF + 難読化ループバック(0x7f…/10進2130706433/8進)。管理用途で正規にも出る=高FP。
    ("ssrf_internal", r"(?i)(127\.0\.0\.1|0\.0\.0\.0|\blocalhost\b|192\.168\.\d|169\.254\.\d|\b0x7f[0-9a-f]{6}\b|\b2130706433\b|\b017700000001\b)"),
    # オープンリダイレクト: プロトコル相対 //host へ誘導(=//)。正規の //cdn 参照もある=高FP。
    ("redirect", r"=//[a-z0-9.\-]"),
]
_SIG_RE = [(name, re.compile(pat)) for name, pat in _SIGNATURES]
_SIG_WEIGHT = {"sqli": 55, "xss": 45, "traversal": 50, "rce": 60,
               "scanner_ua": 65, "sensitive_path": 30,
               "sqli_blind": 60, "nosqli": 55, "lfi": 55, "jndi": 65, "ssrf": 60,
               "proto": 50, "crlf": 45, "xxe": 55, "ognl": 60, "ssi": 60, "ldapi": 55,
               "ssti": 50, "ssrf_internal": 45, "redirect": 45}

_DEFAULTS = {
    "enabled": False,            # 既定OFF(完全パススルー)
    "rate_per_sec": 20.0,        # IP毎の定常許容レート
    "burst": 40,                 # バースト許容
    # 同時接続数の上限(evolution #30): 1 IP が同時に保持できる接続数の上限(nginx limit_conn 相当)。
    #   レート(per-request)とは別軸=接続枯渇/保持(slowloris 増幅)対策。既定0=無制限(NAT巻き添え
    #   回避で明示オプトイン)。超過接続は head 解析前に即切断。
    "max_conn_per_ip": 0,
    # keep-alive 越しの検査回避を封じる(evolution #31): 転送リクエストの Connection を close に
    #   書き換え、1接続=1リクエストにする。これが無いと2本目以降が未検査で素通りする(WAFバイパス)。
    #   既定ON(安全側)。keep-alive を活かしたい高度運用のみ False(検査回避のリスクを承知の上)。
    "force_conn_close": True,
    # 信頼 proxy(evolution #32): 本機の手前に信頼できる proxy/LB がいる構成で、その CIDR を列挙すると
    #   peer がそれに含まれる時 *だけ* X-Forwarded-For から実クライアントIPを採用(rate-limit/ban/subnet が
    #   全クライアント=proxyIP に潰れるのを防ぐ)。既定[]=直結前提で XFF を一切信頼しない(偽装無効化)。
    "trusted_proxies": [],
    # パス別レート制限(evolution #21): 認証/高コスト経路を *グローバルより厳格に* 絞る。
    #   各ルール {path: 前方一致prefix(リテラル), rate: 毎秒, burst: 瞬間(既定=rate)}。
    #   per-IP の専用トークンバケツを既存のIP毎バケツに重ねる。既定[]=無効(ゼロコスト)。
    "path_limits": [],
    # レート超過(throttle)応答(evolution #24): 標準的な HTTP 429 + Retry-After をまっとうな
    #   クライアント/SDK に返してバックオフを促す。False で従来の無言TCP切断へ。
    "throttle_response": True,    # throttle時に 429 を返す(False=即時切断・無応答)
    "throttle_retry_after": 1,   # 429 の Retry-After 秒(クライアントへの再試行目安)
    # サブネット集約防御(evolution #25): 同一サブネット(/24・v6 /64)で *別IP* が多数BANされたら
    #   分散攻撃の温床=新規IPにソフト加点して早期に絞る。既定OFF・ハードBANはしない(NAT/CGNAT
    #   巻き添え回避)。distinct IP 閾値+時間窓で誤検知を抑える正直なトレードオフ機能。
    "subnet_defense": False,     # 既定OFF(共有NATを巻き込み得るため明示オプトイン)
    "subnet_threshold": 8,       # この数の *別IP* が窓内BANでサブネットを hot 扱い
    "subnet_window_sec": 3600,   # BAN を集計する時間窓(秒)
    "subnet_score": 30,          # hot サブネットの新規IPへ一度だけ加える score(deny_score未満=ソフト)
    # HTTPメソッドポリシー(evolution #26): XST(TRACE/TRACK)・プロキシ濫用(CONNECT)等、アプリ
    #   前段にまず正規には来ない異常メソッドを遮断。低FP=既定で3種を拒否(空配列で無効化可)。
    "blocked_methods": ["TRACE", "TRACK", "CONNECT"],
    # メソッドオーバーライド悪用対策(evolution #72): X-HTTP-Method-Override 等で実効メソッドを
    # 差し替え、blocked_methods や method ベース認可を回避する手口を塞ぐ。オーバーライド先にも
    # method ポリシーを適用。method_override_block でオーバーライドヘッダ自体を拒否(より厳格)。
    "method_override_check": True,   # オーバーライド先メソッドにも blocked_methods を適用
    "method_override_block": False,  # オーバーライドヘッダの存在自体を遮断(opt-in・厳格)
    # パスオーバーライド ACL バイパス対策(evolution #73): X-Original-URL/X-Rewrite-URL は内部
    # rewrite 用ヘッダ。前段エッジにクライアントが送る=パス ACL 回避の手口(IIS/nginx)。既定で遮断。
    "path_override_block": True,     # クライアント供給の X-Original-URL/X-Rewrite-URL 等を遮断
    # Range ヘッダ DoS 対策(evolution #76): 多数レンジ要求(Apache Killer・CVE-2011-3192 系)で
    # サーバに大量のバッファを確保させる DoS を、レンジ数の上限で遮断。正規クライアントは 1〜2 レンジ。
    "range_check_enabled": True,     # 過大な Range(多数レンジ)を遮断
    "range_max_ranges": 8,           # Range ヘッダの許容レンジ数(超で遮断)
    # キャッシュ汚染ヘッダの除去(evolution #75): バックエンドが反映すると Web キャッシュ汚染/
    # パスワードリセットのポイズニングを招く unkeyed ヘッダを、*信頼 proxy 経由でない* クライアント
    # 供給時に転送前に除去する(信頼 proxy 背後ではその proxy が正当に設定する=除去しない)。
    "strip_cache_poison_headers": True,
    "cache_poison_headers": ["x-forwarded-host", "x-forwarded-scheme",
                             "x-forwarded-server", "x-forwarded-port",
                             "x-forwarded-prefix", "x-host"],
    # バックエンド・バイパス防止(evolution #77): エッジ経由を証明する時間有界トークンを転送要求へ
    # 付与する。バックエンドが検証し、トークン無し(=ChickenNet を迂回した直叩き/再ルーティング)を
    # 拒否する。鍵は env CHICKENNET_ORIGIN_KEY をエッジ・バックエンドで共有(VM 外保管を推奨)。opt-in。
    "origin_cloaking_enabled": False,  # 転送要求にオリジントークンを付与(バックエンドが検証)
    "origin_header": "X-Edge-Token",   # トークンを載せるヘッダ名(中立名・バックエンドと合わせる)
    "origin_window_sec": 30,           # トークンの時間バケット幅(リプレイ窓・時計ずれ吸収)
    # 迂回検知 / dead-man's switch(evolution #78): ChickenNet 経由のトラフィックが *直近は活発だったのに
    # 突然ゼロ* になったら、再ルーティング等で迂回された疑い。busy→ゼロ の遷移のみ警報=自然な低トラフ
    # では誤検知しない。AsyncEdgeGuard の独立した定期チェックループから呼ぶ。
    "stall_detect_enabled": True,    # トラフィック急停止(迂回の疑い)を検知して警報
    "stall_min_rate": 1.0,           # 「直近 busy」とみなす最小レート(req/s)。これ未満は静観
    # 資源枯渇ハードニング(evolution #79): 接続フラッドで FD/ソケット/メモリを枯渇させ OS ごと
    # 落とす低レイヤ攻撃に対し、*全体* の同時接続数で頭打ちにしてロードシェッドする(per-IP の #30 の上)。
    "max_total_conn": 20000,         # 全体の同時接続上限(超過分は即切断)。0=無制限
    # per-IP 接続レート上限(#10): 接続→即RST/即切断を高速反復する churn フラッドを、head 解析や
    #   backend 接続より手前で安価に shed する(秒間の新規接続数)。0=無効(NAT 巻添え回避で既定OFF)。
    "conn_rate_per_ip": 0,
    "window_sec": 10,            # flood検知ウィンドウ
    "flood_threshold": 150,      # window内の要求数閾値
    # スコア閾値は2段階(evolution #110 で PoW チャレンジ段を廃止・単発拒否へ統合):
    #   deny_score  以上 … その場のリクエストのみ拒否(BANはしない・単発の疑わしい signal 用)。
    #   block_score 以上 … 自動BAN(TTL付き・累犯エスカレーション)。
    "deny_score": 40,            # これ以上で単発拒否(BANなし)
    "block_score": 100,          # これ以上でBAN
    "slowloris_score": 50,       # ヘッダ未完(slowloris)1回あたりの加点(反復でBAN)
    # 応答アウェア脅威スコア(evolution #60): バックエンド応答のクライアントエラー(4xx)の
    # 連射を列挙(404)/ブルートフォース・クレデンシャルスタッフィング(401/403)の足跡として検知。
    # リクエスト署名では捕まらない攻撃を *応答の足跡* で捉える。5xx はバックエンド起因で
    # クライアントの非ではない事が多いので加点しない(テレメトリのみ)=誤遮断回避。
    "resp_score_enabled": True,  # 応答エラーレートで脅威加点(列挙/ブルートフォース検知)
    "resp_error_window_sec": 60, # 4xx 集計窓
    "resp_error_threshold": 50,  # 窓内 4xx 数の閾(超で加点・1回=保守的な値)
    "resp_error_score": 50,      # 閾超過1回あたりの加点(note_response は block_score のみ判定=
                                 # 1バーストはスコア記録に留め即BANしない)。2バーストで block_score(100)→BAN。
    # 要求ボディ検査(evolution #61): head-only の死角=POST/JSON/GraphQL 本文の SQLi/XSS/RCE/SSTI を、
    # 本文先頭を *有界* に能動読取して head と同じ署名エンジンで走査する。block_score 超で BAN。
    "body_scan_enabled": True,   # 要求ボディのシグネチャ走査(head-only の死角を塞ぐ)
    "body_scan_max_bytes": 65536,  # 本文先頭この量だけ走査(全バッファしない=fail-fast/有界)
    # 誤BAN低減(#FP): 要求ボディ(=問い合わせフォーム等の本文)由来のシグネチャは確度が低い
    #   (一般ユーザーが "SELECT 文について" 等と書く)。本文ヒットのスコア寄与をこの係数で下げ、
    #   『単発の疑わしい本文』では即BANせずスコア記録止まりにする(block_score 未満なら allow)。1.0=従来どおり。
    "body_sig_weight_factor": 0.7,
    "body_decode_enabled": True,   # gzip/deflate 圧縮ボディを有界解凍して走査(#74・圧縮回避封じ)
    # ヘッダ整合性ボット検知(evolution #63): UA はブラウザを名乗るのに実ブラウザが常時送る
    # ヘッダ(Accept-Language/Accept-Encoding)を欠く=ツールの UA 偽装。低FPで *加点のみ*
    # (単独では落とさず、flood/scan 等と合算でエスカレーション)。
    "bot_consistency_enabled": True,   # UA とヘッダの整合性チェック(ブラウザ偽装ツール検知)
    "bot_inconsistency_score": 20,     # 不整合1回あたりの加点(deny_score 未満=単独では非遮断)
    # JWT 検査(evolution #68): Authorization: Bearer の JWT を *鍵無しで* 構造点検する。
    # alg:none(無署名トークン=認証バイパス)を遮断。jwt_allowed_algs を設定すると許可外
    # アルゴリズム(RS256→HS256 等の alg 混同)も遮断。署名検証はアプリの責務(鍵が無い)。
    "jwt_inspect_enabled": True,   # Bearer JWT の alg:none / 許可外 alg を遮断
    "jwt_allowed_algs": [],        # 許可する alg のホワイトリスト(空=none のみ遮断)。例 ["RS256","ES256"]
    # クレデンシャル単位レート制限(evolution #70): IP ではなく Bearer トークン/API キーの *識別子*
    # 単位でレートを集計する。攻撃者が IP をローテーションしつつ同一の盗用キーを使う濫用を、IP に
    # 依らず絞る。トークンは生で保持せずハッシュ短縮。超過で加点(既定=deny_score→単発拒否)。
    "cred_rate_enabled": False,    # API キー/トークン単位のレート制限(IP ローテーション濫用対策)
    "cred_rate_window_sec": 60,    # 集計窓
    "cred_rate_limit": 600,        # 窓内のリクエスト上限(超で加点)
    "cred_rate_score": 40,         # 超過時の加点(既定=deny_score 相当→次要求で単発拒否)
    # スロー POST(R-U-Dead-Yet)対策(evolution #64): 要求ボディの *総受信時間* に上限を設ける。
    # head slowloris(head_timeout)は対処済みだが、ボディを小出しして接続を保持する攻撃に上限が
    # 無かった。client→backend 方向のみに効く(応答=backend→client の長時間ストリームは縛らない)。
    "body_timeout_enabled": True,  # 要求ボディの総受信時間に上限(slow-body 接続枯渇対策)
    "body_max_sec": 60,            # ボディ受信の総許容秒(超過=切断+slow_body 加点)。大容量UL は上げる
    # Set-Cookie ハードニング(evolution #65): 応答 Set-Cookie に欠けた保護属性を補完する。
    # バックエンドが付け忘れても WAF 側で Cookie を硬くする(セキュリティヘッダ注入#12 と同型)。
    "cookie_harden_enabled": True, # 応答 Set-Cookie に SameSite/Secure(TLS時)を補完
    "cookie_samesite": "Lax",      # 欠落時に付与する SameSite 値("" で無効化)。Lax=ブラウザ既定相当
    "cookie_httponly": False,      # HttpOnly も補完するか(JS 読取 Cookie を壊し得る=opt-in)
    # CORS 誤設定の無害化(evolution #69): 応答の Access-Control-Allow-Credentials: true と
    # Access-Control-Allow-Origin が * / null の併存は *常に危険な誤設定*(任意/サンドボックス origin が
    # 資格情報付き応答を読める)。資格情報ヘッダを除去して無害化する。静的 origin + credentials の
    # 正当構成は一切触らない=FPほぼ無し。
    "cors_harden_enabled": True,   # ACAO:*/null + ACAC:true の危険な CORS 誤設定を無害化
    # オープンリダイレクト無害化(evolution #71): 3xx 応答の Location が *外部の許可外ホスト* を
    # 指す=フィッシング誘導。enforce=Location を安全パスへ書換、audit=記録のみ。リクエスト自身の
    # Host と open_redirect_allow のホストは常に許容(OAuth 等の正当な外部遷移は許可リストで通す)。
    "open_redirect_enabled": False,    # 外部許可外への 3xx リダイレクトを無害化
    "open_redirect_mode": "enforce",   # enforce=安全パスへ書換 / audit=記録のみ
    "open_redirect_allow": [],         # 許可する外部リダイレクト先ホスト(例 ["accounts.google.com"])
    "open_redirect_safe_path": "/",    # enforce 時に書き換える安全な遷移先
    # ファイルアップロード検査(evolution #66): multipart の filename= から危険拡張子(webshell/実行体)を
    # 拒否する。#61(本文シグネチャ)とは別関心=ファイル種別ポリシー。二重拡張子(shell.php.jpg)も
    # 全セグメント検査で捉える。block_score 超で BAN。
    "upload_scan_enabled": True,   # multipart アップロードの危険拡張子拒否(webshell 投入対策)
    # GraphQL クエリ防御(evolution #67): 深いネスト/複雑度/イントロスペクション/バッチを上限化。
    # 既定OFF(GraphQL を使う配備で有効化)。graphql_paths のエンドポイントにだけ適用。
    "graphql_enabled": False,      # GraphQL 固有のDoS/情報漏洩防御
    "graphql_paths": ["/graphql"], # GraphQL とみなすパス(前方一致)
    "graphql_max_depth": 12,       # 選択セットの最大ネスト深さ(超で遮断)
    "graphql_max_complexity": 100, # 選択セット数の上限(エイリアス/フィールド増幅対策)
    "graphql_block_introspection": True,  # __schema/__type を遮断(本番のスキーマ漏洩防止)
    "graphql_max_batch": 10,       # バッチ(配列)オペレーション数の上限
    "upload_deny_ext": [           # 拒否するサーバ実行/スクリプト拡張子(小文字・ドット無し)
        "php", "php3", "php4", "php5", "php7", "phtml", "pht", "phar",
        "jsp", "jspx", "jspf", "asp", "aspx", "asa", "asax", "cer",
        "exe", "dll", "sh", "bash", "bat", "cmd", "com", "cgi", "pl",
        "py", "rb", "jar", "war", "ear", "htaccess"],
    "ban_ttl_sec": 300,          # 自動BANの有効期間
    # 累犯エスカレーション(evolution #19): 同一IPの再BANほどTTLを指数的に延長(初回=据置)。
    "ban_escalation": True,      # 累犯ほど長くBAN(常習攻撃者の再来を重く罰し、再処理を減らす)
    "ban_escalation_cap": 64,    # TTL倍率の上限(base*cap が最長。例 300s×64 ≈ 5.3時間)
    "ban_escalation_retain_sec": 86400,  # 累犯回数(ban_count)を再起動越しに覚えておく窓(BAN期限切れ後)。
                                 #   この秒数を過ぎた offender は初犯に戻す(=エスカレーション記憶の保持期間)
    "block_page": True,          # 遮断時に静かに切断せず『アクセス遮断ページ』を返す
    "appeal_enabled": True,      # 遮断ページに『解除リクエスト(異議申立)』を表示
    "appeal_after_sec": 120,     # BANから この秒数 経過後にのみ解除リクエストを表示(数分後)
    "persist_bans": True,        # BANをディスク永続化(再起動で消えない・クラスタは共有ファイル/Redis継ぎ目)
    "mode": "enforce",           # enforce=実遮断 / audit=通過するがアラート(監視モード)
    "blocked_extensions": [],    # 遮断する拡張子(例 .env .sql .bak .git .ini)
    "blocked_urls": [],          # 遮断するURL部分文字列(例 /admin /wp-admin)
    "require_tls": False,        # 正規TLS以外(平文)を遮断(X-Forwarded-Proto=https 必須)
    "geo_mode": "off",           # off / allow / block(CIDR)
    "geo_cidrs": [],             # 国/地域のCIDR(海外通信ブロック等・DB不要)
    # データ漏洩防止: 1IPが窓(N日)内に送出できる量/接続時間の上限(明らかな大量流出を遮断)
    "quota_enabled": False,
    "quota_window_days": 1,      # 集計窓(1〜N日)
    "quota_max_gb": 0.0,         # 0=無制限。窓内に1IPへ送出(=持ち出し)できる上限GB(10^9 bytes)
    "quota_max_conn_sec": 0.0,   # 0=無制限。窓内の合計接続時間(秒)の上限
    # サイト(ドメイン)許可/遮断: Hostで判定。whitelist=これ以外遮断 / blacklist=これを遮断
    "site_mode": "off",          # off / whitelist / blacklist
    "site_whitelist": [],        # 例 ["example.com", "*.corp.local"]
    "site_blacklist": [],
    # IP(送信元)単位の白/黒リスト。CIDRで包括登録可(例 "10.0.0.0/8")。ドメインと同じUX。
    "ip_mode": "off",            # off / whitelist / blacklist
    "ip_whitelist": [],
    "ip_blacklist": [],
    "usage_record": True,        # ネットワーク使用量リスト(誰が/どのサイトと/どれだけ)を記録
    "score_halflife_sec": 30.0,  # スコア半減期
    # 低速・規則性検知(ステルスBot/スクレイパ。Floodに掛からない等間隔アクセスを炙る)
    "cadence_score": 35,         # 機械的規則性を検知した時の加点
    "cadence_min_samples": 8,    # 判定に要する最小サンプル数
    "cadence_cv_threshold": 0.15,  # 変動係数(これ未満=規則正しすぎ=機械)
    "cadence_max_mean_interval": 3.0,  # 平均間隔がこれ超なら対象外(遅い正規ポーラを誤検知しない)
    # 高FPシグネチャの個別ON/OFF(既定OFF)。{name: True} で有効化。誤検知が許容な環境だけ点ける。
    "optional_sigs": {},
    # 検知の段階的厳格度(evolution #16): 1=保守(誤検知最小)〜4=最大(高FP許容)。set_paranoia が
    # レベルに応じて高FPの任意シグネチャを一括ON(個別 optional_sigs の上位ダイヤル)。既定1。
    "paranoia": 1,
    # 出口DLP(evolution #6): 応答に混入した秘密情報(鍵/トークン/カード番号)の漏洩検知。
    "dlp_enabled": False,        # 既定OFF(オプトイン)
    "dlp_action": "audit",       # audit=アラートのみ / block=漏洩チャンクを送らず切断
    "dlp_max_scan_bytes": 262144,  # 応答先頭この量だけ走査(fail-fast=全バッファしない)
    # 応答セキュリティヘッダ(evolution #12): バックエンド応答に防御ヘッダを注入/情報漏洩ヘッダを除去。
    "sec_headers_enabled": False,  # 既定OFF(オプトイン)。ON で保守的な既定ヘッダ群を付与
    "sec_headers_extra": {},     # 運用者の追加/上書き(例 {"Content-Security-Policy": "default-src 'self'"})
    "sec_headers_strip": [],     # 除去するヘッダ名(例 ["Server","X-Powered-By"]=指紋/情報漏洩を消す)
}
# 既定OFFの高FPシグネチャ(テンプレ/内部IPはアプリ次第で正規にも現れる=オプトイン運用)。
_OPTIONAL_SIGS = frozenset({"ssti", "ssrf_internal", "redirect"})
# フィールド限定シグネチャ(#FP: scanner_ua/sensitive_path): この2つは意味的に『そのフィールド
# 自体』を指す時だけ攻撃シグナルであり、汎用走査面(path+query+UA混成/各ヘッダ値/本文)に
# 混ざった自由記述内での言及(bioに「nmapやsqlmapに詳しい」/問い合わせ本文に「/wp-login.phpに
# アクセスできない」等)まで拾うと即BAN級の誤検知になる(実証済)。_scan_signatures の汎用走査
# ループからはこの2つを除外し、inspect() が user_agent / path それぞれ専用に個別評価する
# (only= 引数)。他の全カテゴリの走査方式は変えない=最小限のスコープ。
_UA_ONLY_SIGS = frozenset({"scanner_ua"})
_PATH_ONLY_SIGS = frozenset({"sensitive_path"})
_FIELD_SCOPED_SIGS = _UA_ONLY_SIGS | _PATH_ONLY_SIGS
# 段階的厳格度(evolution #16)→ そのレベルで有効化する任意シグネチャ。レベルが上がるほど
# 検知は積極的(誤検知も増える)。新たな任意シグネチャはこのマップに足すだけで段階に組める。
_PARANOIA_TIERS = {
    1: frozenset(),                                        # 低FPの常時ONのみ(既定・最も静か)
    2: frozenset({"redirect"}),                            # + プロトコル相対リダイレクト
    3: frozenset({"redirect", "ssrf_internal"}),           # + 内部宛先(SSRF)
    4: frozenset({"redirect", "ssrf_internal", "ssti"}),   # + テンプレート注入(最大)
}
_MAX_IPS = 20000
_EVENTS_MAX = 500
_APPEALS_MAX = 2000    # 解除リクエスト(異議申立)の保持上限(超過で解決済み優先→最古を退避=メモリ有界)
_PATH_LIMIT_MAX = 64   # パス別レート制限ルールの最大数(per-IP バケツ数の上限=メモリ有界)
_MAX_SUBNETS = 4096    # サブネット集約防御で追跡するサブネット数の上限(超過で古い順に間引き)
_SUBNET_IP_CAP = 256   # 1サブネットあたり記憶する distinct BAN済みIP数の上限(hot 判定に十分)


def _subnet_key(ip: str):
    """IP を集約サブネットキーへ畳む(IPv4=/24・IPv6=/64)。不正/空は None。分散攻撃は同一
    サブネット内でIPをローテーションしがち=per-IP では取りこぼす構造を /24・/64 で束ねて捉える。"""
    try:
        ver = ipaddress.ip_address(ip).version
        return str(ipaddress.ip_network(f"{ip}/{24 if ver == 4 else 64}", strict=False))
    except Exception:
        return None
_CRED_RATE_CAP = 50000   # クレデンシャル単位レート集計マップの上限(#70・メモリ有界)
# 重複(挙動同値)検知用の小コーパス(攻撃片+良性)。新旧パターンの一致集合を比較する。
_DEDUP_CORPUS = [
    "", "/api/health", "/index.html", "page=2&sort=name", "hello world",
    "' or 1=1 --", "union select pw from users", "drop table users",
    "<script>alert(1)</script>", "onerror=alert(1)", "javascript:x",
    "document.cookie", "../../etc/passwd", "/proc/self/environ",
    "c:\\windows\\system32", ";cat /etc/shadow", "|nc 1.2.3.4 80",
    "$(reboot)", "`id`", "sqlmap/1.6", "nikto", "/.env", "/wp-login.php",
    "/phpmyadmin/", "/.git/config", "/actuator/env", "${jndi:ldap://x}",
    "%00", "passwd", "select from where", "0x41414141",
]
_MAX_SCAN = 8192            # シグネチャ走査の入力上限(ReDoS/CPU枯渇の面積を有界化)
_PRE_CUT = _MAX_SCAN * 2    # 正規化前の粗い上限
_MAX_SCAN_FIELDS = 64       # 独立走査するフィールド数の上限(path?query+UA + 各ヘッダ値・CPU有界)


def _now() -> float:
    return time.time()


def _jwt_alg(token: str):
    """Bearer JWT の header(1番目のセグメント)から alg を取り出す(#68)。署名検証はしない
    =鍵不要。3セグメントの JWT でなければ None。base64url/JSON が壊れていても None(落ちない)。"""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0]:
        return None
    try:
        import base64
        seg = parts[0]
        seg += "=" * (-len(seg) % 4)              # base64url パディング補完
        hdr = json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
        return str(hdr.get("alg", "")) if isinstance(hdr, dict) else None
    except Exception:
        return None


def _jwt_violation(auth: str, allowed_algs) -> str:
    """Authorization 値から JWT 違反を判定(#68)。返り値: 違反理由 or ""(問題なし/JWTでない)。
      · alg:none … 無署名トークン=認証バイパスの試み(最重大)。
      · allowed_algs 指定時にそれ以外の alg … alg 混同攻撃の疑い。"""
    a = (auth or "").strip()
    if a[:7].lower() != "bearer ":
        return ""
    alg = _jwt_alg(a[7:].strip())
    if alg is None:
        return ""                                 # JWT でない=対象外
    al = alg.strip().lower()
    if al in ("none", ""):
        return "jwt:alg=none"                     # 無署名=認証バイパス
    allowed = [str(x).lower() for x in (allowed_algs or [])]
    if allowed and al not in allowed:
        return f"jwt:alg-not-allowed:{alg[:16]}"  # alg 混同(許可外)
    return ""


_BROWSER_UA_TOKENS = ("chrome", "safari", "firefox", "edg", "opr", "gecko/")


_FILENAME_RE = re.compile(rb'filename\*?\s*=\s*(?:"([^"\r\n]*)"|([^;\r\n]+))', re.I)


def _dangerous_upload_filename(body: bytes, deny_exts, cap: int = 65536):
    """multipart 本文(先頭 cap)の Content-Disposition: filename= から危険拡張子を探す(#66)。
    返り値 (filename, ext) or None。二重拡張子(shell.php.jpg)は *全* ドットセグメントを検査して
    捉える。NUL 切り(shell.php\\x00.jpg)も各セグメントを NUL で切って先頭を見る。deny_exts は
    小文字・ドット無しの集合。filename= が無い(非multipart等)は None。"""
    deny = {str(e).lower().lstrip(".") for e in (deny_exts or [])}
    if not deny:
        return None
    for m in _FILENAME_RE.finditer(body[:cap]):
        raw = (m.group(1) or m.group(2) or b"").strip()
        if not raw:
            continue
        fn = raw.decode("latin1", "replace")
        # パス分離子を除いた basename の全拡張子セグメントを検査(NUL 切りも考慮)
        base = fn.replace("\\", "/").rsplit("/", 1)[-1]
        for seg in base.lower().split(".")[1:]:
            seg = seg.split("\x00", 1)[0].strip()
            if seg in deny:
                return fn[:120], seg
    return None


def _looks_like_browser_ua(ua: str) -> bool:
    """UA が主要ブラウザを *名乗って* いるか(Mozilla/ + ブラウザトークン)。"""
    u = (ua or "").lower()
    return "mozilla/" in u and any(t in u for t in _BROWSER_UA_TOKENS)


def _ua_header_inconsistent(ua: str, header_names) -> bool:
    """UA はブラウザを名乗るのに、実ブラウザが *ほぼ毎回* 送るヘッダを欠くか(#63)。
    実ブラウザは Accept-Language と Accept-Encoding を事実上常に送る。ツール(curl/requests/Go 等)が
    ブラウザ UA を偽装してもこれらを省きがち=偽装の手掛かり。header_names は小文字ヘッダ名の集合。
    判定不能(header_names 不明)や非ブラウザ UA は False(=加点しない・低FP)。"""
    if header_names is None or not _looks_like_browser_ua(ua):
        return False
    names = {str(n).lower() for n in header_names}
    return ("accept-language" not in names) or ("accept-encoding" not in names)


def _zone_of(ip: str) -> str:
    """IPのゾーン分類(app_firewall と同一基準)。遅延importで循環を避ける。"""
    try:
        from .policy import _zone_of as _z
        return _z(ip)
    except Exception:
        return "unknown"


def _arp_table() -> dict:
    """OSのARPテーブルを *読むだけ*(変更しない=OS非侵襲)。LAN内IP→MACのベストエフォート。
    同一L2セグメントのIPのみ解決可。失敗/非対応は空(正直)。"""
    import subprocess
    out = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           errors="replace", timeout=5)
        for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})[\s)]+.*?"
                             r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", r.stdout):
            out[m.group(1)] = m.group(2).replace("-", ":").lower()
    except Exception:
        pass
    return out


# 独自エンコード/暗号のためのデコーダ継ぎ目(#1 native-override seam と同思想・可逆)。
# 正直な限界: 鍵を要する *任意の* 暗号は WAF 単独では復号できない。だがアプリ固有のエンコード
# (社内base92・XOR・proprietary 等)が分かっているなら、その復号 callable を register_scan_decoder で
# 登録すれば、走査面で復号され、復号後の中身に全シグネチャが効く(=独自暗号化型にオプトインで対応)。
_SCAN_DECODERS: dict = {}    # name -> callable(str) -> str|bytes


def register_scan_decoder(name: str, fn) -> dict:
    """走査前に適用する独自デコーダを登録(可逆=clear_scan_decoder で解除)。fn(str)->str|bytes。"""
    _SCAN_DECODERS[str(name)] = fn
    return {"installed": str(name), "active": True, "total": len(_SCAN_DECODERS)}


def clear_scan_decoder(name: str) -> dict:
    return {"cleared": str(name), "was_active": _SCAN_DECODERS.pop(str(name), None) is not None}


def registered_scan_decoders() -> list:
    return sorted(_SCAN_DECODERS)


def _normalize_for_scan(s: str) -> str:
    """シグネチャ走査前の正規化。難読化(多重エンコード/インラインコメント/空白増し/Unicode)を
    減らし、入力長を有界化して ReDoS と CPU 枯渇を抑える。完全な無害化ではない。"""
    if not s:
        return ""
    s = s[:_PRE_CUT]
    if _SCAN_DECODERS:                        # 登録された独自デコーダを走査面で先に適用(可逆)
        for _name, _fn in list(_SCAN_DECODERS.items()):
            try:
                out = _fn(s)
                if isinstance(out, (bytes, bytearray)):
                    out = bytes(out).decode("utf-8", "replace")
                if isinstance(out, str) and out:
                    s = out[:_PRE_CUT]         # 出力も上限化(暴走デコーダで肥大させない)
            except Exception:
                pass                          # 壊れたデコーダで防御を止めない(素通りより安全側)
    try:
        from urllib.parse import unquote_plus
        # 多重%エンコードを最大5回戻す(WAF定石は2回だが、三重以上のエンコード(例: ".."の
        # 三重エンコード %25252e%25252e)は2回では実体の "." まで戻らずtraversal等が素通りする
        # =実証済バイパス。5回は上限のみで、実際は『変化が無くなった時点』で即break=素通り側
        # (既に完全復号済みの通常トラフィック=大多数)は従来どおり1〜2回で抜ける・低速化しない。
        for _ in range(5):
            dec = unquote_plus(s)
            if dec == s:
                break
            s = dec
    except Exception:
        pass
    try:                                     # ;終端のHTMLエンティティのみ復号(&lt;→<, &#60;→<,
        from html import unescape             #   &#x3c;→<)=実体エンコードXSS/SQLi回避を無効化。
        s = re.sub(                           # ';' 必須ゆえ &gt=10 等の REST フィルタ引数は復号せず
            r"&(?:#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z][a-zA-Z0-9]{1,31});",
            lambda m: unescape(m.group(0)), s)   # 誤検知しない(legacy のセミコロン無し実体は除外)
    except Exception:
        pass
    # Unicode 回避対策(ヒエログリフ/絵文字罠): \uXXXX/\xXX エスケープ復号 → NFKC 正規化
    # (全角 ＜ｓｃｒｉｐｔ＞ 等の互換文字を ASCII へ畳む)→ 不可視/書式制御文字(ゼロ幅・ソフト
    # ハイフン・BOM 等)除去。見た目だけ違う回避(un​ion / <script)を実体へ戻す。
    def _unesc(m):
        try:
            return chr(int(m.group(m.lastindex), 16))
        except Exception:
            return m.group(0)
    s = re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})", _unesc, s)
    if not s.isascii():                          # ASCII はそのまま(高速パス)。非ASCIIのみ重処理。
        try:
            s = unicodedata.normalize("NFKC", s)
        except Exception:
            pass
        # 書式文字(Cf=ゼロ幅/ソフトハイフン/方向制御 等)と \t\r\n 以外の制御文字を除去。
        s = "".join(c for c in s if not (
            unicodedata.category(c) == "Cf"
            or (c < " " and c not in "\t\r\n")))
    # Log4j ルックアップ難読化を畳む: 既知のルックアップ名(${lower:j} 等)と :- デフォルト形
    # (${::-j} / ${env:X:-j})だけを中身へ置換。これで ${${lower:j}ndi:ldap://…} の入れ子回避が
    # jndi: として露出する。jndi 本体(${jndi:...} は名が一致せず :- も無い)は保存される=
    # 過剰畳みしない。入れ子を解くため数回繰り返す(有界)。深い多重入れ子は対象外。
    for _ in range(4):
        dec = re.sub(r"\$\{[^${}]*?:-([A-Za-z0-9.]{1,32})\}", r"\1", s)       # :- デフォルト形
        dec = re.sub(r"(?i)\$\{(?:lower|upper|env|sys|java|main|date|ctx|"
                     r"base64|marker|spring|web|k8s|docker|jvmrunargs|sd)\b:?"
                     r"([A-Za-z0-9.]{1,32})\}", r"\1", dec)                    # 既知ルックアップ名
        if dec == s:
            break
        s = dec
    s = s.replace("\x00", "")                # NULバイト除去
    # MySQL 版付きコメント /*!...*/・/*!50000...*/ は DB が *中身を実行する*。一般コメントと
    # 同様に中身ごと消すと UNION 等が検出から消える(sqlmap versionedkeywords 回避)。よって
    # 囲みだけ剥がして中身は残す。一般 /* ... */ 除去より *前* に行う(でないと先に消える)。
    s = re.sub(r"/\*!(?:\d{1,6})?(.{0,200}?)\*/", r" \1 ", s)
    s = re.sub(r"/\*.{0,200}?\*/", " ", s)   # 一般 SQLインラインコメント /**/ 除去(有界lazy)
    # 注入された改行(%0a/%0d)を区切り ; に正規化。path/query/UA に正規の生改行は無いため、
    # CR/LF はコマンド/文の区切りとみなせる(サーバ側で実際そう解釈される)。これで ; ベースの
    # 既存検知(RCE ;cat / stacked SQL ;select)が改行注入にも効く。空白畳みより *前* に行う。
    s = re.sub(r"[\r\n]+", ";", s)
    s = re.sub(r"\s+", " ", s)               # 空白畳み込み(回避抑制+走査面積減)
    s = re.sub(r"\s*(<=|>=|<>|!=|=|<|>)\s*", r"\1", s)  # 比較演算子前後の空白除去(1 < 2 → 1<2)
    s = re.sub(r"([;|])\s+", r"\1", s)       # ;/| 直後の空白除去(; cat → ;cat)
    return s[:_MAX_SCAN].lower()


def _path_for_match(path: str) -> str:
    """アクセス制御/経路照合用に path を *バックエンドが見る形* へ軽く正規化(evolution #40)。
    %エンコードを最大2回復号し小文字化(query/fragment は除去)。これが無いと blocked_urls /
    blocked_extensions / path_limits を /%61dmin・/secret%2eenv・/%6cogin 等で回避できる
    (バックエンドは復号して提供するのに WAF が生 path で照合してしまうため)。署名走査の重い
    正規化(_normalize_for_scan)とは別系統の軽量版。path の '+' は空白でないので unquote(非plus)。"""
    from urllib.parse import unquote
    p = (path or "").split("?", 1)[0].split("#", 1)[0]
    for _ in range(2):                       # 多重%エンコードも戻す(WAF定石・有界)
        d = unquote(p)
        if d == p:
            break
        p = d
    return p.lower()


# 恒真式(tautology)SQLi の *意味的* 検知 — 文字列マッチを卒業する第一歩(evolution #2)。
# 既存シグネチャは literal "1=1" は拾えるが、値を変えた 2=2 / 99=99 / 'a'='a' は別語ゆえ
# 素通りする。『左右が同値の等式』という *構造* で捉え、値の差し替え難読化に依らず捕捉する。
# (正規化後は = の前後空白が畳まれているため演算子は素の '=' で照合できる)
_TAUTOLOGY_RE = re.compile(
    r"(?:(?<!\d)(\d{1,9})=\1(?!\d))"          # N=N(同値の数値): 1=1, 2=2, 777=777
    r"|(?:'([^']{0,40})'='\2)"                # 'x'='x (右の閉じquoteは任意=実SQLi形)
    r"|(?:\"([^\"]{0,40})\"=\"\3)")           # "x"="x


# 恒真式の一般化(evolution #2 step 3): = 限定から比較演算子全般へ。
# OR 1=1 の WAF 回避亜種(1<2 / 2>1 / 1>=1 / 1<>2 / 9!=8 …)は値も演算子も差し替えるが、
# 『両辺が定数で結果が常に真の比較』という *構造* は不変。両辺がリテラル数値のときだけ
# 実際に評価し、恒真(常に真)の比較のみ拾う。片側が識別子(price>100 等)・小数(1.5<2)は
# lookaround で対象外=正常入力を誤検知しない。常に偽の比較(5>9 / 1=2)も拾わない=精度優先。
_CONST_CMP_RE = re.compile(r"(?<![\w.])(\d{1,9})(<=|>=|<>|!=|=|<|>)(\d{1,9})(?![\w.])")


def _const_true_compare(blob: str) -> bool:
    """両辺がリテラル数値で『常に真』の比較が含まれるか(1<2 / 2>1 / 1>=1 …)。"""
    for m in _CONST_CMP_RE.finditer(blob):
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if (op == "=" and a == b) or (op in ("<>", "!=") and a != b) \
                or (op == "<" and a < b) or (op == ">" and a > b) \
                or (op == "<=" and a <= b) or (op == ">=" and a >= b):
            return True
    return False


def _tautology_suspect(blob: str) -> bool:
    """正規化済み文字列に『常に真の等式/不等式』が含まれるか。
    OR/AND と結合する古典的 SQLi 認証バイパスを、具体的な値・演算子に依らず意味で拾う。
    数値・引用符列の同値(N=N / 'x'='x)に加え、両辺が定数で常に真の数値比較(1<2 等)も見る。
    片側が識別子(user=admin / price>100 等)は対象外なので誤検知しない。"""
    return _TAUTOLOGY_RE.search(blob) is not None or _const_true_compare(blob)


# スタッククエリ(複文)SQLi: ; の後に SQL 文(SELECT/UPDATE/…)が続く構造。
# 既存 needle('drop table' 等)を越え、; + 動詞という *構造* で複文注入を捕捉する。
# URL パラメータに ;<SQL動詞> が現れるのは実質常に注入(誤検知が低い)。
_STACKED_RE = re.compile(
    r";\s*(select|insert|update|delete|drop|create|alter|truncate|exec|union|grant)\b")


def _stacked_query_suspect(blob: str) -> bool:
    """正規化済み文字列に『; に続く SQL 文(複文)』が含まれるか=スタッククエリ注入。"""
    return _STACKED_RE.search(blob) is not None


# DOMイベントハンドラ系 XSS の *構造* 検知 — 個別ハンドラ名の列挙(prescan需要)を避け、
# 『タグ内に on<名前>= が現れる』形で捕捉する(<svg onload= / <div onclick= / <svg/onload=)。
# literal '<タグ' を要求するため、?onload=1 のような素の引数は対象外=低誤検知。タグと
# ハンドラの間は同一タグ内(>を跨がない)・区切りは空白か / (または ; = 生改行が正規化で
# 変換された区切り文字。CRLF注入 <svg\nonload=… を \s 限定だと見逃すため追加)を許容。
# prescan ゲート外で常時評価。
_XSS_HANDLER_RE = re.compile(
    r"<\s*[a-z][a-z0-9]{0,15}[^>]{0,200}?[\s/;]on[a-z]{3,12}\s*=", re.I)


def _xss_event_handler_suspect(blob: str) -> bool:
    """正規化済み文字列に『タグ内の onXxx= イベントハンドラ』があるか=ハンドラ型 XSS。"""
    return _XSS_HANDLER_RE.search(blob) is not None


# ── 出口DLP(evolution #6): 応答に混入した *秘密情報の漏洩* を検出 ──
# 入口の侵入検知だけでなく、バックエンドが誤って鍵/トークン/カード番号を返していないかを
# 出口で見張る。高確度の接頭辞を持つ資格情報のみ対象=低誤検知。クレカは Luhn 検証で絞る。
# バイト列に対して直接走査(応答は任意エンコードゆえ正規化はしない)。
_SECRET_RES = [
    ("aws_access_key", re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("github_token", re.compile(rb"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("stripe_secret", re.compile(rb"\bsk_live_[0-9A-Za-z]{24,}")),
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
]
_CC_RE = re.compile(rb"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: bytes) -> bool:
    """Luhn チェックサム(クレカ番号の妥当性)。誤検知=ただの数字列を大幅に減らす。"""
    total, alt = 0, False
    for ch in reversed(digits):
        d = ch - 48
        if d < 0 or d > 9:
            return False
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def scan_secret_leak(data) -> list:
    """応答バイト列から *高確度の* 秘密情報漏洩を検出し、種別名のリストを返す(無ければ空)。
    資格情報は固有接頭辞、クレカは Luhn+主要ブランド接頭(3/4/5/6)で誤検知を抑える。
    正直: 鍵を要する独自暗号で包まれた秘密は復号できない=対象外(register_scan_decoder の領域)。"""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    found = []
    for name, rgx in _SECRET_RES:
        if rgx.search(data):
            found.append(name)
    for m in _CC_RE.finditer(data):
        digits = bytes(c for c in m.group(0) if 48 <= c <= 57)
        if 13 <= len(digits) <= 19 and digits[:1] in (b"3", b"4", b"5", b"6") \
                and _luhn_ok(digits):
            found.append("credit_card")
            break
    return found


class NetShield:
    """L7 DDoS/侵入防御の中核。アプリ層・OS非侵襲・ON/OFF・記録・永続化。"""

    def __init__(self, state_dir: str = ""):
        base = state_dir or default_state_dir()
        os.makedirs(base, exist_ok=True)
        self.path = os.path.join(base, "state.json")
        self._lock = threading.RLock()
        self._ips: dict = {}            # ip -> state
        self._events = deque(maxlen=_EVENTS_MAX)
        self._subnets: dict = {}           # subnet -> {ip: last_ban_ts}(分散攻撃の集約検知・有界)
        self._metrics = {"requests": 0, "allow": 0, "throttle": 0, "block": 0}
        self._ewma = 0.0                # 全体レートのEWMA(ダッシュボード用テレメトリ)
        self._ewma_last = _now()
        self._started = _now()          # プロセス稼働開始時刻(uptime 算出・ダッシュボード)
        # 既知BAN IP の確率的プリスキャン(真O(k)・bytearray)。BAN時に add、判定は lock-free。
        self._ban_bloom = BloomFilter(capacity=max(2000, _MAX_IPS // 4))
        self._secret = secrets.token_bytes(16)
        # 可変状態ファイル(BAN/署名/設定/テレメトリ)の改竄耐性(#52/#53): 保存時に HMAC 署名し
        # 読込時に検証。鍵は再起動を跨ぐため永続(env CHICKENNET_STATE_KEY 推奨・無ければ 0600 で生成)。
        self._state_key = persistent_key(base)
        # 署名運用マーカー(#53): 一度でも署名保存した後は『無署名ファイルの出現』を平文すり替えの
        # 疑いとして改竄扱いする(無署名受理=移行は初回/レガシーのみ許す)。起動時点の有無を1度だけ
        # 記録し(この起動中の移行で揺れないように)、loads 完了後にマーカーを書く。
        self._state_marker = os.path.join(base, ".state_signed")
        self._state_signed_before = os.path.exists(self._state_marker)
        # 改竄検知の可視化(#55): 件数と直近イベントを保持し status/metrics で露出+SIEM へ転送。
        self._tamper = {"count": 0, "last": None, "by_kind": {}}
        # ユーザー/AI 追加のカスタムシグネチャ(SaaS継続アップデート・永続化・常時評価)。
        self._sig_path = os.path.join(base, "rules.json")
        self._bans_path = os.path.join(base, "blocklist.json")   # BAN永続化(再起動耐性)
        self._traffic_path = os.path.join(base, "traffic.json")  # 送出量/接続時間(窓集計)
        self._traffic: dict = {}        # ip -> {day(int): [out_bytes, in_bytes, conn_sec]}
        self._traffic_last_save = 0.0
        # ネットワーク使用量リスト(誰が/どのサイトと/どれだけ)+ 見返せるログ
        self._usage_path = os.path.join(base, "usage.json")
        self._usage_log_path = os.path.join(base, "usage_log.jsonl")
        self._usage: dict = {}          # ip -> {out,in,conns,sec, hosts:{host:{out,in,conns}}}
        self._usage_last_save = 0.0
        self._custom: list = []         # [{name,category,pattern,weight,enabled,source}]
        self._custom_re: list = []      # [(name, category, compiled, weight)]
        self._custom_blocked = 0        # コンパイル時に危険(ReDoS等)で除外した数
        self._appeals: dict = {}        # ip -> {ts, reason, status}(解除リクエスト)
        self._restrictions: dict = {}   # ip -> {report, user_ok, admin_ok, status}(一時制限・双方合意)
        self._geo_nets: list = []       # コンパイル済み geo CIDR
        self._series = deque(maxlen=600)   # リアルタイムグラフ用 時系列サンプル
        self._series_last = 0.0
        self._dlp_kinds: dict = {}         # 漏洩した秘密種別の累積内訳(egress テレメトリ)
        self._sig_hits: dict = {}          # シグネチャ別ヒットの累積内訳(検知テレメトリ)
        self._zone_hits: dict = {}         # ゾーン別リクエストの累積内訳(トラフィック構成)
        self._method_hits: dict = {}       # HTTPメソッド別の累積内訳(既知名のみ・OTHER畳み)
        self._resp_code_hits: dict = {}    # 応答ステータス帯別(4xx/5xx 等)の累積(応答アウェア・#60)
        self._cred_rate: dict = {}         # cred ハッシュ -> 窓内タイムスタンプ deque(#70・有界)
        self._stall_count = 0              # 迂回検知(#78): 前回チェック時の requests カウンタ
        self._stall_ts = -1.0              # -1=未初期化(warmup 番兵。now=0 と衝突しない)
        self._stall_prev_rate = 0.0        # 前区間のレート(busy→ゼロ 遷移の判定用)
        self._cfg_mac = ""                 # in-memory cfg の整合 MAC(#85・メモリすり替え検知)
        self._declog = deque(maxlen=500)   # 直近の判定ログ(プロ分析のゾーン/シグネチャ内訳用)
        self._last_zone = ""
        self.cfg = dict(_DEFAULTS)
        self._load()
        self._load_sigs()
        self._compile_geo()
        self._load_bans()
        if self.cfg.get("persist_bans"):
            _tv, _tm = self._read_state(self._traffic_path, {}, "traffic")
            self._traffic = (_tv or {}).get("traffic", {})
            _uv, _um = self._read_state(self._usage_path, {}, "usage")
            self._usage = (_uv or {}).get("usage", {})
            if _tm:
                self._save_traffic(force=True)        # 旧来無署名→署名済みへ移行
            if _um:
                self._save_usage(force=True)
        else:
            self._traffic, self._usage = {}, {}
        self._mark_state_signed()                     # 以降、無署名出現は改竄として弾く
        self._refresh_cfg_mac()                       # #85: 起動時 cfg の整合基準を確定

    # ── 永続化 ───────────────────────────────────────────────────
    def _read_state(self, path: str, default, what: str):
        """署名付き状態を読み (value, migrate) を返す(#52)。改竄(署名不一致)は安全側 default に
        フェイルセーフし system イベントで警報。無署名(旧来)は生値を使いつつ migrate=True を返し、
        呼び出し側が再保存で署名済みへ移行する。攻撃者が書き換えた状態を *信頼しない* のが要点。"""
        status, val = read_signed_json(path, self._state_key, default)
        if status == "unsigned" and self._state_signed_before:
            status = "tampered"      # 署名運用後の無署名出現=平文すり替えの疑い→改竄扱い
        if status in ("tampered", "rolled_back"):
            # rolled_back = 古い正署名ファイルへの巻き戻し(#102)。署名は正しいが版が後退=拒否。
            reason = ("rollback(古い正署名への巻き戻し)" if status == "rolled_back"
                      else "fail-safe(default)")
            try:
                self.report_tamper("state_tamper", what, reason,
                                   {"file": os.path.basename(path), "status": status})
            except Exception:
                pass
            return default, False
        if status == "missing":
            return default, False
        return (val if val is not None else default), (status == "unsigned")

    def _mark_state_signed(self):
        """署名運用マーカーを書く(初回 loads 後)。これ以降の起動では無署名ファイルの出現を
        平文すり替えとして改竄扱いする(#53)。失敗は無害に握る(マーカーは検知を強める保険)。"""
        try:
            if not os.path.exists(self._state_marker):
                with open(self._state_marker, "w", encoding="utf-8") as f:
                    f.write(str(int(_now())))
        except Exception:
            pass

    def _load(self):
        d, migrate = self._read_state(self.path, {}, "config")
        d = d or {}
        for k, v in (d.get("cfg") or {}).items():
            if k in self.cfg and isinstance(v, type(self.cfg[k])):
                self.cfg[k] = v
        # BANは安全側で揮発(再起動でリセット)・設定のみ永続
        if migrate:                               # 旧来の無署名→署名済みへ移行
            self._save()

    def _save(self) -> bool:
        with self._lock:
            ok = write_signed_json(self.path, {"cfg": self.cfg, "saved": _now()},
                                   self._state_key)
            self._refresh_cfg_mac()           # #85: 正規変更のたびに整合 MAC を更新
            return ok

    def _compute_cfg_mac(self) -> str:
        """in-memory cfg の整合 MAC(#85)。プロセス毎ランダムな _secret で HMAC=メモリを書き換える
        攻撃者は MAC も併せて偽造する必要がある(secret もメモリから探さねばならない)。"""
        blob = json.dumps(self.cfg, sort_keys=True, separators=(",", ":"),
                          default=str).encode("utf-8", "replace")
        return hmac.new(self._secret, blob, hashlib.sha256).hexdigest()

    def _refresh_cfg_mac(self):
        self._cfg_mac = self._compute_cfg_mac()

    def verify_cfg_integrity(self) -> dict:
        """in-memory cfg が *API を通さない out-of-band 改変*(デバッガ/プロセス注入によるメモリ
        すり替え)で書き換えられていないか検査する(#85)。正規変更は _save 時に MAC を更新するので、
        MAC 不一致=正規経路を通らない改変。検出したら署名検証済みディスク state から cfg を復元し
        (=最後の正規状態へ戻す)、memory_tamper を警報する。AsyncEdgeGuard の独立した
        定期チェックループから呼ぶ。"""
        with self._lock:
            if hmac.compare_digest(self._compute_cfg_mac().encode("ascii", "ignore"),
                                   str(self._cfg_mac).encode("ascii", "ignore")):
                return {"ok": True, "tampered": False}   # #19: 定数時間 bytes 比較
            self.cfg = dict(_DEFAULTS)        # クリーン基準へリセット(型改変も確実に上書き)
            self._load()                      # 署名済みディスクから cfg を再適用(=正規状態へ復元)
            self._refresh_cfg_mac()
        try:
            self.report_tamper("memory_tamper", "cfg", "restored-from-disk")
        except Exception:
            pass
        return {"ok": True, "tampered": True, "restored": True}

    # ── カスタムシグネチャ(ユーザー追加 / AI生成・SaaS継続アップデート) ──
    def _load_sigs(self):
        d, migrate = self._read_state(self._sig_path, {}, "signatures")
        d = d or {}
        self._custom = [s for s in (d.get("signatures") or [])
                        if isinstance(s, dict) and s.get("pattern")]
        self._compile_custom()
        if migrate:
            self._save_sigs()

    def _save_sigs(self) -> bool:
        with self._lock:
            return write_signed_json(self._sig_path, {"signatures": self._custom},
                                     self._state_key)

    def _compile_custom(self):
        # 多層防御: validate_pattern を *コンパイル時にも* 適用する。add_signature だけでなく、
        # 改竄/レガシーな署名ファイルを _load_sigs が直接読んだ場合でも、ReDoS パターンを
        # live エンジンへ載せない(Python の re は実行タイムアウトが無く、壊滅的バックトラッキングは
        # WAF 自身の自己DoSになる)。危険/不正なものは無効化して skip。
        out, blocked = [], 0
        for s in self._custom:
            if not s.get("enabled", True):
                continue
            if self.validate_pattern(s.get("pattern", "")):     # 危険(ReDoS等)/不正は載せない
                blocked += 1
                continue
            try:
                rgx = re.compile(s["pattern"])
            except re.error:
                continue
            out.append((s["name"], s.get("category", "custom"), rgx,
                        float(s.get("weight", 40))))
        self._custom_re = out
        self._custom_blocked = blocked

    @staticmethod
    def validate_pattern(pattern: str) -> str:
        """カスタム正規表現の安全性検査。問題があれば理由文字列、無ければ空。
        ReDoS 判定は共通ライブラリ [[saferegex]] に委譲(単一の真実)。カスタム規則は
        さらに厳しめの 400 文字上限を課す。"""
        if not pattern or len(pattern) > 400:
            return "パターンが空/長すぎ(<=400)"
        return saferegex.lint(pattern)     # ネスト量化子/不正 → 理由文字列(安全なら "")

    def _all_patterns(self) -> list:
        """既存(組込+カスタム)の全パターン文字列(重複検知用)。"""
        return [p for _n, p in _SIGNATURES] + [s["pattern"] for s in self._custom]

    def is_duplicate_pattern(self, pattern: str) -> bool:
        """完全一致 or 挙動同値(同一コーパスで一致集合が完全一致)なら重複。"""
        if pattern in self._all_patterns():
            return True
        try:
            cand = re.compile(pattern)
        except re.error:
            return False
        corpus = _DEDUP_CORPUS
        cand_set = frozenset(i for i, s in enumerate(corpus) if cand.search(s))
        if not cand_set:
            return False                       # 何も当たらない物は同値判定しない
        for _n, p in _SIGNATURES + [(s["name"], s["pattern"]) for s in self._custom]:
            try:
                ex = re.compile(p)
            except re.error:
                continue
            if frozenset(i for i, s in enumerate(corpus) if ex.search(s)) == cand_set:
                return True                    # 挙動が同一=重複
        return False

    def add_signature(self, name: str, pattern: str, category: str = "custom",
                      weight: float = 40, source: str = "user") -> dict:
        """カスタムシグネチャを追加(検証+重複拒否+永続化+再コンパイル)。
        name は管理画面のテーブル/onclick属性へ後で埋め込まれるため、ここで許容文字を
        絞る(英数・._- のみ、1〜64字)。誤って緩めても呼び出し側(admin.py)は必ずエスケープ
        すること=多層防御(#111)。"""
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name or ""):
            return {"ok": False, "error": "name は英数・._- のみ、1〜64文字"}
        err = self.validate_pattern(pattern)
        if err:
            return {"ok": False, "error": err}
        if self.is_duplicate_pattern(pattern):
            return {"ok": False, "error": "重複(既存と同一/挙動同値)のため不採用"}
        with self._lock:
            self._custom = [s for s in self._custom if s.get("name") != name]
            self._custom.append({"name": name, "category": category,
                                 "pattern": pattern, "weight": float(weight),
                                 "enabled": True, "source": source})
            self._save_sigs()
            self._compile_custom()
        return {"ok": True, "added": name, "total_custom": len(self._custom)}

    def remove_signature(self, name: str) -> dict:
        with self._lock:
            before = len(self._custom)
            self._custom = [s for s in self._custom if s.get("name") != name]
            self._save_sigs()
            self._compile_custom()
        return {"ok": True, "removed": before - len(self._custom)}

    def list_signatures(self) -> dict:
        opt = self.cfg.get("optional_sigs", {})
        return {"builtin": [{"name": n, "category": n,
                             "optional": n in _OPTIONAL_SIGS,
                             "enabled": (n not in _OPTIONAL_SIGS) or bool(opt.get(n))}
                            for n, _p in _SIGNATURES],
                "optional_signatures": sorted(_OPTIONAL_SIGS),
                "custom": list(self._custom), "custom_active": len(self._custom_re),
                "custom_blocked": self._custom_blocked}

    def set_optional_signature(self, name: str, enabled: bool) -> dict:
        """高FPの任意シグネチャ(_OPTIONAL_SIGS)を個別にON/OFF。永続化する。"""
        if name not in _OPTIONAL_SIGS:
            return {"ok": False, "error": f"{name} はオプション対象でない(対象: "
                    f"{', '.join(sorted(_OPTIONAL_SIGS))})"}
        with self._lock:
            opt = dict(self.cfg.get("optional_sigs", {}))
            opt[name] = bool(enabled)
            self.cfg["optional_sigs"] = opt
            self._save()
        return {"ok": True, "name": name, "enabled": bool(enabled)}

    def set_paranoia(self, level) -> dict:
        """検知の段階的厳格度(1=保守〜4=最大)を1ダイヤルで設定。レベルに応じて高FPの任意
        シグネチャを一括ON(誤検知許容度に合わせる)。set_optional_signature で個別微調整も可
        (その場合 paranoia 値は最後に適用したプリセットを指す)。永続化する。"""
        try:
            level = int(level)
        except Exception:
            level = 1
        level = max(1, min(4, level))
        with self._lock:
            self.cfg["paranoia"] = level
            self.cfg["optional_sigs"] = {n: True for n in _PARANOIA_TIERS[level]}
            self._save()
        return self.paranoia_status()

    def paranoia_status(self) -> dict:
        lvl = int(self.cfg.get("paranoia", 1) or 1)
        opt = self.cfg.get("optional_sigs", {})
        return {"paranoia": lvl, "max_level": 4,
                "enabled_optional": sorted(n for n in _OPTIONAL_SIGS if opt.get(n)),
                "note": "検知の段階的厳格度(1=保守/誤検知最小 〜 4=最大/高FP許容)。"}

    # ── ON/OFF・設定 ─────────────────────────────────────────────
    def is_enabled(self) -> bool:
        return bool(self.cfg["enabled"])

    def enable(self) -> dict:
        self.cfg["enabled"] = True; self._save(); return {"ok": True, "enabled": True}

    def disable(self) -> dict:
        self.cfg["enabled"] = False; self._save(); return {"ok": True, "enabled": False}

    def set_config(self, **kw) -> dict:
        changed = {}
        with self._lock:
            for k, v in kw.items():
                if k not in self.cfg or v is None:
                    continue
                exp = type(self.cfg[k])
                if exp is float and isinstance(v, int) and not isinstance(v, bool):
                    v = float(v)                # int→float を許容(GB/秒/日数を int で渡せる)
                if isinstance(v, exp):
                    self.cfg[k] = v; changed[k] = v
            self._save()
            if "geo_cidrs" in changed or "geo_mode" in changed:
                self._compile_geo()
        return {"ok": True, "changed": changed, "cfg": dict(self.cfg)}

    # ── 宣言的設定ブートストラップ(evolution #27) ──
    def apply_config(self, d: dict) -> dict:
        """運用者が宣言した設定辞書(ファイル/ConfigMap)を *既存の検証済みセッター経由* で適用する。
        宣言的デプロイ(GitOps/k8s の immutable infra)向け。構造/段階キーは専用バリデータに回し、
        残りは set_config(既存キー・型一致のみ通す)。未知キーは無視。適用できたキー一覧を返す。"""
        if not isinstance(d, dict):
            return {"ok": False, "error": "config is not an object", "applied": []}
        routed = {"path_limits": self.set_path_limits,
                  "blocked_methods": self.set_blocked_methods,
                  "paranoia": self.set_paranoia}
        applied, rest = set(), {}
        for k, v in d.items():
            if k in routed:
                try:
                    routed[k](v); applied.add(k)
                except Exception:
                    pass                          # 不正値は黙って捨てる(起動を止めない)
            elif k in self.cfg:
                rest[k] = v
        if rest:
            applied.update(self.set_config(**rest).get("changed", {}).keys())
        return {"ok": True, "applied": sorted(applied)}

    def apply_config_file(self, path: str) -> dict:
        """JSON 設定ファイルを読み込んで apply_config。空パス=no-op。読めない/JSON不正=エラー。
        起動時に env CHICKENNET_CONFIG / CLI --config から呼ぶ(宣言的ブートストラップ)。"""
        if not path:
            return {"ok": True, "applied": [], "note": "no config file"}
        d = safe_read_json(path, None)
        if not isinstance(d, dict):
            return {"ok": False, "error": f"config not found or invalid JSON: {path}",
                    "applied": []}
        return self.apply_config(d)

    # ── 内部: IP状態 ────────────────────────────────────────────
    def _state(self, ip: str) -> dict:
        st = self._ips.get(ip)
        if st is None:
            if len(self._ips) >= _MAX_IPS:
                self._evict()
            st = {"tokens": float(self.cfg["burst"]), "refill": _now(),
                  "window": deque(), "score": 0.0, "score_ts": _now(),
                  "ban_until": 0.0, "seen": _now(),
                  "hits": 0, "first": _now(), "last_req": 0.0,
                  "intervals": deque(maxlen=24), "ban_started": 0.0, "ban_count": 0}
            self._ips[ip] = st
        st["seen"] = _now()
        return st

    def _evict(self):
        # 最も古い(last seen)から1割を間引く(メモリ有界)。ただし **アクティブBANは温存** する
        # (#45): 状態を evict されると次アクセス時に fresh state=ban_until 0=未BAN扱いになり、
        # 攻撃者が多数IPで _ips を埋めて自分のBANを押し出す『eviction による unban 回避』が成立する。
        # 非BANを古い順に間引き、それで足りない(=大半がBAN中)場合のみ最古BANも間引いて境界を維持。
        now = _now()
        target = max(1, _MAX_IPS // 10)
        nonban = sorted((kv for kv in self._ips.items() if not (kv[1]["ban_until"] > now)),
                        key=lambda kv: kv[1]["seen"])
        for ip, _ in nonban[:target]:
            self._ips.pop(ip, None)
        if len(self._ips) >= _MAX_IPS:           # 非BANだけで足りない時のみ最古BANも間引く
            rest = sorted(self._ips.items(), key=lambda kv: kv[1]["seen"])
            for ip, _ in rest[:target]:
                self._ips.pop(ip, None)

    def _decayed_score(self, st: dict) -> float:
        hl = max(1.0, float(self.cfg["score_halflife_sec"]))
        dt = max(0.0, _now() - st["score_ts"])    # 時刻巻き戻し(NTP補正等)で decay が *反転して
        return st["score"] * (0.5 ** (dt / hl))   #   スコア膨張→誤BAN* するのを防ぐ(#44・単調減衰保証)

    def _add_score(self, st: dict, amount: float):
        st["score"] = self._decayed_score(st) + amount
        st["score_ts"] = _now()

    def _credential_rate(self, cred: str) -> int:
        """クレデンシャル(Bearer トークン/API キー)単位の窓内リクエスト数を返す(#70)。
        生のトークンは保持せず sha256 短縮ハッシュをキーにする(漏洩面/メモリ抑制)。マップは
        _CRED_RATE_CAP で有界(超過時は最古を間引く)。ロック内から呼ぶ。"""
        import hashlib
        h = hashlib.sha256(cred.encode("utf-8", "replace")).digest()[:12]
        now = _now()
        win = float(self.cfg.get("cred_rate_window_sec", 60))
        dq = self._cred_rate.get(h)
        if dq is None:
            if len(self._cred_rate) >= _CRED_RATE_CAP:    # 有界化: 最古挿入を1件落とす
                self._cred_rate.pop(next(iter(self._cred_rate)), None)
            dq = self._cred_rate[h] = deque(maxlen=8192)
        dq.append(now)
        cutoff = now - win
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    # ── 主判定(Webサーバ等が要求受理時に呼ぶ) ──────────────────────
    def _policy_block(self, ip: str, path: str, tls: bool) -> str:
        """ポリシー(拡張子/URL/TLS/geo)で遮断すべきなら理由を返す(無ければ空)。"""
        p = _path_for_match(path)            # %デコード+小文字化=エンコード回避を防ぐ(#40)
        for ext in self.cfg.get("blocked_extensions") or []:
            if p.endswith(str(ext).lower()):
                return f"拡張子ブロック: {ext}"
        for u in self.cfg.get("blocked_urls") or []:
            if str(u).lower() in p:
                return f"URLブロック: {u}"
        if self.cfg.get("require_tls") and not tls:
            return "正規TLS以外(平文)を遮断"
        gm = self.cfg.get("geo_mode", "off")
        if gm in ("allow", "block") and self._geo_nets:
            try:
                addr = ipaddress.ip_address(ip)
                inside = any(addr in net for net in self._geo_nets)
            except Exception:
                inside = False
            if gm == "allow" and not inside:
                return "地域許可リスト外(海外通信ブロック)"
            if gm == "block" and inside:
                return "地域遮断リストに該当"
        return ""

    @staticmethod
    def _domain_match(host: str, patterns) -> bool:
        h = (host or "").split(":")[0].lower().rstrip(".")
        if not h:
            return False
        for p in patterns or []:
            p = str(p).lower().strip().rstrip(".")
            if not p:
                continue
            if p.startswith("*."):
                if h == p[2:] or h.endswith("." + p[2:]):
                    return True
            elif h == p or h.endswith("." + p):
                return True
        return False

    def _site_block(self, host: str) -> str:
        """サイト(ドメイン)許可/遮断判定。理由を返す(無ければ空)。"""
        mode = self.cfg.get("site_mode", "off")
        if mode == "whitelist":
            wl = self.cfg.get("site_whitelist") or []
            if wl and not self._domain_match(host, wl):
                return f"ホワイトリスト外サイト: {host}"
        elif mode == "blacklist":
            if self._domain_match(host, self.cfg.get("site_blacklist") or []):
                return f"ブラックリストのサイト: {host}"
        return ""

    def _ip_list_block(self, ip: str) -> str:
        """IP(送信元)単位の白/黒リスト判定。CIDR包括対応。理由を返す(無ければ空)。"""
        mode = self.cfg.get("ip_mode", "off")
        if mode == "off":
            return ""

        def _match(entries) -> bool:
            try:
                addr = ipaddress.ip_address(ip)
            except Exception:
                return False
            for e in entries or []:
                e = str(e).strip()
                try:
                    if "/" in e:
                        if addr in ipaddress.ip_network(e, strict=False):
                            return True
                    elif e == ip:
                        return True
                except Exception:
                    continue
            return False
        if mode == "whitelist" and not _match(self.cfg.get("ip_whitelist")):
            return f"IP許可リスト外: {ip}"
        if mode == "blacklist" and _match(self.cfg.get("ip_blacklist")):
            return f"IPブラックリスト: {ip}"
        return ""

    # ── 白/黒リストの統一編集(ドメイン/IP・個別/包括/一括・追加/削除/置換/全消去) ──
    _LIST_KEYS = {("domain", "white"): "site_whitelist",
                  ("domain", "black"): "site_blacklist",
                  ("ip", "white"): "ip_whitelist",
                  ("ip", "black"): "ip_blacklist"}

    def edit_list(self, kind: str, listname: str, op: str, entries=None) -> dict:
        """kind=domain/ip, listname=white/black, op=add|remove|set|clear。
        entries はリスト=一括、1件=個別、CIDR/ワイルドカード=包括。set=編集(全置換)・保存される。"""
        ln = "white" if str(listname).startswith("white") else "black"
        key = self._LIST_KEYS.get((kind, ln))
        if not key:
            return {"ok": False, "error": "kind は domain/ip, listname は white/black"}
        ents = [str(e).strip() for e in (entries or []) if str(e).strip()]
        cur = list(self.cfg.get(key) or [])
        if op == "add":
            cur = list(dict.fromkeys(cur + ents))        # 重複なし・順序保持
        elif op == "remove":
            rm = set(ents)
            cur = [c for c in cur if c not in rm]
        elif op == "set":
            cur = list(dict.fromkeys(ents))              # 編集=全置換
        elif op == "clear":
            cur = []
        else:
            return {"ok": False, "error": "op は add/remove/set/clear"}
        r = self.set_config(**{key: cur})
        return {"ok": True, "list": key, "op": op, "count": len(cur),
                "entries": cur}

    def list_status(self) -> dict:
        return {"site_mode": self.cfg.get("site_mode"),
                "site_whitelist": list(self.cfg.get("site_whitelist") or []),
                "site_blacklist": list(self.cfg.get("site_blacklist") or []),
                "ip_mode": self.cfg.get("ip_mode"),
                "ip_whitelist": list(self.cfg.get("ip_whitelist") or []),
                "ip_blacklist": list(self.cfg.get("ip_blacklist") or [])}

    # ── データ漏洩防止: 送出量/接続時間の窓集計とクォータ ──
    @staticmethod
    def _day() -> int:
        return int(_now() // 86400)

    def _window_totals(self, ip: str):
        days = int(self.cfg.get("quota_window_days", 1))
        cutoff = self._day() - max(1, days) + 1
        out = inb = sec = 0.0
        for d, v in (self._traffic.get(ip) or {}).items():
            if int(d) >= cutoff:
                out += v[0]; inb += v[1]; sec += v[2]
        return out, inb, sec

    def record_traffic(self, ip: str, out_bytes: float = 0, in_bytes: float = 0,
                       conn_sec: float = 0.0, host: str = "", method: str = "",
                       path: str = "") -> dict:
        """ガードが接続終了時に呼ぶ。使用量リスト(誰が/どのサイトと/どれだけ)を記録し、
        クォータ有効時は窓集計で上限超過を遮断。out_bytes=サーバ→クライアント(=持ち出し)が主指標。"""
        # 1) ネットワーク使用量の記録(誰が/どのサイトと/どれだけ)+ 見返せるログ
        self._record_usage(ip, out_bytes, in_bytes, conn_sec, host, method, path)
        if not self.cfg.get("quota_enabled"):
            return {"counted": False}
        d = str(self._day())
        with self._lock:
            if ip not in self._traffic and len(self._traffic) >= _MAX_IPS:
                for k in list(self._traffic)[:max(1, _MAX_IPS // 10)]:   # 古い順に間引き=有界(#43)
                    self._traffic.pop(k, None)
            ipt = self._traffic.setdefault(ip, {})
            b = ipt.get(d) or [0.0, 0.0, 0.0]
            b[0] += float(out_bytes); b[1] += float(in_bytes); b[2] += float(conn_sec)
            ipt[d] = b
            cutoff = self._day() - max(1, int(self.cfg.get("quota_window_days", 1))) + 1
            for old in [k for k in ipt if int(k) < cutoff]:   # 窓外の古いバケットを掃除
                ipt.pop(old, None)
            self._save_traffic()
        out, _inb, sec = self._window_totals(ip)
        max_gb = float(self.cfg.get("quota_max_gb", 0) or 0)
        max_sec = float(self.cfg.get("quota_max_conn_sec", 0) or 0)
        gb = out / 1e9
        exceeded = ""
        if max_gb > 0 and gb >= max_gb:
            exceeded = f"送出量超過 {gb:.2f}GB/{self.cfg['quota_window_days']}日"
        elif max_sec > 0 and sec >= max_sec:
            exceeded = f"接続時間超過 {int(sec)}s/{self.cfg['quota_window_days']}日"
        if exceeded:
            with self._lock:
                st = self._state(ip)
            self._enforce_or_audit(ip, "block", st, "クォータ: " + exceeded,
                                   kind="quota_exceeded", do_ban=True)
            return {"counted": True, "exceeded": exceeded, "gb": round(gb, 3),
                    "conn_sec": round(sec, 1)}
        return {"counted": True, "gb": round(gb, 3), "conn_sec": round(sec, 1)}

    def _save_traffic(self, force: bool = False):
        if not self.cfg.get("persist_bans"):
            return
        now = _now()
        if not force and now - self._traffic_last_save < 15.0:   # 書込を間引く(秒単位精度不要)
            return
        self._traffic_last_save = now
        write_signed_json(self._traffic_path, {"traffic": self._traffic, "saved": now},
                          self._state_key)

    def quota_status(self, ip: str = "") -> dict:
        if ip:
            out, inb, sec = self._window_totals(ip)
            return {"ip": ip, "out_gb": round(out / 1e9, 3),
                    "in_gb": round(inb / 1e9, 3), "conn_sec": round(sec, 1),
                    "window_days": self.cfg.get("quota_window_days")}
        # 全IPの送出量上位
        rows = []
        for ip2 in list(self._traffic):
            out, inb, sec = self._window_totals(ip2)
            if out or sec:
                rows.append({"ip": ip2, "out_gb": round(out / 1e9, 3),
                             "conn_sec": round(sec, 1)})
        rows.sort(key=lambda r: r["out_gb"], reverse=True)
        return {"enabled": self.cfg.get("quota_enabled"),
                "max_gb": self.cfg.get("quota_max_gb"),
                "max_conn_sec": self.cfg.get("quota_max_conn_sec"),
                "window_days": self.cfg.get("quota_window_days"), "top": rows[:20]}

    # ── ネットワーク使用量リスト(誰が/どのサイトと/どれだけ)+ 見返せるログ ──
    def _record_usage(self, ip, out_bytes, in_bytes, conn_sec, host, method, path):
        if not self.cfg.get("usage_record"):
            return
        host = (host or "").split(":")[0].lower()
        with self._lock:
            if len(self._usage) >= _MAX_IPS:           # メモリ有界(古い順に間引き)
                for k in list(self._usage)[:_MAX_IPS // 10]:
                    self._usage.pop(k, None)
            u = self._usage.setdefault(ip, {"out": 0.0, "in": 0.0, "conns": 0,
                                            "sec": 0.0, "hosts": {}, "last": 0.0})
            u["out"] += float(out_bytes); u["in"] += float(in_bytes)
            u["conns"] += 1; u["sec"] += float(conn_sec); u["last"] = _now()
            if host:
                h = u["hosts"].setdefault(host, {"out": 0.0, "in": 0.0, "conns": 0})
                h["out"] += float(out_bytes); h["in"] += float(in_bytes); h["conns"] += 1
                if len(u["hosts"]) > 60:               # IPあたりの宛先数を有界化(送出量上位を残す)
                    top = dict(sorted(u["hosts"].items(),
                                      key=lambda kv: kv[1]["out"], reverse=True)[:60])
                    u["hosts"] = top
            # 見返せるログ(1接続=1行のjsonl・末尾回転)
            try:
                with open(self._usage_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"ts": round(_now(), 1), "ip": ip, "host": host,
                                        "method": method, "path": (path or "")[:120],
                                        "out": int(out_bytes), "in": int(in_bytes),
                                        "sec": round(conn_sec, 2)},
                                       ensure_ascii=False) + "\n")
            except Exception:
                pass
            self._save_usage()
            self._rotate_usage_log()

    def _save_usage(self, force: bool = False):
        if not self.cfg.get("persist_bans"):
            return
        now = _now()
        if not force and now - self._usage_last_save < 15.0:
            return
        self._usage_last_save = now
        write_signed_json(self._usage_path, {"usage": self._usage, "saved": now},
                          self._state_key)

    def _rotate_usage_log(self, keep: int = 8000):
        try:
            if os.path.getsize(self._usage_log_path) < 4_000_000:   # ~4MB超で回転
                return
            with open(self._usage_log_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            with open(self._usage_log_path, "w", encoding="utf-8") as f:
                f.writelines(lines[-keep:])
        except Exception:
            pass

    def usage_list(self, n: int = 30) -> dict:
        """ネットワーク使用量リスト: 送受信量の多い順に、宛先サイト内訳つきで返す(可視化用)。"""
        with self._lock:
            rows = []
            for ip, u in self._usage.items():
                hosts = sorted(u.get("hosts", {}).items(),
                               key=lambda kv: kv[1]["out"] + kv[1]["in"], reverse=True)
                rows.append({"ip": ip, "out_gb": round(u["out"] / 1e9, 3),
                             "in_gb": round(u["in"] / 1e9, 3), "conns": u["conns"],
                             "conn_sec": round(u["sec"], 1),
                             "top_hosts": [{"host": h, "out_mb": round(v["out"] / 1e6, 2),
                                            "in_mb": round(v["in"] / 1e6, 2),
                                            "conns": v["conns"]} for h, v in hosts[:6]]})
        rows.sort(key=lambda r: r["out_gb"] + r["in_gb"], reverse=True)
        return {"enabled": self.cfg.get("usage_record"), "tracked_ips": len(self._usage),
                "rows": rows[:n]}

    def usage_log(self, limit: int = 100, ip: str = "", host: str = "") -> list:
        """使用量ログ(jsonl)を新しい順に絞って返す(見返しやすさ)。"""
        out = []
        try:
            with open(self._usage_log_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return out
        for line in reversed(lines):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if ip and e.get("ip") != ip:
                continue
            if host and host.lower() not in (e.get("host") or ""):
                continue
            out.append(e)
            if len(out) >= max(1, limit):
                break
        return out

    def usage_clear(self) -> dict:
        with self._lock:
            self._usage = {}
            self._usage_last_save = 0.0
            write_signed_json(self._usage_path, {"usage": {}, "saved": _now()},
                              self._state_key)
            try:
                open(self._usage_log_path, "w").close()
            except Exception:
                pass
        return {"ok": True, "cleared": True}

    def _compile_geo(self):
        nets = []
        for c in self.cfg.get("geo_cidrs") or []:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                continue
        self._geo_nets = nets

    def _scan_signatures(self, blob: str, *, only: frozenset | None = None):
        """1走査面(正規化済み文字列)への署名/構造検知。(name, weight) or (None, 0.0)を返す。
        prescan ゲート付き builtin署名 + 常時カスタム署名 + 構造検知(恒真式/スタック/XSSハンドラ)。
        evolution #39 でフィールド独立走査のため inspect から切り出した(挙動は従来どおり)。
        only: 指定時はこの名前集合の builtin 署名『だけ』を判定する専用フィールド走査
        (#FP: scanner_ua/sensitive_path・_FIELD_SCOPED_SIGS)。カスタム署名/構造検知はスキップ
        (専用フィールド走査は特定カテゴリの的確な判定が目的で、汎用の意味的検知とは別関心)。
        only=None(既定=汎用走査)では _FIELD_SCOPED_SIGS に属す名は評価しない(専用呼び出し
        でのみ判定=フィールド混成による誤検知を避ける)。"""
        if not blob:
            return None, 0.0
        # 高速プレフィルタ(Rust継ぎ目でnative化可)。核語が皆無なら高価な正規表現を丸ごとスキップ
        # (スーパーセット保証=取りこぼさない)。良性トラフィックの大半はここで終了。
        from ..core import accel
        if accel.prescan_suspicious(blob.encode("utf-8", "replace")) > 0:
            opt = self.cfg.get("optional_sigs", {})
            for name, rgx in _SIG_RE:
                if only is not None:
                    if name not in only:
                        continue                 # 専用フィールド走査=指定カテゴリのみ判定
                elif name in _FIELD_SCOPED_SIGS:
                    continue                     # 汎用走査では専用フィールド系は判定しない(#FP)
                if name in _OPTIONAL_SIGS and not opt.get(name):
                    continue                     # 高FPシグネチャは cfg で有効化された時のみ評価
                if saferegex.search(rgx, blob, _MAX_SCAN):   # 入力上限で ReDoS 面積を有界化
                    return name, _SIG_WEIGHT.get(name, 30)
        if only is not None:
            return None, 0.0                     # 専用フィールド走査はここまで(カスタム/構造検知は対象外)
        # カスタムシグネチャ(ユーザー/AI追加)は prescanゲートを通さず常時評価(needleに無いため)。
        for name, _cat, rgx, w in self._custom_re:
            if saferegex.search(rgx, blob, _MAX_SCAN):
                return name, w
        # 意味的検知: literal シグネチャをすり抜けた恒真式 SQLi(2=2 / 'x'='x')/スタック複文 /
        # ハンドラ型 XSS(<svg onload=)を *構造* で捕捉。
        if _tautology_suspect(blob):
            return "sqli-tautology", _SIG_WEIGHT.get("sqli-tautology", 35)
        if _stacked_query_suspect(blob):
            return "sqli-stacked", _SIG_WEIGHT.get("sqli-stacked", 40)
        if _xss_event_handler_suspect(blob):
            return "xss", _SIG_WEIGHT.get("xss", 45)
        return None, 0.0

    def inspect(self, ip: str, *, path: str = "", method: str = "GET",
                user_agent: str = "", query: str = "", zone: str = "",
                tls: bool = True, host: str = "", headers: str = "",
                header_names=None, auth: str = "", cred: str = "",
                override_method: str = "", override_path: str = "",
                range_header: str = "") -> dict:
        if not self.is_enabled():
            return {"action": "allow", "reason": "shield OFF(パススルー)", "score": 0}
        # ── ロック外: 入力検査(純粋・CPU重)。共有状態に触れないのでロックを取らない。
        #    正規表現の走査をロック外に出すことで、ロック保持時間=競合面積を小さくする
        #    (『ロック多用で順番待ち』への対処)。入力は正規化+長さ上限で ReDoS も抑制。
        # path/query/UA に加え、攻撃者制御の他ヘッダ値(headers)も走査面に含める。Log4Shell や
        # SQLi は Referer/X-Forwarded-For/Cookie 等あらゆるヘッダ経由で来るため(UAだけでは不足)。
        # ── スキャン面パディング回避の封じ込め(evolution #39) ──────────────────────────
        # 各フィールド(path?query+UA / 各ヘッダ値)を *独立した* 正規化走査面として検査する。
        # これが無いと『path/query を 8192 まで膨らませてヘッダ内の Log4Shell/SQLi を走査面の外へ
        # 押し出す』だけで全署名を回避できた(実証済の WAF バイパス)。フィールドを連結せず個別に
        # 走査=各フィールドが自分の budget で必ず検査される。フィールド数は _MAX_SCAN_FIELDS で有界。
        _targets = [f"{path}?{query} {user_agent}"]
        if host:
            _targets.append(host)            # Host も走査面に(Host経由のLog4Shell/SQLi死角を塞ぐ・#41)
        _targets.extend(h for h in (headers or "").split("\n") if h)
        blob = _normalize_for_scan(_targets[0])    # 主走査面(reason/後続参照の後方互換用)
        sig_hit, sig_weight = self._scan_signatures(blob)
        # フィールド限定シグネチャ(#FP: scanner_ua/sensitive_path・_FIELD_SCOPED_SIGS)は上の汎用
        # 走査面(path+query+UA混成)からは除外済み。ここで各々の専用フィールド *単体* を対象に
        # 個別判定する(scanner_ua=user_agentのみ/sensitive_path=pathのみ)。bio等の自由記述
        # フィールド内の言及や、query/headers越しの言及では判定しない=意味論どおりのスコープ。
        if sig_hit is None and user_agent:
            sig_hit, sig_weight = self._scan_signatures(
                _normalize_for_scan(user_agent), only=_UA_ONLY_SIGS)
        if sig_hit is None and path:
            sig_hit, sig_weight = self._scan_signatures(
                _normalize_for_scan(path), only=_PATH_ONLY_SIGS)
        for _t in _targets[1:_MAX_SCAN_FIELDS]:    # ヘッダ各値を独立面として(必要分だけ)走査
            if sig_hit is not None:
                break
            _nb = _normalize_for_scan(_t)
            sig_hit, sig_weight = self._scan_signatures(_nb)
        # テレメトリ(ロック外で算出=ロック保持時間を伸ばさない)。method は攻撃者入力ゆえ
        # 既知メソッド名のみ採用し OTHER に畳む(辞書の無制限肥大を防ぐ)。
        mkey = method.upper() if (method and method.isalpha() and len(method) <= 10) else "OTHER"
        with self._lock:
            self._metrics["requests"] += 1
            if sig_hit:                       # シグネチャ別ヒットの累積内訳(テレメトリ・推移用)
                self._sig_hits[sig_hit] = self._sig_hits.get(sig_hit, 0) + 1
            _zk = zone or "?"                 # ゾーン別リクエストの累積内訳(トラフィック構成)
            self._zone_hits[_zk] = self._zone_hits.get(_zk, 0) + 1
            self._method_hits[mkey] = self._method_hits.get(mkey, 0) + 1  # メソッド別
            self._tick_ewma()
            self._last_zone = zone           # _out で判定ログに残す(プロ分析の内訳用)
            st = self._state(ip)
            now = _now()
            # 1) BAN中
            if st["ban_until"] > now:
                return self._out(ip, "block", st, "BAN中", remain=st["ban_until"] - now)
            reasons = []
            # 1.2) サブネット集約防御(evolution #25・既定OFF): 同一サブネット(/24・v6 /64)で多数の
            #      *別IP* がBAN済み=分散攻撃の温床。新規IPに *一度だけ* ソフト加点して早期に絞る
            #      (ハードBANはしない=NAT/CGNAT 巻き添え回避)。flag で1回限り=加点の暴走なし。
            if self.cfg.get("subnet_defense") and not st.get("subnet_checked"):
                st["subnet_checked"] = True
                hot = self._subnet_hot_count(ip)
                if hot >= int(self.cfg.get("subnet_threshold", 8) or 0):
                    self._add_score(st, float(self.cfg.get("subnet_score", 30)))
                    self._metrics["subnet_flag"] = self._metrics.get("subnet_flag", 0) + 1
                    reasons.append(f"subnet:hot:{hot}")
            # 1.25) メソッドポリシー(evolution #26): XST(TRACE/TRACK)・プロキシ濫用(CONNECT)等の
            #       異常メソッドを遮断。アプリ前段にまず正規には来ない=低FP。空配列で無効化。
            mb = self.cfg.get("blocked_methods")
            if mb and (method or "").upper() in mb:
                return self._enforce_or_audit(ip, "block", st,
                    f"メソッド遮断: {(method or '').upper()[:16]}", kind="method_block")
            # 1.255) メソッドオーバーライド悪用(evolution #72): X-HTTP-Method-Override 等で実効
            #        メソッドを差し替える回避を塞ぐ。オーバーライド先にも blocked_methods を適用し、
            #        method_override_block ならオーバーライドヘッダの存在自体を遮断。
            ovr = (override_method or "").strip().upper()[:16]
            if ovr:
                if self.cfg.get("method_override_block"):
                    return self._enforce_or_audit(ip, "block", st,
                        f"メソッドオーバーライド禁止: {ovr}", kind="method_override")
                if mb and self.cfg.get("method_override_check", True) and ovr in mb:
                    return self._enforce_or_audit(ip, "block", st,
                        f"メソッド遮断(override): {ovr}", kind="method_block")
            # 1.256) パスオーバーライド ACL バイパス(evolution #73): X-Original-URL/X-Rewrite-URL は
            #        内部 rewrite 用。前段エッジにクライアントが送る=パス ACL 回避の手口=遮断。
            if override_path and self.cfg.get("path_override_block", True):
                return self._enforce_or_audit(ip, "block", st,
                    f"パスオーバーライド: {override_path[:60]}", kind="path_override")
            # 1.257) Range DoS(evolution #76): 多数レンジ(Apache Killer 系)でサーバに大量バッファを
            #        確保させる DoS を、レンジ数の上限で遮断。正規は 1〜2 レンジ=低FP。
            if range_header and self.cfg.get("range_check_enabled", True):
                if range_header.strip().lower().startswith("bytes="):
                    nr = range_header.count(",") + 1
                    if nr > int(self.cfg.get("range_max_ranges", 8)):
                        return self._enforce_or_audit(ip, "block", st,
                            f"過大な Range({nr} ranges): Apache Killer 系", kind="range_dos")
            # 1.26) ヘッダ整合性ボット検知(evolution #63): UA はブラウザを名乗るのに実ブラウザが
            #       常時送るヘッダを欠く=偽装ツールの手掛かり。低FPのため *加点のみ*(単独では落とさず
            #       flood/scan 等と合算でエスカレーション)。header_names 不明時はスキップ。
            if (self.cfg.get("bot_consistency_enabled")
                    and _ua_header_inconsistent(user_agent, header_names)):
                self._add_score(st, float(self.cfg.get("bot_inconsistency_score", 20)))
                self._metrics["bot_inconsistency"] = self._metrics.get("bot_inconsistency", 0) + 1
                reasons.append("ua-header不整合(ブラウザ偽装の疑い)")
            # 1.28) クレデンシャル単位レート(evolution #70): Bearer トークン/API キーの識別子単位で
            #       レートを集計。IP をローテーションしても同一キーの濫用は絞る。超過で加点。
            if self.cfg.get("cred_rate_enabled") and cred:
                cr = self._credential_rate(cred)
                if cr >= int(self.cfg.get("cred_rate_limit", 600)):
                    self._add_score(st, float(self.cfg.get("cred_rate_score", 40)))
                    self._metrics["cred_rate_hit"] = self._metrics.get("cred_rate_hit", 0) + 1
                    reasons.append(f"cred-rate:{cr}")
            # 1.265) JWT 検査(evolution #68): Bearer JWT の alg:none(無署名=認証バイパス)/
            #        許可外 alg(alg 混同攻撃)を遮断。署名検証はアプリ(鍵が無い)、ここは構造点検のみ。
            if self.cfg.get("jwt_inspect_enabled") and auth:
                jv = _jwt_violation(auth, self.cfg.get("jwt_allowed_algs"))
                if jv:
                    st["score"] = float(self.cfg["block_score"])
                    return self._enforce_or_audit(ip, "block", st, "JWT: " + jv,
                                                  kind="jwt_block", do_ban=True)
            # 1.3) ポリシー(拡張子/URL/正規TLS以外/海外CIDR/サイト許可遮断)。監査なら通過+アラート。
            pol = (self._policy_block(ip, path, tls) or self._site_block(host)
                   or self._ip_list_block(ip))
            if pol:
                return self._enforce_or_audit(ip, "block", st, "ポリシー: " + pol,
                                              kind="policy_block")
            # 2) 侵入シグネチャ(ロック外で判定済み・組込/カスタム共通)を反映
            if sig_hit:
                self._add_score(st, sig_weight or _SIG_WEIGHT.get(sig_hit, 30))
                reasons.append(f"signature:{sig_hit}")
            # 2.5) 低速・規則性(ステルスBot): 機械的に等間隔なアクセスを炙る(Floodに掛からない型)
            if self._cadence_botlike(st, now):
                self._add_score(st, float(self.cfg["cadence_score"]))
                reasons.append("cadence:botlike")
            # 3) flood(スライディングウィンドウ)
            w = st["window"]; w.append(now)
            ws = float(self.cfg["window_sec"])
            while w and w[0] < now - ws:
                w.popleft()
            if len(w) > int(self.cfg["flood_threshold"]):
                self._add_score(st, 25)
                reasons.append(f"flood:{len(w)}/{int(ws)}s")
            # 4) レート制限(トークンバケット)
            throttled = not self._take_token(st)
            throttle_reason = "レート超過(トークン枯渇)"
            # 4.5) パス別レート制限(任意・既定[]=無効ゼロコスト): 認証/高コスト経路を構造的に
            #      厳格化。グローバルが緩くても /login 等への連射(credential stuffing 等)を
            #      専用バケツで絞る。グローバルで既に枯渇なら評価不要(同じ throttle 結末)。
            if not throttled and self.cfg.get("path_limits"):   # 既定[]=falsy で即スキップ(ゼロコスト)
                _pr = self._path_rule_for(path)
                if _pr is not None and not self._path_token_ok(st, _pr):
                    throttled = True
                    throttle_reason = f"パス別レート超過: {_pr.get('path', '')}"
            score = self._decayed_score(st)
            # 5) しきい値判定(監査モードなら遮断せず通過+アラート)
            if score >= float(self.cfg["block_score"]):
                return self._enforce_or_audit(ip, "block", st,
                    "スコア超過→BAN: " + (",".join(reasons) or "高スコア"),
                    kind="ban", do_ban=True)
            # evolution #110: PoW チャレンジ段を廃止。deny_score 以上は BAN までは至らない
            # (=まだ確度が低い)単発の疑わしい signal として、この1件だけを拒否する(BANはしない=
            # 累犯にならなければ次のリクエストから通常どおり再評価される)。
            if score >= float(self.cfg["deny_score"]):
                return self._enforce_or_audit(ip, "block", st,
                    "スコア超過→単発拒否(BANなし): " + (",".join(reasons) or "要注意スコア"),
                    kind="score_deny")
            if throttled:
                return self._enforce_or_audit(ip, "throttle", st, throttle_reason)
            return self._out(ip, "allow", st, ",".join(reasons) or "正常")

    def penalize(self, ip: str, weight: float = 0.0, reason: str = "",
                 kind: str = "slowloris") -> dict:
        """完全なリクエストに至らない不正(slowloris=ヘッダをだらだら送る接続 等)へ
        スコアだけ加点する。単発では落とさず(誤遮断回避=正規の低速回線を守る)、
        反復で累積し block_score 超で BAN。監査モードは遮断しない(_enforce_or_audit 経由)。
        既存のスコア/減衰/BAN-TTL/bloom/イベントを再利用=新しい状態を増やさない。"""
        if not ip:
            return {"action": "ignore", "banned": False}
        with self._lock:
            st = self._state(ip)
            self._add_score(st, float(weight) or float(self.cfg.get("slowloris_score", 50)))
            score = self._decayed_score(st)
            if score >= float(self.cfg["block_score"]):
                r = self._enforce_or_audit(ip, "block", st,
                    reason or "反復的なヘッダ未完接続→BAN", kind=kind, do_ban=True)
                return {"action": r.get("action", "block"),
                        "banned": st.get("ban_until", 0) > _now(),
                        "score": round(score, 1)}
            self._event(ip, kind, {"reason": (reason or "penalty")[:80],
                                   "score": round(score, 1)})
            return {"action": "penalize", "banned": False, "score": round(score, 1)}

    def note_response(self, ip: str, status) -> dict:
        """バックエンド応答1件のステータスを脅威スコアへ還元する(evolution #60)。
        per-IP の 4xx を窓内で数え、閾を超えたら *エラーの足跡* を攻撃兆候として加点する:
          · 404 連射=パス列挙/スキャン、401/403 連射=ブルートフォース/クレデンシャルスタッフィング。
        加点は保守的で、1バーストでは即BANしない(誤遮断回避=単発のエラーバーストだけで
        IPを落とさない)。反復バーストで block_score 超→BAN。
        5xx はバックエンド起因が多く加点しない(テレメトリのみ)。応答パイプから呼ぶ(ロック外)。"""
        try:
            code = int(status)
        except Exception:
            return {"action": "ignore"}
        if not (400 <= code < 600):
            return {"action": "ignore"}
        with self._lock:
            self._metrics["resp_errors"] = self._metrics.get("resp_errors", 0) + 1
            band = f"{code // 100}xx"
            self._resp_code_hits[band] = self._resp_code_hits.get(band, 0) + 1
            if not self.cfg.get("resp_score_enabled") or not ip:
                return {"action": "track"}              # 既定で集計はするが加点は opt-out 可
            if not (400 <= code < 500):
                return {"action": "track"}              # 加点対象はクライアントエラー(4xx)のみ
            now = _now()
            win = float(self.cfg.get("resp_error_window_sec", 60))
            thr = int(self.cfg.get("resp_error_threshold", 50))
            st = self._state(ip)
            dq = st.get("resp_err")
            if dq is None:
                dq = st["resp_err"] = deque(maxlen=1024)
            dq.append(now)
            while dq and dq[0] < now - win:
                dq.popleft()
            if len(dq) < thr:
                return {"action": "track", "errors": len(dq)}
            dq.clear()                                  # 加点したら窓をリセット(二重加点しない)
            self._add_score(st, float(self.cfg.get("resp_error_score", 40)))
            score = self._decayed_score(st)
            reason = f"応答エラー連射({thr}+ の 4xx/{int(win)}s)=列挙/ブルートフォース兆候"
            if score >= float(self.cfg["block_score"]):
                self._enforce_or_audit(ip, "block", st, reason,
                                       kind="resp_anomaly", do_ban=True)
                banned = st.get("ban_until", 0) > _now()
            else:
                self._event(ip, "resp_anomaly", {"reason": reason, "score": round(score, 1)})
                banned = False
        return {"action": "block" if banned else "score", "banned": banned,
                "score": round(score, 1)}

    def inspect_body(self, ip: str, body: bytes) -> dict:
        """要求ボディ先頭(有界)をシグネチャ走査して脅威スコアへ還元する(evolution #61)。
        head と同じ正規化+署名エンジンを使い、POST/JSON/GraphQL 本文に潜む SQLi/XSS/RCE/SSTI
        など head-only 検査の死角を捉える。block_score 超で BAN(enforce 時)。監査モードは記録のみ。
        proxy が本文先頭を読んでから(転送前に)呼ぶ。空/無効/ヒット無しは allow。"""
        if not self.is_enabled() or not self.cfg.get("body_scan_enabled") or not body:
            return {"action": "allow"}
        cap = int(self.cfg.get("body_scan_max_bytes", 65536))
        data = bytes(body[:cap])
        # 重複ウィンドウ走査(#61): _normalize_for_scan は _MAX_SCAN(8192)で頭打ちなので、本文を
        # _MAX_SCAN 窓 + 重複で刻んで *全域* を走査する。これが無いと先頭を無害パディングで埋めて
        # 後段の payload を走査外へ押し出す回避(#39 と同種)が本文で成立してしまう。窓数は cap で有界。
        win, overlap = _MAX_SCAN, 256
        sig_hit, weight, i = None, 0.0, 0
        while i < len(data):
            try:
                blob = _normalize_for_scan(data[i:i + win].decode("latin1", "replace"))
            except Exception:
                break
            sig_hit, weight = self._scan_signatures(blob)
            if sig_hit:
                break
            if i + win >= len(data):
                break
            i += win - overlap                       # 重複=窓境界を跨ぐ payload も捉える
        if not sig_hit:
            return {"action": "allow"}
        with self._lock:
            self._sig_hits[sig_hit] = self._sig_hits.get(sig_hit, 0) + 1
            st = self._state(ip)
            base = float(weight) or float(_SIG_WEIGHT.get(sig_hit, 30))
            factor = float(self.cfg.get("body_sig_weight_factor", 1.0) or 1.0)
            self._add_score(st, base * factor)       # 本文由来は確度を下げて誤BANを抑制
            score = self._decayed_score(st)
            reason = f"body signature: {sig_hit}"
            if score >= float(self.cfg["block_score"]):
                r = self._enforce_or_audit(ip, "block", st, reason,
                                           kind="body_sig", do_ban=True)
                act = r.get("action", "block")
                banned = st.get("ban_until", 0) > _now()
            else:
                self._event(ip, "body_sig", {"signature": sig_hit, "score": round(score, 1)})
                act, banned = "score", False
        return {"action": act if act in ("block", "throttle") else "score",
                "banned": banned, "signature": sig_hit, "score": round(score, 1)}

    def scan_upload(self, ip: str, body: bytes) -> dict:
        """multipart アップロードの危険拡張子(webshell/実行体)を拒否する(evolution #66)。
        #61(本文シグネチャ)とは別関心=ファイル種別ポリシー。filename= から危険拡張子を見つけたら
        加点(block_score 超で BAN)。二重拡張子も全セグメント検査で捉える。無効/該当無しは allow。"""
        if not self.is_enabled() or not self.cfg.get("upload_scan_enabled") or not body:
            return {"action": "allow"}
        cap = int(self.cfg.get("body_scan_max_bytes", 65536))
        hit = _dangerous_upload_filename(body, self.cfg.get("upload_deny_ext"), cap)
        if not hit:
            return {"action": "allow"}
        fn, ext = hit
        with self._lock:
            st = self._state(ip)
            self._add_score(st, float(self.cfg["block_score"]))   # 危険UL=単発で遮断水準
            score = self._decayed_score(st)
            reason = f"危険なアップロード拡張子(.{ext}): {fn}"
            r = self._enforce_or_audit(ip, "block", st, reason, kind="upload_block",
                                       do_ban=True)
            act = r.get("action", "block")
            banned = st.get("ban_until", 0) > _now()
        return {"action": act if act in ("block", "throttle") else "score",
                "banned": banned, "ext": ext, "filename": fn, "score": round(score, 1)}

    def inspect_graphql(self, ip: str, path: str, body: bytes) -> dict:
        """GraphQL エンドポイントへの問い合わせを上限照合する(evolution #67)。深いネスト/複雑度/
        イントロスペクション/バッチ過大を遮断(リゾルバコスト爆発 DoS とスキーマ漏洩を防ぐ)。
        graphql_paths のパスにだけ適用。違反は block_score 加点(単発で遮断水準)。proxy が本文先頭を渡す。"""
        if not self.is_enabled() or not self.cfg.get("graphql_enabled") or not body:
            return {"action": "allow"}
        p = (path or "").split("?", 1)[0]
        paths = self.cfg.get("graphql_paths") or ["/graphql"]
        if not any(p == gp or p.startswith(gp.rstrip("/") + "/") or p == gp.rstrip("/")
                   for gp in paths):
            return {"action": "allow"}
        from .graphql import extract_queries, check
        cap = int(self.cfg.get("body_scan_max_bytes", 65536))
        res = check(extract_queries(bytes(body[:cap])),
                    max_depth_limit=int(self.cfg.get("graphql_max_depth", 12)),
                    max_complexity=int(self.cfg.get("graphql_max_complexity", 100)),
                    block_introspection=bool(self.cfg.get("graphql_block_introspection", True)),
                    max_batch=int(self.cfg.get("graphql_max_batch", 10)))
        if res["allowed"]:
            return {"action": "allow"}
        with self._lock:
            st = self._state(ip)
            self._add_score(st, float(self.cfg["block_score"]))
            score = self._decayed_score(st)
            reason = "GraphQL 制限超過: " + res["reason"]
            r = self._enforce_or_audit(ip, "block", st, reason, kind="graphql_block",
                                       do_ban=True)
            act = r.get("action", "block")
            banned = st.get("ban_until", 0) > _now()
        return {"action": act if act in ("block", "throttle") else "score",
                "banned": banned, "reason": res["reason"], "score": round(score, 1)}

    # ── 応答セキュリティヘッダ(evolution #12) ──
    def set_sec_headers_enabled(self, on: bool) -> dict:
        """応答セキュリティヘッダ注入の ON/OFF(永続化)。書換は proxy._pipe が cfg を読んで実施。"""
        with self._lock:
            self.cfg["sec_headers_enabled"] = bool(on)
            self._save()
        return {"ok": True, "sec_headers_enabled": self.cfg["sec_headers_enabled"]}

    # ── パス別レート制限(evolution #21) ──
    def set_path_limits(self, rules) -> dict:
        """パス別レート制限ルールを *置換* で設定し永続化。各ルール {path, rate[, burst]}:
        path=前方一致prefix(リテラル・ReDoSなし)/ rate=毎秒許容 / burst=瞬間許容(既定=rate)。
        認証/高コスト経路をグローバル(rate_per_sec)より厳格に絞る。不正項目は捨て、最大
        _PATH_LIMIT_MAX 件に丸める。空配列=無効。in-place 変更せず新リストを代入(既定共有回避)。"""
        norm = []
        if isinstance(rules, (list, tuple)):
            for r in rules:
                if not isinstance(r, dict):
                    continue
                p = str(r.get("path", "")).strip()
                if not p:
                    continue
                try:
                    rate = float(r.get("rate", self.cfg["rate_per_sec"]))
                except (TypeError, ValueError):
                    continue
                if rate <= 0:
                    continue
                try:
                    burst = float(r.get("burst", rate))
                except (TypeError, ValueError):
                    burst = rate
                norm.append({"path": p, "rate": rate, "burst": max(1.0, burst)})
                if len(norm) >= _PATH_LIMIT_MAX:
                    break
        with self._lock:
            self.cfg["path_limits"] = norm
            self._save()
        return {"ok": True, "path_limits": list(norm)}

    # ── HTTPメソッドポリシー(evolution #26) ──
    def set_blocked_methods(self, methods) -> dict:
        """遮断する HTTP メソッド一覧を *置換* で設定し永続化。英字のみ・大文字化・重複除去。
        空配列=無効。XST(TRACE/TRACK)/プロキシ濫用(CONNECT)等の低FPな異常メソッド向け。"""
        norm = []
        if isinstance(methods, (list, tuple)):
            for m in methods:
                m = str(m).strip().upper()
                if m and m.isalpha() and len(m) <= 16 and m not in norm:
                    norm.append(m)
        with self._lock:
            self.cfg["blocked_methods"] = norm
            self._save()
        return {"ok": True, "blocked_methods": list(norm)}


    # ── 出口DLP(evolution #6) ──
    def dlp_active(self) -> bool:
        """DLP が有効か(本体ON かつ dlp_enabled)。"""
        return self.is_enabled() and bool(self.cfg.get("dlp_enabled"))

    def scan_leak(self, data) -> list:
        """応答チャンクから秘密情報漏洩の種別を返す(DLP有効時のみ)。"""
        return scan_secret_leak(data) if self.cfg.get("dlp_enabled") else []

    def note_leak(self, ip: str, kinds: list) -> dict:
        """漏洩検出をイベント/メトリクス/種別内訳へ記録。action=block なら呼び出し側が残りを送らず切断。"""
        kinds = list(dict.fromkeys(kinds))[:8]      # 重複除去・上限
        with self._lock:
            self._metrics["dlp_leak"] = self._metrics.get("dlp_leak", 0) + 1
            for k in kinds:                         # 漏洩した秘密種別の累積内訳(テレメトリ)
                self._dlp_kinds[k] = self._dlp_kinds.get(k, 0) + 1
            self._event(ip, "dlp_leak", {"kinds": kinds})
        return {"action": self.cfg.get("dlp_action", "audit"), "kinds": kinds}

    def _enforce_or_audit(self, ip, action, st, reason, *, kind="",
                          do_ban=False, ban_perm=False, **kw):
        """決定点の一元化。監査モードは遮断せず通過+アラート。enforce は必要ならBAN設定。"""
        if self.cfg.get("mode") == "audit":
            self._event(ip, "audit", {"would": action, "reason": reason[:120], "rule": kind})
            return self._out(ip, "allow", st, f"AUDIT(would {action}): {reason}")
        if do_ban:
            st["ban_count"] = st.get("ban_count", 0) + 1       # 累犯回数(エスカレーション用)
            if ban_perm:
                st["ban_until"] = float("inf")
            else:
                ttl = float(self.cfg["ban_ttl_sec"])
                if self.cfg.get("ban_escalation", True):       # 累犯ほど長く(初回 n=1 は据置)
                    cap = int(self.cfg.get("ban_escalation_cap", 64) or 1)
                    ttl *= min(max(1, cap), 2 ** min(st["ban_count"] - 1, 30))
                st["ban_until"] = _now() + ttl
            st["ban_started"] = _now()
            st["permanent"] = bool(ban_perm)
            self._ban_bloom.add(ip)
            self._save_bans()
            if self.cfg.get("subnet_defense"):       # 分散攻撃の集約検知(#25): サブネットにBANを記録
                self._record_subnet_ban(ip)
            if kind:
                self._event(ip, kind, {"reason": reason[:120], "count": st["ban_count"]})
        return self._out(ip, action, st, reason, **kw)

    def _take_token(self, st: dict) -> bool:
        now = _now()
        rate = float(self.cfg["rate_per_sec"]); burst = float(self.cfg["burst"])
        st["tokens"] = min(burst, st["tokens"] + max(0.0, now - st["refill"]) * rate)  # 時刻巻戻しで
        st["refill"] = now                        #   トークンが減らないよう dt≥0 にクランプ(#44)
        if st["tokens"] >= 1.0:
            st["tokens"] -= 1.0
            return True
        return False

    def _path_rule_for(self, path: str):
        """path(query/fragment 除去・小文字)に最初に前方一致する path_limits ルールを返す。
        無ければ None。**リテラル prefix 照合のみ=ReDoS なし**。運用者は具体的なルールを先頭へ並べる。"""
        rules = self.cfg.get("path_limits")
        if not rules:
            return None
        p = _path_for_match(path)            # %デコード(#40)=/%6cogin 等での経路レート回避を防ぐ
        for r in rules:
            pref = str(r.get("path", "")).lower()
            if pref and p.startswith(pref):
                return r
        return None

    def _path_token_ok(self, st: dict, rule: dict) -> bool:
        """マッチした path ルールの専用トークンバケツ(per-IP)を1つ消費。枯渇なら False。
        キーは *ルールの prefix*=攻撃者がパス末尾を変えてもバケツは増えない(メモリ有界)。"""
        key = str(rule.get("path", "")).lower()
        rate = float(rule.get("rate", self.cfg["rate_per_sec"]))
        burst = float(rule.get("burst", rate))
        now = _now()
        buckets = st.setdefault("path_buckets", {})
        b = buckets.get(key)
        if b is None:
            b = {"tokens": burst, "refill": now}
            buckets[key] = b
        b["tokens"] = min(burst, b["tokens"] + max(0.0, now - b["refill"]) * rate)  # dt≥0(#44)
        b["refill"] = now
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True
        return False

    # ── サブネット集約防御(evolution #25): 分散攻撃を /24・/64 で束ねて捉える ──
    def _record_subnet_ban(self, ip: str):
        """BAN された IP を所属サブネットへ記録(distinct IP→最終BAN時刻)。窓外を掃除し、
        サブネット数・サブネット内IP数とも上限で有界化(攻撃者がメモリを膨らませられない)。"""
        key = _subnet_key(ip)
        if not key:
            return
        now = _now()
        window = float(self.cfg.get("subnet_window_sec", 3600) or 0)
        rec = self._subnets.get(key)
        if rec is None:
            if len(self._subnets) >= _MAX_SUBNETS:
                self._evict_subnets()
            rec = {}
            self._subnets[key] = rec
        rec[ip] = now
        if window > 0:                                   # 窓外の古いBANは掃除(hot 判定の鮮度)
            for k in [k for k, t in rec.items() if now - t > window]:
                rec.pop(k, None)
        if len(rec) > _SUBNET_IP_CAP:                    # サブネット内 distinct IP を上限で頭打ち
            for k, _ in sorted(rec.items(), key=lambda kv: kv[1])[:len(rec) - _SUBNET_IP_CAP]:
                rec.pop(k, None)

    def _subnet_hot_count(self, ip: str) -> int:
        """IP の所属サブネットで *窓内にBANされた distinct IP 数* を返す(0=未追跡/不正)。"""
        key = _subnet_key(ip)
        rec = self._subnets.get(key) if key else None
        if not rec:
            return 0
        window = float(self.cfg.get("subnet_window_sec", 3600) or 0)
        if window <= 0:
            return len(rec)
        now = _now()
        return sum(1 for t in rec.values() if now - t <= window)

    def _evict_subnets(self):
        # 最終BANが最も古いサブネットから1割を間引く(メモリ有界)
        victims = sorted(self._subnets.items(),
                         key=lambda kv: max(kv[1].values()) if kv[1] else 0.0)
        for k, _ in victims[:max(1, _MAX_SUBNETS // 10)]:
            self._subnets.pop(k, None)

    def subnet_status(self) -> dict:
        """サブネット集約防御の可視化(有効/追跡数/hot数/設定)。読み取り専用。"""
        with self._lock:
            now = _now()
            window = float(self.cfg.get("subnet_window_sec", 3600) or 0)
            thr = int(self.cfg.get("subnet_threshold", 8) or 0)
            hot = sum(1 for rec in self._subnets.values()
                      if (len(rec) if window <= 0
                          else sum(1 for t in rec.values() if now - t <= window)) >= thr)
            return {"enabled": bool(self.cfg.get("subnet_defense")),
                    "tracked_subnets": len(self._subnets), "hot_subnets": hot,
                    "threshold": thr, "window_sec": window,
                    "subnet_score": self.cfg.get("subnet_score", 30),
                    "note": "分散攻撃の集約検知(/24・v6 /64)。新規IPへソフト加点のみ"
                            "(ハードBANせず=共有NAT巻き添え回避)。既定OFF。"}

    def _out(self, ip, action, st, reason, remain=None):
        self._metrics[action] = self._metrics.get(action, 0) + 1
        if action == "block":
            st["hits"] += 1
        sig = (reason.split("signature:", 1)[1].split(",")[0].strip()
               if "signature:" in reason else "")
        self._declog.append({"t": _now(), "zone": self._last_zone,
                             "action": action, "sig": sig})
        res = {"action": action, "reason": reason,
               "score": round(self._decayed_score(st), 1), "ip": ip}
        if remain is not None:
            res["ban_remain_sec"] = round(remain, 1)
        return res

    # ── 全体レートEWMA(ダッシュボード用テレメトリ) ──
    def _tick_ewma(self):
        now = _now()
        dt = now - self._ewma_last
        if dt <= 0:
            return
        inst = 1.0 / dt
        alpha = 1 - 0.5 ** (dt / 5.0)        # 5秒半減のEWMA
        self._ewma = (1 - alpha) * self._ewma + alpha * inst
        self._ewma_last = now

    # ── 低速規則性 ──
    def _cadence_botlike(self, st: dict, now: float) -> bool:
        """直近リクエスト間隔の規則性を見る。速め(平均<閾値)かつ変動係数が極小=機械。
        遅い正規ポーラ(平均間隔が大)は対象外にして誤検知を抑える。"""
        last = st["last_req"]
        st["last_req"] = now
        if last <= 0:
            return False
        ivs = st["intervals"]
        ivs.append(now - last)
        n = len(ivs)
        if n < int(self.cfg["cadence_min_samples"]):
            return False
        mean = sum(ivs) / n
        if mean <= 0 or mean > float(self.cfg["cadence_max_mean_interval"]):
            return False
        var = sum((x - mean) ** 2 for x in ivs) / n
        cv = (var ** 0.5) / mean
        return cv < float(self.cfg["cadence_cv_threshold"])

    def absorb_suspend(self, gap: float) -> dict:
        """プロセス一時停止(OSスリープ/SIGSTOP/VM一時停止/デバッガ凍結)からの復帰時に呼ぶ(#49)。
        停止中は wall-clock だけが進むため、時限BANが停止時間の分だけ早く切れて攻撃者を
        取り逃がす。停止秒数 gap を『停止開始時点で有効だった』BANタイマーにのみ足し戻し、
        停止を無かったかのように補正する(プロセスごと凍結=停止中に攻撃は来ない→足し戻しは安全側)。
        一時停止(OSスリープ等)を検出する仕組み(旧 watchdog)がある場合にそこから配線する用途。
        返り値=補正件数。"""
        gap = float(gap)
        if gap <= 0:
            return {"ok": True, "absorbed": 0.0, "bans": 0}
        with self._lock:
            thr = _now() - gap                      # ≈ 停止開始時刻(これより後に切れる=停止時点で有効)
            n_ban = 0
            for st in self._ips.values():
                bu = st.get("ban_until", 0.0)
                if bu and bu != float("inf") and bu > thr:   # 停止時点で有効だった時限BAN
                    st["ban_until"] = bu + gap; n_ban += 1
            self._event("system", "suspend_absorbed",
                        {"gap_sec": round(gap, 1), "bans": n_ban})
        return {"ok": True, "absorbed": round(gap, 1), "bans": n_ban}

    # ── BAN管理 ──
    def bans(self) -> list:
        now = _now()
        with self._lock:
            out = []
            for ip, s in self._ips.items():
                if s["ban_until"] <= now:
                    continue
                perm = s.get("permanent") or s["ban_until"] == float("inf")
                out.append({"ip": ip,
                            "remain_sec": (-1 if perm else round(s["ban_until"] - now, 1)),
                            "permanent": bool(perm),
                            "score": round(self._decayed_score(s), 1), "hits": s["hits"]})
            return out

    def ban(self, ip: str, ttl_sec: float = None, permanent: bool = False) -> dict:
        """手動BAN。permanent=True で無期限BAN、ttl_sec で時限BAN(既定は cfg のTTL)。"""
        with self._lock:
            st = self._state(ip)
            st["ban_until"] = (float("inf") if permanent
                               else _now() + float(ttl_sec or self.cfg["ban_ttl_sec"]))
            st["ban_started"] = _now()
            st["permanent"] = bool(permanent)
            self._ban_bloom.add(ip)
            self._save_bans()
        self._event(ip, "manual_ban", {"permanent": permanent})
        return {"ok": True, "banned": ip, "permanent": permanent}

    # ── 一時制限(状況報告書→管理者アラート→双方合意で解除) ──
    def restrict(self, ip: str, ttl_sec: float = None) -> dict:
        """一時制限をかける。解除には『状況報告書(ユーザー)』+『管理者承認』の双方合意が要る。"""
        self.ban(ip, ttl_sec=ttl_sec)
        with self._lock:
            self._restrictions[ip] = {"ts": _now(), "report": "", "user_ok": False,
                                      "admin_ok": False, "status": "restricted"}
        self._event(ip, "restricted", {})
        return {"ok": True, "restricted": ip,
                "note": "解除には状況報告書の提出+管理者承認の双方合意が必要。"}

    def submit_report(self, ip: str, report: str) -> dict:
        """ユーザー側: 状況報告書を提出する→管理者へアラート。"""
        r = self._restrictions.get(ip)
        if not r:
            return {"ok": False, "error": "一時制限の対象ではありません"}
        with self._lock:
            r["report"] = (report or "")[:2000]
            r["user_ok"] = True
            r["status"] = "report_submitted"
        self._event(ip, "restriction_report", {})   # 管理者ダッシュボード/CLIに表示=アラート
        return self._maybe_release(ip)

    def admin_confirm(self, ip: str, agree: bool, note: str = "") -> dict:
        """管理者側: 報告書を確認して合意/不合意。双方合意なら解除。"""
        r = self._restrictions.get(ip)
        if not r:
            return {"ok": False, "error": "一時制限の対象ではありません"}
        with self._lock:
            r["admin_ok"] = bool(agree)
            r["admin_note"] = note
            if not agree:
                r["status"] = "admin_rejected"
        self._event(ip, "restriction_admin_" + ("ok" if agree else "reject"), {})
        return self._maybe_release(ip)

    def _maybe_release(self, ip: str) -> dict:
        r = self._restrictions.get(ip)
        if r and r["user_ok"] and r["admin_ok"]:
            r["status"] = "released"
            self.unban(ip)
            self._event(ip, "restriction_released", {})
            return {"ok": True, "released": True, "status": "released",
                    "note": "双方合意により解除されました。"}
        return {"ok": True, "released": False, "status": r["status"] if r else "?",
                "need": {"user_report": not (r and r["user_ok"]),
                         "admin_confirm": not (r and r["admin_ok"])}}

    def list_restrictions(self) -> list:
        with self._lock:
            return [{"ip": ip, **v} for ip, v in self._restrictions.items()]

    def unban(self, ip: str) -> dict:
        with self._lock:
            st = self._ips.get(ip)
            if st:
                st["ban_until"] = 0.0; st["score"] = 0.0; st["permanent"] = False
            self._save_bans()
        # ブルームは単一ビット削除不可→現役BANから作り直して陳腐ビットを落とす(偽陽性率を保つ)
        self.rebuild_ban_bloom()
        return {"ok": True, "unbanned": ip}

    # ── 遮断ページ / 解除リクエスト(異議申立) ──
    def ban_info(self, ip: str) -> dict:
        """遮断ページ表示用: 残り時間・解除リクエスト可否・申立済みか。"""
        now = _now()
        st = self._ips.get(ip)
        banned = bool(st and st["ban_until"] > now)
        perm = bool(st and (st.get("permanent") or st["ban_until"] == float("inf")))
        age = (now - st["ban_started"]) if (st and st.get("ban_started")) else 0.0
        ap = self._appeals.get(ip)
        return {"banned": banned, "permanent": perm,
                "remain_sec": (-1 if (banned and perm)
                               else round(st["ban_until"] - now, 1) if banned else 0.0),
                "ban_age_sec": round(age, 1),
                "ban_count": int(st.get("ban_count", 0)) if st else 0,   # 累犯回数(エスカレーション)
                "appeal_available": bool(banned and self.cfg["appeal_enabled"]
                                         and age >= float(self.cfg["appeal_after_sec"])),
                "appeal_after_sec": float(self.cfg["appeal_after_sec"]),
                "appealed": (ap["status"] if ap else None)}

    def submit_appeal(self, ip: str, reason: str = "") -> dict:
        """遮断されたユーザーが解除リクエスト(異議申立)を出す。"""
        info = self.ban_info(ip)
        if not info["banned"]:
            return {"ok": False, "error": "現在BANされていません"}
        if not self.cfg["appeal_enabled"]:
            return {"ok": False, "error": "解除リクエストは無効化されています"}
        if info["ban_age_sec"] < float(self.cfg["appeal_after_sec"]):
            return {"ok": False, "error": "まだ受付時間ではありません",
                    "retry_after_sec": round(float(self.cfg["appeal_after_sec"])
                                             - info["ban_age_sec"], 1)}
        with self._lock:
            self._appeals.pop(ip, None)              # 再提出は末尾へ(最新化=最古退避で消えにくく)
            self._appeals[ip] = {"ts": _now(), "reason": (reason or "")[:500],
                                 "status": "pending"}
            # メモリ有界化: 上限超過なら *解決済み(approved/denied)を優先* に退避し、審査待ちを温存。
            # 全て pending のときのみ最古の pending を退避(=多数IPからの申立フラッドで OOM しない)。
            while len(self._appeals) > _APPEALS_MAX:
                victim = next((k for k, v in self._appeals.items()
                               if v.get("status") != "pending"), None)
                self._appeals.pop(victim if victim is not None
                                  else next(iter(self._appeals)), None)
        self._event(ip, "appeal_submitted", {})
        return {"ok": True, "status": "pending",
                "note": "管理者の審査待ちです。承認されると解除されます。"}

    def list_appeals(self, status: str = "") -> list:
        with self._lock:
            return [{"ip": ip, **v} for ip, v in self._appeals.items()
                    if not status or v["status"] == status]

    def resolve_appeal(self, ip: str, approve: bool, note: str = "") -> dict:
        """管理者が解除リクエストを承認(=BAN解除)/却下する。"""
        ap = self._appeals.get(ip)
        if not ap:
            return {"ok": False, "error": f"申立が無い: {ip}"}
        ap["status"] = "approved" if approve else "denied"
        ap["resolved_ts"] = _now()
        ap["note"] = note
        if approve:
            self.unban(ip)
        self._event(ip, "appeal_" + ap["status"], {})
        return {"ok": True, "ip": ip, "status": ap["status"]}

    # ── リアルタイム時系列(グラフ用) / プロ詳細分析 ──
    def sample_series(self) -> None:
        """累積メトリクスのスナップショットを時系列に1点追加(~1秒に1回に間引く)。"""
        now = _now()
        if now - self._series_last < 1.0:
            return
        self._series_last = now
        m = self._metrics
        self._series.append({"t": round(now, 1), "requests": m["requests"],
                             "allow": m["allow"], "block": m["block"],
                             "throttle": m["throttle"],
                             "dlp_leak": m.get("dlp_leak", 0),
                             "sig_total": sum(self._sig_hits.values()),
                             "pub": self._zone_hits.get("public", 0),
                             "ewma": round(self._ewma, 2)})

    def series(self, n: int = 120) -> list:
        """直近の時系列(累積値)。クライアントが差分を取って req/s 等を描画する。"""
        self.sample_series()
        with self._lock:
            return list(self._series)[-max(1, n):]

    def analysis(self) -> dict:
        """プロ向け詳細分析一式(アクション/ゾーン/シグネチャ/上位送信元の内訳)。"""
        now = _now()
        with self._lock:
            zones, sigs, kinds = {}, {}, {}
            for e in self._declog:
                z = e.get("zone") or "?"
                zones[z] = zones.get(z, 0) + 1
                if e.get("sig"):
                    sigs[e["sig"]] = sigs.get(e["sig"], 0) + 1
            for ev in self._events:
                kinds[ev["kind"]] = kinds.get(ev["kind"], 0) + 1
        return {"actions": dict(self._metrics),
                "by_zone": zones,
                "top_signatures": sorted(sigs.items(), key=lambda x: -x[1])[:10],
                "event_kinds": kinds,
                "top_talkers": self.top_talkers(15),
                "active_bans": len(self.bans()),
                "appeals_pending": len(self.list_appeals("pending")),
                "ban_bloom": self._ban_bloom.info(),
                "global_rate_ewma": round(self._ewma, 2),
                "ts": now}

    # ── ネットワーク図(IP:zone:MAC・直感ブロック用) / APT検知の形式化 ──
    def nodes(self, n: int = 60, with_mac: bool = False) -> dict:
        """観測中の送信元をノード化して返す(ダッシュボードのネットワーク図用)。"""
        now = _now()
        macs = _arp_table() if with_mac else {}
        with self._lock:
            rows = []
            for ip, s in self._ips.items():
                rows.append({"ip": ip, "zone": _zone_of(ip),
                             "score": round(self._decayed_score(s), 1),
                             "banned": s["ban_until"] > now,
                             "permanent": bool(s.get("permanent")),
                             "reqs_window": len(s["window"]), "hits": s["hits"],
                             "mac": macs.get(ip, "")})
        rows.sort(key=lambda r: (r["banned"], r["score"], r["reqs_window"]), reverse=True)
        _zones = ["loopback", "private", "public", "special", "unknown"]
        return {"center": "ChickenNet L7 Security", "nodes": rows[:n],
                "zones": {z: sum(1 for r in rows if r["zone"] == z) for z in _zones}}

    def apt_report(self, n: int = 15) -> dict:
        """APT級の兆候を既存シグナルから形式化(アプリ層・低速持続/規則性/累積攻撃の相関)。
        正直: エンドポイントEDRではない=ネット越し挙動からの推定。スコア化して上位を返す。"""
        now = _now()
        ranked = []
        with self._lock:
            for ip, s in self._ips.items():
                ivs = list(s["intervals"])
                regular = False
                if len(ivs) >= 6:
                    mean = sum(ivs) / len(ivs)
                    if 0 < mean <= 5.0:
                        var = sum((x - mean) ** 2 for x in ivs) / len(ivs)
                        regular = (var ** 0.5) / mean < 0.2
                span = now - s.get("first", now)
                persistent = span > 300 and len(ivs) >= 6      # 5分以上 等間隔で居座る
                base = self._decayed_score(s)
                apt = base + (30 if regular else 0) + (25 if persistent else 0) \
                    + min(40, s["hits"] * 8)
                if apt >= 30:
                    ranked.append({"ip": ip, "apt_score": round(apt, 1),
                                   "zone": _zone_of(ip), "regular_beacon": regular,
                                   "low_and_slow": persistent, "hits": s["hits"],
                                   "banned": s["ban_until"] > now})
        ranked.sort(key=lambda r: r["apt_score"], reverse=True)
        return {"suspects": ranked[:n], "count": len(ranked),
                "note": "アプリ層の振る舞い相関(低速持続/規則的ビーコン/累積攻撃)。EDRではない。"}

    # ── BAN永続化(再起動耐性 / クラスタは共有ファイルで疎結合・Redisは継ぎ目) ──
    def _load_bans(self):
        if not self.cfg.get("persist_bans"):
            return
        d, migrate = self._read_state(self._bans_path, {}, "bans")
        d = d or {}
        now = _now()
        retain = float(self.cfg.get("ban_escalation_retain_sec", 86400) or 0)
        for ip, b in (d.get("bans") or {}).items():
            until = float("inf") if b.get("permanent") else float(b.get("until") or 0)
            cnt = int(b.get("count") or 0)
            started = float(b.get("started") or now)
            if not b.get("permanent") and until <= now:
                # 期限切れBAN: 累犯回数だけ保持窓内なら復元(エスカレーションを再起動越しに継続)。
                if cnt > 0 and retain > 0 and (now - started) <= retain:
                    st = self._state(ip)
                    st["ban_count"] = cnt
                    st["ban_started"] = started
                continue                          # BAN自体は復元しない(掃除)
            st = self._state(ip)
            st["ban_until"] = until
            st["ban_started"] = started
            st["permanent"] = bool(b.get("permanent"))
            st["ban_count"] = cnt
            self._ban_bloom.add(ip)
        if migrate:                               # 旧来の無署名 blocklist→署名済みへ移行
            self._save_bans()

    def _save_bans(self):
        if not self.cfg.get("persist_bans"):
            return
        now = _now()
        retain = float(self.cfg.get("ban_escalation_retain_sec", 86400) or 0)
        bans = {}
        for ip, s in self._ips.items():
            cnt = int(s.get("ban_count", 0))
            if s["ban_until"] > now:               # アクティブBAN: 通常どおり永続化(+累犯回数)
                bans[ip] = {"until": (None if s.get("permanent") else s["ban_until"]),
                            "started": s.get("ban_started", now),
                            "permanent": bool(s.get("permanent")), "count": cnt}
            elif cnt > 0 and retain > 0 and (now - s.get("ban_started", 0)) <= retain:
                # 期限切れだが累犯履歴あり: 保持窓内なら回数のみ残す(BANは付与しない)。
                bans[ip] = {"until": 0, "started": s.get("ban_started", now),
                            "permanent": False, "count": cnt}
        write_signed_json(self._bans_path, {"bans": bans, "saved": now}, self._state_key)

    def reload_bans(self) -> dict:
        """共有BANファイルを再読込(クラスタの各ワーカーが定期的に呼べば疎結合で同期)。"""
        with self._lock:
            self._load_bans()
        return {"ok": True, "active_bans": len(self.bans())}

    def flush_state(self) -> dict:
        """現在のBAN状態(累犯回数=ban_count 含む)を確実にディスクへ書き出す。
        graceful shutdown の仕上げに呼ぶ。通常はBAN変化のたびに保存されるが、停止直前に
        明示 flush することで最新のエスカレーション記憶(期限切れ offender の保持分も)を
        取りこぼさない。persist_bans=False なら _save_bans は no-op(=安全に何もしない)。"""
        with self._lock:
            self._save_bans()
        return {"ok": True, "persisted": bool(self.cfg.get("persist_bans"))}

    def is_banned_fast(self, ip: str) -> bool:
        """既知BANかを **ロックなし・ほぼO(1)** で判定(プリスキャン用)。
        ブルーム miss=確実に未BAN(即 False)。hit のみ厳密確認(GIL原子の辞書read)で確定。
        陳腐ビット(期限切れ)による偽陽性は厳密確認が弾く=正規ユーザーを誤って落とさない。"""
        if ip not in self._ban_bloom:
            return False
        st = self._ips.get(ip)               # GIL原子の読み取り(state変更なし=ロック不要)
        return bool(st and st["ban_until"] > _now())

    def rebuild_ban_bloom(self) -> dict:
        """現役BANだけからブルームを作り直す(陳腐ビットを落として偽陽性率を保つ)。"""
        nb = BloomFilter(capacity=max(2000, _MAX_IPS // 4))
        now = _now()
        with self._lock:
            for ip, s in self._ips.items():
                if s["ban_until"] > now:
                    nb.add(ip)
        self._ban_bloom = nb
        return {"ok": True, "bloom": nb.info()}

    # ── 記録/指標 ──
    def _event(self, ip, kind, extra):
        self._events.append({"ts": _now(), "ip": ip, "kind": kind, **extra})

    def traffic_stall_check(self, now: float = None) -> dict:
        """迂回検知 / dead-man's switch(#78)。AsyncEdgeGuard の独立した定期チェックループから
        周期的に呼ぶ。直近の区間が busy
        (>= stall_min_rate)だったのに *今区間で1件も通っていない* なら、再ルーティング等で
        ChickenNet を迂回された疑いとして警報する。busy→ゼロ の遷移のみ=自然な低トラフィックや
        graceful な停止では鳴らない。返り値 {"stall": bool, ...}。"""
        now = _now() if now is None else now
        with self._lock:
            cur = self._metrics.get("requests", 0)
            last_c, last_t, prev_rate = self._stall_count, self._stall_ts, self._stall_prev_rate
            self._stall_count, self._stall_ts = cur, now
            dt = now - last_t
            if last_t < 0 or dt <= 0:
                return {"stall": False, "prev_rate": round(prev_rate, 2),
                        "reason": "warmup"}                     # 初回/無区間
            delta = cur - last_c
            self._stall_prev_rate = delta / dt
            busy_before = prev_rate >= float(self.cfg.get("stall_min_rate", 1.0))
            stalled = (self.cfg.get("stall_detect_enabled", True)
                       and busy_before and delta == 0)
            if stalled:
                self._event("system", "traffic_stall",
                            {"prev_rate": round(prev_rate, 2), "gap_sec": round(dt, 1),
                             "note": "edge traffic stopped while recently busy=possible bypass"})
            ev = stalled
        return {"stall": bool(ev), "prev_rate": round(prev_rate, 2)}

    def report_tamper(self, kind: str, what: str, action: str, extra=None) -> dict:
        """改竄検知を *一級アラート* として可視化する単一経路(#55)。
          · ローカル events に記録(ダッシュボードの /api/shield/events に出る)。
          · 件数/直近/種別内訳を計上 → status/metrics の `tamper` ブロックで前面に出す。
        kind: "state_tamper"(状態ファイル改竄)/ "memory_tamper"(in-memory cfg 改竄)。"""
        d = {"what": what, "action": action}
        if extra:
            d.update(extra)
        with self._lock:
            self._tamper["count"] += 1
            self._tamper["last"] = {"ts": round(_now(), 1), "kind": kind, **d}
            self._tamper["by_kind"][kind] = self._tamper["by_kind"].get(kind, 0) + 1
        self._event("system", kind, d)
        return {"ok": True, "tamper_count": self._tamper["count"]}

    def events(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._events)[-max(1, limit):]

    def top_talkers(self, n: int = 15) -> list:
        with self._lock:
            rows = [{"ip": ip, "score": round(self._decayed_score(s), 1),
                     "reqs_window": len(s["window"]), "hits": s["hits"],
                     "banned": s["ban_until"] > _now()}
                    for ip, s in self._ips.items()]
        return sorted(rows, key=lambda r: (r["score"], r["reqs_window"]),
                      reverse=True)[:n]

    def metrics(self) -> dict:
        with self._lock:
            return {**self._metrics, "tracked_ips": len(self._ips),
                    "uptime": round(_now() - self._started, 1),   # 稼働時間(秒・ダッシュボード)
                    "active_bans": sum(1 for s in self._ips.values()
                                       if s["ban_until"] > _now()),
                    "global_rate_ewma": round(self._ewma, 2),
                    "dlp_kinds": dict(self._dlp_kinds),
                    "sig_hits": dict(self._sig_hits),
                    "zone_hits": dict(self._zone_hits),
                    "method_hits": dict(self._method_hits),
                    "resp_code_hits": dict(self._resp_code_hits),   # 応答ステータス帯(#60)
                    "tamper": dict(self._tamper),          # 改竄検知の可視化(#55)
                    "ban_bloom": self._ban_bloom.info()}

    def tamper_report(self) -> dict:
        """改竄検知の要約+直近の改竄イベント(ダッシュボード /api/shield/tamper 用・#55)。"""
        with self._lock:
            summary = {k: (dict(v) if isinstance(v, dict) else v)
                       for k, v in self._tamper.items()}
        evs = [e for e in self.events(200)
               if e.get("kind") in ("state_tamper", "memory_tamper")]
        return {"summary": summary, "events": evs[:50]}

    def status(self) -> dict:
        from ..core.i18n import t as _t
        return {"cfg": dict(self.cfg), "metrics": self.metrics(),
                "bans": self.bans(),
                "optional_signatures": sorted(_OPTIONAL_SIGS),  # 任意(高FP)シグネチャ名一覧
                "note": _t("status.note")}


# ── プロセス共有シングルトン ──
_SHIELD: NetShield = None
_SHIELD_LOCK = threading.Lock()


def net_shield() -> NetShield:
    global _SHIELD
    if _SHIELD is None:
        with _SHIELD_LOCK:
            if _SHIELD is None:
                _SHIELD = NetShield()
    return _SHIELD
