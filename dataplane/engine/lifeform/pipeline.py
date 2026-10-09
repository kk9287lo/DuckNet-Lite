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

import functools
import hashlib
import heapq
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import threading
import time
import unicodedata
from collections import deque

from ..core.atomic_io import (default_state_dir, atomic_write_json,
                              safe_read_json, tail_jsonl)
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
    ("xss", r"(?i)(<\s*script|onerror\s*=|javascript:|vbscript:|data:text/html|<\s*img[^>]{0,120}?onerror|document\.cookie)"),
    ("traversal", r"(?i)((?:\.\./){2,}|(?:\.\.\\){2,}|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|c:\\windows\\|\bwin\.ini\b|\bboot\.ini\b|\.\.;)"),
    ("rce", r"(?i)((?:;|\|\||&&)\s*(cat|wget|curl|bash|sh|nc|powershell)\b|\$\([^)]{0,200}\)|`[^`]{0,200}`|\|\s*(nc|bash|sh|curl|wget|python)\b|\(\)\s\{|<\?php\b|<\?=)"),
    ("scanner_ua", r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zgrab|nuclei|httpx)\b"),
    ("sensitive_path", r"(?i)(/\.env\b|/wp-login|/xmlrpc\.php|/phpmyadmin|/\.git/|/\.aws/|/actuator/|/\.ssh/)"),
    # ブラインド/時間/エラーベース SQLi: union/恒真式に出ない別系統(関数呼び・遅延・メタ表)。
    # information_schema はスキーマ修飾参照(information_schema.tables 等)必須=地の文の
    # 単発言及(「information_schemaを調べたい」等)を誤検知しない(実SQLiは常にドット修飾で使う)。
    ("sqli_blind", r"(?i)(\bsleep\s*\(|\bbenchmark\s*\(|\bpg_sleep\s*\(|\bwaitfor[\s;]+delay\b|\bextractvalue\s*\(|\bupdatexml\s*\(|\bload_file\s*\(|\binto[\s;]+(?:out|dump)file\b|\binformation_schema\.\w+|\b(?:and|or)\b[\s;]*[0-9]{1,6}\s*=\s*\(\s*select\b)"),
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
# 要求本文用の差し替え(#2)。head では ';' は注入された改行(正規化で ';' にする)かコマンド/文の区切り
# だが、本文の ';' は CSV の区切りや地の文の句読点でもある('Bought two bowls; cat loved them' が rce、
# 'Hi team; To: everyone' が crlf に当たっていた)。本文では ';' の後に文脈が揃う時だけ当てる:
#  rce : ';' の後のコマンドが引数を伴う(-フラグ / パス / $ / リダイレクト / URL / IPv4 / host.tld/…)。
#        '||' '&&' 連結と他の分岐は head と同じ。
#  crlf: ヘッダ名の後にそのヘッダの値の形が続く(set-cookie:名前= / location:URL / to:…@ 等)。
#        本文の走査面では改行は ';' にならない([[_normalize_full]] body=True)ので、ここに来る ';' は
#        字面どおり。値に符号化して入れた改行(%0D%0A 等)は crlf・rce・スタック複文の照合でだけ ';' と
#        して読む(nl=True の見え方・[[_BODY_NL_RULES]]。生の改行=YAML/テキスト/multipart の枠は空白のまま)。
# 判定は head 用より狭い(部分集合)=prescan のスーパーセット性は崩れない。URL/ヘッダの走査は従来どおり。
# 本文の crlf の『ヘッダ名+値の形』(先頭の ';' を除いた部分)。
_BODY_CRLF_SHAPE = (r"(?:set-cookie:\s?[^\s=;]{1,64}=|location:\s?(?:[a-z][a-z0-9+.-]{0,15}:)?/"
                    r"|refresh:\s?\d|content-type:\s?[a-z]{1,32}/[a-z0-9]|content-length:\s?\d"
                    r"|content-disposition:\s?(?:attachment|inline|form-data)\b"
                    r"|(?:bcc|cc|to):\s?[^\s;@]{1,64}@[a-z0-9]|mime-version:\s?\d"
                    r"|content-transfer-encoding:\s?(?:base64|quoted-printable|7bit|8bit|binary)\b)")
_BODY_SIG_PATTERNS = {
    "rce": r"(?i)(;\s*(?:cat|wget|curl|bash|sh|nc|powershell)\b"
           r"(?:\s?\$[a-z_{(]|\s?[<>]{1,2}\s?[/&~$.]|\s(?:--?[a-z0-9]|[/~\\][^\s;]|\.\.?/"
           r"|[a-z][a-z0-9+.-]{0,15}://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
           r"|[\w-]{1,63}\.[\w.-]{1,63}/))"
           r"|(?:\|\||&&)\s*(cat|wget|curl|bash|sh|nc|powershell)\b|\$\([^)]{0,200}\)|`[^`]{0,200}`"
           r"|\|\s*(nc|bash|sh|curl|wget|python)\b|\(\)\s\{|<\?php\b|<\?=)",
    "crlf": r"(?i);" + _BODY_CRLF_SHAPE,
}
_SIG_RE_BODY = [(name, re.compile(_BODY_SIG_PATTERNS[name]) if name in _BODY_SIG_PATTERNS else rgx)
                for name, rgx in _SIG_RE]
_BODY_CRLF_RE = dict(_SIG_RE_BODY)["crlf"]
# 高コストなシグネチャの前置ゲート(真陽性のスーパーセット): その名前の *どの分岐も*
# 必ず含むリテラルを列挙する。1 つも無ければ正規表現は原理的にマッチしないので評価を省く。
# 走査面は正規化済み(小文字化・比較演算子前後の空白除去)なので "1=1" 等の形で確実に現れる。
# これが無いと "select from " 連打(8KB)だけで sqli が 8.4ms/req、"<img " 連打で xss が
# 1.7ms/req を消費し、単一イベントループを数十 req/s で飽和させられた(CPU 枯渇DoS)。
_SIG_GUARD = {
    # union select / or 1=1 / '-- / select..from..where / drop table
    "sqli": ("union", "1=1", "--", "where", "drop"),
    # <script / onerror= / javascript: / vbscript: / data:text/html / <img..onerror /
    # document.cookie
    "xss": ("script", "onerror", "javascript:", "vbscript:", "data:text/html",
            "document.cookie"),
}
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
    # 付与する。バックエンドが検証し、トークン無し(=DuckNet を迂回した直叩き/再ルーティング)を
    # 拒否する。鍵は env DUCKNET_ORIGIN_KEY をエッジ・バックエンドで共有(VM 外保管を推奨)。opt-in。
    "origin_cloaking_enabled": False,  # 転送要求にオリジントークンを付与(バックエンドが検証)
    "origin_header": "X-Edge-Token",   # トークンを載せるヘッダ名(中立名・バックエンドと合わせる)
    "origin_window_sec": 30,           # トークンの時間バケット幅(リプレイ窓・時計ずれ吸収)
    # 迂回検知 / dead-man's switch(evolution #78): DuckNet 経由のトラフィックが *直近は活発だったのに
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
    # WAF が解けない Content-Encoding(br 等)のボディは検査不能=通さない。
    # False にすると圧縮バイトのまま走査して素通しする(=バイパス余地を残す)。
    "body_reject_unscannable_encoding": True,
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
    # 依らず絞る。トークンは生で保持せずハッシュ短縮。上限を超えた *その要求だけ* を遮断する。
    "cred_rate_enabled": False,    # API キー/トークン単位のレート制限(IP ローテーション濫用対策)
    "cred_rate_window_sec": 60,    # 集計窓
    "cred_rate_limit": 600,        # 窓内のリクエスト上限(この件数までは通し、超えた要求を遮断)
    # 超過した要求の送信元 IP への加点(0=加点しない・既定)。共有キー(アプリ埋込/公開キー)では
    # 攻撃者が窓を超えさせ続けると同じキーを使う正規利用者の IP に加点が乗る(BAN の第三者転嫁)ため、
    # キーが利用者ごとに固有の配備でのみ使う(#39: 旧版は文書だけあって未配線だった)。
    "cred_rate_score": 0,
    # スロー POST(R-U-Dead-Yet)対策(evolution #64): 要求ボディの *総受信時間* に上限を設ける。
    # head slowloris(head_timeout)は対処済みだが、ボディを小出しして接続を保持する攻撃に上限が
    # 無かった。client→backend 方向のみに効く(応答=backend→client の長時間ストリームは縛らない)。
    "body_timeout_enabled": True,  # 要求ボディの総受信時間に上限(slow-body 接続枯渇対策)
    "body_max_sec": 60,            # ボディ受信の総許容秒(超過=切断+slow_body 加点)。大容量UL は上げる
    # 応答方向 slow-read 兵糧攻め対策(#D2): 応答転送中に client 側 drain(受信)を待った *累積* 時間の
    # 上限秒。0=無効(既定=SSE/長時間ストリーム/低速回線の大容量DL を壊さない)。>0 にすると、
    # client がわざと小出しに受信して接続/backend ソケットを無期限保持する攻撃を切断できる。
    # 高速 client や無通信の idle SSE は drain 待ちがほぼ 0 なので誤切断しない(累積のみ加算)。
    "resp_stall_sec": 0.0,
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
    # ファイルアップロード検査(evolution #66): multipart(Content-Type: multipart/*)の *パートヘッダ*
    # Content-Disposition の filename= / filename*= から危険拡張子(webshell/実行体)を拒否する。
    # #61(本文シグネチャ)とは別関心=ファイル種別ポリシー(body_scan_enabled とは独立に効く)。
    # 最終拡張子と、ハンドラが中間セグメントにも効く既知の二重拡張子(shell.php.jpg)を見る。
    # 走査 prefix より後ろのパートヘッダも転送しながら検査する。block_score 超で BAN。
    "upload_scan_enabled": True,   # アップロードの危険拡張子拒否(webshell 投入対策)。multipart の
                                   # パートと、生本文アップロードの要求ヘッダ Content-Disposition
    # GraphQL クエリ防御(evolution #67): 深いネスト/複雑度/イントロスペクション/バッチを上限化。
    # 既定OFF(GraphQL を使う配備で有効化)。graphql_paths のエンドポイントにだけ適用(パスは
    # _path_for_match で正規化して照合)。POST(JSON/application/graphql/urlencoded/multipart の
    # operations)と GET ?query= の両方を見る。body_scan_enabled とは独立に効く。
    "graphql_enabled": False,      # GraphQL 固有のDoS/情報漏洩防御
    "graphql_paths": ["/graphql"], # GraphQL とみなすパス(前方一致)
    "graphql_max_depth": 12,       # 選択セットの最大ネスト深さ(超で遮断)
    "graphql_max_complexity": 1000,  # 選択(フィールド。エイリアス付きも 1 個ずつ)数の上限(増幅対策)
    "graphql_block_introspection": True,  # __schema/__type を遮断(__typename は対象外)
    "graphql_max_batch": 10,       # バッチ(配列)オペレーション数の上限
    "graphql_max_bytes": 262144,   # GraphQL 本文はここまで全体を読んで解析。超える本文は 413 で拒否
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
    "cadence_min_mean_interval": 0.01, # これ未満=バースト(µs〜ms)はビーコンでなく flood/レート制限の
                                       # 領分=対象外。高分解能クロックでの tight-loop 誤検知も防ぐ。
    # 高FPシグネチャの個別ON/OFF(既定OFF)。{name: True} で有効化。誤検知が許容な環境だけ点ける。
    "optional_sigs": {},
    # 検知の段階的厳格度(evolution #16): 1=保守(誤検知最小)〜4=最大(高FP許容)。set_paranoia が
    # レベルに応じて高FPの任意シグネチャを一括ON(個別 optional_sigs の上位ダイヤル)。既定1。
    "paranoia": 1,
    # 全角記号の畳み込み(rem_fwfold): 日本語の地の文で普通に使う全角の ｜ ＄ （ ） ； ｀([[_CJK_FW_PUNCT]])は
    # 既定では ASCII のメタ文字へ畳まない(決定・dec_headfold)。バックエンド自身が全角を ASCII へ変換する
    # 構成(入力へ NFKC を掛けるアプリ・Windows の best-fit 変換)では本物の | $ ( ) ; ` として読まれるので、
    # ON で本文も URL/ヘッダも前の版の NFKC と同じに畳む(日本語の題名等の誤検知も前の版と同じに戻る)。
    "fold_fullwidth_punct": False,
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
_CADENCE_SAMPLES = 24  # per-IP に保持する要求間隔の数(=cadence_min_samples の上限・#40)
# メソッド別テレメトリに個別キーで載せる既知メソッド(それ以外は OTHER に畳む=攻撃者が任意の
# 英字トークンで辞書を無制限に伸ばせないように・#14)。運用者の blocked_methods も個別に数える。
_KNOWN_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "TRACK", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH", "REPORT",
    "PURGE"})
_CFG_REV = 2           # 保存する cfg の版(1=版なし・cred_rate_score 未配線の時代・#39)
_USAGE_HOSTS_CAP = 60  # 1 IP あたり記録する宛先ホスト数の上限
_USAGE_HOSTS_LOW = 48  # 刈り取り後の目標水位(上限との差=ソートの償却間隔)
_EVENTS_MAX = 500
_APPEALS_MAX = 2000    # 解除リクエスト(異議申立)の保持上限(超過で解決済み優先→最古を退避=メモリ有界)
_PATH_LIMIT_MAX = 64   # パス別レート制限ルールの最大数(per-IP バケツ数の上限=メモリ有界)
_MAX_SUBNETS = 4096    # サブネット集約防御で追跡するサブネット数の上限(超過で古い順に間引き)
_SUBNET_IP_CAP = 256   # 1サブネットあたり記憶する distinct BAN済みIP数の上限(hot 判定に十分)
_SUBNET_IP_LOW = 192   # 間引き後の目標水位(上限との差=ソートの償却間隔)


def _subnet_key(ip: str):
    """IP を集約サブネットキーへ畳む(IPv4=/24・IPv6=/64)。不正/空は None。分散攻撃は同一
    サブネット内でIPをローテーションしがち=per-IP では取りこぼす構造を /24・/64 で束ねて捉える。"""
    try:
        ver = ipaddress.ip_address(ip).version
        return str(ipaddress.ip_network(f"{ip}/{24 if ver == 4 else 64}", strict=False))
    except Exception:
        return None


@functools.lru_cache(maxsize=4096)
def _canon_ip_str(s: str) -> str:
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return ""
    if a.version == 6:
        if a.scope_id:                    # ゾーンID付き(fe80::1%eth0)は正規形にしない(外すのは
            return ""                     # 呼び出し側の判断: peer は proxy、設定は _canon_cfg_ip)
        if a.ipv4_mapped:                 # ::ffff:192.0.2.1 は proxy 同様に純IPv4へ
            return str(a.ipv4_mapped)
    return str(a)


def _canon_ip(ip) -> str:
    """単一IPを照合用の正規形へ(前後空白除去・小文字/圧縮表記・IPv4-mapped は純IPv4)。
    単一IPでない(CIDR/ゾーンID付き/不正/非文字列)なら ""。peer IP は正規形で届くため、
    BAN の鍵や白/黒リストを生文字列で比べると '2001:DB8::1' 等の別表記が一致しなかった(#25/#45)。"""
    return _canon_ip_str(ip.strip()) if isinstance(ip, str) else ""


def _canon_cfg_ip(ip) -> str:
    """設定・保存済み BAN・手動操作の単一IPを peer と同じ形へ(_canon_ip+IPv6 のゾーンID除去)。
    proxy は peer/XFF のゾーンID(fe80::1%eth0 の %eth0)を外して渡す(_norm_ip)ので、設定側を
    ゾーン付きのまま比べると一致しない: 旧版で書いた白リストの項目が締め出し・黒リスト/BAN は
    素通りになっていた。ゾーンは任意文字を運べるので値には残さない。IPv4 にゾーンは無い(不正のまま)。"""
    c = _canon_ip(ip)
    if not c and isinstance(ip, str) and "%" in ip:
        head = ip.strip().split("%", 1)[0]
        if ":" in head:
            c = _canon_ip(head)
    return c


@functools.lru_cache(maxsize=16)
def _compile_ip_list(entries: tuple):
    """IP 白/黒リスト -> (正規形の単一IP集合, CIDR ネット列)。設定は滅多に変わらないので
    タプルをキーにキャッシュし、リクエストごとの全件パースを避ける。"""
    singles, nets = set(), []
    for e in entries:
        e = str(e).strip()
        if "/" in e:
            net = _cidr_net(e)
            if net is not None:
                nets.append(net)
        else:
            c = _canon_cfg_ip(e)              # ゾーンID付き(fe80::1%eth0)も peer と同じ形で
            if c:
                singles.add(c)
    return frozenset(singles), tuple(nets)
_CRED_RATE_CAP = 50000   # クレデンシャル単位レート集計マップの上限(#70・メモリ有界)
_CRED_IDS_MAX = 4        # 1 要求で計上するクレデンシャル識別子の上限(proxy は Bearer/X-API-Key の 2 つ)


def _cred_ids(cred) -> tuple:
    """inspect(cred=...) を計上対象の識別子タプルへ。単一 str(従来の呼び出し)か str の列を受け、
    空・非文字列・重複(Bearer と X-API-Key に同じ値)を除く。重複を除かないと 1 要求で 2 回数える。"""
    if isinstance(cred, str):
        return (cred,) if cred else ()
    if not isinstance(cred, (list, tuple, set, frozenset)):
        return ()
    return tuple(dict.fromkeys(c for c in cred if isinstance(c, str) and c))[:_CRED_IDS_MAX]
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
_PRE_CUT = _MAX_SCAN * 2    # 正規化前の粗い上限(=正規化後の全体上限でもある)
_SCAN_WIN_OVERLAP = 256     # 走査窓の重なり(窓境界を跨ぐ payload の分断を防ぐ)
_MAX_SCAN_WINDOWS = 12      # 1 フィールドあたりの走査窓上限(走査 CPU 面積を有界化)
_MIN_PARTS_PER_CHUNK = 2    # 生チャンク 1 つに必ず配る窓数(予算独占で未走査を作らない)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)   # POSIX: 最終要素が symlink なら open 失敗。Win は無し。


def _open_state_write(path: str, mode: str):
    """state_dir 直下の *固定パス* へ symlink を経由せず追記/切詰で開く(#symlink-arbitrary-write)。
    mode='a'(追記)/'w'(切詰)。共有 state_dir で攻撃者が usage_log.jsonl や .state_signed を
    任意ファイルへの symlink に仕込み、追記でログ注入/ディスク枯渇、切詰で任意ファイル truncate を
    起こす攻撃を封じる。予め symlink を除去(追従しない)し、POSIX では O_NOFOLLOW でも最終要素の
    追従を拒否する(0600 が効かない Windows は islink 判定で補う)。テキスト file を返す。"""
    try:
        if os.path.islink(path):
            os.unlink(path)                    # 仕込まれた symlink を除去(追従せず新規通常ファイルを作る)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW
    flags |= os.O_APPEND if mode == "a" else os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    # backslashreplace: 厳格な UTF-8 だと host/path の孤立サロゲート('\udc80' 等)1 文字で
    # UnicodeEncodeError になり、その行(=その接続の記録)が黙って捨てられていた。書くのは
    # json.dumps の行なので \udXXX 表記は JSON の正しいエスケープ=読み戻すと同じ値(atomic_io と同じ)。
    return os.fdopen(fd, mode, encoding="utf-8", errors="backslashreplace")
_MAX_SCAN_FIELDS = 96       # 独立走査するフィールド数の上限(path?query+UA + Host + 各ヘッダ値
                            # (最大64個別+結合末尾)・CPU有界)。_scan_header_values の 64+1 と
                            # Host/primary を全て走査面に収めるため 64→96(head は 16KB 上限ゆえ
                            # フィールド数は元々有界=CPU影響は軽微)。


def _now() -> float:
    return time.time()


def _jwt_alg(token: str):
    """Bearer JWT の header(1番目のセグメント)から alg を取り出す(#68)。署名検証はしない
    =鍵不要。3セグメントの JWT でなければ None。base64url/JSON が壊れていても None(落ちない)。
    header に alg メンバーが無いものも None(=JWT でない)。JWS header は alg 必須(RFC 7515)で、
    1 段目が base64url(JSON) の 3 段トークンは JWT 以外にもある(itsdangerous の
    payload.timestamp.signature 等)。旧実装は欠落を "" にして alg=none 扱い=即時BANしていた。"""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0]:
        return None
    try:
        import base64
        seg = parts[0]
        seg += "=" * (-len(seg) % 4)              # base64url パディング補完
        hdr = json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
        if not isinstance(hdr, dict) or "alg" not in hdr:
            return None
        return str(hdr["alg"])
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


# ── アップロード検査(#66)の multipart 解析 ──
# 旧実装は本文のどこにある 'filename=' も拾い(フォーム値/テキスト本文で誤遮断+BAN・#10)、
# filename* を復号せず(#11)、本文先頭しか見なかった(#33)。今は multipart の *パートヘッダ* の
# Content-Disposition だけを、解析器ごとの読み方の違いの和集合で読む。
# Content-Disposition の値の中で filename= を拾う素朴な読み方(区切り抜け等にも寛容な網)。
# 'filename' の直前が名前の一部でないこと(xfilename= を拾わない)。
_CD_FILENAME_RE = re.compile(
    r'(?<![\w*-])filename(\*?)[ \t]*=[ \t]*(?:"([^"\r\n]*)"|([^;\s"]+))', re.I)
_CD_CONT_RE = re.compile(r"filename\*(\d{1,3})(\*?)")    # RFC 2231 継続 filename*0= / *1*=
_HDR_NAME_RE = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:")
_UPLOAD_HDR_MAX = 65536      # 1 パートのヘッダ塊の上限。超過=壊れた/回避狙い→フェイルクローズ
_UPLOAD_HDR_LINES = 100      # 1 パートのヘッダ行数の上限(実在のパートは折り返し込みでも十数行)。超過=同上
_UPLOAD_PARTS_MAX = 10000    # 1 本文で検査するパート数の上限。超過=フェイルクローズ
# 中間セグメントでも実行され得る拡張子。Apache mod_mime の AddHandler/AddType はファイル名の
# *どの* ドット区切りにも効く(shell.php.jpg が PHP として動く)。最終拡張子は拒否リスト全体で
# 見るが、中間はこれ(と拒否リストの積)だけ=www.example.com.har の com を拾わない(#9)。
# pl は言語タグ付きの名前(messages.pl.yml=ポーランド語の翻訳ファイル)と衝突するので中間では見ない
# (最終拡張子 .pl は従来どおり拒否)。
_UPLOAD_MULTI_EXT = frozenset((
    "php", "php3", "php4", "php5", "php7", "php8", "phps", "pht", "phtml", "phar",
    "cgi", "py", "asp", "aspx", "jsp", "jspx", "jspf", "shtml"))


def _mp_params(value: str, escapes: bool = True) -> list:
    """Content-Type / Content-Disposition 値のパラメータを [(小文字名, 値)] で返す(先頭の型は飛ばす)。
    escapes=True は quoted-string の \\ エスケープを解く(RFC 7230)。False は最初の '"' で閉じる
    素朴な読み方(エスケープを解かない実装の見え方)。区切りは ';' か空白(区切り抜けにも寛容)。"""
    n = len(value)
    j = value.find(";")
    head = value if j < 0 else value[:j]
    i = 0 if "=" in head else (n if j < 0 else j + 1)
    out = []
    while i < n:
        while i < n and value[i] in "; \t\r\n":
            i += 1
        k = i
        while i < n and value[i] not in "=; \t\r\n":
            i += 1
        name = value[k:i].lower()
        while i < n and value[i] in " \t":
            i += 1
        if i >= n or value[i] != "=":
            continue                              # 値の無い属性(型名など)
        i += 1
        while i < n and value[i] in " \t":
            i += 1
        if i < n and value[i] == '"':
            i += 1
            buf = []
            while i < n:
                ch = value[i]
                if ch == "\\" and escapes and i + 1 < n:
                    buf.append(value[i + 1])
                    i += 2
                    continue
                i += 1
                if ch == '"':
                    break
                buf.append(ch)
            v = "".join(buf)
        else:
            k = i
            while i < n and value[i] != ";":
                i += 1
            v = value[k:i].strip()
        if name:
            out.append((name, v))
    return out


def _rfc5987(v: str, charset: bool = True) -> str:
    """RFC 5987/8187 の ext-value(charset'lang'%XX…)を復号する(#11)。拡張子判定には ASCII が
    残れば足りるので常に UTF-8(不正は置換)で読む。charset=False は継続の 2 個目以降(%XX のみ)。"""
    from urllib.parse import unquote_to_bytes
    v = v.strip().strip('"')
    if charset and v.count("'") >= 2:
        v = v.split("'", 2)[2]
    return unquote_to_bytes(v).decode("utf-8", "replace")


def _cd_filenames(value: str) -> list:
    """Content-Disposition 値からファイル名の候補を全部集める。エスケープを解く/解かない読み方、
    filename*(RFC 5987)、RFC 2231 継続(filename*0= …)、素朴な正規表現の和集合=どの解析器が採る
    名前も取りこぼさない(誤検知はパートヘッダの中に限られる)。"""
    names, cont = [], {}
    for esc in (True, False):
        for k, v in _mp_params(value, esc):
            if k == "filename":
                names.append(v)
            elif k == "filename*":
                names.append(_rfc5987(v))
            elif esc:
                m = _CD_CONT_RE.fullmatch(k)
                if m:
                    cont[int(m.group(1))] = (v, bool(m.group(2)))
    if cont:                                      # 継続は番号順に連結(*N* は %XX 復号・先頭だけ charset 付き)
        parts = []
        for idx in sorted(cont):
            v, enc = cont[idx]
            parts.append(_rfc5987(v, idx == 0) if enc else v)
        names.append("".join(parts))
    for m in _CD_FILENAME_RE.finditer(value):
        v = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        names.append(_rfc5987(v) if m.group(1) else v)
    return [x for x in names if x]


def _upload_bad_ext(fn: str, deny) -> str:
    """ファイル名が拒否拡張子なら該当拡張子、でなければ ""。最終拡張子は deny 全体、中間セグメントは
    _UPLOAD_MULTI_EXT に入るものだけ(二重拡張子 shell.php.jpg・#9)。パス(/ と \\)は basename に、
    Windows が捨てる末尾の '.'/空白は落とし、NUL で切った形(C 文字列として保存する実装)と
    切らない形の両方を見る。"""
    base = fn.replace("\\", "/").rsplit("/", 1)[-1]
    for cand in (base.split("\x00", 1)[0], base):
        segs = cand.rstrip(" .").lower().split(".")
        if len(segs) < 2:
            continue
        last = segs[-1].strip()
        if last in deny:
            return last
        for s in segs[1:-1]:
            s = s.strip()
            if s in deny and s in _UPLOAD_MULTI_EXT:
                return s
    return ""


def _part_header_hit(block: bytes, deny):
    """パートヘッダ塊(LF 区切りの行)の Content-Disposition から危険なファイル名を探す。
    折り返し行・ヘッダ名で始まらない行は前の行の続きとして読む(裸 LF を改行と見ない実装の見え方)。
    続き行は断片の並びに貯めて最後に 1 回だけ連結する(+ で伸ばすと続き行の数の 2 乗・#4)。"""
    lines = []
    for ln in block.split(b"\n"):
        ln = ln.rstrip(b"\r")
        if not ln:
            continue
        if lines and (ln[:1] in (b" ", b"\t") or not _HDR_NAME_RE.match(ln)):
            lines[-1].append(ln.strip())
        else:
            lines.append([ln])
    for frags in lines:
        name, _, val = b" ".join(frags).partition(b":")
        if name.strip().lower() != b"content-disposition":
            continue
        for fn in _cd_filenames(val.decode("latin1", "replace")):
            ext = _upload_bad_ext(fn, deny)
            if ext:
                return fn[:120], ext
    return None


class _MultipartHeads:
    """multipart 本文から *パートヘッダ塊* を逐次に切り出す(#10/#33)。本文そのものは保持しない
    (区切り検出用の末尾とヘッダ塊だけを有界に持つ=転送しながら全パートを検査できる)。
    区切り行は行頭(直前が LF)の '--' + boundary。行は LF 区切り(CR は剥ぐ)=CRLF と LF だけの
    送信者の両方に効く。終端区切り(--boundary--)の後ろも見続ける(寛容な解析器が拾う形も逃さない)。
    検査量は 1 パートのヘッダ塊の長さに線形(#4): 塊全体は終わりで 1 回だけ返し、行が揃った時点の
    早期検査はその行を含む論理行だけを返す。旧実装は行が揃うたびに塊全体を返して読み直させ(行数の
    2 乗)、害の無い行を 1500 回繰り返した小さな要求 1 本でイベントループが数秒止まった。"""
    __slots__ = ("_pat", "_buf", "_hdr", "_st", "_lines", "_lstart", "_early", "parts", "bad")

    def __init__(self, boundary: bytes):
        self._pat = b"--" + bytes(boundary)
        self._buf = bytearray(b"\n")              # 本文先頭も行頭として扱う
        self._hdr = bytearray()
        self._st = 0                              # 0=区切り探し 1=区切り行の残り 2=ヘッダ行
        self._lines = 0                           # この塊のヘッダ行数(_UPLOAD_HDR_LINES まで)
        self._lstart = 0                          # この塊の最後の論理行(折り返しの親行)の開始位置
        self._early = 0                           # この塊で早期検査に返した量(バイト)
        self.parts = 0
        self.bad = ""

    def feed(self, data) -> list:
        """data を食わせ、検査すべきヘッダ塊(bytes)の列を返す(完結した塊と、Content-Disposition
        行が揃った時点のその論理行)。"""
        out = []
        buf, pat = self._buf, self._pat
        buf += data
        while not self.bad:
            if self._st == 0:
                i = buf.find(pat)
                while i == 0 or (i > 0 and buf[i - 1] != 0x0A):
                    i = buf.find(pat, i + 1)
                if i < 0:
                    keep = len(pat) + 1               # 区切りの途中かもしれない末尾(+直前の LF)
                    if len(buf) > keep:
                        del buf[:len(buf) - keep]
                    break
                del buf[:i + len(pat)]
                self._hdr.clear()
                self._lines = self._lstart = self._early = 0
                self._st = 1
            elif self._st == 1:
                j = buf.find(b"\n")
                if j < 0:
                    if len(buf) > _UPLOAD_HDR_MAX:
                        self.bad = "multipart の区切り行が過大"
                    break
                del buf[:j + 1]
                self.parts += 1
                if self.parts > _UPLOAD_PARTS_MAX:
                    self.bad = "multipart のパート数が上限超過"
                    break
                self._st = 2
            else:
                j = buf.find(b"\n")
                if j < 0:
                    if len(self._hdr) + len(buf) > _UPLOAD_HDR_MAX:
                        self.bad = "multipart のパートヘッダが過大"
                    break
                line = bytes(buf[:j]).rstrip(b"\r")
                if line:
                    del buf[:j + 1]
                    self._lines += 1
                    if self._lines > _UPLOAD_HDR_LINES:
                        self.bad = "multipart のパートヘッダの行数が上限超過"
                        break
                    if not self._hdr or not (line[:1] in (b" ", b"\t")
                                             or not _HDR_NAME_RE.match(line)):
                        self._lstart = len(self._hdr)     # 新しい論理行(_part_header_hit と同じ読み方)
                    self._hdr += line + b"\n"
                    if len(self._hdr) > _UPLOAD_HDR_MAX:
                        self.bad = "multipart のパートヘッダが過大"
                    elif line.lstrip()[:19].lower() == b"content-disposition":
                        # 行が揃った時点でも見る(ヘッダ塊の終わりを待つと、塊の途中までを含む
                        # チャンクが先に転送される)。見るのはこの行を含む論理行だけ。塊の終わりで
                        # 続き行込みの塊全体をもう一度見る。'content-disposition' で始まる折り返し行が
                        # 続いて論理行が伸び続ける形は、早期検査の量が塊の 2 倍に達したら終わりの
                        # 1 回に任せる(伸びるたびに読み直すと 2 乗)。
                        n = len(self._hdr) - self._lstart
                        if self._early + n <= 2 * len(self._hdr):
                            self._early += n
                            out.append(bytes(self._hdr[self._lstart:]))
                else:
                    del buf[:j]                   # 空行の LF は残す(中身が空なら次の区切りの行頭)
                    out.append(bytes(self._hdr))
                    self._st = 0
        return out


class _ChunkDecode:
    """Transfer-Encoding: chunked の枠を逐次に解いて中身だけを返す(転送中のアップロード検査用)。
    枠の厳密な検証は proxy(_ChunkedEnd)が担う=壊れた枠はそこで転送が止まる。ここは寛容に読む。"""
    __slots__ = ("_st", "_line", "_left", "done")

    def __init__(self):
        self._st = 0                              # 0=サイズ行 1=中身 2=中身直後の CRLF
        self._line = bytearray()
        self._left = 0
        self.done = False

    def feed(self, data) -> bytes:
        out = bytearray()
        i, n = 0, len(data)
        while i < n and not self.done:
            if self._st == 1:
                take = min(self._left, n - i)
                out += data[i:i + take]
                i += take
                self._left -= take
                if self._left == 0:
                    self._st = 2
                continue
            j = data.find(b"\n", i)
            if j < 0:
                self._line += data[i:]
                if len(self._line) > 4096:
                    self.done = True
                break
            self._line += data[i:j]
            i = j + 1
            ln = bytes(self._line).strip()
            self._line.clear()
            if self._st == 2:
                self._st = 0
                continue
            try:
                size = int(ln.split(b";", 1)[0].strip(), 16)
            except ValueError:
                self.done = True
                break
            if size <= 0:
                self.done = True
            else:
                self._left, self._st = size, 1
        return bytes(out)


class _UploadScan:
    """アップロード検査の逐次版(#33): 本文を転送しながら *全* パートのヘッダを検査する。
    feed(生の本文バイト) は危険なパートを見つけたら (filename, ext) を返す(以後も同じ値)。
    壊れた/過大な multipart は (理由, "")=検査できないのでフェイルクローズ。chunked=True は
    転送符号化の枠を解いてから見る(枠でパートヘッダを分断する回避を封じる)。"""
    __slots__ = ("_heads", "_deny", "_dechunk", "hit")

    def __init__(self, boundaries, deny, chunked: bool = False):
        self._heads = [_MultipartHeads(b) for b in boundaries]
        self._deny = deny
        self._dechunk = _ChunkDecode() if chunked else None
        self.hit = None

    def feed(self, data):
        if self.hit is not None or not data:
            return self.hit
        if self._dechunk is not None:
            data = self._dechunk.feed(bytes(data))
        for h in self._heads:
            for block in h.feed(data):
                r = _part_header_hit(block, self._deny)
                if r:
                    self.hit = r
                    return r
            if h.bad:
                self.hit = (h.bad, "")
                return self.hit
        return None


def _mp_boundaries(content_type: str, sample: bytes = b"") -> list:
    """multipart の境界(bytes)の候補。Content-Type の boundary 引数(重複/読み方違いは全部・最大 4)。
    Content-Type が無いときだけ本文先頭行(--boundary)から推定する。multipart 以外の
    Content-Type は空(=アップロード検査の対象外・#10)。"""
    ct = (content_type or "").strip()
    out = []
    if ct:
        if not ct.lower().startswith("multipart/"):
            return []
        for esc in (True, False):
            for k, v in _mp_params(ct, esc):
                b = v.strip().encode("latin1", "replace")[:200]
                if k == "boundary" and b and b not in out:
                    out.append(b)
    if not out and sample:
        first = bytes(sample[:512]).split(b"\n", 1)[0].rstrip(b"\r \t")
        if first.startswith(b"--") and len(first) > 2:
            out.append(first[2:202])
    return out[:4]


def _multipart_field(body: bytes, boundaries, field: str):
    """multipart 本文から name=field のパートの中身(bytes)を返す。無ければ None、本文内で完結
    しない(ヘッダや次の区切りが無い)なら False。GraphQL multipart の operations 欄用(#5)。"""
    res = None
    for bnd in boundaries:
        pat = b"--" + bytes(bnd)
        i = 0
        while True:
            i = body.find(pat, i)
            if i < 0:
                break
            if i > 0 and body[i - 1] != 0x0A:
                i += 1
                continue
            if body[i + len(pat):i + len(pat) + 2] == b"--":
                break                             # 終端区切り=以降にパートは無い
            j = body.find(b"\n", i)
            if j < 0:
                res = False                       # 区切り行が途中で切れている
                break
            pos = j + 1
            while True:                           # ヘッダ行を空行まで
                e = body.find(b"\n", pos)
                if e < 0:
                    return False
                if not body[pos:e].rstrip(b"\r"):
                    break
                pos = e + 1
            name = ""
            for ln in body[j + 1:pos].split(b"\n"):
                nm, _, val = ln.rstrip(b"\r").partition(b":")
                if nm.strip().lower() == b"content-disposition":
                    name = dict(_mp_params(val.decode("latin1", "replace"))).get("name", name)
            start = e + 1
            if name == field:
                k = start - 1                     # 中身が空なら空行の LF の直後が区切り
                while True:
                    k = body.find(pat, k + 1)
                    if k < 0:
                        return False
                    if body[k - 1] == 0x0A:
                        break
                end = k - 1
                if end > start and body[end - 1] == 0x0D:
                    end -= 1
                return body[start:max(start, end)]
            i = start
    return res


def _dangerous_upload_filename(body: bytes, deny_exts, cap: int = 65536, content_type: str = ""):
    """multipart 本文(先頭 cap)の *パートヘッダ* の Content-Disposition(filename= / filename*= /
    RFC 2231 継続)から危険拡張子を探す(#66)。返り値 (filename, ext) or None。壊れた/過大な
    multipart は (理由, "")。最終拡張子と、中間セグメントでも実行され得る二重拡張子
    (shell.php.jpg)を見る。NUL 切り(shell.php\\x00.jpg)・パス付きも考慮。deny_exts は小文字・
    ドット無しの集合。content_type が multipart 以外/本文が multipart でない場合は None。"""
    deny = {str(e).lower().lstrip(".") for e in (deny_exts or [])}
    if not deny:
        return None
    data = bytes(body[:cap])
    bnds = _mp_boundaries(content_type, data)
    if not bnds:
        return None
    return _UploadScan(bnds, deny).feed(data)


def _disposition_upload_filename(values, deny_exts):
    """要求ヘッダの Content-Disposition(生本文アップロード・T2)のファイル名から危険拡張子を探す。
    WordPress REST の /wp/v2/media 等は本文がファイルそのもので、保存名はこのヘッダの filename /
    filename*(RFC 5987)で渡る。読み方(_cd_filenames)も拡張子規則(_upload_bad_ext)も multipart の
    パートヘッダと同じ。values は値 1 本(str)か出現ごとの並び。返り値 (filename, ext) or None。"""
    deny = {str(e).lower().lstrip(".") for e in (deny_exts or [])}
    if not deny or not values:
        return None
    for v in ((values,) if isinstance(values, str) else values):
        for fn in _cd_filenames(str(v)):
            ext = _upload_bad_ext(fn, deny)
            if ext:
                return fn[:120], ext
    return None


def _graphql_path(path: str, paths) -> bool:
    """path が graphql_paths のどれかに当たるか(前方一致)。両側を _path_for_match で正規化して
    比べる(/GraphQL・/graphq%6C も backend は同じハンドラへ回す・#6)。"""
    p = _path_for_match(path)
    for gp in (paths or ["/graphql"]):
        g = _path_for_match(str(gp))
        g0 = g.rstrip("/")
        if p == g or p == g0 or p.startswith(g0 + "/"):
            return True
    return False


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


@functools.lru_cache(maxsize=64)
def _lower_tuple(items: tuple) -> tuple:
    """設定由来の文字列列を小文字タプル化して使い回す(リクエストごとの再変換を避ける)。
    設定は滅多に変わらないので、タプルをキーにしたキャッシュで十分に効く。"""
    return tuple(str(x).lower() for x in items)


@functools.lru_cache(maxsize=4096)
def _cidr_net(cidr: str):
    """CIDR 文字列 -> ip_network(不正なら None)。ip_network() の構築は高価で、白/黒リストは
    *リクエストごと* に全件照合されるため、結果をキャッシュしないとエントリ数 x リクエスト数
    ぶんのパースが積み上がる(実測 1000 件で 1.6ms/リクエスト)。"""
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return None


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
    """走査前に適用する独自デコーダを登録(可逆=clear_scan_decoder で解除)。fn(str)->str|bytes。
    fn は 1 フィールドの *全体*(先頭 _PRE_CUT 文字)を 1 回受け取る。出力も _PRE_CUT で打ち切り、
    その全域を窓分割して走査する([[_scan_windows]])。"""
    _SCAN_DECODERS[str(name)] = fn
    return {"installed": str(name), "active": True, "total": len(_SCAN_DECODERS)}


def clear_scan_decoder(name: str) -> dict:
    return {"cleared": str(name), "was_active": _SCAN_DECODERS.pop(str(name), None) is not None}


def registered_scan_decoders() -> list:
    return sorted(_SCAN_DECODERS)


def _apply_scan_decoders(s: str) -> str:
    """登録された独自デコーダを順に適用する(出力は _PRE_CUT で打ち切り=暴走デコーダで肥大させない)。
    壊れたデコーダ(例外/非文字列)は飛ばす=防御を止めない(素通りより安全側)。"""
    for _name, _fn in list(_SCAN_DECODERS.items()):
        try:
            out = _fn(s)
            if isinstance(out, (bytes, bytearray)):
                out = bytes(out).decode("utf-8", "replace")
            if isinstance(out, str) and out:
                s = out[:_PRE_CUT]
        except Exception:
            pass
    return s


_NFKC_MAX_EXPAND = 4        # 1 文字あたりの NFKC 展開許容倍率(超える文字は展開しない)


@functools.lru_cache(maxsize=8192)
def _nfkc_char(c: str) -> str:
    """1 文字の NFKC。展開が _NFKC_MAX_EXPAND を超える文字は畳まずそのまま返す。
    走査面の長さを入力の定数倍に抑えるための安全弁([[_normalize_full]] の異常時経路)。"""
    n = unicodedata.normalize("NFKC", c)
    return n if len(n) <= _NFKC_MAX_EXPAND else c


# \t\n\v\f\r(空白類)以外の C0 制御文字。[[_normalize_full]] が ASCII/非 ASCII の別なく除去する。
_CTRL_RE = re.compile(r"[\x00-\x08\x0e-\x1f]")
_SS_RUN = 10    # 非 starter 始まりの文字をこの数ごとに区切る(1 文字は NFKD で非 starter 最大 2 個)


def _char_class(pred, spans) -> str:
    """spans の範囲で pred を満たす code point を、正規表現の文字クラス本体(連続区間に畳む)にする。"""
    ranges = []
    for lo, hi in spans:
        for cp in range(lo, hi):
            if not pred(chr(cp)):
                continue
            if ranges and ranges[-1][1] == cp - 1:
                ranges[-1][1] = cp
            else:
                ranges.append([cp, cp])
    return "".join("\\U%08x" % a if a == b else "\\U%08x-\\U%08x" % (a, b) for a, b in ranges)


@functools.lru_cache(maxsize=1)
def _nonstarter_run_re():
    """NFKD の先頭が非 starter(結合クラス≠0)になる文字が _SS_RUN を超えて続く箇所の正規表現。
    結合クラス≠0 の文字は BMP/SMP にしか無いので、そこだけを初回に 1 度数え上げて作る(十数 ms)。"""
    cls = _char_class(lambda c: bool(unicodedata.combining(c) or (
        unicodedata.decomposition(c)
        and unicodedata.combining(unicodedata.normalize("NFKD", c)[0]))),
        ((0, 0xD800), (0xE000, 0x20000)))
    return re.compile("[%s]{%d,}" % (cls, _SS_RUN + 1))


@functools.lru_cache(maxsize=1)
def _cf_re():
    """書式文字(Cf=ゼロ幅/ソフトハイフン/方向制御/BOM/タグ文字 等)の正規表現。1 文字ずつ
    unicodedata.category を引く Python ループ(32K 文字で数 ms)の代わり。Cf は BMP/SMP と
    第 14 面(タグ文字)にしか無いので、そこだけを初回に 1 度数え上げて作る。"""
    cls = _char_class(lambda c: unicodedata.category(c) == "Cf",
                      ((0, 0x20000), (0xE0000, 0xE1000)))
    return re.compile("[%s]+" % cls)


_CGJ = chr(0x034F)     # U+034F COMBINING GRAPHEME JOINER(不可視・結合クラス 0=並べ替えの壁)
_I_DOT = chr(0x0130)   # U+0130(lower() で 2 文字に伸びる唯一の文字)


def _ss_split(m) -> str:
    run = m.group(0)
    return _CGJ.join(run[i:i + _SS_RUN] for i in range(0, len(run), _SS_RUN))


def _stream_safe(s: str) -> str:
    """UAX #15 の Stream-Safe Text Format 相当: 非 starter の長い連続へ U+034F(CGJ・結合クラス 0)を
    挟む。CPython の NFKC は連続の中を挿入ソートで並べ替えるため、結合クラスが交互に変わる結合文字を
    長く続けると入力長の 2 乗の時間が掛かった(16K で約 40ms・#64)。区切れば 1 区間の並べ替えは
    定数長=線形。区切るのは _SS_RUN を超えて続く所だけ=通常の文章(アクセント・濁点等)は変わらない。"""
    return _nonstarter_run_re().sub(_ss_split, s)


def _strip_sql_comments(s: str) -> str:
    """SQL インラインコメントを *線形時間* で除去する(旧: 有界 lazy 正規表現)。
    2パス構成は旧実装と完全一致: (1) MySQL 版付き /*! [digits] 中身 */ は囲みだけ剥がして
    中身を残す(DB が実行するため)。(2) 一般 /* ... */ は中身ごと除去。いずれも最寄りの */
    までを str.find で取る=バックトラック無し。旧 `.{0,8192}?` の上限を撤廃したので、8192 超の
    巨大コメントも確実に除去できる(旧は上限超過で未除去=実証済バイパスだった)。未終端 /* は
    従来どおり literal 保持。バックトラック皆無ゆえ /* 連打による CPU 枯渇DoSを起こさない。"""
    if "/*" not in s:
        return s
    # パス1: 版付きコメント /*! ... */(中身を残す)
    out = []
    i, n = 0, len(s)
    while i < n:
        j = s.find("/*!", i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        end = s.find("*/", j + 3)
        if end < 0:
            out.append(s[j:])
            break
        k, d = j + 3, 0
        while k < end and d < 6 and s[k].isdigit():   # 旧 \d{1,6} 相当(先頭最大6桁を消費)
            k += 1
            d += 1
        out.append(" " + s[k:end] + " ")
        i = end + 2
    s = "".join(out)
    if "/*" not in s:
        return s
    # パス2: 一般コメント /* ... */(中身ごと除去)
    out = []
    i, n = 0, len(s)
    while i < n:
        j = s.find("/*", i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        end = s.find("*/", j + 2)
        if end < 0:
            out.append(s[j:])
            break
        out.append(" ")
        i = end + 2
    return "".join(out)


def _normalize_full(s: str, *, body: bool = False, decode: bool = True,
                    cap: int = _PRE_CUT, nl: bool = False, nl_views: list | None = None,
                    fold_fw: bool = False, json_esc: bool = False) -> str:
    """シグネチャ走査前の正規化。難読化(多重エンコード/インラインコメント/空白増し/Unicode)を
    減らし、入力長を有界化して ReDoS と CPU 枯渇を抑える。完全な無害化ではない。
    返値は 1 窓(_MAX_SCAN)へ *切り詰めない*(全域を [[_scan_windows]] が窓分割する)。
    入力は _PRE_CUT、返値の長さは cap(既定 _PRE_CUT)で有界=NFKC 展開等でも走査面積は爆発しない。
    body=True は要求本文用: 改行(生でも %0D%0A 由来でも)を ';' にせず空白として畳む。本文の改行は
    地の文/YAML/CSV/multipart の枠の区切りで、文/コマンドの区切りとみなすと誤検知になる(#0/#2)。
    CJK の地の文で普通に使う全角の ｜ ＄ （ ） ； ｀ は、本文でも head でも ASCII のメタ文字へ畳まず空白に
    する([[_CJK_FW_PUNCT]]・#3・dec_headfold)。全角英字・＜＞ 等の畳み込みは本文も head も同じ。
    fold_fw=True(運用者の設定 fold_fullwidth_punct)はその表の文字も前の版と同じく NFKC で畳む(本文も head も)。
    nl=True(body=True と併用)は本文の crlf・rce・複文照合用の見え方([[_BODY_NL_RULES]]): 生の改行
    (文書の枠)は空白のまま、復号で現れた改行(%0D%0A・&#10;・\\u000a 等で *値に* 入った改行)だけを
    head と同じく ';' にする。nl_views(body=True・nl=False の時)には、復号で現れた改行の後に照合対象の
    語が続く時だけ([[_BODY_NL_LEAD]])、nl=True と同じ結果の見え方を同じ復号結果から作って積む(復号を
    2 回しない・[[NetShield._scan_field]])。
    json_esc=True(JSON 本文・[[_json_body]])は、その見え方でだけ JSON の短いエスケープ(\\n \\r \\t 等)も
    復号する=JSON.stringify が書く \\r\\n も %0D%0A・\\u000a と同じ値の改行([[_json_unescape_short]])。
    本文の走査面(他の検知が見る返値)は変えない。
    decode=False は登録デコーダを掛けない([[_scan_windows]] がフィールド全体へ 1 回掛けた後)。"""
    if not s:
        return ""
    s = s[:_PRE_CUT]
    if decode and _SCAN_DECODERS:             # 登録された独自デコーダを走査面で先に適用(可逆)
        s = _apply_scan_decoders(s)
    if body and ("\r" in s or "\n" in s):
        # 本文の生の改行=枠。復号前に空白へ(後段に残る改行は復号で値に現れたものだけ=区別できる)。
        # nl=False の走査面は改行も空白も最後に 1 個の空白へ畳むので、先に空白にしても結果は同じ。
        s = s.replace("\r", " ").replace("\n", " ")
    lim = len(s) * _NFKC_MAX_EXPAND           # NFKC 展開の上限: 周回をまたいで *元の長さ* の 4 倍
    # 復号の外側 fixpoint(有界3周): entity/NFKC 復号が *後段で* 新たに生む %エスケープを
    # URL 復号し損ねる死角を塞ぐ(例 &#37;3cscript → %3cscript が復号されず素通り)。各ステップは
    # ガード付きで no-op 時は安価=既に復号済みの通常トラフィックは実質1周で抜ける(低速化しない)。
    for _decode_round in range(3):
        _before = s
        if "%" in s or "+" in s:      # unquote_plus は "+"→空白 も行うため "%" 単独では判定不足
            try:
                from urllib.parse import unquote_plus
                # 多重%エンコードを最大5回戻す(三重以上 %25252e%25252e は2回では実体 "." まで
                # 戻らず traversal 等が素通り=実証済バイパス)。変化が無くなり次第 break。
                for _ in range(5):
                    dec = unquote_plus(s)
                    if dec == s:
                        break
                    s = dec
            except Exception:
                pass
        if "&" in s:
            try:                                 # ;終端のHTMLエンティティのみ復号(&lt;→<, &#60;→<,
                from html import unescape         #   &#x3c;→<)=実体エンコードXSS/SQLi回避を無効化。
                s = re.sub(                       # ';' 必須ゆえ &gt=10 等の REST フィルタ引数は復号せず
                    r"&(?:#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z][a-zA-Z0-9]{1,31});",
                    lambda m: unescape(m.group(0)), s)   # 誤検知しない(legacy のセミコロン無し実体は除外)
            except Exception:
                pass
        # Unicode 回避対策(ヒエログリフ/絵文字罠): \uXXXX/\xXX エスケープ復号 → NFKC 正規化
        # (全角 ＜ｓｃｒｉｐｔ＞ 等の互換文字を ASCII へ畳む)→ 不可視/書式制御文字(ゼロ幅・ソフト
        # ハイフン・BOM 等)除去。見た目だけ違う回避(un​ion / <script)を実体へ戻す。
        if "\\" in s:
            def _unesc(m):
                try:
                    return chr(int(m.group(m.lastindex), 16))
                except Exception:
                    return m.group(0)
            s = re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})", _unesc, s)
        if not s.isascii():                          # ASCII はそのまま(高速パス)。非ASCIIのみ重処理。
            if not fold_fw:                          # ON(fold_fullwidth_punct)は下の NFKC で畳む=前の版と同じ
                for _c in _CJK_FW_PUNCT:             # CJK の地の文の全角記号はメタ文字にしない(本文も head も)
                    if _c in s:
                        s = s.replace(_c, " ")
            try:
                # NFKC は 1 文字を最大 18 文字へ展開する(例 U+FDFA)。8KB を埋められると走査面が
                # 入力の十数倍に膨れ、(a) そのまま全域を走査すれば CPU 枯渇DoS、(b) 溢れた分を
                # 切り捨てれば後続 payload が走査面から消えるバイパス、という二択になる。
                # そこで *異常に伸びる時だけ* 「大きく伸びる文字を展開しない」正規化へ落とす。
                # ASCII の難読化に使える互換文字(全角英数 1→1・合字 ﬁ→2・丸数字 1→1・㈱ 1→3)は
                # いずれも _NFKC_MAX_EXPAND 以内なので畳み込みは維持=検知能力は落ちない。
                # 展開しないのは U+FDFA(アラビア語句)等、ASCII 攻撃文字列を作れない文字だけ。
                # 既に NFKC 済みなら何もしない(大半の非 ASCII テキスト)。結合文字の長い連続は
                # 先に区切る([[_stream_safe]]: NFKC の並べ替えが 2 乗にならないように・#64)。
                if not unicodedata.is_normalized("NFKC", s):
                    s2 = _stream_safe(s)
                    t = unicodedata.normalize("NFKC", s2)
                    # 上限は周回ごとの 4 倍ではなく元の入力の 4 倍(前の周回で展開しなかった U+FDFA を
                    # 次の周回で展開させない)。U+0130 は最後の lower() で 2 文字になるので数に入れる。
                    if len(t) + t.count(_I_DOT) > lim:
                        t = "".join(_nfkc_char(c) for c in s2)
                    s = t[:cap]
            except Exception:
                s = s[:cap]
            # 書式文字(Cf=ゼロ幅/ソフトハイフン/方向制御 等)を除去。isprintable() が真なら Cf も
            # 制御文字も無い=見ずに済む。
            if not s.isprintable():
                s = _cf_re().sub("", s)
        # \t\n\v\f\r(空白類)以外の C0 制御文字を除去。ASCII の高速パスでも同じに行う(#66: 旧実装は
        # 非 ASCII の分岐の中だけで行い、同じ値が無関係な非 ASCII 文字の有無で別物に見えた)。
        # \v\f は除去せず後段で空白に畳む(SQL では空白=除去すると union\vselect が繋がって消える)。
        if not s.isprintable():                      # 制御文字が無ければ(大半)正規表現も回さない
            s = _CTRL_RE.sub("", s)
        if s == _before:                             # 安定=これ以上復号で変化しない → 早期終了
            break
    # Log4j ルックアップ難読化を畳む: 既知のルックアップ名(${lower:j} 等)と :- デフォルト形
    # (${::-j} / ${env:X:-j})だけを中身へ置換。これで ${${lower:j}ndi:ldap://…} の入れ子回避が
    # jndi: として露出する。jndi 本体(${jndi:...} は名が一致せず :- も無い)は保存される=
    # 過剰畳みしない。入れ子を解くため数回繰り返す(有界)。深い多重入れ子は対象外。
    if "${" in s:
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
    # (?s)=DOTALL 必須: 実SQLコメントは複数行にまたがれる(標準的な仕様。UNION/*\n*/SELECT は
    # 実DBで有効な"UNION SELECT")。DOTALL が無いと '.' が実改行にマッチせず、コメントとして
    # 認識されずに /* */ が生の文字として残る=UNION と SELECT の間の空白畳み込みが働かず
    # \bunion\b[\s(;]*\bselect\b 等が素通りする(実証済バイパス)。
    # コメント除去は線形スキャナ [[_strip_sql_comments]] に委譲(旧: 有界 lazy 正規表現)。
    # 旧実装は /* 連打(未終端)に対し各アンカーが最大 _MAX_SCAN 文字を前方走査し、単一
    # イベントループを ~120ms/req 占有する CPU 枯渇DoSだった。線形版は同一の除去結果
    # (版付きは中身保持・一般は中身除去)を保ちつつバックトラック無し。
    s = _strip_sql_comments(s)
    # 注入された改行(%0a/%0d)を区切り ; に正規化。path/query/UA に正規の生改行は無いため、
    # CR/LF はコマンド/文の区切りとみなせる(サーバ側で実際そう解釈される)。これで ; ベースの
    # 既存検知(RCE ;cat / stacked SQL ;select)が改行注入にも効く。空白畳みより *前* に行う。
    # 本文(body=True)では行わない: 本文の改行は正規の区切りで、次の空白畳みで空白になる。
    # 例外は nl=True(本文の crlf・rce・複文照合用): 生の改行は冒頭で空白にしたので、ここに残るのは
    # 復号で値に現れた改行だけ=head と同じく ';' にする。
    # JSON 本文(json_esc)ではその見え方でだけ、JSON の短いエスケープ(\n \r 等)も値の改行として復号する
    # (本文の走査面=返値 s は変えない。v は値の改行の見え方の元)。
    v = s
    if json_esc and body and (nl or nl_views is not None) and "\\" in s:
        v = _json_unescape_short(s)
        if nl:
            s = v
    if (not body or nl) and ("\r" in s or "\n" in s):
        s = re.sub(r"[\r\n]+", ";", s)
    elif (nl_views is not None and ("\r" in v or "\n" in v)
          and _BODY_NL_LEAD.search(v) is not None):
        # 本文で値の改行の後に照合対象の語が続く時だけ、nl=True と同じ見え方を *同じ復号結果から*
        # 作って渡す(復号をやり直さない。行頭がその語でない普通の改行では何も増えない)
        nl_views.append(_collapse_scan_text(re.sub(r"[\r\n]+", ";", v), cap))
    return _collapse_scan_text(s, cap)


# JSON の短いエスケープ(RFC 8259 §7)。左から重ならずに当てるので \\ は先に 1 組として読む=二重に
# エスケープされた \\n(値の中の字面のバックスラッシュ + n。コード片の文字列リテラル等)は改行にしない。
# \t \f は空白、\b(後退)は除く(本文の走査面で制御文字を除くのと同じ)。\uXXXX は復号の段で済んでいる。
_JSON_SHORT_ESC_RE = re.compile(r'\\([\\"/bfnrt])')
_JSON_SHORT_ESC = {"\\": "\\", '"': '"', "/": "/", "b": "", "f": " ", "n": "\n", "r": "\r", "t": " "}


def _json_unescape_short(s: str) -> str:
    """JSON の短いエスケープを復号する([[_normalize_full]] json_esc の値の改行の見え方用)。"""
    return _JSON_SHORT_ESC_RE.sub(lambda m: _JSON_SHORT_ESC[m.group(1)], s)


def _collapse_scan_text(s: str, cap: int) -> str:
    """[[_normalize_full]] の仕上げ: 空白の畳み込み、スキーム/比較演算子/区切りの前後の空白除去、
    小文字化、cap での切り詰め。"""
    s = re.sub(r"\s+", " ", s)               # 空白畳み込み(回避抑制+走査面積減)
    if ":" in s:
        # スキーム直前の空白を除去(javascript : → javascript:)。ブラウザは URL 内の tab/CR/LF を
        # *除去* してからスキームを解釈するため、javascript%09: は javascript: として実行される。
        # 本正規化は tab を空白へ畳むだけなので javascript : となり xss 署名/prescan(literal
        # "javascript")の双方を回避できた(#normalization)。tab を全除去すると union\tselect が
        # unionselect となり \bunion\b 境界が壊れSQL検知を落とすため、コロン隣接の空白のみ削る。
        s = re.sub(r"\s+:", ":", s)
    if "<" in s or ">" in s or "=" in s:
        s = re.sub(r"\s*(<=|>=|<>|!=|=|<|>)\s*", r"\1", s)  # 比較演算子前後の空白除去(1 < 2 → 1<2)
    if ";" in s or "|" in s:
        s = re.sub(r"([;|])\s+", r"\1", s)   # ;/| 直後の空白除去(; cat → ;cat)
    # lower() は切り詰めの *前*: U+0130 等は小文字化で 2 文字に伸びる(後に掛けると cap の 2 倍・#63)
    return s.lower()[:cap]


def _normalize_for_scan(s: str) -> str:
    """正規化して 1 窓分(_MAX_SCAN)へ切り詰める。単発フィールドの軽量参照用。
    *走査* には使わないこと(切り詰めた分が「転送されるのに未走査」の迂回窓になる)。"""
    return _normalize_full(s)[:_MAX_SCAN]


def _window_starts(n: int, step: int) -> list:
    """長さ n を _MAX_SCAN 幅・step 刻み(=重なり付き)の窓で覆う開始位置の列(全域がどれかに載る)。"""
    starts = [0]
    while starts[-1] + _MAX_SCAN < n:
        starts.append(starts[-1] + step)
    return starts


def _normalized_parts(chunk: str, step: int, depth: int = 0, *, body: bool = False,
                      nl: bool = False, nl_parts: list | None = None, fold_fw: bool = False,
                      json_esc: bool = False) -> list:
    """生入力 1 断片を *1 回だけ* 正規化し、走査窓の列として返す(#65)。
    返値の上限は断片長 × _NFKC_MAX_EXPAND(+1)。1 文字の展開は NFKC・lower() 込みで最大 4 倍
    ([[_nfkc_char]])なので、展開しても切り捨ては起きず、正規化結果の全域がどれかの窓に載る。
    旧実装は上限 _PRE_CUT で頭打ちになると結果を捨て、生入力を半分ずつ正規化し直していた
    (16K の U+3300 で 15 回)。上限に届いた時(展開上限の想定外)だけ、安全弁として生入力を
    半分に割って正規化し直す(重なり付き・深さと最小長で有界)。
    登録デコーダはここでは掛けない([[_scan_windows]] がフィールド全体へ 1 回掛け済み)。
    nl_parts(本文・nl=False)を渡すと、値に復号で現れた改行の後に照合対象の語が続く時だけ、改行を
    ';' にした見え方(nl=True と同じ)の窓をそこへ足す(同じ正規化の 1 回で作る・[[_normalize_full]])。"""
    cap = len(chunk) * _NFKC_MAX_EXPAND + 1
    views = [] if nl_parts is not None else None
    n = _normalize_full(chunk, body=body, decode=False, cap=cap, nl=nl, nl_views=views, fold_fw=fold_fw,
                        json_esc=json_esc)
    if len(n) < cap or depth >= 4 or len(chunk) <= 512:
        if views:
            nl_parts.extend(v[j:j + _MAX_SCAN] for v in views for j in _window_starts(len(v), step))
        return [n[j:j + _MAX_SCAN] for j in _window_starts(len(n), step)]
    half = len(chunk) // 2
    return (_normalized_parts(chunk[:half + _SCAN_WIN_OVERLAP], step, depth + 1, body=body, nl=nl,
                              nl_parts=nl_parts, fold_fw=fold_fw, json_esc=json_esc)
            + _normalized_parts(chunk[half:], step, depth + 1, body=body, nl=nl, nl_parts=nl_parts,
                                fold_fw=fold_fw, json_esc=json_esc))


def _scan_windows(s: str, *, body: bool = False, nl: bool = False,
                  nl_views: list | None = None, fold_fw: bool = False, json_esc: bool = False) -> tuple:
    """1 フィールドの走査面を返す。生入力を _MAX_SCAN 窓+重なりで刻み、*窓ごとに* 正規化して
    (正規化結果が長ければさらに窓分割して)返す。
    旧実装は「正規化してから [:_MAX_SCAN] で切る」だったため、次の 2 つが『backend へ転送
    されるのに未走査』の迂回窓になっていた(いずれも実証済のバイパス):
      (a) proxy が転送するヘッダ/リクエストターゲット(最大 16384)の 8192 以降。先頭を
          無害な "A" で埋めるだけで後続の Log4Shell/SQLi が全署名を回避できた。
      (b) 正規化中の NFKC 展開(1 文字→最大 18 文字。例 U+FDFA)で押し出された後半。
          切り詰めは正規化 *後* だったため、展開させるだけで後続 payload が消えた。
    生入力の側で刻めば、展開で溢れた分も次の生窓に必ず現れる=全域が走査面に載る。重なりは
    窓境界を跨ぐ payload の分断を防ぐ。生入力は _PRE_CUT、窓数は _MAX_SCAN_WINDOWS で有界
    (=CPU 枯渇にならない)。8192 以下の通常フィールドは窓 1 枚=従来と同じ経路・同じ費用。
    登録デコーダはフィールド全体へ 1 回だけ掛け、その出力(上限 _PRE_CUT)を刻む(#62: 旧実装は
    生チャンクごとに掛け、出力が _PRE_CUT に届くと捨てて生入力の半分ずつを復号し直していた=
    全体が要る復号(圧縮/枠付き形式)は断片で失敗し、復号結果が走査面に載らなかった)。
    body=True は本文用の正規化([[_normalize_full]])で窓を作る。nl=True は本文の crlf・rce・複文照合用の
    見え方(値に復号で現れた改行だけを ';' にする)で窓を作る。nl_views(本文・nl=False)にリストを
    渡すと、値に復号で現れた改行の後に照合対象の語が続く時だけ([[_BODY_NL_LEAD]])、その見え方
    (nl=True と同じ)の窓が足される(同じ窓予算・重複除去。正規化は 1 回のまま)。
    fold_fw=True(運用者の設定 fold_fullwidth_punct)は全角の ｜ ＄ （ ） ； ｀ も畳む([[_normalize_full]])。
    json_esc=True(JSON 本文)はその見え方でだけ JSON の短いエスケープ(\\n \\r 等)も値の改行として読む。"""
    raw = s[:_PRE_CUT]
    if not raw:
        return ("",)
    if _SCAN_DECODERS:
        raw = _apply_scan_decoders(raw)
    step = _MAX_SCAN - _SCAN_WIN_OVERLAP
    groups, nl_groups = [], []
    for i in _window_starts(len(raw), step):
        nlp = [] if nl_views is not None else None
        groups.append(_normalized_parts(raw[i:i + _MAX_SCAN], step, body=body, nl=nl, nl_parts=nlp,
                                        fold_fw=fold_fw, json_esc=json_esc))
        if nlp:
            nl_groups.append(nlp)
    if nl_groups:
        nl_views.extend(w for w in _budget_windows(nl_groups) if w)
    return _budget_windows(groups)


def _budget_windows(groups: list) -> tuple:
    """チャンクごとの窓の列から、窓予算内の走査窓の列を作る(重なり由来の同一窓は 1 回だけ)。"""
    # 窓予算は全チャンク通しで数える(#61)。1 文字の展開は最大 4 倍なので、_PRE_CUT 文字を
    # 4 倍に展開しても窓は 11 枚=_MAX_SCAN_WINDOWS に収まり、全域が載る(旧実装はチャンクごとに
    # 12//チャンク数 で打ち切って余りを他へ回さず、16K の 1→4 展開で 4 割強を落としていた)。
    # 上限を超えるのは安全弁(半分割り)が働いた想定外の時だけ。その時もチャンク数で按分し、
    # チャンク内は等間隔に間引く=先頭チャンクを大量展開する文字で埋めて予算を独占させ、
    # *後続チャンクを丸ごと未走査に* する回避(先頭パディング回避の再来・実証済)は起きない。
    if sum(len(g) for g in groups) > _MAX_SCAN_WINDOWS:
        share = max(_MIN_PARTS_PER_CHUNK, _MAX_SCAN_WINDOWS // len(groups))
        groups = [g if len(g) <= share else
                  [g[k * (len(g) - 1) // (share - 1)] for k in range(share)] for g in groups]
    wins, seen = [], set()
    for g in groups:
        for _p in g:
            if _p in seen:                 # 重なり由来の同一窓は走査しない(無駄な CPU)
                continue
            seen.add(_p)
            wins.append(_p)
    return tuple(wins) or ("",)


# 本文(バイト列)を走査用の文字列へ読む(#8)。UTF-8 として正しい所は UTF-8 として読み、不正な
# バイト(バイナリのファイル部・latin-1 の旧式フォーム等)だけを latin-1 として 1:1 で読む。
# 旧実装は全体を latin-1 で読んでいたため、生 UTF-8 の全角/ゼロ幅は 1 バイトずつの文字化けになり、
# NFKC/書式文字の畳み込みが効かなかった(%XX や \u エスケープで送った同じ値だけが検知された)。
# 不正バイトを U+FFFD にせず latin-1 で残すのは、どのバイトも走査面から消さないため。
_SURROGATE_TO_LATIN1 = {0xDC80 + _b: 0x80 + _b for _b in range(128)}
# 走査前の正規化([[_normalize_full]])で NFKC の前に空白へ置き換える全角記号(本文も head も・#3)。
# ｜ ＄ （ ） ； ｀ は日本語/中国語の地の文や題名で普通に使う('データ分析の基礎｜Python'・
# '価格は＄（税込）'・'宛先；To: …')が、NFKC で | $ ( ) ; ` になると rce の '| python'・'$(…)'・
# '`…`'、crlf/複文の ';'、ldapi の ')(' に当たり、UTF-8 で読むようにした(#8)本文の保存 1 回ごとに
# 42 点(単発拒否の閾値超え)が入っていた。シェル/SQL がこれらの全角形を区切りとして読むことは
# 無い。値の送り方(生 UTF-8・\u エスケープ・%XX)に依らず同じに扱うため、復号の各周回で置き換える。
# head(URL/ヘッダ)も同じ(決定・dec_headfold): ブラウザが %XX で送る '?q=データ分析の基礎｜Python'
# の検索 1 回が 60 点=単発拒否になっていた(前の版から)。全角英字や XSS の ＜＞ 等の畳み込み(#8)は
# 本文も head もそのまま。
_CJK_FW_PUNCT = ("＄", "（", "）", "；", "｀", "｜")


def _body_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", "surrogateescape").translate(_SURROGATE_TO_LATIN1)


# バイナリ本文の署名走査の省略(T1・決定)。圧縮画像/protobuf/zip 等のランダムなバイト列は `…` や
# $(…) を偶然含み、64KB で rce 約 42 点(単発拒否の deny_score 超)になっていた。省くのは *宣言型が
# バイナリ* かつ *中身がバイナリ*(走査する先頭にタブ/CR/LF 以外の C0 制御バイトがある)のときだけ。
# テキストの中身をバイナリ型で送っても、テキスト型でバイナリを送っても走査する。型は引数を落とした
# 小文字の type/subtype で見る。+xml/+json の構文接尾辞(image/svg+xml 等)はテキスト=常に走査する。
_BINARY_CT_TOP = ("image/", "audio/", "video/", "font/")
_BINARY_CT_APP = frozenset((
    "octet-stream", "x-protobuf", "protobuf", "x-google-protobuf", "vnd.google.protobuf",
    "grpc", "grpc+proto", "grpc-web", "grpc-web+proto",
    "zip", "x-zip-compressed", "gzip", "x-gzip", "x-tar", "x-bzip2", "x-xz", "zstd",
    "x-7z-compressed", "x-rar-compressed", "vnd.rar", "pdf", "wasm",
    "msgpack", "x-msgpack", "vnd.msgpack", "cbor", "bson"))
_BINARY_BYTE_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _binary_ctype(content_type: str) -> bool:
    """Content-Type がバイナリの表現型か(T1)。空/テキスト型/+xml・+json 接尾辞は False。"""
    t = (content_type or "").split(";", 1)[0].strip().lower()
    if not t or t.endswith(("+xml", "+json")):
        return False
    if t.startswith(_BINARY_CT_TOP):
        return True
    return t.startswith("application/") and t[12:] in _BINARY_CT_APP


def _json_body(text: str, content_type: str = "") -> bool:
    """本文が JSON か(値の改行の見え方で JSON の短いエスケープ \\n \\r を読む本文・[[_normalize_full]]
    json_esc)。Content-Type が JSON(application/json・+json 接尾辞・ndjson 等)か、型が無い/違っても
    先頭(空白・BOM の後)が { か [ の本文(CORS の事前確認を避けて text/plain で送る JSON もある)。
    本文全体で決める=後ろの窓も同じ読み方。フォーム・multipart・テキストの \\n は字面のまま
    (コード片の文字列リテラルを値の改行と読まない)。"""
    if "json" in (content_type or "").split(";", 1)[0].lower():
        return True
    return text.lstrip(" \t\r\n﻿")[:1] in ("{", "[")


# ブラウザ形 multipart/form-data の枠(RFC 2046/7578)。Content-Type は重複/省略され得る(proxy は
# 1 本だけのときしか渡さない)ので形で見分ける: 先頭行が --<境界> の本文だけを multipart とみなす
# (ブラウザ/curl/requests は前置き無し)。
_MP_FIRST_RE = re.compile(r"--([0-9A-Za-z'()+_,./:=?-](?:[0-9A-Za-z'()+_,./:=? -]{0,68}"
                          r"[0-9A-Za-z'()+_,./:=?-])?)[ \t]*\r?\n")
_MP_HEADER_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*:")
_MP_FILENAME_RE = re.compile(r"(?i)\bfilename\*?[ \t]*=")
_MP_SEP = "\n_\n"     # 部どうしの区切り: 空白/';' ではない 1 語=部を跨いだ照合('--… 等)を作らない


def _mp_split_part(pt: str) -> tuple:
    """1 部を (部ヘッダ, 中身) に分ける。最初の空行までがヘッダ。ヘッダの形でない行があれば
    全体を中身とみなす(=ヘッダ扱いで照合を外す範囲を最小にする)。"""
    if pt.startswith("\r\n"):
        return "", pt[2:]
    if pt.startswith("\n"):
        return "", pt[1:]
    ends = [(i, k) for i, k in ((pt.find("\r\n\r\n"), 4), (pt.find("\n\n"), 2)) if i >= 0]
    i, k = min(ends) if ends else (len(pt), 0)
    head = pt[:i]
    for line in head.split("\n"):
        line = line.rstrip("\r")
        if not (_MP_HEADER_RE.match(line) or line[:1] in (" ", "\t")):
            return "", pt
    return head, pt[i + k:]


def _multipart_fields(text: str):
    """multipart 本文なら (部の中身の連結, 境界+部ヘッダの連結) の 2 フィールドを返す。非該当は None。
    枠(--境界 行)を外し、部ヘッダと中身を別フィールドで走査させる(#0)。枠を中身と続けて読むと、
    末尾がアポストロフィの値 + 改行 + '--境界' が sqli('--)に当たり、普通のアップロードが毎回
    加点された。部ヘッダ(name/filename 等)と境界の文字列そのものは捨てずに別フィールドとして
    走査する(filename 経由の注入や、multipart でない本文に偽の枠を書く手を死角にしない)。
    バイナリのファイル部(filename 付きで中身に制御文字を含む)は中身を署名走査しない: 圧縮画像等の
    ランダムなバイト列は `…` や $(…) を偶然含み(数十 KB の画像でほぼ確実)、rce 等に当たって
    普通のアップロードが加点されていた。ファイル種別の危険は scan_upload(拡張子)が見る。
    filename の無い部(フォーム値)は不正バイトが混じっても走査する(1 バイト足して素通りさせない)。"""
    m = _MP_FIRST_RE.match(text)
    if m is None:
        return None
    boundary = m.group(1)
    delim = "\n--" + boundary
    pieces = text[m.end():].split(delim)
    parts = [[pieces[0]]]                   # 部ごとの断片の並び(連結は部ごとに 1 回=本文長に線形・#38)
    for p in pieces[1:]:
        q = (p[2:] if p.startswith("--") else p).lstrip(" \t")   # 終端 --境界-- と行末の空白
        if q.startswith("\r\n"):
            parts.append([q[2:]])
        elif q.startswith("\n"):
            parts.append([q[1:]])
        elif not q:
            parts.append([""])
        else:
            parts[-1] += (delim, p)         # 境界を接頭に持つ別の行=枠ではない(中身へ戻す)
    heads, bodies = [boundary], []
    for frags in parts:
        pt = "".join(frags)
        if pt.endswith("\r"):
            pt = pt[:-1]                    # 次の枠の直前の CRLF の CR
        h, c = _mp_split_part(pt)
        if h:
            heads.append(h)
        if c and not (_MP_FILENAME_RE.search(h) and _CTRL_RE.search(c)):
            bodies.append(c)
    return _MP_SEP.join(bodies), _MP_SEP.join(heads)


def _path_decoded(path: str) -> str:
    """照合用パスの前段(evolution #40): query/fragment を落とし、%エンコードを最大2回復号して
    小文字化する。ドットセグメント・'//'・';' は解決しない(要求行に書かれたままの区切り)。
    経路制御は通常 _path_for_match(配信先の形)で照合する。/a/../b を解決せずに経路照合する
    バックエンドも守りたい呼び出し元は、両方の形で照合する(遮断=どちらかが当たれば遮断、
    許可=両方とも許可のときだけ)。path の '+' は空白でないので unquote(非plus)。"""
    from urllib.parse import unquote
    p = (path or "").split("?", 1)[0].split("#", 1)[0]
    for _ in range(2):                       # 多重%エンコードも戻す(WAF定石・有界)
        d = unquote(p)
        if d == p:
            break
        p = d
    return p.lower()


def _path_for_match(path: str) -> str:
    """アクセス制御/経路照合用に path を *バックエンドが見る形* へ軽く正規化(evolution #40)。
    %エンコードを最大2回復号し小文字化(query/fragment は除去・_path_decoded)。これが無いと
    blocked_urls / blocked_extensions / path_limits を /%61dmin・/secret%2eenv・/%6cogin 等で
    回避できる(バックエンドは復号して提供するのに WAF が生 path で照合してしまうため)。
    署名走査の重い正規化(_normalize_for_scan)とは別系統の軽量版。
    復号後に *バックエンドが配信する形* へ解決する: 各セグメントの ';' 以降(パスパラメータ。
    servlet コンテナと同じく '..;x' も '..')を除き、'/' の連続を 1 個に畳み、RFC 3986 の
    remove_dot_segments(. を除き .. で 1 段戻る・根より上へは戻らない・末尾スラッシュは残す)。
    これが無いと //admin・/public/../private が '/admin'・'/private' の経路レート規則を外れ、
    //graphql・/graphql;x=1 が GraphQL ガードを外れた。照合専用で、転送する要求そのものは変えない。"""
    p = _path_decoded(path)
    # 早道: ドットセグメント('/.' か先頭 '.')・'//'・';' のどれも無い普通のパスはそのまま
    if "/." in p or "//" in p or ";" in p or p[:1] == ".":
        segs = p.split("/")
        out = []
        for s in segs:                       # 1 パス・線形(病的な '../'*N でも O(N))
            s = s.split(";", 1)[0]
            if s == "..":
                if out:
                    out.pop()                # 根より上へは戻らない
            elif s and s != ".":             # 空(= '/' の連続)と '.' は捨てる
                out.append(s)
        q = "/".join(out)
        if p[:1] == "/":
            q = "/" + q
        if out and segs[-1].split(";", 1)[0] in ("", ".", ".."):
            q += "/"                         # 末尾スラッシュ/末尾ドットセグメント=ディレクトリ
        p = q
    return p                                 # 小文字化は解決と可換('.'/'/'/';' を生む文字は無い)


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
# 本文用(#2): 本文の ';' は CSV の区切りや地の文('Looks good; update the changelog')にも出るので、
# 動詞の後に SQL 文の *構文* まで続く時だけ複文とみなす(update <名前> set / delete from /
# insert into / select … from / drop|create|alter <オブジェクト> 等。動詞の集合は head 用と同じで、
# 判定は head 用の部分集合)。走査面は正規化済み=空白は 1 個に畳まれ、';' 直後の空白は除去済み。
_STACKED_BODY_RE = re.compile(
    r";\s*(?:select\b[^;]{0,120}?\bfrom\b"
    r"|insert\s(?:ignore\s)?into\b"
    r"|update\s[\w.`\"\[\]]{1,64}\sset\b"
    r"|delete\sfrom\b"
    r"|(?:drop|create|alter)\s(?:or\sreplace\s|temporary\s|unique\s)?"
    r"(?:table|database|schema|view|index|procedure|function|trigger)\b"
    r"|truncate\stable\b"
    r"|exec(?:\s?[(@]|\s(?:xp_|sp_|master\.))"
    r"|union\s(?:all\s|distinct\s)?select\b"
    r"|grant\s[\w, ]{1,80}?\son\s[^;]{1,80}?\sto\b)")


def _stacked_query_suspect(blob: str, *, body: bool = False) -> bool:
    """正規化済み文字列に『; に続く SQL 文(複文)』が含まれるか=スタッククエリ注入。
    body=True は要求本文用(SQL 文の構文まで要求する・[[_STACKED_BODY_RE]])。"""
    return (_STACKED_BODY_RE if body else _STACKED_RE).search(blob) is not None


# 本文で、値に符号化して入れた改行(%0A・&#10;・\\u000a 等)を ';' にした見え方(nl=True)でも照合する
# 規則(#14)。値の改行はサーバ側で文/コマンドの区切りになる(head と同じ注入)が、本文の他の署名には
# 見せない(';' にすると '...' + 改行 が traversal の '..;' に当たる等、別の誤検知が出る)。どれも ';' の
# 後に文脈(引数・SQL 文の構文・ヘッダ値の形)を要求する本文用の照合なので、テキストエリアの
# 'Cat food …' / 'Update: …' / 'To: …' 行は当たらない。並びは [[NetShield._scan_builtin]] と同じ
# (署名の rce → crlf、構造検知のスタック複文)。(名前, 正規表現, 既定の重み)。
_BODY_NL_RULES = (("rce", dict(_SIG_RE_BODY)["rce"], 30),
                  ("crlf", _BODY_CRLF_RE, 30),
                  ("sqli-stacked", _STACKED_BODY_RE, 40))
# その見え方を作るかの前置ゲート([[_normalize_full]] の改行の段=復号で値に現れた改行だけが残る所で
# 見る)。見え方で新たに当たりうるのは ';'(=値の改行)の直後にコマンド名/SQL の動詞/ヘッダ名+':' が
# 来る形だけ(他の分岐は本文の走査面で照合済み)で、改行と語の間・ヘッダ名と ':' の間で仕上げが消すのは
# 空白だけ=真陽性のスーパーセット。改行の後は改行以外の空白だけを見る(改行の長い連続で 2 乗に
# ならない)。小文字化の前なので大小を無視する。
_BODY_NL_LEAD = re.compile(
    r"[\r\n][^\S\r\n]*(?:(?:cat|wget|curl|bash|sh|nc|powershell|select|exec)\b"
    r"|(?:insert|update|delete|drop|create|alter|truncate|union|grant)\s"
    r"|(?:set-cookie|location|refresh|content-(?:type|length|disposition|transfer-encoding)"
    r"|bcc|cc|to|mime-version)[^\S\r\n]*:)", re.I)


# DOMイベントハンドラ系 XSS の *構造* 検知 — 個別ハンドラ名の列挙(prescan需要)を避け、
# 『タグ内に on<名前>= が現れる』形で捕捉する(<svg onload= / <div onclick= / <svg/onload=)。
# literal '<タグ' を要求するため、?onload=1 のような素の引数は対象外=低誤検知。タグと
# ハンドラの間は同一タグ内(>を跨がない)・区切りは空白か / (または ; = 生改行が正規化で
# 変換された区切り文字。CRLF注入 <svg\nonload=… を \s 限定だと見逃すため追加)を許容。
# prescan ゲート外で常時評価。
_XSS_HANDLER_RE = re.compile(
    r"<\s*[a-z][a-z0-9]{0,15}[^>]{0,120}?[\s/;]on[a-z]{3,12}\s*=", re.I)


def _xss_event_handler_suspect(blob: str) -> bool:
    """正規化済み文字列に『タグ内の onXxx= イベントハンドラ』があるか=ハンドラ型 XSS。
    先に必須文字(< / on / =)の有無だけ見る: 3 つのどれかが欠ければ正規表現は絶対に
    マッチしない=真陽性を落とさずに、"<img " 連打のような入力で正規表現が 8KB を
    バックトラック走査する CPU 枯渇(実測 6.4ms/req・イベントループ占有)を避ける。"""
    if "<" not in blob or "=" not in blob or "on" not in blob:
        return False
    return _XSS_HANDLER_RE.search(blob) is not None


# ── 設定値の検証(set_config / _load / 専用セッターが共有する唯一の入口) ──
_SIG_WEIGHT_MAX = 1000.0   # カスタムシグネチャ weight の上限(組込は 30〜65)
# cred_rate_limit / resp_error_threshold の上限。窓内の件数は時刻の deque の長さで数えるので、
# deque が閾値ぶんの長さを持てないと永久に発火しない(旧: 8192/1024 固定で黙って無効だった)。
_RATE_COUNT_MAX = 1 << 20
_RATE_COUNT_KEYS = frozenset({"cred_rate_limit", "resp_error_threshold"})
# 0 以下が『無効』ではなく *壊れた動作* になるキー(#50)。resp_error_threshold<=0 は 4xx が来るたび
# 加点して 2 件で BAN、dlp_max_scan_bytes<=0 は dlp_active のまま何も走査しない(=黙って DLP 無効)。
# 他のキーの『0=無効/無制限』と取り違えやすいので、受理せず現状を保つ。
_POSITIVE_KEYS = frozenset({"resp_error_threshold", "dlp_max_scan_bytes"})
# 0 以上だけが意味を持つキー。body_sig_weight_factor の負値は本文ヒットで他の検知の加点を
# 打ち消していた(読む側は 0 に丸める・#36)。API では拒否し、保存済みの旧値は 0 に丸めて読む。
_NONNEG_KEYS = frozenset({"body_sig_weight_factor"})
# 列挙値の文字列キー(#49)。綴り違い('BLOCK' 'deny' 等)を黙って受理すると、block のつもりが
# audit として動いていた。前後空白と大小文字だけ正規化し、それ以外は拒否する。値は読む側の
# 比較(== "audit" 等)と同じ綴りで持つ(cookie_samesite は Set-Cookie にそのまま書く綴り・""=付けない)。
# Lite の geo_mode は CIDR 判定のみ(GeoIP の country_* は持たない)。
_ENUM_KEYS = {
    "dlp_action": ("audit", "block"),
    "mode": ("enforce", "audit"),
    "open_redirect_mode": ("enforce", "audit"),
    "geo_mode": ("off", "allow", "block"),
    "site_mode": ("off", "whitelist", "blacklist"),
    "ip_mode": ("off", "whitelist", "blacklist"),
    "cookie_samesite": ("Lax", "Strict", "None", ""),
}
# 照合用: 小文字の綴り → 正規の綴り
_ENUM_CANON = {k: {a.lower(): a for a in vs} for k, vs in _ENUM_KEYS.items()}
# 列挙値を検証しなかった旧版が *認識しない綴り*('Whitelist' ' audit' 等)で実際に取っていた動作
# (#18)。読む側は正規の綴りとの完全一致で比べていたので、ip_mode='Whitelist' は off として動いて
# いた。保存値を正規化して読むと動作が変わるキー(正規化後 != これ)だけを warnings で名指しする。
# cookie_samesite は旧版も strip して Set-Cookie に書き、ブラウザは大小を区別しないので対象外。
_ENUM_LEGACY_EFFECT = {
    "dlp_action": "audit",            # == "block" のときだけ遮断していた
    "mode": "enforce",                # == "audit" のときだけ記録のみ
    "open_redirect_mode": "audit",    # != "enforce" は記録のみ
    "geo_mode": "off", "site_mode": "off", "ip_mode": "off",
}
_ENUM_NORM_CODE = "cfg_enum_normalized"
# 許可リスト型のモードと、そのリストのキー(空なら全遮断になることを警告文に添える)
_ALLOW_LIST_OF = {("ip_mode", "whitelist"): "ip_whitelist", ("geo_mode", "allow"): "geo_cidrs"}
# HTTP ヘッダへそのまま書く自由入力の文字列キー。origin_header は要求ヘッダの *名前*
# (エッジトークン・#77)、open_redirect_safe_path は応答の Location の *値*。改行(CR/LF)・NUL・
# 他の制御文字(C0/DEL/C1 と U+2028/2029)はヘッダの区切りを壊すので受理しない。ヘッダ名は
# さらに RFC 9110 の token(tchar の並び)に限る(空白・':' 等を含む名前は送れない)。
_HEADER_STR_KEYS = frozenset({"origin_header", "open_redirect_safe_path"})
_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_HDR_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _finite_number(v) -> bool:
    """有限の実数か。NaN/±inf と、float に直せない巨大 int(JSON で書ける)を弾く。
    NaN は比較が常に偽になり閾値判定を黙って無効化し、巨大 int は float() で例外になる。"""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    try:
        return math.isfinite(float(v))
    except OverflowError:
        return False


def _sig_weight(w):
    """カスタムシグネチャ weight を検証して float で返す(不正は None)。NaN はスコアを永久に
    NaN にし(閾値比較が常に偽=その IP は BAN されない)、負値は他の検知の加点を打ち消す。
    上限超えの有限値は _SIG_WEIGHT_MAX へ丸める: 旧版は任意の weight(『見たら BAN』の 5000 等)を
    受理して保存しており、無効化すると更新で検知が止まる。1000 でも 1 回の一致で block_score を大きく
    超えるので動作は同じ。"""
    if isinstance(w, bool):
        return None
    try:
        w = float(w)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(w) or w < 0:
        return None
    return min(w, _SIG_WEIGHT_MAX)


def _sig_weight_capped(w) -> bool:
    """weight が上限を超える有限値で、_sig_weight が丸めたか(一覧・追加結果での注記用)。"""
    try:
        return (not isinstance(w, bool) and math.isfinite(float(w))
                and float(w) > _SIG_WEIGHT_MAX)
    except (TypeError, ValueError, OverflowError):
        return False


# ── カスタムシグネチャの補助(名前・件数上限・正規化との食い違い) ──
# 最大件数(#59)。カスタム規則は prescan ゲートを通らず全要求の全走査窓で評価されるため、件数に
# 比例して全要求が遅くなる(実測 2000 件で 1 要求 17ms)。超過は追加を拒否し、読込時は無効化して残す。
_CUSTOM_SIG_MAX = 256
_CUSTOM_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
# 組込/構造検知の名前(小文字)。同名のカスタム規則は理由表示とヒット数が組込と混ざる(#29)。
_BUILTIN_SIG_NAMES = frozenset(
    [n for n, _p in _SIGNATURES] + list(_SIG_WEIGHT) + ["sqli-tautology", "sqli-stacked"])
# 組込署名の重複判定用コーパス一致集合。不変なので import 時に 1 度だけ求める(#32/#59)。
_SIG_CORPUS_SETS = tuple(
    (p, frozenset(i for i, s in enumerate(_DEDUP_CORPUS) if rgx.search(s)))
    for (_n, p), (_n2, rgx) in zip(_SIGNATURES, _SIG_RE))
# 走査面の正規化(_normalize_full)が書き換えるため、パターンに書いても決して一致しない字面(#30)。
_CUSTOM_LITERAL_LINTS = (
    (re.compile(r"%[0-9A-Fa-f]{2}"), "%XX は走査前に URL デコードされる(デコード後の文字で書く)"),
    (re.compile(r"\\\+|\[\+\]"), "'+' は走査前に空白へデコードされる"),
    (re.compile(r"\\[rn]|[\r\n]"),
     "改行(CR/LF)は走査前に、URL/ヘッダでは ';' へ、本文では空白へ置き換えられる"),
    (re.compile(r"&(?:#x?[0-9A-Fa-f]{1,7}|[A-Za-z][A-Za-z0-9]{1,31});"),
     "HTML 実体参照は走査前に復号される"),
)
# 保存済み optional_sigs の旧値(文字列)を読み替える真偽語(_load のみ・API は bool 以外を拒否・#57)
_BOOL_WORDS = {"true": True, "on": True, "yes": True, "1": True,
               "false": False, "off": False, "no": False, "0": False}


def _custom_re_flags(pattern: str) -> int:
    """カスタム規則のコンパイルフラグ。走査面は小文字化済みなので、大文字(または文字コード指定の
    エスケープ)を含む規則だけ IGNORECASE にする(#30)。大文字が無ければ大小区別の有無で一致は
    変わらず、IGNORECASE はリテラル前方一致の最適化を失って遅い(実測 256 件で 1 要求 +40%)。
    エスケープの英字(\\S \\W \\D \\B 等)は大文字に数えない。"""
    body = re.sub(r"\\.", "", pattern)
    if body != body.lower() or re.search(r"\\[xuUN0-7]", pattern):
        return re.IGNORECASE
    return 0


def _custom_pattern_warnings(pattern) -> list:
    """カスタム規則が走査面(正規化・小文字化済み)では当たり得ない書き方への警告(拒否はしない)。
    大文字は IGNORECASE で照合するので対象外(#30)。"""
    if not isinstance(pattern, str):
        return []
    return [msg for rx, msg in _CUSTOM_LITERAL_LINTS if rx.search(pattern)]


class _SigScan:
    """1 要求(または 1 本文)ぶんの署名走査の集計(#31)。
    組込署名+構造検知は従来どおり『最初のヒット』で確定する(組込の採点は変えない)。カスタム署名は
    それに隠されず全窓で評価し、最も重いものが組込より重ければそちらを採る(旧版は組込が先に当たると
    weight 1000 の規則も評価されず、組込の 50 点だけが入った)。逆に weight 0(監視のみ)の規則が
    当たっても組込の走査は止めない(止めると他フィールドの攻撃を見逃す)。"""
    __slots__ = ("hit", "weight", "c_hit", "c_weight", "rules")

    def __init__(self, rules):
        self.hit, self.weight = None, 0.0           # 組込/構造の初出ヒット
        self.c_hit, self.c_weight = None, -1.0      # カスタムの最重ヒット(-1=未。weight 0 も拾う)
        self.rules = rules                          # weight 降順のカスタム規則(走査中は固定)

    def floor(self) -> float:
        """これを超える weight のカスタム規則だけが結果を変えうる。"""
        return max(self.c_weight, self.weight if self.hit is not None else -1.0)

    def done(self) -> bool:
        """組込は確定し、結果を変えうるカスタム規則も残っていない。"""
        return self.hit is not None and not (self.rules and self.rules[0][3] > self.floor())

    def result(self):
        if self.c_hit is not None and (self.hit is None or self.c_weight > self.weight):
            return self.c_hit, self.c_weight
        return self.hit, self.weight


def _norm_path_limits(rules, default_rate: float):
    """パス別レート制限ルールを正規化したリストを返す。受理できない入力は None
    (配列以外、または非空なのに有効ルールが 0 件=入力ミス。既存ルールを黙って消さない)。"""
    if not isinstance(rules, (list, tuple)):
        return None
    norm = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        p = str(r.get("path", "")).strip()
        if not p:
            continue
        try:
            rate = float(r.get("rate", default_rate))
        except (TypeError, ValueError, OverflowError):
            continue
        if not math.isfinite(rate) or rate <= 0:     # NaN/inf はバケツが空にならない
            continue
        try:
            burst = float(r.get("burst", rate))
        except (TypeError, ValueError, OverflowError):
            burst = rate
        if not math.isfinite(burst):
            burst = rate
        norm.append({"path": p, "rate": rate, "burst": max(1.0, burst)})
        if len(norm) >= _PATH_LIMIT_MAX:
            break
    if rules and not norm:
        return None
    return norm


def _norm_blocked_methods(methods):
    """遮断メソッドを正規化して (norm, rejected) を返す。英字のみ・大文字化・重複除去。
    "TRACE,CONNECT" のような文字列は分解して受理し、それ以外の型は None。"""
    if isinstance(methods, str):
        methods = [m for m in methods.replace(",", " ").split() if m]
    elif not isinstance(methods, (list, tuple)):
        return None
    norm, rejected = [], []
    for m in methods:
        m = str(m).strip().upper()
        if m and m.isalpha() and len(m) <= 16 and m not in norm:
            norm.append(m)
        elif m:
            rejected.append(m[:16])
    return norm, rejected


def _dropped_elements(k: str, raw, kept):
    """_load(strict=False)が保存値の *一部の要素だけ* 捨てたときの記録用(フル版 #16 と同じ)。
    リスト/辞書キーの捨てた要素数を返す(捨てていなければ None)。重複の畳み込みは数えない
    (意味は変わらない)。キーごと捨てた場合は呼び出し側の keys に入る。"""
    if k == "blocked_methods":                 # _norm_blocked_methods の rejected は重複も含む
        items = raw.replace(",", " ").split() if isinstance(raw, str) else raw
        if not isinstance(items, (list, tuple)):
            return None
        bad = 0
        for m in items:
            m = str(m).strip().upper()
            if m and not (m.isalpha() and len(m) <= 16):
                bad += 1
        return bad or None
    if isinstance(raw, (list, tuple, dict)) and isinstance(kept, (list, dict)):
        lost = len(raw) - len(kept)
        return lost if lost > 0 else None
    return None


# site_mode="whitelist" の許可リスト(#85 r4)。_site_block は空の許可リストを評価しない=*全 Host
# 許可*(fail-open。ip/geo の許可リストは空=全遮断)。設定の入口では結果がこの組になる変更を拒否し、
# 旧版が保存した state だけは締め出さないよう従来どおり読み込んで status の warnings で知らせる。
_SITE_KEYS = ("site_mode", "site_whitelist")
_SITE_WL_EMPTY_CODE = "site_whitelist_empty"
_SITE_WL_EMPTY_ERR = ("site_mode=whitelist には site_whitelist が 1 件以上必要です"
                      "(空の許可リストは全 Host を許可してしまうため、この変更は適用していません)")


def _site_wl_empty(wl) -> bool:
    """許可リストが実質空か(_domain_match と同じ正規化で、照合に使える項目が 1 件も無い)。
    空白だけ/"." だけの項目も空とみなす(どの Host にも一致しない=設定ミス)。"""
    return not any(str(p).lower().strip().rstrip(".") for p in (wl or ()))


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


def _card_issuer_ok(d: bytes) -> bool:
    """主要ブランドの IIN(発行者番号の先頭)か(#26)。旧実装は先頭 3/4/5/6 なら何でも通したため、
    13 桁の JAN/EAN コード(45/49 始まり)や 16 桁の注文番号の約 1 割が Luhn を満たして
    credit_card と判定され、DLP block で商品一覧の応答が切れていた。
    Visa 4 / Mastercard 51-55・2221-2720 / Amex 34・37 / Discover 6011・644-649・65 /
    JCB 3528-3589 / Diners 300-305・36・38 / UnionPay 62 /
    Maestro 5018・5020・5038・5893・6304・6759・6761-6763・676770・676774 /
    RuPay 508500-508999・606985-607984・608001-608500(652150-653149 は 65 に含まれる)。
    Maestro と RuPay は前版が検出していたのに絞り込みで抜けていた(review #39)。登録された範囲だけを
    足す(50xx/60xx/63xx 全体は足さない=注文番号の誤検知を戻さない)。d は 14 桁以上の数字列。"""
    if d[:1] == b"4":
        return True
    p2, p3, p4, p6 = int(d[:2]), int(d[:3]), int(d[:4]), int(d[:6])
    return (51 <= p2 <= 55 or 2221 <= p4 <= 2720 or p2 in (34, 37, 36, 38, 62, 65)
            or p4 == 6011 or 644 <= p3 <= 649 or 3528 <= p4 <= 3589 or 300 <= p3 <= 305
            or p4 in (5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763)
            or p6 in (676770, 676774) or 508500 <= p6 <= 508999
            or 606985 <= p6 <= 607984 or 608001 <= p6 <= 608500)


def scan_secret_leak(data, start: int = 0, limit: int = None) -> list:
    """応答バイト列から *高確度の* 秘密情報漏洩を検出し、種別名のリストを返す(無ければ空)。
    資格情報は固有接頭辞、クレカは 14〜19 桁+主要ブランドの IIN+Luhn で誤検知を抑える
    (13 桁は JAN/EAN と衝突するので対象外・#26)。
    start/limit はストリームを窓に分けて走査する呼び出し側(proxy._pipe)用(#48): 一致の *開始位置*
    を [start, limit) に限り、data[start-1] と data[limit:] は前後の文脈としてだけ使う。窓の端を
    語境界(\\b)とみなさないので、読取の切れ目で長い数字列の途中がカード番号に見えることも、
    境界跨ぎの秘密を取りこぼすこともない(limit 以降に始まる一致は次の窓で判定する)。
    正直: 鍵を要する独自暗号で包まれた秘密は復号できない=対象外(register_scan_decoder の領域)。"""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if limit is None:
        limit = len(data)
    found = []
    for name, rgx in _SECRET_RES:
        m = rgx.search(data, start)
        if m is not None and m.start() < limit:
            found.append(name)
    for m in _CC_RE.finditer(data, start):
        if m.start() >= limit:
            break
        digits = bytes(c for c in m.group(0) if 48 <= c <= 57)
        if 14 <= len(digits) <= 19 and _card_issuer_ok(digits) and _luhn_ok(digits):
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
        self._ewma_n = 0                # 直近の畳み込み以降に来た要求数(同時刻の要求も数える・#41)
        self._started = _now()          # プロセス稼働開始時刻(uptime 算出・ダッシュボード)
        # 既知BAN IP の確率的プリスキャン(真O(k)・bytearray)。BAN時に add、判定は lock-free。
        self._ban_bloom = BloomFilter(capacity=max(2000, _MAX_IPS // 4))
        self._secret = secrets.token_bytes(16)
        # 可変状態ファイル(BAN/署名/設定/テレメトリ)の改竄耐性(#52/#53): 保存時に HMAC 署名し
        # 読込時に検証。鍵は再起動を跨ぐため永続(env DUCKNET_STATE_KEY 推奨・無ければ 0600 で生成)。
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
        self._bans_last_save = 0.0      # BAN 永続化の間引き用(直近書込時刻)
        self._bloom_rebuilt = 0.0       # BAN ブルーム再構築の間引き用(直近実行時刻)
        self._subnet_hot = 0            # hot サブネット数の短命キャッシュ(監視スクレイプ用)
        self._subnet_hot_ts = 0.0
        self._bloom_dirty = False       # 間引きで未反映の解除が残っているか
        self._bans_dirty = False        # 間引きで未書込の変更が残っているか
        self._bans_flush_timer = None   # 間引いた BAN 保存を後で書く一発タイマー(#48・高々1本)
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
        # 保存済みの要注意設定(旧版が保存し得た site_mode=whitelist + 空リスト等)は挙動を変えずに
        # 読み込み、起動時に 1 回だけ system イベントで知らせる(以後は status の warnings・#85 r4)。
        for w in self.config_warnings():
            self._event("system", w["code"], {"note": w["message"],
                                              "keys": list(w.get("keys") or ())})

    # ── 永続化 ───────────────────────────────────────────────────
    def _read_state(self, path: str, default, what: str, status_out: list | None = None):
        """署名付き状態を読み (value, migrate) を返す(#52)。改竄(署名不一致)は安全側 default に
        フェイルセーフし system イベントで警報。無署名(旧来)は生値を使いつつ migrate=True を返し、
        呼び出し側が再保存で署名済みへ移行する。攻撃者が書き換えた状態を *信頼しない* のが要点。
        status_out(list)を渡すと最終判定(ok/unsigned/missing/tampered/rolled_back/invalid)を
        1 件追記する(cfg の復元元・fail-closed 起動の判断用)。"""
        status, val = read_signed_json(path, self._state_key, default)
        seen = status
        if status in ("missing", "unsigned"):
            # 署名運用後の無署名出現=平文すり替えの疑い→改竄扱い(#53)。加えて #44: マーカー
            # (.state_signed)も状態ファイルも同じ書込可能ディレクトリにあり、消すだけで『初回起動/
            # レガシー移行』に見せかけられた(BAN 全消し・平文 cfg の受理が警報ゼロ)。この鍵で署名
            # 保存した実績(署名付きサイドカー .hw)が残っているのに欠損/無署名なら改竄とみなす。
            # 初回起動・署名導入前の移行には .hw が無いので従来どおり(誤警報なし)。正直な残余:
            # .hw まで含めて全部消されると初回起動と区別できない(外部の単調カウンタが要る)。
            from ..core.signed_state import has_signed_history
            if ((status == "unsigned" and self._state_signed_before)
                    or has_signed_history(path, self._state_key)):
                status, val = "tampered", default
        # 署名は「改竄されていない」ことしか保証しない。正しく署名された壊れた JSON や
        # 無署名の旧形式が配列/文字列/None でも呼び出し側は mapping 前提で .get() する。
        # 期待した形でなければ安全側の default に倒す(呼び出し側を全部守る)。
        if val is not None and not isinstance(val, type(default)):
            if status_out is not None:
                status_out.append("invalid")
            return default, False
        if status_out is not None:
            status_out.append(status)
        if status in ("tampered", "rolled_back"):
            # rolled_back = 古い正署名ファイルへの巻き戻し(#102)。署名は正しいが版が後退=拒否。
            reason = ("rollback(古い正署名への巻き戻し)" if status == "rolled_back"
                      else "fail-safe(default)")
            extra = {"file": os.path.basename(path), "status": status}
            if seen != status:
                extra["seen"] = seen          # missing=削除 / unsigned=平文すり替え
            try:
                self.report_tamper("state_tamper", what, reason, extra)
            except Exception:
                pass
            # 署名実績のあるファイルの *削除* は、警報したうえで migrate=True を返し、呼び出し側の
            # 再保存で fail-safe 値(state.json は既定値+防御有効)を署名保存させる(#19)。保存しないと
            # 起動のたびに同じ削除を警報し続けた(意図した初期化でも毎回 malicious が SIEM へ飛ぶ)。
            # 保存で .hw の版が進むので、再び消されれば再び警報する(=削除 1 回につき 1 回)。
            # 中身の改竄・すり替え・巻き戻し(ファイルが残る)は証拠を上書きせず従来どおり毎回警報。
            return default, (seen == "missing" and status == "tampered")
        if status == "missing":
            return default, False
        return (val if val is not None else default), (status == "unsigned")

    def _mark_state_signed(self):
        """署名運用マーカーを書く(初回 loads 後)。これ以降の起動では無署名ファイルの出現を
        平文すり替えとして改竄扱いする(#53)。失敗は無害に握る(マーカーは検知を強める保険)。"""
        try:
            if not os.path.exists(self._state_marker):
                with _open_state_write(self._state_marker, "w") as f:
                    f.write(str(int(_now())))
        except Exception:
            pass

    def _load(self, into: dict | None = None) -> str:
        """署名済み cfg を読み込む。into を渡すとその dict へ適用し(self.cfg には触れない)、
        無署名からの移行保存も呼び出し側に任せる。戻り値=state.json の判定(ok=署名検証済み /
        unsigned=旧来の無署名で移行が要る / missing / tampered / rolled_back / invalid)。
        起動時(into=None)に改竄・巻き戻し・署名実績のある欠損で読めず、しかも初回起動でない
        (この鍵で保存した実績 .hw か、起動前からの .state_signed マーカーがある)ときは、既定値の
        うえで shield を有効にして起動する(利用者判断の fail-closed。旧版は enabled=False の既定値で
        起動し、state.json を壊すだけで WAF を止められた)。警報は _read_state が出す。初回起動
        (実績なし)と、一度も保存していない欠損は従来どおり既定値(OFF)・警報なし。"""
        cfg = self.cfg if into is None else into
        st: list = []
        d, migrate = self._read_state(self.path, {}, "config", status_out=st)
        status = st[0] if st else "missing"
        d = d or {}
        # 版なし(=旧版)の保存値は cred_rate_score を読まない(#39)。旧版は cfg を全キー保存する
        # ので未配線だった頃の既定 40 が必ず残っており、配線後にそれを効かせると既存の導入で
        # 加点(=共有キーでの BAN 第三者転嫁)が突然有効になる。新版で明示した値は版付きで残る。
        legacy = not isinstance(d.get("rev"), int) or d["rev"] < _CFG_REV
        dropped, partial, renamed = [], {}, {}
        for k, v in (d.get("cfg") or {}).items():
            if legacy and k == "cred_rate_score":
                continue
            # 署名が正しくても値が壊れている場合がある(旧版の set_config は構造/NaN を素通しで
            # 保存していた)。API と同じ検証を通し、壊れた保存値で起動直後から全断させない。
            ok, nv = self._coerce_cfg(k, v, strict=False, base=cfg) if k in cfg else (False, None)
            if ok:
                cfg[k] = nv
                # 要素の一部だけ捨てたリスト/辞書も記録する(黙って消え、次の保存でファイルからも消えた)
                lost = _dropped_elements(k, v, nv)
                if lost:
                    partial[k] = lost
                # 旧版では効いていなかった綴りが正規化で効き始めるキー(#18・warnings で名指し)
                if isinstance(v, str) and nv != v and _ENUM_LEGACY_EFFECT.get(k, nv) != nv:
                    renamed[k] = nv
            elif k in cfg:
                dropped.append(k)                 # 不正な保存値=既定値のまま(黙って捨てない)
        if dropped or partial:                    # どのキー/要素を捨てたかだけ記録(値は載せない)
            ev = {"keys": sorted(dropped),
                  "note": "保存済みの不正な設定値は読まず既定値を使う"}
            if partial:
                ev["elements"] = partial          # キーごとの読まなかった要素数
                ev["note"] = ((ev["note"] + "。") if dropped else "") + (
                    "一部の要素を読まなかった(elements。次の保存で設定ファイルからも消えるので、"
                    "必要なら使える形で登録し直す)")
            self._event("system", "cfg_load_rejected", ev)
        if into is None:                          # 起動時の読込だけを warnings の根拠にする
            self._enum_renamed = renamed
        # BANは安全側で揮発(再起動でリセット)・設定のみ永続
        if into is None and status in ("tampered", "rolled_back"):
            from ..core.signed_state import has_signed_history
            if self._state_signed_before or has_signed_history(self.path, self._state_key):
                cfg["enabled"] = True             # 改竄で読めない=直前の値は不明。止めない側へ
                self._event("system", "cfg_fail_closed",
                            {"file": os.path.basename(self.path), "status": status,
                             "note": "state.json を検証できないため既定値+防御有効で起動"})
        # 旧来の無署名→署名済みへ移行。署名実績のある state.json の削除(#19)も、上の fail-closed を
        # 当てた後の cfg を保存する(次の起動で同じ削除を再警報せず、OFF にも戻らない)。
        if migrate and into is None:
            self._save()
        return status

    def _save(self) -> bool:
        with self._lock:
            ok = write_signed_json(self.path, {"cfg": self.cfg, "saved": _now(),
                                               "rev": _CFG_REV}, self._state_key)
            self._refresh_cfg_mac()           # #85: 正規変更のたびに整合 MAC を更新
            return ok

    def _cfg_blob(self) -> bytes:
        return json.dumps(self.cfg, sort_keys=True, separators=(",", ":"),
                          default=str).encode("utf-8", "replace")

    def _compute_cfg_mac(self, blob: bytes | None = None) -> str:
        """in-memory cfg の整合 MAC(#85)。プロセス毎ランダムな _secret で HMAC=メモリを書き換える
        攻撃者は MAC も併せて偽造する必要がある(secret もメモリから探さねばならない)。"""
        return hmac.new(self._secret, self._cfg_blob() if blob is None else blob,
                        hashlib.sha256).hexdigest()

    def _refresh_cfg_mac(self):
        # MAC を取った正規 cfg の直列化も保持する。ディスクの cfg を検証できない復元で既定値
        # (enabled=False)へ倒さず、ここへ戻す(使う前に同じ MAC で照合=すり替えは使わない)。
        blob = self._cfg_blob()
        self._cfg_mac = self._compute_cfg_mac(blob)
        self._cfg_good = blob

    def verify_cfg_integrity(self) -> dict:
        """in-memory cfg が *API を通さない out-of-band 改変*(デバッガ/プロセス注入によるメモリ
        すり替え)で書き換えられていないか検査する(#85)。正規変更は _save 時に MAC を更新するので、
        MAC 不一致=正規経路を通らない改変。検出したら署名検証済みディスク state から cfg を復元し
        (=最後の正規状態へ戻す)、memory_tamper を警報する。ディスクを検証できなければ最後に MAC が
        一致した cfg を保つ(戻り値 source=disk/memory/defaults)。AsyncEdgeGuard の独立した
        定期チェックループから呼ぶ。"""
        with self._lock:
            if hmac.compare_digest(self._compute_cfg_mac().encode("ascii", "ignore"),
                                   str(self._cfg_mac).encode("ascii", "ignore")):
                return {"ok": True, "tampered": False}   # #19: 定数時間 bytes 比較
            # 復元した cfg はローカルに組み立て、*1 回の代入* で差し替える(#42)。旧実装は先に
            # self.cfg を既定値(enabled=False)へ替えてからディスクを読んでいたため、その間に
            # ロック無しで is_enabled() を読む inspect()/proxy が『shield OFF』で素通ししていた。
            new = dict(_DEFAULTS)             # クリーン基準(型改変も確実に上書き)
            src = "disk"
            if self._load(into=new) != "ok":  # 署名検証済みディスクから再適用(=正規状態へ復元)
                # ディスクも欠損/改竄/巻き戻し/無署名で検証できない(メモリとの同時改竄)。旧実装は
                # 既定値(enabled=False)へ倒れて WAF が止まっていた。最後に MAC が一致した cfg を
                # 保ち、それも照合できなければ既定値+防御有効にする(利用者判断の fail-closed)。
                good = getattr(self, "_cfg_good", b"")
                try:
                    if not (good and hmac.compare_digest(
                            self._compute_cfg_mac(good).encode("ascii", "ignore"),
                            str(self._cfg_mac).encode("ascii", "ignore"))):
                        raise ValueError("unverified")
                    new, src = json.loads(good), "memory"
                    if not isinstance(new, dict):
                        raise ValueError("unverified")
                except Exception:
                    new, src = dict(_DEFAULTS), "defaults"
                    new["enabled"] = True
            self.cfg = new
            self._refresh_cfg_mac()
        action = {"disk": "restored-from-disk", "memory": "kept-last-verified",
                  "defaults": "fail-closed(defaults+enabled)"}[src]
        try:
            self.report_tamper("memory_tamper", "cfg", action)
        except Exception:
            pass
        return {"ok": True, "tampered": True, "restored": True, "source": src}

    # ── カスタムシグネチャ(ユーザー追加 / AI生成・SaaS継続アップデート) ──
    def _load_sigs(self):
        d, migrate = self._read_state(self._sig_path, {}, "signatures")
        d = d or {}
        # pattern が文字列であることも長さも見ずに再コンパイルへ渡していた。数値や巨大な
        # 文字列が入っていると _compile_custom で例外/過大コストになる。入口で弾く。
        # 名前も同様(#54): name 欠落は KeyError で NetShield() ごと起動不能、リスト名は inspect() の
        # ヒット集計で TypeError(=全要求が落ちる)になっていた。規則として成り立たない要素だけを
        # 捨て、*どれを* 捨てたかを system イベントで名指しする。weight 不正/長すぎ/ReDoS 等の
        # 『形は正しいが載せられない』規則は消さずに残し、無効として一覧へ出す(_compile_custom・#55。
        # 旧版は不正 weight の規則を黙って読み捨て、次の保存で rules.json からも消していた)。
        raw = d.get("signatures")
        report = []
        if raw is not None and not isinstance(raw, list):
            report.append({"name": None, "reason": "signatures が配列でない(全体を無視)"})
            raw = []
        custom = []
        for i, s in enumerate(raw or []):
            nm = s.get("name") if isinstance(s, dict) else None
            if not isinstance(s, dict):
                why = "規則がオブジェクトでない"
            elif not isinstance(nm, str) or not _CUSTOM_NAME_RE.fullmatch(nm):
                why = "name が不正(英数・._- の 1〜64 文字)"
            elif not isinstance(s.get("pattern"), str) or not 0 < len(s["pattern"]) <= 2000:
                why = "pattern が文字列でない/空/長すぎ(<=2000)"
            else:
                custom.append(s)
                continue
            report.append({"index": i, "reason": why,
                           "name": re.sub(r"[^A-Za-z0-9._-]", "?", nm)[:64]
                           if isinstance(nm, str) else None})
        self._custom = custom
        self._compile_custom()
        report += [{"name": v["name"], "reason": v["reason"]} for v in self._custom_view
                   if not v["active"] and v.get("enabled", True)]
        if report:
            self._event("system", "custom_sig_rejected",
                        {"count": len(report), "rules": report[:32],
                         "note": "読み込めない/無効なカスタムシグネチャ(一覧の active/reason を参照)"})
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
        # 載せない規則も消さずに残し、理由付きで一覧(list_signatures)へ出す(#55。旧版は件数しか
        # 出さず、どの規則が効いていないのか分からなかった)。件数上限(#59)も超過分を無効化する。
        # 大文字を含む規則は IGNORECASE でコンパイルする: 走査面は小文字化済みなので、旧版では
        # 永久に当たらなかった(#30・_custom_re_flags)。
        out, blocked, view = [], 0, []
        for s in self._custom:
            w = _sig_weight(s.get("weight", 40))
            why, rgx = "", None
            if not s.get("enabled", True):
                why = "無効(enabled=false)"
            elif w is None:
                why = "weight が不正(0 以上の有限の数値)"
            else:
                why = self.validate_pattern(s.get("pattern", ""))   # 危険(ReDoS等)/長すぎは載せない
                if not why and len(out) >= _CUSTOM_SIG_MAX:
                    why = f"件数上限({_CUSTOM_SIG_MAX})超過"
                if not why:
                    try:
                        rgx = re.compile(s["pattern"], _custom_re_flags(s["pattern"]))
                    except re.error as e:
                        why = f"正規表現エラー: {e}"
                if why:
                    blocked += 1
            v = dict(s)
            if w is None:
                v["weight"] = None             # NaN/inf をそのまま返すと管理画面の JSON が壊れる
            elif _sig_weight_capped(s.get("weight", 40)):
                v["weight"] = w                # 旧版が保存した上限超え: 一覧は実際に効く値を出す
            v["active"] = not why
            if why:
                v["reason"] = why
            view.append(v)
            if rgx is not None:
                cat = s.get("category", "custom")
                out.append((s["name"], cat if isinstance(cat, str) else "custom", rgx, w))
        # weight の降順(同値は登録順)。走査は重い順に当て、それ以下しか残らなければ打ち切る(#31)。
        out.sort(key=lambda t: -t[3])
        self._custom_re = out
        self._custom_blocked = blocked
        self._custom_view = view

    @staticmethod
    def validate_pattern(pattern: str) -> str:
        """カスタム正規表現の安全性検査。問題があれば理由文字列、無ければ空。
        ReDoS 判定は共通ライブラリ [[saferegex]] に委譲(単一の真実)。カスタム規則は
        さらに厳しめの 400 文字上限を課す。"""
        if not pattern or len(pattern) > 400:
            return "パターンが空/長すぎ(<=400)"
        return saferegex.lint(pattern)     # ネスト量化子/不正 → 理由文字列(安全なら "")

    def is_duplicate_pattern(self, pattern: str, exclude_name: str = "") -> bool:
        """完全一致 or 挙動同値(同一コーパスで一致集合が完全一致)なら重複。
        比べるのは組込と *稼働中* のカスタム規則のコンパイル済みパターンだけ(#32: 読込時に無効化した
        ReDoS パターンまで再コンパイルして実行し、追加のたびにプロセスが数秒止まっていた)。
        exclude_name の規則は置換される本人なので比べない(#58: 同名の編集が自分自身との重複で
        拒否されていた)。候補は live と同じフラグ(_custom_re_flags)で評価する。"""
        live = [rgx for n, _c, rgx, _w in self._custom_re if n != exclude_name]
        if any(pattern == p for p, _st in _SIG_CORPUS_SETS) or any(
                pattern == rgx.pattern for rgx in live):
            return True
        try:
            cand = re.compile(pattern, _custom_re_flags(pattern))
        except re.error:
            return False
        corpus = _DEDUP_CORPUS
        cand_set = frozenset(i for i, s in enumerate(corpus) if cand.search(s))
        if not cand_set:
            return False                       # 何も当たらない物は同値判定しない
        if any(st == cand_set for _p, st in _SIG_CORPUS_SETS):
            return True                        # 組込と挙動が同一=重複
        return any(frozenset(i for i, s in enumerate(corpus) if rgx.search(s)) == cand_set
                   for rgx in live)

    def add_signature(self, name: str, pattern: str, category: str = "custom",
                      weight: float = 40, source: str = "user") -> dict:
        """カスタムシグネチャを追加(検証+重複拒否+永続化+再コンパイル)。
        name は管理画面のテーブル/onclick属性へ後で埋め込まれるため、ここで許容文字を
        絞る(英数・._- のみ、1〜64字)。誤って緩めても呼び出し側(admin.py)は必ずエスケープ
        すること=多層防御(#111)。
        同名の規則があれば置き換える(=編集)。組込と同名は不可(#29: 理由表示とヒット数が組込と
        混ざる)。件数は _CUSTOM_SIG_MAX まで(#59)。走査面の正規化で当たらなくなる字面には
        warnings を返す(#30・拒否はしない)。"""
        if not isinstance(name, str) or not _CUSTOM_NAME_RE.fullmatch(name):
            return {"ok": False, "error": "name は英数・._- のみ、1〜64文字"}
        if name.lower() in _BUILTIN_SIG_NAMES:
            return {"ok": False, "error": f"name '{name}' は組込シグネチャと同名(別の名前にする)"}
        w = _sig_weight(weight)
        if w is None:
            return {"ok": False, "error": "weight は 0 以上の有限の数値"
                                          f"({_SIG_WEIGHT_MAX:g} を超える値は {_SIG_WEIGHT_MAX:g})"}
        err = self.validate_pattern(pattern) if isinstance(pattern, str) else "pattern は文字列"
        if err:
            return {"ok": False, "error": err}
        with self._lock:
            # 重複判定・上限確認・置換を同じロック下で行う(#58: 判定がロック外だと、同じパターンの
            # 並行追加が別名で両方通った)。比較は live のコンパイル済みだけ=軽い(#32)。
            if self.is_duplicate_pattern(pattern, exclude_name=name):
                return {"ok": False, "error": "重複(既存と同一/挙動同値)のため不採用"}
            others = [s for s in self._custom if s.get("name") != name]
            if len(others) >= _CUSTOM_SIG_MAX:
                return {"ok": False, "error": f"カスタムシグネチャは最大 {_CUSTOM_SIG_MAX} 件"
                        "(不要な規則を削除してから追加)"}
            self._custom = others + [{"name": name, "category": category,
                                      "pattern": pattern, "weight": w,
                                      "enabled": True, "source": source}]
            self._save_sigs()
            self._compile_custom()
            out = {"ok": True, "added": name, "total_custom": len(self._custom)}
        warns = _custom_pattern_warnings(pattern)
        if _sig_weight_capped(weight):        # 丸めた(拒否はしない)ことを返す
            warns.append(f"weight は上限 {_SIG_WEIGHT_MAX:g} として保存した"
                         f"(1 回の一致で block_score を大きく超える)")
        if warns:
            out["warnings"] = warns
        return out

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
                # 各規則に active(稼働中か)と、無効なら reason を付ける(#55)
                "custom": list(self._custom_view), "custom_active": len(self._custom_re),
                "custom_blocked": self._custom_blocked, "custom_max": _CUSTOM_SIG_MAX}

    def dry_run_signature(self, pattern, sample) -> dict:
        """カスタムシグネチャの試験(状態は一切変更しない)。live と同じ照合をする: サンプルを走査面と
        同じ正規化(_scan_windows)に通し、live と同じフラグでコンパイルしたパターンを当てる。旧版は生の
        サンプルへ re.search しており、%XX や大文字を含む『実際には永久に当たらない』規則を一致と
        表示していた(#30)。危険なパターン(ReDoS)は validate_pattern で弾き、コンパイルも照合もしない。"""
        if not isinstance(pattern, str):
            return {"ok": True, "matches": False, "error": "pattern は文字列"}
        err = self.validate_pattern(pattern)
        if err:
            return {"ok": True, "matches": False, "error": err}
        try:
            rgx = re.compile(pattern, _custom_re_flags(pattern))
        except re.error as e:
            return {"ok": True, "matches": False, "error": str(e)}
        wins = _scan_windows(str("" if sample is None else sample)[:4096],
                             fold_fw=bool(self.cfg.get("fold_fullwidth_punct")))   # live と同じ見え方
        out = {"ok": True, "error": None,
               "matches": any(saferegex.search(rgx, w, _MAX_SCAN) for w in wins),
               "normalized": wins[0][:512]}           # 照合した走査面(先頭)
        warns = _custom_pattern_warnings(pattern)
        if warns:
            out["warnings"] = warns
        return out

    def set_optional_signature(self, name: str, enabled: bool) -> dict:
        """高FPの任意シグネチャ(_OPTIONAL_SIGS)を個別にON/OFF。永続化する。"""
        if name not in _OPTIONAL_SIGS:
            return {"ok": False, "error": f"{name} はオプション対象でない(対象: "
                    f"{', '.join(sorted(_OPTIONAL_SIGS))})"}
        if not isinstance(enabled, bool):        # "false" を真値=ON と読まない(#57)
            return {"ok": False, "error": "enabled は true/false"}
        with self._lock:
            opt = dict(self.cfg.get("optional_sigs", {}))
            opt[name] = bool(enabled)
            self.cfg["optional_sigs"] = opt
            self._save()
        return {"ok": True, "name": name, "enabled": bool(enabled)}

    def set_paranoia(self, level) -> dict:
        """検知の段階的厳格度(1=保守〜4=最大)を1ダイヤルで設定。レベルに応じて高FPの任意
        シグネチャを一括ON(誤検知許容度に合わせる)。set_optional_signature で個別微調整も可
        (その場合 paranoia 値は最後に適用したプリセットを指す)。永続化する。
        検証は set_config と同じ _coerce_cfg(整数のみ・1〜4 へ clamp)。不正値は ok:False で拒否して
        現状を保つ(#56: 旧版は 'max'/null/3.7 等を 1(または切り捨て)に落として任意署名を全 OFF にし、
        apply_config はそれを applied と報告していた=宣言的設定の綴り違いで黙って検知が弱まった)。"""
        ok, level = self._coerce_cfg("paranoia", level)
        if not ok:
            return {**self.paranoia_status(), "ok": False,
                    "error": "paranoia は 1〜4 の整数"}
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
        with self._lock:            # 近隣の設定変更はすべてロック下。ここだけ素通しだった
            self.cfg["enabled"] = True
            self._save()
        return {"ok": True, "enabled": True}

    def disable(self) -> dict:
        # 書換と _save(MAC 更新)の間を整合チェック(verify_cfg_integrity・定期チェックループ)に
        # 覗かれると「改竄」と誤認されて enabled=True へ巻き戻され、偽の memory_tamper まで出る。
        with self._lock:
            self.cfg["enabled"] = False
            self._save()
        return {"ok": True, "enabled": False}

    def _coerce_cfg(self, k: str, v, strict: bool = True, base: dict | None = None):
        """設定 1 キーの値を検証・正規化して (受理可否, 値) を返す。管理 API(/api/shield/config)・
        宣言的設定(apply_config)・保存済み state の読込(_load)は *すべて* ここを通る
        (入口ごとに検証が違うと、緩い入口から壊れた値が入って inspect() が毎回例外=全断になる)。
        構造キーは専用セッターと同じ正規化関数に回し、数値は有限値のみ受理する(NaN/inf は
        レート制限を黙って無効化し、管理画面の JSON も壊す)。strict=False(_load)はリストの
        不正要素だけ捨てて残りを生かす。"""
        if k not in _DEFAULTS or v is None:
            return False, None
        dflt = _DEFAULTS[k]
        if k == "path_limits":                # base=組み立て中の cfg(_load(into=…)・#42)
            n = _norm_path_limits(v, float((self.cfg if base is None else base)
                                           .get("rate_per_sec", 20.0)))
            return n is not None, n
        if k == "blocked_methods":
            n = _norm_blocked_methods(v)
            return n is not None, (n[0] if n is not None else None)
        if k == "optional_sigs":
            # 任意シグネチャ名 → bool のみ(#57)。汎用の dict 規則(文字列/数値も可)のままだと、
            # 走査側は真偽値で ON/OFF を見るため "false"/"off"/"0" が ON になっていた(高FP署名を
            # 切ったつもりで点ける=正規の要求を遮断)。API(strict)は未知名・非 bool を含めば丸ごと
            # 拒否。保存済みの旧値(_load)は数値と明白な真偽語だけ読み替え、他は捨てる。
            if not isinstance(v, dict):
                return False, None
            good = {}
            for a, b in v.items():
                if a not in _OPTIONAL_SIGS:
                    continue
                if not isinstance(b, bool) and not strict:
                    b = (bool(b) if _finite_number(b) else
                         _BOOL_WORDS.get(b.strip().lower()) if isinstance(b, str) else None)
                if isinstance(b, bool):
                    good[a] = b
            return (len(good) == len(v) or not strict), good
        if isinstance(dflt, bool):          # bool は int の部分型。数値枠と相互に入らないよう先に判定
            return isinstance(v, bool), v
        if isinstance(dflt, (int, float)):
            if not _finite_number(v) or (isinstance(dflt, int) and not isinstance(v, int)):
                return False, None
            v = float(v) if isinstance(dflt, float) else v   # int→float は許容(GB/秒/日数)
            if k == "paranoia":
                v = max(1, min(4, v))                         # set_paranoia と同じ範囲
            elif k in _RATE_COUNT_KEYS and v > _RATE_COUNT_MAX:
                # API では拒否して知らせる。旧版は上限なしで受理し、巨大値(1億など)は『実質無効』の
                # 書き方として使われていた。保存済みの旧値を捨てると既定値(50 / 600)で 4xx 加点や
                # API キー遮断が突然効き始めるので、上限へ丸めて読む(上限でも実質発火しない)。
                if strict:
                    return False, None
                v = _RATE_COUNT_MAX
            elif k == "cadence_min_samples" and v > _CADENCE_SAMPLES:
                # 間隔は _CADENCE_SAMPLES 個しか溜まらない=超える値は周期性検知を黙って永久に
                # 無効化していた(#40)。API では拒否して知らせ、保存済みの旧値は上限へ丸める。
                if strict:
                    return False, None
                v = _CADENCE_SAMPLES
            if k in _POSITIVE_KEYS and v <= 0:
                return False, None
            if k in _NONNEG_KEYS and v < 0:
                if strict:
                    return False, None
                v = 0.0 if isinstance(dflt, float) else 0     # 旧版の保存値は読む側と同じく 0 へ
            return True, v
        if isinstance(dflt, str):
            if k in _ENUM_KEYS:
                c = _ENUM_CANON[k].get(v.strip().lower()) if isinstance(v, str) else None
                return c is not None, c
            if k in _HEADER_STR_KEYS:         # ヘッダへ書く値: 制御文字を拒否(_load では既定値へ)
                if not isinstance(v, str) or _CTRL_CHARS_RE.search(v):
                    return False, None
                if k == "origin_header":      # 名前の前後の空白は落とし、token だけ受理
                    v = v.strip(" ")
                    if not _HDR_TOKEN_RE.fullmatch(v):
                        return False, None
                return True, v
            return isinstance(v, str), v
        if isinstance(dflt, list):          # path_limits 以外のリストは文字列の配列
            if not isinstance(v, list):
                return False, None
            good = [e for e in v if isinstance(e, str)]
            return (len(good) == len(v) or not strict), good
        if isinstance(dflt, dict):          # optional_sigs / sec_headers_extra: 文字列キー→スカラー
            if not isinstance(v, dict):
                return False, None
            good = {a: b for a, b in v.items() if isinstance(a, str)
                    and (isinstance(b, (str, bool)) or _finite_number(b))}
            return (len(good) == len(v) or not strict), good
        return False, None

    def set_config(self, **kw) -> dict:
        changed, rejected, new = {}, [], {}
        with self._lock:
            old_paranoia = self.cfg.get("paranoia")
            for k, v in kw.items():
                if k not in self.cfg or v is None:
                    continue
                ok, v = self._coerce_cfg(k, v)
                if not ok:
                    rejected.append(k)      # 型/範囲/要素が不正=現状を保つ(黙って壊さない)
                    continue
                new[k] = v
            # 結果が site_mode=whitelist + 空の site_whitelist(全 Host 許可=fail-open)になる変更は、
            # 同じ呼び出しの他キーも含めて丸ごと拒否する(#85 r4・何も適用しない)。site 系に触れない
            # 変更は、旧版が保存した同じ組(互換で維持)に巻き込まない。
            if (any(k in new for k in _SITE_KEYS)
                    and new.get("site_mode", self.cfg.get("site_mode")) == "whitelist"
                    and _site_wl_empty(new.get("site_whitelist", self.cfg.get("site_whitelist")))):
                return {"ok": False, "changed": {}, "cfg": dict(self.cfg),
                        "rejected": [k for k in kw if k in self.cfg and kw[k] is not None],
                        "error": _SITE_WL_EMPTY_ERR}
            for k, v in new.items():
                self.cfg[k] = v; changed[k] = v
            # paranoia は set_paranoia と同じく段階プリセットも当てる(数値だけ変わって任意
            # シグネチャが連動しない食い違いを防ぐ)。optional_sigs を同時に明示したらそちら優先。
            p = changed.get("paranoia")
            if p is not None and p != old_paranoia and "optional_sigs" not in changed:
                self.cfg["optional_sigs"] = {n: True for n in _PARANOIA_TIERS[p]}
            self._save()
            if "geo_cidrs" in changed or "geo_mode" in changed:
                self._compile_geo()
        out = {"ok": bool(changed) or not rejected, "changed": changed, "cfg": dict(self.cfg)}
        if rejected:
            out["rejected"] = rejected
            if not changed:
                out["error"] = "不正な値のため拒否: " + ", ".join(rejected)
        return out

    # ── 宣言的設定ブートストラップ(evolution #27) ──
    def apply_config(self, d: dict) -> dict:
        """運用者が宣言した設定辞書(ファイル/ConfigMap)を *既存の検証済みセッター経由* で適用する。
        宣言的デプロイ(GitOps/k8s の immutable infra)向け。構造/段階キーは専用バリデータに回し、
        残りは set_config(既存キー・型一致のみ通す)。未知キーは無視。適用できたキー一覧(applied)と、
        不正値/誤設定で適用しなかったキー(rejected)・理由(errors)を返す。"""
        if not isinstance(d, dict):
            return {"ok": False, "error": "config is not an object", "applied": []}
        routed = {"path_limits": self.set_path_limits,
                  "blocked_methods": self.set_blocked_methods,
                  "paranoia": self.set_paranoia}
        applied, rest, rejected, errors = set(), {}, [], []
        for k, v in d.items():
            if k in routed:
                try:
                    r = routed[k](v)
                    # セッターが拒否(ok:False=現状維持)したキーを applied と報告しない
                    if not (isinstance(r, dict) and r.get("ok") is False):
                        applied.add(k)
                    else:
                        rejected.append(k)
                except Exception:
                    rejected.append(k)            # 不正値は捨てる(起動を止めない)
            elif k in self.cfg:
                rest[k] = v
        # site_mode/site_whitelist は別の呼び出しで適用する。結果が whitelist+空 になる宣言は
        # set_config が呼び出しごと拒否するので、同居させると無関係なキーまで落ちる(#85 r4)。
        site = {k: rest.pop(k) for k in _SITE_KEYS if k in rest}
        for part in (rest, site):
            if part:
                r = self.set_config(**part)
                applied.update(r.get("changed", {}).keys())
                rejected.extend(r.get("rejected") or [])
                if r.get("ok") is False and r.get("error"):
                    errors.append(r["error"])
        out = {"ok": True, "applied": sorted(applied)}
        if rejected:                              # 起動は止めず、適用しなかったキーと理由を返す
            out["rejected"] = sorted(set(rejected))
        if errors:
            out["errors"] = errors
        return out

    def apply_config_file(self, path: str) -> dict:
        """JSON 設定ファイルを読み込んで apply_config。空パス=no-op。読めない/JSON不正=エラー。
        起動時に env DUCKNET_CONFIG / CLI --config から呼ぶ(宣言的ブートストラップ)。"""
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
                  "intervals": deque(maxlen=_CADENCE_SAMPLES), "ban_started": 0.0,
                  "ban_count": 0,
                  # ゾーンは IP から一意に決まる不変値。ここで 1 度だけ解決して持ち回る
                  # (ダッシュボードが 2 秒ごとに全 IP ぶん ipaddress 解析するのを防ぐ)。
                  "zone": _zone_of(ip)}
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
        nonban = heapq.nsmallest(target, (kv for kv in self._ips.items()
                                          if not (kv[1]["ban_until"] > now)),
                                 key=lambda kv: kv[1]["seen"])
        for ip, _ in nonban:
            self._ips.pop(ip, None)
        # 時限BANも間引くのは、非BANだけでは *低水位(上限-1割)* に届かない時だけ(#15)。旧実装は
        # 『まだ満杯なら』だけ見ていたため、非BANが 1〜target-1 件だとそれだけ消して表は満杯の手前で
        # 止まり、以後は新規 IP 1 件ごとにロック下で全件走査し、直前に来た正規クライアントの状態まで
        # 次の新規 IP 1 件で消えていた。低水位まで落とせば 1 回の走査を多数の新規 IP で償却する。
        over = len(self._ips) - (_MAX_IPS - target)
        if over > 0:
            # (#8) 運用者の永続BANは決して捨てず、時限BANは *期限の近い順* に捨てる(失うBAN残り
            # 時間を最小に)。旧実装は最古 seen 順で、BAN 中は seen が更新されないため永続BANや
            # 長期制限が真っ先に消え、blocklist.json からも落ちていた(=表を埋めるだけで解ける)。
            inf = float("inf")
            rest = heapq.nsmallest(over, (kv for kv in self._ips.items()
                                          if kv[1]["ban_until"] != inf
                                          and not kv[1].get("permanent")),
                                   key=lambda kv: kv[1]["ban_until"])
            for ip, _ in rest:
                self._ips.pop(ip, None)

    def _decayed_score(self, st: dict) -> float:
        if not st["score"]:
            return 0.0                            # 0 の減衰は 0(pow を省く高速パス)
        hl = max(1.0, float(self.cfg["score_halflife_sec"]))
        dt = max(0.0, _now() - st["score_ts"])    # 時刻巻き戻し(NTP補正等)で decay が *反転して
        if dt < 0.05:                             # 高分解能クロックでの境界割れ防止: _add_score 直後の
            return st["score"]                    #   読み戻しで、微小 dt の減衰により score が閾値を
                                                  #   わずかに下回り BAN が不発になる(Linux 等)のを防ぐ。
        return st["score"] * (0.5 ** (dt / hl))   #   スコア膨張→誤BAN* するのを防ぐ(#44・単調減衰保証)

    def _add_score(self, st: dict, amount: float):
        st["score"] = self._decayed_score(st) + amount
        st["score_ts"] = _now()

    def _set_score(self, st: dict, value: float):
        """スコアを値で置き換える(即時BAN 系)。score_ts も必ず今にする(#37): 旧実装は score
        だけ書き、休んでいた IP では直後の読み戻しが休止時間ぶん減衰して 0 と報告されていた。"""
        st["score"] = float(value)
        st["score_ts"] = _now()

    def _early_block(self, ip: str, st: dict, reason: str, *, kind: str) -> dict:
        """inspect() の早期 return する遮断枝(メソッド/オーバーライド/Range/cred/ポリシー)の
        出口(#16)。その要求は flood 窓/トークンへ計上済みなので、それでスコアが block_score に
        達していれば通常経路の 5) と同じく BAN する(遮断され続けるクライアントも文書どおり
        flood→自動BAN に至り、以後は BAN 済みのプリスキャンで落ちる=毎回のフル走査を払わせない)。"""
        if self._decayed_score(st) >= float(self.cfg["block_score"]):
            return self._enforce_or_audit(
                ip, "block", st,
                f"スコア超過→BAN: {reason}(窓内 {len(st['window'])} 要求)",
                kind="ban", do_ban=True)
        return self._enforce_or_audit(ip, "block", st, reason, kind=kind)

    def _credential_rate(self, cred: str) -> int:
        """クレデンシャル(Bearer トークン/API キー)単位の窓内リクエスト数を返す(#70)。
        生のトークンは保持せず sha256 短縮ハッシュをキーにする(漏洩面/メモリ抑制)。マップは
        _CRED_RATE_CAP で有界(超過時は最古を間引く)。ロック内から呼ぶ。"""
        import hashlib
        h = hashlib.sha256(cred.encode("utf-8", "replace")).digest()[:12]
        now = _now()
        win = float(self.cfg.get("cred_rate_window_sec", 60))
        # deque の長さ=数えられる上限。固定 8192 だと cred_rate_limit>8192 が永久に不発だった。
        # 判定は『上限を *超えた* か』なので上限+1 件まで数えられる長さにする(#38)。
        cap = max(8192, min(int(self.cfg.get("cred_rate_limit", 600)), _RATE_COUNT_MAX) + 1)
        dq = self._cred_rate.get(h)
        if dq is None:
            if len(self._cred_rate) >= _CRED_RATE_CAP:    # 有界化: 最古挿入を1件落とす
                self._cred_rate.pop(next(iter(self._cred_rate)), None)
            dq = self._cred_rate[h] = deque(maxlen=cap)
        elif dq.maxlen < cap:                              # 閾値を引き上げた後の既存キー
            dq = self._cred_rate[h] = deque(dq, maxlen=cap)
        dq.append(now)
        cutoff = now - win
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    # ── 主判定(Webサーバ等が要求受理時に呼ぶ) ──────────────────────
    def _policy_block(self, ip: str, path: str, tls: bool) -> str:
        """ポリシー(拡張子/URL/TLS/geo)で遮断すべきなら理由を返す(無ければ空)。"""
        p = _path_for_match(path)            # %デコード+小文字化=エンコード回避を防ぐ(#40)
        # 遮断リストの小文字化を *リクエストごとに 1 件ずつ* やり直していた。結果は設定が
        # 変わらない限り同じなのでキャッシュし、拡張子は C 実装の endswith(tuple) 一発にする。
        exts = _lower_tuple(tuple(self.cfg.get("blocked_extensions") or ()))
        if exts and p.endswith(exts):
            hit = next((e for e in exts if p.endswith(e)), "")
            return f"拡張子ブロック: {hit}"
        for u in _lower_tuple(tuple(self.cfg.get("blocked_urls") or ())):
            if u in p:
                return f"URLブロック: {u}"
        if self.cfg.get("require_tls") and not tls:
            return "正規TLS以外(平文)を遮断"
        gm = self.cfg.get("geo_mode", "off")
        # allow(許可リスト)は *空でも* 評価する。旧実装は self._geo_nets が空だと
        # ブロックごとスキップし、「この地域だけ許可」の設定が黙って『全部許可』に
        # なっていた(CIDR を 1 つ綴り間違えただけで発生)。空の許可リスト=どこにも
        # 含まれない=全遮断、が allowlist の正しい意味で、ip_mode="whitelist" の
        # 既存挙動とも揃う。block はリストが空なら遮断対象なし=そのままで正しい。
        if (gm == "allow") or (gm == "block" and self._geo_nets):
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
            # 空の許可リストは評価しない=全許可(旧来挙動)。設定の入口では whitelist+空 を拒否し、
            # ここへ来るのは旧版が保存した state だけ(締め出さない・warnings で通知・#85 r4)。
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
            # 単一IPエントリは *正規形同士* で比べる(#45): 生文字列比較では '2001:DB8::1' や
            # 非圧縮表記のエントリが正規形の peer と一致せず、黒リストは素通り・白リストは締め出し。
            cip = _canon_ip(ip)
            if not cip:
                return False
            addr = ipaddress.ip_address(cip)
            try:
                singles, nets = _compile_ip_list(tuple(entries or ()))
            except TypeError:                # 設定に unhashable(dict 等)が混入していても照合は続ける
                singles, nets = _compile_ip_list(tuple(str(e) for e in entries or ()))
            if cip in singles:
                return True
            return any(addr.version == net.version and addr in net for net in nets)
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
        if r.get("ok") is False:
            # 拒否(whitelist 運用中に許可リストを空にする等・#85 r4)=何も変えていない。結果を
            # 見ずに ok:True を返すと、運用者は消せた/空にできたと誤解する。
            return {"ok": False, "list": key, "op": op,
                    "error": r.get("error") or "設定を拒否しました",
                    "entries": list(self.cfg.get(key) or [])}
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
            # BAN 決定は他の全経路と同じくロック下で(#82)。ロック外だと _save_bans の _ips 走査が
            # 管理スレッドの並行 ban() と衝突して RuntimeError になり、保存ごと失っていた。
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
        # Host から :port を外して宛先名にする。':' で単純に切ると IPv6 の Host
        # ('[2001:db8::1]:443' や素の '2001:db8::1')が '[2001' / '2001' に潰れていた。
        host = (host or "").strip().lower()
        if host.startswith("["):                       # [v6] / [v6]:port
            host = host[1:].partition("]")[0]
        elif host.count(":") == 1:                     # name:port(素の IPv6 はコロンが複数)
            host = host.partition(":")[0]
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
                if len(u["hosts"]) > _USAGE_HOSTS_CAP:  # IPあたりの宛先数を有界化(送出量上位を残す)
                    # 上限ちょうどまで刈ると、そのIPの *次のリクエスト* でまた全件ソートに
                    # なる(リクエスト数に対して二次)。低水位まで落として償却する。
                    u["hosts"] = dict(sorted(u["hosts"].items(),
                                             key=lambda kv: kv[1]["out"],
                                             reverse=True)[:_USAGE_HOSTS_LOW])
            # 見返せるログ(1接続=1行のjsonl・末尾回転)
            try:
                with _open_state_write(self._usage_log_path, "a") as f:
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
            with _open_state_write(self._usage_log_path, "w") as f:
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
        # 絞り込み前に *全行* を読み込んでいた。ログが育つほど 1 回の閲覧コストが増えるので、
        # 末尾から必要量だけ遡って読む共有ヘルパへ委譲する(ip/host 絞り込みで落ちるぶんを
        # 見越して多めに取る)。
        try:
            rows = tail_jsonl(self._usage_log_path,
                              max(1, limit) * (8 if (ip or host) else 2))
        except Exception:
            return out
        for e in rows:
            if not isinstance(e, dict):
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
                _open_state_write(self._usage_log_path, "w").close()
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

    def _scan_field(self, text: str, *, only: frozenset | None = None, acc=None,
                    body: bool = False, json_esc: bool = False):
        """1 フィールドを *全域* 走査する([[_scan_windows]] の各窓へ署名照合)。
        返値は _scan_signatures と同形 (name, weight) / (None, 0.0)。acc(_SigScan)を渡すと
        複数フィールド/本文の窓をまたいで集計する(組込は初出・カスタムは最重・#31)。
        body=True は要求本文用の正規化で窓を作り(改行を ';' にしない・[[_normalize_full]])、
        ';' 前提の検知に文脈を要求する本文用の照合で走査する(#2・[[_SIG_RE_BODY]])。
        本文の crlf・rce・スタック複文は、値に符号化して入れた改行(%0D%0A 等)を ';' にした見え方でも
        照合する([[_BODY_NL_RULES]]。値がリダイレクト先/Cookie/コマンド/SQL に入る時の注入=head と同じ形・
        #14)。その見え方は値の改行の後に照合対象の語が続く時だけ、同じ 1 回の正規化から作る(復号を
        やり直さない・[[_BODY_NL_LEAD]])。生の改行(YAML/テキスト/multipart の枠・部ヘッダの行の
        区切り)は ';' にしない=正規にヘッダの形をした部ヘッダの並びや、テキストの行頭の語は当たらない。
        全角の ｜ ＄ （ ） ； ｀ を畳むか(cfg fold_fullwidth_punct・既定 OFF)は本文も head もここで読む。
        json_esc=True(JSON 本文・[[_json_body]])は、その見え方でだけ JSON の短いエスケープ(\\r\\n 等)も
        値の改行として読む(他の検知が見る本文の走査面は変えない)。"""
        if acc is None:
            acc = _SigScan(self._custom_re)
        nl_rules = (tuple(r for r in _BODY_NL_RULES if only is None or r[0] in only)
                    if body else ())
        nl_wins = [] if nl_rules else None       # 値の改行を ';' にした見え方の窓(要る時だけ入る)
        for _w in _scan_windows(text, body=body, nl_views=nl_wins,
                                fold_fw=bool(self.cfg.get("fold_fullwidth_punct")),
                                json_esc=json_esc and body):
            self._scan_into(_w, acc, only=only, body=body)
            if acc.hit is not None and (only is not None or acc.done()):
                break
        if nl_wins and acc.hit is None:
            for _w in nl_wins:
                for _name, _rgx, _wt in nl_rules:
                    if saferegex.search(_rgx, _w, _MAX_SCAN):
                        acc.hit, acc.weight = _name, _SIG_WEIGHT.get(_name, _wt)
                        break
                if acc.hit is not None:
                    break
        return acc.result()

    def _scan_into(self, blob: str, acc, *, only: frozenset | None = None, body: bool = False):
        """1 窓を acc(_SigScan)へ走査する。組込は未ヒットの間だけ当て、カスタム規則は結果を
        変えうる(現在の最重より重い)ものだけを当てる。規則は weight 降順=最初の一致が最重(#31)。
        カスタム規則は prescan ゲートを通さず常時評価(needle に無いため)。body は組込へ渡す。"""
        if acc.hit is None:
            acc.hit, acc.weight = self._scan_builtin(blob, only=only, body=body)
        if only is None and acc.rules and blob:
            floor = acc.floor()
            # 未ヒット(良性トラフィックの大半)は全規則が対象=weight 比較を省いた素の走査
            rules = (acc.rules if floor < 0 else
                     [r for r in acc.rules if r[3] > floor])
            for name, _cat, rgx, w in rules:
                if saferegex.search(rgx, blob, _MAX_SCAN):
                    acc.c_hit, acc.c_weight = name, w
                    break

    def _scan_signatures(self, blob: str, *, only: frozenset | None = None, body: bool = False):
        """1 窓の最終判定(組込の初出ヒットと、それより重いカスタム署名の重い方)。
        (name, weight) or (None, 0.0)。weight は常に具体値(カスタムの 0=監視のみ を含む)。
        body=True は要求本文用の照合(';' 前提の検知に文脈を要求する・#2)。"""
        acc = _SigScan(self._custom_re)
        self._scan_into(blob, acc, only=only, body=body)
        return acc.result()

    def _scan_builtin(self, blob: str, *, only: frozenset | None = None, body: bool = False):
        """1走査面(正規化済み文字列)への組込署名/構造検知。(name, weight) or (None, 0.0)を返す。
        prescan ゲート付き builtin署名 + 構造検知(恒真式/スタック/XSSハンドラ)。カスタム署名は
        _scan_into が別に集計する(組込の初出ヒットに隠されないように・#31)。
        evolution #39 でフィールド独立走査のため inspect から切り出した(挙動は従来どおり)。
        only: 指定時はこの名前集合の builtin 署名『だけ』を判定する専用フィールド走査
        (#FP: scanner_ua/sensitive_path・_FIELD_SCOPED_SIGS)。カスタム署名/構造検知はスキップ
        (専用フィールド走査は特定カテゴリの的確な判定が目的で、汎用の意味的検知とは別関心)。
        only=None(既定=汎用走査)では _FIELD_SCOPED_SIGS に属す名は評価しない(専用呼び出し
        でのみ判定=フィールド混成による誤検知を避ける)。
        body=True は要求本文用: rce の ';' 分岐・crlf・スタック複文に文脈を要求する(#2。本文の ';' は
        CSV の区切りや地の文の句読点でもある)。head(URL/ヘッダ)の判定は変えない。"""
        if not blob:
            return None, 0.0
        # 高速プレフィルタ(Rust継ぎ目でnative化可)。核語が皆無なら高価な正規表現を丸ごとスキップ
        # (スーパーセット保証=取りこぼさない)。良性トラフィックの大半はここで終了。
        from ..core import accel
        if accel.prescan_suspicious(blob.encode("utf-8", "replace")) > 0:
            opt = self.cfg.get("optional_sigs", {})
            for name, rgx in (_SIG_RE_BODY if body else _SIG_RE):
                if only is not None:
                    if name not in only:
                        continue                 # 専用フィールド走査=指定カテゴリのみ判定
                elif name in _FIELD_SCOPED_SIGS:
                    continue                     # 汎用走査では専用フィールド系は判定しない(#FP)
                if name in _OPTIONAL_SIGS and not opt.get(name):
                    continue                     # 高FPシグネチャは cfg で有効化された時のみ評価
                _g = _SIG_GUARD.get(name)
                if _g is not None and not any(_lit in blob for _lit in _g):
                    continue                 # 必須リテラル皆無=マッチ不能。高価な走査を省く
                if saferegex.search(rgx, blob, _MAX_SCAN):   # 入力上限で ReDoS 面積を有界化
                    return name, _SIG_WEIGHT.get(name, 30)
        if only is not None:
            return None, 0.0                     # 専用フィールド走査はここまで(カスタム/構造検知は対象外)
        # 意味的検知: literal シグネチャをすり抜けた恒真式 SQLi(2=2 / 'x'='x')/スタック複文 /
        # ハンドラ型 XSS(<svg onload=)を *構造* で捕捉。
        if _tautology_suspect(blob):
            return "sqli-tautology", _SIG_WEIGHT.get("sqli-tautology", 35)
        if _stacked_query_suspect(blob, body=body):
            return "sqli-stacked", _SIG_WEIGHT.get("sqli-stacked", 40)
        if _xss_event_handler_suspect(blob):
            return "xss", _SIG_WEIGHT.get("xss", 45)
        return None, 0.0

    def inspect(self, ip: str, *, path: str = "", method: str = "GET",
                user_agent: str = "", query: str = "", zone: str = "",
                tls: bool = True, host: str = "", headers: str = "",
                header_names=None, auth: str = "", cred="",
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
        # path/query/UA を *各々独立フィールド* として走査面へ(#39 拡張)。主走査面
        # (path?query UA の連結)は末尾で _MAX_SCAN 切り詰めされるため、path を 8192 まで
        # 膨らませるだけで後続の query/UA が走査面外へ押し出され、その中の Log4Shell/SQLi/XSS
        # が全一般署名を回避できた(実証済バイパス。UA は最後尾ゆえ最も容易)。各フィールドを
        # 個別に持てば、どれか1つを padding しても他は自分の budget で必ず一般署名走査される
        # (scanner_ua/sensitive_path は下のフィールド限定走査が別途担当)。
        for _f in (path, query, user_agent):
            if _f:
                _targets.append(_f)
        _targets.extend(h for h in (headers or "").split("\n") if h)
        _wins0 = _scan_windows(_targets[0],        # 主走査面(全域を窓分割=切り詰めない)
                               fold_fw=bool(self.cfg.get("fold_fullwidth_punct")))
        blob = _wins0[0]                           # reason/後続参照の後方互換用(先頭窓)
        # 組込は初出ヒットで確定、カスタムは全フィールドで最重を集計(#31・_SigScan)
        _acc = _SigScan(self._custom_re)
        for _w in _wins0:
            self._scan_into(_w, _acc)
            if _acc.done():
                break
        # フィールド限定シグネチャ(#FP: scanner_ua/sensitive_path・_FIELD_SCOPED_SIGS)は上の汎用
        # 走査面(path+query+UA混成)からは除外済み。ここで各々の専用フィールド *単体* を対象に
        # 個別判定する(scanner_ua=user_agentのみ/sensitive_path=pathのみ)。bio等の自由記述
        # フィールド内の言及や、query/headers越しの言及では判定しない=意味論どおりのスコープ。
        if _acc.hit is None and user_agent:
            _acc.hit, _acc.weight = self._scan_field(user_agent, only=_UA_ONLY_SIGS)
        if _acc.hit is None and path:
            _acc.hit, _acc.weight = self._scan_field(path, only=_PATH_ONLY_SIGS)
        for _t in _targets[1:_MAX_SCAN_FIELDS]:    # ヘッダ各値を独立面として(必要分だけ)走査
            if _acc.done():
                break
            self._scan_field(_t, acc=_acc)         # 各値も全域(切り詰めない)
        sig_hit, sig_weight = _acc.result()
        # テレメトリ(ロック外で算出=ロック保持時間を伸ばさない)。method は攻撃者入力ゆえ
        # 既知メソッド名のみ採用し OTHER に畳む(辞書の無制限肥大を防ぐ)。
        # 旧実装は『英字 10 文字以下』なら何でも新しいキーにしていた=要求ごとに辞書が伸びた(#14)。
        mkey = method.upper() if method and len(method) <= 16 else ""
        if mkey not in _KNOWN_METHODS and mkey not in (self.cfg.get("blocked_methods") or ()):
            mkey = "OTHER"
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
            # 3)/4) の *計上*(flood 窓・+25 加点・トークン消費)は、下の早期 return する遮断枝より
            #      前で済ませる(#16)。旧実装は枝で返った要求を窓にもバケツにも数えなかったため、
            #      遮断され続けるクライアントは flood→自動BAN に至らず、BAN 済みを落とすプリスキャン
            #      (is_banned_fast)にも載らないまま、毎回フル走査+ロックを払わせていた。枝の出口
            #      (_early_block)はスコアが block_score に達していれば通常経路の 5) と同じく BAN する。
            #      理由文字列の並びは従来どおり(flood の理由は 3) の位置で足す)。
            w = st["window"]; w.append(now)
            ws = float(self.cfg["window_sec"])
            while w and w[0] < now - ws:
                w.popleft()
            flooding = len(w) > int(self.cfg["flood_threshold"])
            if flooding:
                self._add_score(st, 25)
            throttled = not self._take_token(st)
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
                return self._early_block(ip, st,
                    f"メソッド遮断: {(method or '').upper()[:16]}", kind="method_block")
            # 1.255) メソッドオーバーライド悪用(evolution #72): X-HTTP-Method-Override 等で実効
            #        メソッドを差し替える回避を塞ぐ。オーバーライド先にも blocked_methods を適用し、
            #        method_override_block ならオーバーライドヘッダの存在自体を遮断。
            ovr = (override_method or "").strip().upper()[:16]
            if ovr:
                if self.cfg.get("method_override_block"):
                    return self._early_block(ip, st,
                        f"メソッドオーバーライド禁止: {ovr}", kind="method_override")
                if mb and self.cfg.get("method_override_check", True) and ovr in mb:
                    return self._early_block(ip, st,
                        f"メソッド遮断(override): {ovr}", kind="method_block")
            # 1.256) パスオーバーライド ACL バイパス(evolution #73): X-Original-URL/X-Rewrite-URL は
            #        内部 rewrite 用。前段エッジにクライアントが送る=パス ACL 回避の手口=遮断。
            if override_path and self.cfg.get("path_override_block", True):
                return self._early_block(ip, st,
                    f"パスオーバーライド: {override_path[:60]}", kind="path_override")
            # 1.257) Range DoS(evolution #76): 多数レンジ(Apache Killer 系)でサーバに大量バッファを
            #        確保させる DoS を、レンジ数の上限で遮断。正規は 1〜2 レンジ=低FP。
            if range_header and self.cfg.get("range_check_enabled", True):
                if range_header.strip().lower().startswith("bytes="):
                    nr = range_header.count(",") + 1
                    if nr > int(self.cfg.get("range_max_ranges", 8)):
                        return self._early_block(ip, st,
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
            #       レートを集計。IP をローテーションしても同一キーの濫用は絞る。上限を *超えた*
            #       要求を遮断する(旧実装は >= で、上限 N に対し N-1 件しか通さなかった・#38)。
            #       cred は単一の識別子(str)か、要求に載った識別子の列。列なら *各々に* 計上し
            #       最大値で判定する(1 つだけ数えると、捨て値の Bearer を毎回変えて盗んだ
            #       X-API-Key で認証させる手口で識別子がローテーションし、上限が発動しなかった)。
            if self.cfg.get("cred_rate_enabled") and (_creds := _cred_ids(cred)):
                cr = max(self._credential_rate(c) for c in _creds)
                if cr > int(self.cfg.get("cred_rate_limit", 600)):
                    self._metrics["cred_rate_hit"] = self._metrics.get("cred_rate_hit", 0) + 1
                    # カウンタは *クレデンシャル共有* なのに、加点先は要求元 IP だった。
                    # 共有キー(モバイルアプリ埋込・フロントエンド公開キー・流出トークン)を
                    # 攻撃者が自分のホストから回して窓を超えさせ続ければ、同じキーを使う
                    # *正規利用者* の IP に毎回 +40 が乗り、数リクエストで BAN できた
                    # (第三者への BAN 転嫁)。既定は加点せず、超過した *その要求だけ* を絞る。
                    # BAN もスコアも残さないので巻き添えは一時的で回復する。IP 単位の濫用は
                    # 既存のレート制限/脅威スコアが引き続き担当する=検知能力は落ちない。
                    # キーが利用者ごとに固有の配備だけは cred_rate_score>0 で加点できる(#39)。
                    _crs = float(self.cfg.get("cred_rate_score", 0) or 0)
                    if _crs > 0:
                        self._add_score(st, _crs)
                    return self._early_block(
                        ip, st, f"クレデンシャル単位のレート超過({cr})", kind="cred_rate")
            # 1.265) JWT 検査(evolution #68): Bearer JWT の alg:none(無署名=認証バイパス)/
            #        許可外 alg(alg 混同攻撃)を遮断。署名検証はアプリ(鍵が無い)、ここは構造点検のみ。
            if self.cfg.get("jwt_inspect_enabled") and auth:
                jv = _jwt_violation(auth, self.cfg.get("jwt_allowed_algs"))
                if jv:
                    self._set_score(st, self.cfg["block_score"])     # score_ts も更新(#37)
                    return self._enforce_or_audit(ip, "block", st, "JWT: " + jv,
                                                  kind="jwt_block", do_ban=True)
            # 1.3) ポリシー(拡張子/URL/正規TLS以外/海外CIDR/サイト許可遮断)。監査なら通過+アラート。
            pol = (self._policy_block(ip, path, tls) or self._site_block(host)
                   or self._ip_list_block(ip))
            if pol:
                return self._early_block(ip, st, "ポリシー: " + pol, kind="policy_block")
            # 2) 侵入シグネチャ(ロック外で判定済み・組込/カスタム共通)を反映
            if sig_hit:
                # weight は走査が常に具体値で返す。`or 既定` は weight 0(監視のみ)を『未設定』と
                # 取り違えて 30 点(組込と同名ならその weight)を足していた(#22/#29)。
                self._add_score(st, float(sig_weight))
                reasons.append(f"signature:{sig_hit}")
            # 2.5) 低速・規則性(ステルスBot): 機械的に等間隔なアクセスを炙る(Floodに掛からない型)
            #      加点は *検知エピソードにつき 1 回*(規則的でない→規則的 に変わった時だけ。リズムが
            #      崩れたら再武装)。旧実装は間隔サンプルが規則的な間 *毎要求* 加点し、1 秒間隔の
            #      ポーリング(正規ブラウザの通知取得等)が約 10 秒で単発拒否→BAN になっていた。
            #      前回の加点が 1/16 に減衰する(半減期 x4・既定 120 秒)までは次のエピソードを加点
            #      しない: 休止を挟むポーリングでも、規則性だけで積み上がるのは cadence_score の
            #      約 1.07 倍まで(既定 35→37 < deny_score 40)。
            if self._cadence_botlike(st, now):
                if (not st.get("cadence_on")
                        and now - st.get("cadence_ts", 0.0)
                        >= 4.0 * max(1.0, float(self.cfg["score_halflife_sec"]))):
                    st["cadence_on"] = True
                    st["cadence_ts"] = now
                    self._add_score(st, float(self.cfg["cadence_score"]))
                    reasons.append("cadence:botlike")
            else:
                st["cadence_on"] = False
            # 3) flood(スライディングウィンドウ)。窓と加点は早期 return の前で計上済み(#16)。
            if flooding:
                reasons.append(f"flood:{len(w)}/{int(ws)}s")
            # 4) レート制限(トークンバケット)。消費は早期 return の前で計上済み(#16)。
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
        既存のスコア/減衰/BAN-TTL/bloom/イベントを再利用=新しい状態を増やさない。
        シールド OFF(完全パススルー)の間は何もしない(#28): inspect() と同じく本体スイッチに従う。
        旧実装は OFF でも slow-read/slowloris 等で加点・BAN・blocklist 保存まで行い、ON に戻した
        瞬間に OFF の間の BAN で正規利用者が 403 になった。"""
        if not ip or not self.is_enabled():
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
            if not self.is_enabled():
                # シールド OFF(完全パススルー)は集計のみ(#28)。旧実装は OFF でも加点・BAN して
                # blocklist に保存し、ON に戻した直後の要求を 403 にしていた。
                return {"action": "track"}
            if not (400 <= code < 500):
                return {"action": "track"}              # 加点対象はクライアントエラー(4xx)のみ
            now = _now()
            win = float(self.cfg.get("resp_error_window_sec", 60))
            thr = int(self.cfg.get("resp_error_threshold", 50))
            st = self._state(ip)
            dq = st.get("resp_err")
            cap = max(1024, min(thr, _RATE_COUNT_MAX))   # 固定 1024 だと閾値>1024 が永久に不発
            if dq is None or dq.maxlen < cap:
                dq = st["resp_err"] = deque(dq or (), maxlen=cap)
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

    def inspect_body(self, ip: str, body: bytes, *, content_type: str = "") -> dict:
        """要求ボディ先頭(有界)をシグネチャ走査して脅威スコアへ還元する(evolution #61)。
        head と同じ正規化+署名エンジンを使い、POST/JSON/GraphQL 本文に潜む SQLi/XSS/RCE/SSTI
        など head-only 検査の死角を捉える。block_score 超で BAN(enforce 時)。監査モードは記録のみ。
        proxy が本文先頭を読んでから(転送前に)呼ぶ。空/無効/ヒット無しは allow。
        content_type(要求の Content-Type・省略可)がバイナリ型で、走査する先頭の中身もバイナリなら
        署名走査せず allow(skipped="binary")にして metrics の body_binary_skipped に数える(T1)。"""
        if not self.is_enabled() or not self.cfg.get("body_scan_enabled") or not body:
            return {"action": "allow"}
        cap = int(self.cfg.get("body_scan_max_bytes", 65536))
        data = bytes(body[:cap])
        if content_type and _binary_ctype(content_type) and _BINARY_BYTE_RE.search(data):
            with self._lock:
                self._metrics["body_binary_skipped"] = (
                    self._metrics.get("body_binary_skipped", 0) + 1)
            return {"action": "allow", "skipped": "binary"}
        # 重複ウィンドウ走査(#61): _normalize_for_scan は _MAX_SCAN(8192)で頭打ちなので、本文を
        # _MAX_SCAN 窓 + 重複で刻んで *全域* を走査する。これが無いと先頭を無害パディングで埋めて
        # 後段の payload を走査外へ押し出す回避(#39 と同種)が本文で成立してしまう。窓数は cap で有界。
        # 本文は UTF-8 として読む(不正なバイトだけ latin-1・#8)。multipart は枠を外し、部の中身と
        # 部ヘッダを別フィールドにする(#0)。窓は本文用の正規化で作る(改行を ';' にしない・#0/#2)。
        try:
            text = _body_text(data)
            fields = _multipart_fields(text) or (text,)
        except Exception:
            fields = (data.decode("latin1", "replace"),)
        # JSON 本文なら、値の改行の見え方で JSON の短いエスケープ(\r\n 等)も読む(本文全体で決める=
        # 後ろの窓も同じ。multipart の部・フォーム・テキストの \n は字面のまま・[[_json_body]])
        js = len(fields) == 1 and _json_body(fields[0], content_type)
        win, overlap = _MAX_SCAN, 256
        _acc = _SigScan(self._custom_re)             # 組込は初出・カスタムは全窓の最重(#31)
        for field in fields:
            i = 0
            while i < len(field):
                try:
                    # 正規化 *後* を再度窓分割する: NFKC 展開(1 文字→最大 4 文字)で後半が
                    # 1 窓の外へ押し出されるのを防ぐ(生の窓の刻みだけでは足りない)。
                    self._scan_field(field[i:i + win], acc=_acc, body=True, json_esc=js)
                except Exception:
                    break
                if _acc.done():
                    break
                if i + win >= len(field):
                    break
                i += win - overlap                   # 重複=窓境界を跨ぐ payload も捉える
            if _acc.done():
                break
        sig_hit, weight = _acc.result()
        if not sig_hit:
            return {"action": "allow"}
        with self._lock:
            self._sig_hits[sig_hit] = self._sig_hits.get(sig_hit, 0) + 1
            st = self._state(ip)
            # weight 0(監視のみ)も係数 0(本文ヒットは記録のみ)も、`or 既定` で『未設定』扱いに
            # されて満額加点されていた(#22/#36)。係数は有限の 0 以上ならそのまま使う。
            factor = self.cfg.get("body_sig_weight_factor", 1.0)
            factor = max(0.0, float(factor)) if _finite_number(factor) else 1.0
            self._add_score(st, float(weight) * factor)   # 本文由来は確度を下げて誤BANを抑制
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

    def scan_upload(self, ip: str, body: bytes, content_type: str = "", *,
                    disposition=()) -> dict:
        """multipart アップロードの危険拡張子(webshell/実行体)を拒否する(evolution #66)。
        #61(本文シグネチャ)とは別関心=ファイル種別ポリシー。multipart の *パートヘッダ* の
        Content-Disposition(filename= / filename*= / RFC 2231 継続)だけを見る(フォーム値や本文中の
        'filename=' という文字列は対象外・#10)。content_type が multipart 以外なら対象外、空なら本文
        先頭行から境界を推定する。見るのは body の先頭 body_scan_max_bytes(proxy は残りを転送しながら
        upload_scanner で検査する・#33)。見つけたら加点(単発で遮断水準=BAN)。無効/該当無しは allow。
        disposition は *要求ヘッダ* の Content-Disposition の値(1 本の str か出現ごとの並び)。生本文
        アップロードの保存名として同じ拡張子規則で見る(T2・本文が空でも見る)。"""
        if not self.is_enabled() or not self.cfg.get("upload_scan_enabled"):
            return {"action": "allow"}
        deny = self.cfg.get("upload_deny_ext")
        hit = _disposition_upload_filename(disposition, deny) if disposition else None
        if not hit and body:
            cap = int(self.cfg.get("body_scan_max_bytes", 65536))
            hit = _dangerous_upload_filename(body, deny, cap, content_type)
        if not hit:
            return {"action": "allow"}
        return self.upload_violation(ip, *hit)

    def upload_scanner(self, content_type: str, sample: bytes = b"", chunked: bool = False):
        """本文を転送しながら全パートのヘッダを検査する逐次スキャナ(_UploadScan)を返す(#33)。
        アップロード検査が無効/拒否リストが空/multipart でない(境界が取れない)なら None。
        feed(生の本文バイト) が (filename, ext) を返したら upload_violation へ渡す。"""
        if not self.is_enabled() or not self.cfg.get("upload_scan_enabled"):
            return None
        deny = {str(e).lower().lstrip(".") for e in (self.cfg.get("upload_deny_ext") or [])}
        bnds = _mp_boundaries(content_type, sample) if deny else []
        return _UploadScan(bnds, deny, chunked) if bnds else None

    def upload_violation(self, ip: str, fn: str, ext: str) -> dict:
        """危険なアップロード(ext="" は検査できない壊れた/過大な multipart)を加点し遮断する。"""
        with self._lock:
            st = self._state(ip)
            self._add_score(st, float(self.cfg["block_score"]))   # 危険UL=単発で遮断水準
            score = self._decayed_score(st)
            reason = (f"危険なアップロード拡張子(.{ext}): {fn}" if ext
                      else f"検査できない multipart: {fn}")
            r = self._enforce_or_audit(ip, "block", st, reason, kind="upload_block",
                                       do_ban=True)
            act = r.get("action", "block")
            banned = st.get("ban_until", 0) > _now()
        return {"action": act if act in ("block", "throttle") else "score",
                "banned": banned, "ext": ext, "filename": fn, "score": round(score, 1)}

    def graphql_max_bytes(self, path: str) -> int:
        """この要求パスに GraphQL ガードが効くなら本文の上限(graphql_max_bytes)、効かなければ 0。
        proxy は >0 のとき本文をこの長さまで読み切って inspect_graphql へ渡す(#4)。"""
        if not self.is_enabled() or not self.cfg.get("graphql_enabled"):
            return 0
        if not _graphql_path(path, self.cfg.get("graphql_paths")):
            return 0
        try:
            return max(1, int(self.cfg.get("graphql_max_bytes", 262144)))
        except (TypeError, ValueError):
            return 262144

    def inspect_graphql(self, ip: str, path: str, body: bytes = b"", content_type: str = "",
                        complete: bool = True) -> dict:
        """GraphQL エンドポイントへの問い合わせを上限照合する(evolution #67)。深いネスト/複雑度/
        イントロスペクション/バッチ過大を遮断(リゾルバコスト爆発 DoS とスキーマ漏洩を防ぐ)。
        graphql_paths(正規化パスで前方一致・#6)にだけ適用。見るもの(#5): path のクエリ文字列の
        query=(GET)、本文(JSON/application/graphql/urlencoded の query 欄/multipart の operations 欄)。
        本文は全体(graphql_max_bytes まで)を解析する(#4)。上限を超える/読み切れない本文
        (complete=False)は検査できないので {"action": "reject", "status": 413}(加点しない・監査
        モードは記録のみ)。JSON の封筒なのに読めない本文と上限違反は block_score 加点(単発で遮断水準)。"""
        lim = self.graphql_max_bytes(path)
        if not lim:
            return {"action": "allow"}
        from .graphql import parse_body, form_queries, check
        body = bytes(body or b"")
        qs = (path or "").split("?", 1)[1].split("#", 1)[0] if "?" in (path or "") else ""
        url_q = form_queries(qs) if qs else []
        body_q, err, too_big = [], "", False
        bnds = _mp_boundaries(content_type) if content_type else []
        if bnds:              # graphql-multipart-request-spec: operations 欄が GraphQL(ファイルは対象外)
            ops = _multipart_field(body[:lim + 1], bnds, "operations")
            if ops is False:
                too_big = len(body) > lim or not complete    # operations が上限内で完結しない
            elif ops is not None:
                body_q, err = parse_body(ops, "application/json")
        elif not complete or len(body) > lim:
            too_big = True
        elif body:
            body_q, err = parse_body(body, content_type)
        if too_big:
            with self._lock:
                if self.cfg.get("mode") == "audit":
                    self._event(ip, "audit", {"would": "reject", "rule": "graphql_too_large",
                                              "reason": f"GraphQL 本文が graphql_max_bytes({lim})超"})
                    return {"action": "allow"}
                self._event(ip, "graphql_too_large", {"limit": lim})
            return {"action": "reject", "status": 413, "reason": "too-large"}
        if err:
            res = {"allowed": False, "reason": err}
        else:
            lims = dict(max_depth_limit=int(self.cfg.get("graphql_max_depth", 12)),
                        max_complexity=int(self.cfg.get("graphql_max_complexity", 1000)),
                        block_introspection=bool(self.cfg.get("graphql_block_introspection",
                                                              True)),
                        max_batch=int(self.cfg.get("graphql_max_batch", 10)))
            res = check(body_q, **lims)
            if res["allowed"] and url_q:
                res = check(url_q, **lims)
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
        # 配列以外(オブジェクト/文字列/None)や有効ルール 0 件の非空配列を [] に *置換* すると、
        # /login 等の既存ルールが ok:True のまま黙って消える。拒否して現状を保つ
        # (set_blocked_methods と同じ方針。正規化は set_config と共通=入口で食い違わない)。
        norm = _norm_path_limits(rules, float(self.cfg["rate_per_sec"]))
        if norm is None:
            return {"ok": False,
                    "error": "path_limits は {path, rate[, burst]} の配列で指定してください",
                    "path_limits": list(self.cfg.get("path_limits") or [])}
        with self._lock:
            self.cfg["path_limits"] = norm
            self._save()
        return {"ok": True, "path_limits": list(norm)}

    # ── HTTPメソッドポリシー(evolution #26) ──
    def set_blocked_methods(self, methods) -> dict:
        """遮断する HTTP メソッド一覧を *置換* で設定し永続化。英字のみ・大文字化・重複除去。
        空配列=無効。XST(TRACE/TRACK)/プロキシ濫用(CONNECT)等の低FPな異常メソッド向け。"""
        # 型が違う入力(宣言的設定の JSON で "TRACE,CONNECT" のような文字列を書いた等)を
        # 黙って [] として *置換* すると、遮断メソッドの設定が消えたまま ok:True が返り、
        # 運用者は防御が効いていると誤解する。受理できない型は拒否して現状を保つ。
        # 正規化は set_config と共通(/api/shield/config 経由の小文字が素通りしない)。
        n = _norm_blocked_methods(methods)
        if n is None:
            return {"ok": False, "error": "blocked_methods は配列で指定してください",
                    "blocked_methods": list(self.cfg.get("blocked_methods") or [])}
        norm, rejected = n
        with self._lock:
            self.cfg["blocked_methods"] = norm
            self._save()
        out = {"ok": True, "blocked_methods": list(norm)}
        if rejected:                          # 黙って捨てない(設定ミスを気づけるように)
            out["rejected"] = rejected
        return out


    # ── 出口DLP(evolution #6) ──
    def dlp_active(self) -> bool:
        """DLP が有効か(本体ON かつ dlp_enabled)。"""
        return self.is_enabled() and bool(self.cfg.get("dlp_enabled"))

    def scan_leak(self, data, start: int = 0, limit: int = None) -> list:
        """応答チャンクから秘密情報漏洩の種別を返す(DLP有効時のみ)。start/limit は
        scan_secret_leak と同じ(ストリームの窓走査・#48)。"""
        return scan_secret_leak(data, start, limit) if self.cfg.get("dlp_enabled") else []

    def dlp_effective_action(self) -> str:
        """DLP の *実効* 動作("block" / "audit")。全体 mode=audit(遮断せず記録のみ)の間は
        dlp_action=block でも記録だけにする(#51・旧実装は DLP だけが audit モードを無視して切断)。"""
        if self.cfg.get("dlp_action") == "block" and self.cfg.get("mode") != "audit":
            return "block"
        return "audit"

    def note_leak(self, ip: str, kinds: list) -> dict:
        """漏洩検出をイベント/メトリクス/種別内訳へ記録。action=block なら呼び出し側が残りを送らず切断。"""
        kinds = list(dict.fromkeys(kinds))[:8]      # 重複除去・上限
        action = self.dlp_effective_action()
        ev = {"kinds": kinds}
        if action != "block" and self.cfg.get("dlp_action") == "block":
            ev["would"] = "block"                   # 全体 audit モードで遮断を見送った(#51)
        with self._lock:
            self._metrics["dlp_leak"] = self._metrics.get("dlp_leak", 0) + 1
            for k in kinds:                         # 漏洩した秘密種別の累積内訳(テレメトリ)
                self._dlp_kinds[k] = self._dlp_kinds.get(k, 0) + 1
            self._event(ip, "dlp_leak", ev)
        return {"action": action, "kinds": kinds}

    def note_unscannable(self, ip: str, encoding: str) -> dict:
        """DLP が読めない符号化(gzip/br 等)の応答本文を記録する(#1)。DLP 有効時は backend へ
        Accept-Encoding: identity を渡すので通常は起きない。それでも圧縮で返った本文は秘密の有無を
        確かめられない=dlp_action どおり(block は送らず切断・audit は記録して通す)に扱う。"""
        action = self.dlp_effective_action()
        ev = {"encoding": str(encoding)[:40]}
        if action != "block" and self.cfg.get("dlp_action") == "block":
            ev["would"] = "block"
        with self._lock:
            self._metrics["dlp_unscannable"] = self._metrics.get("dlp_unscannable", 0) + 1
            self._event(ip, "dlp_unscannable", ev)
        return {"action": action}

    def _enforce_or_audit(self, ip, action, st, reason, *, kind="",
                          do_ban=False, ban_perm=False, **kw):
        """決定点の一元化。監査モードは遮断せず通過+アラート。enforce は必要ならBAN設定。"""
        if self.cfg.get("mode") == "audit":
            self._event(ip, "audit", {"would": action, "reason": reason[:120], "rule": kind})
            return self._out(ip, "allow", st, f"AUDIT(would {action}): {reason}")
        if do_ban:
            st["ban_count"] = st.get("ban_count", 0) + 1       # 累犯回数(エスカレーション用)
            now = _now()
            cur = st.get("ban_until", 0.0)
            # 既存のより長いBAN(運用者の永続BAN・restrict の長期制限・エスカレーション済み)を
            # 短い自動BANで *上書きしない*(#7)。penalize/note_response/record_traffic 等は BAN 中の
            # IP からも呼ばれ、旧実装は永続BANを ban_ttl_sec に縮めて blocklist へも書いていた。
            perm = bool(ban_perm) or cur == float("inf") or (bool(st.get("permanent")) and cur > now)
            if perm:
                new_until = float("inf")
            else:
                ttl = float(self.cfg["ban_ttl_sec"])
                if self.cfg.get("ban_escalation", True):       # 累犯ほど長く(初回 n=1 は据置)
                    cap = int(self.cfg.get("ban_escalation_cap", 64) or 1)
                    ttl *= min(max(1, cap), 2 ** min(st["ban_count"] - 1, 30))
                new_until = now + ttl
            if new_until > cur:                  # 新規/延長のときだけ BAN 期間と開始時刻を更新
                st["ban_until"] = new_until
                st["ban_started"] = now
            st["permanent"] = perm
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
            # 上限 *ちょうど* まで削ると、次の 1 件でまた全件ソートになり、BAN 件数に対して
            # 二次コストになる。低水位まで一気に落として 1 回のソートを多数の BAN で償却する。
            for k, _ in sorted(rec.items(), key=lambda kv: kv[1])[:len(rec) - _SUBNET_IP_LOW]:
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
        """サブネット集約防御の可視化(有効/追跡数/hot数/設定)。読み取り専用。
        hot 数の算出は O(サブネット数 x サブネット内IP数)。分散攻撃で表が埋まると
        1 回 16ms(上限では約 50ms)かかり、これを監視系のスクレイプ(/api/metrics)
        が叩くたびにロックを握ったまま繰り返していた。粗いゲージなので短命キャッシュで十分。"""
        with self._lock:
            now = _now()
            window = float(self.cfg.get("subnet_window_sec", 3600) or 0)
            thr = int(self.cfg.get("subnet_threshold", 8) or 0)
            ttl = float(self.cfg.get("subnet_status_cache_sec", 2.0) or 0)
            if ttl > 0 and (now - self._subnet_hot_ts) < ttl:
                hot = self._subnet_hot
            else:
                hot = sum(1 for rec in self._subnets.values()
                          if (len(rec) if window <= 0
                              else sum(1 for t in rec.values() if now - t <= window)) >= thr)
                self._subnet_hot, self._subnet_hot_ts = hot, now
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
        # 要求を 1 件数え、時刻が進んだ時に『前回からの件数 / 経過』でまとめて畳み込む(#41)。
        # 旧実装は dt<=0 で何も数えずに返していたため、粗い壁時計(Windows の 15.625ms 刻み等)で
        # 同じ時刻を共有した要求が全部捨てられ、1000 req/s でも EWMA が ~60 で頭打ちになっていた。
        self._ewma_n += 1
        now = _now()
        dt = now - self._ewma_last
        if dt < 0:                           # 壁時計の巻き戻し(NTP 補正等): 基準を付け替える
            self._ewma_last = now            # (追い付くまで凍結→追い付いた瞬間に跳ねる、を防ぐ)
            return
        if dt == 0:
            return                           # 同じ刻み: 件数だけ溜めて次の刻みで畳み込む
        inst = self._ewma_n / dt
        alpha = 1 - 0.5 ** (dt / 5.0)        # 5秒半減のEWMA
        self._ewma = (1 - alpha) * self._ewma + alpha * inst
        self._ewma_last = now
        self._ewma_n = 0

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
        if (mean <= 0
                or mean < float(self.cfg.get("cadence_min_mean_interval", 0.01))
                or mean > float(self.cfg["cadence_max_mean_interval"])):
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
            for ip, st in self._ips.items():
                bu = st.get("ban_until", 0.0)
                if bu and bu != float("inf") and bu > thr:   # 停止時点で有効だった時限BAN
                    st["ban_until"] = bu + gap; n_ban += 1
                    # 停止中に wall-clock で切れた BAN は、復帰後の再構築でブルームから落ちている
                    # ことがある。延長したら戻さないと is_banned_fast が偽陰性になる(#45)。
                    self._ban_bloom.add(ip)
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
        key = _canon_cfg_ip(ip)               # fe80::1%eth0 は peer と同じ fe80::1 を BAN
        if not key:
            # 生文字列を鍵にすると空白付き/大文字/非圧縮 IPv6 は正規形の peer と一致せず、一覧に
            # 載るのに何も遮断しない BAN になっていた(#25/#45)。単一IP以外(CIDR 等)は拒否する。
            return {"ok": False,
                    "error": "単一のIPアドレスを指定してください(範囲/CIDR はファイアウォールのルールで遮断)"}
        ip = key
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
        r = self.ban(ip, ttl_sec=ttl_sec)
        if not r.get("ok"):
            return r
        ip = r["banned"]                  # 正規形で記録(遮断ページの申告は peer=正規形で引く)
        with self._lock:
            self._restrictions[ip] = {"ts": _now(), "report": "", "user_ok": False,
                                      "admin_ok": False, "status": "restricted"}
        self._event(ip, "restricted", {})
        return {"ok": True, "restricted": ip,
                "note": "解除には状況報告書の提出+管理者承認の双方合意が必要。"}

    def submit_report(self, ip: str, report: str) -> dict:
        """ユーザー側: 状況報告書を提出する→管理者へアラート。"""
        ip = _canon_ip(ip) or ip              # restrict は正規形で記録する(#45)
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
        ip = _canon_ip(ip) or ip              # restrict は正規形で記録する(#45)
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
        # 共有 _restrictions の読取+status 書込はロック下で行う(#D12: submit_report/admin_confirm は
        # 各自の with 内で他フィールドを書くが、_maybe_release は従来ロック外で status を書き、
        # list_restrictions 等の並行読取と競合していた)。unban/_event は I/O を伴うのでロック外へ。
        with self._lock:
            r = self._restrictions.get(ip)
            released = bool(r and r["user_ok"] and r["admin_ok"])
            if released:
                r["status"] = "released"
            status = r["status"] if r else "?"
            need_user = not (r and r["user_ok"])
            need_admin = not (r and r["admin_ok"])
        if released:
            self.unban(ip)
            self._event(ip, "restriction_released", {})
            return {"ok": True, "released": True, "status": "released",
                    "note": "双方合意により解除されました。"}
        return {"ok": True, "released": False, "status": status,
                "need": {"user_report": need_user, "admin_confirm": need_admin}}

    def list_restrictions(self) -> list:
        with self._lock:
            return [{"ip": ip, **v} for ip, v in self._restrictions.items()]

    def unban(self, ip: str) -> dict:
        # 表記ゆれでも同じIPを解除する(#45)。旧版が生の綴りで保存した IP でない鍵(CIDR 等)も
        # 一覧の綴りそのままで解除できるよう、正規形と生文字列の両方を引く。
        key = _canon_cfg_ip(ip)               # ban と同じくゾーンID付きも peer の形で引く
        raw = ip if isinstance(ip, str) else ""
        hit = False
        with self._lock:
            for k in {key, raw, raw.strip()} - {""}:
                st = self._ips.get(k)
                if st:
                    hit = True
                    st["ban_until"] = 0.0; st["score"] = 0.0; st["permanent"] = False
                # 解除=運用者が誤BANと判断 → サブネット hot 集計からも外す(#84)。残すと同じ /24・/64 の
                # 新規ユーザに subnet:hot の加点が窓(既定1時間)のあいだ付き続けた。
                sk = _subnet_key(k)
                rec = self._subnets.get(sk) if sk else None
                if rec is not None and rec.pop(k, None) is not None:
                    if not rec:
                        self._subnets.pop(sk, None)
                    self._subnet_hot_ts = 0.0       # hot 数の短命キャッシュも捨てる
            if not key and not hit:
                return {"ok": False, "error": "単一のIPアドレスを指定してください"}
            self._save_bans()
        # ブルームは単一ビット削除不可→現役BANから作り直して陳腐ビットを落とす(偽陽性率を保つ)
        self.rebuild_ban_bloom()
        return {"ok": True, "unbanned": key or raw}

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
        # 共有 _appeals の読取+変更をロック下で行う(#D12: 従来 resolve_appeal は無ロックで
        # status/resolved_ts/note を書き、list_appeals/analysis の並行読取と競合していた)。
        # unban/_event は I/O を伴うのでロック外へ。status はロック内で確定させて後段で使う。
        with self._lock:
            ap = self._appeals.get(ip)
            if not ap:
                return {"ok": False, "error": f"申立が無い: {ip}"}
            status = "approved" if approve else "denied"
            ap["status"] = status
            ap["resolved_ts"] = _now()
            ap["note"] = note
        if approve:
            self.unban(ip)
        self._event(ip, "appeal_" + status, {})
        return {"ok": True, "ip": ip, "status": status}

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
        _zones = ["loopback", "private", "public", "special", "unknown"]
        zc = {z: 0 for z in _zones}
        # 旧実装は全 IP(最大 _MAX_IPS=20000)ぶんの dict を作り、IP ごとに ipaddress で
        # ゾーンを解析し直し、全件ソートしてから先頭 n 件だけ返していた。しかもこれを
        # グローバルロックを握ったまま行うため、2 秒ごとのダッシュボード更新が inspect() を
        # 止めていた(実測 105ms/回・攻撃者は送信元を増やすだけで N を伸ばせる)。
        # ゾーンは状態にキャッシュ済みの不変値を使い、上位 n 件だけ heap で選ぶ。
        top = []
        with self._lock:
            for ip, s in self._ips.items():
                z = s.get("zone")
                if z is None:                     # 旧バージョンから引き継いだ状態の補完
                    z = s["zone"] = _zone_of(ip)
                zc[z] = zc.get(z, 0) + 1
                ent = ((s["ban_until"] > now, round(self._decayed_score(s), 1),
                        len(s["window"])), ip, s["hits"], bool(s.get("permanent")), z)
                if len(top) < n:
                    heapq.heappush(top, ent)
                elif ent[0] > top[0][0]:
                    heapq.heapreplace(top, ent)
        rows = [{"ip": ip, "zone": z, "score": k[1], "banned": k[0],
                 "permanent": perm, "reqs_window": k[2], "hits": hits,
                 "mac": macs.get(ip, "")}
                for k, ip, hits, perm, z in sorted(top, reverse=True)]
        return {"center": "DuckNet-Lite", "nodes": rows,
                "zones": zc}

    def apt_report(self, n: int = 15) -> dict:
        """APT級の兆候を既存シグナルから形式化(アプリ層・低速持続/規則性/累積攻撃の相関)。
        正直: エンドポイントEDRではない=ネット越し挙動からの推定。スコア化して上位を返す。"""
        now = _now()
        ranked = []
        with self._lock:
            for ip, s in self._ips.items():
                iv = s["intervals"]
                nv = len(iv)
                base = self._decayed_score(s)
                # 規則性/居座りの加点(計 55)は間隔サンプルが 6 本ないと成立しない。
                # 6 本未満なら apt は base + hits 加点で決まるので、閾値に届かない状態は
                # ここで足切りする。旧実装は全 IP ぶん deque を list へコピーしていた
                # (実測 9.0ms/回・ロック内・2 秒ごと)。
                if nv < 6 and base + min(40, s["hits"] * 8) < 30:
                    continue
                ivs = list(iv) if nv >= 6 else ()
                regular = False
                if nv >= 6:
                    mean = sum(ivs) / len(ivs)
                    if 0 < mean <= 5.0:
                        var = sum((x - mean) ** 2 for x in ivs) / len(ivs)
                        regular = (var ** 0.5) / mean < 0.2
                span = now - s.get("first", now)
                persistent = span > 300 and nv >= 6            # 5分以上 等間隔で居座る
                apt = base + (30 if regular else 0) + (25 if persistent else 0) \
                    + min(40, s["hits"] * 8)
                if apt >= 30:
                    ranked.append({"ip": ip, "apt_score": round(apt, 1),
                                   "zone": s.get("zone") or _zone_of(ip),
                                   "regular_beacon": regular,
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
        raw = d.get("bans")
        merged = set()                            # この読込で既に復元したアクティブBAN(別綴りの合流用)
        for ip, b in (raw.items() if isinstance(raw, dict) else ()):
            # 1 エントリでも壊れていると、以前は起動時に例外で落ちて *防御が上がらなかった*。
            # 壊れた行だけ捨てて残りを復元する(BAN 表全体を失わない)。
            if not isinstance(b, dict) or not isinstance(ip, str):
                continue
            # 旧版は手動BANの生の綴り(大文字/非圧縮 IPv6・空白付き)を鍵に保存していた(#45)。
            # 正規形へ寄せて実際の peer と一致させる。IP でない旧鍵(CIDR 等)はそのまま読む
            # (一覧に出して解除できるように)。
            ip = _canon_cfg_ip(ip) or ip          # ゾーンID付きの旧鍵も peer の形へ(fe80::1%eth0)
            try:
                until = float("inf") if b.get("permanent") else float(b.get("until") or 0)
                cnt = int(b.get("count") or 0)
                started = float(b.get("started") or now)
            except (TypeError, ValueError):
                continue
            if ip in merged:                      # 同じIPの別綴り: 長い方の BAN を残す
                st = self._ips.get(ip)
                if st is not None and st["ban_until"] >= until:
                    st["ban_count"] = max(int(st.get("ban_count", 0)), cnt)
                    continue
            if not b.get("permanent") and until <= now:
                # 期限切れBAN: 累犯回数だけ保持窓内なら復元(エスカレーションを再起動越しに継続)。
                if cnt > 0 and retain > 0 and (now - started) <= retain:
                    st = self._state(ip)
                    st["ban_count"] = cnt
                    st["ban_started"] = started
                continue                          # BAN自体は復元しない(掃除)
            st = self._state(ip)
            if ip in merged:
                cnt = max(int(st.get("ban_count", 0)), cnt)
            merged.add(ip)
            st["ban_until"] = until
            st["ban_started"] = started
            st["permanent"] = bool(b.get("permanent"))
            st["ban_count"] = cnt
            self._ban_bloom.add(ip)
        if migrate:                               # 旧来の無署名 blocklist→署名済みへ移行
            self._save_bans()

    def _save_bans(self, force: bool = False):
        """BAN 表をディスクへ。新規BANのたびに全件を JSON 化して fsync する実装だったため、
        BAN 表が育つほど 1 回の書込が重くなり(実測: 20000 件で 3.2MB / 133ms)、しかもそれを
        グローバルロックを握ったまま行っていた。多数の送信元(IPv6 /64 で十分)で囮URLを踏んで
        BAN 表を膨らませれば、以後は毎秒数リクエストで全通信を止められる=DoS になっていた。
        そこで最小間隔で間引く(未書込は _bans_dirty に残し、次の保存/flush_state で必ず出す)。
        force=True は shutdown 等の確実に書き切りたい場面用。"""
        if not self.cfg.get("persist_bans"):
            return
        now = _now()
        self._bans_dirty = True
        iv = float(self.cfg.get("ban_persist_min_interval_sec", 2.0) or 0)
        big = len(self._ips) >= int(self.cfg.get("ban_persist_debounce_from", 512) or 0)
        if not force and big and iv > 0 and (now - self._bans_last_save) < iv:
            # 間引いた変更は残り間隔の経過後に *必ず* 書く(#48)。以後 BAN/解除が来ないと誰も
            # _bans_dirty を拾わず、クラッシュ/強制終了で直近の BAN(永続含む)や解除が消えていた。
            # 遅延は最大 iv(時計の巻き戻しで now-last が負になっても間引きが長引かない)。
            self._schedule_bans_flush(min(iv, iv - (now - self._bans_last_save)))
            return                      # 表が小さいうちは従来どおり即時保存(耐久性優先)
        self._bans_last_save = now
        self._bans_dirty = False
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
        if not write_signed_json(self._bans_path, {"bans": bans, "saved": now}, self._state_key):
            self._bans_dirty = True     # 書けなかった=未書込のまま(次の保存/flush_state で再試行)

    def _schedule_bans_flush(self, delay: float):
        """間引いた BAN 保存を delay 秒後に 1 回だけ書く一発タイマー(#48)。保留中は張り直さない
        (スレッドは高々 1 本)。state_dir が消えていれば書かない(作り直さない)。ロック内から呼ぶ。"""
        if self._bans_flush_timer is not None:
            return

        def _fire():
            try:
                with self._lock:
                    self._bans_flush_timer = None
                    if self._bans_dirty and os.path.isdir(os.path.dirname(self._bans_path)):
                        self._save_bans(force=True)
            except Exception:
                pass

        t = threading.Timer(max(0.0, delay) + 0.05, _fire)
        t.daemon = True
        self._bans_flush_timer = t
        try:
            t.start()
        except RuntimeError:            # スレッドを起こせない(資源枯渇)=次の保存/flush_state に委ねる
            self._bans_flush_timer = None

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
            self._save_bans(force=True)     # 間引きを無視して必ず書き切る
            # traffic/usage も間引き付きで書いているので、停止時に force しないと
            # 直近の集計(最大 15 秒ぶん)が毎回失われる。
            for _fn in (getattr(self, "_save_traffic", None),
                        getattr(self, "_save_usage", None)):
                if _fn is None:
                    continue
                try:
                    _fn(force=True)
                except Exception:
                    pass
        return {"ok": True, "persisted": bool(self.cfg.get("persist_bans"))}

    def is_banned_fast(self, ip: str) -> bool:
        """既知BANかを **ロックなし・ほぼO(1)** で判定(プリスキャン用)。
        ブルーム miss=確実に未BAN(即 False)。hit のみ厳密確認(GIL原子の辞書read)で確定。
        陳腐ビット(期限切れ)による偽陽性は厳密確認が弾く=正規ユーザーを誤って落とさない。"""
        if ip not in self._ban_bloom:
            return False
        st = self._ips.get(ip)               # GIL原子の読み取り(state変更なし=ロック不要)
        return bool(st and st["ban_until"] > _now())

    def rebuild_ban_bloom(self, force: bool = False) -> dict:
        """現役BANだけからブルームを作り直す(陳腐ビットを落として偽陽性率を保つ)。
        unban のたびに全 _ips(最大 20000)を舐め直していたため、ダッシュボードの「全解除」
        (BAN 1 件ごとに /api/shield/unban を投げる)が O(BAN数 x 追跡IP数)になっていた
        (実測: BAN 5000 件で合計 46.5 秒・その間グローバルロックを取り合う)。
        陳腐ビットは *偽陽性にしかならず* is_banned_fast が必ず _ips で確認するため、
        作り直しを遅らせても遮断判定は一切変わらない。最小間隔で間引く。"""
        now = _now()
        iv = float(self.cfg.get("bloom_rebuild_min_interval_sec", 2.0) or 0)
        if not force and iv > 0 and (now - self._bloom_rebuilt) < iv:
            self._bloom_dirty = True          # 次回の呼び出しでまとめて作り直す
            return {"ok": True, "deferred": True}
        self._bloom_rebuilt = now
        self._bloom_dirty = False
        nb = BloomFilter(capacity=max(2000, _MAX_IPS // 4))
        with self._lock:
            for ip, s in self._ips.items():
                if s["ban_until"] > now:
                    nb.add(ip)
            # 公開もロック内で行う。外に出すと、スナップショットと差し替えの間に
            # 記録された BAN がブルームから落ち、is_banned_fast が素通しにしてしまう。
            self._ban_bloom = nb
        return {"ok": True, "bloom": nb.info()}

    def maintain_ban_bloom(self) -> dict:
        """BAN ブルームの周期保守(#46)。周期 tick(traffic_stall_check)から呼ぶ。
          · 解除の連打で間引いた再構築(_bloom_dirty)を最小間隔の経過後に消化する。以前は
            『次回の呼び出し』=次の unban まで誰も消化せず、陳腐ビットが残り続けた。
          · 自然失効した BAN は unban を通らないので一度もブルームから落ちず、長期稼働で飽和して
            (est_fp_rate→1)安価な否定フィルタとして効かなくなっていた。前回の再構築から
            bloom_refresh_sec(既定 300 秒)経つか、追加数が設計容量に達したら作り直す。
        O(追跡IP数) の作り直しは高々この周期ごと=要求のホットパスには載せない。"""
        if self._bloom_dirty:
            return self.rebuild_ban_bloom()    # 最小間隔内なら再び deferred=次の tick で消化
        bf = self._ban_bloom
        if not bf.n:
            return {"ok": True, "idle": True}
        refresh = float(self.cfg.get("bloom_refresh_sec", 300.0) or 0)
        if bf.n >= bf.capacity or (refresh > 0 and _now() - self._bloom_rebuilt >= refresh):
            return self.rebuild_ban_bloom()
        return {"ok": True, "idle": True}

    # ── 記録/指標 ──
    def _event(self, ip, kind, extra):
        self._events.append({"ts": _now(), "ip": ip, "kind": kind, **extra})

    def traffic_stall_check(self, now: float = None) -> dict:
        """迂回検知 / dead-man's switch(#78)。AsyncEdgeGuard の独立した定期チェックループから
        周期的に呼ぶ。直近の区間が busy
        (>= stall_min_rate)だったのに *今区間で1件も通っていない* なら、再ルーティング等で
        DuckNet を迂回された疑いとして警報する。busy→ゼロ の遷移のみ=自然な低トラフィックや
        graceful な停止では鳴らない。返り値 {"stall": bool, ...}。
        周期 tick に便乗して BAN ブルームの保守(maintain_ban_bloom・#46)も回す。"""
        try:
            self.maintain_ban_bloom()            # 失敗しても迂回検知は続ける
        except Exception:
            pass
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
        now = _now()
        # 旧実装は全 IP ぶんの dict を作ってから全件ソートしていた(実測 15.6ms/回・ロック内)。
        # 2 秒ごとのダッシュボード更新で回るので、上位 n 件だけ heap で選ぶ(O(N log n))。
        with self._lock:
            top = heapq.nlargest(n, (
                (round(self._decayed_score(s), 1), len(s["window"]), ip,
                 s["hits"], s["ban_until"] > now)
                for ip, s in self._ips.items()))
        return [{"ip": ip, "score": sc, "reqs_window": rw, "hits": hits, "banned": banned}
                for sc, rw, ip, hits, banned in top]

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

    def config_warnings(self) -> list:
        """壊れてはいないが運用者が直すべき設定の一覧([{code, keys, message, message_en}]・無ければ空)。
        message は日本語、message_en は同じ内容の英文(英語表示のダッシュボードが優先して出す)。
        · site_whitelist_empty(#85 r4): site_mode=whitelist なのに site_whitelist が空=全 Host を
          許可している。設定の入口では拒否するが、旧版が保存した state は締め出し回避のため維持。
        · cfg_enum_normalized(#18): 旧版が保存した列挙値の綴り('Whitelist' 等)を正規化して読み、
          旧版では効いていなかった設定がこの版で効き始めた。運用者が別の値にしたキーは外す
          (設定を保存し直せば正規の綴りで残るので、次の起動からは出ない)。"""
        out = []
        if self.cfg.get("site_mode") == "whitelist" and not self.cfg.get("site_whitelist"):
            out.append({"code": _SITE_WL_EMPTY_CODE, "keys": list(_SITE_KEYS),
                        "message": "site_mode=whitelist ですが site_whitelist が空のため、全 Host を"
                                   "許可しています(以前の版で保存された設定を互換のため維持)。"
                                   "許可する Host を site_whitelist に追加するか、site_mode を off に"
                                   "してください。",
                        "message_en": "site_mode=whitelist but site_whitelist is empty, so every Host "
                                      "is allowed (a setting saved by an earlier version, kept for "
                                      "compatibility). Add the Hosts to allow to site_whitelist, or "
                                      "set site_mode to off."})
        ren = {k: v for k, v in (getattr(self, "_enum_renamed", None) or {}).items()
               if self.cfg.get(k) == v}
        if ren:
            keys = sorted(ren)
            now = ", ".join(f"{k}={ren[k]}" for k in keys)
            was = ", ".join(f"{k}={_ENUM_LEGACY_EFFECT[k]}" for k in keys)
            empty = [lk for (k, v), lk in _ALLOW_LIST_OF.items()
                     if ren.get(k) == v and not self.cfg.get(lk)]
            out.append({"code": _ENUM_NORM_CODE, "keys": keys,
                        "message": f"以前の版で保存された設定の綴り(大文字小文字・前後の空白)を正規化し、"
                                   f"{now} として読み込みました。以前の版はこの綴りを認識せず {was} と"
                                   f"同じ動作でしたが、この版では設定どおりに効きます。"
                                   + (f"{', '.join(empty)} が空のため、該当する送信元をすべて遮断します。"
                                      if empty else "")
                                   + "意図した設定か確認し、違えば変更してください(設定を保存し直すと"
                                     "次の起動からこの警告は出ません)。",
                        "message_en": f"Settings saved by an earlier version were spelled differently "
                                      f"(letter case or surrounding spaces); they were normalized and "
                                      f"are now read as {now}. Earlier versions did not recognize that "
                                      f"spelling and behaved as {was}; this version applies the "
                                      f"settings as written. "
                                      + (f"{', '.join(empty)} {'is' if len(empty) == 1 else 'are'} "
                                         f"empty, so every client is blocked. " if empty else "")
                                      + "Check that this is what you want and change it if not "
                                        "(after you save the settings again, this warning no longer "
                                        "appears from the next start)."})
        return out

    def status(self) -> dict:
        from ..core.i18n import t as _t
        return {"cfg": dict(self.cfg), "metrics": self.metrics(),
                "bans": self.bans(),
                "optional_signatures": sorted(_OPTIONAL_SIGS),  # 任意(高FP)シグネチャ名一覧
                "warnings": self.config_warnings(),             # 要注意の設定(#85 r4)
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
