"""monitor.py — 送信ネットワークの安全ガード(SSRF防御・URL秘匿・資格情報除去)
================================================================================
他PJ(MITのマルチチャネルAIゲートウェイ)の『network policy』の良所を **クリーンルームで蒸留**
(コードはコピーせず思想を Python 標準ライブラリで再実装・名称も刷新)。防御AIの web_fetch/
外部取得が **SSRF(Server-Side Request Forgery)** で内部資産やクラウドメタデータに到達するのを防ぐ。

機能:
  · `classify_ip/is_blocked_ip` = ループバック/プライベート/リンクローカル/マルチキャスト/予約/
    未指定 + **クラウドメタデータIP**(169.254.169.254 等)をブロック対象に分類(標準ライブラリ ipaddress)。
  · `check_host/check_url` = ホスト名を解決し、**いずれかの解決先が危険レンジなら拒否**
    (DNSリバインディング/名前→内部IP の SSRF を遮断)。スキームは http/https のみ許可。
  · `redact_url` = token/key/secret/password 等の **機微クエリを秘匿**(ログ漏えい防止)。
    Unicodeフィラーでキー名を分断して検出を逃れる回避も正規化して無効化(アンチエベイジョン)。
  · `strip_userinfo` = URL の user:pass@ を除去。`safe_url` = 秘匿+資格情報除去(ログ用)。

正直/安全: ブロックは『内部到達を防ぐ』専守防衛。許可リスト(allow_*)で正当な用途は通す。
攻撃用途(内部探索の補助等)は提供しない。出典なし=オフライン。
"""
from __future__ import annotations
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .kb_common import tokens


# ── クラウドのインスタンスメタデータ(SSRFの主要標的) ──────────────────────────
# link-local(169.254/16, fe80::/10)で大半は捕捉されるが、明示でも弾く。
_CLOUD_METADATA_IPS = {
    "169.254.169.254",     # AWS/GCP/Azure/Oracle IMDS
    "100.100.100.200",     # Alibaba Cloud
    "fd00:ec2::254",       # AWS IPv6 IMDS
    "fe80::a9fe:a9fe",     # 一部環境の IPv6 リンクローカル表現
}

# ── 機微なクエリ名(URLに埋まる資格情報) ──────────────────────────────────────
_SENSITIVE_QUERY = {
    "token", "key", "api_key", "apikey", "secret", "access_token", "auth_token",
    "password", "pass", "passwd", "auth", "jwt", "session", "id_token", "code",
    "client_secret", "app_secret", "hook_token", "refresh_token", "signature",
    "x_amz_signature", "x_amz_security_token", "private_key", "credential",
    "authorization", "sig", "sas", "sig_token", "access_key", "secret_key",
}
# キー名分断によるアンチ検出回避を無効化(制御文字/空白/Unicodeフィラー/プラスを除去)
_QUERY_NAME_SEP_RE = re.compile(r"[\s\x00-\x1f\u115f\u1160\u3164\uffa0\u200b-\u200f\u202a-\u202e\ufeff+\-]+")

_REDACTED = "[REDACTED]"


def _norm_query_name(name: str) -> str:
    """クエリ名を正規化(小文字化+分断文字除去+ -/_ 統一)して機微判定に使う。"""
    import urllib.parse as _up
    try:
        n = _up.unquote(name)
    except Exception:
        n = name
    n = _QUERY_NAME_SEP_RE.sub("", n).lower()
    return n.replace("-", "_")


# ══ IP 分類 ══════════════════════════════════════════════════════════════════
def classify_ip(ip_str: str) -> dict:
    """IP文字列を分類する。{ok, category, blocked, reason}。解析不能は ok:False。"""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except Exception as e:
        return {"ok": False, "error": f"IP解析不能: {e}"}
    cat, blocked = "global", False
    if ip_str.strip() in _CLOUD_METADATA_IPS or str(ip) in _CLOUD_METADATA_IPS:
        cat, blocked = "cloud_metadata", True
    elif ip.is_unspecified:
        cat, blocked = "unspecified", True
    elif ip.is_loopback:
        cat, blocked = "loopback", True
    elif ip.is_link_local:
        cat, blocked = "link_local", True
    elif ip.is_multicast:
        cat, blocked = "multicast", True
    elif ip.is_private:
        cat, blocked = "private", True
    elif ip.is_reserved:
        cat, blocked = "reserved", True
    elif getattr(ip, "is_site_local", False):
        cat, blocked = "site_local", True
    return {"ok": True, "ip": str(ip), "version": ip.version, "category": cat,
            "blocked": blocked,
            "reason": (f"{cat} は内部到達の恐れ(SSRF)= ブロック" if blocked else "グローバル")}


def is_blocked_ip(ip_str: str, *, allow_unique_local: bool = False) -> bool:
    """SSRF的に危険なIPか(プライベート/ループバック/メタデータ等)。"""
    c = classify_ip(ip_str)
    if not c.get("ok"):
        return True   # 解析不能は安全側=ブロック
    if allow_unique_local and c["category"] in ("private", "site_local"):
        # IPv6 ULA(fc00::/7)などプロキシ用途を許す場合
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"):
                return False
        except Exception:
            pass
    return bool(c["blocked"])


# ══ ホスト/URL チェック(DNS解決して全解決先を検査) ══════════════════════════
def check_host(host: str, *, allow_unique_local: bool = False) -> dict:
    """ホスト名(またはIP)を解決し、いずれかの解決先が危険レンジなら拒否する
    (名前→内部IP / DNSリバインディングの SSRF を遮断)。"""
    host = (host or "").strip().strip("[]")
    if not host:
        return {"ok": False, "blocked": True, "reason": "ホスト空"}
    # 直接IPならそのまま判定
    try:
        ipaddress.ip_address(host)
        b = is_blocked_ip(host, allow_unique_local=allow_unique_local)
        return {"ok": True, "host": host, "resolved": [host], "blocked": b,
                "reason": classify_ip(host).get("reason", "")}
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        return {"ok": False, "blocked": True, "reason": f"名前解決失敗: {e}", "host": host}
    bad = [ip for ip in ips if is_blocked_ip(ip, allow_unique_local=allow_unique_local)]
    return {"ok": True, "host": host, "resolved": ips, "blocked": bool(bad),
            "blocked_ips": bad,
            "reason": (f"解決先に危険IP {bad} を含む=SSRFブロック" if bad else "全解決先がグローバル")}


def check_url(url: str, *, allow_schemes=("http", "https"),
              allow_unique_local: bool = False, resolve: bool = True) -> dict:
    """URLをSSRF観点で検査。スキーム制限+ホストの解決先レンジ判定。{ok, allowed, reason}。"""
    try:
        parts = urlsplit(url)
    except Exception as e:
        return {"ok": False, "allowed": False, "reason": f"URL解析不能: {e}"}
    scheme = (parts.scheme or "").lower()
    if scheme not in allow_schemes:
        return {"ok": True, "allowed": False,
                "reason": f"スキーム {scheme!r} は不許可(許可={list(allow_schemes)})"}
    host = parts.hostname or ""
    if not host:
        return {"ok": True, "allowed": False, "reason": "ホスト無し"}
    if not resolve:
        return {"ok": True, "allowed": True, "host": host, "reason": "解決スキップ(スキームのみ検査)"}
    h = check_host(host, allow_unique_local=allow_unique_local)
    allowed = h.get("ok") and not h.get("blocked")
    return {"ok": True, "allowed": bool(allowed), "host": host,
            "resolved": h.get("resolved"), "reason": h.get("reason"),
            "safe_url": safe_url(url)}


# ══ URL の秘匿・資格情報除去 ══════════════════════════════════════════════════
def strip_userinfo(url: str) -> str:
    """URL から user:pass@ を除去する(資格情報の漏えい防止)。"""
    try:
        parts = urlsplit(url)
        if not parts.username and not parts.password:
            return url
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    except Exception:
        return url


def redact_url(url: str) -> str:
    """機微なクエリ値([REDACTED])・URL資格情報を秘匿する(ログ用)。"""
    try:
        parts = urlsplit(strip_userinfo(url))
        if not parts.query:
            return urlunsplit(parts)
        out = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            out.append((k, _REDACTED if _norm_query_name(k) in _SENSITIVE_QUERY else v))
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(out, doseq=True, safe="[]"), parts.fragment))
    except Exception:
        return url


def safe_url(url: str) -> str:
    """ログ/表示に安全なURL(資格情報除去+機微クエリ秘匿)。"""
    return redact_url(strip_userinfo(url))


# ══ 知識(防御の原則) ══════════════════════════════════════════════════════
PILLARS = [
    "外部取得はSSRFを疑え: ユーザー/モデルが与えたURL/ホストは内部資産(localhost/プライベート網/"
    "クラウドメタデータ 169.254.169.254)を指しうる。送信前に解決先IPを検査し内部到達を遮断。",
    "名前解決まで検査: ホスト名が内部IPに解決される/DNSリバインディングで後から内部に化ける。"
    "全解決先を見て、1つでも危険レンジなら拒否(安全側)。",
    "URLは秘密を運ぶ: クエリに token/key/secret、ホストに user:pass。ログ/表示前に秘匿・除去する"
    "(漏えいの最頻経路)。キー名分断の回避も正規化して無効化。",
    "専守防衛: 許可リストで正当な用途は通し、内部探索の補助等の攻撃用途は作らない。",
]

TOPICS = [
    {"id": "ssrf", "kind": "ssrf", "title": "SSRF(サーバサイドリクエストフォージェリ)防御",
     "body": "サーバが受け取ったURL/ホストへ自ら通信する機能(web_fetch等)が、攻撃者誘導で"
             "localhost/プライベート網/クラウドメタデータ(169.254.169.254/100.100.100.200/"
             "fd00:ec2::254)へ到達する脆弱性。対策=スキーム制限(http/https)+解決先IPの"
             "危険レンジ判定+全解決先検査。check_url が入口。",
     "tags": ["ssrf", "metadata", "private ip", "dns rebinding", "ssrf防御"]},
    {"id": "url-secrets", "kind": "redact", "title": "URLの機微秘匿・資格情報除去",
     "body": "クエリの token/api_key/secret/password やホストの user:pass はログ/エラー/表示で"
             "漏えいしやすい。redact_url で機微クエリを[REDACTED]化、strip_userinfo で資格情報除去。"
             "キー名をUnicodeフィラーで分断して検出回避する手口も正規化で無効化。",
     "tags": ["redact", "secret", "url", "logging", "秘匿", "資格情報"]},
    {"id": "ip-ranges", "kind": "ip", "title": "特殊用途IPレンジの分類",
     "body": "loopback(127/8, ::1)/private(10,172.16/12,192.168)/link-local(169.254, fe80::/10)/"
             "multicast/reserved/unspecified/IPv6 ULA(fc00::/7)。classify_ip が標準ライブラリ"
             "ipaddress で分類し blocked を返す。allow_unique_local でプロキシ用途のULAを許容可。",
     "tags": ["ip", "ranges", "ipaddress", "ula", "レンジ"]},
]


class NetGuard:
    """送信ネットワークの安全ガード(SSRF防御・URL秘匿)の単一入口。"""

    def __init__(self):
        self.topics = TOPICS

    def kinds(self) -> list:
        return sorted({t["kind"] for t in self.topics})

    def pillars(self) -> list:
        return list(PILLARS)

    def search(self, query: str, top: int = 4) -> list:
        qt = tokens(query)
        if not qt:
            return []
        scored = []
        for t in self.topics:
            hay = tokens(t["title"]) | tokens(t["body"]) | tokens(" ".join(t.get("tags", [])))
            sc = len(qt & hay)
            if sc:
                scored.append((sc, t))
        scored.sort(key=lambda x: -x[0])
        return [{"id": t["id"], "title": t["title"], "body": t["body"]} for _, t in scored[:top]]

    # 実機能(委譲)
    def classify_ip(self, ip_str: str) -> dict:
        return classify_ip(ip_str)

    def is_blocked_ip(self, ip_str: str, allow_unique_local: bool = False) -> bool:
        return is_blocked_ip(ip_str, allow_unique_local=allow_unique_local)

    def check_host(self, host: str, allow_unique_local: bool = False) -> dict:
        return check_host(host, allow_unique_local=allow_unique_local)

    def check_url(self, url: str, allow_schemes=("http", "https"),
                  allow_unique_local: bool = False, resolve: bool = True) -> dict:
        return check_url(url, allow_schemes=allow_schemes,
                         allow_unique_local=allow_unique_local, resolve=resolve)

    def redact_url(self, url: str) -> str:
        return redact_url(url)

    def strip_userinfo(self, url: str) -> str:
        return strip_userinfo(url)

    def safe_url(self, url: str) -> str:
        return safe_url(url)

    def guard_request(self, url: str, **kw) -> dict:
        """送信前ゲート: 許可なら ok:True、危険なら ok:False(理由つき)。安全URLも返す。"""
        c = self.check_url(url, **kw)
        return {"ok": bool(c.get("allowed")), "allowed": bool(c.get("allowed")),
                "reason": c.get("reason"), "safe_url": safe_url(url),
                "host": c.get("host"), "resolved": c.get("resolved")}

    def overview(self) -> dict:
        return {"kinds": self.kinds(), "topics": len(self.topics),
                "metadata_ips": sorted(_CLOUD_METADATA_IPS),
                "sensitive_query_params": sorted(_SENSITIVE_QUERY),
                "operations": ["classify_ip", "is_blocked_ip", "check_host", "check_url",
                               "guard_request", "redact_url", "strip_userinfo", "safe_url"],
                "note": ("SSRF防御(内部/メタデータIP遮断・全解決先検査)+URL秘匿(機微クエリ/資格情報除去)。"
                         "標準ライブラリのみ・専守防衛。他PJのnetwork policyをクリーンルーム蒸留。出典なし。")}


_NET_GUARD: NetGuard | None = None


def monitor() -> NetGuard:
    global _NET_GUARD
    if _NET_GUARD is None:
        _NET_GUARD = NetGuard()
    return _NET_GUARD
