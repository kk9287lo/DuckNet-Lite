"""
banner.py — 動的デセプション(Moving Target Defense・防御専用・依存ゼロ)
====================================================================================
攻撃者の自動フィンガープリンティング(『この前衛は nginx か? バージョンは?』)を攪乱する。
公開応答(WAF 遮断ページ・400/402/503 等)の Server バナーを、攻撃者ごと・時間帯ごとに
矛盾する別物へ揺らす。同一の攻撃者が短時間に観測しても Apache→IIS と食い違うため、
スキャン結果の信頼性が崩れ、自動列挙の手掛かりを潰す(人間オペレータの手作業を誘発)。

正直な線引き(誇張しない):
  · これは『指紋を揺らす(攪乱)』防御であって、攻撃者を攻撃したり罠ネットワークを物理生成
    したりはしない(OS非侵襲・防御専用)。決定的な精密解析は欺けない=自動列挙を外す層。
  · 既定オフ。CHICKENNET_DECEPTION を設定したときだけ働く(正規の監視を不用意に混乱させない)。
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import time

# ありふれた実在のサーバ名簿(矛盾させて指紋を無効化する素材)。
_SERVERS = (
    "Apache/2.4.41 (Ubuntu)", "nginx/1.18.0", "Microsoft-IIS/10.0",
    "Apache/2.4.52 (Debian)", "nginx/1.21.6", "LiteSpeed",
    "openresty/1.21.4.1", "Microsoft-IIS/8.5", "Apache-Coyote/1.1",
    "cloudflare", "gws", "Jetty(9.4.43)",
)


def _family(banner: str) -> str:
    """バナーからサーバ系統を抽出(Apache/2.4→apache, Microsoft-IIS→microsoft,
    Apache-Coyote→apache, Jetty(9.4.43)→jetty)。先頭の英字並びを系統名とする。"""
    m = re.match(r"[a-z]+", banner.lower())
    return m.group(0) if m else banner.lower()


# 系統ごとにグループ化(出現順を保つ)。隣接窓で必ず系統が変わる回転に使う。
_FAMILIES: list = []
_BY_FAMILY: dict = {}
for _s in _SERVERS:
    _f = _family(_s)
    if _f not in _BY_FAMILY:
        _BY_FAMILY[_f] = []
        _FAMILIES.append(_f)
    _BY_FAMILY[_f].append(_s)
# 系統数と互いに素なストライド候補。t*stride で系統を巡回すると、隣接窓の差(stride mod nf)が
# 必ず非ゼロ=別系統になり、かつ全系統を漏れなく巡回する(再観測が必ず矛盾する=MTD強化)。
_COPRIME = [s for s in range(1, max(2, len(_FAMILIES)))
            if math.gcd(s, len(_FAMILIES)) == 1] or [1]


def is_enabled() -> bool:
    """デセプションが有効か(既定オフ。CHICKENNET_DECEPTION で opt-in)。"""
    return os.environ.get("CHICKENNET_DECEPTION", "").lower() not in ("", "0", "false", "no")


def rotating_banner(seed: str = "", window: int = 30, now: float = None) -> str:
    """偽の Server バナーを返す。seed(攻撃者IP 等)と時間窓で決まるため、同一攻撃者には
    *時間で変化* して見える(=矛盾)。同一窓内では安定(レスポンス内での自己矛盾は避ける)。
    隣接する窓では **必ず別系統**(Apache→IIS 等)を返すよう系統を回転させる=偶然の一致で
    攻撃者に『一貫している』と確信させない(単純ハッシュmodだと隣接窓で同系統が偶発し得た)。"""
    now = time.time() if now is None else now
    t = int(now) // max(1, int(window))
    nf = len(_FAMILIES)
    if nf <= 1:
        members = _BY_FAMILY[_FAMILIES[0]]
    else:
        h = hashlib.blake2b(f"{seed}|fam".encode("utf-8", "replace"), digest_size=5).digest()
        base = int.from_bytes(h[:4], "big")          # 攻撃者ごとに開始系統をずらす
        stride = _COPRIME[h[4] % len(_COPRIME)]      # 攻撃者ごとに巡回順もずらす(隣接は必ず別系統)
        members = _BY_FAMILY[_FAMILIES[(base + t * stride) % nf]]
    # 系統内の版は窓ごとにハッシュで選ぶ(同系統内でも版が揺れる=さらに攪乱)。
    hv = hashlib.blake2b(f"{seed}|{t}|var".encode("utf-8", "replace"), digest_size=4).digest()
    return members[int.from_bytes(hv, "big") % len(members)]


def banner_for(ip: str = "", now: float = None) -> str:
    """有効時のみ偽バナーを返す薄いラッパ(無効なら空=Server ヘッダを付けない)。"""
    return rotating_banner(ip, now=now) if is_enabled() else ""


# 偽 Server バナーだけ揺らしても、随伴ヘッダ(X-Powered-By 等)が無い/矛盾すると賢いスキャナに
# 嘘を見抜かれる。系統に *整合する* 随伴ヘッダを同じ窓で付け、嘘を内部矛盾させない(MTD強化)。
_PHP_VERS = ("7.4.33", "8.0.30", "8.1.27", "8.2.18")


def _companions(banner: str, seed: str, t: int) -> list:
    """偽バナーの系統に整合する随伴ヘッダ。整合する『定番の手掛かり』がある系統だけ付け、
    無い系統は付けない(=沈黙もまた整合)。版は窓ごとに揺らして静的な手掛かりを避ける。"""
    fam = _family(banner)
    if fam == "microsoft":                       # IIS は ASP.NET スタックが定番
        return [("X-Powered-By", "ASP.NET"), ("X-AspNet-Version", "4.0.30319")]
    if fam in ("apache", "litespeed"):           # LAMP/LiteSpeed は PHP が定番
        h = hashlib.blake2b(f"{seed}|{t}|php".encode("utf-8", "replace"), digest_size=2).digest()
        return [("X-Powered-By", "PHP/" + _PHP_VERS[int.from_bytes(h, "big") % len(_PHP_VERS)])]
    if fam == "cloudflare":                       # CF 特有ヘッダ
        return [("CF-Cache-Status", "DYNAMIC")]
    return []                                     # nginx/openresty/gws/jetty 等は沈黙が自然


def headers_for(ip: str = "", now: float = None, window: int = 30) -> list:
    """有効時のみ、偽 Server バナー + 系統整合の随伴ヘッダを (name, value) のリストで返す。
    同一窓では安定・隣接窓では系統ごと変わる(banner と同じ巡回)=嘘が内部矛盾しない。
    無効なら空リスト(何も付けない=製品の正体を漏らさない既定)。"""
    if not is_enabled():
        return []
    now = time.time() if now is None else now
    banner = rotating_banner(ip, window=window, now=now)
    t = int(now) // max(1, int(window))
    return [("Server", banner)] + _companions(banner, ip, t)
