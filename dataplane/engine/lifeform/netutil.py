"""
netutil.py — IP/CIDR の小さな共有ヘルパ(依存ゼロ)
====================================================================================
アローリスト照合(信頼送信元の除外)を各所で個別実装していたのを1つに束ねる。
proxy.py の信頼 proxy(trusted_proxies)判定などが共通で使う。
"""
from __future__ import annotations

import ipaddress


def valid_cidr(cidr: str) -> bool:
    """IP 単体 or CIDR として妥当か(ipaddress で検証)。"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except Exception:
        return False


def ip_in_any(ip: str, cidrs) -> bool:
    """ip が cidrs(IP/CIDR の列)のいずれかに含まれるか。空/不正は False。
    IPv4-mapped('::ffff:192.0.2.1')は IPv4 の CIDR とも照合する(IPv6 の CIDR とは従来どおり)。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    # dual-stack('::' 待受)の IPv4 クライアントは '::ffff:a.b.c.d' で届く。ipaddress は別バージョン
    # 同士を常に不一致にするので IPv4 の CIDR に決して一致せず、呼び出し側ごとに正規化を強いていた
    # (忘れた所は信頼 proxy 判定を素通り)。素の IPv4/IPv6 は alt=None で従来と同じ判定。
    alt = addr.ipv4_mapped if addr.version == 6 else None
    for net in cidrs:
        try:
            n = ipaddress.ip_network(net, strict=False)
        except Exception:
            continue
        if addr in n or (alt is not None and alt in n):
            return True
    return False
