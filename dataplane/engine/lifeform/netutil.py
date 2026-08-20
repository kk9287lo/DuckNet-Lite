"""
netutil.py — IP/CIDR の小さな共有ヘルパ(依存ゼロ)
====================================================================================
アローリスト照合(信頼送信元の除外)を各所で個別実装していたのを1つに束ねる。
AlertSink と DnsFilter が共通で使う。
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
    """ip が cidrs(IP/CIDR の列)のいずれかに含まれるか。空/不正は False。"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    for net in cidrs:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except Exception:
            continue
    return False
