"""
netaddr.py — ホスト/ポートの表記とアドレスファミリ(IPv6 対応・標準ライブラリのみ)
====================================================================================
「アドレスをどう書くか」「どのファミリで bind するか」を1か所に集める。

以前はこの判断が各所の f-string に散っており、IPv6 で 2 つの壊れ方をしていた:

  · `f"http://{host}:{port}"` は host が IPv6 リテラルだと `http://::1:8081` になる。
    これは URL として不正で、パースすると host も port も取り違える。管理画面の URL・
    GUI の接続先・起動バナーが全てこれを使っていたため、IPv6 で待受けた瞬間に
    GUI が本体を見つけられなくなっていた。
  · `http.server` の既定 `address_family` は AF_INET 固定。`--admin-host ::1` を
    指定すると `gaierror(-9) Address family for hostname not supported` で bind に失敗し、
    起動そのものが止まる(= IPv6 専用ホストでは製品が動かない)。

RFC 3986 は URL 中の IPv6 リテラルを `[...]` で囲うことを要求する。
"""
from __future__ import annotations

import socket


def family_for(host: str, port: int = 0):
    """host を bind/接続するときのアドレスファミリ。

    IPv6 リテラル(`::1`, `::`)や IPv6 しか持たない名前なら AF_INET6、それ以外は AF_INET。
    解決できないときは AF_INET(従来どおり)へ落とす ―― ここで例外にすると、名前解決が
    一時的に失敗しただけで起動不能になる。
    """
    h = (host or "").strip().strip("[]")
    if not h:
        return socket.AF_INET
    try:
        infos = socket.getaddrinfo(h, port or None, type=socket.SOCK_STREAM)
    except OSError:
        return socket.AF_INET6 if ":" in h else socket.AF_INET
    for fam, *_ in infos:                       # IPv4 が使えるならそちらを優先(後方互換)
        if fam == socket.AF_INET:
            return socket.AF_INET
    return infos[0][0] if infos else socket.AF_INET


def is_v6_literal(host: str) -> bool:
    """host が IPv6 リテラルか(`[]` 付き・素のどちらでも)。"""
    h = (host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        return True
    if ":" not in h:
        return False
    try:
        socket.inet_pton(socket.AF_INET6, h.split("%")[0])
        return True
    except (OSError, ValueError):
        return False


def hostport(host: str, port) -> str:
    """`host:port` を組み立てる。IPv6 リテラルは `[]` で囲う。"""
    h = (host or "").strip().strip("[]")
    return ("[%s]:%s" if is_v6_literal(h) else "%s:%s") % (h, port)


def url(host: str, port, path: str = "", scheme: str = "http") -> str:
    """`http://host:port/path` を組み立てる。IPv6 リテラルは `[]` で囲う(RFC 3986)。"""
    if path and not path.startswith("/"):
        path = "/" + path
    return "%s://%s%s" % (scheme, hostport(host, port), path)
