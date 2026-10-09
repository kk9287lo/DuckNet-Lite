"""
test_sweep_rem_cover.py — 表示名(DUCKNET_COVER)と偽バナーの整合。
====================================================================================
· DUCKNET_COVER を直接設定したとき(--stealth を使わない運用・CRLF の env ファイル)、末尾の CR などの
  制御文字が管理画面の Server ヘッダと遮断ページへそのまま入っていた。空・空白だけの値は、アイコンの
  判定では『未設定』、表示名では『空の名前』と食い違っていた。
· 偽バナー(DUCKNET_DECEPTION)で Tomcat の Apache-Coyote に PHP の X-Powered-By を付けていた(系統を
  apache と数えていたため)。Tomcat は X-Powered-By を既定で出さないので、嘘が内部で矛盾していた。
"""
import os
import socket
import tempfile

import importlib.util

import dataplane.engine.lifeform.pipeline as ND
from dataplane.admin import AdminDashboard
from dataplane.engine.services import banner as deception
from dataplane.engine.services import proxy as P

# 製品名の既定(Lite はステルスの profile を持たない)
_PRODUCT = ("DuckNet L7 Security" if importlib.util.find_spec("dataplane.profile")
            else "DuckNet-Lite")


def _with_cover(value, default="(none)"):
    """DUCKNET_COVER=value のときの案内ページの表示名(proxy._cover_brand は両版にある)。"""
    old = os.environ.get("DUCKNET_COVER")
    os.environ["DUCKNET_COVER"] = value
    try:
        return P._cover_brand(default)
    finally:
        if old is None:
            os.environ.pop("DUCKNET_COVER", None)
        else:
            os.environ["DUCKNET_COVER"] = old


def _admin_server_header(cover):
    """(生の応答 head の Server 行, 本文)。urllib は行末の余分な CR を黙って落とすので生のバイトを読む。"""
    old = os.environ.get("DUCKNET_COVER")
    os.environ["DUCKNET_COVER"] = cover
    with tempfile.TemporaryDirectory() as d:
        osh = ND._SHIELD
        ND._SHIELD = ND.NetShield(state_dir=d)
        adm = AdminDashboard(host="127.0.0.1", port=0)
        try:
            url = adm.start()["url"]
            host, port = url.split("//", 1)[1].rstrip("/").rsplit(":", 1)
            with socket.create_connection((host, int(port)), timeout=10) as s:
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + f"{host}:{port}".encode()
                          + b"\r\n\r\n")             # 管理画面は Host を照合する(DNS rebinding 対策)
                raw = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    raw += chunk
            head, _, body = raw.partition(b"\r\n\r\n")
            line = next(ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"server:"))
            return line[len(b"server:"):].lstrip(b" ").decode("latin1"), body
        finally:
            adm.stop()
            ND._SHIELD = osh
            if old is None:
                os.environ.pop("DUCKNET_COVER", None)
            else:
                os.environ["DUCKNET_COVER"] = old


def test_c1_cover_name_from_a_crlf_env_file_has_no_control_characters():
    server, html = _admin_server_header("System Health Monitor\r")
    assert server == "System Health Monitor", repr(server)
    assert b"System Health Monitor" in html and b"DuckNet" not in html
    old = os.environ.get("DUCKNET_COVER")
    os.environ["DUCKNET_COVER"] = "Ops\tConsole\r"
    try:
        page = P._block_page({"reason": "x", "remain_sec": 30}).decode("utf-8", "replace")
    finally:
        if old is None:
            os.environ.pop("DUCKNET_COVER", None)
        else:
            os.environ["DUCKNET_COVER"] = old
    assert "Ops Console" in page and "\r" not in page.split("\r\n\r\n", 1)[-1], page[:300]
    assert _with_cover(" a\r\nb\x01 ") == "a  b" and _with_cover(" \r ") == "(none)"


def test_c2_empty_cover_means_unset_everywhere():
    server, html = _admin_server_header("   ")
    assert server == _PRODUCT, repr(server)
    old = os.environ.get("DUCKNET_COVER")
    os.environ["DUCKNET_COVER"] = " \r "
    try:
        assert P._cover_brand("X") == "X"
        assert _PRODUCT in P._block_page({"remain_sec": 30}).decode("utf-8", "replace")
    finally:
        if old is None:
            os.environ.pop("DUCKNET_COVER", None)
        else:
            os.environ["DUCKNET_COVER"] = old


def test_c3_tomcat_banner_never_carries_a_php_header():
    os.environ["DUCKNET_DECEPTION"] = "1"
    try:
        seen = 0
        for s in range(300):
            for i in range(len(deception._FAMILIES)):
                hs = deception.headers_for(f"198.51.100.{s % 250}", window=30, now=5000.0 + 30 * i + s)
                if hs[0][1].startswith("Apache-Coyote"):
                    seen += 1
                    assert "X-Powered-By" not in dict(hs[1:]), hs
        assert seen > 0
    finally:
        os.environ.pop("DUCKNET_DECEPTION", None)
