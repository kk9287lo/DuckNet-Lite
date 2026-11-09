"""
test_vulnfix.py — 脆弱性修正の回帰(CSRF・トークン配布・状態署名)。
====================================================================================
いずれも「防御機構そのものを攻撃者の道具に変えられた」系の欠陥。修正が戻らないよう固定する:
  · 管理面: Origin 検査が IP リテラルなら何でも通していた(攻撃者サーバ発の状態変更 POST)
  · 管理面: 前段リバースプロキシ越しでも peer が loopback に見え、誰にでもトークンを配っていた
  · 状態署名: .hw サイドカーの署名がファイル名に束縛されておらず、別 state へ移植して
    ロールバック防止の高水位を下げられた
"""
import os
import tempfile
import http.client
import http.server
import threading
import urllib.error
import urllib.request

from dataplane.admin import AdminDashboard, _make_handler
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.core.signed_state import (
    _hw_path, _read_file_hw, _write_file_hw, persistent_key)


class _FakeHandler:
    """_make_handler が返すクラスの判定メソッドだけを、HTTP を立てずに突く。"""

    def __init__(self, cls, headers):
        self.__class__ = type("H", (cls,), {})   # __init__ を通さずメソッドだけ借りる
        self.headers = headers


def _handler_cls(token="T0KEN"):
    return _make_handler(AdminDashboard(host="127.0.0.1", port=0, token=token))


def test_origin_check_requires_same_origin_not_any_ip_literal():
    # 旧実装は rebinding 用の _hostname_allowed に委ねており、IP リテラルなら何でも
    # 「同一オリジン」と見なしていた=攻撃者が IP で配ったページからの POST が通った。
    cls = _handler_cls()
    h = _FakeHandler(cls, {"Host": "127.0.0.1:8081", "Origin": "http://203.0.113.9"})
    assert cls._origin_ok(h) is False
    h = _FakeHandler(cls, {"Host": "127.0.0.1:8081", "Origin": "http://127.0.0.1:8081"})
    assert cls._origin_ok(h) is True
    h = _FakeHandler(cls, {"Host": "127.0.0.1:8081"})        # 提示なし=トークンで守る
    assert cls._origin_ok(h) is True


def test_origin_allowlist_still_honoured():
    cls = _handler_cls()
    os.environ["DUCKNET_ADMIN_ALLOWED_HOSTS"] = "ops.example"
    try:
        h = _FakeHandler(cls, {"Host": "127.0.0.1", "Origin": "https://ops.example"})
        assert cls._origin_ok(h) is True
    finally:
        os.environ.pop("DUCKNET_ADMIN_ALLOWED_HOSTS", None)


def test_token_cookie_not_issued_through_a_reverse_proxy():
    # 前段 proxy からは接続元が loopback に見える。旧 Cookie も X-Forwarded-For も
    # 認証に使わず、生トークン Cookie を再発行しないことを実 HTTP で確かめる。
    with tempfile.TemporaryDirectory() as state_dir:
        old_shield, old_firewall = ND._SHIELD, FW._FW
        ND._SHIELD = ND.NetShield(state_dir=state_dir)
        FW._FW = FW.AppFirewall(state_dir=state_dir)
        admin = AdminDashboard(host="127.0.0.1", port=0, token="T0KEN",
                               state_dir=state_dir)
        assert admin.start()["ok"]

        class ReverseProxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                upstream = http.client.HTTPConnection("127.0.0.1", admin.port, timeout=3)
                try:
                    headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("host", "connection")}
                    headers["Host"] = "127.0.0.1:%d" % admin.port
                    headers["X-Forwarded-For"] = "203.0.113.9"
                    upstream.request("GET", self.path, headers=headers)
                    response = upstream.getresponse()
                    body = response.read()
                    self.send_response(response.status)
                    for name, value in response.getheaders():
                        if name.lower() not in ("connection", "transfer-encoding"):
                            self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    upstream.close()

        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ReverseProxy)
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        base = "http://127.0.0.1:%d" % proxy.server_port
        try:
            for path, headers in (("/", {}), ("/?token=wrong", {}),
                                  ("/?token=T0KEN", {}),
                                  ("/", {"X-Token": "T0KEN"})):
                with urllib.request.urlopen(urllib.request.Request(base + path,
                                                                  headers=headers)) as response:
                    cookie = response.headers.get("Set-Cookie") or ""
                    assert response.status == 200
                    assert "ducknet_admin=;" in cookie and "Max-Age=0" in cookie
                    assert "T0KEN" not in cookie
            try:
                urllib.request.urlopen(urllib.request.Request(
                    base + "/api/state", headers={"Cookie": "ducknet_admin=T0KEN"}))
            except urllib.error.HTTPError as error:
                assert error.code == 401
                error.close()
            else:
                raise AssertionError("old cookie authorized through the proxy")
            with urllib.request.urlopen(urllib.request.Request(
                    base + "/api/state", headers={"X-Token": "T0KEN"})) as response:
                assert response.status == 200
        finally:
            proxy.shutdown()
            proxy.server_close()
            worker.join(3)
            admin.stop()
            ND._SHIELD, FW._FW = old_shield, old_firewall


def test_hw_sidecar_is_bound_to_its_state_file():
    with tempfile.TemporaryDirectory() as d:
        key = persistent_key(d)
        a = os.path.join(d, "blocklist.json")
        b = os.path.join(d, "config.json")
        _write_file_hw(a, 42, key)
        assert _read_file_hw(a, key) == 42
        # 別 state の .hw として移植しても受理されない(高水位を下げられない)
        with open(_hw_path(a), "rb") as f:
            blob = f.read()
        with open(_hw_path(b), "wb") as f:
            f.write(blob)
        assert _read_file_hw(b, key) == 0
