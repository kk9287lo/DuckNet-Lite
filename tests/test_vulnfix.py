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

from dataplane.admin import AdminDashboard, _make_handler
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
    # 前段プロキシ越しだと peer が 127.0.0.1 に潰れる。ここで配ると誰でも管理者になれる。
    cls = _handler_cls()
    f = cls._may_set_token_cookie
    assert f("127.0.0.1", False, "", "T0KEN", True) is False
    assert f("127.0.0.1", False, "", "T0KEN", False) is True     # 直接の loopback は従来どおり
    assert f("127.0.0.1", True, "", "T0KEN", True) is True       # 認証済みなら可
    assert f("203.0.113.5", False, "T0KEN", "T0KEN", True) is True   # 正しい ?token 提示
    assert f("203.0.113.5", False, "wrong", "T0KEN", False) is False


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
