"""
test_cookieharden.py — Set-Cookie ハードニング(evolution #65)。
====================================================================================
バックエンドが Cookie 保護属性を付け忘れても WAF 側で補完する。SameSite は常に、Secure は
TLS 接続時のみ(平文で付けると壊れる)、HttpOnly は opt-in(JS読取Cookieを壊し得る)。
"""
from dataplane.engine.services.proxy import inject_security_headers as inj, _harden_set_cookie


def test_harden_adds_samesite_and_secure_on_tls():
    cfg = {"cookie_samesite": "Lax"}
    out = _harden_set_cookie("Set-Cookie: sid=abc; Path=/", cfg, tls=True)
    assert "SameSite=Lax" in out and "Secure" in out
    assert out.startswith("Set-Cookie: sid=abc; Path=/")     # 元属性は保持


def test_secure_not_added_on_plain_http():
    cfg = {"cookie_samesite": "Lax"}
    out = _harden_set_cookie("Set-Cookie: sid=abc", cfg, tls=False)
    assert "SameSite=Lax" in out and "Secure" not in out      # 平文に Secure を付けない


def test_existing_attrs_respected():
    cfg = {"cookie_samesite": "Lax", "cookie_httponly": True}
    line = "Set-Cookie: sid=abc; Secure; HttpOnly; SameSite=Strict"
    out = _harden_set_cookie(line, cfg, tls=True)
    assert out == line                                        # 全て既存=変更しない


def test_httponly_opt_in():
    base = "Set-Cookie: sid=abc"
    assert "HttpOnly" not in _harden_set_cookie(base, {"cookie_samesite": ""}, tls=False)
    assert "HttpOnly" in _harden_set_cookie(base, {"cookie_httponly": True,
                                                   "cookie_samesite": ""}, tls=False)


def test_non_cookie_line_untouched():
    assert _harden_set_cookie("Content-Type: text/html", {}, tls=True) == "Content-Type: text/html"


def test_inject_hardens_cookies_independently_of_sec_headers():
    # add_headers=False(sec ヘッダ無効)でも harden_cookies=True なら Cookie は硬くなる。
    head = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1\r\nContent-Type: text/html"
    out = inj(head, {"cookie_samesite": "Lax"}, tls=True,
              add_headers=False, harden_cookies=True).decode()
    assert "SameSite=Lax" in out and "Secure" in out
    assert "X-Content-Type-Options" not in out               # sec ヘッダは付けない


def test_inject_both_sec_and_cookies():
    head = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1"
    out = inj(head, {"cookie_samesite": "Lax"}, tls=False,
              add_headers=True, harden_cookies=True).decode()
    assert "X-Content-Type-Options: nosniff" in out          # #12 sec ヘッダ
    assert "SameSite=Lax" in out                             # #65 cookie
    assert "Secure" not in out                               # 平文=Secure なし


def test_inject_default_no_cookie_change():
    # 既定(harden_cookies=False)では Cookie を触らない=#12 の従来契約を維持。
    head = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1"
    out = inj(head, {}).decode()
    assert "X-Frame-Options: SAMEORIGIN" in out
    assert "SameSite" not in out and out.count("Set-Cookie: s=1") == 1


def test_multiple_cookies_each_hardened():
    head = (b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n"
            b"Content-Type: text/html")
    out = inj(head, {"cookie_samesite": "Lax"}, tls=True,
              add_headers=False, harden_cookies=True).decode()
    assert out.count("SameSite=Lax") == 2 and out.count("Secure") == 2
