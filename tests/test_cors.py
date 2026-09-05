"""
test_cors.py — CORS 誤設定の無害化(evolution #69)。
====================================================================================
応答の Access-Control-Allow-Credentials: true が ACAO: * / null と併存する危険な誤設定
(任意/サンドボックス origin が資格情報付き応答を読める)を、credentials 行を除去して無害化する。
静的 origin + credentials の正当構成や、credentials 無しの ACAO:* は一切触らない(FPほぼ無し)。
"""
from dataplane.engine.services.proxy import inject_security_headers as inj, _neutralize_cors


def _lines(*hdrs):
    return list(hdrs)


def test_neutralize_wildcard_with_credentials():
    out = _neutralize_cors(_lines("Access-Control-Allow-Origin: *",
                                  "Access-Control-Allow-Credentials: true"))
    assert any("allow-origin: *" in x.lower() for x in out)
    assert not any("allow-credentials" in x.lower() for x in out)   # credentials 除去


def test_neutralize_null_with_credentials():
    out = _neutralize_cors(_lines("Access-Control-Allow-Origin: null",
                                  "Access-Control-Allow-Credentials: true"))
    assert not any("allow-credentials" in x.lower() for x in out)


def test_static_origin_with_credentials_untouched():
    # 正当構成(静的 origin + credentials)は触らない
    lines = _lines("Access-Control-Allow-Origin: https://app.example.com",
                   "Access-Control-Allow-Credentials: true")
    assert _neutralize_cors(lines) == lines


def test_wildcard_without_credentials_untouched():
    lines = _lines("Access-Control-Allow-Origin: *", "Content-Type: application/json")
    assert _neutralize_cors(lines) == lines                         # credentials 無し=無害


def test_no_cors_headers_untouched():
    lines = _lines("Content-Type: text/html", "X-Frame-Options: DENY")
    assert _neutralize_cors(lines) == lines


def test_inject_neutralizes_cors_independently():
    head = (b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n"
            b"Access-Control-Allow-Credentials: true\r\nContent-Type: application/json")
    out = inj(head, {}, add_headers=False, harden_cookies=False, harden_cors=True).decode()
    assert "Access-Control-Allow-Origin: *" in out
    assert "Allow-Credentials" not in out                           # 無害化
    assert "X-Content-Type-Options" not in out                      # sec ヘッダは付けない


def test_inject_default_leaves_cors():
    # 既定(harden_cors=False)では CORS を触らない
    head = (b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n"
            b"Access-Control-Allow-Credentials: true")
    out = inj(head, {}).decode()
    assert "Allow-Credentials: true" in out
