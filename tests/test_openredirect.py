"""
test_openredirect.py — オープンリダイレクト無害化(evolution #71)。
====================================================================================
3xx 応答の Location が外部の許可外ホストを指す=フィッシング誘導。enforce で安全パスへ書換、
audit で記録のみ。リクエスト自身の Host と許可リスト(サブドメイン含む)は常に許容(低FP)。
"""
from dataplane.engine.services.proxy import (
    _location_host, _redirect_violation_host, AsyncEdgeGuard,
)


def test_location_host_parsing():
    assert _location_host("https://evil.com/phish") == "evil.com"
    assert _location_host("//evil.com/x") == "evil.com"                # scheme 相対
    assert _location_host("http://user:p@evil.com:8080/x") == "evil.com"  # userinfo/port 除去
    assert _location_host("/dashboard") == ""                          # 相対=同一サイト
    assert _location_host("https://APP.Example.COM/") == "app.example.com"  # 小文字化


def test_violation_detection():
    lines = ["Location: https://evil.com/x"]
    assert _redirect_violation_host("HTTP/1.1 302 Found", lines, "app.example.com", []) == "evil.com"
    # 自サイトは許容
    assert _redirect_violation_host("HTTP/1.1 302 Found",
                                    ["Location: https://app.example.com/home"],
                                    "app.example.com", []) == ""
    # 許可リスト(サブドメイン含む)
    assert _redirect_violation_host("HTTP/1.1 302 Found",
                                    ["Location: https://accounts.google.com/o"],
                                    "app.example.com", ["google.com"]) == ""
    # 相対リダイレクトは安全
    assert _redirect_violation_host("HTTP/1.1 302 Found", ["Location: /next"],
                                    "app.example.com", []) == ""
    # 3xx でない=対象外
    assert _redirect_violation_host("HTTP/1.1 200 OK", ["Location: https://evil.com"],
                                    "app.example.com", []) == ""


def _with_cfg(**cfg):
    from dataplane.engine.lifeform.pipeline import net_shield
    sh = net_shield()
    prev = {k: sh.cfg.get(k) for k in cfg}
    sh.cfg.update(cfg)
    return sh, prev


def test_enforce_rewrites_location():
    sh, prev = _with_cfg(open_redirect_enabled=True, open_redirect_mode="enforce",
                         open_redirect_allow=[], open_redirect_safe_path="/")
    try:
        g = AsyncEdgeGuard()
        head = b"HTTP/1.1 302 Found\r\nLocation: https://evil.com/phish\r\nServer: x"
        out = g._apply_redirect_policy(head, "app.example.com", ip="1.2.3.4").decode()
        assert "Location: /" in out and "evil.com" not in out          # 安全パスへ書換
        assert g.metrics.get("open_redirect", 0) >= 1
    finally:
        sh.cfg.update(prev)


def test_audit_records_but_keeps():
    sh, prev = _with_cfg(open_redirect_enabled=True, open_redirect_mode="audit",
                         open_redirect_allow=[])
    try:
        g = AsyncEdgeGuard()
        head = b"HTTP/1.1 302 Found\r\nLocation: https://evil.com/x"
        out = g._apply_redirect_policy(head, "app.example.com", ip="1.2.3.4").decode()
        assert "evil.com" in out                                       # audit=応答不変
        assert g.metrics.get("open_redirect", 0) >= 1                  # でも記録される
    finally:
        sh.cfg.update(prev)


def test_same_host_redirect_untouched():
    sh, prev = _with_cfg(open_redirect_enabled=True, open_redirect_mode="enforce")
    try:
        g = AsyncEdgeGuard()
        head = b"HTTP/1.1 302 Found\r\nLocation: https://app.example.com/home"
        out = g._apply_redirect_policy(head, "app.example.com").decode()
        assert "app.example.com/home" in out                           # 自サイト=不変
    finally:
        sh.cfg.update(prev)
