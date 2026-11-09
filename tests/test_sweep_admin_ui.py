"""
test_sweep_admin_ui.py — 管理ダッシュボードの描画・本文解釈・CSRF・revert(Lite)。
====================================================================================
いずれも「管理画面そのものが運用者を欺く/攻撃者の道具になる」系の欠陥。修正が戻らないよう固定する:
  · #1/#40  onclick の JS 文字列へデータ(IP 等)を埋めていた=属性の実体参照復号で ' が戻り保存型 XSS
  · #24     chunked/壊れた JSON/上限超の本文が {} に化け、既定値(=無効化側)でルートが走っていた
  · #26     Origin 検査がホスト名だけ=同一ホスト別ポートのページから状態変更 POST が通った
  · #69     paranoia 変更の「元に戻す」で、個別に点けていた任意シグネチャが消えたままになる
"""
import html as _html
import json
import re
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane import admin as A

# 無害な目印: IPv6 スコープ ID は ipaddress.ip_address() が引用符ごと受理してしまう(#1)。
_MARK = "fe80::1%a'b<c"


def _js_esc(s: str) -> str:
    """ダッシュボード JS の esc() と同じ置換(HTML 実体参照化)。"""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


# ── 共通: 一時状態で本物の管理サーバを立てる ─────────────────────────
class _Admin:
    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ofw, self.osh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=self.tmp.name)
        ND._SHIELD = ND.NetShield(state_dir=self.tmp.name)
        ND._SHIELD.cfg["persist_bans"] = False
        self.adm = A.AdminDashboard(host="127.0.0.1", port=0, state_dir=self.tmp.name)
        self.adm.start()
        self.port = self.adm.port
        self.token = self.adm.token
        return self

    def __exit__(self, *exc):
        try:
            self.adm.stop()
        finally:
            FW._FW, ND._SHIELD = self.ofw, self.osh
            self.tmp.cleanup()

    @property
    def fw(self):
        return FW._FW

    @property
    def sh(self):
        return ND._SHIELD

    def post(self, path, body=None, headers=None, raw=None):
        """JSON POST(既定は X-Token + application/json)。(status, dict|None) を返す。"""
        h = {"X-Token": self.token, "Content-Type": "application/json"}
        if headers is not None:
            h = headers
        data = raw if raw is not None else json.dumps(body if body is not None else {}).encode()
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     data=data, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except Exception:
                return e.code, None

    def get(self, path):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     headers={"X-Token": self.token})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def raw(self, data: bytes, timeout=5.0) -> bytes:
        """生のリクエストを送り、応答(取れた分)を返す。切断・リセットは b"" 扱い。"""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        out = b""
        try:
            try:
                s.sendall(data)
            except OSError:
                pass
            while True:
                try:
                    ch = s.recv(65536)
                except OSError:
                    break
                if not ch:
                    break
                out += ch
        finally:
            s.close()
        return out


# ── #1/#40: インラインハンドラへデータを埋めない ───────────────────────
_ON_ATTR = re.compile(r'\son([a-z]+)="([^"]*)"')
_INTERP = re.compile(r"\$\{((?:[^{}]|\{[^{}]*\})*)\}")


def _decoded_handlers_with(marker: str):
    """テンプレート中の全 on*="…" 属性について、${esc(…)} へ marker を流し込み、
    ブラウザと同じく属性値の実体参照を復号した「実際にコンパイルされる JS」を返す。"""
    out = []
    for m in _ON_ATTR.finditer(A._HTML):
        val = m.group(2)
        sub = _INTERP.sub(lambda e: _js_esc(marker) if e.group(1).startswith("esc(") else "0", val)
        out.append((val, _html.unescape(sub)))
    return out


def test_c1_c40_inline_handlers_never_carry_data_in_js_strings():
    """#1/#40: IP 等を onclick="unban('${esc(ip)}')" の JS 文字列へ埋めていた。esc() の &#39; は
    属性値の復号で ' に戻るため、引用符入りの「IP」(IPv6 スコープ ID は引用符も通る)で
    文字列から抜け出せた。値は data-* 属性に置き、ハンドラ本体は定数にする。"""
    hs = _decoded_handlers_with(_MARK)
    assert hs, "on* 属性を1つも見つけられない=テストが素通りしている"
    leaked = [orig for orig, js in hs if "a'b" in js or "<c" in js]
    assert not leaked, "データが JS 文字列へ復号されて入る: %r" % leaked
    # ボタン自体は残っている(消して直したことにしない)
    called = " ".join(js for _, js in hs)
    for fn in ("unban(", "resolveAppeal(", "toggleNode(", "resolvePending("):
        assert fn in called, fn


# ── #24: 本文の解釈失敗をルート実行に化けさせない ──────────────────────
def test_rejected_post_does_not_wait_for_declared_body():
    """An unauthenticated peer cannot hold a handler by declaring a body and stalling."""
    with _Admin() as a:
        req = (b"POST /api/shield/toggle HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
               b"Content-Type: application/json\r\nContent-Length: 1048576\r\n\r\n"
               % a.port)
        resp = a.raw(req, timeout=0.5)
        assert b" 401 " in resp.split(b"\r\n", 1)[0], resp[:100]
        # A complete rejected request still receives the rejection response.
        complete = req.replace(b"1048576", b"2") + b"{}"
        resp = a.raw(complete, timeout=0.5)
        assert b" 401 " in resp.split(b"\r\n", 1)[0], resp[:100]


def test_rejected_post_has_total_deadline_under_body_dribble():
    """A trickle below the socket timeout cannot extend an unauthenticated read."""
    sent = threading.Event()
    codes = []
    make_handler = A._make_handler

    def observed_handler(app):
        handler = make_handler(app)
        send = handler._send

        def observed_send(self, code, *args, **kwargs):
            codes.append(code)
            sent.set()
            return send(self, code, *args, **kwargs)

        handler._send = observed_send
        return handler

    with patch.object(A, "_make_handler", new=observed_handler):
        with _Admin() as a:
            client = socket.create_connection(("127.0.0.1", a.port), timeout=2)
            stop = threading.Event()

            def drip():
                while not stop.wait(0.05):
                    try:
                        client.sendall(b"x")
                    except OSError:
                        break

            worker = threading.Thread(target=drip, daemon=True)
            try:
                client.sendall((b"POST /api/shield/toggle HTTP/1.1\r\n"
                                b"Host: 127.0.0.1:%d\r\n"
                                b"Content-Length: 1048576\r\n\r\nx") % a.port)
                worker.start()
                began = time.monotonic()
                assert sent.wait(0.7), "rejection waited for the full declared body"
                assert codes == [401] and time.monotonic() - began < 0.7
            finally:
                stop.set()
                client.close()
                worker.join(timeout=1)


def test_unauthenticated_header_dribble_has_total_deadline():
    """An incomplete request head cannot retain an admin worker indefinitely."""
    with patch.object(A, "_ADMIN_HEAD_DEADLINE_SEC", 0.3):
        with _Admin() as a:
            client = socket.create_connection(("127.0.0.1", a.port), timeout=2)
            client.settimeout(1)
            stop = threading.Event()

            def drip():
                while not stop.wait(0.04):
                    try:
                        client.sendall(b"x")
                    except OSError:
                        break

            worker = threading.Thread(target=drip, daemon=True)
            try:
                client.sendall((b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                b"X-Padding: ") % a.port)
                worker.start()
                began = time.monotonic()
                try:
                    response = client.recv(1024)
                except OSError:
                    response = b""
                assert time.monotonic() - began < 0.8
                assert b" 200 " not in response.split(b"\r\n", 1)[0]
            finally:
                stop.set()
                client.close()
                worker.join(timeout=1)
            good = a.raw((b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                          b"Connection: close\r\n\r\n") % a.port)
            assert good.startswith(b"HTTP/1.0 200"), good[:80]


def test_admin_handler_slots_recover_after_header_deadline():
    """Slow peers consume at most the configured slots; their expiry frees them."""
    with patch.object(A, "_ADMIN_HEAD_DEADLINE_SEC", 0.6), \
            patch.object(A, "_ADMIN_MAX_HANDLERS", 2):
        with _Admin() as a:
            peers = [socket.create_connection(("127.0.0.1", a.port), timeout=2)
                     for _ in range(2)]
            try:
                for peer in peers:
                    peer.sendall(b"G")
                deadline = time.monotonic() + 0.4
                while a.adm._server._handler_slots._value and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert a.adm._server._handler_slots._value == 0
                refused = a.raw((b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                                 b"Connection: close\r\n\r\n") % a.port, timeout=1)
                assert b" 200 " not in refused.split(b"\r\n", 1)[0]
            finally:
                for peer in peers:
                    peer.close()
            deadline = time.monotonic() + 1.2
            while a.adm._server._handler_slots._value != 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert a.adm._server._handler_slots._value == 2
            good = a.raw((b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                          b"Connection: close\r\n\r\n") % a.port)
            assert good.startswith(b"HTTP/1.0 200"), good[:80]


def test_c24_chunked_body_does_not_disable_shield():
    """#24: Content-Length 無しの chunked 本文は {} 扱いになり、{"on":true} が disable() を呼んでいた。"""
    with _Admin() as a:
        a.sh.enable()
        body = b'{"on":true}'
        req = (b"POST /api/shield/toggle HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
               b"X-Token: %s\r\nContent-Type: application/json\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n"
               % (a.port, a.token.encode(), len(body), body))
        resp = a.raw(req)
        assert a.sh.is_enabled() is True, "chunked の『ON』でシールドが OFF になった"
        if resp:
            assert b" 200 " not in resp.split(b"\r\n", 1)[0], resp[:80]


def test_c24_malformed_json_does_not_open_global_block():
    """#24: 壊れた JSON は {} に化け、/api/global_block が public=allow(遮断解除)を実行していた。"""
    with _Admin() as a:
        a.fw.enable()
        a.fw.set_policy("public", "deny")
        code, r = a.post("/api/global_block", raw=b"{'on': True}")
        assert a.fw.policy.get("public") == "deny", "壊れた本文で全体遮断が解除された"
        assert code == 400 and r and r.get("ok") is False, (code, r)
        # 正しい本文は従来どおり通る
        code, r = a.post("/api/global_block", {"on": False})
        assert code == 200 and a.fw.policy.get("public") == "allow"


def test_global_block_save_failure_is_atomic_through_admin_api():
    """The API must not report a global block while the firewall is still off."""
    with _Admin() as a:
        assert a.fw.disable()["ok"]
        assert not a.fw.is_enabled()
        before = dict(a.fw.policy)
        with patch.object(FW, "write_signed_json", return_value=False):
            code, result = a.post("/api/global_block", {"on": True})
        assert code == 200 and result["ok"] is False
        assert not a.fw.is_enabled() and a.fw.policy == before
        assert a.get("/api/admin_audit")["entries"] == []
        code, result = a.post("/api/global_block", {"on": True})
        assert code == 200 and result["ok"] is True
        assert a.fw.is_enabled() and a.fw.policy["public"] == "deny"


def test_memory_only_ban_changes_are_still_audited():
    """A failed durable save does not erase the audit trail of a live BAN change."""
    with _Admin() as a:
        assert a.sh.enable()["ok"]
        assert a.sh.set_config(persist_bans=True)["ok"]
        ip = "198.51.100.55"
        with patch.object(ND, "write_signed_json", return_value=False):
            code, result = a.post("/api/shield/ban", {"ip": ip})
            assert code == 200 and result["ok"] is False
            assert result["applied_in_memory"] is True
        assert a.sh.is_banned_fast(ip)
        entries = a.get("/api/admin_audit")["entries"]
        assert len(entries) == 1 and entries[0]["endpoint"] == "/api/shield/ban"
        assert entries[0]["after"]["persisted"] is False
        assert "memory only" in entries[0]["summary"]

        with patch.object(ND, "write_signed_json", return_value=False):
            code, result = a.post("/api/shield/unban", {"ip": ip})
            assert code == 200 and result["ok"] is False
            assert result.get("applied_in_memory") is not True
        assert a.sh.is_banned_fast(ip)
        entries = a.get("/api/admin_audit")["entries"]
        # Rejected unban made no state change; the change-audit remains the
        # earlier memory-only BAN, and the live deny is still effective.
        assert len(entries) == 1 and entries[0]["endpoint"] == "/api/shield/ban"
        code, result = a.post("/api/shield/unban", {"ip": ip})
        assert code == 200 and result["ok"] is True
        assert not a.sh.is_banned_fast(ip)
        entries = a.get("/api/admin_audit")["entries"]
        assert len(entries) == 2 and entries[0]["endpoint"] == "/api/shield/unban"
        assert entries[0]["after"]["persisted"] is True
        assert "memory only" not in entries[0]["summary"]


def test_c24_oversized_body_is_rejected_without_running_the_route():
    """#24: 上限超の本文は先頭 1MiB だけ読んで JSON 失敗→ {} で firewall を無効化していた。"""
    with _Admin() as a:
        a.fw.enable()
        big = b'{"on":true,"pad":"' + b"A" * (A._MAX_BODY + 1024) + b'"}'
        head = (b"POST /api/firewall/toggle HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                b"X-Token: %s\r\nContent-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % (a.port, a.token.encode(), len(big)))
        resp = a.raw(head + big, timeout=10.0)
        assert a.fw.enabled is True, "上限超の『ON』で firewall が OFF になった"
        if resp:
            assert b" 200 " not in resp.split(b"\r\n", 1)[0], resp[:80]
        # サーバは生きている
        assert "firewall" in a.get("/api/state")


def test_c24_missing_boolean_or_rules_key_is_rejected():
    """#24: キーの綴り違い({"enable":true} / {"rule":[…]})で既定値の破壊側が走っていた
    (シールド OFF・パス別レート制限の全消去)。明示の値が無ければ 400 で何もしない。"""
    with _Admin() as a:
        a.sh.enable()
        code, r = a.post("/api/shield/toggle", {"enable": True})
        assert a.sh.is_enabled() is True, "綴り違いの本文でシールドが OFF になった"
        assert code == 400 and r.get("ok") is False, (code, r)
        rules = [{"path": "/login", "rate": 1, "burst": 2}]
        assert a.sh.set_path_limits(rules)["ok"] is True
        code, r = a.post("/api/shield/path_limits", {"rule": rules})
        assert [x["path"] for x in a.sh.cfg["path_limits"]] == ["/login"], "ルールが全消去された"
        assert r.get("ok") is False, (code, r)
        # 正しい本文は従来どおり
        code, r = a.post("/api/shield/toggle", {"on": False})
        assert code == 200 and r["ok"] is True and a.sh.is_enabled() is False


# ── #26: CSRF の同一オリジン判定はポートまで見る ──────────────────────
class _FakeHandler:
    """_make_handler のクラスから判定メソッドだけを、HTTP を立てずに借りる。"""

    def __init__(self, cls, headers):
        self.__class__ = type("H", (cls,), {})
        self.headers = headers


def test_c26_origin_on_another_port_of_same_host_is_rejected():
    """#26: Origin と Host をホスト名だけで比べていたため、127.0.0.1:9999 の任意ページから
    127.0.0.1:8081 の管理 API を叩けた(SameSite Cookie はポートを区別しない)。"""
    cls = A._make_handler(A.AdminDashboard(host="127.0.0.1", port=0, token="T"))

    def ok(host, origin):
        return cls._origin_ok(_FakeHandler(cls, {"Host": host, "Origin": origin}))

    assert ok("127.0.0.1:8081", "http://127.0.0.1:9999") is False
    assert ok("[::1]:8081", "http://[::1]:9999") is False
    assert ok("localhost:8081", "http://localhost:3000") is False
    assert ok("127.0.0.1", "http://127.0.0.1:9999") is False        # Host 省略=既定ポート
    # 同一オリジンは従来どおり通る
    assert ok("127.0.0.1:8081", "http://127.0.0.1:8081") is True
    assert ok("[::1]:8081", "http://[::1]:8081") is True
    assert ok("127.0.0.1", "http://127.0.0.1") is True
    assert ok("127.0.0.1:80", "http://127.0.0.1") is True
    h = _FakeHandler(cls, {"Host": "127.0.0.1:8081", "Referer": "http://127.0.0.1:9999/x"})
    assert cls._origin_ok(h) is False


def test_c26_legacy_cookie_cannot_authenticate_post():
    """Cookie は port で分離されないため旧 Cookie は POST 認証に使わない。"""
    with _Admin() as a:
        a.sh.enable()
        cookie = {"Cookie": "%s=%s" % (A._COOKIE_NAME, a.token)}
        code, _ = a.post("/api/shield/toggle", {"on": False},
                         headers=dict(cookie, **{"Content-Type": "text/plain"}))
        assert a.sh.is_enabled() is True, "Cookie + text/plain の POST で状態が変わった"
        assert code == 401, code
        # ダッシュボードのヘッダ要求(同一オリジン + JSON)は通る
        port = a.port
        code, r = a.post("/api/shield/toggle", {"on": False},
                         headers={"X-Token": a.token, "Content-Type": "application/json",
                                  "Origin": "http://127.0.0.1:%d" % port})
        assert code == 200 and a.sh.is_enabled() is False, (code, r)
        # 別ポートの Origin は 403
        code, _ = a.post("/api/shield/toggle", {"on": True},
                         headers={"X-Token": a.token, "Content-Type": "application/json",
                                  "Origin": "http://127.0.0.1:%d" % (port + 1)})
        assert code == 403 and a.sh.is_enabled() is False
        # ヘッダトークンのプログラム的クライアント(curl 既定の form 型含む)は従来どおり
        code, _ = a.post("/api/shield/toggle", {"on": True},
                         headers={"X-Token": a.token,
                                  "Content-Type": "application/x-www-form-urlencoded"})
        assert code == 200 and a.sh.is_enabled() is True


def test_resolve_remember_requires_json_boolean_before_rule_persistence():
    with _Admin() as a:
        assert a.fw.enable()["ok"]
        assert a.fw.set_policy("public", "prompt")["ok"]
        pid = a.fw.evaluate("192.0.2.31")["pending_id"]
        assert pid
        code, body = a.post("/api/firewall/resolve",
                            {"id": pid, "approve": True, "remember": "false"})
        assert code == 400 and body["ok"] is False
        assert a.fw.rules == []
        code, body = a.post("/api/firewall/resolve",
                            {"id": pid, "approve": True, "remember": False})
        assert code == 200 and body["ok"] is True and body["remembered"] is False
        assert a.fw.rules == []
        pid2 = a.fw.evaluate("192.0.2.32")["pending_id"]
        code, body = a.post("/api/firewall/resolve",
                            {"id": pid2, "approve": True, "remember": True})
        assert code == 200 and body["ok"] is True and body["remembered"] is True
        assert len(a.fw.rules) == 1


# ── #69: paranoia の「元に戻す」は任意シグネチャの個別設定も戻す ───────────
def test_c69_paranoia_revert_restores_individual_optional_sigs():
    """#69: revert は {level: 変更前} だけで、set_paranoia がプリセットで optional_sigs を
    上書きするため、個別に点けていた SSTI 検知が黙って OFF のまま残った。"""
    with _Admin() as a:
        assert a.sh.set_paranoia(1)["paranoia"] == 1
        assert a.sh.set_optional_signature("ssti", True)["ok"] is True
        code, r = a.post("/api/shield/paranoia", {"level": 2})
        assert code == 200 and r["paranoia"] == 2
        entry = a.get("/api/admin_audit")["entries"][0]
        assert entry["endpoint"] == "/api/shield/paranoia" and entry["revert"], entry
        rv = entry["revert"]
        code, r = a.post(rv["endpoint"], rv["body"])
        assert code == 200, (code, r)
        cfg = a.sh.cfg
        assert cfg["paranoia"] == 1
        on = sorted(n for n, v in (cfg.get("optional_sigs") or {}).items() if v)
        assert on == ["ssti"], on


def test_paranoia_revert_save_failure_keeps_all_prior_settings():
    """A failed save cannot publish just the level or some optional signatures."""
    with _Admin() as a:
        assert a.sh.set_optional_signature("ssti", True)["ok"]
        before = {"paranoia": a.sh.cfg["paranoia"],
                  "optional_sigs": dict(a.sh.cfg["optional_sigs"])}
        with patch.object(ND, "write_signed_json", return_value=False):
            code, result = a.post("/api/shield/paranoia",
                                  {"level": 3, "optional_sigs": {"ssti": True}})
        assert code == 200 and result["ok"] is False, result
        assert a.sh.cfg["paranoia"] == before["paranoia"]
        assert a.sh.cfg["optional_sigs"] == before["optional_sigs"]
        assert a.get("/api/admin_audit")["entries"] == []

        code, result = a.post("/api/shield/paranoia",
                              {"level": 3, "optional_sigs": {"unknown": True}})
        assert code == 400 and result["ok"] is False
        assert a.sh.cfg["paranoia"] == before["paranoia"]
        assert a.sh.cfg["optional_sigs"] == before["optional_sigs"]
        assert a.get("/api/admin_audit")["entries"] == []
