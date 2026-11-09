"""
test_sweep_r2_ipsource.py — 要求元の身元(IP/クレデンシャル)の正規化の回帰(sweep r2: ipsource 群)。
====================================================================================
· T1 信頼 proxy の X-Forwarded-For 候補を生の綴りのまま NetShield へ渡していた。'2001:DB8::1' の
     ような別表記は正規形で持つ BAN/状態の鍵と一致せず、BAN 済みクライアントが新顔として通った。
     ゾーンID(fe80::1%a'b)は任意文字を運べるのに、そのまま実クライアントの鍵になっていた。
· T3 クレデンシャル単位レートは Bearer があると X-API-Key を数えなかった。毎回ランダムな Bearer
     を付けて盗んだ API キーで認証させると、識別子が毎回変わり上限が一度も発動しなかった。
(T2 gossip / T4 完全性検査は Full のみの機能=このモジュールには無い)
実通信は 127.0.0.1・ポート 0。state は tmp で隔離。
"""
import contextlib
import socket
import tempfile
import threading

if __name__ == "__main__":
    # 単体で走らせたとき(python tests/test_sweep_r2_ipsource.py)も run_all.py と同じく、製品の import
    # より前に状態dirを使い捨ての一時dirへ向ける(利用者の旧共用・現専用の保存先に触れない)。
    import atexit
    import os
    import shutil
    _RUNNER_STATE = tempfile.mkdtemp(prefix="ducknet-test-state-")
    os.environ["DUCKNET_STATE_DIR"] = _RUNNER_STATE
    os.environ.setdefault("DUCKNET_OFFLINE", "1")
    atexit.register(shutil.rmtree, _RUNNER_STATE, True)

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import AsyncEdgeGuard, _real_client_ip
from guard_support import stop_guard_owned


# ── 共通ヘルパ ──────────────────────────────────────────────────────────────
def _tmpdir():
    return tempfile.TemporaryDirectory()


@contextlib.contextmanager
def _shield(**cfg):
    """隔離した NetShield(有効)/ AppFirewall をプロセス共有シングルトンへ差し込む。"""
    osh, ofw = ND._SHIELD, FW._FW
    with _tmpdir() as d:
        sh = ND.NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg.update(cfg)
        ND._SHIELD = sh
        FW._FW = FW.AppFirewall(state_dir=d)
        try:
            yield sh
        finally:
            ND._SHIELD, FW._FW = osh, ofw


_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class _Backend:
    """接続ごとに受信 head を記録して固定応答を返す backend。"""

    def __init__(self):
        self.got = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self._srv.settimeout(0.1)
        self.port = self._srv.getsockname()[1]
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        c.settimeout(1.0)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                ch = c.recv(65536)
                if not ch:
                    break
                data += ch
        except OSError:
            pass
        self.got.append(data)
        try:
            c.sendall(_OK)
        except OSError:
            pass
        finally:
            c.close()

    def saw(self) -> bytes:
        return b"".join(self.got)

    def close(self):
        self._stop.set()
        self._t.join(2)
        self._srv.close()


@contextlib.contextmanager
def _guard(backend):
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=backend.port,
                       listen_host="127.0.0.1", listen_port=0)
    r = g.start()
    assert r.get("ok"), r
    try:
        yield g
    finally:
        stop_guard_owned(g)


def _exchange(g, req: bytes, timeout=5.0) -> bytes:
    """1 要求を送り、ガードが閉じるまで応答を読む。"""
    c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=timeout)
    try:
        c.sendall(req)
        resp = b""
        try:
            while True:
                ch = c.recv(65536)
                if not ch:
                    break
                resp += ch
        except OSError:
            pass
        return resp
    finally:
        c.close()


def _xff_req(path: str, xff: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {xff}\r\n\r\n"
            ).encode("latin-1")


_TRUSTED = ["127.0.0.1/32"]


# ── T1: XFF / peer の IP を NetShield と同じ正規形へ ─────────────────────────
def test_r2_xff_noncanonical_spelling_resolves_to_canonical_key():
    """T1: 信頼 proxy の XFF 候補を生の綴りで返していた('2001:DB8::1' のまま)。"""
    for raw, canon in (("2001:DB8::1", "2001:db8::1"),
                       ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
                       ("::ffff:192.0.2.1", "192.0.2.1"),
                       ("::FFFF:192.0.2.1", "192.0.2.1")):
        got = _real_client_ip("127.0.0.1", _xff_req("/", raw), _TRUSTED)
        assert got == canon, (raw, got)
        assert got == ND._canon_ip(raw)            # NetShield の鍵と同一の形
    # IPv4-mapped で書かれた信頼 hop は信頼 CIDR と照合される(実クライアント扱いにしない)
    got = _real_client_ip("127.0.0.1", _xff_req("/", "192.0.2.5, ::ffff:127.0.0.1"), _TRUSTED)
    assert got == "192.0.2.5", got


def test_r2_xff_scope_id_not_used_as_client_key():
    """T1: ゾーンID付き候補(任意文字を運べる)が実クライアントの鍵になっていた。"""
    scoped = "fe80::1%a'b<c"
    got = _real_client_ip("127.0.0.1", _xff_req("/", scoped), _TRUSTED)
    assert got == "fe80::1", got                   # ゾーンだけ外した正規形(任意文字は残らない)
    got = _real_client_ip("127.0.0.1", _xff_req("/", "192.0.2.7, " + scoped), _TRUSTED)
    assert got == "fe80::1", got                   # 左のクライアント申告へは進まない
    # 実通信: NetShield の状態の鍵にも、backend へ渡す X-Forwarded-For にも載らない
    be = _Backend()
    try:
        with _shield(trusted_proxies=list(_TRUSTED)) as sh, _guard(be) as g:
            # 状態欠落時の ACL は既定 ON。解決済み IP だけを通して、
            # ゾーンID除去と backend 転送の検証を実行する。
            assert FW._FW.add_rule("fe80::1/128", "allow")["ok"]
            _exchange(g, _xff_req("/r2-scope", scoped))
            keys = list(sh._ips)
        assert "fe80::1" in keys, keys
        assert not any("%" in k for k in keys), keys
        saw = be.saw()
        assert b"/r2-scope" in saw                 # 要求自体は通る(誤遮断しない)
        assert b"x-forwarded-for: fe80::1" in saw.lower(), saw
        assert b"a'b" not in saw and b"%" not in saw, saw
    finally:
        be.close()


def test_r2_norm_ip_canonicalises_peer_like_netshield():
    """T1: _norm_ip は IPv4-mapped の展開だけで、別表記の IPv6 をそのまま返していた。"""
    n = AsyncEdgeGuard._norm_ip
    assert n("2001:DB8:0:0::1") == "2001:db8::1"
    assert n("::FFFF:192.0.2.1") == "192.0.2.1"
    assert n("::ffff:192.0.2.1") == "192.0.2.1"
    # リンクローカル peer のゾーンID(カーネルが付ける受信 IF 名)は外す=BAN できる鍵へ
    assert n("fe80::1%eth0") == "fe80::1"
    assert n("192.0.2.1") == "192.0.2.1" and n("") == ""


def test_r2_ban_applies_to_noncanonical_trusted_xff():
    """T1: 2001:db8::1 の BAN が、信頼 XFF の '2001:DB8::1' から来た要求に効かなかった。"""
    be = _Backend()
    try:
        with _shield(trusted_proxies=list(_TRUSTED)) as sh, _guard(be) as g:
            # BAN 側も ACL では許可する。遮断されたなら NetShield の
            # 正規化済み BAN によるものと判定できるようにする。
            assert FW._FW.add_rule("2001:db8::1/128", "allow")["ok"]
            assert FW._FW.add_rule("2001:db8::2/128", "allow")["ok"]
            assert sh.ban("2001:db8::1", ttl_sec=600)["ok"]
            _exchange(g, _xff_req("/r2-banned", "2001:DB8::1"))
            _exchange(g, _xff_req("/r2-banned-mapped", "2001:db8:0:0:0:0:0:1"))
            _exchange(g, _xff_req("/r2-other", "2001:DB8::2"))       # 対照: 未 BAN は通る
        saw = be.saw()
        assert b"/r2-banned" not in saw, "BAN 済みクライアントが別表記の XFF で通過した"
        assert b"/r2-other" in saw
        assert len(be.got) == 1, be.got
    finally:
        be.close()


# ── T3: クレデンシャル単位レートは要求に載った全識別子を数える ──────────────
def test_r2_cred_rate_counts_api_key_alongside_random_bearer():
    """T3: 毎回ランダムな Bearer + 盗んだ X-API-Key で、識別子が毎回変わり上限が発動しなかった。"""
    be = _Backend()
    try:
        with _shield(cred_rate_enabled=True, cred_rate_limit=3), _guard(be) as g:
            for i in range(6):
                _exchange(g, (f"GET /r2-api HTTP/1.1\r\nHost: x\r\n"
                              f"Authorization: Bearer junk{i}\r\n"
                              f"X-API-Key: stolen-key\r\n\r\n").encode())
        passed = sum(1 for d in be.got if b"/r2-api" in d)
        assert passed <= 3, passed                 # 上限 3 件までは通す(#38)
    finally:
        be.close()


def test_r2_cred_rate_inspect_charges_every_identifier():
    """T3: inspect() は識別子の列を受け、各々に計上する(単一 str の従来呼び出しも有効)。"""
    with _tmpdir() as d:
        sh = ND.NetShield(state_dir=d)
        sh.cfg.update(enabled=True, cred_rate_enabled=True, cred_rate_limit=3)
        acts = [sh.inspect(f"192.0.2.{10 + i}", path="/api",
                           cred=(f"junk{i}", "stolen-key"))["action"] for i in range(5)]
        # 上限 3 件までは通し、超えた要求を遮断(#38: 旧実装は 3 件目で遮断していた)
        assert acts[:3] == ["allow", "allow", "allow"] and "block" in acts[3:], acts
        # 単一 str の従来シグネチャ: 盗用キー単体でも同じ窓を共有して数える
        assert sh.inspect("192.0.2.40", path="/api", cred="stolen-key")["action"] == "block"
        # 同じ値が Bearer と X-API-Key の両方に載っても 1 要求 1 回の計上(二重計上なら 3 件目で超過)
        assert sh.inspect("192.0.2.50", path="/api", cred=("dup-key", "dup-key"))["action"] == "allow"
        assert sh.inspect("192.0.2.51", path="/api", cred=("dup-key", ""))["action"] == "allow"
        assert sh.inspect("192.0.2.52", path="/api", cred="dup-key")["action"] == "allow"
        assert sh.inspect("192.0.2.53", path="/api", cred="dup-key")["action"] == "block"


if __name__ == "__main__":
    import unittest
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except unittest.SkipTest as e:
            ok += 1
            print("SKIP", fn.__name__, "->", e)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")
