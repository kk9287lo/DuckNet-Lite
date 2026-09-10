"""
test_startup_seams.py — 起動部と繋ぎ目の潜在バグの再発防止。
====================================================================================
どれも「テストが無いので気づかれていなかった」類の欠陥だった:
  · 設定ミス 1 つでゲートウェイが起動できない(env/引数の数値化が無防備)
  · 起動失敗の理由が捨てられ、5 秒待たされた末に「タイムアウト」としか出ない
  · バナーが実際の待受と違うアドレスを表示する
  · --cluster の停止経路が丸ごと機能せず、子ワーカーが待受ポートを握ったまま残る
  · 防御を用意できないときに黙って素通しする(fail-open)
  · 許可リストが空だと「全部許可」になる(allowlist の意味が反転)
  · クラスタの再起動が *閉じた* listener を使い回して二度と上がらない
  · ロケール未設定(C/POSIX)を「英語」と誤読し、Python のバージョン差で UI 言語が変わる
  · 状態ディレクトリに書けなくても何も言わず、BAN もライセンスも毎回消える
"""
import io
import os
import socket
import sys
import tempfile
import threading
import time
from unittest import SkipTest   # OS 機能が無い環境は黙って通さず明示 SKIP

from dataplane import service
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.services.proxy import AsyncEdgeGuard


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


# ── 設定ミスで起動できなくならない ──
def test_env_float_falls_back_instead_of_crashing():
    """綴り間違い 1 つでゲートウェイが起動時に ValueError で死んでいた(--help も出せない)。
    防御が上がらないのが最悪なので、警告して既定で動く。"""
    key = "DUCKNET_TEST_FLOAT"
    old = os.environ.get(key)
    try:
        os.environ[key] = "abc"
        assert service._env_float(key, 5.0) == 5.0
        os.environ[key] = "  2.5 "
        assert service._env_float(key, 5.0) == 2.5
        os.environ[key] = ""
        assert service._env_float(key, 5.0) == 5.0
        os.environ.pop(key, None)
        assert service._env_float(key, 7.0) == 7.0
    finally:
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old


def test_split_hostport_handles_ipv6_and_bad_ports():
    """旧実装は partition(':') + int() だったため、*IPv6 を指定しただけ* で起動時に
    ValueError で落ちた([::1]:8080 は port=':1]:8080' と解釈されていた)。"""
    f = service._split_hostport
    assert f("127.0.0.1:8080", 80) == ("127.0.0.1", 8080)
    assert f("[::1]:8080", 80) == ("::1", 8080)
    assert f("::1", 80) == ("::1", 80)              # 裸の IPv6(ポート省略)
    assert f("host-only", 80) == ("host-only", 80)
    assert f("", 80) == ("127.0.0.1", 80)
    for bad in ("1.2.3.4:abc", "1.2.3.4:0", "1.2.3.4:70000", "[::1"):
        try:
            f(bad, 80)
        except SystemExit:
            continue
        raise AssertionError("不正な指定が通ってしまった: %r" % (bad,))


# ── 起動失敗の診断 ──
def test_start_reports_the_real_reason_without_waiting():
    """ポート使用中でも例外を捨てて『起動タイムアウト』しか返さず、しかも 5 秒待たされた。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen(1)
    try:
        g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9,
                           listen_host="127.0.0.1", listen_port=port)
        t = time.perf_counter()
        info = g.start()
        took = time.perf_counter() - t
        assert info.get("ok") is False
        assert "タイムアウト" not in info.get("error", "")   # 真因が残ること
        assert took < 3.0, took                              # 5 秒待たされないこと
    finally:
        s.close()


def test_start_still_reports_ok_on_a_free_port():
    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9,
                       listen_host="127.0.0.1", listen_port=0)
    try:
        info = g.start()
        assert info.get("ok") is True, info
    finally:
        g.stop(grace=0.0)


def test_cluster_forks_workers_and_stop_reaps_every_one():
    """--cluster の実プロセス回帰。旧実装では stop() が子を一切止めず、親だけ死んで
    ワーカーが待受ポートを握ったまま残った(実測 13 個残存)。fork して立ち上げ、
    停止後に (1) 子 pid が全滅していること (2) 待受が完全に消えていること を確かめる。
    fork/SO_REUSEPORT を持たない OS(Windows)は対象外なので明示的に SKIP する。"""
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT 非対応の OS(単一プロセスへ降格する経路)")

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()                                    # 直後に同じ番号を掴み直す

    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9,
                       listen_host="127.0.0.1", listen_port=port)
    info = g.serve_cluster(workers=3)
    try:
        assert info.get("mode") == "cluster", info
        assert info.get("ok") is True, info
        pids = list(info.get("child_pids") or [])
        assert len(pids) == 2, info                  # 親も 1 ワーカーを担うので n-1 個
        for pid in pids:
            os.kill(pid, 0)                          # 生きている(死んでいれば OSError)
        socket.create_connection(("127.0.0.1", port), timeout=2.0).close()  # 実際に待受
    finally:
        g.stop(grace=0.0)

    for pid in pids:
        for _ in range(100):                         # 刈り取りは同期だが念のため待つ
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.05)
        else:
            raise AssertionError(f"ワーカー {pid} が停止後も生き残っている")

    # 「解放された」の判定は *待受が消えたか* で行う。空きポートへの bind 可否で見ると、
    # 同時に走る他テストのループバック通信が同じ番号を TIME_WAIT に残すだけで
    # EADDRINUSE になり、製品と無関係に落ちる(実測: 3.10/3.14 の一括実行でのみ再現)。
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        except OSError:
            break                                    # 誰も待受けていない=解放済み
        time.sleep(0.05)
    else:
        raise AssertionError(f"停止後もポート {port} で待受けが続いている(ワーカー残存)")


def test_cluster_restart_rebinds_instead_of_reusing_a_closed_listener():
    """--cluster で上げた親は、停止時に閉じた listener を持ち越してはいけない。
    持ち越すと次の start() が **閉じたソケット** を asyncio へ渡し、以後どうやっても
    起動しない。自己防衛 watchdog の restart() は stop()→start() なので、クラスタ運用では
    『一度でも再起動が要る状況になったら二度と復帰しない』という壊れ方をしていた。"""
    if not (hasattr(os, "fork") and hasattr(socket, "SO_REUSEPORT")):
        raise SkipTest("fork/SO_REUSEPORT 非対応の OS(単一プロセスへ降格する経路)")

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9,
                       listen_host="127.0.0.1", listen_port=port)
    assert g.serve_cluster(workers=2).get("ok") is True
    g.stop(grace=0.0)
    assert g._listen_sock is None, "停止後も listener を握ったまま(次回 start が閉じた fd を使う)"

    info = g.restart()                               # watchdog がやるのと同じ経路
    try:
        assert info.get("ok") is True, info
        socket.create_connection(("127.0.0.1", g.listen_port), timeout=2.0).close()
    finally:
        g.stop(grace=0.0)


def _fd_count():
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1                                    # /proc の無い OS(Windows 等)


def test_stop_releases_sockets_without_waiting_for_the_gc():
    """停止しても FD が GC 任せで開いたまま残っていた(実測: 高負荷停止の直後に 31 本、
    gc.collect() でようやく 5 本)。asyncio のトランスポートは循環参照を作るので、
    参照カウントだけでは解放されない。watchdog の restart() は stop()→start() なので、
    長寿命プロセスでは再起動のたびにこれが積み上がる。"""
    base = _fd_count()
    if base < 0:
        raise SkipTest("/proc/self/fd が無い環境では FD を数えられない")

    back = socket.socket()
    back.bind(("127.0.0.1", 0))
    back.listen(64)
    bport = back.getsockname()[1]
    held = []

    def accept_and_hold():                           # 応答しない=接続が in-flight のまま残る
        while True:
            try:
                c, _ = back.accept()
            except OSError:
                return
            held.append(c)

    th = threading.Thread(target=accept_and_hold, daemon=True)
    th.start()

    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=bport,
                       listen_host="127.0.0.1", listen_port=0)
    assert g.start().get("ok") is True
    clients = []
    try:
        for i in range(20):
            c = socket.socket()
            c.settimeout(3.0)
            try:
                c.connect(("127.0.0.1", g.listen_port))
                c.sendall(b"GET /hold%d HTTP/1.1\r\nHost: h\r\n\r\n" % i)
            except OSError:
                c.close()
                continue
            clients.append(c)
        time.sleep(0.3)                              # 接続を確立させる
        assert _fd_count() > base, "接続が張られていない(前提が崩れている)"
        g.stop(grace=0.2)
        for c in clients:                            # テスト側が持つ FD を先に手放す
            try:
                c.close()
            except OSError:
                pass
        clients = []
        for c in held:
            try:
                c.close()
            except OSError:
                pass
        held[:] = []
        time.sleep(0.2)
        after = _fd_count()                          # 残っていればガード側の取りこぼし
        assert after <= base + 6, (
            "停止後もガード側の FD が %d 本残っている(base=%d, now=%d)"
            % (after - base, base, after))
    finally:
        for c in clients:
            try:
                c.close()
            except OSError:
                pass
        try:
            g.stop(grace=0.0)
        except Exception:
            pass
        back.close()
        for c in held:
            try:
                c.close()
            except OSError:
                pass


def test_stop_makes_the_server_wakeup_safe_to_re_enter():
    """停止のたびに `Exception ignored in _SelectorTransport.__del__` が数十本、
    ログへ流れていた(実測 10 回に 3 回、1 回あたり 30 本)。

    原因は CPython の asyncio.Server._wakeup が *再入不可* なこと ―― 2 回目は
    self._waiters が None のまま反復して TypeError になる。一方 Server._clients は
    WeakSet なので、放置されたトランスポートが GC でまとめて回収されると _detach が
    「残り 0 件」を何度も観測し、_wakeup を連打してしまう。
    セキュリティ製品が停止のたびにクラッシュしたようなログを出すのは通らないので、
    stop() は閉じ終えた Server の wakeup を無効化する(誰も待っていないので無害)。
    """
    # まず「素の CPython は 2 回目で落ちる」ことを確認する(将来 CPython 側が直したら
    # このテストは SKIP になり、余計な細工を残していると気づける)。
    probe = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9,
                           listen_host="127.0.0.1", listen_port=0)
    assert probe.start().get("ok") is True
    raw = probe._server
    try:
        raw._wakeup()                                # 1 回目は正常
        try:
            raw._wakeup()                            # 2 回目
        except TypeError:
            pass
        else:
            raise SkipTest("この Python では Server._wakeup が再入可能(上流で修正済み)")
    finally:
        probe.stop(grace=0.0)

    g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=9,
                       listen_host="127.0.0.1", listen_port=0)
    assert g.start().get("ok") is True
    srv = g._server
    g.stop(grace=0.0)
    for _ in range(3):                               # GC が何度 _detach しても落ちない
        srv._wakeup()


def test_stop_workers_is_a_noop_without_cluster():
    g = AsyncEdgeGuard(listen_host="127.0.0.1", listen_port=0)
    assert g._workers == []
    assert g._stop_workers(0.0) == 0


# ── IPv6 専用ホスト ──
def _ipv6_or_skip():
    if not socket.has_ipv6:
        raise SkipTest("IPv6 非対応のビルド")
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
    except OSError as e:
        raise SkipTest(f"IPv6 ループバックが使えない環境: {e!r}")


def test_address_is_written_with_brackets_for_ipv6():
    """`f"{host}:{port}"` は host が IPv6 だと `::1:8081` になり、URL としても
    アドレスとしても壊れる。表記を1か所(netaddr)に集めて [] で囲う(RFC 3986)。"""
    from dataplane.engine.core import netaddr
    assert netaddr.hostport("127.0.0.1", 8443) == "127.0.0.1:8443"
    assert netaddr.hostport("::1", 8443) == "[::1]:8443"
    assert netaddr.hostport("[::1]", 8443) == "[::1]:8443"     # 二重に囲わない
    assert netaddr.hostport("::", 8443) == "[::]:8443"
    assert netaddr.hostport("example.test", 80) == "example.test:80"
    assert netaddr.url("::1", 8081) == "http://[::1]:8081"
    assert netaddr.url("::1", 8081, "/api/state") == "http://[::1]:8081/api/state"
    assert netaddr.url("127.0.0.1", 8081, "api/state") == "http://127.0.0.1:8081/api/state"
    assert netaddr.is_v6_literal("::1") and netaddr.is_v6_literal("[fe80::1]")
    assert not netaddr.is_v6_literal("127.0.0.1") and not netaddr.is_v6_literal("host")
    # 表記の往復: netaddr で書いたものを service._split_hostport が読み戻せる
    for host in ("127.0.0.1", "::1", "example.test"):
        h, p = service._split_hostport(netaddr.hostport(host, 8443), 80)
        assert (h, p) == (host, 8443), (host, h, p)


def test_family_for_follows_the_listen_address():
    from dataplane.engine.core import netaddr
    assert netaddr.family_for("127.0.0.1") == socket.AF_INET
    assert netaddr.family_for("0.0.0.0") == socket.AF_INET
    _ipv6_or_skip()
    assert netaddr.family_for("::1") == socket.AF_INET6
    assert netaddr.family_for("::") == socket.AF_INET6


def test_admin_dashboard_can_listen_on_ipv6():
    """http.server の既定 address_family は AF_INET 固定。--admin-host に IPv6 を
    指定すると gaierror(-9) で bind に失敗し、service.run() はそこで SystemExit する
    ―― つまり **IPv6 専用ホストでは製品が一切起動できなかった**。"""
    _ipv6_or_skip()
    from dataplane.admin import AdminDashboard
    probe = socket.socket(socket.AF_INET6)
    probe.bind(("::1", 0))
    port = probe.getsockname()[1]
    probe.close()
    adm = AdminDashboard(host="::1", port=port, token="tok-ipv6")
    a = adm.start()
    try:
        assert a.get("ok") is True, a
        assert a["url"] == f"http://[::1]:{adm.port}", a["url"]     # GUI がこの URL を使う
        s = socket.socket(socket.AF_INET6)                          # 実際に到達できる
        s.settimeout(5.0)
        s.connect(("::1", adm.port))
        s.sendall(b"GET /api/state HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n")
        head = s.recv(64)
        s.close()
        assert head.startswith(b"HTTP/1."), head
    finally:
        adm.stop()


def test_guard_reports_ipv6_listen_address_in_a_usable_form():
    _ipv6_or_skip()
    probe = socket.socket(socket.AF_INET6)
    probe.bind(("::1", 0))
    port = probe.getsockname()[1]
    probe.close()
    g = AsyncEdgeGuard(backend_host="::1", backend_port=9,
                       listen_host="::1", listen_port=port)
    info = g.start()
    try:
        assert info.get("ok") is True, info
        assert info["listen"] == f"[::1]:{g.listen_port}", info["listen"]
        assert g.url() == f"http://[::1]:{g.listen_port}", g.url()
    finally:
        g.stop(grace=0.0)


# ── fail-open の封じ込め ──
def test_geo_allowlist_blocks_when_the_compiled_list_is_empty():
    """geo_mode='allow' はコンパイル済み CIDR が空だとブロックごとスキップされ、
    『この地域だけ許可』の設定が黙って『全部許可』になっていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.apply_config({"geo_mode": "allow", "geo_cidrs": ["zzz-invalid"]})
        assert sh._policy_block("203.0.113.9", "/x", True)      # 空の許可リスト=全遮断
        sh.apply_config({"geo_mode": "allow", "geo_cidrs": ["203.0.113.0/24"]})
        assert not sh._policy_block("203.0.113.9", "/x", True)  # 許可内は通す
        assert sh._policy_block("198.51.100.7", "/x", True)     # 許可外は遮断
        sh.apply_config({"geo_mode": "block", "geo_cidrs": []})
        assert not sh._policy_block("203.0.113.9", "/x", True)  # 空の遮断リスト=対象なし


def test_blocked_methods_wrong_type_does_not_erase_the_setting():
    """型の違う宣言的設定(JSON に文字列を書いた等)で、遮断メソッドが空に *置換* され
    ながら ok:True が返っていた=防御が黙って消える。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_blocked_methods(["TRACE", "CONNECT"])
        assert sh.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
        r = sh.set_blocked_methods({"a": 1})
        assert r.get("ok") is False
        assert sh.cfg["blocked_methods"] == ["TRACE", "CONNECT"]   # 保持される
        r = sh.set_blocked_methods("TRACE, CONNECT")               # 文字列は受理して分解
        assert r.get("ok") is True and sh.cfg["blocked_methods"] == ["TRACE", "CONNECT"]
        r = sh.set_blocked_methods(["GET", "b@d"])                 # 不正要素は黙って捨てない
        assert r.get("rejected") == ["B@D"]


def test_unscannable_content_encoding_is_rejected_by_default():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.cfg.get("body_reject_unscannable_encoding") is True


# ── 停止時の取りこぼし ──
def test_flush_state_also_forces_traffic_and_usage():
    """flush_state() が BAN しか書き出さず、間引き中の traffic/usage を停止時に落としていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg["persist_bans"] = True
        sh.cfg["usage_record"] = True
        sh._record_usage("203.0.113.7", 100, 50, 0.1, "h.example", "GET", "/")
        sh._traffic.setdefault("203.0.113.7", {}).setdefault(0, [1.0, 1.0, 1.0])
        sh.flush_state()
        assert os.path.exists(sh._traffic_path), "traffic が書き出されていない"
        assert os.path.exists(sh._usage_path), "usage が書き出されていない"


# ── 言語判定(env → UI/遮断ページの言語) ──
def _with_os_locale(name):
    """OS 側のロケール報告を差し替えるコンテキスト(テストをホスト非依存にする)。
    name=None は「ロケール未設定(C)」、文字列はその設定値を報告する。"""
    import contextlib
    import locale as _loc

    @contextlib.contextmanager
    def _ctx():
        o_set, o_get = _loc.setlocale, _loc.getlocale
        _loc.setlocale = lambda *a, **k: (name or "C")
        _loc.getlocale = lambda *a, **k: ((name.split(".")[0], None) if name
                                          else ("C", "UTF-8"))
        try:
            yield
        finally:
            _loc.setlocale, _loc.getlocale = o_set, o_get
    return _ctx()


def test_c_locale_is_not_mistaken_for_english():
    """ロケール未設定(C/POSIX)は『英語』ではなく『不明』。既定の ja に落ちること。

    Python 3.11 以前の locale.getlocale() は C ロケールを ('en_US', ...) と *報告する*
    ため、ロケールを設定しないサーバ(systemd ユニット・コンテナ・cron の既定)では
    同じ日本語環境が Python のバージョン差だけで英語 UI に化けていた
    (実測: 同一コンテナで 3.10=en / 3.13=ja。遮断ページや通知の言語まで変わる)。

    OS 側のロケールは明示的に模す。ホストのロケールに依存させると、日本語 Windows では
    通って英語 Windows では落ちる(実際 CI の windows-latest で落ちた)。
    env が何も言っていないときに OS を見るのは設計どおり(#84)なので、
    『OS も未設定なら ja』と『OS が英語なら en』の両方を固定する。
    """
    from dataplane.engine.core import i18n
    keys = ("DUCKNET_LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE", "LANG", "LANGUAGE")
    old = {k: os.environ.get(k) for k in keys}
    try:
      with _with_os_locale(None):                    # OS もロケール未設定(C)
        for env, expect in (
                ({}, "ja"),                              # 何も指定なし
                ({"LANG": "C"}, "ja"),                   # ロケール未設定の代表例
                ({"LANG": "C.UTF-8"}, "ja"),             # Docker 公式イメージの既定
                ({"LANG": "POSIX"}, "ja"),
                ({"LC_ALL": "C.UTF-8", "LANG": "ja_JP.UTF-8"}, "ja"),
                ({"LC_CTYPE": "en_US.UTF-8", "LANG": "ja_JP.UTF-8"}, "ja"),  # 文字種は言語ではない
                ({"LC_MESSAGES": "en_US.UTF-8", "LANG": "ja_JP.UTF-8"}, "en"),
                ({"LANG": "ja_JP.UTF-8"}, "ja"),
                ({"LANG": "en_US.UTF-8"}, "en"),         # 明示された英語は従来どおり
                ({"LC_ALL": "en_GB.UTF-8"}, "en"),
                ({"LANGUAGE": "en"}, "en"),
                ({"DUCKNET_LANG": "en", "LANG": "ja_JP.UTF-8"}, "en"),   # 明示指定が最優先
                ({"DUCKNET_LANG": "ja", "LANG": "en_US.UTF-8"}, "ja"),
        ):
            for k in keys:
                os.environ.pop(k, None)
            os.environ.update(env)
            got = i18n.lang()
            assert got == expect, f"{env or '(指定なし)'} → {got}(期待 {expect})"
      with _with_os_locale("English_United States.1252"):   # 英語 Windows 相当
        for env, expect in (
                ({}, "en"),                                  # #84: env 無しでも英語になる
                ({"LANG": "C"}, "en"),                       # env が何も言っていない=OS を見る
                ({"LANG": "ja_JP.UTF-8"}, "ja"),             # 明示指定は OS より優先
                ({"DUCKNET_LANG": "ja"}, "ja"),
        ):
            for k in keys:
                os.environ.pop(k, None)
            os.environ.update(env)
            got = i18n.lang()
            assert got == expect, f"[英語OS] {env or '(指定なし)'} → {got}(期待 {expect})"
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ── サービスとして動かしたときのログ ──
def test_startup_banner_reaches_a_redirected_log_while_still_running():
    """標準出力がパイプ/ファイル(= systemd・docker・nohup、つまり実運用の全部)だと
    Python はブロックバッファにする。そのため **起動して数秒経ってもログが 0 バイト**
    という状態になっていた ―― 内容が出るのは *プロセスが止まったとき*。
    起動バナーには **管理トークン** が載るので、運用者は「起動したか」も
    「どのトークンで管理画面へ入るか」も分からない。
    実際に子プロセスとして起動し、*動いている間に* バナーが読めることを確かめる。"""
    import subprocess

    def _free():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as d:
        logp = os.path.join(d, "svc.log")
        env = dict(os.environ)
        env.update({"DUCKNET_OFFLINE": "1", "DUCKNET_STATE_DIR": os.path.join(d, "state"),
                    "DUCKNET_SELF_DEFENSE": "0", "PYTHONPATH": root})
        env.pop("PYTHONUNBUFFERED", None)          # -u 相当が効いていては検証にならない
        cmd = [sys.executable, "-m", "dataplane",
               "--host", "127.0.0.1", "--listen", str(_free()),
               "--admin", str(_free()), "--backend", "127.0.0.1:9"]
        with open(logp, "wb") as out:
            proc = subprocess.Popen(cmd, cwd=root, stdout=out, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, env=env)
        try:
            seen = ""
            for _ in range(150):                   # 最大 15 秒
                if proc.poll() is not None:
                    break
                with open(logp, encoding="utf-8", errors="replace") as f:
                    seen = f.read()
                if "管理トークン" in seen or "アクセスキー" in seen:
                    break
                time.sleep(0.1)
            assert proc.poll() is None, (
                "子プロセスが落ちた(exit=%r)。ログ: %r" % (proc.poll(), seen[-400:]))
            assert "管理トークン" in seen or "アクセスキー" in seen, (
                "稼働中なのにバナーがログへ出てこない(ブロックバッファに滞留している)。"
                "ログ %d バイト: %r" % (len(seen), seen[-400:]))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass


# ── 非 UTF-8 コンソールでの出力(英語版 Windows・ASCII ロケール) ──
def test_force_utf8_stdio_survives_a_cp1252_console():
    """本製品のメッセージは日本語なので、非 UTF-8 の標準出力へそのまま書くと落ちる。
    _force_utf8_stdio() を通した後は書けること。"""
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
        sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
        try:
            print("警告")                        # 素の cp1252 では書けない
            raise AssertionError("cp1252 に日本語が書けてしまった(前提が崩れている)")
        except UnicodeEncodeError:
            pass
        service._force_utf8_stdio()
        print("警告: 保護は動作していません")     # 寄せた後は書ける
        print("警告", file=sys.stderr)
    finally:
        sys.stdout, sys.stderr = old_out, old_err


def test_every_module_entry_point_normalizes_stdio_before_printing():
    """`python -m <pkg>` で直接起動できる入口は、日本語を出す前に必ず標準出力を
    UTF-8 へ寄せること。

    `python -m dataplane.gui` は service.main() を通らないためこれが抜けており、
    非 UTF-8 コンソールでは『別プロセスがポートを占有していて保護が動作していない』
    という *いちばん落ちてはいけない警告* を出そうとした瞬間に UnicodeEncodeError で
    落ちていた(cp1252 の stderr で再現済み)。
    """
    import ast
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pkg = os.path.join(root, "dataplane")
    entries = []
    for dirpath, dirnames, filenames in os.walk(pkg):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        if "__main__.py" in filenames:
            entries.append(os.path.join(dirpath, "__main__.py"))
    assert entries, "python -m の入口が1つも見つからない(探索が壊れている)"
    entries = [(p, False) for p in entries]
    # テストランナー自身も「直接起動される入口」。しかも *無条件* に検査する:
    # ここが出す日本語は SkipTest や例外のメッセージ ―― つまりリテラルではなく
    # **実行時の値** なので、下の「非ASCIIリテラルを print しているか」では拾えない。
    # 実際その穴で漏らし、英語版 Windows の CI が結果表示の途中で
    # UnicodeEncodeError を起こし、要約すら出ないまま exit 1 になっていた。
    entries.append((os.path.join(root, "tests", "run_all.py"), True))

    for path, always in entries:
        src = open(path, encoding="utf-8").read()
        tree = ast.parse(src)
        prints_non_ascii = any(
            isinstance(n, ast.Constant) and isinstance(n.value, str)
            and not n.value.isascii()
            for c in ast.walk(tree)
            if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "print"
            for n in ast.walk(c))
        if not (always or prints_non_ascii):
            continue        # 自分では非ASCIIを出さない入口(委譲するだけ)は対象外
        called = any(isinstance(n, ast.Call)
                     and getattr(n.func, "id", "") == "_force_utf8_stdio"
                     for n in ast.walk(tree))
        assert called, (                      # 定義があるだけでは足りない。呼ぶこと。
            "%s が標準出力を UTF-8 へ寄せていない(非 UTF-8 端末で落ちる)"
            % os.path.relpath(path, root))


# ── app.env の読み込み(全入口で同じ挙動) ──
def test_env_file_loader_is_forgiving_and_caller_wins():
    """設定ファイルの読み込みは製品本体が行う。以前はシェルのランチャ 3 本が各々の
    脆いパーサを持ち、`KEY = value` のように = の前後へ空白を入れただけで run.sh が
    起動不能になり、GUI ランチャに至っては app.env を読んでさえいなかった。"""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "app.env")
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write("# コメント\n"
                    "DUCKNET_TEST_A=plain\n"
                    "  DUCKNET_TEST_B = spaced \n"        # = の前後に空白
                    "   # 字下げコメント\n"
                    'DUCKNET_TEST_C="quoted!bang"\r\n'    # 引用符 + CRLF
                    "DUCKNET_TEST_D=has=equals\n"
                    "BAD-KEY=x\n")                        # 不正キーは飛ばす(落とさない)
        keys = ["DUCKNET_TEST_A", "DUCKNET_TEST_B", "DUCKNET_TEST_C",
                "DUCKNET_TEST_D", "BAD-KEY", "DUCKNET_TEST_E"]
        old = {k: os.environ.get(k) for k in keys}
        try:
            os.environ["DUCKNET_TEST_E"] = "fromcaller"
            with open(p, "a", encoding="utf-8") as f:
                f.write("DUCKNET_TEST_E=fromfile\n")
            service.load_env_file(p)
            assert os.environ["DUCKNET_TEST_A"] == "plain"
            assert os.environ["DUCKNET_TEST_B"] == "spaced"
            assert os.environ["DUCKNET_TEST_C"] == "quoted!bang"
            assert os.environ["DUCKNET_TEST_D"] == "has=equals"
            assert "BAD-KEY" not in os.environ
            assert os.environ["DUCKNET_TEST_E"] == "fromcaller"   # 呼び出し側が勝つ
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def test_unwritable_state_dir_is_detected_not_silently_ignored():
    """状態ディレクトリに書けないまま起動しても、見た目は完全に正常に動く。
    BAN・累犯記録・ライセンス・完全性ベースラインだけが *毎回の再起動で黙って消える*
    (ハードニングした systemd ユニットや読取専用ボリュームで普通に起こる)。
    モードビットではなく実書き込みで判定すること。"""
    with tempfile.TemporaryDirectory() as d:
        assert service.state_dir_writable(d) is True

        blocker = os.path.join(d, "iam-a-file")     # ファイルの下にはディレクトリを作れない
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        assert service.state_dir_writable(os.path.join(blocker, "state")) is False

        # POSIX の書込不可ディレクトリ(root は権限を無視できるので対象外)
        if os.name == "posix" and getattr(os, "geteuid", lambda: 0)() != 0:
            ro = os.path.join(d, "ro")
            os.mkdir(ro)
            os.chmod(ro, 0o555)
            try:
                assert service.state_dir_writable(ro) is False
            finally:
                os.chmod(ro, 0o755)


def test_env_file_missing_is_not_an_error():
    assert service.load_env_file(os.path.join(tempfile.gettempdir(), "no-such-app.env")) == 0
