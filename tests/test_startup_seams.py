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


def test_env_file_missing_is_not_an_error():
    assert service.load_env_file(os.path.join(tempfile.gettempdir(), "no-such-app.env")) == 0
