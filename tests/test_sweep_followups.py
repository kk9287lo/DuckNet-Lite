"""
test_sweep_followups.py — バグ総点検(2026-10)の申し送り分の回帰テスト。
==========================================================================
各修正班が「担当外」として残した小さな欠陥を、主セッションで直したもの。
Full / Lite で同じファイルを置く(gossip は Full 専用なので Lite では SKIP)。
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from unittest import SkipTest

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.services.proxy import _real_client_ip


def _xff(value: str) -> bytes:
    return ("GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: " + value
            + "\r\n\r\n").encode("latin-1")


# ── XFF: 信頼 hop が付けたゾーンID付きの値を『読み飛ばして左へ』進んでいた ──
def test_f1_xff_zone_id_from_trusted_hop_is_stripped_not_skipped():
    """右端(信頼 proxy が付けた=接続元)がリンクローカルのゾーンID付き(fe80::1%eth0)だと、
    候補として捨てて左へ進み、*クライアントが自分で書いた* 値を実クライアントとして採っていた
    (BAN 回避・他人へのなりすまし)。ゾーンIDは外して接続元として扱う(peer と同じ扱い)。"""
    trusted = ["127.0.0.1/32"]
    got = _real_client_ip("127.0.0.1", _xff("198.51.100.66, fe80::1%eth0"), trusted)
    assert got == "fe80::1", got
    # ゾーンIDに任意文字を載せても、鍵に残るのは正規形のアドレスだけ
    got = _real_client_ip("127.0.0.1", _xff("198.51.100.66, fe80::1%a'b<c"), trusted)
    assert got == "fe80::1", got
    # 左端(クライアント申告)のゴミは従来どおり無視して、右の正しい値を採る
    got = _real_client_ip("127.0.0.1", _xff("garbage, 192.0.2.7"), trusted)
    assert got == "192.0.2.7", got


# ── 使用量: IPv6 の Host([v6]:port)が '[2001' として記録されていた ──
def test_f2_usage_host_keeps_bracketed_ipv6():
    """_record_usage は Host から ':' 以降を落としていたため、'[2001:db8::1]:443' が '[2001'
    になり、IPv6 宛ての内訳がすべて 1 つの壊れた名前に潰れていた。"""
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        sh.enable()
        sh.cfg["usage_record"] = True
        for host in ("[2001:DB8::1]:443", "[2001:db8::2]", "App.Example:8080", "plain.example",
                     "2001:db8::3"):
            sh.record_traffic("192.0.2.10", out_bytes=100, in_bytes=10, conn_sec=0.1,
                              host=host, method="GET", path="/")
        rows = sh.usage_list()["rows"]
        hosts = sorted(h["host"] for r in rows for h in r["top_hosts"])
        assert hosts == sorted(["2001:db8::1", "2001:db8::2", "app.example", "plain.example",
                                "2001:db8::3"]), hosts


# ── ファイアウォール: IPv4-mapped の接続元が IPv4 のルール/ゾーンに当たらなかった ──
def test_f3_firewall_matches_ipv4_mapped_source():
    """dual-stack の待受では IPv4 クライアントが '::ffff:192.0.2.5' として届く。_match_rule は
    版(v4/v6)が違うネットワークを照合しないため IPv4 の deny ルールを素通りし、ゾーン判定も
    loopback/private を外していた。判定の入口で純 IPv4 に戻す。"""
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        fw.enable()
        fw.add_rule("192.0.2.0/24", "deny")
        r = fw.evaluate("::ffff:192.0.2.5")
        assert r["action"] == "deny", r
        assert fw.evaluate("::ffff:127.0.0.1")["zone"] == "loopback"
        assert fw.evaluate("192.0.2.5")["action"] == "deny"       # 純 IPv4 は従来どおり


# ── gossip: IPv6 の待受/ピアが ':::1:7946' と表示されていた ──
def test_f4_gossip_status_brackets_ipv6():
    """状態表示(ダッシュボードが読む gossip_status.json と status())が f"{host}:{port}" で、
    IPv6 では ':::1:7946' のように区切りの分からない表記になっていた。"""
    try:
        from dataplane.engine.services.gossip import GossipNode
    except ImportError:
        raise SkipTest("gossip は Full 版のみ")
    with tempfile.TemporaryDirectory() as tmp:
        sh = ND.NetShield(state_dir=tmp)
        g = GossipNode(sh, secret="k", host="::1", port=7946,
                       peers=[("2001:db8::9", 7946), ("192.0.2.9", 7946)], state_dir=tmp)
        assert g.status()["listen"] == "[::1]:7946", g.status()
        g._write_status()
        with open(os.path.join(tmp, "gossip_status.json"), encoding="utf-8") as f:
            st = json.load(f)
        assert st["listen"] == "[::1]:7946", st
        assert st["peers"] == ["[2001:db8::9]:7946", "192.0.2.9:7946"], st


# ── 起動表示: 宣言的設定で拒否されたキーと、直すべき保存済み設定が見えなかった ──
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _banner(state_dir, extra_args=()):
    """製品を子プロセスで起動し、起動バナー(管理トークンの行まで)を読んで止める。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(state_dir, exist_ok=True)
    logp = os.path.join(state_dir, "svc.log")
    env = dict(os.environ)
    env.update({"DUCKNET_OFFLINE": "1", "DUCKNET_STATE_DIR": state_dir,
                "DUCKNET_SELF_DEFENSE": "0", "PYTHONPATH": root})
    cmd = [sys.executable, "-m", "dataplane", "--host", "127.0.0.1",
           "--listen", str(_free_port()), "--admin", str(_free_port()),
           "--backend", "127.0.0.1:9"] + list(extra_args)
    with open(logp, "wb") as out:
        proc = subprocess.Popen(cmd, cwd=root, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env=env)
    seen = ""
    try:
        for _ in range(200):                       # 最大 20 秒
            with open(logp, encoding="utf-8", errors="replace") as f:
                seen = f.read()
            if proc.poll() is not None or "管理トークン" in seen or "アクセスキー" in seen:
                break
            time.sleep(0.1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)
    assert "管理トークン" in seen or "アクセスキー" in seen, seen[-600:]
    return seen


def test_f5_banner_reports_rejected_declarative_keys():
    """宣言的設定(--config)で拒否されたキー(例: 空の site_whitelist での whitelist)は、
    『適用 → …』の一覧に *無い* ことでしか分からなかった。拒否を [警告] で出す。"""
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "cfg.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"site_mode": "whitelist", "rate_per_sec": 25}, f)
        seen = _banner(os.path.join(d, "state"), ["--config", cfg])
    lines = [ln for ln in seen.splitlines() if "宣言的設定" in ln]
    assert any("rate_per_sec" in ln for ln in lines), lines            # 他のキーは適用される
    assert any("[警告]" in ln and "site_mode" in ln for ln in lines), lines


def test_f6_banner_warns_about_saved_empty_site_whitelist():
    """旧版が保存した whitelist+空(全 Host 許可のまま互換維持)は、/api/state の warnings と
    イベントにしか出ず、コンソールで起動した運用者には見えなかった。"""
    with tempfile.TemporaryDirectory() as d:
        st = os.path.join(d, "state")
        sh = ND.NetShield(state_dir=st)
        with sh._lock:
            sh.cfg["site_mode"] = "whitelist"
            sh.cfg["site_whitelist"] = []
            sh._save()
        seen = _banner(st)
    assert any("[警告]" in ln and "site_whitelist" in ln for ln in seen.splitlines()), seen[-600:]


# ── ダッシュボード: /api/state の shield.warnings を表示していなかった ──
def test_f7_dashboard_renders_config_warnings_escaped():
    """r4(#85)で /api/state に shield.warnings を足したが、ダッシュボードの JS は読んでおらず
    画面には何も出なかった。警告欄があり、本文を esc() を通して描くこと(データを生の HTML や
    JS 文字列へ入れない=#1 と同じ規則)。"""
    import re
    import dataplane.admin as A
    page = A._HTML
    assert 'id="cfgwarn"' in page, "警告欄が無い"
    js = page[page.index("async function refresh()"):]
    end = js.find("\nasync function", 1)
    js = js if end < 0 else js[:end]
    assert "s.shield.warnings" in js, "refresh() が shield.warnings を読んでいない"
    sink = [ln for ln in js.splitlines() if 'cfgwarn' in ln and 'innerHTML' in ln]
    assert sink and all(re.search(r"esc\(w\.message", ln) for ln in sink), sink


# ── 管理 API: 早期拒否(415/403/401/421)が本文を読まずに閉じ、拒否理由が届かなかった ──
def test_f8_admin_early_reject_still_delivers_the_response():
    """本文を読まないまま応答して接続を閉じると、未読データのせいで TCP RST になり(Windows は
    受信済みの応答まで捨てる)、正規のクライアントが 415/403/401 の理由を受け取れなかった
    (負荷時に test_c26 が ConnectionAbortedError で落ちたのはこれ)。宣言された本文を上限内で
    読み捨ててから応答する。"""
    import dataplane.admin as A
    with tempfile.TemporaryDirectory() as d:
        ofw, osh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=d)
        ND._SHIELD = ND.NetShield(state_dir=d)
        adm = A.AdminDashboard(host="127.0.0.1", port=0, state_dir=d)
        adm.start()
        try:
            body = b"x" * (512 * 1024)                 # 上限(1 MiB)内の大きめの本文
            cases = [
                ("415", {"Cookie": "%s=%s" % (A._COOKIE_NAME, adm.token),
                         "Content-Type": "text/plain"}),
                ("401", {"Content-Type": "application/json"}),
            ]
            for want, hdrs in cases:
                for _ in range(3):
                    s = socket.create_connection(("127.0.0.1", adm.port), timeout=10)
                    try:
                        head = "POST /api/shield/toggle HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % adm.port
                        head += "".join("%s: %s\r\n" % kv for kv in hdrs.items())
                        head += "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
                        got = b""
                        try:
                            s.sendall(head.encode("latin-1") + body)
                            while True:
                                c = s.recv(65536)
                                if not c:
                                    break
                                got += c
                        except OSError as e:
                            raise AssertionError("応答を受け取る前に接続が切られた: %r (受信 %r)"
                                                 % (e, got[:80]))
                        assert got.startswith(b"HTTP/1.") and (b" " + want.encode() + b" ") in got[:20], got[:120]
                    finally:
                        s.close()
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


# ── stop() が待受を手放さない(Linux): close() は accept()/recvfrom() の待ちを起こさない ──
def _port_is_free(port, kind):
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", port))                # SO_REUSEADDR なし=本当に空いているか
        return True
    except OSError:
        return False
    finally:
        s.close()


def _assert_released(name, obj, port, kind):
    obj.stop()
    deadline = time.time() + 3.0
    while time.time() < deadline and not _port_is_free(port, kind):
        time.sleep(0.05)
    assert _port_is_free(port, kind), "%s: stop() 後もポート %d が使用中のまま" % (name, port)


def test_f9_listeners_release_their_port_on_stop():
    """別スレッドが accept()/recvfrom() で待っているソケットを close() しても、Linux では待ちが
    起きずカーネルが待受を保持したままになる。デコイ・DNS フィルタ・gossip・LDAP プロキシの
    stop() は close() だけだったため、停止後もポートを掴み続け、同じポートで再起動できなかった
    (Windows では close() で起きるので見えなかった)。shutdown() で起こしてから閉じる。"""
    try:
        from dataplane.engine.lifeform.listeners import CanaryListener, DecoySensor
        from dataplane.engine.lifeform.dns import DnsFilter
        from dataplane.engine.lifeform.ldap_proxy import LdapProxy, ProxyMonitor, LdapEnumDetector
        from dataplane.engine.services.gossip import GossipNode
    except ImportError:
        raise SkipTest("デコイ/DNS/LDAP プロキシ/gossip は Full 版のみ")
    with tempfile.TemporaryDirectory() as d:
        a = CanaryListener(DecoySensor(state_dir=d), "ldap", "127.0.0.1", 0, read_timeout=0.3)
        assert a.start()["ok"]
        _assert_released("decoy", a, a.port, socket.SOCK_STREAM)
        p = LdapProxy(ProxyMonitor(state_dir=d), LdapEnumDetector(), listen_host="127.0.0.1",
                      listen_port=0, upstream_host="127.0.0.1", upstream_port=9)
        assert p.start()["ok"]
        _assert_released("ldap-proxy", p, p.listen_port, socket.SOCK_STREAM)
        f = DnsFilter(host="127.0.0.1", port=0, state_dir=d)
        assert f.start()["ok"]
        _assert_released("dns", f, f.port, socket.SOCK_DGRAM)
        g = GossipNode(ND.NetShield(state_dir=d), secret="k", host="127.0.0.1", port=0,
                       state_dir=d)
        assert g.start()["ok"]
        _assert_released("gossip", g, g.port, socket.SOCK_DGRAM)


# ── 整合性監視の通知: すり替えの場所と隔離先が載っていなかった ──
def test_f10_integrity_tamper_event_names_shadowing_paths_and_quarantine():
    """r5 で監視は『ソースより先に import される兄弟(同名パッケージ/拡張モジュール)』と pyc を
    検知し、修復で隔離するようになったが、通知(report_tamper)には basename しか載らず、
    パッケージの場合は 'pipeline' のような名前だけで、隔離先(証拠の置き場)も分からなかった。"""
    try:
        from dataplane.engine.services.proxy import AsyncEdgeGuard
    except ImportError:
        raise SkipTest("proxy が無い")
    shadow = os.path.join(tempfile.gettempdir(), "pkg", "pipeline")
    pyc = os.path.join(tempfile.gettempdir(), "pkg", "__pycache__", "policy.cpython-312.pyc")

    class _SI:
        def tick(self):
            return {"event": "tamper", "modified": [shadow, pyc], "missing": [],
                    "manifest_valid": True, "shadowed": [shadow], "bytecode": [pyc],
                    "repair": {"ok": True, "quarantined": {shadow: shadow + ".quarantined-1"}}}

    with tempfile.TemporaryDirectory() as d:
        old = ND._SHIELD
        ND._SHIELD = ND.NetShield(state_dir=d)
        try:
            g = AsyncEdgeGuard()
            if not hasattr(g, "_make_integrity_tick"):
                raise SkipTest("整合性監視は Full 版のみ")
            g._make_integrity_tick(_SI())()
            last = ND._SHIELD._tamper["last"]
        finally:
            ND._SHIELD = old
    assert last.get("kind") == "integrity_tamper", last
    assert last.get("shadowed") == [shadow], last
    assert last.get("bytecode") == [pyc], last
    assert last.get("quarantined") == {shadow: shadow + ".quarantined-1"}, last
