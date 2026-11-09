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
from unittest.mock import patch

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


def test_acl_signed_reload_and_legacy_migration():
    # 初回の無署名 ACL は従来の意味で読み、直ちに署名形式へ移す。
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "acl.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"enabled": True, "policy": {"public": "allow"},
                       "rules": [{"net": "8.8.8.8/32", "action": "deny"}]}, f)
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.is_enabled() and fw.evaluate("8.8.8.8")["action"] == "deny"
        assert fw.evaluate("1.1.1.1")["action"] == "allow"
        with open(path, encoding="utf-8") as f:
            assert json.load(f)["_sv"] == 3
        restored = FW.AppFirewall(state_dir=tmp)
        assert restored.is_enabled() and restored.evaluate("8.8.8.8")["action"] == "deny"
        assert restored.evaluate("1.1.1.1")["action"] == "allow"


def test_acl_legacy_malformed_structure_uses_safe_policy():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "acl.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"enabled": True, "policy": ["public", "allow"],
                       "rules": [{"net": "1.1.1.1/32", "action": "unknown"}]}, f)
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.is_enabled() and fw.evaluate("1.1.1.1")["action"] == "deny"
        assert fw.rules == []


def test_acl_tamper_and_deletion_after_signed_save_fail_closed():
    # ACL だけを書き換え/消せる攻撃者が FW を OFF にしても、再起動後に外部を許可しない。
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.is_enabled() is True                  # 状態欠落は安全側で起動
        fw.enable()
        fw.set_policy("public", "allow")
        fw.add_rule("8.8.8.8/32", "deny")
        assert FW.AppFirewall(state_dir=tmp).evaluate("1.1.1.1")["action"] == "allow"
        path = fw.path
        with open(path, encoding="utf-8") as f:
            signed = json.load(f)
        signed["_payload"]["enabled"] = False
        with open(path, "w", encoding="utf-8") as f:
            json.dump(signed, f)
        tampered = FW.AppFirewall(state_dir=tmp)
        assert tampered.is_enabled() and tampered.evaluate("1.1.1.1")["action"] == "deny"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"enabled": False, "policy": {"public": "allow"}}, f)
        unsigned = FW.AppFirewall(state_dir=tmp)
        assert unsigned.is_enabled() and unsigned.evaluate("1.1.1.1")["action"] == "deny"
        os.unlink(path)
        deleted = FW.AppFirewall(state_dir=tmp)
        assert deleted.is_enabled() and deleted.evaluate("1.1.1.1")["action"] == "deny"


def test_acl_failed_save_rejects_and_restores_previous_policy():
    # 永続化失敗を成功と返すと、再起動後に有効化・deny ルールが消える。
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.disable()["ok"]
        with patch.object(FW, "write_signed_json", return_value=False):
            assert fw.enable()["ok"] is False and not fw.is_enabled()
        assert fw.enable()["ok"] and fw.is_enabled()
        assert fw.add_rule("8.8.8.8/32", "deny")["ok"]
        before_rules = list(fw.rules)
        before_policy = dict(fw.policy)
        with patch.object(FW, "write_signed_json", side_effect=OSError("disk full")):
            assert fw.disable()["ok"] is False and fw.is_enabled()
            assert fw.set_policy("public", "allow")["ok"] is False
            assert fw.add_rule("1.1.1.1/32", "allow")["ok"] is False
            assert fw.remove_rule("8.8.8.8/32")["ok"] is False
        assert fw.policy == before_policy and fw.rules == before_rules
        restored = FW.AppFirewall(state_dir=tmp)
        assert restored.is_enabled() and restored.policy == before_policy
        assert restored.rules == before_rules
        assert restored.evaluate("8.8.8.8")["action"] == "deny"


def test_acl_remember_failure_keeps_pending_request():
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        fw.enable()
        fw.set_policy("public", "prompt")
        pid = fw.evaluate("1.1.1.1")["pending_id"]
        with patch.object(FW, "write_signed_json", return_value=False):
            result = fw.approve(pid, remember=True)
        assert result["ok"] is False
        assert [p["id"] for p in fw.pending()] == [pid]
        assert fw.rules == []
        assert fw.approve(pid, remember=True)["ok"] is True
        assert fw.pending() == []
        assert FW.AppFirewall(state_dir=tmp).evaluate("1.1.1.1")["action"] == "allow"


def test_acl_rule_input_rejects_non_string_and_oversize_without_state_change():
    """A bool is a valid ipaddress integer, but it is not a durable CIDR rule."""
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.add_rule("1.1.1.1/32", "deny", note="operator")["ok"]
        before = list(fw.rules)
        with open(fw.path, "rb") as f:
            saved = f.read()
        for net, note in ((True, "bad"), (1, "bad"),
                          ("2.2.2.2/32", True),
                          ("2.2.2.2/32", "x" * (FW._NOTE_MAX_CHARS + 1)),
                          (" " * (FW._NET_MAX_CHARS + 1), "bad")):
            result = fw.add_rule(net, "allow", note=note)
            assert result["ok"] is False, (net, note, result)
            assert fw.rules == before
            with open(fw.path, "rb") as f:
                assert f.read() == saved
        restored = FW.AppFirewall(state_dir=tmp)
        assert restored.rules == before
        assert restored.evaluate("1.1.1.1")["action"] == "deny"


def test_acl_load_only_explicit_boolean_false_disables_even_for_signed_state():
    for signed in (False, True):
        for enabled in (None, [], 0, "false"):
            with tempfile.TemporaryDirectory() as tmp:
                payload = {"policy": {"public": "allow"}, "rules": []}
                if enabled is not None:
                    payload["enabled"] = enabled
                path = os.path.join(tmp, "acl.json")
                if signed:
                    fresh = FW.AppFirewall(state_dir=tmp)
                    assert FW.write_signed_json(path, payload, fresh._state_key)
                else:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(payload, f)
                fw = FW.AppFirewall(state_dir=tmp)
                assert fw.is_enabled() and fw.evaluate("1.1.1.1")["action"] == "deny"
                assert fw.status()["load_warning"]
        # 正規の旧版/署名済み明示 OFF は既存意味を変えない。
        with tempfile.TemporaryDirectory() as tmp:
            payload = {"enabled": False, "policy": {"public": "allow"}, "rules": []}
            path = os.path.join(tmp, "acl.json")
            if signed:
                fresh = FW.AppFirewall(state_dir=tmp)
                assert FW.write_signed_json(path, payload, fresh._state_key)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
            fw = FW.AppFirewall(state_dir=tmp)
            assert not fw.is_enabled() and fw.status()["load_warning"] == ""
            assert FW.AppFirewall(state_dir=tmp).is_enabled() is False


def test_acl_load_rejects_entire_oversized_or_malformed_rule_set():
    valid = {"net": "1.1.1.1/32", "action": "deny", "note": "operator"}
    cases = ([valid] * (FW._RULES_MAX + 1),
             [valid, {"net": True, "action": "deny"}],
             [valid, {"net": "2.2.2.2/32", "action": "allow",
                      "note": "x" * (FW._NOTE_MAX_CHARS + 1)}])
    for signed in (False, True):
        for rules in cases:
            with tempfile.TemporaryDirectory() as tmp:
                payload = {"enabled": True, "policy": {"public": "allow"}, "rules": rules}
                path = os.path.join(tmp, "acl.json")
                if signed:
                    fresh = FW.AppFirewall(state_dir=tmp)
                    assert FW.write_signed_json(path, payload, fresh._state_key)
                else:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(payload, f)
                fw = FW.AppFirewall(state_dir=tmp)
                assert fw.is_enabled() and fw.rules == []
                assert all(action == "deny" for action in fw.policy.values())
                assert fw.evaluate("1.1.1.1")["action"] == "deny"
                assert fw.evaluate("127.0.0.1")["action"] == "deny"
                assert "ルール" in fw.status()["load_warning"]


def test_acl_rule_limit_replacement_and_compiled_cache_cleanup():
    with tempfile.TemporaryDirectory() as tmp, patch.object(FW, "_RULES_MAX", 2):
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.add_rule("1.1.1.1/32", "deny")["ok"]
        assert fw.add_rule("2.2.2.2/32", "deny")["ok"]
        assert fw.evaluate("1.1.1.1")["action"] == "deny"
        assert fw._nets
        before = list(fw.rules)
        with open(fw.path, "rb") as f:
            saved = f.read()
        assert fw.add_rule("3.3.3.3/32", "allow")["ok"] is False
        assert fw.rules == before
        with open(fw.path, "rb") as f:
            assert f.read() == saved
        assert fw.add_rule("1.1.1.1/32", "allow")["ok"] is True
        assert len(fw.rules) == 2
        assert fw.remove_rule("1.1.1.1/32")["ok"]
        assert "1.1.1.1/32" not in fw._nets
        assert fw.add_rule("3.3.3.3/32", "deny")["ok"]
        assert FW.AppFirewall(state_dir=tmp).evaluate("3.3.3.3")["action"] == "deny"


def test_acl_pending_resolution_requires_bool_remember_and_string_id():
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.set_policy("public", "prompt")["ok"]
        pid = fw.evaluate("1.1.1.1")["pending_id"]
        assert pid
        assert fw.approve(pid, remember="false")["ok"] is False
        assert fw.deny_pending(pid, remember=1)["ok"] is False
        assert fw.approve([], remember=False)["ok"] is False
        assert [p["id"] for p in fw.pending()] == [pid]
        assert fw.rules == []
        assert fw.approve(pid, remember=False)["ok"] is True
        assert fw.rules == []
        pid2 = fw.evaluate("2.2.2.2")["pending_id"]
        assert fw.approve(pid2, remember=True)["ok"] is True
        assert FW.AppFirewall(state_dir=tmp).evaluate("2.2.2.2")["action"] == "allow"


def test_acl_global_block_is_one_durable_change():
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.is_enabled()
        assert fw.set_global_block(True)["ok"]
        assert fw.is_enabled() and fw.evaluate("1.1.1.1")["action"] == "deny"
        assert fw.set_global_block(False)["ok"]
        assert fw.is_enabled() and fw.evaluate("1.1.1.1")["action"] == "allow"
        restored = FW.AppFirewall(state_dir=tmp)
        assert restored.is_enabled() and restored.evaluate("1.1.1.1")["action"] == "allow"


def test_acl_global_block_failed_save_restores_both_fields():
    with tempfile.TemporaryDirectory() as tmp:
        fw = FW.AppFirewall(state_dir=tmp)
        assert fw.disable()["ok"]
        with patch.object(FW, "write_signed_json", return_value=False):
            assert fw.set_global_block(False)["ok"] is False
        assert not fw.is_enabled() and fw.policy["public"] == "deny"
        assert fw.set_global_block(True)["ok"]
        with patch.object(FW, "write_signed_json", return_value=False):
            assert fw.set_global_block(False)["ok"] is False
        assert fw.is_enabled() and fw.evaluate("1.1.1.1")["action"] == "deny"
        restored = FW.AppFirewall(state_dir=tmp)
        assert restored.is_enabled() and restored.evaluate("1.1.1.1")["action"] == "deny"


def test_acl_large_log_reads_only_bounded_tail_and_skips_bad_lines():
    import builtins
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "acl_log.jsonl")
        with open(path, "wb") as f:
            f.seek(FW._LOG_READ_MAX + 1024)
            f.write(b"oversized-prefix\n")
            for i in range(2005):
                f.write(json.dumps({"action": "deny", "id": i}).encode() + b"\n")
            f.write(b"not-json\n")
            f.write(b'{"action":[]}\n')

        actual_open = builtins.open

        class BoundedReader:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.inner.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def read(self, size=-1):
                assert 0 <= size <= FW._LOG_READ_MAX, size
                return self.inner.read(size)

            def readlines(self, *args):
                raise AssertionError("ACL log must not be fully read")

        def bounded_open(name, *args, **kwargs):
            inner = actual_open(name, *args, **kwargs)
            return BoundedReader(inner) if os.fspath(name) == path else inner

        with patch.object(FW, "open", bounded_open, create=True):
            fw = FW.AppFirewall(state_dir=tmp)
        logs = fw.log(2000)
        assert len(logs) == 1998 and logs[0]["id"] == 7 and logs[-1]["id"] == 2004
        assert fw.stats()["by_action"] == {"deny": 1998}


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
    """Invalid declarations reject the whole batch before opening either listener."""
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "cfg.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"site_mode": "whitelist", "rate_per_sec": 25}, f)
        state = os.path.join(d, "state")
        baseline = dict(ND.NetShield(state_dir=state).cfg)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ports = [_free_port(), _free_port()]
        env = dict(os.environ, DUCKNET_STATE_DIR=state, DUCKNET_OFFLINE="1", PYTHONPATH=root)
        cmd = [sys.executable, "-m", "dataplane", "--host", "127.0.0.1", "--listen", str(ports[0]),
               "--admin", str(ports[1]), "--backend", "127.0.0.1:9", "--config", cfg]
        result = subprocess.run(cmd, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=15)
        seen = (result.stdout + result.stderr).decode("utf-8", "replace")
        assert result.returncode != 0 and "宣言的設定を適用できません" in seen, seen
        assert "管理トークン" not in seen
        for port in ports:
            with socket.socket() as probe:
                probe.settimeout(0.2)
                assert probe.connect_ex(("127.0.0.1", port)) != 0
        restored = ND.NetShield(state_dir=state).cfg
        assert restored["rate_per_sec"] == baseline["rate_per_sec"]
        assert restored["site_mode"] == baseline["site_mode"]
        # A valid declaration still starts normally and reports its applied key.
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"rate_per_sec": 25}, f)
        seen = _banner(state, ["--config", cfg])
        assert any("宣言的設定" in line and "rate_per_sec" in line for line in seen.splitlines()), seen


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
    受信済みの応答まで捨てる)、正規のクライアントが 403/401 の理由を受け取れなかった
    (負荷時に test_c26 が ConnectionAbortedError で落ちたのはこれ)。送信済みの本文は
    短い総期限内で読み捨て、宣言だけの本文を待ち続けない。"""
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
                ("403", {"X-Token": adm.token, "Content-Type": "text/plain",
                         "Origin": "http://127.0.0.1:9999"}),
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


# ── 完全性監視: 基準を書けなかったのに ok を返していた ──
def test_f11_integrity_baseline_reports_failure_when_nothing_was_saved():
    """baseline() は複製とマニフェストの書込例外をすべて握りつぶして常に ok=True を返していた。
    保存先に書けない(読み取り専用・ファイルで塞がれている等)と基準は何も残らないのに、
    --integrity-baseline は終了コード 0 で終わり、終了コードを見る deploy 手順は成功と判断した。"""
    try:
        from dataplane.engine.core.integrity import SelfIntegrity
    except ImportError:
        raise SkipTest("自己完全性監視は Full 版のみ")
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "code.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("a'b<c\n")
        state = os.path.join(d, "state")
        os.makedirs(state)
        with open(os.path.join(state, ".integrity"), "w", encoding="utf-8") as f:
            f.write("x")                                   # 基準の置き場(ディレクトリ)を作れなくする
        out = SelfIntegrity(state, paths=[src], secret=b"k" * 32).mon.baseline()
        assert out.get("ok") is False, out
        assert out.get("errors"), out                       # 何が書けなかったかを残す
        ok_state = os.path.join(d, "state2")
        os.makedirs(ok_state)
        out2 = SelfIntegrity(ok_state, paths=[src], secret=b"k" * 32).mon.baseline()
        assert out2.get("ok") is True and not out2.get("errors"), out2   # 正常系は従来どおり


# ── トレイ: 保護の切り替えに失敗しても何も言わなかった ──
def test_f12_tray_toggle_failure_is_reported_not_swallowed():
    """トレイの『防御 ON/OFF』『Under Attack 切替』は失敗を except Exception: pass で捨てており、
    ゲートウェイが止まっている・トークンが合わない等で切り替わらなくても利用者は気づけなかった。
    失敗は『何が起きたか+次の一手』の平文で知らせる(例外文字列や JSON は出さない)。"""
    try:
        import dataplane.gui.app  # noqa: F401  (Full 版のコントロールパネル=トレイに防御切替がある)
    except ImportError:
        raise SkipTest("トレイに防御の切り替えが無い版(Lite)")
    try:
        import dataplane.gui.__main__ as GM
    except Exception as e:                                  # Tk の無いサーバ等
        raise SkipTest("GUI モジュールを読み込めない環境: %r" % (e,))

    class _Down:
        def cfg(self):
            raise ConnectionRefusedError(10061, "refused")

        def set_config(self, changes):
            raise AssertionError("cfg() が失敗したのに set_config まで進んだ")

    class _Ok:
        def __init__(self):
            self.sent = []

        def cfg(self):
            return {"enabled": True, "under_attack": False}

        def set_config(self, changes):
            self.sent.append(changes)

    shown = []
    assert GM._tray_toggle(_Down(), "enabled", shown.append) is False
    assert len(shown) == 1 and shown[0], shown
    assert "Traceback" not in shown[0] and "{" not in shown[0], shown[0]
    assert "10061" not in shown[0], shown[0]               # 生の例外文字列を出さない
    ok = _Ok()
    shown.clear()
    assert GM._tray_toggle(ok, "under_attack", shown.append) is True
    assert ok.sent == [{"under_attack": True}] and shown == [], (ok.sent, shown)
