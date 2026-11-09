"""
test_sweep_bans.py — BAN 管理まわりの回帰(掃討パス: bans グループ)。
====================================================================================
· #7  既存の永続BAN/長期制限が、penalize 等の自動BAN(ban_ttl_sec)で短縮されない。
· #8  _evict が現役BANを捨てず、容量超過時は新規IPを拒否する。
· #25 手動BANは IP を正規化して保存し、CIDR/ゾーンID付き/不正な文字列は拒否する。
· #45 IP 白/黒リスト・BAN/解除は表記ゆれ(大文字/非圧縮 IPv6)でも同じIPとして照合する。
· #48 間引かれた BAN 保存は、後続イベントが無くても間隔経過後に必ずディスクへ出る。
· #82 クォータ超過BANはロック下で決定する(並行 ban と _ips を奪い合わない)。
· #84 BAN 解除した IP はサブネット hot 集計から外れる。
"""
import tempfile
import threading
import time

from dataplane.engine.lifeform import pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.core.signed_state import read_signed_json


def _shield(d):
    sh = NetShield(state_dir=d)
    sh.enable()
    return sh


# ── #7: 永続/長期BANが自動BANで短縮される ──────────────────────────────

def test_c7_permanent_ban_not_shortened_by_penalize():
    """永続BAN中の IP へ penalize(slowloris 等)が 2 回来ると、旧実装は ban_ttl_sec(300s)の
    時限BANへ上書きし、その短縮版を blocklist へ書いていた(再起動後も 300s で解ける)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        ip = "203.0.113.9"
        sh.ban(ip, permanent=True)
        sh.penalize(ip)
        sh.penalize(ip)
        info = sh.ban_info(ip)
        assert info["banned"] and info["permanent"], info
        assert info["remain_sec"] == -1, info
        again = NetShield(state_dir=d).ban_info(ip)      # 再起動後も永続のまま
        assert again["banned"] and again["permanent"], again


def test_c7_restricted_long_ban_not_shortened():
    """7日の一時制限(restrict)が penalize 2 回で 300s に縮み、双方合意を待たずに解けていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        ip = "203.0.113.10"
        sh.restrict(ip, ttl_sec=7 * 86400)
        sh.penalize(ip)
        sh.penalize(ip)
        assert sh.ban_info(ip)["remain_sec"] > 6 * 86400, sh.ban_info(ip)


# ── #8: 表が BAN で埋まると永続BANまで追い出される ─────────────────────────

def _flood_self_bans(sh, n):
    """攻撃者が使い捨て IPv6 で即BAN級の違反を重ね、自分の BAN で状態表を埋める
    (Lite には囮URLが無いので penalize の一撃加点で BAN させる)。"""
    accepted, rejected = [], []
    for i in range(n):
        ip = f"2001:db8:{i:x}::1"
        result = sh.penalize(ip, weight=1000)
        if result.get("banned"):
            accepted.append(ip)
        else:
            assert result.get("ok") is False and result.get("action") == "block", result
            rejected.append(ip)
    return accepted, rejected


def test_c8_evict_keeps_permanent_ban():
    """旧実装は非BANが尽きると最古(seen)の BAN から捨て、運用者の永続BANまで消して
    blocklist.json からも落としていた(=表を埋めるだけで BAN が解ける)。"""
    old = P._MAX_IPS
    P._MAX_IPS = 12
    try:
        with tempfile.TemporaryDirectory() as d:
            sh = _shield(d)
            v = "198.51.100.66"
            sh.ban(v, permanent=True)
            accepted, rejected = _flood_self_bans(sh, 30)
            assert accepted and rejected
            assert all(sh.is_banned_fast(ip) for ip in accepted)
            assert len(sh._ips) <= P._MAX_IPS
            assert sh.is_banned_fast(v)
            assert sh.inspect(v, path="/")["action"] == "block"
            assert v in {b["ip"] for b in NetShield(state_dir=d).bans()}
    finally:
        P._MAX_IPS = old


def test_c8_evict_preserves_all_active_temporary_bans():
    """長期制限と使い捨てIPの現役BANを容量圧力で解除してはならない。"""
    old = P._MAX_IPS
    P._MAX_IPS = 12
    try:
        with tempfile.TemporaryDirectory() as d:
            sh = _shield(d)
            r = "198.51.100.77"
            sh.restrict(r, ttl_sec=7 * 86400)
            accepted, rejected = _flood_self_bans(sh, 30)
            assert accepted and rejected
            assert all(sh.is_banned_fast(ip) for ip in accepted)
            assert sh.is_banned_fast(r)
            assert sh.ban_info(r)["remain_sec"] > 6 * 86400
            assert len(sh._ips) <= P._MAX_IPS                # 表の上限は保たれる
    finally:
        P._MAX_IPS = old


# ── #25 / #45: IP を生文字列で照合していた ─────────────────────────────

def test_c25_manual_ban_noncanonical_spellings_block():
    """空白付き・大文字・非圧縮 IPv6・IPv4-mapped で手動BANすると、一覧には載るのに
    実際の通信(正規形の peer IP)は素通りしていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        cases = [("203.0.113.5 ", "203.0.113.5"),
                 ("2001:DB8::1", "2001:db8::1"),
                 ("2001:0db8:0:0:0:0:0:2", "2001:db8::2"),
                 ("::ffff:203.0.113.6", "203.0.113.6")]
        for raw, peer in cases:
            r = sh.ban(raw)
            assert r["ok"] and r["banned"] == peer, r
            assert sh.inspect(peer, path="/")["action"] == "block", raw
        assert {b["ip"] for b in sh.bans()} == {p for _r, p in cases}


def test_c25_manual_ban_rejects_cidr_and_non_ip():
    """CIDR やゾーンID付き・IP でない文字列も ok:True で受け付け、何も遮断しないBANが一覧に
    並んでいた。単一IP以外は拒否する(範囲はファイアウォールのルールで扱う)。
    ゾーンID付き(fe80::1%eth0)は、proxy が peer のゾーンを外して渡すようになったので、ゾーンを
    外した fe80::1 として BAN する(実際に遮断できる・rv_config #17)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for raw in ("203.0.113.0/24", "not-an-ip", "", "a'b<c"):
            r = sh.ban(raw)
            assert r.get("ok") is False and r.get("error"), (raw, r)
        assert sh.bans() == []
        r = sh.ban("fe80::1%eth0")
        assert r.get("ok") is True and r.get("banned") == "fe80::1", r
        assert sh.inspect("fe80::1", path="/")["action"] == "block"


def test_c25_admin_ban_route_rejects_cidr_and_normalizes():
    """管理画面の手動BAN(/api/shield/ban)は CIDR も ok:true で受けて一覧に載せるだけで何も
    遮断せず、空白付き/大文字の IPv6 も素通りさせていた。"""
    import json
    import urllib.error
    import urllib.request
    import dataplane.engine.lifeform.policy as FW
    from dataplane.admin import AdminDashboard
    with tempfile.TemporaryDirectory() as d:
        ofw, osh = FW._FW, P._SHIELD
        FW._FW = FW.AppFirewall(state_dir=d)
        P._SHIELD = _shield(d)
        adm = AdminDashboard(host="127.0.0.1", port=0)
        adm._state_dir = d
        url = adm.start()["url"]
        try:
            def post(path, body):
                req = urllib.request.Request(
                    url + path, data=json.dumps(body).encode(), method="POST",
                    headers={"Content-Type": "application/json", "X-Token": adm.token})
                try:
                    response = urllib.request.urlopen(req, timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    return response.status, json.loads(response.read())

            status, r = post("/api/shield/ban", {"ip": "203.0.113.0/24"})
            assert status == 400, (status, r)
            assert r.get("ok") is False and r.get("error"), r
            status, r = post("/api/shield/ban", {"ip": " 2001:DB8::1 "})
            assert status == 200, (status, r)
            assert r.get("ok") is True, r
            assert P._SHIELD.inspect("2001:db8::1", path="/")["action"] == "block"
            assert {b["ip"] for b in P._SHIELD.bans()} == {"2001:db8::1"}
        finally:
            adm.stop()
            FW._FW, P._SHIELD = ofw, osh


def test_c45_unban_accepts_noncanonical_spelling():
    """別表記での解除が ok:True を返しつつ何もしていなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.ban("2001:db8::7")
        assert sh.unban("2001:DB8:0::7")["ok"]
        assert sh.inspect("2001:db8::7", path="/")["action"] != "block"
        assert sh.bans() == []


def test_c45_restriction_flow_matches_noncanonical_spelling():
    """一時制限を別表記で掛けると、遮断ページ(peer=正規形)からの報告書も管理者の承認も
    同じ制限に届かず、双方合意で解除できなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.restrict("2001:DB8::20", ttl_sec=3600)["ok"]
        assert sh.inspect("2001:db8::20", path="/")["action"] == "block"
        assert sh.submit_report("2001:db8::20", "help")["ok"]
        r = sh.admin_confirm("2001:DB8:0::20", True)
        assert r.get("released") is True, r
        assert not sh.is_banned_fast("2001:db8::20")


def test_c45_ip_blacklist_matches_noncanonical_ipv6():
    """黒リストの IPv6 単一エントリが大文字/非圧縮表記だと一致せず素通り(fail-open)していた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(ip_mode="blacklist",
                      ip_blacklist=["2001:DB8::1", "2001:0db8:0:0:0:0:0:2", " 203.0.113.9 "])
        assert sh.inspect("2001:db8::1", path="/")["action"] == "block"
        assert sh.inspect("2001:db8::2", path="/")["action"] == "block"
        assert sh.inspect("203.0.113.9", path="/")["action"] == "block"
        assert sh.inspect("2001:db8::3", path="/")["action"] == "allow"


def test_c45_ip_whitelist_noncanonical_entry_not_locked_out():
    """白リストの IPv6 単一エントリが非正規表記だと、許可したはずのホストが締め出されていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(ip_mode="whitelist", ip_whitelist=["2001:DB8::10"])
        assert sh.inspect("2001:db8::10", path="/")["action"] == "allow"
        assert sh.inspect("2001:db8::11", path="/")["action"] == "block"


def test_c45_legacy_noncanonical_persisted_ban_loads():
    """旧版が生の綴りのまま blocklist.json へ書いた BAN も、読み込み時に正規形へ寄せて効かせる。
    IP でない旧キー(CIDR 等)は捨てずに読み込み、一覧から解除できる。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for legacy in ("2001:DB8::5", "203.0.113.0/24"):   # 旧 ban() が作っていた生キー
            st = sh._state(legacy)
            st["ban_until"] = float("inf")
            st["permanent"] = True
        sh._save_bans(force=True)
        sh2 = _shield(d)
        assert sh2.inspect("2001:db8::5", path="/")["action"] == "block"
        listed = {b["ip"] for b in sh2.bans()}
        assert listed == {"2001:db8::5", "203.0.113.0/24"}, listed
        assert sh2.unban("203.0.113.0/24")["ok"]
        assert {b["ip"] for b in sh2.bans()} == {"2001:db8::5"}


# ── #48: 間引かれた保存が二度と書かれない ─────────────────────────────

def test_c48_debounced_ban_is_flushed_without_further_events():
    """表が大きいと 2 秒以内の 2 件目以降の保存は _bans_dirty を立てて戻るだけで、以後 BAN が
    来なければ誰も書かなかった(クラッシュで永続BANが消える)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.cfg["ban_persist_debounce_from"] = 1        # 小さな表でも間引きを効かせる
        sh.cfg["ban_persist_min_interval_sec"] = 0.3
        sh.ban("203.0.113.1", permanent=True)          # 即時保存
        sh.ban("203.0.113.2", permanent=True)          # 間引かれる
        deadline = time.monotonic() + 3.0
        on_disk = set()
        while time.monotonic() < deadline:
            _st, payload = read_signed_json(sh._bans_path, sh._state_key, {})
            on_disk = set(((payload or {}).get("bans") or {}).keys())
            if "203.0.113.2" in on_disk:
                break
            time.sleep(0.05)
        assert on_disk == {"203.0.113.1", "203.0.113.2"}, on_disk
        assert not sh._bans_dirty
        assert {b["ip"] for b in NetShield(state_dir=d).bans()} == on_disk


# ── #82: クォータBANがロック外で走る ───────────────────────────────

def _held_by_caller(lock) -> bool:
    """別スレッドから非ブロッキング取得を試みる。取れない=呼び出し側が保持中。"""
    got = []

    def probe():
        ok = lock.acquire(blocking=False)
        got.append(ok)
        if ok:
            lock.release()

    t = threading.Thread(target=probe)
    t.start()
    t.join(5)
    return got == [False]


def test_c82_quota_ban_decided_under_lock():
    """record_traffic はクォータ超過時の BAN 決定(_save_bans が _ips を走査)をロック外で行い、
    管理スレッドの並行 ban と衝突して RuntimeError で保存ごと失っていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.cfg["quota_enabled"] = True
        sh.cfg["quota_max_gb"] = 1e-9
        seen = []
        orig = sh._enforce_or_audit

        def spy(*a, **k):
            seen.append(_held_by_caller(sh._lock))
            return orig(*a, **k)

        sh._enforce_or_audit = spy
        r = sh.record_traffic("198.51.100.7", out_bytes=10000)
        assert r.get("exceeded"), r
        assert seen == [True], seen
        assert sh.is_banned_fast("198.51.100.7")


# ── #84: 解除後もサブネットが hot のまま ─────────────────────────────

def test_c84_unban_clears_subnet_hot_record():
    """誤BANを全て解除しても /24 の hot 記録が窓(既定1時間)残り、同じ /24 の新規ユーザに
    subnet:hot の加点を付け続けていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.set_config(subnet_defense=True, subnet_threshold=3)
        ips = [f"198.51.100.{i}" for i in (1, 2, 3)]
        for ip in ips:
            sh.penalize(ip)
            sh.penalize(ip)
        assert sh._subnet_hot_count("198.51.100.200") == 3      # 前提: hot になっている
        for ip in ips:
            sh.unban(ip)
        assert sh.bans() == []
        assert sh._subnet_hot_count("198.51.100.200") == 0
        r = sh.inspect("198.51.100.200", path="/home")
        assert "subnet:hot" not in r.get("reason", ""), r
