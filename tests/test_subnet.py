"""
test_subnet.py — サブネット集約防御(evolution #25)。
====================================================================================
同一サブネット(/24・v6 /64)で *別IP* が多数BANされたら分散攻撃の温床とみなし、新規IPへ
一度だけソフト加点(ハードBANはしない=NAT/CGNAT 巻き添え回避)。既定OFF・distinct IP 要件・
別サブネット非波及・一度限り・時間窓・メモリ有界を回帰から守る。BANは block_score 一発到達の
ペナルティで決定論誘発。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import (NetShield, _now, _subnet_key,
                                                _MAX_SUBNETS)


def _shield(tmp, **cfg):
    sh = NetShield(state_dir=tmp); sh.enable()
    sh.cfg["subnet_defense"] = True
    sh.cfg["subnet_threshold"] = 3
    sh.cfg.update(cfg)
    return sh


def _ban(sh, ip):
    sh._ips.pop(ip, None)                         # 既BANなら状態を消して再BAN可能に
    sh.penalize(ip, weight=sh.cfg["block_score"], reason="test-ban",
                kind="test_ban")                  # block_score一発→即時BAN→サブネット記録


def test_subnet_key():
    assert _subnet_key("198.51.100.37") == "198.51.100.0/24"
    assert _subnet_key("2001:db8:abcd:1234::5") == "2001:db8:abcd:1234::/64"
    assert _subnet_key("not-an-ip") is None and _subnet_key("") is None


def test_off_by_default_no_bump():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        for i in range(1, 6):                     # subnet_defense は既定 False
            _ban(sh, f"198.51.100.{i}")
        r = sh.inspect("198.51.100.200", path="/home")
        assert "subnet:hot" not in r["reason"] and r["score"] == 0
        assert sh._subnets == {}                  # 記録もしない


def test_hot_subnet_bumps_new_ip():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)                         # threshold=3
        for i in range(1, 4):                     # 3つの別IPをBAN(同一 /24)
            _ban(sh, f"198.51.100.{i}")
        r = sh.inspect("198.51.100.200", path="/home")    # 同 /24 の新規クリーンIP
        assert "subnet:hot:3" in r["reason"]
        assert sh._ips["198.51.100.200"]["score"] >= 30


def test_distinct_ips_required():
    # 同じIPを何度BANしてもサブネットは hot にならない(distinct で数える)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for _ in range(10):
            _ban(sh, "198.51.100.9")
        r = sh.inspect("198.51.100.201", path="/home")
        assert "subnet:hot" not in r["reason"]


def test_other_subnet_unaffected():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for i in range(1, 4):
            _ban(sh, f"198.51.100.{i}")
        r = sh.inspect("203.0.113.50", path="/home")      # 別 /24
        assert "subnet:hot" not in r["reason"] and r["score"] == 0


def test_bump_applied_once_per_ip():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for i in range(1, 4):
            _ban(sh, f"198.51.100.{i}")
        ip = "198.51.100.202"
        r1 = sh.inspect(ip, path="/home"); s1 = sh._ips[ip]["score"]
        r2 = sh.inspect(ip, path="/home")                 # 2回目は加点しない(flag)
        assert "subnet:hot" in r1["reason"] and "subnet:hot" not in r2["reason"]
        assert sh._ips[ip]["score"] <= s1                 # 減衰のみ(増えない)


def test_window_excludes_stale_bans():
    # 窓より古いBANは hot 集計から外れる(_subnets の時刻を直接操作)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp, subnet_window_sec=10)
        for i in range(1, 4):
            _ban(sh, f"198.51.100.{i}")
        key = "198.51.100.0/24"
        for k in list(sh._subnets[key]):                  # 全BANを窓外(11秒前)へ
            sh._subnets[key][k] = _now() - 11
        r = sh.inspect("198.51.100.203", path="/home")
        assert "subnet:hot" not in r["reason"]


def test_subnet_table_is_memory_bounded():
    # 大量の別 /24 を記録しても追跡サブネット数は上限で頭打ち(攻撃者がメモリを膨らませられない)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp, subnet_window_sec=0)
        for i in range(_MAX_SUBNETS + 200):
            a, b = divmod(i, 256)
            sh._record_subnet_ban(f"10.{a % 256}.{b}.5")
        assert len(sh._subnets) <= _MAX_SUBNETS


def test_subnet_status_reports_hot():
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for i in range(1, 4):
            _ban(sh, f"198.51.100.{i}")
        s = sh.subnet_status()
        assert s["enabled"] is True and s["hot_subnets"] == 1 and s["threshold"] == 3
