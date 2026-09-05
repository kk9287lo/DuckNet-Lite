"""
test_pathrate.py — パス別レート制限(evolution #21)。
====================================================================================
グローバル(rate_per_sec)が通常ブラウジング向けに緩くても、/login 等の認証/高コスト経路への
連射(credential stuffing 等)を *専用トークンバケツ* で構造的に絞る。既定[]=無効(挙動不変)、
prefix リテラル照合(ReDoSなし)、バケツは *ルールprefix* でキー(攻撃者がパス末尾を変えても
バケツ数は増えない=メモリ有界)、不正ルールの除去/上限/永続化を回帰から守る。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield, _PATH_LIMIT_MAX


def _shield(tmp):
    sh = NetShield(state_dir=tmp); sh.enable()
    return sh


def test_off_by_default_no_path_throttle():
    # 既定 path_limits=[] → パス別 throttle は一切起きない(グローバルのみ・挙動不変)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        for _ in range(10):
            r = sh.inspect("203.0.113.10", path="/login")
            assert r["action"] == "allow"


def test_targeted_path_throttles_after_burst():
    # /login に burst=3 の厳格ルール。3発は通り4発目で『パス別レート超過』。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_path_limits([{"path": "/login", "rate": 0.001, "burst": 3}])
        ip = "203.0.113.11"
        for _ in range(3):
            assert sh.inspect(ip, path="/login")["action"] == "allow"
        r = sh.inspect(ip, path="/login")
        assert r["action"] == "throttle" and "パス別レート超過: /login" in r["reason"]


def test_other_paths_unaffected():
    # 制限は /login のみ。別経路(/home)は同一IPでも素通し。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_path_limits([{"path": "/login", "rate": 0.001, "burst": 1}])
        ip = "203.0.113.12"
        assert sh.inspect(ip, path="/login")["action"] == "allow"   # バケツ消費
        assert sh.inspect(ip, path="/login")["action"] == "throttle"
        for _ in range(5):
            assert sh.inspect(ip, path="/home")["action"] == "allow"  # 無関係経路は無制限


def test_bucket_keyed_by_prefix_is_bounded():
    # パス末尾を変えても同じ prefix ルールの *単一* バケツを引く(攻撃者がバケツを増やせない)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_path_limits([{"path": "/api/", "rate": 0.001, "burst": 2}])
        ip = "203.0.113.13"
        assert sh.inspect(ip, path="/api/a")["action"] == "allow"     # 2→1
        assert sh.inspect(ip, path="/api/b")["action"] == "allow"     # 1→0(別パスでも同バケツ)
        assert sh.inspect(ip, path="/api/c")["action"] == "throttle"  # 枯渇
        st = sh._ips[ip]
        assert list(st["path_buckets"].keys()) == ["/api/"]           # バケツは1つだけ


def test_per_ip_isolation():
    # バケツは per-IP。あるIPの枯渇が別IPに波及しない。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_path_limits([{"path": "/login", "rate": 0.001, "burst": 1}])
        assert sh.inspect("203.0.113.14", path="/login")["action"] == "allow"
        assert sh.inspect("203.0.113.14", path="/login")["action"] == "throttle"
        assert sh.inspect("203.0.113.15", path="/login")["action"] == "allow"  # 別IPは満タン


def test_set_path_limits_validation_and_cap():
    # 不正項目は除去・型強制・件数上限に丸める。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        res = sh.set_path_limits([
            {"path": "/a", "rate": 1},          # OK(burst 既定=rate)
            "not-a-dict",                       # 除去
            {"path": "", "rate": 1},            # path 空=除去
            {"path": "/b", "rate": -1},         # rate<=0=除去
            {"path": "/c", "rate": "bad"},      # rate 非数=除去
            {"path": "/d", "rate": 2, "burst": "bad"},  # burst 非数→rate(2)
        ])["path_limits"]
        paths = [r["path"] for r in res]
        assert paths == ["/a", "/d"]
        assert res[0]["burst"] == 1.0 and res[1]["burst"] == 2.0
        # 上限丸め
        big = sh.set_path_limits([{"path": f"/p{i}", "rate": 1}
                                  for i in range(_PATH_LIMIT_MAX + 30)])["path_limits"]
        assert len(big) == _PATH_LIMIT_MAX


def test_path_limits_persist_across_reload():
    # 設定は永続化され、(同 state_dir の)新インスタンスで復元される。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _shield(tmp)
        sh.set_path_limits([{"path": "/login", "rate": 0.5, "burst": 5}])
        sh2 = NetShield(state_dir=tmp)
        assert sh2.cfg["path_limits"] == [{"path": "/login", "rate": 0.5, "burst": 5.0}]
