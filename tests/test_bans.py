"""
test_bans.py — 累犯BANエスカレーション(evolution #19)。
====================================================================================
常習攻撃者(同一IPの再BAN)ほど BAN の TTL を指数的に延長する。初回は据置(既存挙動不変)、
無効化トグル、倍率上限を回帰から守る。BANは決定論的にハニーポット命中(即時BAN)で誘発する。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield, _now


def _ban_once(sh, ip):
    """ハニーポット命中で即時BAN(do_ban 経路)。BAN中の状態を返す。"""
    sh.inspect(ip, path="/.env")           # 既定ハニーポット → 即時BAN
    return sh._ips[ip]


def test_first_ban_is_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.cfg["ban_ttl_sec"] = 100.0
        st = _ban_once(sh, "203.0.113.81")
        assert st["ban_count"] == 1
        assert 95.0 < st["ban_until"] - _now() <= 100.5      # 初回は base のまま


def test_repeat_offender_escalates():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.cfg["ban_ttl_sec"] = 100.0
        ip = "203.0.113.82"
        st = _ban_once(sh, ip); ttl1 = st["ban_until"] - _now()
        st["ban_until"] = 0.0                                 # 期限切れを模す→再犯可能
        _ban_once(sh, ip); ttl2 = st["ban_until"] - _now()
        st["ban_until"] = 0.0
        _ban_once(sh, ip); ttl3 = st["ban_until"] - _now()
        assert st["ban_count"] == 3
        assert ttl2 > ttl1 * 1.8 and ttl3 > ttl2 * 1.8       # 概ね 2 倍ずつ


def test_escalation_can_be_disabled():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.cfg["ban_ttl_sec"] = 100.0
        sh.cfg["ban_escalation"] = False
        ip = "203.0.113.83"
        st = _ban_once(sh, ip); t1 = st["ban_until"] - _now()
        st["ban_until"] = 0.0
        _ban_once(sh, ip); t2 = st["ban_until"] - _now()
        assert st["ban_count"] == 2 and abs(t2 - t1) < 2.0    # 回数は増えるが TTL 一定


def test_escalation_respects_cap():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.cfg["ban_ttl_sec"] = 10.0
        sh.cfg["ban_escalation_cap"] = 4
        ip = "203.0.113.84"; st = None
        for _ in range(8):
            st = _ban_once(sh, ip)
            st["ban_until"] = 0.0
        st = _ban_once(sh, ip)                                # 9回目
        ttl = st["ban_until"] - _now()
        assert st["ban_count"] == 9 and 38.0 < ttl <= 41.0    # base*cap=40 で頭打ち


def test_ban_info_exposes_count():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        ip = "203.0.113.85"
        _ban_once(sh, ip)
        assert sh.ban_info(ip)["ban_count"] == 1
        assert sh.ban_info("198.51.100.1")["ban_count"] == 0  # 未知IP


def _restart(tmp, **cfg):
    """同じ state_dir で新インスタンス=プロセス再起動を模す(BANファイルを読み直す)。"""
    sh = NetShield(state_dir=tmp); sh.cfg["persist_bans"] = True; sh.enable()
    sh.cfg["ban_ttl_sec"] = 100.0; sh.cfg.update(cfg)
    sh._load_bans()
    return sh


def test_count_survives_restart_while_banned():
    # (a) 再起動時にまだBAN中: BANも累犯回数も復元される。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _restart(tmp); ip = "203.0.113.86"
        _ban_once(sh, ip); sh._ips[ip]["ban_until"] = 0.0; _ban_once(sh, ip)   # count=2, active
        assert sh._ips[ip]["ban_count"] == 2
        sh._save_bans()
        sh2 = _restart(tmp); st = sh2._ips.get(ip)
        assert st and st["ban_count"] == 2 and st["ban_until"] > _now()        # BAN中+回数も生存


def test_escalation_memory_survives_restart_after_expiry():
    # (b) BAN期限切れ後に再起動→再来: 保持窓内なら累犯回数を覚えており、エスカレーションが継続。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _restart(tmp); ip = "203.0.113.87"
        _ban_once(sh, ip); sh._ips[ip]["ban_until"] = 0.0; _ban_once(sh, ip)   # count=2
        sh._ips[ip]["ban_until"] = 0.0                                          # 期限切れを模す
        sh._save_bans()
        sh2 = _restart(tmp); st = sh2._ips.get(ip)
        assert st and st["ban_count"] == 2 and st["ban_until"] <= _now()        # 回数のみ生存(BANなし)
        _ban_once(sh2, ip)                                                      # 再来=3犯目
        assert sh2._ips[ip]["ban_count"] == 3
        assert sh2._ips[ip]["ban_until"] - _now() > 100.0 * 1.8                 # エスカレート(base 100 超)


def test_escalation_memory_forgotten_beyond_retention():
    # (b') 保持窓を過ぎた offender は初犯に戻す(=累犯記憶の保持期間)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = _restart(tmp, ban_escalation_retain_sec=1); ip = "203.0.113.88"
        _ban_once(sh, ip); sh._ips[ip]["ban_until"] = 0.0; _ban_once(sh, ip)   # count=2
        sh._ips[ip]["ban_until"] = 0.0
        sh._ips[ip]["ban_started"] = _now() - 10                                # 保持窓(1s)を超過
        sh._save_bans()
        sh2 = _restart(tmp, ban_escalation_retain_sec=1)
        assert sh2._ips.get(ip) is None                                         # 忘却=初犯扱い
