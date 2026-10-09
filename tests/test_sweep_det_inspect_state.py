"""
test_sweep_det_inspect_state.py — inspect() の状態管理まわりの回帰(掃討パス: det_inspect_state・Lite)。
====================================================================================
· #14 メソッド別テレメトリが、未知のメソッド名ごとに辞書キーを増やし続けていた。
· #15 状態表が時限BANで埋まると _evict の低水位が失われ、新規 IP ごとに全件走査+正規利用者の状態が消えた。
· #16 早期 return の遮断枝で返った要求が flood 窓に数えられず、遮断され続けるクライアントが BAN に至らなかった。
· #37 JWT の即時BANが score_ts を更新せず、報告スコアが 0 になっていた。
· #38 cred_rate_limit=N で N-1 件しか通らなかった(N=1 なら全遮断)。
· #39 cred_rate_score が文書にあるのに読まれていなかった(配線。既定 0=従来どおり加点なし)。
· #40 cadence_min_samples が間隔の保持数(24)を超えると周期性検知が黙って無効になっていた。
· #41 全体レート EWMA が同じ時刻を共有した要求を捨て、粗い時計で ~60 req/s に頭打ちしていた。
· #42 cfg 改竄の復元中、無ロックの読み手に enabled=False(既定値)が見えていた。
"""
import math
import tempfile
import time

from dataplane.engine.lifeform import pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.core.signed_state import write_signed_json


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.enable()
    if cfg:
        r = sh.set_config(**cfg)
        assert not r.get("rejected"), r.get("rejected")
    return sh


class _Clock:
    """P._now を差し替える仮想時計(with で戻す)。"""

    def __init__(self, t=1_000_000.0):
        self.t = t

    def __enter__(self):
        self._orig = P._now
        P._now = lambda: self.t
        return self

    def __exit__(self, *exc):
        P._now = self._orig
        return False


# ── #14: メソッド別テレメトリの無制限肥大 ─────────────────────────────────
def test_d14_method_hits_fold_unknown_methods_into_other():
    """英字 10 文字以下なら何でも新しいキーになり、要求ごとに辞書が伸び続けていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for i in range(300):
            tok = "Q" + "".join("ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(i // 26 ** k) % 26] for k in range(3))
            sh.inspect("192.0.2.%d" % (i % 200 + 1), path="/", method=tok)
        sh.inspect("192.0.2.201", path="/", method="GET")
        sh.inspect("192.0.2.202", path="/", method="propfind")
        mh = sh.metrics()["method_hits"]
        assert len(mh) <= 4, len(mh)
        assert mh.get("OTHER", 0) >= 300, mh
        assert mh.get("GET") == 1 and mh.get("PROPFIND") == 1, mh


# ── #15: 時限BANで埋まった表での _evict ─────────────────────────────────
def test_d15_evict_keeps_low_water_mark_when_table_is_mostly_bans():
    """非BANが 1 割未満だと _evict がそれだけ消して終わり、新規 IP ごとに全件走査し、
    直前に来た正規クライアントの状態まで次の新規 IP 1 件で消えていた。"""
    old = P._MAX_IPS
    P._MAX_IPS = 100
    try:
        with tempfile.TemporaryDirectory() as d:
            sh = _shield(d)
            now = P._now()
            perm = "2001:db8::aa"
            assert sh.ban(perm, permanent=True)["ok"]
            for i in range(98):
                st = sh._state("2001:db8:1::%x" % i)
                st["ban_until"] = now + 300 + i
                st["ban_count"] = 1
            sh._state("192.0.2.200")             # 非BAN は 1 件だけ=表は満杯(100)
            assert len(sh._ips) == P._MAX_IPS
            calls = [0]
            orig = sh._evict

            def counted():
                calls[0] += 1
                return orig()
            sh._evict = counted
            sh._state("192.0.2.1")
            sh._state("192.0.2.10")["hits"] = 7     # 正規クライアントの状態(目印)
            for i in range(7):
                sh._state("192.0.2.%d" % (20 + i))
            assert calls[0] == 1, calls             # 1 回の走査を多数の新規 IP で償却
            assert sh._ips.get("192.0.2.10", {}).get("hits") == 7
            assert sh.is_banned_fast(perm)           # 運用者の永続BANは決して捨てない
            assert len(sh._ips) <= P._MAX_IPS
            kept = [s["ban_until"] for k, s in sh._ips.items()
                    if k.startswith("2001:db8:1::")]
            assert kept and min(kept) >= now + 300 + (98 - len(kept)), kept
    finally:
        P._MAX_IPS = old


# ── #16: 早期 return の遮断枝と flood 窓 ──────────────────────────────────
def test_d16_rejected_requests_count_toward_flood_and_ban():
    """遮断枝(メソッド/パスオーバーライド/ポリシー)で返った要求は窓に数えられず、遮断され続ける
    クライアントが flood→自動BAN に至らないまま、毎回フル走査を払わせていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, flood_threshold=10)
        ip = "192.0.2.150"
        for _ in range(5):                                   # 閾値未満は BAN しない
            assert sh.inspect(ip, path="/", method="TRACE")["action"] == "block"
        assert len(sh._ips[ip]["window"]) == 5
        assert not sh.is_banned_fast(ip)
        for _ in range(30):
            sh.inspect(ip, path="/", method="TRACE")
        assert sh.is_banned_fast(ip), sh._ips[ip]
        ip2 = "192.0.2.151"
        for _ in range(30):
            sh.inspect(ip2, path="/", method="GET", override_path="/x")
        assert sh.is_banned_fast(ip2)
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, flood_threshold=10, geo_mode="allow", geo_cidrs=["198.51.100.0/24"])
        ip3 = "192.0.2.152"
        for _ in range(30):
            sh.inspect(ip3, path="/", method="GET")
        assert sh.is_banned_fast(ip3)


# ── #37: 即時BAN の score_ts ───────────────────────────────────────────
def test_d37_jwt_ban_reports_block_score_after_idle():
    """10 分休んだ IP が alg:none を送ると BAN されるのに、判定・BAN 一覧のスコアは 0.0 だった。"""
    from test_jwt import _jwt
    with _Clock() as clk, tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        ip = "192.0.2.50"
        assert sh.inspect(ip, path="/")["action"] == "allow"
        clk.t += 600
        r = sh.inspect(ip, path="/", auth="Bearer " + _jwt("none"))
        assert r["action"] == "block"
        assert r["score"] == float(sh.cfg["block_score"]), r
        assert [b["score"] for b in sh.bans() if b["ip"] == ip] == [r["score"]]


# ── #38: cred_rate_limit の off-by-one ─────────────────────────────────
def test_d38_cred_rate_limit_lets_exactly_limit_through():
    """上限 3 で 3 件目が、上限 1 で最初の 1 件目が遮断されていた。内部 deque の上限ちょうど
    (8192)でも N 件は通し N+1 件目を遮断する。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_enabled=True, cred_rate_limit=3)
        acts = [sh.inspect("192.0.2.%d" % (90 + i), path="/api", cred="ordinary-key")["action"]
                for i in range(4)]
        assert acts == ["allow", "allow", "allow", "block"], acts
        sh.set_config(cred_rate_limit=1)
        assert sh.inspect("192.0.2.99", path="/api", cred="other-key")["action"] == "allow"
        assert sh.inspect("192.0.2.98", path="/api", cred="other-key")["action"] == "block"
        sh.set_config(cred_rate_limit=8192)
        with sh._lock:
            for _ in range(8192):
                sh._credential_rate("tok-busy")
        assert sh.inspect("192.0.2.97", path="/api", cred="tok-busy")["action"] == "block"


# ── #39: cred_rate_score の配線 ────────────────────────────────────────
def test_d39_cred_rate_score_is_applied_when_set():
    """文書の cred_rate_score を設定しても、上限超過後のスコアは 0.0 のままだった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_enabled=True, cred_rate_limit=2)
        for _ in range(3):
            r = sh.inspect("192.0.2.100", path="/api", cred="k1")
        assert r["action"] == "block" and r["score"] == 0.0, r     # 既定=加点なし(従来どおり)
        sh.set_config(cred_rate_score=30)
        r = sh.inspect("192.0.2.101", path="/api", cred="k1")
        assert r["action"] == "block" and r["score"] == 30.0, r


def test_d39_legacy_saved_cred_rate_score_not_activated():
    """旧版は cfg を全キー保存するので、未配線だった頃の既定 40 が保存値に必ず残っている。
    配線後にそれを読んで、既存の導入で加点(=第三者への BAN 転嫁)が突然有効になってはならない。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        legacy = dict(sh.cfg, cred_rate_score=40, cred_rate_enabled=True)
        assert write_signed_json(sh.path, {"cfg": legacy, "saved": time.time()}, sh._state_key)
        sh2 = NetShield(state_dir=d)
        assert sh2.cfg["cred_rate_enabled"] is True
        assert sh2.cfg["cred_rate_score"] == 0, sh2.cfg["cred_rate_score"]
        sh2.set_config(cred_rate_score=40)                 # 新版で明示した値は再起動後も残る
        assert NetShield(state_dir=d).cfg["cred_rate_score"] == 40


# ── #40: cadence_min_samples と間隔の保持数 ──────────────────────────────
def test_d40_cadence_min_samples_above_capacity_rejected():
    """30 は受理されるのに間隔は 24 個しか溜まらず、周期性検知が永久に発火しなかった。"""
    with _Clock() as clk, tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.set_config(cadence_min_samples=30)
        assert "cadence_min_samples" in (r.get("rejected") or []), r.get("changed")
        assert sh.cfg["cadence_min_samples"] == 8
        assert not sh.set_config(cadence_min_samples=24).get("rejected")
        fired = 0
        for _ in range(30):
            fired += "cadence" in sh.inspect("192.0.2.101", path="/")["reason"]
            clk.t += 1.0
        assert fired >= 1
        # 旧版が保存した上限超えの値は、上限へ丸めて読む(黙って既定 8 へ戻さない)
        legacy = dict(sh.cfg, cadence_min_samples=30)
        assert write_signed_json(sh.path, {"cfg": legacy, "saved": clk.t}, sh._state_key)
        assert NetShield(state_dir=d).cfg["cadence_min_samples"] == 24


# ── #41: 全体レート EWMA と粗い時計 ─────────────────────────────────────
def test_d41_ewma_counts_requests_sharing_a_timestamp():
    """15.625ms 刻みの壁時計では同じ刻みの要求が捨てられ、1000 req/s でも EWMA が ~60 だった。
    壁時計の巻き戻しでも凍結/スパイクしない。"""
    tick = 0.015625
    true_t = [1_000_000.0]
    orig = P._now
    P._now = lambda: math.floor(true_t[0] / tick) * tick
    try:
        with tempfile.TemporaryDirectory() as d:
            sh = NetShield(state_dir=d)
            sh._ewma_last = P._now()
            for _ in range(1000 * 20):
                true_t[0] += 0.001
                with sh._lock:
                    sh._tick_ewma()
            assert 700.0 < sh._ewma < 1300.0, sh._ewma
            before, peak = sh._ewma, 0.0
            true_t[0] -= 10.0                           # NTP 補正等の巻き戻し
            for _ in range(100 * 30):
                true_t[0] += 0.01
                with sh._lock:
                    sh._tick_ewma()
                peak = max(peak, sh._ewma)
            assert peak <= before + 1.0, (peak, before)    # 追い付いた瞬間に跳ねない
            assert 50.0 < sh._ewma < 200.0, sh._ewma
    finally:
        P._now = orig


# ── #42: cfg 改竄の復元と無ロックの読み手 ─────────────────────────────────
def test_d42_integrity_restore_never_exposes_disabled_cfg():
    """復元はまず cfg を既定値(enabled=False)へ差し替えてからディスクを読んでいたため、
    その間に来た要求が『shield OFF(パススルー)』で素通りしていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.enable()
        seen = []
        orig = sh._read_state

        def spy(*a, **kw):                     # ディスク読込の最中に無ロックの読み手が見る値
            seen.append(sh.is_enabled())
            return orig(*a, **kw)
        sh._read_state = spy
        sh.cfg["flood_threshold"] = 999999     # API を通さない改変 → MAC 不一致
        r = sh.verify_cfg_integrity()
        assert r.get("tampered") is True, r
        assert seen and all(seen), seen
        assert sh.is_enabled() and sh.cfg["flood_threshold"] == 150
