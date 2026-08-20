"""
test_ops.py — エンタープライズ運用機能: SIEM転送(Syslog/Webhook)。
              標準ライブラリのみ・依存ゼロ。
====================================================================================
辛口レビュー(運用の壁)への回答を回帰から守る:
  · 「SIEM連携が無い」→ stdlib(socket/urllib)で Syslog/Webhook 転送を実装(opt-in・既定OFF)。
"""
import contextlib
import socket
import tempfile
import threading
import time

from dataplane.engine.lifeform import forwarders as F
from dataplane.engine.lifeform.alerts import AlertSink
from dataplane.engine.lifeform.pipeline import NetShield


# ── SIEM 転送(Syslog/Webhook) ─────────────────────────────────────────
def test_parse_endpoint_forms():
    assert F._parse_endpoint("udp://10.0.0.5:514") == ("udp", "10.0.0.5", 514)
    assert F._parse_endpoint("tcp://h:601") == ("tcp", "h", 601)
    assert F._parse_endpoint("host:9000") == ("udp", "host", 9000)   # 既定 udp
    assert F._parse_endpoint("host") == ("udp", "host", 514)          # 既定ポート


def test_syslog_rfc5424_line_shape():
    fw = F.SyslogForwarder("udp://127.0.0.1:514", facility=16)
    line = fw._line({"client": "1.2.3.4", "kind": "searchRequest"}, "sensor",
                    F._SEV["alert"]).decode()
    assert line.startswith("<129>1 ")          # PRI=16*8+1, VERSION=1
    assert " chickennet " in line and " sensor " in line
    assert '"client":"1.2.3.4"' in line         # 本体に JSON を載せる


def test_syslog_udp_end_to_end_stdlib_only():
    # 実際に UDP で受けて RFC5424 が届くことを stdlib だけで確認(外部 SIEM 不要)。
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(3.0)
    try:
        port = rx.getsockname()[1]
        fw = F.SyslogForwarder(f"udp://127.0.0.1:{port}")
        fw.send({"client": "9.9.9.9", "verdict": "malicious",
                 "signals": ["全subtree列挙"]}, "ldap_proxy", F._SEV["alert"])
        data, _ = rx.recvfrom(65535)
        msg = data.decode("utf-8", "replace")
        assert msg.startswith("<") and ">1 " in msg and "9.9.9.9" in msg   # <PRI>1 …
    finally:
        rx.close()


class _FakeFwd:
    """送信を記録するだけのテスト用 forwarder(ネットワーク非依存)。"""
    def __init__(self):
        self.events = []
    def send(self, event, source, severity):
        self.events.append((dict(event), source, severity))


def test_fanout_inactive_is_noop():
    fo = F.build_from_env({})                    # env 空 = 無効
    assert fo.active is False
    fo.emit({"client": "x"}, "sensor", "malicious")   # 例外なし・何も起きない


def test_fanout_emits_with_severity_mapping():
    fake = _FakeFwd()
    fo = F.Fanout([fake])
    assert fo.active is True
    fo.emit({"client": "1.1.1.1", "verdict": "malicious"}, "sensor", "malicious")
    fo.emit({"client": "2.2.2.2", "verdict": "suspicious"}, "sensor", "suspicious")
    fo.close()                                   # = pool.shutdown(wait=False)
    # close 後に残務を確実に流すため少し待つ(非同期 submit)。
    deadline = time.time() + 2.0
    while len(fake.events) < 2 and time.time() < deadline:
        time.sleep(0.02)
    sevs = sorted(s for _, _, s in fake.events)
    assert sevs == [F._SEV["alert"], F._SEV["warning"]]   # malicious→alert, suspicious→warning


def test_build_from_env_constructs_forwarders():
    fo = F.build_from_env({"CHICKENNET_SYSLOG": "udp://h:514",
                           "CHICKENNET_WEBHOOK": "https://example/hook"})
    assert fo.active and len(fo._fws) == 2
    types = {type(x).__name__ for x in fo._fws}
    assert types == {"SyslogForwarder", "WebhookForwarder"}


# ── AlertSink への転送配線(初出のみ・ignored/連打は送らない) ──────────────
def test_alertsink_forwards_only_new_real_alerts():
    fake = _FakeFwd()
    with tempfile.TemporaryDirectory() as tmp:
        sink = AlertSink("sensor", state_dir=tmp, dedup_window=60.0,
                         forwarders=F.Fanout([fake]))
        sink.record(("1.1.1.1", "ldap", "search"),
                    {"client": "1.1.1.1"}, verdict="malicious", action="alert")
        sink.record(("1.1.1.1", "ldap", "search"),     # 窓内連打 → dedup(送らない)
                    {"client": "1.1.1.1"}, verdict="malicious", action="alert")
        sink.record(("8.8.8.8", "ldap", "search"),     # allowlist 等の ignored(送らない)
                    {"client": "8.8.8.8"}, verdict="suspicious", action="ignored")
        sink._fanout.close()
        deadline = time.time() + 2.0
        while len(fake.events) < 1 and time.time() < deadline:
            time.sleep(0.02)
    assert len(fake.events) == 1                  # 初出の実アラート1件だけが転送される
    assert fake.events[0][0]["client"] == "1.1.1.1"
    assert fake.events[0][1] == "sensor"


# ── 本体WAF(NetShield)の SIEM 転送配線 ──────────────────────────────────
@contextlib.contextmanager
def _fake_default_fanout():
    """default_fanout() を fake で差し替える(env 不要・ネットワーク非依存)。後で復元。"""
    fake = _FakeFwd()
    prev = F._DEFAULT
    F._DEFAULT = F.Fanout([fake])
    try:
        yield fake
    finally:
        F._DEFAULT.close()
        F._DEFAULT = prev


def _wait(cond, t=2.0):
    deadline = time.time() + t
    while not cond() and time.time() < deadline:
        time.sleep(0.02)


def test_netshield_forwards_dlp_leak_as_malicious():
    with tempfile.TemporaryDirectory() as tmp, _fake_default_fanout() as fake:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.note_leak("5.5.5.5", ["aws_access_key", "private_key"])
        _wait(lambda: len(fake.events) >= 1)
        assert len(fake.events) == 1
        ev, source, sev = fake.events[0]
        assert source == "waf" and sev == F._SEV["alert"]          # 漏洩=最重大
        assert ev["client"] == "5.5.5.5" and ev["kind"] == "dlp_leak"
        assert "aws_access_key" in ev["signals"]


def test_netshield_forwards_manual_ban_as_info():
    with tempfile.TemporaryDirectory() as tmp, _fake_default_fanout() as fake:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.ban("8.8.4.4", permanent=True)
        _wait(lambda: len(fake.events) >= 1)
        assert len(fake.events) == 1
        ev, source, sev = fake.events[0]
        assert ev["kind"] == "manual_ban" and sev == F._SEV["informational"]


def test_netshield_forward_throttles_same_ip_kind():
    with tempfile.TemporaryDirectory() as tmp, _fake_default_fanout() as fake:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.note_leak("6.6.6.6", ["aws_access_key"])   # 初出=転送
        sh.note_leak("6.6.6.6", ["aws_access_key"])   # 窓内同一(ip,kind)=抑止
        sh.note_leak("7.7.7.7", ["aws_access_key"])   # 別IP=転送
        _wait(lambda: len(fake.events) >= 2, t=3.0)
        time.sleep(0.1)                                # 抑止された分が来ないことを確認
        clients = sorted(e[0]["client"] for e in fake.events)
        assert clients == ["6.6.6.6", "7.7.7.7"]       # 6.6.6.6 は1回だけ


def test_netshield_block_path_forwards_via_inspect():
    # ホットパス(inspect)の実遮断/監査が転送されることを end-to-end で確認。
    with tempfile.TemporaryDirectory() as tmp, _fake_default_fanout() as fake:
        sh = NetShield(state_dir=tmp); sh.enable()
        for _ in range(120):                           # 連続攻撃→脅威スコア累積→遮断/BAN
            sh.inspect("203.0.113.77", path="/",
                       query="id=1' union select pwd from users-- ",
                       user_agent="sqlmap/1.7")
        _wait(lambda: len(fake.events) >= 1, t=3.0)
        assert len(fake.events) >= 1                    # (ip,kind)スロットルで概ね1件
        ev, source, sev = fake.events[0]
        assert source == "waf" and ev["client"] == "203.0.113.77"
        assert sev in (F._SEV["alert"], F._SEV["warning"])   # enforce=alert / audit=warning


def test_netshield_no_forward_when_fanout_inactive():
    # 既定(env 未設定)では default_fanout が inactive=転送ゼロ・例外なし(ゼロコスト)。
    F._DEFAULT = None                                  # env 未設定で再構築 → inactive
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp); sh.enable()
        sh.note_leak("1.2.3.4", ["aws_access_key"])    # 例外なく no-op
        sh.ban("1.2.3.4")
        assert F.default_fanout().active is False


# ── SIEM フラッド/盲目化(#8)対策: 容量固定キュー + 非ブロッキング + 抑制サマリ ──
def test_fanout_bounded_queue_and_nonblocking_emit():
    rel = threading.Event()

    class _Block:
        def __init__(self): self.n = 0
        def send(self, ev, s, sev):
            self.n += 1
            rel.wait(2.0)                       # 最初の送信で worker を塞ぎ、キューに溜めさせる

    fo = F.Fanout([_Block()], capacity=50, max_per_sec=100000, summary_sec=100)
    try:
        t0 = time.time()
        for i in range(5000):                   # 異なるIPからのアラート洪水を模す
            fo.emit({"client": f"10.0.0.{i % 256}", "verdict": "malicious"}, "waf", "malicious")
        assert (time.time() - t0) < 1.0         # emit は 5000 件でも塞がらない(完全非同期)
        st = fo.stats()
        assert st["queued"] <= 50               # 容量固定=無制限に溜めない(メモリ枯渇回避)
        assert st["dropped"] > 0                # 超過分は drop-oldest
    finally:
        rel.set(); fo.close()


def test_fanout_reports_suppression_so_siem_not_silently_blinded():
    class _Fail:
        def __init__(self): self.events = []
        def send(self, ev, s, sev):
            self.events.append(ev)
            if ev.get("kind") != "forwarder_backpressure":
                raise OSError("429 Too Many Requests")   # 本物のアラートは 429 で失敗

    f = _Fail()
    fo = F.Fanout([f], capacity=1000, max_per_sec=100000, summary_sec=0.2)
    try:
        for i in range(30):
            fo.emit({"client": f"1.2.3.{i}", "verdict": "malicious", "kind": "sqli"},
                    "waf", "malicious")
        deadline = time.time() + 4.0
        while time.time() < deadline:
            if any(e.get("kind") == "forwarder_backpressure" for e in f.events):
                break
            time.sleep(0.05)
        # 攻撃者が窓口を 429 でパンクさせても "N件抑制" のメタアラートが必ず届く=静かな盲目化を防ぐ
        assert any(e.get("kind") == "forwarder_backpressure" for e in f.events)
    finally:
        fo.close()
