"""
dns.py — DNSフィルタ設置(stdlib UDP・ドメイン遮断/上流転送・OS非侵襲)
====================================================================================
悪性/不要ドメインの名前解決を遮断する DNS フィルタ(sinkhole/NXDOMAIN)。許可ドメインは
上流リゾルバへ転送して結果を中継する。標準ライブラリのみ・依存ゼロ。

OS非侵襲の線引き: 本機はDNSサーバを *立てる* だけ。OSのリゾルバ設定(/etc/resolv.conf や
Windowsのネットワーク設定)は **触らない**。利用者が自分の端末/ルータの参照先を本機へ向ける
ことで効く(透明・可逆)。

  · ブロック判定: 完全一致 / ワイルドカード(*.evil.com) / サフィックス(evil.com=サブdrも) / 正規表現。
  · 応答: nxdomain(既定) または sinkhole(A=設定IP・既定0.0.0.0)。
  · 監査モード: 遮断せず通すがアラート(ログ)= 監視。
  · 永続化: <state-dir>/dns_rules.json。記録: 直近の判定をリングに保持。

L7 ヒューリスティック検知(明示ブロックリストに載らない『未知』を振る舞いで捕捉):
  正規の名前解決ポート(53)は内部で常時開いているため、攻撃者は同じ53番を
  C2・内部偵察・データ持出しの通路に転用する。本機は宛先IP/ポートではなく
  *問い合わせの中身* (QNAME/QTYPE/発信元の頻度)を見て、業務通信と異常を切り分ける。
  · トンネリング/持出し: 異常に長いQNAME・高エントロピーのラベル・TXT/NULL多用・
    同一上位ドメインへの大量サブドメイン照会(ビーコン)。
  · 内部偵察(AD): _ldap._tcp / _kerberos._tcp / _gc._tcp 等のSRV照会。
    ドメイン参加端末では正規にも出るため、既定は『遮断せず可視化(アラート)』。
  既定は監査(alert)寄り=止める前にまず見える化する。誤遮断を避けつつ兆候を残す。
"""
from __future__ import annotations

import os
import re
import socket
import threading
import time
from collections import deque, Counter
from math import log2 as _log2

from ..core.atomic_io import default_state_dir, atomic_write_json, safe_read_json, append_jsonl
from .forwarders import default_fanout
from .netutil import valid_cidr, ip_in_any
from ...profile import cover_thread_name as _cover_tn   # #81: スレッド名のステルス化


def parse_qname(data: bytes) -> str:
    """DNSメッセージ先頭の質問からQNAMEを取り出す(小文字)。"""
    pos, labels = 12, []
    try:
        while pos < len(data):
            ln = data[pos]
            if ln == 0:
                break
            if ln & 0xC0:                 # 圧縮ポインタ(質問部には通常無い)
                break
            labels.append(data[pos + 1:pos + 1 + ln].decode("latin1", "replace"))
            pos += 1 + ln
    except Exception:
        return ""
    return ".".join(labels).lower()


# QTYPE(問い合わせ種別)。トンネリングは TXT/NULL を、偵察は SRV/ANY を好む。
QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
         15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def parse_question(data: bytes) -> tuple:
    """先頭の質問から (QNAME小文字, QTYPE整数) を取り出す。QNAME終端0の直後の
    2バイトが QTYPE。壊れていれば QTYPE=0。圧縮ポインタは質問部には通常無い。"""
    qname = parse_qname(data)
    pos = 12
    try:
        while pos < len(data):
            ln = data[pos]
            if ln == 0:
                qpos = pos + 1
                qtype = (data[qpos] << 8) | data[qpos + 1]
                return qname, qtype
            if ln & 0xC0:
                break
            pos += 1 + ln
    except Exception:
        pass
    return qname, 0


def _shannon(s: str) -> float:
    """文字列のシャノンエントロピー(bit/文字)。base32/hex でエンコードされた
    トンネリング・ラベルは値が高くなる(英単語のドメインは低い)。
    ヒストグラムは C 実装の Counter、数式は log2(n)-Σc·log2(c)/n(毎クエリのホットパス)。"""
    if not s:
        return 0.0
    n = len(s)
    return _log2(n) - sum(c * _log2(c) for c in Counter(s).values()) / n


def _question_section(data: bytes) -> bytes:
    pos = 12
    while pos < len(data) and data[pos] != 0:
        if data[pos] & 0xC0:
            pos += 2
            return data[12:pos + 4]
        pos += 1 + data[pos]
    return data[12:pos + 5]               # qname終端0 + qtype(2)+qclass(2)


def build_nxdomain(query: bytes) -> bytes:
    """NXDOMAIN応答を組む(該当ドメインは存在しない=解決拒否)。"""
    tid = query[:2]
    flags = b"\x81\x83"                   # QR=1, RD=1, RA=1, RCODE=3(NXDOMAIN)
    header = tid + flags + b"\x00\x01" + b"\x00\x00" * 3
    return header + _question_section(query)


def build_sinkhole_a(query: bytes, ip: str = "0.0.0.0") -> bytes:
    """A応答(sinkhole IP)を組む。Aクエリ向け(攻撃ドメインを無害IPへ吸い込む)。"""
    tid = query[:2]
    header = tid + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" * 2
    q = _question_section(query)
    try:
        ipb = socket.inet_aton(ip)
    except OSError:
        ipb = b"\x00\x00\x00\x00"
    answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x3c"
              + b"\x00\x04" + ipb)        # ptr→質問, A, IN, TTL=60, RDLEN=4, IP
    return header + q + answer


# AD(Active Directory)が内部で名前解決に使う SRV サービス名の接頭辞。
# ドメイン参加端末では正規に出るため『遮断ではなく可視化(アラート)』の対象にする。
_AD_SRV_PREFIXES = ("_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
                    "_gc._tcp", "_kpasswd._tcp", "_kpasswd._udp",
                    "_msdcs", "_vlmcs._tcp", "_ldap._tcp.dc._msdcs")


class DnsAnomalyDetector:
    """QNAME/QTYPE/発信元頻度から DNS の悪用兆候を点数化する純粋ロジック。

    宛先で弾く方式ではなく『問い合わせの中身と振る舞い』で判断するので、
    ブロックリスト未登録の未知トンネリング/C2/偵察も捕捉できる。ソケットを
    持たない=単体テスト可能。判定は decide() から呼ばれ、結果は
    verdict ∈ {clean, suspicious, malicious} と signals(根拠) で返す。

    既定しきい値は誤検知を避ける保守的な値。category が recon のみのときは
    malicious に昇格させない(AD 参加端末の正規 SRV を止めないため)。
    """

    def __init__(self, *, max_qname: int = 100, max_label: int = 40,
                 entropy_label_min: int = 20, entropy_min: float = 3.6,
                 beacon_window: float = 10.0, beacon_unique: int = 20,
                 max_clients: int = 4096, recon_mode: str = "alert"):
        self.max_qname = max_qname            # QNAME 全長の上限(超過で持出し疑い)
        self.max_label = max_label            # 単一ラベル長の上限
        self.entropy_label_min = entropy_label_min   # エントロピー評価する最小ラベル長
        self.entropy_min = entropy_min        # 高エントロピー判定の閾(bit/文字)
        self.beacon_window = beacon_window    # ビーコン観測窓(秒)
        self.beacon_unique = beacon_unique    # 窓内の同一上位ドメイン別サブdr数の閾
        self.max_clients = max(1, max_clients)   # 追跡する発信元数の上限(LRUで頭打ち)
        # AD偵察(SRV)の扱い: "alert"=可視化(既定) / "ignore"=フラグせず(AD前段の騒音回避)。
        self.recon_mode = recon_mode if recon_mode in ("alert", "ignore") else "alert"
        # 発信元ごとの最近の (時刻, 上位ドメイン, サブラベル) を保持(ビーコン検出用)。
        # UDP の送信元IPは偽装容易=無制限に増やすとメモリ枯渇。LRU で件数を縛る。
        self._recent: dict = {}
        self._lock = threading.RLock()

    @staticmethod
    def _registrable(qname: str) -> str:
        """ざっくり上位2ラベルを『上位ドメイン』とみなす(完全な公開接尾辞解決は
        しない=依存ゼロ維持)。ビーコンのまとめ単位に使うだけなので近似で十分。"""
        parts = qname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else qname

    def _beacon_count(self, client: str, qname: str, now: float) -> int:
        """同一発信元×同一上位ドメインに対する、観測窓内の『別サブドメイン数』。
        DNS トンネリングは毎回ユニークなサブドメインを引くので数が跳ねる。"""
        if not client:
            return 0
        base = self._registrable(qname)
        sub = qname[:-len(base)].rstrip(".") if qname.endswith(base) else qname
        with self._lock:
            # pop+再挿入で LRU 化(最後に触れた発信元が末尾=最新)。
            dq = self._recent.pop(client, None) or deque(maxlen=512)
            self._recent[client] = dq
            cutoff = now - self.beacon_window
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            dq.append((now, base, sub))
            # 追跡数を上限で頭打ち(最も古く触れた発信元から退避=偽装フラッド耐性)。
            while len(self._recent) > self.max_clients:
                self._recent.pop(next(iter(self._recent)), None)
            return len({s for (_, b, s) in dq if b == base and s})

    def inspect(self, qname: str, qtype: int = 1, client: str = "",
                now: float = None) -> dict:
        now = time.time() if now is None else now
        signals = []
        score = 0
        recon = False
        labels = [l for l in qname.split(".") if l]
        longest = max((len(l) for l in labels), default=0)
        leftmost = labels[0] if labels else ""
        ent = _shannon(leftmost)

        # ── 持出し/トンネリング: 長さ ──
        if len(qname) >= self.max_qname:
            score += 2
            signals.append(f"qname長={len(qname)}≥{self.max_qname}")
        if longest >= self.max_label:
            score += 2
            signals.append(f"最長ラベル={longest}≥{self.max_label}")

        # ── 持出し/トンネリング: エントロピー(エンコードされた払い出し) ──
        if len(leftmost) >= self.entropy_label_min and ent >= self.entropy_min:
            score += 2
            signals.append(f"高エントロピーlabel({ent:.2f}bit)")
            if ent >= self.entropy_min + 0.6:
                score += 1

        # ── 辞書語エンコードの持出し回避: 機密を Base32/hex でなく英単語列
        #    (apple-banana-river…)に変換するとエントロピーが ~2.7bit へ急降下し上の
        #    エントロピー判定をすり抜ける。しかし『1ラベルに多数のハイフン区切りトークン』は
        #    正規ドメインには稀。エントロピーに依存しない構造(token数×長さ)で捕捉する。
        #    ※実データ持出しは多量のクエリを要するためビーコン検知(下記)が本命の網。
        ntok = leftmost.count("-") + 1
        if ntok >= 6 and len(leftmost) >= 24:
            score += 2
            signals.append(f"辞書語チャンク疑い(token={ntok}・低エントロピー回避)")

        # ── QTYPE: TXT/NULL は古典的トンネリング経路、ANY は偵察寄り ──
        if qtype in (16, 10) and ent >= 3.0 and len(leftmost) >= 12:
            score += 2
            signals.append(f"{QTYPE.get(qtype, qtype)}+エンコード疑いlabel")
        if qtype == 255:
            score += 1
            signals.append("ANYクエリ")

        # ── 内部偵察(AD): _ldap._tcp 等の AD サービス名照会。正規にも出るため
        #    点数は加えず recon フラグのみ=『遮断せず可視化』に留める。
        #    recon_mode="ignore" なら AD 前段の騒音回避のためフラグしない。 ──
        if self.recon_mode == "alert":
            low = qname.lower()
            if any(p in low for p in _AD_SRV_PREFIXES):
                recon = True
                signals.append("AD向けサービス照会(偵察兆候)")

        # ── ビーコン: 同一上位ドメインへ大量のユニークサブドメイン。
        #    閾超で疑い、持続的な大量(2倍)なら更に加点=トンネリングの強い兆候。 ──
        uniq = self._beacon_count(client, qname, now)
        if uniq >= self.beacon_unique:
            score += 3
            signals.append(f"ビーコン疑い({uniq}/{self.beacon_window:.0f}s)")
            if uniq >= self.beacon_unique * 2:
                score += 2

        if score >= 5:
            verdict = "malicious"
        elif score >= 3 or recon:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"verdict": verdict, "score": score, "recon": recon,
                "signals": signals, "entropy": round(ent, 2)}


class DnsFilter:
    def __init__(self, host: str = "127.0.0.1", port: int = 5335,
                 upstream: str = "1.1.1.1", upstream_port: int = 53,
                 mode: str = "nxdomain", sinkhole_ip: str = "0.0.0.0",
                 state_dir: str = "", max_inflight: int = 256,
                 dedup_window: float = 60.0, recon_mode: str = "alert"):
        base = state_dir or default_state_dir()
        os.makedirs(base, exist_ok=True)
        self.path = os.path.join(base, "dns_rules.json")
        self.host, self.port = host, port
        self.upstream, self.upstream_port = upstream, upstream_port
        self.sinkhole_ip = sinkhole_ip
        self._sock = None
        self._thread = None
        self._running = False
        # 1問い合わせ=1短命ワーカーで並行処理。上流解決(最大数秒)が他のクエリを
        # 止めないようにする。同時数は上限で絞り、超過分は取りこぼす(DNSは再送される)。
        self._sem = threading.BoundedSemaphore(max(1, max_inflight))
        self._log = deque(maxlen=500)
        self._lock = threading.RLock()
        # 応答レート制限(RRL・#15): UDP は送信元を詐称できるため、応答をそのまま返すと
        #   攻撃者が『送信元=被害者IP』で偽装→当機が被害者へ大量応答を撃ち返す反射増幅の踏み台に
        #   なり得る。送信元IP毎に窓内の応答数を上限化し、超過分は *無応答で破棄*(spoof フラッドを
        #   増幅させない)。正規クライアントの再送は通る程度の緩い上限。
        self._rrl: dict = {}                            # ip -> [window_start, count]
        self._rrl_window = 1.0
        self._rrl_max = 30                              # 送信元毎の毎秒応答上限(d 読込後に上書き)
        d = safe_read_json(self.path, {}) or {}
        self.mode = d.get("mode", mode)                 # nxdomain / sinkhole / audit
        self.audit = bool(d.get("audit", False))
        self.blocklist = list(d.get("blocklist") or [])
        self.regexes = [re.compile(p) for p in (d.get("regexes") or [])
                        if _safe_re(p)]
        self._regex_src = [p for p in (d.get("regexes") or []) if _safe_re(p)]
        self.metrics = {"queries": 0, "blocked": 0, "forwarded": 0,
                        "suspicious": 0, "heuristic_blocked": 0, "recon": 0}
        # L7 ヒューリスティック検知。既定 ON だが『監査(止めず可視化)』寄り。
        self.heuristics = bool(d.get("heuristics", True))
        self.heuristics_audit = bool(d.get("heuristics_audit", True))
        # 利用者が選べる検知の挙動(永続化):
        #   recon_mode … AD偵察(SRV)を可視化(alert)するか無視(ignore)するか。
        #   dedup_window … 同一(発信元×ドメイン×action)の通知連打を窓内で集約(秒, 0=無効)。
        rm = d.get("recon_mode", recon_mode)
        self.recon_mode = rm if rm in ("alert", "ignore") else "alert"
        self.dedup_window = float(d.get("dedup_window", dedup_window))
        self._rrl_max = int(d.get("rrl_max_per_sec", 30))   # #15: 応答レート上限(永続化・0=無効)
        # 送信元アローリスト: 信頼できるスキャナ/監視からのクエリは L7 検知を免除
        # (誤検知抑制)。ただし明示ブロックリストは免除しない=既知悪性は常に遮断。
        self.allowlist = [n for n in (d.get("allowlist") or []) if valid_cidr(n)]
        self.detector = DnsAnomalyDetector(recon_mode=self.recon_mode)
        # 注目イベント(block/alert)だけを永続化(管理画面の横断表示・cross-process)。
        self.threat_log_path = os.path.join(base, "dns_log.jsonl")
        self._recent_threats: dict = {}        # (client,domain,action)->last_ts(dedup用)

    def _save(self):
        with self._lock:
            atomic_write_json(self.path, {"mode": self.mode, "audit": self.audit,
                                          "blocklist": self.blocklist,
                                          "regexes": self._regex_src,
                                          "heuristics": self.heuristics,
                                          "heuristics_audit": self.heuristics_audit,
                                          "recon_mode": self.recon_mode,
                                          "dedup_window": self.dedup_window,
                                          "allowlist": self.allowlist})

    def set_detection(self, recon_mode: str = None, dedup_window: float = None) -> dict:
        """利用者が検知の挙動を選ぶ: AD偵察の可視化/無視・通知連打の集約窓。"""
        with self._lock:
            if recon_mode in ("alert", "ignore"):
                self.recon_mode = recon_mode
                self.detector.recon_mode = recon_mode
            if dedup_window is not None:
                self.dedup_window = max(0.0, float(dedup_window))
            self._save()
        return {"ok": True, "recon_mode": self.recon_mode,
                "dedup_window": self.dedup_window}

    def _threat_record(self, client: str, domain: str, action: str,
                       now: float) -> bool:
        """注目イベントを永続化すべきか。dedup 窓内の連打は False(集約)。
        同一イベントの連打を1件に畳み、ログ/管理画面の氾濫を防ぐ。"""
        if self.dedup_window <= 0:
            return True
        key = (client, domain, action)
        last = self._recent_threats.get(key)
        self._recent_threats[key] = now
        if len(self._recent_threats) > 4096:           # 追跡数を上限で間引く
            cutoff = now - self.dedup_window
            for k in [k for k, v in self._recent_threats.items() if v < cutoff]:
                self._recent_threats.pop(k, None)
        return last is None or now - last > self.dedup_window

    def add_allow(self, cidr: str) -> dict:
        """送信元 IP/CIDR を L7 検知の免除リストへ追加(明示ブロックは免除しない)。"""
        cidr = (cidr or "").strip()
        if not valid_cidr(cidr):
            return {"ok": False, "error": f"IP/CIDR 不正: {cidr}"}
        with self._lock:
            if cidr not in self.allowlist:
                self.allowlist.append(cidr)
            self._save()
        return {"ok": True, "allowlist": list(self.allowlist)}

    def remove_allow(self, cidr: str) -> dict:
        with self._lock:
            before = len(self.allowlist)
            self.allowlist = [c for c in self.allowlist if c != cidr]
            self._save()
        return {"ok": True, "removed": before - len(self.allowlist)}

    def _allowed(self, ip: str) -> bool:
        return ip_in_any(ip, self.allowlist)

    def set_heuristics(self, enabled: bool = None, audit: bool = None) -> dict:
        """L7 検知の ON/OFF と、監査(可視化のみ)/強制(遮断)の切替。"""
        with self._lock:
            if enabled is not None:
                self.heuristics = bool(enabled)
            if audit is not None:
                self.heuristics_audit = bool(audit)
            self._save()
        return {"ok": True, "heuristics": self.heuristics,
                "heuristics_audit": self.heuristics_audit}

    # ── ブロック管理 ──
    def add_block(self, domain: str) -> dict:
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain:
            return {"ok": False, "error": "ドメイン未指定"}
        with self._lock:
            if domain not in self.blocklist:
                self.blocklist.append(domain)
            self._save()
        return {"ok": True, "blocked": domain, "total": len(self.blocklist)}

    def remove_block(self, domain: str) -> dict:
        domain = (domain or "").strip().lower().rstrip(".")
        with self._lock:
            before = len(self.blocklist)
            self.blocklist = [d for d in self.blocklist if d != domain]
            self._save()
        return {"ok": True, "removed": before - len(self.blocklist)}

    def add_regex(self, pattern: str) -> dict:
        if not _safe_re(pattern):
            return {"ok": False, "error": "不正/危険な正規表現"}
        with self._lock:
            if pattern not in self._regex_src:
                self._regex_src.append(pattern)
                self.regexes.append(re.compile(pattern))
            self._save()
        return {"ok": True, "regex": pattern}

    def set_mode(self, mode: str = "", audit: bool = None) -> dict:
        with self._lock:
            if mode in ("nxdomain", "sinkhole"):
                self.mode = mode
            if audit is not None:
                self.audit = bool(audit)
            self._save()
        return {"ok": True, "mode": self.mode, "audit": self.audit}

    def is_blocked(self, domain: str) -> bool:
        d = (domain or "").lower().rstrip(".")
        if not d:
            return False
        for b in self.blocklist:
            if b.startswith("*."):
                if d == b[2:] or d.endswith("." + b[2:]):
                    return True
            elif d == b or d.endswith("." + b):       # サフィックス一致(サブドメインも)
                return True
        return any(rgx.search(d) for rgx in self.regexes)

    # ── 判定(テスト可能なコア) ──
    def decide(self, query: bytes, client: str = "", now: float = None) -> dict:
        now = time.time() if now is None else now
        qname, qtype = parse_question(query)
        blocked = self.is_blocked(qname)
        threat = None
        # 明示ブロックリスト優先。未登録なら L7 ヒューリスティックで振る舞い判定。
        if blocked:
            action = "audit_pass" if self.audit else "block"
        else:
            action = "allow"
            # 免除元(信頼スキャナ/監視)は L7 検知をスキップ=誤検知を出さない。
            if self.heuristics and qname and not self._allowed(client):
                threat = self.detector.inspect(qname, qtype, client)
                if threat["verdict"] == "malicious" and not self.heuristics_audit:
                    action = "block"            # 強制モード=遮断(NXDOMAIN/sinkhole)
                elif threat["verdict"] in ("malicious", "suspicious"):
                    action = "alert"            # 監査=止めず可視化(ログに兆候を残す)
        entry = {"ts": now, "client": client, "domain": qname,
                 "qtype": QTYPE.get(qtype, qtype), "action": action}
        if threat and threat["verdict"] != "clean":
            entry["threat"] = threat["verdict"]
            entry["signals"] = threat["signals"]
        with self._lock:
            self._log.append(entry)
            self.metrics["queries"] += 1
            if action == "block":
                self.metrics["blocked"] += 1
                if threat:
                    self.metrics["heuristic_blocked"] += 1
            elif action == "alert":
                self.metrics["suspicious"] += 1
                if threat and threat.get("recon"):
                    self.metrics["recon"] += 1
            # 注目イベントのみ永続化(全クエリは書かない=肥大回避)。サイズ超でローテ。
            # dedup 窓内の同一連打は集約(永続化しない)=ログ/管理画面の氾濫を防ぐ。
            if action in ("block", "alert") and \
                    self._threat_record(client, qname, action, now):
                append_jsonl(self.threat_log_path, entry)
                # SIEM/Webhook へも初出を転送(opt-in・env 未設定なら no-op)。submit=非ブロッキング。
                default_fanout().emit(entry, "dns", entry.get("threat", "suspicious"))
        return {"qname": qname, "qtype": qtype, "blocked": blocked,
                "action": action, "threat": threat}

    def respond_block(self, query: bytes) -> bytes:
        if self.mode == "sinkhole":
            return build_sinkhole_a(query, self.sinkhole_ip)
        return build_nxdomain(query)

    def _forward(self, query: bytes, timeout: float = 3.0) -> bytes:
        """許可ドメインを上流リゾルバへ転送して応答を中継する。
        応答インジェクション(オフパス・キャッシュ汚染)対策:
          · connect で上流 IP:ポートに固定=カーネルが他送信元の偽造応答を破棄。
          · 応答の transaction ID が問い合わせと一致するもののみ採用(取り違え/偽造を排除)。
        一致しない/不達は例外→呼び出し側で安全側(NXDOMAIN)に倒す。"""
        qid = query[:2]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            try:
                s.connect((self.upstream, self.upstream_port))
                s.send(query)
            except OSError:                       # connect 不可な環境は従来送信に退避
                s.sendto(query, (self.upstream, self.upstream_port))
            deadline = time.monotonic() + timeout
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    raise TimeoutError("DNS応答待ちタイムアウト")
                s.settimeout(remain)
                data = s.recv(4096)
                if len(data) >= 2 and data[:2] == qid:   # txid 一致のみ採用
                    with self._lock:
                        self.metrics["forwarded"] += 1
                    return data
                # txid 不一致(偽造/迷子)=破棄して残り時間で再受信
        finally:
            s.close()

    def handle(self, query: bytes, client: str = "") -> bytes:
        d = self.decide(query, client)
        if d["action"] == "block":            # 明示ブロック or 強制時の悪性判定
            return self.respond_block(query)
        try:                                  # allow / alert(可視化のみ)は上流へ
            return self._forward(query)
        except Exception:
            return build_nxdomain(query)      # 上流不達は安全側でNXDOMAIN

    def _rate_limited(self, src: str) -> bool:
        """送信元 src への応答が窓内上限を超えたか(#15・反射増幅の踏み台化を防ぐ)。
        上限<=0 で無効。超過時 True=この問い合わせには *応答しない*(spoof フラッドを増幅させない)。"""
        if self._rrl_max <= 0 or not src:
            return False
        now = time.monotonic()
        with self._lock:
            ent = self._rrl.get(src)
            if ent is None or now - ent[0] >= self._rrl_window:
                self._rrl[src] = [now, 1]
                if len(self._rrl) > 4096:               # 有界化(最古窓を間引く)
                    for k in [k for k, v in self._rrl.items()
                              if now - v[0] >= self._rrl_window][:512]:
                        self._rrl.pop(k, None)
                return False
            ent[1] += 1
            return ent[1] > self._rrl_max

    def _serve_one(self, s, data: bytes, addr) -> None:
        """1問い合わせをワーカースレッドで処理して応答(上流待ちが全体を止めない)。"""
        try:
            src = addr[0] if addr else ""
            if self._rate_limited(src):       # RRL: 反射増幅(spoof 送信元への撃ち返し)を断つ
                self.metrics["rrl_dropped"] = self.metrics.get("rrl_dropped", 0) + 1
                return                        # 無応答で破棄=被害者に増幅パケットを送らない
            resp = self.handle(data, client=src)
            s.sendto(resp, addr)
        except Exception:
            pass
        finally:
            self._sem.release()

    # ── サーバ ──
    def start(self) -> dict:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
        except Exception as e:
            return {"ok": False, "error": f"bind失敗(:{self.port} は要特権の場合あり): {e}"}
        self._sock = s
        self.port = s.getsockname()[1]
        self._running = True

        def _loop():
            while self._running:
                try:
                    data, addr = s.recvfrom(4096)
                except Exception:
                    break
                if not self._sem.acquire(blocking=False):
                    continue                  # 過負荷=取りこぼし(再送に委ねる)
                try:
                    threading.Thread(target=self._serve_one, args=(s, data, addr),
                                     daemon=True, name=_cover_tn("dq")).start()  # #81
                except Exception:
                    self._sem.release()       # スレッド生成失敗でも枠を返す(枠漏れ防止)
        self._thread = threading.Thread(target=_loop, daemon=True, name=_cover_tn("dns"))
        self._thread.start()
        return {"ok": True, "listen": f"{self.host}:{self.port}",
                "upstream": f"{self.upstream}:{self.upstream_port}", "mode": self.mode,
                "note": "OSのDNS設定は変更しません。端末/ルータの参照先を本機へ向けて使用。"}

    def stop(self) -> dict:
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        return {"ok": True}

    def log(self, n: int = 100) -> list:
        with self._lock:
            return list(self._log)[-max(1, n):]

    def status(self) -> dict:
        return {"mode": self.mode, "audit": self.audit,
                "blocklist": list(self.blocklist), "regexes": list(self._regex_src),
                "heuristics": self.heuristics, "heuristics_audit": self.heuristics_audit,
                "recon_mode": self.recon_mode, "dedup_window": self.dedup_window,
                "allowlist": list(self.allowlist),
                "metrics": dict(self.metrics), "listen": f"{self.host}:{self.port}",
                "upstream": f"{self.upstream}:{self.upstream_port}",
                "note": "DNSフィルタ(OS非侵襲)。許可は上流転送・遮断はNXDOMAIN/sinkhole。"
                        " L7検知は既定で監査(止めず可視化)。強制遮断は set_heuristics(audit=False)。"}


def _safe_re(pattern: str) -> bool:
    # ReDoS/不正判定は共通ライブラリ saferegex に委譲(DNS 規則はさらに 200 文字上限)。
    if not pattern or len(pattern) > 200:
        return False
    try:
        from ..core import saferegex
        return saferegex.is_safe(pattern)
    except Exception:
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False


_DNS: DnsFilter = None


def dns() -> DnsFilter:
    global _DNS
    if _DNS is None:
        _DNS = DnsFilter()
    return _DNS
