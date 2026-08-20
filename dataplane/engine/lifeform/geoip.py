"""
geoip.py — プラガブルな GeoIP(IP→国コード)・依存ゼロ・任意DBファイル
====================================================================================
国単位の海外通信ブロックのための『精密geo』。外部ライブラリやネットワークに依存せず、
利用者が用意した **CIDR→国コードのDBファイル**(`CIDR,CC` 形式・GeoLite2のcountry blocks等を
2列に整形したもの)を読み込み、IP→国を O(log n) 区間二分探索で解決する。

  · DBが無ければ loaded=False で国判定は ""(=呼び出し側は CIDR モードにフォールバック)。
  · ホットパスでも軽い(bisect)。区間は非重複前提(一般的なGeoIP配布はそう)。
正直: DBの鮮度/正確さは利用者が用意するデータ次第。本機はDBを同梱しない(データ依存を作らない)。
"""
from __future__ import annotations

import bisect
import ipaddress
import os

from ..core.atomic_io import default_state_dir


class GeoIP:
    def __init__(self):
        self._starts: list = []
        self._ends: list = []
        self._cc: list = []
        self.loaded = False
        self.count = 0
        self.source = ""

    def _set_rows(self, rows):
        """rows = [(start_int, end_int, cc)] を取り込む(start順にソートして保持)。"""
        rows.sort()
        self._starts = [r[0] for r in rows]
        self._ends = [r[1] for r in rows]
        self._cc = [r[2] for r in rows]
        self.loaded = bool(rows)
        self.count = len(rows)

    def load_pairs(self, pairs) -> dict:
        """[(cidr, cc)] から読み込む(テスト/プログラム用)。"""
        rows = []
        for cidr, cc in pairs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            if len(str(cc)) != 2:
                continue
            rows.append((int(net.network_address), int(net.broadcast_address),
                         str(cc).upper()))
        self._set_rows(rows)
        self.source = "(pairs)"
        return {"ok": self.loaded, "count": self.count}

    def load(self, path: str = "") -> dict:
        """`CIDR,CC`(またはTAB区切り)のDBファイルを読み込む。"""
        path = path or os.path.join(default_state_dir(), "geoip.csv")
        if not os.path.isfile(path):
            self.loaded = False
            return {"ok": False, "error": f"GeoIP DBが無い: {path}",
                    "hint": "CIDR,CC 形式のファイルを用意(GeoLite2 country blocks を2列整形等)"}
        pairs = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.replace("\t", ",").split(",")
                    if len(parts) < 2 or "/" not in parts[0]:
                        continue
                    pairs.append((parts[0].strip(), parts[1].strip()))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        r = self.load_pairs(pairs)
        self.source = path
        return {**r, "source": path}

    def country(self, ip: str) -> str:
        """IP→国コード(2文字)。未ロード/不一致は ""。"""
        if not self.loaded:
            return ""
        try:
            x = int(ipaddress.ip_address(ip))
        except Exception:
            return ""
        i = bisect.bisect_right(self._starts, x) - 1
        if 0 <= i < len(self._starts) and self._starts[i] <= x <= self._ends[i]:
            return self._cc[i]
        return ""

    def info(self) -> dict:
        return {"loaded": self.loaded, "ranges": self.count, "source": self.source,
                "note": "DB未ロード時は国判定不可→CIDRモードにフォールバック。"}


_GEO: GeoIP = None


def geoip() -> GeoIP:
    global _GEO
    if _GEO is None:
        _GEO = GeoIP()
        try:
            _GEO.load()                       # 既定パスにDBがあれば自動ロード(無ければ無効)
        except Exception:
            pass
    return _GEO
