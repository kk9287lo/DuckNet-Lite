"""
bloom.py — 確率的ブルームフィルタ(標準ライブラリのみ・真のO(k)・依存ゼロ)
====================================================================================
既知BAN IP の『1判定ほぼO(1)』瞬殺プリスキャン用。多数のBotが同時に押し寄せても、
重い inspect(ロック/正規表現/辞書state)へ行く手前で、ビット演算だけで弾けるようにする。

正直な実装上の要点(『巨大Python int をビットマスクにする』案の落とし穴を回避):
  · Python の int は任意精度。1MB級の int への AND/シフトは limb 全体を走査する =
    実質 O(mビット) で『1ナノ秒』にならない。
  · 真の O(k) は **bytearray のバイト添字 + ビット演算**(`bits[i>>3] & (1<<(i&7))`)。
    本実装はこちらを使う。k 個のハッシュは二重ハッシュ(Kirsch–Mitzenmacher)で1回のblake2bから生成。

性質: 偽陰性ゼロ(『入っていない』は100%正確=BAN漏れしない)。偽陽性は数%(設定可)だが、
本防御では後段の **正規ルートの厳密確認**([[pipeline]] の inspect())が拾うため実害なし。
"""
from __future__ import annotations

import hashlib
import math


class BloomFilter:
    def __init__(self, capacity: int = 50000, error_rate: float = 0.01):
        capacity = max(1, int(capacity))
        error_rate = min(0.5, max(1e-6, float(error_rate)))
        m = int(-(capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.m = max(8, m)
        self.k = max(1, int(round((self.m / capacity) * math.log(2))))
        self.bits = bytearray((self.m + 7) // 8)
        self.capacity = capacity
        self.n = 0

    def _indices(self, item):
        if isinstance(item, str):
            item = item.encode("utf-8", "replace")
        h = hashlib.blake2b(item, digest_size=16).digest()
        h1 = int.from_bytes(h[:8], "little")
        h2 = int.from_bytes(h[8:], "little") | 1     # 奇数化(周期性を避ける)
        m = self.m
        for i in range(self.k):
            yield (h1 + i * h2) % m

    def add(self, item) -> None:
        for idx in self._indices(item):
            self.bits[idx >> 3] |= (1 << (idx & 7))   # 真のO(1)ビットセット
        self.n += 1

    def __contains__(self, item) -> bool:
        for idx in self._indices(item):
            if not (self.bits[idx >> 3] & (1 << (idx & 7))):
                return False                          # 1ビットでも欠ければ確実に未登録
        return True

    def clear(self) -> None:
        self.bits = bytearray(len(self.bits))
        self.n = 0

    def info(self) -> dict:
        set_bits = sum(bin(b).count("1") for b in self.bits)
        fill = set_bits / self.m if self.m else 0.0
        # 現在の推定偽陽性率 (fill^k)
        return {"m_bits": self.m, "k": self.k, "added": self.n,
                "bytes": len(self.bits), "fill": round(fill, 4),
                "est_fp_rate": round(fill ** self.k, 5)}
