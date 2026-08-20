"""
origin.py — エッジ経由を証明する時間有界トークン(バイパス防止・標準ライブラリのみ・純粋)
====================================================================================
APT はしばしば「門(WAF)と戦わず、地面を変える」: 仮想 NIC のルーティングを書き換える、または
バックエンドの IP を直叩きして *ChickenNet を迂回* する。本モジュールはそれを構造的に潰す。

  · エッジ(ChickenNet)は転送するリクエストに、共有鍵から導く *時間バケット HMAC* トークンを付与する。
  · バックエンドは verify_origin_token でそれを検証し、無い/不正なリクエストを拒否する。
  · 鍵を持たない攻撃者はトークンを作れない=迂回トラフィックは弾かれる。

正直な範囲: 時間バケット方式なので、リプレイは窓(既定30秒)内に限り可能。完全な防止には
内部経路の MITM が前提になり、そこまで握られていれば別問題。鍵はエッジ・バックエンドで共有
(env `CHICKENNET_ORIGIN_KEY`)。鍵を VM 外(KMS/シークレット管理)に置けば、スナップショット窃取
されてもトークンは偽造できない。
"""
from __future__ import annotations

import hashlib
import hmac
import time


def _b(key) -> bytes:
    return key if isinstance(key, (bytes, bytearray)) else str(key).encode("utf-8")


def origin_token(key, now: float = None, window: float = 30.0) -> str:
    """現在の時間バケットに対する HMAC トークン(hex 32 文字)。エッジが付与する。"""
    now = time.time() if now is None else now
    bucket = int(now // max(1.0, float(window)))
    return hmac.new(_b(key), str(bucket).encode("ascii"), hashlib.sha256).hexdigest()[:32]


def verify_origin_token(token: str, key, now: float = None,
                        window: float = 30.0, skew: int = 1) -> bool:
    """トークンを検証する(バックエンドが呼ぶ)。現在バケット ± skew を許容して時計ずれを吸収。
    定数時間比較。token 空/不正は False。"""
    tok = str(token or "")
    if not tok:
        return False
    now = time.time() if now is None else now
    win = max(1.0, float(window))
    b = int(now // win)
    for d in range(-int(skew), int(skew) + 1):
        cand = hmac.new(_b(key), str(b + d).encode("ascii"), hashlib.sha256).hexdigest()[:32]
        if hmac.compare_digest(cand, tok):
            return True
    return False
