"""
txnlog.py — 構造化トランザクションログ(標準ライブラリのみ)
====================================================================================
全 HTTP トランザクションを *安定スキーマ* の1行 JSON で記録する。アラート(重要事象のみ・#10で
SIEM へ)とは別軸で、『全リクエストの構造化メタデータ』を残し、脅威ハンティング/事後相関に使う。
ローカル JSONL(サイズ超で自動ローテ)へ書き、任意で #10 の転送基盤へも流せる。

安定スキーマ(列は固定=機械処理しやすい):
  ts uid src method host uri ua zone action verdict reason sig score bytes_in bytes_out duration
  · uid … 1トランザクションの相関ID。
  · action … allow/block/throttle/challenge(WAF 判定)。verdict … clean/suspicious/malicious。
  · sig … 反応したシグネチャ/IoC/カナリア等のタグ(reason から抽出)。

正直な線引き(誇張しない):
  · 既定OFF(全リクエスト=高ボリューム)。収集は外部ログシッパー or ローカル参照を想定(本機は
    ネット送信を強制しない)。SIEM への *毎件* 転送は txnlog_forward で opt-in
    (高ボリューム=syslog UDP 推奨・webhook は不可)。
  · 同期追記(既存の usage_log と同方式)。append は逐次書込み=SSD に優しい。
"""
from __future__ import annotations

import base64
import os
import threading
import time

from ..core.atomic_io import default_state_dir, append_jsonl, tail_jsonl
from ..lifeform.forwarders import default_fanout

# 安定スキーマの列順(機械処理のため固定)。文字列列と数値列を分けて既定値を埋める。
_STR_FIELDS = ("src", "method", "host", "uri", "ua", "zone", "action",
               "verdict", "reason", "sig")
_NUM_FIELDS = ("score", "bytes_in", "bytes_out", "duration")


def new_uid() -> str:
    """1トランザクションの相関ID(短いランダム)。"""
    return base64.urlsafe_b64encode(os.urandom(6)).decode("ascii").rstrip("=")


class TransactionLog:
    """全トランザクションを安定スキーマで JSONL 追記(ローテ付き)。任意で SIEM へも転送。"""

    def __init__(self, state_dir: str = "", max_bytes: int = 20_000_000, backups: int = 3):
        base = state_dir or default_state_dir()
        os.makedirs(base, exist_ok=True)
        self._path = os.path.join(base, "txn_log.jsonl")
        self._max_bytes, self._backups = max_bytes, backups
        self._lock = threading.Lock()
        self.count = 0

    def record(self, rec: dict, forward: bool = False) -> dict:
        out = {"ts": round(float(rec.get("ts") or time.time()), 3),
               "uid": rec.get("uid") or new_uid()}
        for k in _STR_FIELDS:
            out[k] = str(rec.get(k, ""))
        for k in _NUM_FIELDS:
            out[k] = rec.get(k, 0)
        append_jsonl(self._path, out, max_bytes=self._max_bytes, backups=self._backups)
        with self._lock:
            self.count += 1
        if forward:                               # 高ボリューム=opt-in(syslog UDP 推奨)
            try:
                default_fanout().emit(out, "http", out.get("verdict", "clean"))
            except Exception:
                pass
        return out

    def tail(self, n: int = 100) -> list:
        return tail_jsonl(self._path, n)


_TXN: TransactionLog = None


def txn_log() -> TransactionLog:
    global _TXN
    if _TXN is None:
        _TXN = TransactionLog()
    return _TXN
