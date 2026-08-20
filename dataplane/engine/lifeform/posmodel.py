"""
posmodel.py — 正のセキュリティモデル(スキーマ allowlist・標準ライブラリのみ)
====================================================================================
既存の検知は『既知の悪を弾く』負のモデル(署名/IoC/スコア)。本モジュールは逆に『許可した
エンドポイントだけ通す』正のモデルを足す。運用者が許可する (パス, メソッド) を宣言し、それ以外を
逸脱として弾く/記録する。未知の攻撃・ゼロデイにも構造的に強い(許可されていない=通さない)。

ルール 1件: {"path": "/api/users", "match": "exact|prefix|regex", "methods": ["GET","POST"]}
  · match 既定 prefix。methods 空=任意メソッド許可。query は無視(パスのみで判定)。
  · regex は ReDoS 検証(NetShield.validate_pattern)を通った安全なものだけ載せる。

純粋ロジック(ソケット非依存)=テスト容易。NetShield が読み込み・inspect で照合する。
"""
from __future__ import annotations

import re


class Rule:
    """1件の許可ルール(パスパターン + 許可メソッド)。"""

    __slots__ = ("path", "match", "methods", "_re")

    def __init__(self, path: str, match: str = "prefix", methods=None, regex=None):
        self.path = path
        self.match = match
        self.methods = {str(m).upper() for m in (methods or [])}   # 空=任意
        self._re = regex

    def path_matches(self, path: str) -> bool:
        p = path.split("?", 1)[0]                       # query は判定対象外
        if self.match == "exact":
            return p == self.path
        if self.match == "regex":
            return bool(self._re and self._re.fullmatch(p))
        return p.startswith(self.path)                  # prefix(既定)

    def method_ok(self, method: str) -> bool:
        return (not self.methods) or method.upper() in self.methods


class PositiveModel:
    """許可ルール集合。check で (許可か, 理由) を返す。ルール空=制約なし(allow)。"""

    def __init__(self, rules=None):
        self.rules = list(rules or [])

    @property
    def empty(self) -> bool:
        return not self.rules

    @property
    def size(self) -> int:
        return len(self.rules)

    def check(self, method: str, path: str) -> dict:
        """(method, path) を許可ルールと照合。
          · ルール空 … 制約なし → allowed(no-model)。
          · パス一致ルールがあり method も許可 … allowed。
          · パスは一致するが method 不許可 … denied(method-not-allowed)。
          · どのルールにもパスが一致しない … denied(path-not-in-allowlist)。"""
        if not self.rules:
            return {"allowed": True, "reason": "no-model"}
        method = (method or "GET").upper()
        path_seen = False
        for r in self.rules:
            if r.path_matches(path):
                path_seen = True
                if r.method_ok(method):
                    return {"allowed": True, "reason": "allow", "rule": r.path}
        if path_seen:
            return {"allowed": False, "reason": "method-not-allowed"}
        return {"allowed": False, "reason": "path-not-in-allowlist"}


def build_model(raw, validate=None) -> PositiveModel:
    """生のルール配列 → PositiveModel。不正/危険(ReDoS)ルールは黙って捨てる(壊さない)。
    validate: パターンが危険なら理由文字列を返す関数(NetShield.validate_pattern)を渡せる。"""
    rules = []
    for item in (raw or []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        if not path:
            continue
        match = str(item.get("match", "prefix")).lower()
        if match not in ("exact", "prefix", "regex"):
            match = "prefix"
        methods = item.get("methods") or []
        rgx = None
        if match == "regex":
            if validate is not None and validate(path):     # ReDoS/不正は載せない
                continue
            try:
                rgx = re.compile(path)
            except re.error:
                continue
        rules.append(Rule(path, match, methods, rgx))
    return PositiveModel(rules)
