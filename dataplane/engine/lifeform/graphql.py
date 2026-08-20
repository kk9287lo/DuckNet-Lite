"""
graphql.py — GraphQL クエリの解析と上限照合(標準ライブラリのみ・純粋)
====================================================================================
GraphQL は1エンドポイント(例 /graphql)に任意の問い合わせを POST する。WAF のパス/メソッドや
署名では捉えにくい固有のリスクがある:
  · 深いネスト({a{b{c{...}}}})… リゾルバコストが指数的に膨らむ DoS。
  · 選択セット/エイリアス増幅({a1:x a2:x ...})… 1リクエストで多数フィールドを展開。
  · バッチ([{...},{...}])… 1接続で多数オペレーション。
  · イントロスペクション(__schema/__type)… 本番でスキーマ全体を漏らす。
完全なパーサではなく、*構造の粗い指標*(波括弧ネスト深さ・選択セット数)で上限を課す軽量ガード。
文字列リテラル内の波括弧は深さに数えない(誤検知回避)。
"""
from __future__ import annotations


def extract_queries(body) -> list:
    """body から GraphQL クエリ文字列群を取り出す。JSON {"query":..} / バッチ [..] / 生クエリ対応。
    GraphQL でなさそうなら空リスト。"""
    text = (body.decode("latin1", "replace") if isinstance(body, (bytes, bytearray))
            else str(body)).strip()
    if not text:
        return []
    # 再帰爆弾([[[[…]]]] 等)は深さで *パース前* に弾く(json の深さ制限の甘さ=自己DoS回避)。
    from ..core import saferegex
    d = saferegex.safe_json_loads(text, default=None)
    if d is not None:                              # 妥当な JSON=GraphQL over JSON として解釈
        if isinstance(d, list):
            return [str(o.get("query", "")) for o in d if isinstance(o, dict) and o.get("query")]
        if isinstance(d, dict):
            return [str(d["query"])] if d.get("query") else []
        return []                                  # JSON だが dict/list でない=非GraphQL
    head = text[:12].lower()                        # JSON でない=application/graphql 生クエリ判定
    if text[:1] == "{" or head.startswith(("query", "mutation", "subscription", "fragment")):
        return [text]
    return []


def max_depth(q: str) -> int:
    """選択セット(波括弧)の最大ネスト深さ。文字列リテラル内は無視する。"""
    depth = maxd = 0
    in_str = esc = False
    for c in q:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
            if depth > maxd:
                maxd = depth
        elif c == "}":
            depth = max(0, depth - 1)
    return maxd


def selection_count(q: str) -> int:
    """選択セット数(複雑度の粗い指標)。文字列内の { は数えない。"""
    n = 0
    in_str = esc = False
    for c in q:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            n += 1
    return n


def has_introspection(q: str) -> bool:
    return "__schema" in q or "__type" in q


def check(queries, *, max_depth_limit: int = 12, max_complexity: int = 100,
          block_introspection: bool = True, max_batch: int = 10) -> dict:
    """クエリ群を上限照合。返り値 {"allowed":bool, "reason":..}。GraphQL でない=allowed(not-graphql)。"""
    if not queries:
        return {"allowed": True, "reason": "not-graphql"}
    if len(queries) > max_batch:
        return {"allowed": False, "reason": f"batch-too-large:{len(queries)}"}
    for q in queries:
        d = max_depth(q)
        if d > max_depth_limit:
            return {"allowed": False, "reason": f"depth:{d}"}
        c = selection_count(q)
        if c > max_complexity:
            return {"allowed": False, "reason": f"complexity:{c}"}
        if block_introspection and has_introspection(q):
            return {"allowed": False, "reason": "introspection"}
    return {"allowed": True, "reason": "ok"}
