"""
graphql.py — GraphQL クエリの解析と上限照合(標準ライブラリのみ・純粋)
====================================================================================
GraphQL は1エンドポイント(例 /graphql)に任意の問い合わせを POST する。WAF のパス/メソッドや
署名では捉えにくい固有のリスクがある:
  · 深いネスト({a{b{c{...}}}})… リゾルバコストが指数的に膨らむ DoS。
  · 選択セット/エイリアス増幅({a1:x a2:x ...})… 1リクエストで多数フィールドを展開。
  · バッチ([{...},{...}])… 1接続で多数オペレーション。
  · イントロスペクション(__schema/__type)… 本番でスキーマ全体を漏らす。
完全なパーサではなく、字句解析+文脈の追跡で *構造の指標* を取る軽量ガード:
  · 深さ   … 選択セットのネスト。引数/変数既定値の入力オブジェクト({a:{b:1}})は数えない。
  · 複雑度 … 文書に書かれた選択(フィールド。エイリアス付きも 1 個ずつ・...Fragment 展開も 1)の数。
  · イントロスペクション … フィールド名がちょうど __schema / __type のとき。__typename は通常の
    メタフィールド(Apollo/urql が全選択に付ける)なので対象外。
文字列("…" / \"\"\"…\"\"\")と '#' コメント内は構造に数えない。字句は正規表現の search で拾い、
文字列/コメントは find で読み飛ばす=入力長に線形(呼び出し側が graphql_max_bytes で長さを抑える)。
"""
from __future__ import annotations

import re

# 選択セット内で意味を持つ字句(名前/数値/... /構造記号/文字列・コメントの開始)。空白・カンマ等は
# search が読み飛ばす。選択セットの外(文書レベル/引数/入力値)では名前を数えないので、構造記号と
# 文字列・コメントの開始だけを拾う軽い方を使う(引数だらけの文書でも Python 側の反復が増えない)。
_TOK_SEL = re.compile(r'[_A-Za-z][_0-9A-Za-z]*|\d[\w.]*|\.\.\.|[{}()\[\]:@$"#]')
_TOK_VAL = re.compile(r'[{}()\[\]"#]')
_STR_STOP = re.compile(r'["\\\n\r]')
_EOL = re.compile(r'[\n\r]')
_INTROSPECTION = frozenset(("__schema", "__type"))
# JSON の封筒らしい書き出し(生の GraphQL 文書は '[' や '{"' では始まらない)。
_JSONISH = re.compile(r'\s*(?:\[|\{\s*")')
# urlencoded フォームらしい書き出し(name=…)。生の GraphQL 文書はこの形では始まらない。
_FORMISH = re.compile(r'[\w.%\[\]-]+=')


def _skip_string(q: str, i: int, n: int) -> int:
    """q[i] の '"' から始まる文字列(通常/ブロック)の直後の位置を返す。未終端は行末(ブロックは末尾)。"""
    if q.startswith('"""', i):
        j = i + 3
        while True:
            k = q.find('"""', j)
            if k < 0:
                return n
            if q[k - 1] == "\\":                  # \""" はブロック文字列内のエスケープ
                j = k + 3
                continue
            return k + 3
    j = i + 1
    while True:
        m = _STR_STOP.search(q, j)
        if m is None:
            return n
        c = m.group()
        if c == "\\":
            j = m.end() + 1
        elif c == '"':
            return m.end()
        else:
            return m.start()                      # 改行=未終端(字句エラー)。ここで閉じる


def analyze(q: str) -> dict:
    """GraphQL 文書の構造指標 {"depth", "fields", "sets", "introspection"} を返す。
    文脈スタック: S=選択セット / A=引数・変数定義 / O=入力オブジェクト / L=リスト。'{' は文書レベルと
    選択セット内でだけ選択セット、引数/値の中では入力オブジェクト(深さ・選択数に数えない)。"""
    q = str(q)
    n = len(q)
    stack = []
    depth = maxd = fields = sets = 0
    intro = False
    prev = ""                                     # 直前の意味ある字句(コメントは透明)
    spread = on_type = False                      # 直前が '...' / '... on'
    pos = 0
    while pos < n:
        in_sel = bool(stack) and stack[-1] == "S"
        m = (_TOK_SEL if in_sel else _TOK_VAL).search(q, pos)
        if m is None:
            break
        t = m.group()
        pos = m.end()
        c = t[0]
        if c == "#":                              # コメント=行末まで読み飛ばす
            e = _EOL.search(q, pos)
            pos = e.start() if e else n
            continue
        was_spread, was_on = spread, on_type
        spread = on_type = False
        if c == '"':
            pos = _skip_string(q, m.start(), n)
            prev = '"'
        elif c == "{":
            if not stack or stack[-1] == "S":
                stack.append("S")
                depth += 1
                sets += 1
                if depth > maxd:
                    maxd = depth
            else:
                stack.append("O")
            prev = "{"
        elif c == "}":
            if stack and stack.pop() == "S":
                depth -= 1
            prev = "}"
        elif c == "(":
            stack.append("A")
            prev = "("
        elif c == ")":
            if stack and stack[-1] == "A":
                stack.pop()
            prev = ")"
        elif c == "[":
            stack.append("L")
            prev = "["
        elif c == "]":
            if stack and stack[-1] == "L":
                stack.pop()
            prev = "]"
        elif t == "...":
            spread = True
            prev = "..."
        elif c in ":@$":
            prev = c
        elif c.isdigit():
            prev = "0"
        else:                                     # 名前(選択セット内でだけここへ来る)
            if prev in ("@", "$") or was_on:
                pass                              # ディレクティブ名/変数名/型条件(... on T)
            elif was_spread:
                if t == "on":
                    on_type = True                # インラインフラグメントの型条件が続く
                else:
                    fields += 1                   # ...Fragment 展開も 1 選択
            else:
                if prev != ":":
                    fields += 1                   # エイリアス a: f は 1 選択(f 側は数えない)
                if t in _INTROSPECTION:
                    intro = True
            prev = "n"
    return {"depth": maxd, "fields": fields, "sets": sets, "introspection": intro}


def extract_queries(body) -> list:
    """body から GraphQL クエリ文字列群を取り出す。JSON {"query":..} / バッチ [..] / 生クエリ対応。
    GraphQL でなさそうなら空リスト(JSON の封筒なのに読めないものも空。区別は parse_body)。"""
    return parse_body(body)[0]


def parse_body(body, content_type: str = "") -> tuple:
    """要求本文から GraphQL 文書群を取り出す。返り値 (queries, err)。
    application/x-www-form-urlencoded(と 'query=' で始まる本文)は query 欄、JSON は query(配列は
    バッチ)、それ以外の本文は生の文書(application/graphql)として読む。err="malformed" は JSON の
    封筒に見えるのに読めない本文(深すぎる入れ子を含む)=生文書として数えると封筒全体が深さ 1 に
    見えて上限を素通りするので、呼び出し側がフェイルクローズする。"""
    if isinstance(body, (bytes, bytearray)):
        b = bytes(body)
        if b.startswith(b"\xef\xbb\xbf"):          # UTF-8 BOM(.NET 等が付ける)は飛ばす
            b = b[3:]
        text = b.decode("latin1", "replace")
    else:
        text = str(body).lstrip("\N{ZERO WIDTH NO-BREAK SPACE}")   # BOM
    text = text.strip()
    if not text:
        return [], ""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        return form_queries(text), ""
    # 再帰爆弾([[[[…]]]] 等)は深さで *パース前* に弾く(json の深さ制限の甘さ=自己DoS回避)。
    from ..core import saferegex
    d = saferegex.safe_json_loads(text, default=None)
    if d is not None:                              # 妥当な JSON=GraphQL over JSON として解釈
        if isinstance(d, list):
            return [str(o.get("query", "")) for o in d
                    if isinstance(o, dict) and o.get("query")], ""
        if isinstance(d, dict):
            return ([str(d["query"])] if d.get("query") else []), ""
        return [], ""                              # JSON だが dict/list でない=非GraphQL
    if _JSONISH.match(text):
        return [], "malformed"                     # JSON の封筒なのに読めない(切断/破損/深すぎ)
    if _FORMISH.match(text):                       # Content-Type 無しの query=… 等(生文書は name= で始まらない)
        return form_queries(text), ""
    head = text[:12].lower()                      # JSON でない=application/graphql 生クエリ判定
    if text[:1] == "{" or head.startswith(("query", "mutation", "subscription", "fragment")):
        return [text], ""
    return [], ""


def form_queries(qs: str) -> list:
    """クエリ文字列/urlencoded 本文の query 欄(複数あれば全部)。GET /graphql?query=… 用。"""
    from urllib.parse import parse_qs
    try:
        vals = parse_qs(qs, keep_blank_values=True).get("query") or []
    except Exception:
        return []
    return [v for v in vals if v.strip()]


def max_depth(q: str) -> int:
    """選択セットの最大ネスト深さ。文字列/コメント/引数の入力オブジェクトは数えない。"""
    return analyze(q)["depth"]


def selection_count(q: str) -> int:
    """選択セット({…})の数。文字列/コメント/引数の入力オブジェクトの { は数えない。"""
    return analyze(q)["sets"]


def field_count(q: str) -> int:
    """選択(フィールド・エイリアス付きフィールド・フラグメント展開)の数=複雑度の指標。"""
    return analyze(q)["fields"]


def has_introspection(q: str) -> bool:
    """フィールド名 __schema / __type を選択しているか(__typename・文字列・コメントは対象外)。"""
    return analyze(q)["introspection"]


def check(queries, *, max_depth_limit: int = 12, max_complexity: int = 1000,
          block_introspection: bool = True, max_batch: int = 10) -> dict:
    """クエリ群を上限照合。返り値 {"allowed":bool, "reason":..}。GraphQL でない=allowed(not-graphql)。
    複雑度は選択(フィールド。エイリアス付きも 1 個ずつ)の数。"""
    if not queries:
        return {"allowed": True, "reason": "not-graphql"}
    if len(queries) > max_batch:
        return {"allowed": False, "reason": f"batch-too-large:{len(queries)}"}
    for q in queries:
        a = analyze(q)
        if a["depth"] > max_depth_limit:
            return {"allowed": False, "reason": f"depth:{a['depth']}"}
        if a["fields"] > max_complexity:
            return {"allowed": False, "reason": f"complexity:{a['fields']}"}
        if block_introspection and a["introspection"]:
            return {"allowed": False, "reason": "introspection"}
    return {"allowed": True, "reason": "ok"}
