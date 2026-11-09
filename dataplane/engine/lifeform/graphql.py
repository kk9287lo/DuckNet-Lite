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
  · 実効の深さ・複雑度 … 名前付きフラグメント(fragment F on T {…})を展開した先まで数えた値
    (操作ごとの最大)。上限照合は字面と実効の大きい方で行う。フラグメントが 2 回ずつ次の
    フラグメントを展開する連鎖は、字面では数十個でも実行時には 2^段数 個の選択になる。
    フラグメントの循環(F→G→F)は上限超過として扱う(GraphQL の仕様では無効な文書)。
  · イントロスペクション … フィールド名がちょうど __schema / __type のとき。__typename は通常の
    メタフィールド(Apollo/urql が全選択に付ける)なので対象外。
文字列("…" / \"\"\"…\"\"\")と '#' コメント内は構造に数えない。字句は正規表現の search で拾い、
文字列/コメントは find で読み飛ばす=入力長に線形(呼び出し側が graphql_max_bytes で長さを抑える)。
フラグメントの解決も再帰しない(展開の連鎖が深くてもスタックを使わない)。
"""
from __future__ import annotations

import codecs
import hashlib
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
# JSON の値の書き出し(json.loads が受け付ける NaN/Infinity を含む)。これで始まらない本文は JSON として
# 読めないので、json の深さ検査(1 文字ずつの走査)を省く。
_JSON_START = re.compile(r'[\[{"\-0-9tfnNI]')
# 定義の前の読み飛ばす字句(空白・カンマ・BOM・'#' コメント)。後ろに何も続けない match だけで使う
# (=後戻りしない)。
_IGNORED = re.compile(r'(?:[\s,\ufeff]|#[^\n\r]*)*')
_NAME = re.compile(r'[_A-Za-z][_0-9A-Za-z]*')
_NAME_CHAR = re.compile(r'[_0-9A-Za-z]')
_CAP = 1 << 30                                    # 実効の数の頭打ち(整数を大きくしない)
_MAX_ENVELOPE_QUERIES = 512                       # 別名の読み方も含めた独立の走査予算


class _EnvelopeQueries(list):
    """List-compatible readings with the original JSON operation count.

    Query/QUERY may select different strings on different receivers, but are
    alternative readings of one operation. Public callers can still use a list;
    mutating it discards the count proof and restores the ordinary list budget.
    """
    __slots__ = ("_batch_count", "_original")

    def __init__(self, values, batch_count):
        super().__init__(values)
        self._batch_count = batch_count
        self._original = tuple(self)


def _envelope_queries(document) -> tuple:
    objects = document if isinstance(document, list) else [document]
    values = []
    for item in objects:
        if not isinstance(item, dict):
            continue
        item_values = []
        uninspectable_query = False
        persisted_hashes = []
        for name, value in item.items():
            # Struct-based JSON receivers can match every case alias. Exact
            # duplicates were already rejected by the strict JSON decoder.
            lower = name.lower()
            if lower == "extensions" and isinstance(value, dict):
                persisted_hashes.extend(_persisted_hashes(value))
            if lower == "query":
                if isinstance(value, str) and value.strip():
                    if len(values) >= _MAX_ENVELOPE_QUERIES:
                        return [], "query-readings-too-large"
                    values.append(value)
                    item_values.append(value)
                else:
                    uninspectable_query = True
        # APQ/persisted-query backends can execute a cached document using only
        # the hash. The edge cannot enforce depth, complexity or introspection
        # limits against a document absent from this request.
        if persisted_hashes and (not item_values or uninspectable_query or
                                 not _hashes_match_queries(persisted_hashes, item_values)):
            return [], "persisted-query-uninspectable"
    return _EnvelopeQueries(values, len(objects)), ""


def _persisted_hashes(extensions: dict) -> list:
    """All case-alias hash readings a JSON receiver may select."""
    hashes = []
    for name, value in extensions.items():
        if name.lower() != "persistedquery":
            continue
        if not isinstance(value, dict):
            hashes.append(None)
            continue
        found = [item for key, item in value.items() if key.lower() == "sha256hash"]
        hashes.extend(found or [None])
    return hashes


def _hashes_match_queries(hashes: list, queries: list) -> bool:
    """Every receiver view must bind the same visible document bytes."""
    try:
        digests = {hashlib.sha256(query.encode("utf-8")).hexdigest()
                   for query in queries}
    except UnicodeError:
        return False
    return len(digests) == 1 and all(
        type(value) is str and re.fullmatch(r"[0-9a-fA-F]{64}", value)
        and value.lower() in digests for value in hashes)


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


def _fragment_name(q: str, start: int, end: int):
    """q[start:end](定義の '{' の前)が 'fragment 名前 …' ならその名前、違えば None。"""
    i = _IGNORED.match(q, start, end).end()
    if not q.startswith("fragment", i) or i + 8 >= end or _NAME_CHAR.match(q, i + 8):
        return None
    m = _NAME.match(q, _IGNORED.match(q, i + 8, end).end(), end)
    return m.group() if m else None


def _expand(own, frags, done):
    """1 つの定義の実効の (深さ, 選択数)。own={"depth", "fields", "spreads": [(深さ, 名前)…]}。
    展開先は done(解決済みのフラグメント)から引く。未定義のフラグメントは字面どおり 1 選択。
    フラグメントの根の選択セットは展開した位置の選択セットに混ざる(深さ k の展開は k-1+展開先の深さ)。"""
    d, f = own["depth"], own["fields"]
    for k, name in own["spreads"]:
        got = done.get(name)
        if got is not None:
            if k - 1 + got[0] > d:
                d = k - 1 + got[0]
            f += got[1]
        elif name not in frags:
            f += 1
    return min(d, _CAP), min(f, _CAP)


def _resolve(frags) -> tuple:
    """名前付きフラグメントを展開した実効の (深さ, 選択数) を名前ごとに求める(再帰しない深さ優先)。
    返り値 (解決済み {名前: (深さ, 選択数)}, 循環があったか)。"""
    done, state, cycle = {}, {}, False
    for root in frags:
        if root in state:
            continue
        state[root] = 1                           # 1=展開中 / 2=解決済み
        stack = [(root, 0)]
        while stack:
            name, i = stack[-1]
            sp = frags[name]["spreads"]
            if i < len(sp):
                stack[-1] = (name, i + 1)
                tgt = sp[i][1]
                if tgt in frags:
                    st = state.get(tgt)
                    if st == 1:
                        cycle = True              # 展開中のものへ戻る=循環
                    elif st is None:
                        state[tgt] = 1
                        stack.append((tgt, 0))
                continue
            done[name] = _expand(frags[name], frags, done)
            state[name] = 2
            stack.pop()
    return done, cycle


def analyze(q: str) -> dict:
    """GraphQL 文書の構造指標 {"depth", "fields", "sets", "introspection", "depth_eff", "fields_eff",
    "cycle"} を返す。depth/fields は文書の字面、*_eff は名前付きフラグメントを展開した操作ごとの最大、
    cycle はフラグメントの循環。
    文脈スタック: S=選択セット / A=引数・変数定義 / O=入力オブジェクト / L=リスト。'{' は文書レベルと
    選択セット内でだけ選択セット、引数/値の中では入力オブジェクト(深さ・選択数に数えない)。"""
    q = str(q)
    n = len(q)
    stack = []
    depth = maxd = fields = sets = 0
    intro = False
    prev = ""                                     # 直前の意味ある字句(コメントは透明)
    spread = on_type = False                      # 直前が '...' / '... on'
    cur = None                                    # いま読んでいる定義(操作/フラグメント)
    def_start = 0                                 # その定義の頭(直前の定義の '}' の後)
    frags, ops = {}, []
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
                if not stack:                     # 文書レベルの '{'=定義(操作/フラグメント)の始まり
                    cur = {"depth": 0, "fields": 0, "spreads": []}
                    name = _fragment_name(q, def_start, m.start())
                    if name is None:
                        ops.append(cur)
                    elif name in frags:           # 同名の重複(仕様では無効)=重い側に倒して合算
                        cur = frags[name]
                    else:
                        frags[name] = cur
                stack.append("S")
                depth += 1
                sets += 1
                if depth > maxd:
                    maxd = depth
                if cur is not None and depth > cur["depth"]:
                    cur["depth"] = depth
            else:
                stack.append("O")
            prev = "{"
        elif c == "}":
            if stack and stack.pop() == "S":
                depth -= 1
            if not stack and cur is not None:     # 定義の終わり
                cur, def_start = None, pos
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
                    if cur is not None:
                        cur["spreads"].append((depth, t))
            else:
                if prev != ":":
                    fields += 1                   # エイリアス a: f は 1 選択(f 側は数えない)
                    if cur is not None:
                        cur["fields"] += 1
                if t in _INTROSPECTION:
                    intro = True
            prev = "n"
    done, cycle = _resolve(frags) if frags else ({}, False)
    deff = feff = 0
    for op in ops:
        d, f = _expand(op, frags, done)
        deff, feff = max(deff, d), max(feff, f)
    return {"depth": maxd, "fields": fields, "sets": sets, "introspection": intro,
            "depth_eff": deff, "fields_eff": feff, "cycle": cycle}


def extract_queries(body) -> list:
    """body から GraphQL クエリ文字列群を取り出す。JSON {"query":..} / バッチ [..] / 生クエリ対応。
    GraphQL でなさそうなら空リスト(JSON の封筒なのに読めないものも空。区別は parse_body)。"""
    return parse_body(body)[0]


def _json_encoding(b: bytes) -> str:
    """本文の符号化を JSON の仕様どおりに判定する(RFC 4627 の方法=Python の json.loads・Jackson と同じ):
    BOM があればそれ、無ければ先頭 4 バイトの NUL の並び(JSON の先頭は必ず ASCII の字)。"""
    if b.startswith((codecs.BOM_UTF32_BE, codecs.BOM_UTF32_LE)):
        return "utf-32"
    if b.startswith((codecs.BOM_UTF16_BE, codecs.BOM_UTF16_LE)):
        return "utf-16"
    if b.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if len(b) >= 4:
        if not b[0]:
            return "utf-16-be" if b[1] else "utf-32-be"
        if not b[1]:
            return "utf-16-le" if b[2] or b[3] else "utf-32-le"
    elif len(b) == 2:
        if not b[0]:
            return "utf-16-be"
        if not b[1]:
            return "utf-16-le"
    return "utf-8"


def _readings(body, charsets: str = "") -> list:
    """本文の読み方(文字列)の並び。最初が JSON の仕様どおりの判定で読んだもの。charsets(Content-Type の
    値)で charset が宣言されていれば、その読み方(違う字面になるものだけ)を後ろに足す。バックエンドには
    判定で読むもの(Python・Jackson)と宣言で読むもの(Spring・Node の body-parser 等)があるので、両方を照合する。"""
    if not isinstance(body, (bytes, bytearray)):
        return [str(body).lstrip("\N{ZERO WIDTH NO-BREAK SPACE}")]   # BOM
    b = bytes(body)
    enc = _json_encoding(b)
    if enc in ("utf-8", "utf-8-sig"):
        # Valid UTF-8 must retain the actual query text so a persisted-query
        # digest binds to the same bytes the backend receives. For invalid
        # UTF-8, latin-1 still preserves ASCII structural tokens for scanning.
        raw = b[3:] if enc == "utf-8-sig" else b
        try:
            first = raw.decode("utf-8")
        except UnicodeDecodeError:
            first = raw.decode("latin1")
    else:
        first = b.decode(enc, "replace").lstrip("\N{ZERO WIDTH NO-BREAK SPACE}")
    out = [first]
    if charsets:
        from ..core import saferegex
        for t in saferegex.declared_readings(b, charsets):
            if t not in out:
                out.append(t)
    return out


def parse_body(body, content_type: str = "") -> tuple:
    """要求本文から GraphQL 文書群を取り出す。返り値 (queries, err)。
    application/x-www-form-urlencoded(と 'query=' で始まる本文)は query 欄、JSON は query とその
    大小文字別名(配列はバッチ)、それ以外の本文は生の文書(application/graphql)として読む。
    別名の読み方はすべて検査するが、バッチ件数は元の操作数で数える。err="malformed" は JSON の
    封筒に見えるのに読めない本文(深すぎる入れ子を含む)=生文書として数えると封筒全体が深さ 1 に
    見えて上限を素通りするので、呼び出し側がフェイルクローズする。
    bytes の本文は JSON の仕様どおりに符号化を判定して読む(UTF-16/32 の JSON も読める)。宣言された
    charset の読み方まで照合するときは parse_readings を使う。"""
    return _parse_text(_readings(body)[0], content_type)


def parse_readings(body, content_type: str = "", charsets: str = None) -> list:
    """本文の読み方ごとの (queries, err) の並び(最初は parse_body と同じ)。呼び出し側はすべてを照合し、
    1 つでも上限を超える/読めない読み方があれば拒否する。charsets は charset を読む Content-Type の値
    (省略時は content_type。multipart の欄はパートの Content-Type を渡す)。"""
    texts = _readings(body, content_type if charsets is None else charsets)
    from ..core import saferegex
    try:
        texts += saferegex.declared_form_readings(texts, content_type if charsets is None else charsets)
    except saferegex.FormInspectionLimit as error:
        return [([], str(error))]
    return [_parse_text(t, content_type) for t in texts]


def _parse_text(text: str, content_type: str = "") -> tuple:
    """文字列にした本文 1 つの (queries, err)(parse_body の本体)。"""
    text = text.strip()
    if not text:
        return [], ""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        return _parse_form(text)
    # 再帰爆弾([[[[…]]]] 等)は深さで *パース前* に弾く(json の深さ制限の甘さ=自己DoS回避)。
    # JSON の値で始まらない本文は JSON として読めないので、1 文字ずつの深さ検査を省く。
    from ..core import saferegex
    d = (saferegex.safe_json_loads(text, default=None, reject_duplicates=True) if _JSON_START.match(text)
         else None)
    if d is not None:                              # 妥当な JSON=GraphQL over JSON として解釈
        if isinstance(d, (list, dict)):
            return _envelope_queries(d)
        return [], ""                              # JSON だが dict/list でない=非GraphQL
    if _JSONISH.match(text):
        return [], "malformed"                     # JSON の封筒なのに読めない(切断/破損/深すぎ)
    if _FORMISH.match(text):                       # Content-Type 無しの query=… 等(生文書は name= で始まらない)
        return _parse_form(text)
    head = text[:12].lower()                      # JSON でない=application/graphql 生クエリ判定
    if text[:1] == "{" or head.startswith(("query", "mutation", "subscription", "fragment")):
        return [text], ""
    return [], ""


def _parse_form(text: str) -> tuple:
    from ..core import saferegex
    try:
        if form_persisted_uninspectable(text):
            return [], "persisted-query-uninspectable"
        return form_queries(text), ""
    except saferegex.FormInspectionLimit as error:
        return [], str(error)


def form_queries(qs: str) -> list:
    """クエリ文字列/urlencoded 本文の query 欄と大小文字別名をすべて読む。"""
    from urllib.parse import parse_qs
    from ..core import saferegex
    saferegex.check_form_field_budget(qs)
    try:
        fields = parse_qs(qs, keep_blank_values=True, max_num_fields=saferegex.MAX_FORM_FIELDS)
    except Exception:
        return []
    return [value for name, vals in fields.items() if name.lower() == "query"
            for value in vals if value.strip()]


def form_persisted_uninspectable(qs: str) -> bool:
    """Whether a URL/form operation may execute a cached, unseen document."""
    from urllib.parse import parse_qs
    from ..core import saferegex
    saferegex.check_form_field_budget(qs)
    try:
        fields = parse_qs(qs, keep_blank_values=True, max_num_fields=saferegex.MAX_FORM_FIELDS)
    except Exception:
        return False
    persisted_hashes = []
    queries = []
    opaque = False
    for name, values in fields.items():
        lower = name.lower()
        if lower == "query":
            queries.extend(values)
        elif lower == "extensions":
            for value in values:
                extension = saferegex.safe_json_loads(value, default=None,
                                                       reject_duplicates=True)
                if not isinstance(extension, dict):
                    opaque = True  # duplicate/malformed extension has no unique receiver view
                else:
                    persisted_hashes.extend(_persisted_hashes(extension))
    if opaque:
        return True
    return bool(persisted_hashes) and (
        not queries or any(not value.strip() for value in queries)
        or not _hashes_match_queries(persisted_hashes, queries))


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
    複雑度は選択(フィールド。エイリアス付きも 1 個ずつ)の数。深さ・複雑度は文書の字面と、名前付き
    フラグメントを展開した実効の大きい方で見る。フラグメントの循環は fragment-cycle で拒否する。"""
    if not queries:
        return {"allowed": True, "reason": "not-graphql"}
    batch_count = (queries._batch_count if isinstance(queries, _EnvelopeQueries)
                   and tuple(queries) == queries._original else len(queries))
    if batch_count > max_batch:
        return {"allowed": False, "reason": f"batch-too-large:{batch_count}"}
    for q in queries:
        a = analyze(q)
        if a["cycle"]:
            return {"allowed": False, "reason": "fragment-cycle"}
        depth = max(a["depth"], a["depth_eff"])
        if depth > max_depth_limit:
            return {"allowed": False, "reason": f"depth:{depth}"}
        fields = max(a["fields"], a["fields_eff"])
        if fields > max_complexity:
            return {"allowed": False, "reason": f"complexity:{fields}"}
        if block_introspection and a["introspection"]:
            return {"allowed": False, "reason": "introspection"}
    return {"allowed": True, "reason": "ok"}
