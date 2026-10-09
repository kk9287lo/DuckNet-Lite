"""
saferegex.py — ReDoS 耐性のための正規表現ユーティリティ(標準ライブラリのみ・差し込み式)
====================================================================================
正直な前提: CPython の `re` は実行中に GIL を保持し、外部 `regex` のような『マッチのタイムアウト
秒数指定』ができない。短い入力でも壊滅的バックトラッキングを起こすパターンを1本踏むと、その
スレッドはフリーズし得る(= WAF 自身の自己DoS)。本モジュールはこの限界に対する *現実的* な
多層防御を提供する:

  1) lint(pattern)        — 危険な構造(ネスト量化子 (a+)+ 等)を *載せる前に* 検出して弾く。
  2) compile_safe(...)    — lint + コンパイルをまとめ、危険/不正は ValueError。
  3) search/scan(...)     — 走査前に入力長を上限で切る。ReDoS の所要時間は入力長の関数なので、
                            入力上限は最悪計算量の『天井』になる(最も効く実防御)。
  4) run_with_timeout(...) — 別スレッド+join(timeout) の保険。ただし暴走中の C 実装の re は
                            GIL を握るため中断できない(スレッドは残存)= Python の壁。純Python
                            ループや I/O 向けの限定的な保険であることを明記する。
  5) LiteralScanner       — 複数リテラルの Aho-Corasick(線形時間 O(n))。バックトラックが無く
                            ReDoS 不能。リテラル IoC/シグネチャは正規表現でなくこちらで照合できる。
  6) declared_readings(...) — 宣言された charset で本文を読み直す(未知の名前で codec の表を太らせない・
                            線形でない codec は使わない)。
"""
from __future__ import annotations

import functools
import re
import threading
from collections import deque

DEFAULT_MAX_INPUT = 8192        # 走査前に切り詰める入力長の上限(最悪計算量の天井)
MAX_PATTERN_LEN = 1000          # パターン文字列の長さ上限(過大な規則を拒否)

# ネスト量化子: (… + …) + / (… * …) * / (…){2,} + など指数的バックトラックの温床。
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)\s*[*+{]")
# 量化された後方に無限量化が続く ){n,}+ 形
_BOUND_THEN_STAR = re.compile(r"\)\s*\{\d+,\}\s*[*+]")
# 交代(|)を含むグループへの量化: (a|aa)+ 等。ネスト量化子とは別の形の指数的バックトラック
# (曖昧な交代+反復)で、上の2つでは検出できない。中の "|" の有無だけを見る安全側のヒューリスティック。
_ALTERNATION_QUANT = re.compile(
    r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*(?:[*+]|\{\d+,)")
# 同じ原子に非有界量化子が直に続く \s*\s* / .*.* / a+a* : 入力の分け方が O(n^k) 通りになり
# (k=連続数)、入力上限 8192 でも事実上終わらない(^\s*\s*\s*\s*x$ は 400 文字で 1.7 秒)。
# 書き手にとっては 1 個と同じ意味=弾いても失うものが無い。
_ADJ_SAME_QUANT = re.compile(
    r"(\\.|\[(?:\\.|[^\]\\])*\]|\.|[^\\()\[\]{}|*+?^$])[*+]\??\1[*+]")
# 外側が有界反復 {n} / {m,n} でも、回数がこれを超え本体が可変長なら非有界と同じく扱う。
# (a|aa){24}b は 36 文字で 1.2 秒、(a|a?){18}b は 20 文字で 156 秒(指数)。3 回までは
# IPv4 の (\d{1,3}\.){3} のような実用形を通すための上限(3 回なら本体の揺れ^3 で有界)。
_BOUNDED_REPEAT_MAX = 3


def _body_has_unbounded_or_alt(body: str) -> bool:
    """グループ本体に、非有界量化子(* + {n,})または交代 | が(文字クラス/エスケープ外に)
    含まれるか。上の平坦な正規表現が『ネストを跨げない』盲点を補う深さ非依存スキャン用。"""
    i, n = 0, len(body)
    in_class = False
    while i < n:
        c = body[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c in "*+|":
            return True
        if c == "{":
            j = body.find("}", i)
            if j != -1:
                inner = body[i + 1:j]
                if "," in inner and inner.split(",", 1)[1].strip() == "":
                    return True  # {n,} = 上限なし
                if "," in inner:
                    # {m,n}(m<n)= *可変長* の内側反復。外側量化子と組むと分解が曖昧になり
                    # 指数爆発する((a{1,10})+b は lint を素通りしていた)。上限付きでも弾く。
                    _lo, _, _hi = inner.partition(",")
                    try:
                        if int(_hi.strip() or "0") > int(_lo.strip() or "0"):
                            return True
                    except ValueError:
                        return True          # 解釈不能な量化子は安全側で危険扱い
                i = j + 1
                continue
        i += 1
    return False


def _outer_repeats(pattern: str, q: int) -> bool:
    """pattern[q] から始まる量化子が、直前のグループを *何度も* 繰り返すか:
    * + {n,} と、回数の上限が _BOUNDED_REPEAT_MAX を超える {n} / {m,n}。"""
    n = len(pattern)
    if q >= n:
        return False
    if pattern[q] in "*+":
        return True
    if pattern[q] != "{":
        return False
    j = pattern.find("}", q)
    if j == -1:
        return False
    inner = pattern[q + 1:j]
    hi = inner.split(",", 1)[1] if "," in inner else inner
    hi = hi.strip()
    if "," in inner and hi == "":
        return True                          # {n,} = 上限なし
    try:
        return int(hi) > _BOUNDED_REPEAT_MAX
    except ValueError:
        return False                         # 量化子ではない(リテラルの {…})


def _has_nested_evil_quant(pattern: str) -> bool:
    """反復(* + {n,}、または上限 > _BOUNDED_REPEAT_MAX の {n}/{m,n})されたグループの本体に、
    さらに非有界量化子か交代が『任意の深さ』で含まれるか。(a+)+ / ((a+))+ / (a{2,})+ / ((a|a))+ /
    (a|aa){24} 等の指数的バックトラックを、ネストを跨いで検出する(平坦な _NESTED_QUANT/
    _ALTERNATION_QUANT はネスト内の量化子を見逃す)。"""
    i, n = 0, len(pattern)
    in_class = False
    stack = []
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c == "(":
            stack.append(i)
            i += 1
            continue
        if c == ")":
            if stack:
                start = stack.pop()
                if (_outer_repeats(pattern, i + 1)
                        and _body_has_unbounded_or_alt(pattern[start + 1:i])):
                    return True
            i += 1
            continue
        i += 1
    return False


try:                                   # 標準 re の構文木(3.11+ は re._parser、3.10 は sre_parse)
    from re import _parser as _sre_parse
except ImportError:                    # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse     # type: ignore[no-redef]

_REPEAT_OPS = tuple(getattr(_sre_parse, n) for n in
                    ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
                    if hasattr(_sre_parse, n))


def _has_nullable_repeat(pattern: str) -> bool:
    """*空にも一致し得る* 本体を反復しているか: (a?){26} / (a?a?)+ / (?:x?y?){30} 等。
    各回が『空 or 1 文字』を選べるため分け方が 2^回数 通りになり、(a?){26}a{26} は 26 文字で
    1.4 秒、(a?a?)+b は 24 文字で 60 秒を超える。文字列走査では ? の意味(省略/グループ構文/
    遅延)や入れ子を正しく追えないため、標準 re 自身の構文木で各反復の本体の最小幅を見る。
    本体が空に一致し得る反復は書き手にとって無意味(a{0,26} 等で書ける)=弾いても失うものが無い。"""
    try:
        tree = _sre_parse.parse(pattern)
    except Exception:
        return False                    # 不正な正規表現は lint 本体の re.compile が理由を返す

    def _walk(sp, depth=0) -> bool:
        if depth > 100:
            return False
        for op, av in sp:
            if op in _REPEAT_OPS:
                _lo, hi, item = av
                if hi > _BOUNDED_REPEAT_MAX and item.getwidth()[0] == 0:
                    return True
            for x in (av if isinstance(av, (tuple, list)) else (av,)):
                subs = x if isinstance(x, (tuple, list)) else (x,)
                for y in subs:
                    if isinstance(y, _sre_parse.SubPattern) and _walk(y, depth + 1):
                        return True
        return False
    try:
        return _walk(tree)
    except Exception:
        return False


def lint(pattern: str) -> str:
    """パターンの安全性を検査。問題があれば理由(日本語)を、無ければ空文字を返す。"""
    if not pattern:
        return "パターンが空"
    if len(pattern) > MAX_PATTERN_LEN:
        return f"パターンが長すぎ(<= {MAX_PATTERN_LEN})"
    if (_NESTED_QUANT.search(pattern) or _BOUND_THEN_STAR.search(pattern)
            or _ALTERNATION_QUANT.search(pattern)
            or _has_nested_evil_quant(pattern)
            or _ADJ_SAME_QUANT.search(pattern)
            or _has_nullable_repeat(pattern)):
        return "ネスト量化子/交代の反復の疑い(ReDoS 危険)"
    try:
        re.compile(pattern)
    except re.error as e:
        return f"正規表現として不正: {e}"
    return ""


def is_safe(pattern: str) -> bool:
    return lint(pattern) == ""


def compile_safe(pattern: str, flags: int = 0):
    """lint を通したうえでコンパイル。危険/不正なら ValueError(理由付き)。"""
    reason = lint(pattern)
    if reason:
        raise ValueError(reason)
    return re.compile(pattern, flags)


def cap(text, max_len: int = DEFAULT_MAX_INPUT):
    """走査対象を上限長に切り詰める(str / bytes 両対応)。"""
    if text is None:
        return text
    return text[:max_len] if len(text) > max_len else text


def search(rx, text, max_len: int = DEFAULT_MAX_INPUT):
    """入力長を上限で切ってから search(rx は compiled)。ReDoS の面積を有界化する。"""
    if text is None:
        return None
    return rx.search(cap(text, max_len))


def run_with_timeout(fn, timeout: float, default=None):
    """fn() を別スレッドで実行し timeout 秒で諦める(返り値 or default)。
    注意: 暴走中の C 実装 re は GIL を保持するため *中断はできない*(スレッドは残存)。
    主防御は入力長上限と lint。これは純Python処理/IO 向けの保険。"""
    box = {}

    def worker():
        try:
            box["v"] = fn()
        except Exception as e:           # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return default                   # タイムアウト(worker はバックグラウンド継続)
    if "e" in box:
        raise box["e"]
    return box.get("v", default)


def json_too_deep(text: str, max_depth: int) -> bool:
    """文字列の最大ネスト深度が max_depth を超えるか(クォート/エスケープ考慮で [ { を数える)。
    json.loads を呼ぶ *前に* 再帰爆弾([[[[…]]]] / {…} の異常入れ子)を弾くための軽量検査。"""
    depth = maxd = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[" or ch == "{":
            depth += 1
            if depth > maxd:
                maxd = depth
                if maxd > max_depth:
                    return True
        elif ch == "]" or ch == "}":
            if depth > 0:
                depth -= 1
    return False


def safe_json_loads(text, *, max_len: int = 2_000_000, max_depth: int = 200, default=None):
    """再帰爆弾/巨大入力に耐える json.loads。深すぎ/大きすぎはパースせず default。例外も握る。
    標準 re と同様に標準 json も *深さ制限が甘い*(深い入れ子で RecursionError を誘発)ため、
    パース前に長さと深さで足切りして CPU/スタックの浪費を防ぐ。"""
    import json as _json
    if text is None:
        return default
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", "replace")
    if len(text) > max_len:
        return default
    if json_too_deep(text, max_depth):
        return default                              # 再帰爆弾=パースしない
    try:
        return _json.loads(text)
    except Exception:
        return default


# ── 宣言された charset で本文を読み直す ──────────────────────────────────────────
# 本文を宣言どおりに読むバックエンド(Java の Servlet/Spring・Node の body-parser 等)は、Content-Type の
# charset=… で本文を文字にする。ASCII と違う字に読む符号化(EBCDIC の IBM037/IBM500・UTF-16/32・UTF-7)や、
# 2 バイト目に ASCII の値を含む符号化(Shift_JIS・GBK・Big5 等)では、検査が UTF-8/latin-1 で読んだ字面と
# バックエンドが見る字面が食い違う。呼び出し側が宣言どおりの読み方も照合できるよう、その読み方を返す。
_CHARSET_RE = re.compile(r'(?i)(?:^|[;\s])charset[ \t]*=[ \t]*(?:"([^"]*)"|([^;\s"]*))')
# UTF-8/ASCII は呼び出し側が既に読んでいる(同じ字面)ので返さない。
_DECL_SKIP = frozenset(("utf-8", "utf-8-sig", "ascii"))
# 本文の符号化ではない Python 固有の codec と、入力長に対して線形でない codec(punycode)は使わない。
_DECL_DENY = frozenset(("punycode", "idna", "unicode-escape", "raw-unicode-escape", "undefined"))
# IBM の符号ページ番号(Java の別名 IBM-37 / IBM1047 / cp-500 等)。
_IBM_CP_RE = re.compile(r"(?:ibm|cp)_?0*(\d{2,5})")
# Python に無い EBCDIC: IBM-1047(z/OS の Open Systems 版)。IBM-037 と 6 字(¬ Ý ^ [ ] ¨ の位置)だけ違う。
_CP1047_FROM_037 = str.maketrans("¬Ý^[]¨", "^[¬Ý¨]")


@functools.lru_cache(maxsize=256)
def _codec_name(label: str) -> str:
    """正規化した charset ラベル → Python の codec 名(使えない/使わないものは "")。
    codecs.lookup に未知の名前を渡すと encodings の表に 1 件ずつ溜まり続ける(要求ごとに違う名前を
    送られると上限無しに太る)ので、別名表か encodings の実在モジュールで確かめてから引く。"""
    import codecs
    import encodings.aliases
    import importlib.util
    m = _IBM_CP_RE.fullmatch(label)
    cands = [label] + ([f"cp{int(m.group(1)):03d}"] if m else [])
    for c in cands:
        if c == "cp1047":
            return "cp1047"
        mod = encodings.aliases.aliases.get(c)
        if mod is None:
            try:
                if importlib.util.find_spec("encodings." + c) is None:
                    continue
            except Exception:
                continue
            mod = c
        try:
            name = codecs.lookup(mod).name
            b"a".decode(name, "replace")          # bytes→bytes の codec(base64・rot13 等)は弾く
                                                  # (空の bytes は codec を確かめずに '' を返す)
        except Exception:
            return ""
        return "" if name in _DECL_SKIP or name in _DECL_DENY else name
    return ""


def declared_charsets(content_type: str) -> list:
    """Content-Type の charset 引数を Python の codec 名で返す。UTF-8/ASCII・未知・使わない codec は除く。
    重複(1 本の中の重複も、重複ヘッダをカンマで連結したものも)は、最初と最後の 2 つ(実装によって
    最初を採るものと最後を採るものがある)。"""
    ct = (content_type or "")[:1024]
    if "charset" not in ct.lower():
        return []
    found = []
    for m in _CHARSET_RE.finditer(ct):
        raw = (m.group(1) if m.group(1) is not None else m.group(2))[:64].lower()
        label = re.sub(r"[^0-9a-z]+", "_", raw).strip("_")
        name = _codec_name(label) if label else ""
        if name:
            found.append(name)
    if not found:
        return []
    return [found[0]] if found[0] == found[-1] else [found[0], found[-1]]


def declared_readings(data, content_type: str = "") -> list:
    """本文 data(bytes)を、Content-Type で宣言された charset で読んだ文字列の並び(重複は 1 つ)。
    宣言が無い・UTF-8/ASCII・未知なら空。BOM の無い UTF-16/UTF-32 はバックエンドによって
    バイト順の既定が違う(Java はビッグエンディアン・Python は実行機の順)ので両方を返す。
    先頭の BOM(U+FEFF)は外す。復号できないバイトは置換文字にする。"""
    import codecs
    out = []
    names = declared_charsets(content_type)
    if not names:
        return out
    b = bytes(data or b"")
    for name in names:
        if name == "cp1047":
            encs = ("cp037",)
        elif name == "utf-16" and not b.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            encs = ("utf-16-be", "utf-16-le")
        elif name == "utf-32" and not b.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            encs = ("utf-32-be", "utf-32-le")
        else:
            encs = (name,)
        for enc in encs:
            try:
                t = b.decode(enc, "replace")
            except Exception:
                continue
            if name == "cp1047":
                t = t.translate(_CP1047_FROM_037)
            t = t.lstrip("\N{ZERO WIDTH NO-BREAK SPACE}")
            if t not in out:
                out.append(t)
    return out


class LiteralScanner:
    """複数リテラルの線形時間(O(テキスト長))一括検索 = Aho-Corasick。
    正規表現と違いバックトラックが無く ReDoS 不能。リテラルな IoC/シグネチャ照合に最適。"""

    def __init__(self, patterns, ignore_case: bool = True):
        self.ignore_case = ignore_case
        self._goto = [{}]                # 状態 -> {文字: 次状態}
        self._fail = [0]
        self._out = [set()]              # 状態 -> その状態で終端するパターン集合
        for p in patterns:
            if p:
                self._add(p.lower() if ignore_case else p)
        self._build()

    def _add(self, word: str):
        s = 0
        for ch in word:
            nxt = self._goto[s].get(ch)
            if nxt is None:
                nxt = len(self._goto)
                self._goto.append({})
                self._fail.append(0)
                self._out.append(set())
                self._goto[s][ch] = nxt
            s = nxt
        self._out[s].add(word)

    def _build(self):
        q = deque()
        for ch, nxt in self._goto[0].items():
            self._fail[nxt] = 0
            q.append(nxt)
        while q:
            s = q.popleft()
            for ch, nxt in self._goto[s].items():
                q.append(nxt)
                f = self._fail[s]
                while f and ch not in self._goto[f]:
                    f = self._fail[f]
                self._fail[nxt] = self._goto[f].get(ch, 0) if f or ch in self._goto[0] else 0
                self._out[nxt] |= self._out[self._fail[nxt]]

    def search(self, text):
        """最初に一致したリテラルを返す(無ければ None)。"""
        if not text:
            return None
        if self.ignore_case:
            text = text.lower()
        s = 0
        for ch in text:
            while s and ch not in self._goto[s]:
                s = self._fail[s]
            s = self._goto[s].get(ch, 0)
            if self._out[s]:
                return next(iter(self._out[s]))
        return None

    def findall(self, text):
        """一致した全リテラル(集合)。"""
        found = set()
        if not text:
            return found
        if self.ignore_case:
            text = text.lower()
        s = 0
        for ch in text:
            while s and ch not in self._goto[s]:
                s = self._fail[s]
            s = self._goto[s].get(ch, 0)
            if self._out[s]:
                found |= self._out[s]
        return found
