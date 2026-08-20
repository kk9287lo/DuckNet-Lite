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
"""
from __future__ import annotations

import re
import threading
from collections import deque

DEFAULT_MAX_INPUT = 8192        # 走査前に切り詰める入力長の上限(最悪計算量の天井)
MAX_PATTERN_LEN = 1000          # パターン文字列の長さ上限(過大な規則を拒否)

# ネスト量化子: (… + …) + / (… * …) * / (…){2,} + など指数的バックトラックの温床。
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)\s*[*+{]")
# 量化された後方に無限量化が続く ){n,}+ 形
_BOUND_THEN_STAR = re.compile(r"\)\s*\{\d+,\}\s*[*+]")


def lint(pattern: str) -> str:
    """パターンの安全性を検査。問題があれば理由(日本語)を、無ければ空文字を返す。"""
    if not pattern:
        return "パターンが空"
    if len(pattern) > MAX_PATTERN_LEN:
        return f"パターンが長すぎ(<= {MAX_PATTERN_LEN})"
    if _NESTED_QUANT.search(pattern) or _BOUND_THEN_STAR.search(pattern):
        return "ネスト量化子の疑い(ReDoS 危険)"
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
