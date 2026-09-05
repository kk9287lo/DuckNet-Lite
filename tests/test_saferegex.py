"""
test_saferegex.py — ReDoS 耐性ユーティリティ(evolution: saferegex)。
====================================================================================
Python 標準 re には実行タイムアウトが無いため、危険パターンを *載せる前に* lint で弾き、
走査前に入力長を上限で切ることで最悪計算量を有界化する。リテラルは線形時間の Aho-Corasick
で安全に照合できる。組込みシグネチャ全てが lint を通過する(自分の足を撃たない)ことも担保。
"""
import time

from dataplane.engine.core import saferegex


def test_lint_flags_nested_quantifiers():
    assert saferegex.lint("(a+)+") != ""          # 典型的 ReDoS
    assert saferegex.lint("(a*)*b") != ""
    assert saferegex.lint("(.*)*") != ""
    assert saferegex.is_safe(r"\bunion\b\s+select\b")     # 普通の安全パターン
    assert saferegex.lint("") != ""               # 空は不可
    assert saferegex.lint("(") != ""              # 不正正規表現
    assert saferegex.lint("a" * 2000) != ""       # 長すぎ


def test_lint_flags_variable_bounded_inner_quantifier():
    """{m,n}(m<n)= *可変長* の内側反復も外側量化子と組めば指数爆発する。
    旧 lint は上限なし {n,} しか見ておらず、(a{1,10})+b が「安全」として通り、
    24 文字の入力で 0.6 秒を消費するカスタム署名を登録できた。"""
    for bad in (r"(a{1,10})+b", r"(x{1,5}y{1,5})+z", r"(a{2,})+b"):
        assert saferegex.lint(bad) != "", bad
    # 固定回数({n} や {n}{m})や外側量化子の無い {m,n} は従来どおり安全
    for ok in (r"(a{3}){2}b", r"\d{1,3}\.\d{1,3}", r"^[a-z]{1,32}$"):
        assert saferegex.lint(ok) == "", ok


def test_compile_safe_behaviour():
    rx = saferegex.compile_safe(r"(?i)\bdrop\b\s+\btable\b")
    assert rx.search("... DROP TABLE users ...")
    raised = False
    try:
        saferegex.compile_safe("(a+)+")
    except ValueError:
        raised = True
    assert raised                                  # 危険パターンは拒否


def test_search_caps_input():
    rx = saferegex.compile_safe("needle")
    # 上限より後ろにある一致は(切り詰めで)見えない=最悪計算量の天井になる
    text = ("x" * 100) + "needle"
    assert saferegex.search(rx, text, max_len=1000) is not None
    assert saferegex.search(rx, text, max_len=50) is None
    assert saferegex.search(rx, None) is None


def test_run_with_timeout_returns_default():
    # 長い処理は timeout で諦めて default(GIL の制約は docstring に明記済)
    def slow():
        time.sleep(2.0)
        return "done"
    t0 = time.time()
    assert saferegex.run_with_timeout(slow, 0.2, default="TIMEOUT") == "TIMEOUT"
    assert (time.time() - t0) < 1.5                # 即座に返る(待ち続けない)
    assert saferegex.run_with_timeout(lambda: 1 + 1, 1.0) == 2


def test_literal_scanner_linear_multi_match():
    sc = saferegex.LiteralScanner(["sqlmap", "nikto", "/.env"], ignore_case=True)
    assert sc.search("hello SQLMAP world") == "sqlmap"      # 大文字小文字無視
    assert sc.search("nothing here") is None
    found = sc.findall("get /.env and run nikto")
    assert "/.env" in found and "nikto" in found


def test_builtin_signatures_are_redos_safe():
    # 自分のシグネチャが ReDoS lint を通る(WAF 自身の自己DoSを防ぐ)。
    from dataplane.engine.lifeform.pipeline import _SIGNATURES
    bad = [(n, saferegex.lint(p)) for n, p in _SIGNATURES if saferegex.lint(p)]
    assert not bad, f"risky builtin signatures: {bad}"


def test_safe_json_loads_rejects_recursion_bomb():
    bomb = "[" * 5000 + "]" * 5000              # 中身は空・ネストだけ異常に深い
    assert saferegex.safe_json_loads(bomb, max_depth=200, default="REJECT") == "REJECT"
    assert saferegex.json_too_deep(bomb, 200) is True
    # 正常な JSON は通る・文字列内の括弧は深さに数えない
    assert saferegex.safe_json_loads('{"q": "[[[[ in a string ]]]]"}') == {"q": "[[[[ in a string ]]]]"}
    assert saferegex.safe_json_loads('{"a":{"b":{"c":1}}}') == {"a": {"b": {"c": 1}}}
    assert saferegex.safe_json_loads("not json", default=None) is None
    assert saferegex.safe_json_loads("x" * 10, max_len=3, default="BIG") == "BIG"


def test_graphql_extract_survives_json_bomb():
    from dataplane.engine.lifeform.graphql import extract_queries
    bomb = ("[" * 4000 + "]" * 4000).encode()
    assert extract_queries(bomb) == []          # 例外もスタック溢れも無く空で返る


def test_all_compiled_patterns_are_redos_safe():
    # 自分のコンパイル済み正規表現すべて(signatures/tautology/stacked/filename/secret/monitor)が
    # ネスト量化子(ReDoS)を含まない=WAF が自分自身を DoS しない。将来の混入も検出する。
    import re as _re
    import dataplane.engine.lifeform.pipeline as P
    import dataplane.engine.lifeform.monitor as M
    risky = []

    def _check(name, pat):
        s = (pat.pattern.decode("latin1") if isinstance(pat.pattern, (bytes, bytearray))
             else pat.pattern)
        r = saferegex.lint(s)
        if r and "ネスト" in r:          # 長さ超過等ではなく ReDoS 構造のみを問題視
            risky.append((name, s[:60]))

    for mod in (P, M):
        for nm in dir(mod):
            v = getattr(mod, nm)
            if isinstance(v, _re.Pattern):
                _check(f"{mod.__name__}.{nm}", v)
            elif isinstance(v, (list, tuple)):
                for it in v:
                    if isinstance(it, _re.Pattern):
                        _check(nm, it)
                    elif isinstance(it, (tuple, list)):
                        for x in it:
                            if isinstance(x, _re.Pattern):
                                _check(nm, x)
    assert not risky, f"ReDoS-prone compiled patterns: {risky}"
