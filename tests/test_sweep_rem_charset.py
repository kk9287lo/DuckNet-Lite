"""
test_sweep_rem_charset.py — 本文を backend と同じに読み、GraphQL を実行時と同じに数える。
====================================================================================
· GraphQL の本文を常に latin-1 で読んでいたため、UTF-16/32 の JSON 本文(Python の json.loads や
  Jackson はそのまま読む)を「GraphQL でない」か深さ 1 の文書と見ていた。JSON の仕様どおりに符号化を
  判定し、Content-Type で宣言された charset の読み方(EBCDIC・Shift_JIS 等)でも照合する。
· GraphQL の深さ・選択数が名前付きフラグメントの展開先を足していなかった(...F を 1 選択と数えるだけ)。
  展開した先まで数えた実効の深さ・選択数でも照合し、フラグメントの循環は fragment-cycle で拒否する。
· 本文の署名走査が宣言された charset(EBCDIC の IBM037/IBM500/IBM1047・UTF-7 等)で読み直さなかった。
署名の確かめには、無害な目印だけに当たるカスタム署名を使う(攻撃の文字列は使わない)。GraphQL の文書は
構造(入れ子とフラグメント)だけの無害なもの。
"""
import asyncio
import json
import tempfile
import time

import dataplane.engine.lifeform.pipeline as ND
from dataplane.engine.core import saferegex
from dataplane.engine.lifeform import graphql as G
from dataplane.engine.lifeform.pipeline import NetShield

_MARK = "ducknetmarker4242"       # 英数字だけ(EBCDIC の '-' は latin-1 でバッククォートに見える)
_IBM037_TO_1047 = bytes.maketrans(b"\x5f\xad\xb0\xba\xbb\xbd", b"\xb0\xba\x5f\xad\xbd\xbb")


def _nest(n: int) -> str:
    """深さ n の選択セットだけの文書。"""
    return "{" + "a{" * (n - 1) + "x" + "}" * (n - 1) + "}"


def _ibm1047(s: str) -> bytes:
    return s.encode("cp037").translate(_IBM037_TO_1047)


def _gsh(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg["graphql_enabled"] = True
    sh.cfg.update(cfg)
    return sh


def _bsh(d):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg["body_scan_enabled"] = True
    r = sh.add_signature("marker-rule", r"ducknetmarker\d+", weight=10)
    assert r["ok"], r
    return sh


# ── GraphQL: 本文の読み方 ───────────────────────────────────────────────────
def test_g1_json_body_is_read_like_json_loads_in_every_unicode_encoding():
    """UTF-8/16/32(BOM の有無・両方のバイト順)の JSON 本文から、json.loads と同じ文書を取り出して数える。"""
    q = _nest(20)
    env = json.dumps({"query": q})
    for enc in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be",
                "utf-32", "utf-32-le", "utf-32-be"):
        raw = env.encode(enc)
        assert json.loads(raw)["query"] == q                    # backend(Python)はこう読む
        assert G.parse_body(raw, "application/json") == ([q], ""), enc
        r = G.check(G.parse_body(raw)[0], max_depth_limit=12)
        assert r == {"allowed": False, "reason": "depth:20"}, (enc, r)
    small = json.dumps({"query": "{ me { id name } }"}).encode("utf-16")
    assert G.check(G.parse_body(small, "application/json")[0])["allowed"]


def test_g2_declared_charset_is_also_read():
    """Content-Type の charset(EBCDIC・BOM の無い UTF-16 のどちらのバイト順も)で読んだ文書も照合に入る。"""
    q = _nest(20)
    env = json.dumps({"query": q})
    cases = (("IBM037", env.encode("cp037")), ("ibm500", env.encode("cp500")),
             ("IBM-1047", _ibm1047(env)), ("cp875", env.encode("cp875")),
             ("UTF-16", env.encode("utf-16-be")), ("utf-16", env.encode("utf-16-le")))
    with tempfile.TemporaryDirectory() as d:             # 挙動の検査を先に(新しい関数が無くても落ちる)
        sh = _gsh(d)
        for cs, raw in cases:
            r = sh.inspect_graphql("192.0.2.43", "/graphql", raw, "application/json; charset=" + cs)
            assert r["action"] == "block" and r["reason"] == "depth:20", (cs, r)
    for cs, raw in cases:
        rs = G.parse_readings(raw, "application/json; charset=" + cs)
        assert ([q], "") in rs, (cs, rs)
    # 宣言が無い EBCDIC は EBCDIC として読まない(判定で読む backend には読めない本文)
    assert all(qs != [q] for qs, _ in G.parse_readings(env.encode("cp037"), "application/json"))
    # 同じ字面になる読み方は 1 つにまとめる(ASCII だけの本文に charset を付けても 1 回)
    assert len(G.parse_readings(env.encode(), "application/json; charset=iso-8859-1")) == 1


def test_g3_shift_jis_second_byte_backslash_does_not_hide_structure():
    """Shift_JIS の 'ソ' は 2 バイト目が '\\'。latin-1 で読むと文字列の閉じ '"' を食って以降を文字列と
    見るが、Shift_JIS で読む backend には深さ 17 の文書に見える。宣言どおりの読み方で 17 と数える。"""
    q = '{ a(s: "ソ") { ' + "b{" * 15 + "c" + "}" * 15 + ' } e(t: "x") }'
    raw = q.encode("shift_jis")
    assert raw.count(b"\\") == 1
    with tempfile.TemporaryDirectory() as d:
        sh = _gsh(d)
        r = sh.inspect_graphql("192.0.2.40", "/graphql", raw,
                               "application/graphql; charset=Shift_JIS")
        assert r["action"] == "block" and r["reason"] == "depth:17", r
    rs = G.parse_readings(raw, "application/graphql; charset=Shift_JIS")
    depths = sorted(G.analyze(qs[0])["depth"] for qs, _ in rs if qs)
    assert depths == [1, 17], depths                     # latin-1 の読み方では 1 段に見える


def test_g4_inspect_graphql_reads_utf16_and_keeps_normal_queries_allowed():
    """NetShield 経由: UTF-16 の深い文書は遮断し、普通の文書は UTF-16 でも宣言付きでも通す。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _gsh(d)
        deep = json.dumps({"query": _nest(20)}).encode("utf-16-le")
        r = sh.inspect_graphql("192.0.2.41", "/graphql", deep, "application/json")
        assert r["action"] == "block" and r["reason"] == "depth:20", r
        ok = json.dumps({"query": "query Q { me { id ...F } } fragment F on User { name }"})
        for raw, ct in ((ok.encode("utf-16"), "application/json"),
                        (ok.encode("utf-16-be"), "application/json; charset=utf-16"),
                        (ok.encode("cp037"), "application/json; charset=ibm037"),
                        (ok.encode(), "application/json; charset=utf-8")):
            assert sh.inspect_graphql("192.0.2.42", "/graphql", raw, ct)["action"] == "allow", ct


def test_g6_multipart_operations_part_is_read_in_its_own_charset():
    """graphql-multipart-request-spec の operations 欄は、パートの Content-Type の charset でも読む
    (Node の busboy はフォームの欄をパートの charset で文字にする)。欄は JSON として読む。"""
    env = json.dumps({"query": _nest(20), "variables": {"file": None}})

    def mp(part_ct, payload):
        return (b"--B\r\nContent-Disposition: form-data; name=\"operations\"\r\n"
                + (b"Content-Type: " + part_ct + b"\r\n" if part_ct else b"") + b"\r\n"
                + payload + b"\r\n--B\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{}\r\n--B--\r\n")
    with tempfile.TemporaryDirectory() as d:
        sh = _gsh(d)
        for part_ct, payload in ((b"application/json; charset=ibm037", env.encode("cp037")),
                                 (b"application/json; charset=Shift_JIS", env.encode("shift_jis")),
                                 (b"application/json", env.encode("utf-16-le")),
                                 (b"", env.encode())):
            r = sh.inspect_graphql("192.0.2.44", "/graphql", mp(part_ct, payload),
                                   "multipart/form-data; boundary=B")
            assert r["action"] == "block" and r["reason"] == "depth:20", (part_ct, r)
        ok = json.dumps({"query": "{ me { id } }"}).encode("cp037")
        r = sh.inspect_graphql("192.0.2.45", "/graphql", mp(b"application/json; charset=ibm037", ok),
                               "multipart/form-data; boundary=B")
        assert r["action"] == "allow", r


def test_g5_charset_names_are_resolved_without_growing_the_codec_cache():
    """要求ごとに違う charset の名前を送られても Python の codec の表(encodings._cache)を太らせない。
    本文の符号化ではない名前・入力長に対して線形でない codec は使わない。"""
    import encodings
    before = len(encodings._cache)
    for i in range(3000):
        assert saferegex.declared_charsets(f"text/plain; charset=x-none-{i}") == []
    assert len(encodings._cache) - before < 5, len(encodings._cache) - before
    for name in ("punycode", "idna", "unicode_escape", "base64", "rot13", "utf-8", "UTF8",
                 "us-ascii", "aliases"):
        assert saferegex.declared_charsets("text/plain; charset=" + name) == [], name
    assert saferegex.declared_charsets("text/plain; charset=IBM-37") == ["cp037"]
    assert saferegex.declared_charsets("text/plain; charset=\"IBM1047\"") == ["cp1047"]
    # 重複は最初と最後(UTF-8 は呼び出し側が読むので数えない)
    assert saferegex.declared_charsets(
        "text/plain; charset=koi8-u, text/plain; charset=cp1252, text/plain; charset=ibm500"
    ) == ["koi8-u", "cp500"]


# ── GraphQL: 名前付きフラグメント ────────────────────────────────────────────
def test_f1_fragment_chain_adds_up_to_the_executed_depth():
    """フラグメントの中のフラグメントを展開した先まで深さに数える(根の選択セットは展開位置に混ざる)。"""
    q = "query Q { a { ...F1 } }\n" + "\n".join(
        f"fragment F{i} on T {{ b {{ ...F{i + 1} }} }}" for i in range(1, 15)) + "\nfragment F15 on T { z }"
    assert G.check([q], max_depth_limit=12) == {"allowed": False, "reason": "depth:16"}
    assert G.check([q], max_depth_limit=16)["allowed"]
    a = G.analyze(q)
    assert a["depth"] == 2 and a["depth_eff"] == 16 and a["fields_eff"] == 16, a


def test_f2_fragment_fan_out_is_counted_as_executed():
    """各フラグメントが次を 2 回展開する 16 段=実行時 65536 選択。字面の 34 ではなく 65536 と数える。"""
    q = "query { ...F1 }\n" + "\n".join(
        f"fragment F{i} on T {{ ...F{i + 1} ...F{i + 1} }}" for i in range(1, 17)) + "\nfragment F17 on T { z }"
    assert G.check([q]) == {"allowed": False, "reason": "complexity:65536"}
    a = G.analyze(q)
    assert a["fields"] == 34 and a["fields_eff"] == 2 ** 16, a
    wide = "query { ...F1 }\n" + "\n".join(
        f"fragment F{i} on T {{ ...F{i + 1} ...F{i + 1} }}" for i in range(1, 1001)) + "\nfragment F1001 on T { z }"
    assert G.analyze(wide)["fields_eff"] == G._CAP                # 頭打ち(巨大な整数を作らない)


def test_f3_fragment_cycles_are_refused():
    for q in ("query { ...F } fragment F on T { a ...F }",
              "query { ...F } fragment F on T { a ...G } fragment G on T { b ...F }",
              "query { x } fragment F on T { ...G } fragment G on T { ...F }"):
        assert G.check([q]) == {"allowed": False, "reason": "fragment-cycle"}, q
        assert G.analyze(q)["cycle"], q


def test_f4_long_chains_resolve_without_recursion_in_linear_time():
    """2 万段の連鎖でも RecursionError にならず、入力長に比例する時間で数える。"""
    def chain(n):
        return ("query { ...F0 }\n" + "\n".join(f"fragment F{i} on T {{ x {{ ...F{i + 1} }} }}"
                                                for i in range(n)) + f"\nfragment F{n} on T {{ z }}")
    assert G.check([chain(20000)]) == {"allowed": False, "reason": "depth:20001"}
    times = []
    for n in (2500, 20000):
        q = chain(n)
        t = time.perf_counter()
        a = G.analyze(q)
        times.append(time.perf_counter() - t)
        assert a["depth_eff"] == n + 1 and a["fields_eff"] == n + 1, (n, a)
    assert times[1] < max(times[0], 0.002) * 30, times          # 8 倍の長さ(線形≈8 倍・2 乗≈64 倍)


def test_f5_written_counts_and_ordinary_documents_are_unchanged():
    """字面の数え方(既存の field_count/max_depth)は変えない。コメントの中の 'fragment' は定義にしない。"""
    assert G.field_count("query Q { me { ...F } } fragment F on User { id name }") == 4
    assert G.field_count("{ a { b } c { d } }") == 4
    q = "# fragment X on T\nquery { a { ...X } } fragment X on T { b { c } }"
    a = G.analyze(q)
    assert (a["depth_eff"], a["fields_eff"]) == (3, 3), a
    q2 = "query { a { ...X } } fragment # note\n X on T @include(if: true) { b { c { d } } }"
    assert G.analyze(q2)["depth_eff"] == 4
    assert G.analyze("fragmentX { a }")["depth_eff"] == 1             # 名前であってキーワードではない
    assert G.analyze('{ a(s: "...F fragment F on T {{{") { b } }')["depth_eff"] == 2
    ok = ("query Q($id: ID!) { user(id: $id) { ...U friends { ...U } } }\n"
          "fragment U on User { id name avatar { url } }")
    assert G.check([ok])["allowed"]


# ── 本文の署名走査: 宣言された charset ──────────────────────────────────────
def test_b1_body_in_declared_charset_is_signature_scanned():
    """EBCDIC(IBM037/IBM500/IBM1047)・UTF-7・BOM の無い UTF-16 で書いた本文を、宣言どおりに読んで走査する。"""
    cases = (("text/plain; charset=IBM037", ("note " + _MARK).encode("cp037")),
             ("application/json; charset=ibm500", json.dumps({"note": _MARK}).encode("cp500")),
             ("text/plain; charset=IBM-1047", _ibm1047("note " + _MARK)),
             ("text/plain; charset=utf-7", ("note " + _MARK).encode("utf-7")),
             ("text/plain; charset=utf-16", ("note " + _MARK).encode("utf-16-be")))
    for ct, body in cases:
        with tempfile.TemporaryDirectory() as d:
            r = _bsh(d).inspect_body("192.0.2.50", body, content_type=ct)
        assert r.get("signature") == "marker-rule", (ct, r)
    with tempfile.TemporaryDirectory() as d:            # 宣言が無ければ EBCDIC としては読まない
        sh = _bsh(d)
        assert sh.inspect_body("192.0.2.51", ("note " + _MARK).encode("cp037"),
                               content_type="text/plain")["action"] == "allow"
        # 宣言と違う中身(ASCII)でも、UTF-8 として読む走査は従来どおり
        r = sh.inspect_body("192.0.2.52", ("note " + _MARK).encode(),
                            content_type="text/plain; charset=ibm037")
        assert r.get("signature") == "marker-rule", r


def test_b2_duplicate_content_type_charset_is_read_through_the_proxy():
    """Content-Type が重複すると proxy は型を渡さない(T1)が、charset はどれを backend が採っても読む。"""
    from dataplane.engine.services.proxy import AsyncEdgeGuard
    from test_sweep_det_body import _Reads
    body = ("note " + _MARK).encode("cp037")
    for cts in ([b"text/plain; charset=IBM037"],
                [b"text/plain; charset=IBM037", b"text/plain; charset=IBM037"],
                [b"text/plain; charset=koi8-u", b"text/plain; charset=IBM037"]):
        head = (b"POST /f HTTP/1.1\r\nHost: x\r\n"
                + b"".join(b"Content-Type: " + c + b"\r\n" for c in cts)
                + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        with tempfile.TemporaryDirectory() as d:
            old = ND._SHIELD
            ND._SHIELD = _bsh(d)
            try:
                async def go():
                    return await AsyncEdgeGuard()._scan_request_body(head + body, _Reads(),
                                                                     "192.0.2.53", "/f")
                asyncio.run(go())
                hits = dict(ND._SHIELD._sig_hits)
            finally:
                ND._SHIELD = old
        assert hits.get("marker-rule") == 1, (cts, hits)
