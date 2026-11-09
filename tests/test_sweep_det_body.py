"""
test_sweep_det_body.py — 本文系の検知(GraphQL ガード / アップロード検査 / 本文走査の配線)の回帰
(sweep: det_body 群)。
====================================================================================
· #3  '__type' の部分一致で __typename(Apollo 等が全選択に付ける)をイントロスペクション扱いした。
· #4  body_scan_max_bytes で切った JSON は読めず、深さ/バッチ上限を素通りした(graphql_max_bytes 新設)。
· #5  GET ?query= / x-www-form-urlencoded の query= は GraphQL 上限を通らなかった。
· #6  graphql_paths を生の request-target と比べていた(/GraphQL・/graphq%6C で外れた)。
· #7  複雑度が『{』の数で、エイリアス/フィールド増幅を数えず、引数の入力オブジェクトを数えていた。
· #34 '#' コメントを字句解析せず、コメント内の { や " で深さが狂った。
· #9  二重拡張子の検査が全ドットセグメントを見て、ドメイン名入りのファイル名(.com)を遮断+BAN した。
· #10 multipart のパートヘッダ以外(フォーム値/テキスト本文)の 'filename=' まで拾って遮断した。
· #11 RFC 5987 の filename*=UTF-8''… を復号せず拡張子ポリシーが効かなかった。
· #33 走査 prefix より後ろのパートヘッダ(複数ファイルの 2 個目以降)を検査しなかった。
· #12 body_scan_enabled=False でアップロード検査と GraphQL ガードまで黙って止まった。
· #13 走査中に総受信時間を超えた本文を切断せず backend へ転送していた。
· #35 中身が空の正しい gzip 本文を『走査不能』として 415 にしていた。
"""
import asyncio
import contextlib
import gzip
import json
import socket
import tempfile
import threading
import time
from urllib.parse import quote

import dataplane.engine.lifeform.graphql as G
import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.lifeform.graphql import check, has_introspection, max_depth
from dataplane.engine.lifeform.pipeline import NetShield, _dangerous_upload_filename
from dataplane.engine.services.proxy import AsyncEdgeGuard
from guard_support import stop_guard_owned

# tests/test_graphql.py の深さ 10 問い合わせ(test_only_applies_to_graphql_paths)と
# イントロスペクション問い合わせ。
_DEEP = b'{"query":"' + b"{a" * 10 + b" x " + b"}" * 10 + b'"}'
_INTRO = "{ __schema { x } }"
_MP_CT = "multipart/form-data; boundary=b"


def _mp(filename: bytes, content: bytes = b"x") -> bytes:
    """tests/test_upload.py の _mp と同形(境界 b・1 ファイルパート)。"""
    return (b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
            + filename + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            + content + b"\r\n--b--\r\n")


def _sh(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


@contextlib.contextmanager
def _shield(**cfg):
    """隔離した NetShield(既定で有効)/ AppFirewall をプロセス共有シングルトンへ差し込む。"""
    osh, ofw = ND._SHIELD, FW._FW
    with tempfile.TemporaryDirectory() as d:
        sh = ND.NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg.update(cfg)
        ND._SHIELD = sh
        FW._FW = FW.AppFirewall(state_dir=d)
        try:
            yield sh
        finally:
            ND._SHIELD, FW._FW = osh, ofw


class _Reads:
    """read(n) ごとに chunk を返す(n を超える分は次回へ持ち越す)。"""

    def __init__(self, chunks=()):
        self.q = [c for c in chunks if c]

    async def read(self, n=65536):
        if not self.q:
            return b""
        c = self.q.pop(0)
        if len(c) > n:
            self.q.insert(0, c[n:])
            c = c[:n]
        return c


def _scan(buf, path="/x", chunks=(), **cfg):
    """隔離 shield の下で _scan_request_body を 1 回走らせ、(extra, blocked) を返す。"""
    with _shield(**cfg):
        g = AsyncEdgeGuard()

        async def go():
            return await g._scan_request_body(buf, _Reads(chunks), "203.0.113.80", path)

        return asyncio.run(go())


def _post(path: bytes, body: bytes, ctype: bytes = b"application/json", cl=None) -> bytes:
    n = len(body) if cl is None else cl
    return (b"POST " + path + b" HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n"
            b"Content-Type: " + ctype + b"\r\nContent-Length: " + str(n).encode()
            + b"\r\n\r\n")


_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


class _Backend:
    """接続ごとに受信バイトを記録して固定応答を返す backend(EOF か 1 秒無通信まで読む)。"""

    def __init__(self, resp: bytes = _OK, idle: float = 1.0):
        self.resp = resp
        self.idle = idle
        self.got = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self._srv.settimeout(0.1)
        self.port = self._srv.getsockname()[1]
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        c.settimeout(self.idle)
        data = b""
        try:
            while len(data) < 1048576:
                ch = c.recv(65536)
                if not ch:
                    break
                data += ch
        except OSError:
            pass
        self.got.append(data)
        try:
            c.sendall(self.resp)
        except OSError:
            pass
        finally:
            c.close()

    def saw(self) -> bytes:
        return b"".join(self.got)

    def close(self):
        self._stop.set()
        self._t.join(2)
        self._srv.close()


def _through(parts, *, delay=0.05, guard_kw=None, **cfg):
    """parts を 1 接続でガードへ流し、(backend が受け取った全バイト, 応答) を返す。"""
    be = _Backend()
    try:
        with _shield(**cfg):
            g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=be.port,
                               listen_host="127.0.0.1", listen_port=0, **(guard_kw or {}))
            r = g.start()
            assert r.get("ok"), r
            try:
                c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=8)
                try:
                    for i, p in enumerate(parts):
                        if i:
                            time.sleep(delay)
                        try:
                            c.sendall(p)
                        except OSError:
                            break
                    resp = b""
                    try:
                        while True:
                            ch = c.recv(65536)
                            if not ch:
                                break
                            resp += ch
                    except OSError:
                        pass
                finally:
                    c.close()
                time.sleep(0.2)
            finally:
                stop_guard_owned(g)
        return be.saw(), resp
    finally:
        be.close()


# ── #3: __typename はイントロスペクションではない ─────────────────────────────
def test_d3_typename_is_not_introspection():
    """#3: '__type' の部分一致で、Apollo Client/urql が全選択セットに付ける __typename を
    イントロスペクション扱いし、通常のクエリを遮断して IP を BAN していた。"""
    q = "query GetUser { user(id: 1) { id name __typename } }"
    assert not has_introspection(q)
    assert has_introspection(_INTRO) and has_introspection("{ __type(name: x){ f } }")
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, graphql_enabled=True)
        r = sh.inspect_graphql("192.0.2.20", "/graphql", json.dumps({"query": q}).encode())
        assert r["action"] == "allow", r
        assert not sh.is_banned_fast("192.0.2.20")


# ── #4: GraphQL 本文は graphql_max_bytes まで全体を解析し、超えたら拒否 ──────────
def test_d4_graphql_body_beyond_scan_prefix_is_parsed_in_full():
    """#4: body_scan_max_bytes(64KiB)で切った JSON は読めず、封筒ごと生文書扱い(深さ 1)や
    not-graphql になって、深さ上限もバッチ上限も素通りした。"""
    assert ND._DEFAULTS.get("graphql_max_bytes") == 262144
    query = json.loads(_DEEP)["query"]
    body = json.dumps({"query": query, "variables": {"note": "x" * 70000}}).encode()
    batch = json.dumps([{"query": "{ me { id } }"}] * 5000).encode()
    assert 65536 < len(body) < 262144 and 65536 < len(batch) < 262144
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, graphql_enabled=True, graphql_max_depth=5)
        r = sh.inspect_graphql("192.0.2.22", "/graphql", body)
        assert r["action"] == "block" and r["reason"].startswith("depth"), r
        r = sh.inspect_graphql("192.0.2.23", "/graphql", batch)
        assert r["action"] == "block", r
        assert (r["reason"].startswith("batch-too-large")
                or r["reason"] == "query-readings-too-large"), r


def test_d4_graphql_body_over_max_bytes_is_rejected_without_ban():
    """#4(決定): graphql_max_bytes を超える GraphQL 本文は全体を読めない=検査できないので拒否する
    (413 相当・加点/BAN はしない)。監査モードは記録だけで通す。"""
    body = json.dumps({"query": "{ me { id } }", "variables": {"note": "x" * 2000}}).encode()
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, graphql_enabled=True, graphql_max_bytes=1024)
        r = sh.inspect_graphql("192.0.2.24", "/graphql", body)
        assert r["action"] == "reject" and r.get("status") == 413, r
        assert not sh.is_banned_fast("192.0.2.24")
        ok = sh.inspect_graphql("192.0.2.24", "/graphql", b'{"query":"{ me { id } }"}')
        assert ok["action"] == "allow", ok
        sh.cfg["mode"] = "audit"
        assert sh.inspect_graphql("192.0.2.25", "/graphql", body)["action"] == "allow"


def test_d4_proxy_reads_graphql_body_past_scan_cap_and_413s_oversize():
    """#4: proxy は GraphQL パスの本文を graphql_max_bytes まで読み切って検査し、宣言長が上限を
    超える本文は backend へ送らず 413 を返す。"""
    query = json.loads(_DEEP)["query"]
    body = json.dumps({"query": query, "variables": {"note": "x" * 70000}}).encode()
    head = _post(b"/graphql", body)
    _, blocked = _scan(head + body[:4096], "/graphql", [body[4096:]],
                       graphql_enabled=True, graphql_max_depth=5,
                       body_scan_enabled=False)   # GraphQL 独立の全量検査を確認
    assert blocked is True, blocked
    small = b'{"query":"{ me { id } }","variables":{"note":"' + b"x" * 1500 + b'"}}'
    req = _post(b"/graphql", small)
    saw, resp = _through([req + small], graphql_enabled=True, graphql_max_bytes=1024)
    assert resp.startswith(b"HTTP/1.1 413"), resp[:80]
    assert b"/graphql" not in saw, saw[:80]
    saw, resp = _through([req + small], graphql_enabled=True)       # 既定上限内は通る
    assert b"/graphql" in saw and resp.endswith(b"ok"), (saw[:80], resp[:80])
    # GraphQL 固有の上限は operations 欄だけが対象。本文署名の全体上限は別に適用される。
    up = (b'--b\r\nContent-Disposition: form-data; name="operations"\r\n\r\n'
          b'{"query":"mutation($f: Upload!) { up(file: $f) { id } }","variables":{"f":null}}\r\n'
          b'--b\r\nContent-Disposition: form-data; name="0"; filename="photo.jpg"\r\n\r\n'
          + b"\xff" * 5000 + b"\r\n--b--\r\n")
    saw, resp = _through([_post(b"/graphql", up, _MP_CT.encode()) + up],
                         graphql_enabled=True, graphql_max_bytes=1024)
    assert saw.endswith(b"\r\n--b--\r\n") and resp.endswith(b"ok"), (len(saw), resp[:80])


# ── #5: GET ?query= / urlencoded の query= も検査する ─────────────────────────
def test_d5_graphql_get_and_urlencoded_transports_are_checked():
    """#5: inspect_graphql は本文しか見ず、GET /graphql?query=… と
    application/x-www-form-urlencoded の query=… は上限照合を一切通らなかった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, graphql_enabled=True, graphql_max_depth=5)
        r = sh.inspect_graphql("192.0.2.40", "/graphql?query=" + quote(_INTRO), b"")
        assert r["action"] == "block" and r["reason"] == "introspection", r
        form = ("query=" + quote(json.loads(_DEEP)["query"])).encode()
        r = sh.inspect_graphql("192.0.2.41", "/graphql", form,
                               "application/x-www-form-urlencoded")
        assert r["action"] == "block" and r["reason"].startswith("depth"), r
        ok = sh.inspect_graphql("192.0.2.42", "/graphql?query=" + quote("{ me { id } }"), b"")
        assert ok["action"] == "allow", ok


def test_d5_graphql_get_query_blocked_end_to_end():
    """#5: GET の問い合わせは本文走査(_scan_request_body)を通らず、そのまま backend へ届いていた。"""
    hdr = b" HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\nAccept: application/json\r\n\r\n"
    saw, _ = _through([b"GET /graphql?query=" + quote(_INTRO).encode() + hdr],
                      graphql_enabled=True)
    assert b"/graphql" not in saw, saw[:120]
    saw, resp = _through([b"GET /graphql?query=" + quote("{ me { id } }").encode() + hdr],
                         graphql_enabled=True)
    assert b"GET /graphql" in saw and resp.endswith(b"ok"), (saw[:120], resp[:80])


# ── #6: graphql_paths は正規化パスで照合 ──────────────────────────────────────
def test_d6_graphql_paths_compare_normalized_path():
    """#6: graphql_paths を生の request-target と大小区別つきで比べ、/GraphQL や /graphq%6C
    (backend は同じハンドラへ回す)では深さ上限が外れた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, graphql_enabled=True, graphql_max_depth=2)
        for p in ("/graphql", "/GraphQL", "/graphq%6C", "/graphql/"):
            assert sh.inspect_graphql("192.0.2.21", p, _DEEP)["action"] == "block", p
        assert sh.inspect_graphql("192.0.2.26", "/api/data", _DEEP)["action"] == "allow"


# ── #7: 複雑度はフィールド(エイリアス込み)の数 ─────────────────────────────────
def test_d7_complexity_counts_selected_fields_and_aliases():
    """#7: graphql_max_complexity は『{』の数しか数えず、1 段に 5000 個並べたエイリアス
    (文書化された増幅対策の対象)を複雑度 1 で通した。逆に引数の入力オブジェクト
    (where フィルタ)の { を深さに数えていた。"""
    flat = "{ " + " ".join(f"f{i}: name" for i in range(5000)) + " }"
    r = check([flat])                    # 挙動の検査を先に(新しい補助関数が無くても欠陥を検出する)
    assert not r["allowed"] and r["reason"].startswith("complexity"), r
    assert G.field_count(flat) == 5000
    assert G.field_count("{ a { b } c { d } }") == 4
    assert G.field_count("query Q { me { ...F } } fragment F on User { id name }") == 4
    flt = "{ users(where: {a: {b: {c: {d: 1}}}}) { id name } }"
    assert max_depth(flt) == 2 and G.field_count(flt) == 3
    assert check([flt], max_depth_limit=2)["allowed"]


# ── #34: '#' コメント・ブロック文字列の字句解析 ──────────────────────────────
def test_d34_comments_and_block_strings_are_lexed():
    """#34: '#' コメントを字句として扱わず、コメント内の { を深さに数え(誤遮断)、コメント内の
    1 個の " で以降を文字列扱いして深さ 20 の選択を深さ 0 と見ていた。"""
    q1 = "{ me { id } }\n# note: {{{{{{{{{{{{{{{{"
    assert max_depth(q1) == 2 and check([q1])["allowed"]
    q2 = '# a 5" display\n' + "{a" * 20 + " x " + "}" * 20
    assert max_depth(q2) == 20 and not check([q2])["allowed"]
    q3 = '{ a(text: """block "with" quotes { """) { b } }'
    assert max_depth(q3) == 2 and G.field_count(q3) == 2
    assert not has_introspection('{ user(note: "__schema") { id } }')
    assert not has_introspection("{ me { id } }\n# __schema")


# ── #9: 二重拡張子は最終拡張子+既知のハンドラ拡張子だけ ───────────────────────
def test_d9_domain_style_filenames_are_not_blocked():
    """#9: 全ドットセグメントを既定拒否リスト('com' を含む)と比べ、www.example.com.har
    (DevTools の HAR 書き出し名)等のアップロードを遮断し IP を BAN していた。"""
    for fn in (b"www.example.com.har", b"example.com.crt", b"site-backup.example.com.zip",
               b"messages.pl.yml"):                    # 言語タグ付きの翻訳ファイル名も
        with tempfile.TemporaryDirectory() as d:
            sh = _sh(d)
            r = sh.scan_upload("192.0.2.30", _mp(fn))
            assert r["action"] == "allow", (fn, r)
            assert not sh.is_banned_fast("192.0.2.30")
    deny = ND._DEFAULTS["upload_deny_ext"]
    assert _dangerous_upload_filename(_mp(b"report.com"), deny)[1] == "com"   # 最終拡張子
    assert _dangerous_upload_filename(_mp(b"shell.php.jpg"), deny)[1] == "php"  # 二重拡張子


# ── #10: パートヘッダの filename= だけを見る ─────────────────────────────────
def test_d10_filename_text_outside_part_headers_is_ignored():
    """#10: 本文のどこにある 'filename=' も拾い、フォーム値・multipart のテキスト欄・text/plain
    本文の 1 行で遮断+BAN していた。"""
    cases = (
        (b"text=hello+world&filename=notes.py", "application/x-www-form-urlencoded"),
        (b"--b\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n"
         b"please rename it to filename=report.py\r\n--b--\r\n", _MP_CT),
        (b"rename done; filename=build.sh\r\n", "text/plain"),
    )
    for body, ctype in cases:
        with tempfile.TemporaryDirectory() as d:
            sh = _sh(d)
            assert sh.scan_upload("192.0.2.31", body)["action"] == "allow", body
            assert sh.scan_upload("192.0.2.31", body, ctype)["action"] == "allow", body
            assert not sh.is_banned_fast("192.0.2.31")
    # proxy 経由(本文走査)でも urlencoded のフォーム値では遮断しない
    form = b"text=hello+world&filename=notes.py"
    _, blocked = _scan(_post(b"/f", form, b"application/x-www-form-urlencoded") + form)
    assert blocked is False, blocked


# ── #11: RFC 5987 の filename* を復号 ───────────────────────────────────────
def test_d11_rfc5987_filename_star_is_decoded():
    """#11: filename*=UTF-8''note%2Exyz を復号せず、multipart 解析器(busboy/Werkzeug/Django)が
    note.xyz と読むファイルに拡張子ポリシーが効かなかった。"""
    body = (b"--b\r\nContent-Disposition: form-data; name=\"file\"; "
            b"filename*=UTF-8''note%2Exyz\r\n"
            b"Content-Type: application/octet-stream\r\n\r\nx\r\n--b--\r\n")
    hit = _dangerous_upload_filename(body, ["xyz"])
    assert hit and hit[1] == "xyz", hit
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, upload_deny_ext=["xyz"])
        assert sh.scan_upload("192.0.2.33", body, _MP_CT)["action"] == "block"


# ── #33: 走査 prefix より後ろのパートヘッダも検査 ────────────────────────────
def _two_files(second: bytes) -> bytes:
    first = (b"--b\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"photo.jpg\"\r\n"
             b"Content-Type: image/jpeg\r\n\r\n" + b"\xff" * 70000 + b"\r\n")
    return first + (b"--b\r\nContent-Disposition: form-data; name=\"f2\"; filename=\""
                    + second + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                    b"x\r\n--b--\r\n")


def test_d33_part_headers_beyond_scan_prefix_are_checked():
    """#33: アップロード検査は本文先頭 body_scan_max_bytes しか見ず、70KB の 1 個目のファイルの
    後ろに置いた 2 個目のパート(拒否拡張子)はそのまま backend へ流れた。"""
    body = _two_files(b"note.xyz")
    req = _post(b"/upload", body, _MP_CT.encode()) + body
    saw, _ = _through([req[:30000], req[30000:]], upload_deny_ext=["xyz"],
                      body_scan_enabled=False)
    assert b"note.xyz" not in saw, len(saw)
    ok = _two_files(b"notes.txt")                      # 拒否拡張子でなければ全体が届く
    req = _post(b"/upload", ok, _MP_CT.encode()) + ok
    saw, resp = _through([req[:30000], req[30000:]], upload_deny_ext=["xyz"],
                         body_scan_enabled=False)
    assert saw.endswith(b"x\r\n--b--\r\n") and resp.endswith(b"ok"), (len(saw), resp[:60])


def test_d33_chunked_upload_beyond_prefix_is_checked():
    """#33: chunked 転送の multipart でも、走査 prefix より後ろのパートヘッダを(枠を解いて)検査する。"""
    body = _two_files(b"note.xyz")
    # 小さな枠(数バイトずつ送るストリーミング送信者)=区切り行もヘッダ名も枠をまたぐ(#D5 と同じ形)
    framed = b"".join(b"%x\r\n" % len(body[i:i + 7]) + body[i:i + 7] + b"\r\n"
                      for i in range(0, len(body), 7)) + b"0\r\n\r\n"
    head = (b"POST /upload HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\nContent-Type: "
            + _MP_CT.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n")
    req = head + framed
    saw, _ = _through([req[:30000], req[30000:]], upload_deny_ext=["xyz"],
                      body_scan_enabled=False)
    seen = AsyncEdgeGuard._dechunk_bounded(saw.partition(b"\r\n\r\n")[2], 1 << 20)
    assert seen is not None and b"note.xyz" not in seen, len(saw)   # 枠を解いても届いていない
    assert not saw.endswith(b"0\r\n\r\n"), len(saw)                 # 要求は完結させない
    ok = _two_files(b"notes.txt")
    framed = b"".join(b"%x\r\n" % len(ok[i:i + 7]) + ok[i:i + 7] + b"\r\n"
                      for i in range(0, len(ok), 7)) + b"0\r\n\r\n"
    saw, resp = _through([(head + framed)[:30000], (head + framed)[30000:]],
                         upload_deny_ext=["xyz"], body_scan_enabled=False)
    assert saw.endswith(b"0\r\n\r\n") and resp.endswith(b"ok"), (len(saw), resp[:60])


# ── #12: body_scan_enabled はアップロード検査/GraphQL ガードを止めない ───────────
def test_d12_body_scan_off_keeps_upload_and_graphql_checks():
    """#12: body_scan_enabled=False だと本文を一切読まず、別キーで有効な upload_scan_enabled と
    graphql_enabled の検査まで黙って止まっていた。"""
    up = _mp(b"shell.php")
    gq = b'{"query":"' + _INTRO.encode() + b'"}'
    cfg = dict(body_scan_enabled=False, upload_scan_enabled=True, graphql_enabled=True)
    _, b1 = _scan(_post(b"/upload", up, _MP_CT.encode()) + up, "/upload", **cfg)
    _, b2 = _scan(_post(b"/graphql", gq) + gq, "/graphql", **cfg)
    assert b1 is True and b2 is True, (b1, b2)
    # どれも無効なら従来どおり本文を読まない
    _, b3 = _scan(_post(b"/upload", up, _MP_CT.encode()) + up, "/upload",
                  body_scan_enabled=False, upload_scan_enabled=False, graphql_enabled=False)
    assert b3 is False


# ── #13: 走査中の総時間超過は切断 ───────────────────────────────────────────
class _Dribbler:
    """1 バイトずつ小出しにする slow-body 送信者(tests/test_slowbody.py と同形)。"""

    async def read(self, n):
        await asyncio.sleep(0.03)
        return b"x"


def test_d13_scan_phase_timeout_disconnects():
    """#13: 走査フェーズで body_max_sec を超えても blocked=False を返し、部分本文を backend へ
    転送して新しい body_max_sec でもう一度待っていた。"""
    buf = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n"
    with _shield(body_scan_enabled=True, body_scan_max_bytes=262144,
                 body_timeout_enabled=True, body_max_sec=0.25):
        g = AsyncEdgeGuard(head_timeout=10.0)

        async def go():
            return await g._scan_request_body(buf, _Dribbler(), "203.0.113.81")

        _, blocked = asyncio.run(go())
        assert blocked, blocked
        assert g.metrics.get("slow_body", 0) == 1


def test_d13_slow_body_never_reaches_backend():
    """#13: 実通信でも、走査中に総受信時間を超えた要求は backend に一切届かない。"""
    head = (b"POST /submit HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n"
            b"Content-Type: text/plain\r\nContent-Length: 100000\r\n\r\n")
    t0 = time.time()
    saw, _ = _through([head] + [b"a"] * 40, delay=0.05, body_max_sec=0.5)
    assert saw == b"", saw[:80]
    assert time.time() - t0 < 6.0


def test_d13_body_max_sec_is_total_across_scan_and_stream():
    """#13: 走査フェーズの後、残りの転送に *新しい* body_max_sec を与えていた。先頭を上限ぎりぎりで
    送り切ってから小出しにすると、本文の受信を body_max_sec のほぼ 2 倍まで保持できた。"""
    be = _Backend(idle=8.0)                                # 本文を待つ間に backend 側が先に切らない
    try:
        with _shield(mode="audit", body_timeout_enabled=True, body_max_sec=1.5):
            g = AsyncEdgeGuard(backend_host="127.0.0.1", backend_port=be.port,
                               listen_host="127.0.0.1", listen_port=0, head_timeout=5.0)
            assert g.start().get("ok")
            try:
                c = socket.create_connection(("127.0.0.1", g.listen_port), timeout=8)
                t0 = time.time()
                c.sendall(b"POST /submit HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n"
                          b"Content-Type: text/plain\r\nContent-Length: 100000\r\n\r\n")
                for _ in range(8):                         # 先頭 64KiB を 1.2 秒かけて送り切る
                    time.sleep(0.15)
                    c.sendall(b"a" * 8192)
                closed = None
                c.settimeout(0.05)
                while time.time() - t0 < 6.0:              # 以後は 1 バイトずつ小出し
                    try:
                        c.sendall(b"a")
                        c.recv(65536)                      # 応答か EOF が来た=本文の受信が打ち切られた
                    except socket.timeout:
                        continue
                    except OSError:
                        pass
                    closed = time.time() - t0
                    break
                c.close()
            finally:
                stop_guard_owned(g)
        assert closed is not None and closed < 2.1, closed   # 総時間 1.5 秒で打ち切られる
    finally:
        be.close()


# ── #35: 空の gzip 本文は走査可能 ────────────────────────────────────────────
def test_d35_empty_gzip_body_is_scannable():
    """#35: 解凍結果 b'' を『解けなかった』と同一視し、正しい空の gzip 本文に 415 を返していた。"""
    z = gzip.compress(b"")
    buf = (b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Encoding: gzip\r\nContent-Length: "
           + str(len(z)).encode() + b"\r\n\r\n" + z)
    _, blocked = _scan(buf)
    assert blocked is False, blocked
    _, blocked = _scan(buf.replace(b"gzip", b"br"))   # 解けない符号化は従来どおり 415
    assert blocked == "unscannable", blocked
    head = gzip.compress(b"hello")[:10]                # 途中で切れた gzip(中身が出ない)は空ではない
    cut = (b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Encoding: gzip\r\nContent-Length: "
           + str(len(head)).encode() + b"\r\n\r\n" + head)
    _, blocked = _scan(cut)
    assert blocked == "unscannable", blocked
