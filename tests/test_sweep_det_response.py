"""
test_sweep_det_response.py — 応答方向の検知(出口 DLP・応答アウェア採点)の回帰。
====================================================================================
· #1  圧縮応答(gzip 等)を DLP が読めず、block でも秘密がそのまま届いていた。
· #26 13 桁の JAN/EAN コードや主要ブランド外の番号を credit_card と誤検知していた。
· #27 DLP が有効だと audit でも応答末尾 64B が保留され、SSE/逐次応答が止まっていた。
· #28 シールド OFF(完全パススルー)でも応答 4xx 連射と penalize が加点・BAN していた。
· #47 chunked 応答の枠(サイズ行)で分断された秘密を見逃していた。
· #48 読取の切れ目を語境界とみなし、長い数字列の途中を credit_card と誤判定していた。
· #49 dlp_action の綴り違い('BLOCK' 等)を黙って受理し、audit として動いていた。
· #50 resp_error_threshold / dlp_max_scan_bytes の 0 以下を受理していた。
· #51 全体 mode=audit(遮断せず記録のみ)でも DLP block が応答を切っていた。
· #52 文書が DLP を『マスク』、resp_stall_sec を『迂回検知』と誤記していた。
· #53 #59/#60 の回帰テストが分割読取の経路を実際には通っていなかった。
"""
import asyncio
import contextlib
import gzip
import os
import tempfile

import dataplane.engine.lifeform.pipeline as ND
import dataplane.engine.lifeform.policy as FW
from dataplane.engine.lifeform.pipeline import NetShield, scan_secret_leak
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_proxy_request import _LEAK, _through   # _LEAK = AWS 文書の例示キー(無効)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── 共通ヘルパ ──────────────────────────────────────────────────────────────
@contextlib.contextmanager
def _shield(**cfg):
    """隔離した NetShield(既定で有効)/ AppFirewall をプロセス共有シングルトンへ差し込む。"""
    osh, ofw = ND._SHIELD, FW._FW
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg.update(cfg)
        ND._SHIELD = sh
        FW._FW = FW.AppFirewall(state_dir=d)
        try:
            yield sh
        finally:
            ND._SHIELD, FW._FW = osh, ofw


class _Sink:
    def __init__(self):
        self.buf = bytearray()

    def write(self, b):
        self.buf += b

    async def drain(self):
        pass

    def close(self):
        pass


class _Reads:
    """backend の読取 1 回ごとに chunk を 1 つ返す(StreamReader のように結合しない)。"""

    def __init__(self, chunks):
        self.q = list(chunks)

    async def read(self, n=65536):
        return self.q.pop(0) if self.q else b""


def _pipe(chunks, **cfg):
    """backend 応答 chunks を _pipe(scan=True)へ 1 読取ずつ流し、(client へ出たバイト, shield)。"""
    with _shield(**cfg) as sh:
        out = _Sink()
        asyncio.run(AsyncEdgeGuard()._pipe(_Reads(chunks), out, scan=True, ip="192.0.2.80",
                                           tls=False, req_host="app.example"))
        return bytes(out.buf), sh


def _resp(body, *extra):
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    for h in extra:
        head += h + b"\r\n"
    return head + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _stream(head, events, gap, **cfg):
    """EOF を送らない backend: events を gap 秒あけて 1 つずつ流し、各時点で client が受け取った
    本文を返す(最後に EOF)。"""
    got = []

    async def go():
        r = asyncio.StreamReader()
        out = _Sink()
        t = asyncio.ensure_future(AsyncEdgeGuard()._pipe(r, out, scan=True, ip="192.0.2.81",
                                                         tls=False, req_host="app.example"))
        r.feed_data(head)
        for ev in events:
            r.feed_data(ev)
            await asyncio.sleep(gap)
            got.append(bytes(out.buf).partition(b"\r\n\r\n")[2])
        r.feed_eof()
        await t
        got.append(bytes(out.buf).partition(b"\r\n\r\n")[2])

    with _shield(**cfg):
        asyncio.run(go())
    return got


def _chunked(head, parts):
    body = b"".join(b"%x\r\n" % len(p) + p + b"\r\n" for p in parts) + b"0\r\n\r\n"
    return head + body


def _dechunk(body):
    out, i = b"", 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            return out
        n = int(body[i:j], 16)
        if n == 0:
            return out
        out += body[j + 2:j + 2 + n]
        i = j + 2 + n + 2


# ── #1 圧縮応答 ─────────────────────────────────────────────────────────────
def test_d1_dlp_forwards_identity_accept_encoding():
    """#1: クライアントの Accept-Encoding: gzip, deflate, br をそのまま backend へ渡していたため、
    圧縮された応答本文を DLP が読めず、block でも秘密が素通りしていた。"""
    req = (b"GET /api/item HTTP/1.1\r\nHost: app.example\r\nUser-Agent: Mozilla/5.0\r\n"
           b"Accept: application/json\r\nAccept-Language: ja\r\n"
           b"Accept-Encoding: gzip, deflate, br\r\n\r\n")
    saw, _, _ = _through([req], dlp_enabled=True, dlp_action="block")
    ae = [ln for ln in saw.split(b"\r\n") if ln.lower().startswith(b"accept-encoding")]
    assert ae == [b"Accept-Encoding: identity"], ae
    # DLP が無効なら従来どおりクライアントの値を渡す(圧縮転送を損なわない)
    saw, _, _ = _through([req], dlp_enabled=False)
    assert b"Accept-Encoding: gzip, deflate, br" in saw, saw


def test_d1_compressed_response_is_unscannable_and_follows_dlp_action():
    """#1: それでも圧縮で返ってきた本文は走査できない=dlp_unscannable として数え、
    block なら本文を送らず切断、audit なら記録して通す。"""
    body = b'{"debug":"key=' + _LEAK + b'"}'
    gz = gzip.compress(body)
    resp = _resp(gz, b"Content-Encoding: gzip")
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block")
    assert gz not in out, out
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="audit")
    assert out == resp
    assert sh.metrics().get("dlp_unscannable", 0) == 1
    assert any(e.get("kind") == "dlp_unscannable" for e in sh.events())


def test_d1_encoded_response_without_body_is_not_blocked():
    # 本文の無い応答(304 等)は Content-Encoding が付いていても走査不能ではない=そのまま届く。
    resp = (b"HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nETag: \"a1\"\r\n\r\n")
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block")
    assert out == resp
    assert sh.metrics().get("dlp_unscannable", 0) == 0


# ── #26 カード番号の誤検知 ─────────────────────────────────────────────────
def _ean13(first12: str) -> str:
    s = sum(int(c) * (3 if i % 2 else 1) for i, c in enumerate(first12))
    return first12 + str((10 - s % 10) % 10)


def _with_luhn(prefix: str, length: int) -> str:
    base = prefix + "0" * (length - len(prefix) - 1)
    for d in "0123456789":
        if ND._luhn_ok((base + d).encode()):
            return base + d
    raise AssertionError(prefix)


def test_d26_jan_codes_are_not_credit_cards():
    """#26: 13 桁の JAN/EAN コード(49/45 始まり)の約 1 割が Luhn を満たし credit_card と
    判定されていた(ecommerce プリセットの DLP block で商品一覧が切れる)。"""
    jans = []
    for i in range(2000):
        code = _ean13("49" + "%010d" % (i * 7919))
        if ND._luhn_ok(code.encode()):
            jans.append(code)
        if len(jans) >= 20:
            break
    assert jans
    for code in jans:
        body = '{"items":[{"jan":"%s","name":"marker"}]}' % code
        assert scan_secret_leak(body) == [], code


def test_d26_issuer_prefix_and_length_required():
    # 主要ブランドの IIN 外(60xx / 63xx / 30 6x 等)は Luhn を満たしても対象外。
    for prefix in ("60", "63", "306", "3500", "5000"):
        num = _with_luhn(prefix, 16)
        assert scan_secret_leak("id " + num) == [], num
    # 13 桁は対象外(EAN/JAN と衝突する)
    assert scan_secret_leak("n " + _with_luhn("4", 13)) == []
    # 既知ブランドは従来どおり検出(既存フィクスチャ+各 IIN)
    assert scan_secret_leak(b"card 4242 4242 4242 4242") == ["credit_card"]
    assert scan_secret_leak("amex 378282246310005") == ["credit_card"]
    for prefix, n in (("51", 16), ("2221", 16), ("2720", 16), ("6011", 16), ("644", 16),
                      ("65", 16), ("3528", 16), ("3589", 16), ("300", 14), ("36", 14),
                      ("38", 14), ("62", 16), ("4", 19)):
        num = _with_luhn(prefix, n)
        assert scan_secret_leak("c " + num) == ["credit_card"], num


# ── #27 保留窓が SSE/逐次応答を止める ─────────────────────────────────────
_SSE_HEAD = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n"
             b"Connection: close\r\n\r\n")
_EV1, _EV2 = b"data: hello\n\n", b"data: second event\n\n"


def test_d27_audit_mode_never_holds_back_bytes():
    """#27: audit(既定)でも各読取の末尾 64B を保留していた=保留しても何も守らないのに、
    小さな SSE イベントや long-poll 応答が EOF まで届かなかった。"""
    for harden in (True, False):
        got = _stream(_SSE_HEAD, [_EV1, _EV2], 0.3, dlp_enabled=True, dlp_action="audit",
                      cookie_harden_enabled=harden, cors_harden_enabled=harden)
        assert got[0] == _EV1, (harden, got)
        assert got[1] == _EV1 + _EV2, (harden, got)
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        got = _stream(head, [b"line one\n"], 0.3, dlp_enabled=True, dlp_action="audit",
                      cookie_harden_enabled=harden, cors_harden_enabled=harden)
        assert got[0] == b"line one\n", (harden, got)


def test_d27_block_mode_streams_sse_and_flushes_idle_tail():
    # block: SSE は保留しない。その他の応答も backend が黙ったら保留分を短時間で放出する。
    got = _stream(_SSE_HEAD, [_EV1, _EV2], 0.3, dlp_enabled=True, dlp_action="block")
    assert got[0] == _EV1 and got[1] == _EV1 + _EV2, got
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    got = _stream(head, [b"line one\n", b"line two\n"], 1.0, dlp_enabled=True,
                  dlp_action="block")
    assert got[0] == b"line one\n", got
    assert got[1] == b"line one\nline two\n", got
    assert got[2] == b"line one\nline two\n", got


def test_d27_block_mode_still_withholds_boundary_spanning_secret():
    # 連続した読取で境界を跨ぐ秘密は、従来どおり頭も送らない(#42 の保証は維持)。
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    c1, c2 = head + b"data key=" + _LEAK[:12], _LEAK[12:] + b" end"
    for harden in (True, False):
        out, sh = _pipe([c1, c2], dlp_enabled=True, dlp_action="block",
                        cookie_harden_enabled=harden, cors_harden_enabled=harden)
        assert _LEAK[:8] not in out, (harden, out)
        assert sh.metrics().get("dlp_leak", 0) == 1


# ── #28 シールド OFF でも応答採点/penalize が BAN ─────────────────────────
def test_d28_note_response_does_nothing_while_shield_off():
    """#28: シールド OFF(完全パススルー)でも 4xx 連射で加点・BAN し blocklist に保存していた。
    ON に戻した瞬間、OFF の間の BAN で正規利用者が 403 になった。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.disable()
        sh.cfg.update(resp_error_threshold=5, resp_score_enabled=True)
        ip = "192.0.2.82"
        for _ in range(100):
            r = sh.note_response(ip, 404)
        assert not r.get("banned"), r
        assert r.get("action") != "block", r
        assert not sh.is_banned_fast(ip)
        assert sh.metrics()["resp_code_hits"].get("4xx", 0) == 100   # テレメトリは維持
        assert not any(e.get("kind") == "resp_anomaly" for e in sh.events())
        sh.enable()
        assert sh.inspect(ip, path="/home")["action"] == "allow"
        again = NetShield(state_dir=d)
        assert not again.is_banned_fast(ip)


def test_d28_penalize_does_nothing_while_shield_off():
    # slow-read / slowloris / smuggling 由来の penalize も OFF の間は加点しない。
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.disable()
        ip = "192.0.2.83"
        for kind in ("slow_read", "slowloris", "smuggling"):
            r = sh.penalize(ip, reason="marker", kind=kind)
            assert not r.get("banned"), r
        assert not sh.is_banned_fast(ip)
        assert sh._decayed_score(sh._state(ip)) == 0.0
        sh.enable()
        assert sh.penalize(ip, reason="marker")["action"] == "penalize"   # ON なら従来どおり


def test_d28_shield_off_end_to_end_then_enable_is_not_banned():
    # 実経路: OFF の間に backend が 404 を返し続けても、ON に戻した直後の要求は 403 にならない。
    import test_sweep_proxy_request as T
    be = T._Backend(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    req = b"GET /nothing HTTP/1.1\r\nHost: app.example\r\n\r\n"
    try:
        with _shield(enabled=False, resp_error_threshold=2) as sh, T._guard(be) as g:
            for _ in range(8):
                assert T._exchange(g, [req]).startswith(b"HTTP/1.1 404")
            assert not sh.is_banned_fast("127.0.0.1")
            sh.enable()
            resp = T._exchange(g, [req])
            assert resp.startswith(b"HTTP/1.1 404"), resp[:40]
    finally:
        be.close()


# ── #47 chunked の枠で分断された秘密 ───────────────────────────────────────
_CH_HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"


def test_d47_secret_split_by_chunk_framing_is_detected():
    """#47: 枠付きのまま走査していたため、chunk 境界(\\r\\n<hex>\\r\\n)が秘密の途中に入ると
    検出できず、クライアントが組み立て直した秘密をそのまま受け取っていた。"""
    resp = _chunked(_CH_HEAD, [b"key=" + _LEAK[:10], _LEAK[10:] + b"\n"])
    for split in (None, len(_CH_HEAD) + 8, len(resp) - 9):
        chunks = [resp] if split is None else [resp[:split], resp[split:]]
        out, sh = _pipe(chunks, dlp_enabled=True, dlp_action="block")
        assert _LEAK not in _dechunk(out.partition(b"\r\n\r\n")[2]), (split, out)
        assert _LEAK[:10] not in out, (split, out)          # 秘密の頭も送らない
        assert sh.metrics().get("dlp_leak", 0) == 1, split


def test_d47_clean_chunked_response_is_byte_identical():
    # 枠はそのまま転送する(走査面だけ de-chunk)。秘密が無ければ 1 バイトも変えない。
    parts = [b"row-%04d marker a'b<c\n" % i for i in range(300)]
    resp = _chunked(_CH_HEAD, parts)
    for cut in (1, 7, 100, 4096):
        chunks = [resp[i:i + cut] for i in range(0, len(resp), cut)]
        for action in ("block", "audit"):
            out, sh = _pipe(chunks, dlp_enabled=True, dlp_action=action)
            assert out == resp, (cut, action)
            assert sh.metrics().get("dlp_leak", 0) == 0


# ── #48 読取の切れ目を語境界とみなす ──────────────────────────────────────
def test_d48_read_boundary_is_not_a_word_boundary():
    """#48: 読取ごとの走査で末尾を \\b とみなしていたため、26 桁の ID の 16 桁目で読取が
    切れると '4242424242424242' が credit_card に見え、同じ応答がパケット次第で切られていた。"""
    num = b"4242424242424242" + b"0000000000"
    body = b'{"big_id":"' + num + b'"}'
    assert scan_secret_leak(body) == []
    resp = _resp(body)
    for split in (None, resp.index(num) + 16, resp.index(num) + 4):
        chunks = [resp] if split is None else [resp[:split], resp[split:]]
        out, sh = _pipe(chunks, dlp_enabled=True, dlp_action="block")
        assert out == resp, split
        assert not sh.metrics().get("dlp_kinds"), split


def test_d48_secret_at_end_of_body_still_detected():
    # 本文の最後(EOF 直前)にある秘密や、1 バイトずつ届く秘密も取りこぼさない。
    resp = _resp(b"key=" + _LEAK)
    for chunks in ([resp], [resp[:-3], resp[-3:]], [bytes([c]) for c in resp]):
        out, sh = _pipe(chunks, dlp_enabled=True, dlp_action="block")
        assert _LEAK[:6] not in out.partition(b"\r\n\r\n")[2], len(chunks)
        assert sh.metrics().get("dlp_leak", 0) == 1


# ── #49 / #50 設定値の検証 ────────────────────────────────────────────────
def test_d49_dlp_action_must_be_audit_or_block():
    """#49: dlp_action は自由文字列で、'BLOCK' や 'deny' を ok で受理して audit として動いていた
    (ダッシュボードには 'BLOCK' と表示される)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        for v in ("deny", "", "auditt", "blocked", 1):
            r = sh.set_config(dlp_action=v)
            assert "dlp_action" in r.get("rejected", []), v
            assert sh.cfg["dlp_action"] == "audit", v
            r = sh.apply_config({"dlp_action": v})
            assert "dlp_action" not in r.get("applied", []), (v, r)
        for v in ("BLOCK", "Block", " block "):
            assert sh.set_config(dlp_action=v)["ok"], v
            assert sh.cfg["dlp_action"] == "block", v
        assert sh.set_config(dlp_action="Audit")["ok"] and sh.cfg["dlp_action"] == "audit"


def test_d50_nonpositive_threshold_and_scan_budget_rejected():
    """#50: resp_error_threshold<=0 は 4xx 2 件で BAN、dlp_max_scan_bytes<=0 は DLP を
    黙って無効化していた(他のキーの『0=無効』と取り違えやすい)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        for key in ("resp_error_threshold", "dlp_max_scan_bytes"):
            before = sh.cfg[key]
            for v in (0, -1):
                r = sh.set_config(**{key: v})
                assert key in r.get("rejected", []), (key, v)
                assert sh.cfg[key] == before, (key, v)
            assert sh.set_config(**{key: 1})["ok"], key


# ── #51 全体 audit モード ──────────────────────────────────────────────────
def test_d51_global_audit_mode_makes_dlp_record_only():
    """#51: mode=audit は『遮断せず記録のみ』のはずが、DLP block だけは応答を切っていた。"""
    resp = _resp(b'{"k":"' + _LEAK + b'"}')
    out, sh = _pipe([resp], dlp_enabled=True, dlp_action="block", mode="audit")
    assert out == resp
    assert sh.metrics().get("dlp_leak", 0) == 1
    ev = [e for e in sh.events() if e.get("kind") == "dlp_leak"]
    assert ev and ev[-1].get("would") == "block", ev
    # enforce なら従来どおり遮断
    out, _ = _pipe([resp], dlp_enabled=True, dlp_action="block", mode="enforce")
    assert _LEAK not in out


# ── #52 文書 ───────────────────────────────────────────────────────────────
def _doc(name):
    with open(os.path.join(_ROOT, "docs", name), encoding="utf-8") as f:
        return f.read()


def test_d52_docs_describe_dlp_and_resp_stall_correctly():
    """#52: DLP はマスク(伏字化)しないのに『検知・マスク』、resp_stall_sec は slow-read の
    累積待ち上限なのに『迂回検知』と書かれていた。resp_error_score の説明も途中で切れていた。"""
    dash = _doc("dashboard.md")
    dlp = [ln for ln in dash.splitlines() if "出口DLP" in ln]
    assert dlp and all("マスク" not in ln for ln in dlp), dlp
    rows = {ln.split("|")[1].strip(): ln for ln in _doc("defenses.md").splitlines()
            if ln.startswith("| `")}
    stall = rows["`resp_stall_sec`"]
    assert "迂回" not in stall and "slow-read" in stall, stall
    score = rows["`resp_error_score`"]
    assert not score.rstrip(" |").endswith(("減衰しても", "=")), score   # 途中で切れていない


# ── #53 #59/#60 の回帰テストが分割読取を通っていない ─────────────────────────
def test_d53_proxy_request_helper_delivers_one_read_per_chunk():
    """#53: test_sweep_proxy_request の _run_pipe は StreamReader に全 chunk を先に流すため、
    _pipe からは 1 回の読取に結合されていた=『パケット分割でも同じ』が分割を通っていなかった。"""
    import test_sweep_proxy_request as T
    reads = []
    orig = AsyncEdgeGuard._pipe

    async def spy(self, src, dst, *a, **k):
        class _Count:
            async def read(self, n=65536):
                b = await src.read(n)
                if b:
                    reads.append(len(b))
                return b
        return await orig(self, _Count(), dst, *a, **k)

    AsyncEdgeGuard._pipe = spy
    try:
        T._run_pipe([b"HTTP/1.1 2", b"00 OK\r\nContent-Length: 2\r\n\r\n", b"ok"])
    finally:
        AsyncEdgeGuard._pipe = orig
    assert len(reads) == 3, reads
