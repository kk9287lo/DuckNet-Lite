"""
test_sweep_rv_lite_tray.py — トレイの状態表示: 相手の確認・トークンの渡し先・監査モード(Lite)
====================================================================================
トレイの状態表示(test_sweep_lite_tray_status)を入れた後の独立レビューで見つかった 3 件:
  · #25 管理ポートを *別のプログラム* が使っていて、そのプログラムが自前の認証で 401 を返すと、
        トレイは「状態を確認できません(管理トークン不一致)」と出していた。ゲートウェイは起動すら
        できていないのに、DUCKNET_ADMIN_TOKEN を直せば済むかのように見えた。本製品の 401
        (本文 "token required")の時だけトークン不一致、ほかは「ゲートウェイに接続できません」。
  · #26 状態ポーラは、起動時に受け取った管理トークンを 5 秒ごとに *いま* ポートで待ち受けている
        相手へ送っていた。本体が止まった後に別のプロセスが同じポートで待ち受けると、設定済みの
        トークン(app.env の DUCKNET_ADMIN_TOKEN)がそのプロセスへ渡った。トークンを付ける前に、
        トークン無しの要求で相手が本製品の管理APIかを確かめる(_ensure_gateway と同じ指紋)。
  · #27 シールドが有効でも mode=audit(検知は記録のみ・何も遮断しない)の間、トレイは通常アイコンで
        「防御 ON」と出していた。ON とは別の表示(防御 ON(監査モード: 記録のみ…))と淡色アイコンにする。
実際の管理ダッシュボードと、役を差し替えられる偽の待受(別のプログラム/本製品を模したもの)で確かめる。
"""
import contextlib
import http.server
import io
import os
import shutil
import tempfile
import threading
import time
from unittest import SkipTest

ADMIN_401 = b'{"ok": false, "error": "token required"}'   # 本製品の管理APIの 401 本文


@contextlib.contextmanager
def _patched(obj, **attrs):
    """obj の属性を一時的に差し替える。"""
    saved = {k: getattr(obj, k) for k in attrs}
    try:
        for k, v in attrs.items():
            setattr(obj, k, v)
        yield
    finally:
        for k, v in saved.items():
            setattr(obj, k, v)


def _G():
    import dataplane.gui.__main__ as G
    return G


def _u16(s: str) -> int:
    """szTip(WCHAR 配列)で占める UTF-16 単位数。"""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


# ── 役を差し替えられる偽の待受 ─────────────────────────────────────────
class _Stub(http.server.BaseHTTPRequestHandler):
    """server.answer(handler) -> (code, headers, body) を返す待受。届いた (path, X-Token) を
    server.seen へ記録する(トークンがどこへ渡ったかを後で確かめる)。"""

    def do_GET(self):
        self.server.seen.append((self.path, self.headers.get("X-Token")))
        code, headers, body = self.server.answer(self)
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@contextlib.contextmanager
def _stub(answer, port=0):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Stub)
    srv.answer, srv.seen = answer, []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield "http://127.0.0.1:%d" % srv.server_address[1], srv.seen
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(3)


def _foreign_401(_h):
    """別のプログラム: 何を聞かれても自前の認証で 401(本製品の指紋は無い)。"""
    return (401, [("WWW-Authenticate", 'Basic realm="other app"'),
                  ("Content-Type", "application/json")], b'{"message":"Unauthorized"}')


def _plain_200(_h):
    """別のプログラム: 認証なしで何にでも 200(しかも本製品の指標の形をしている)。"""
    return (200, [("Content-Type", "text/plain")], b"ducknet_shield_enabled 1\n")


def _not_found(_h):
    return (404, [("Content-Type", "text/plain")], b"not here")


def _ducknet_like(token, metrics=b"ducknet_shield_enabled 1\n", authed=None):
    """本製品の管理APIを模す: トークンが合わなければ 401 + "token required"、合えば
    authed(handler) の応答(既定は metrics を 200 で)。"""
    def answer(h):
        if h.headers.get("X-Token") != token:
            return (401, [("Content-Type", "application/json")], ADMIN_401)
        if authed is not None:
            return authed(h)
        return (200, [("Content-Type", "text/plain")], metrics)
    return answer


@contextlib.contextmanager
def _dashboard(token="rv-tray-token"):
    """実際の管理ダッシュボード(状態は一時ディレクトリ・抜けるときに元へ戻す)。"""
    import dataplane.engine.lifeform.policy as FW
    import dataplane.engine.lifeform.pipeline as ND
    from dataplane.admin import AdminDashboard
    tmp = tempfile.mkdtemp(prefix="ducknet-rv-tray-")
    ofw, osh = FW._FW, ND._SHIELD
    adm = None
    try:
        FW._FW = FW.AppFirewall(state_dir=tmp)
        ND._SHIELD = ND.NetShield(state_dir=tmp)
        adm = AdminDashboard(host="127.0.0.1", port=0, token=token, state_dir=tmp)
        info = adm.start()
        yield adm, info["url"], ND._SHIELD
    finally:
        if adm is not None:
            adm.stop()
        FW._FW, ND._SHIELD = ofw, osh
        shutil.rmtree(tmp, True)


# ── #25 別のプログラムの 401 を「トークン不一致」と言わない ─────────────────
def test_foreign_401_on_admin_port_is_unreachable_not_token_mismatch():
    G = _G()
    with _stub(_foreign_401) as (url, _seen):
        for tok in ("", "configured-token"):
            assert G._fetch_shield_state(url, tok, timeout=2.0) == "unreachable", tok
        # 起動時の流れ: _ensure_gateway は「本製品ではない」と判断して空トークンを返す(起動しない)。
        # その後のポーラの表示は「接続できません」=トークンを直す話ではないと分かる。
        def _no_spawn(*a, **k):
            raise AssertionError("must not spawn a gateway on an occupied port")
        for env_tok in ("", "configured-token"):
            with _patched(G, _spawn_gateway=_no_spawn), \
                    contextlib.redirect_stderr(io.StringIO()):
                tok, child = G._ensure_gateway(url, env_tok)
            assert (tok, child) == ("", None), (tok, child)
            tip, _icon = G._status_view(G._fetch_shield_state(url, tok, timeout=2.0),
                                        "DuckNet-Lite")
            assert "Gateway unreachable" in tip, tip
            assert "トークン" not in tip and "token" not in tip, tip


def test_ducknet_401_is_still_token_mismatch():
    """本製品の 401 はこれまでどおり「トークン不一致」(前回の修正の意図: ON/OFF を偽らない)。"""
    G = _G()
    with _dashboard("right-token") as (_adm, url, sh):
        sh.enable()
        assert G._fetch_shield_state(url, "right-token") == "on"
        assert G._fetch_shield_state(url, "wrong-token") == "auth"
        assert G._fetch_shield_state(url, "") == "auth"
    with _stub(_ducknet_like("right-token")) as (url, _seen):
        assert G._fetch_shield_state(url, "wrong-token", timeout=2.0) == "auth"
        assert G._fetch_shield_state(url, "", timeout=2.0) == "auth"


# ── #26 本製品と確かめられない相手へトークンを送らない ───────────────────
def test_token_is_not_sent_to_a_listener_that_is_not_ducknet():
    G = _G()
    for answer in (_plain_200, _not_found, _foreign_401):
        with _stub(answer) as (url, seen):
            assert G._fetch_shield_state(url, "secret-tok", timeout=2.0) == "unreachable", \
                answer.__name__
        assert seen, answer.__name__                 # 相手には届いている(確認の要求)
        assert all(t is None for _p, t in seen), (answer.__name__, seen)


def test_identity_probe_does_not_follow_redirects_to_the_real_admin():
    """相手が本物の管理APIへリダイレクトしても、その先の 401 を『相手は本製品』と取り違えない
    (指紋を借りた別物へトークンを送らない)。"""
    G = _G()
    with _stub(_ducknet_like("secret-tok")) as (real, real_seen):
        def _redirect(_h):
            return (302, [("Location", real + "/api/state")], b"")
        with _stub(_redirect) as (url, seen):
            assert G._fetch_shield_state(url, "secret-tok", timeout=2.0) == "unreachable"
            assert G._admin_is_ours("127.0.0.1", int(url.rsplit(":", 1)[1]), 2.0) is False
    assert all(t is None for _p, t in seen), seen
    assert real_seen == [], real_seen                # リダイレクト先へは要求すら出していない


def test_verified_admin_gets_the_token_without_following_redirects():
    """相手を確かめた後の本要求も、リダイレクトに従ってトークンを持ち出さない。"""
    G = _G()
    with _stub(_plain_200) as (target, target_seen):
        def _authed(_h):
            return (302, [("Location", target + "/steal")], b"")
        with _stub(_ducknet_like("secret-tok", authed=_authed)) as (url, seen):
            assert G._fetch_shield_state(url, "secret-tok", timeout=2.0) == "unreachable"
    assert ("/api/metrics", "secret-tok") in seen, seen
    assert target_seen == [], target_seen


def test_ducknet_is_probed_without_the_token_then_read_with_it():
    G = _G()
    with _stub(_ducknet_like("secret-tok")) as (url, seen):
        assert G._fetch_shield_state(url, "secret-tok", timeout=2.0) == "on"
    # 1 本目はトークン無しの確認、2 本目でだけトークンを付けて状態を読む
    assert len(seen) == 2 and seen[0][1] is None, seen
    assert seen[1] == ("/api/metrics", "secret-tok"), seen


def test_token_is_not_handed_to_whoever_takes_the_admin_port_later():
    """設定済みトークンで本体が稼働 → 本体が止まる → 別のプロセスが同じポートで待ち受ける、の後の
    ポーリングで、そのプロセスへトークンが渡らない(以前は 5 秒ごとに渡していた)。"""
    G = _G()
    token = "configured-in-app-env"
    with _dashboard(token) as (adm, url, sh):
        sh.disable()
        tok, child = G._ensure_gateway(url, token)
        assert (tok, child) == (token, None)        # 稼働中の本体を確認してトークンを使う
        assert G._fetch_shield_state(url, tok) == "off"
        port = int(url.rsplit(":", 1)[1].split("/")[0])
        adm.stop()
    cm, err = None, None
    for _ in range(50):
        try:
            cm = _stub(_plain_200, port)
            ctx = cm.__enter__()
            break
        except OSError as e:
            cm, err = None, e
            time.sleep(0.05)
    if cm is None:
        raise SkipTest("管理APIのポートを別の待受で取り直せない: %r" % (err,))
    try:
        _u, seen = ctx
        assert G._fetch_shield_state(url, tok, timeout=2.0) == "unreachable"
        assert seen and all(t is None for _p, t in seen), seen
    finally:
        cm.__exit__(None, None, None)


# ── #27 監査モード(記録のみ)を「防御 ON」と同じに見せない ──────────────────
def test_audit_view_is_distinct_and_dimmed():
    G = _G()
    from dataplane.gui import ASSET_ICO, ASSET_ICO_OFF
    tip, icon = G._status_view("audit", "DuckNet-Lite")
    on_tip, on_icon = G._status_view("on", "DuckNet-Lite")
    assert tip != on_tip and on_icon == ASSET_ICO
    assert icon == ASSET_ICO_OFF, icon               # 遮断していない=淡色(ON だけが通常アイコン)
    for w in ("監査モード", "記録のみ", "audit", "record only"):
        assert w in tip, (w, tip)
    assert tip.startswith("DuckNet-Lite — ") and _u16(tip) <= 127, tip
    long_brand = "長い偽装名😀" * 40                  # 長いブランドでも状態の文言は欠けない
    t2, _ = G._status_view("audit", long_brand)
    assert _u16(t2) <= 127 and t2.endswith(tip[len("DuckNet-Lite"):]), t2


def test_audit_gauge_is_read_from_metrics():
    G = _G()
    cases = (
        (b"ducknet_shield_enabled 1\nducknet_shield_audit_mode 1\n", "audit"),
        (b"ducknet_shield_audit_mode 1\nducknet_shield_enabled 1\n", "audit"),   # 行の順序に依らない
        (b"ducknet_shield_enabled 1\nducknet_shield_audit_mode 0\n", "on"),
        (b"ducknet_shield_enabled 1\n", "on"),            # 指標を出さない旧い本体は従来どおり
        (b"ducknet_shield_enabled 0\nducknet_shield_audit_mode 1\n", "off"),     # 検査自体が止まっている
        (b"ducknet_shield_audit_mode 1\n", "unreachable"),  # 有効/無効が無い=本製品の応答ではない
    )
    for body, want in cases:
        with _stub(_ducknet_like("tok", metrics=body)) as (url, _seen):
            assert G._fetch_shield_state(url, "tok", timeout=2.0) == want, (body, want)


def test_poller_shows_audit_as_its_own_state():
    G = _G()
    stop = threading.Event()
    seq = iter(["on", "audit", "audit", "on", "audit"])
    shown = []

    def fetch():
        try:
            return next(seq)
        except StopIteration:
            stop.set()
            return shown[-1]
    G._poll_status(fetch, shown.append, stop, interval=0.001)
    assert shown == ["on", "audit", "on", "audit"], shown


def test_audit_mode_end_to_end_with_real_dashboard():
    """実際の本体で mode=audit にすると、トレイは監査モードと読む(/api/metrics の
    ducknet_shield_audit_mode を本体が出していること込み)。"""
    G = _G()
    with _dashboard("audit-token") as (_adm, url, sh):
        sh.enable()
        assert G._fetch_shield_state(url, "audit-token") == "on"
        r = sh.set_config(mode="audit")
        assert r.get("ok") and sh.cfg.get("mode") == "audit", r
        assert G._fetch_shield_state(url, "audit-token") == "audit"
        sh.set_config(mode="enforce")
        assert G._fetch_shield_state(url, "audit-token") == "on"
        sh.set_config(mode="audit")
        sh.disable()
        assert G._fetch_shield_state(url, "audit-token") == "off"   # 無効なら監査より OFF を出す
