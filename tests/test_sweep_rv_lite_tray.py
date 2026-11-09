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


@contextlib.contextmanager
def _env(**values):
    saved = {key: os.environ.get(key) for key in values}
    try:
        for key, value in values.items():
            os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


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


# ── Proof-only polling against foreign listeners ─────────────────────
def test_foreign_or_forged_response_never_receives_token():
    G = _G()
    class Child:
        _ducknet_tray_proof_key = "00" * 32
        def poll(self):
            return None
    for answer in (_foreign_401, _plain_200,
                   lambda _h: (401, [("X-DuckNet-Tray-Proof", "0" * 64)], ADMIN_401)):
        with _stub(answer) as (url, seen):
            assert G._fetch_shield_state(url, "secret", owned_child=Child()) == G.STATE_DOWN
            assert seen and all(token is None for _path, token in seen)


def test_redirect_never_reaches_target_or_discloses_token():
    G = _G()
    class Child:
        _ducknet_tray_proof_key = "00" * 32
        def poll(self):
            return None
    with _stub(_plain_200) as (target, target_seen):
        with _stub(lambda _h: (302, [("Location", target + "/steal")], b"")) as (url, seen):
            assert G._fetch_shield_state(url, "secret", owned_child=Child()) == G.STATE_DOWN
            assert seen == [("/api/state", None)]
    assert target_seen == []


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
    G = _G()
    import dataplane.engine.lifeform.policy as FW
    import dataplane.engine.lifeform.pipeline as ND
    from dataplane.admin import AdminDashboard
    import secrets
    key = secrets.token_hex(32)
    with tempfile.TemporaryDirectory() as tmp, _env(DUCKNET_TRAY_PROOF_KEY=key):
        old_fw, old_sh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=tmp)
        ND._SHIELD = ND.NetShield(state_dir=tmp)
        admin = AdminDashboard(host="127.0.0.1", port=0, token="audit-token", state_dir=tmp)
        info = admin.start()
        class Child:
            _ducknet_tray_proof_key = key
            def poll(self):
                return None
        try:
            url, sh = info["url"], ND._SHIELD
            assert sh.enable()["ok"]
            assert G._fetch_shield_state(url, "wrong", owned_child=Child()) == G.STATE_ON
            assert sh.set_config(mode="audit")["ok"]
            assert G._fetch_shield_state(url, "", owned_child=Child()) == G.STATE_AUDIT
            assert sh.disable()["ok"]
            assert G._fetch_shield_state(url, "secret", owned_child=Child()) == G.STATE_OFF
        finally:
            admin.stop()
            FW._FW, ND._SHIELD = old_fw, old_sh
