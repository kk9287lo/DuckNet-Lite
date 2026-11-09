"""
test_sweep_lite_tray_status.py — トレイで「防御 ON / OFF / 接続不可」を見せる(Lite)
====================================================================================
以前のトレイは製品名だけの固定ツールチップで、シールドが OFF になっていても(既定は OFF)、
本体が落ちていても、ダッシュボードを開くまで気づけなかった。ここでは
  · 状態 → (ツールチップ, アイコン) の対応(ブランド名・DUCKNET_COVER・szTip 上限)
  · 状態ポーラ(変化した時だけ表示を更新・例外で止まらない・終了で止まる)
  · 実際の管理ダッシュボードに対する状態取得(ON/OFF/認証失敗/接続不可/壊れた応答/プロキシ非経由)
  · TrayIcon.set_status(起動前・非 Windows では値を保持するだけ/Windows 実機ではトレイの
    スレッドで適用される)
  · 淡色アイコン DuckNet-off.ico(正しい ICO+PNG・灰色・半透明・生成スクリプトで再現できる)
を確かめる。実トレイを出すのは Windows 専用の 1 件だけ(他 OS は SkipTest)。
"""
import contextlib
import http.server
import importlib.util
import json
import os
import secrets
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import zlib
from unittest import SkipTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIN = sys.platform.startswith("win")
ASSETS = os.path.join(ROOT, "dataplane", "gui", "assets")
OFF_ICO = os.path.join(ASSETS, "DuckNet-off.ico")
ON_ICO = os.path.join(ASSETS, "DuckNet.ico")


@contextlib.contextmanager
def _env(**kv):
    """環境変数を一時的に差し替える(None=削除)。抜けるときに必ず元へ戻す。"""
    saved = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


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


def _fetch_for_test(G, url, token, *, child=None, timeout=2.0):
    return G._fetch_shield_state(url, token, timeout=timeout, owned_child=child)


def _u16(s: str) -> int:
    """szTip(WCHAR 配列)で占める UTF-16 単位数。絵文字などは 2 単位。"""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _wait(pred, sec=5.0):
    end = time.monotonic() + sec
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


# ── 状態 → (ツールチップ, アイコン) ─────────────────────────────────────
def test_status_view_maps_each_state_to_tooltip_and_icon():
    G = _G()
    from dataplane.gui import ASSET_ICO, ASSET_ICO_OFF
    want = {
        "on": (("防御 ON", "Protection ON"), ASSET_ICO),
        "off": (("防御 OFF", "ダッシュボード", "Protection OFF"), ASSET_ICO_OFF),
        "unreachable": (("ゲートウェイに接続できません", "Gateway unreachable"), ASSET_ICO_OFF),
        "auth": (("トークン", "token"), ASSET_ICO_OFF),
    }
    seen = set()
    for state, (words, icon) in want.items():
        tip, got_icon = G._status_view(state, "DuckNet-Lite")
        assert tip.startswith("DuckNet-Lite — "), (state, tip)
        for w in words:
            assert w in tip, (state, w, tip)
        assert got_icon == icon, (state, got_icon)
        assert _u16(tip) <= 127, (state, _u16(tip))
        seen.add(tip)
    assert len(seen) == 4, seen                     # 4 状態は見分けられる
    # ON 以外の文言に「防御 ON」が紛れ込まない(OFF を ON と読み違えさせない)
    for state in ("off", "unreachable", "auth"):
        assert "防御 ON" not in G._status_view(state, "X")[0], state
    # 想定外の状態は「接続できない」と同じ扱い(ON と誤表示しない)
    tip, icon = G._status_view("???", "DuckNet-Lite")
    assert icon == ASSET_ICO_OFF and "Gateway unreachable" in tip, tip


def test_status_view_respects_cover_and_keeps_state_with_long_brand():
    G = _G()
    with _env(DUCKNET_COVER="Disk Indexer"):
        tip, _ = G._status_view("on")               # brand 省略=_brand()(DUCKNET_COVER)
    assert tip.startswith("Disk Indexer — "), tip
    assert "DuckNet" not in tip, tip                # 偽装名運用で製品名を出さない
    with _env(DUCKNET_COVER=None):
        tip, _ = G._status_view("off")
    assert tip.startswith("DuckNet-Lite — "), tip
    # 長いブランド名(絵文字=UTF-16 で 2 単位を含む)でも szTip に収まり、状態の文言は欠けない
    long_brand = "長い偽装名😀" * 40
    for state in ("on", "off", "unreachable", "auth"):
        tip, _ = G._status_view(state, long_brand)
        full, _ = G._status_view(state, "B")
        assert _u16(tip) <= 127, (state, _u16(tip))
        assert tip.endswith(full[len("B"):]), (state, tip)   # 「 — 防御 …」の部分は丸ごと残る
        tip.encode("utf-16-le")                     # 孤立サロゲート(絵文字の半分)を作らない


# ── 状態ポーラ ─────────────────────────────────────────────────────────
def _run_poller(G, seq, show, interval=0.001):
    """seq を順に返す fetch でポーラを回し、使い切ったら止める。返り値=スレッド。"""
    stop = threading.Event()
    it = iter(seq)

    def fetch():
        try:
            v = next(it)
        except StopIteration:
            stop.set()
            return "on" if not shown else shown[-1]
        if isinstance(v, BaseException):
            raise v
        return v
    shown = []

    def _show(st):
        shown.append(st)
        show(st)
    t = threading.Thread(target=G._poll_status, args=(fetch, _show, stop),
                         kwargs={"interval": interval}, daemon=True)
    t.start()
    t.join(10)
    assert not t.is_alive(), "poller did not stop"
    return shown


def test_poller_shows_only_changes():
    G = _G()
    shown = _run_poller(G, ["off", "off", "off", "on", "on", "unreachable",
                            "unreachable", "on", "auth", "auth"], lambda s: None)
    assert shown == ["off", "on", "unreachable", "on", "auth"], shown


def test_poller_survives_fetch_and_show_errors():
    G = _G()
    boom = {"n": 0}

    def show(st):
        if st == "on" and boom["n"] == 0:
            boom["n"] += 1
            raise OSError("tray gone")               # 表示側の一時的な失敗
    shown = _run_poller(G, ["off", RuntimeError("x"), ValueError("y"), "on", "on", "off"],
                        show)
    # fetch の例外は「接続不可」として表示し、ループは続く。show が失敗した "on" は次の周回で
    # もう一度表示する(失敗を「表示済み」と記録しない)。
    assert shown == ["off", "unreachable", "on", "on", "off"], shown


def test_poller_stops_promptly_when_asked():
    G = _G()
    stop = threading.Event()
    calls = []
    t = threading.Thread(target=G._poll_status,
                         args=(lambda: calls.append(1) or "on", lambda s: None, stop),
                         kwargs={"interval": 30.0}, daemon=True)
    t.start()
    assert _wait(lambda: calls, 3.0), "first poll must be immediate"
    t0 = time.monotonic()
    stop.set()
    t.join(3.0)
    assert not t.is_alive() and time.monotonic() - t0 < 2.0
    assert len(calls) == 1, calls                    # 30 秒待ちの途中で抜けた


def test_poller_does_not_show_after_stop():
    G = _G()
    stop = threading.Event()
    shown = []

    def fetch():
        stop.set()                                   # 取得中に終了が選ばれた
        return "off"
    G._poll_status(fetch, shown.append, stop, interval=0.001)
    assert shown == [], shown                        # 消えかけのトレイを触らない


# ── Real state proof and untrusted listeners ────────────────────────────
def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def _dashboard():
    import dataplane.engine.lifeform.policy as FW
    import dataplane.engine.lifeform.pipeline as ND
    from dataplane.admin import AdminDashboard
    tmp = tempfile.mkdtemp(prefix="ducknet-tray-status-")
    old_fw, old_sh = FW._FW, ND._SHIELD
    key = secrets.token_hex(32)
    adm = None
    try:
        with _env(DUCKNET_STATE_DIR=tmp, DUCKNET_TRAY_PROOF_KEY=key):
            FW._FW = FW.AppFirewall(state_dir=tmp)
            ND._SHIELD = ND.NetShield(state_dir=tmp)
            adm = AdminDashboard(host="127.0.0.1", port=0,
                                 token="tray-test-token", state_dir=tmp)
            info = adm.start()

            class Child:
                _ducknet_tray_proof_key = key

                def poll(self):
                    return None

            yield info["url"], ND._SHIELD, Child()
    finally:
        if adm is not None:
            adm.stop()
        FW._FW, ND._SHIELD = old_fw, old_sh
        shutil.rmtree(tmp, True)


def test_fetch_reads_signed_state_from_real_dashboard_without_token():
    G = _G()
    with _dashboard() as (url, sh, child):
        assert sh.disable()["ok"]
        assert _fetch_for_test(G, url, "secret", child=child) == "off"
        assert sh.enable()["ok"]
        assert _fetch_for_test(G, url, "wrong", child=child) == "on"
        assert sh.set_config(mode="audit")["ok"]
        assert _fetch_for_test(G, url, "", child=child) == "audit"
        assert _fetch_for_test(G, url, "secret") == "auth"


def test_fetch_never_routes_through_a_system_proxy():
    G = _G()
    dead = "http://127.0.0.1:%d" % _free_port()
    with _dashboard() as (url, sh, child):
        assert sh.enable()["ok"]
        with _env(http_proxy=dead, HTTP_PROXY=dead, no_proxy=None, NO_PROXY=None):
            assert _fetch_for_test(G, url, "secret", child=child) == "on"


def test_unreachable_and_fake_listener_never_receives_token():
    G = _G()
    class Child:
        _ducknet_tray_proof_key = secrets.token_hex(32)

        def poll(self):
            return None

    child = Child()
    assert _fetch_for_test(G, "http://127.0.0.1:%d" % _free_port(),
                           "secret", child=child, timeout=0.5) == "unreachable"
    seen = []

    class Fake(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("X-Token")))
            body = b'{"ok":false,"error":"token required"}'
            self.send_response(401)
            self.send_header("X-DuckNet-Tray-Proof", "0" * 64)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = "http://127.0.0.1:%d" % server.server_port
        assert _fetch_for_test(G, url, "secret", child=child) == "unreachable"
        assert seen and all(token is None for _path, token in seen)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


# ── main() がポーラを配線する ──────────────────────────────────────────
def test_main_polls_and_shows_state_until_quit():
    G = _G()
    rec = {"status": [], "fetch": []}
    started = threading.Event()

    class _Tray:
        def __init__(self, icon, tip, items, cb):
            rec["icon"], rec["tip"], rec["cb"] = icon, tip, cb

        def start(self):
            return True

        def set_status(self, tip, icon_path=None):
            rec["status"].append((tip, icon_path))
            started.set()

        def stop(self):
            rec["stopped"] = True

    def _fetch(url, tok, timeout=2.0, *, owned_child=None):
        rec["fetch"].append((url, tok))
        return "off"
    out = {}
    class _Child:
        exited = False

        def poll(self):
            return 0 if self.exited else None

        def terminate(self):
            self.exited = True

        def wait(self, timeout=None):
            self.exited = True
            return 0

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "none.env"), "w", encoding="utf-8"):
            pass
        with _env(DUCKNET_ENV_FILE=os.path.join(d, "none.env"), DUCKNET_COVER="Disk Indexer",
                  DUCKNET_ADMIN_URL="http://127.0.0.1:18097", DUCKNET_ICON_DIR=None), \
                _patched(G.tray, available=lambda: True, TrayIcon=_Tray), \
                _patched(G, _ensure_gateway=lambda url, tok: ("tok-1", _Child()),
                         _fetch_shield_state=_fetch, _POLL_SEC=0.01):
            th = threading.Thread(target=lambda: out.setdefault("rc", G.main([])), daemon=True)
            th.start()
            try:
                assert started.wait(5), "poller never showed a state"
                assert _wait(lambda: len(rec["fetch"]) >= 5, 5.0), rec["fetch"]
            finally:
                if "cb" in rec:
                    rec["cb"]("quit")                # トレイの「終了」
                th.join(10)
    assert not th.is_alive() and out.get("rc") == 0, out
    assert rec["fetch"][0] == ("http://127.0.0.1:18097", "tok-1"), rec["fetch"]
    tip, icon = rec["status"][0]
    assert tip.startswith("Disk Indexer — ") and "防御 OFF" in tip, tip
    assert os.path.basename(icon) == "DuckNet-off.ico", icon
    assert os.path.basename(rec["icon"]) == "DuckNet-off.ico", rec["icon"]
    assert "状態を確認できません" in rec["tip"], rec["tip"]
    assert len(rec["status"]) == 1, rec["status"]    # 変化が無ければ再表示しない
    # 終了でポーラも止まる(デーモンでも残り続けない)
    assert _wait(lambda: not any(t.name == "tray-status" and t.is_alive()
                                 for t in threading.enumerate()), 3.0)


def test_status_icons_follow_the_icon_directory():
    """淡色版は通常アイコンと同じ場所から探す。独自アイコン(偽装名運用など)へ差し替えた場所に
    淡色版が無いなら、同梱の鴨を出さずに通常アイコンのまま(状態はツールチップで分かる)。"""
    G = _G()
    with _env(DUCKNET_ICON_DIR=None):
        on, off = G._status_icons()
    assert os.path.basename(on) == "DuckNet.ico" and os.path.isfile(on), on
    assert os.path.basename(off) == "DuckNet-off.ico" and os.path.isfile(off), off
    assert os.path.dirname(on) == os.path.dirname(off)
    with tempfile.TemporaryDirectory() as d:
        shutil.copyfile(ON_ICO, os.path.join(d, "DuckNet.ico"))
        with _env(DUCKNET_ICON_DIR=d):
            on, off = G._status_icons()
            assert on == os.path.join(d, "DuckNet.ico") and off == on, (on, off)
            shutil.copyfile(OFF_ICO, os.path.join(d, "DuckNet-off.ico"))
            on, off = G._status_icons()
            assert off == os.path.join(d, "DuckNet-off.ico"), off


# ── TrayIcon.set_status(Win32 を起動しない) ─────────────────────────
def test_set_status_before_start_records_latest_values():
    from dataplane.gui import tray
    t = tray.TrayIcon("on.ico", "brand", [("Open", "open")], lambda a: None)
    t.set_status("A — 防御 OFF", "off.ico")
    t.set_status("A — 防御 ON")                     # アイコン省略=据え置き
    assert t.tooltip == "A — 防御 ON" and t.icon_path == "off.ico", (t.tooltip, t.icon_path)
    assert t._hwnd is None
    t.set_status("x" * 500)
    assert t.tooltip == "x" * 127                   # szTip は 127 文字+NUL
    t.set_status("a" * 126 + "😀")                   # 絵文字(2 単位)は入り切らない=割らずに落とす
    assert t.tooltip == "a" * 126, len(t.tooltip)
    t2 = tray.TrayIcon("on.ico", "長い" * 100, [], lambda a: None)
    assert _u16(t2.tooltip) <= 127                  # 生成時のツールチップも同じ上限


def test_set_status_on_non_windows_is_a_harmless_noop():
    from dataplane.gui import tray
    with _patched(tray, available=lambda: False):
        t = tray.TrayIcon("on.ico", "brand", [], lambda a: None)
        t._hwnd = 12345                             # 仮に窓があっても Win32 を呼ばない
        t.set_status("B — 防御 OFF", "off.ico")
        assert (t.tooltip, t.icon_path) == ("B — 防御 OFF", "off.ico")
        assert t.start() is False


# ── 淡色アイコン(DuckNet-off.ico) ─────────────────────────────────────
def _png_rgba(png: bytes):
    """テスト側の独立した最小 PNG デコーダ(8bit RGBA・非インターレース・CRC 検証つき)。"""
    assert png[:8] == b"\x89PNG\r\n\x1a\n", png[:8]
    pos, idat, ihdr = 8, b"", None
    while pos < len(png):
        n, typ = struct.unpack(">I4s", png[pos:pos + 8])
        body = png[pos + 8:pos + 8 + n]
        (crc,) = struct.unpack(">I", png[pos + 8 + n:pos + 12 + n])
        assert zlib.crc32(typ + body) & 0xFFFFFFFF == crc, typ
        if typ == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif typ == b"IDAT":
            idat += body
        elif typ == b"IEND":
            break
        pos += 12 + n
    w, h, depth, ctype, _comp, _filt, inter = ihdr
    assert (depth, ctype, inter) == (8, 6, 0), ihdr
    raw = zlib.decompress(idat)
    stride = w * 4
    assert len(raw) == h * (stride + 1)
    out = bytearray()
    prev = bytearray(stride)
    for y in range(h):
        base = y * (stride + 1)
        f = raw[base]
        line = bytearray(raw[base + 1:base + 1 + stride])
        for i in range(stride):
            a = line[i - 4] if i >= 4 else 0
            b = prev[i]
            c = prev[i - 4] if i >= 4 else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + b) & 255
            elif f == 3:
                line[i] = (line[i] + ((a + b) >> 1)) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
            else:
                assert f == 0, f
        out += line
        prev = line
    return w, h, bytes(out)


def _ico_single_png(data: bytes):
    """ICO(1 エントリ・PNG 格納)を検証して (幅バイト, 高さバイト, PNG) を返す。"""
    reserved, typ, count = struct.unpack("<HHH", data[:6])
    assert (reserved, typ, count) == (0, 1, 1), (reserved, typ, count)
    w, h, colors, res, planes, bpp, size, off = struct.unpack("<BBBBHHII", data[6:22])
    assert (colors, res, planes, bpp) == (0, 0, 1, 32), (colors, res, planes, bpp)
    assert off == 22 and off + size == len(data), (off, size, len(data))
    return w, h, data[off:off + size]


def _largest_png_in_ico(data: bytes) -> bytes:
    (count,) = struct.unpack("<H", data[4:6])
    best = None
    for k in range(count):
        w, h, _c, _r, _p, _b, size, off = struct.unpack("<BBBBHHII", data[6 + 16 * k:22 + 16 * k])
        png = data[off:off + size]
        if png[:8] == b"\x89PNG\r\n\x1a\n" and (best is None or size > len(best)):
            best = png
    assert best is not None
    return best


def test_off_icon_is_a_valid_gray_translucent_ico():
    with open(OFF_ICO, "rb") as f:
        data = f.read()
    wb, hb, png = _ico_single_png(data)
    w, h, px = _png_rgba(png)
    with open(ON_ICO, "rb") as f:
        sw, sh, src = _png_rgba(_largest_png_in_ico(f.read()))
    assert (w, h) == (sw, sh), ((w, h), (sw, sh))   # 通常アイコンと同じ寸法
    assert (wb, hb) == (w % 256, h % 256)            # ICO の 0 = 256px
    visible = 0
    for i in range(0, len(px), 4):
        r, g, b, a = px[i:i + 4]
        assert r == g == b, (i // 4, r, g, b)        # 灰色
        sa = src[i + 3]
        assert a <= sa, (i // 4, a, sa)              # どの画素も元より不透明にならない
        if sa == 0:
            assert a == 0
        visible += a > 0
    assert visible > (w * h) // 10, visible          # 空のアイコンではない
    assert sum(px[3::4]) <= 0.6 * sum(src[3::4])    # 全体として明らかに淡い
    assert max(px[3::4]) <= 160, max(px[3::4])
    # リポジトリ直下の ico/ にも同じもの(ソースツリーからの起動は ico/ を先に見る)
    with open(os.path.join(ROOT, "ico", "DuckNet-off.ico"), "rb") as f:
        assert f.read() == data


def _tool():
    p = os.path.join(ROOT, "tools", "make_tray_icons.py")
    spec = importlib.util.spec_from_file_location("make_tray_icons_under_test", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _png_chunks(png: bytes):
    pos, out = 8, []
    while pos < len(png):
        n, typ = struct.unpack(">I4s", png[pos:pos + 8])
        out.append((typ, png[pos + 8:pos + 8 + n]))
        pos += 12 + n
    return out


def test_make_tray_icons_regenerates_the_committed_icon():
    tool = _tool()
    assert tool.__doc__ and "make_tray_icons.py" in tool.__doc__   # 再生成の手順が書いてある
    built = tool.build(ON_ICO)
    with open(OFF_ICO, "rb") as f:
        committed = f.read()
    if built != committed:
        # 同じ画素でも、zlib の実装違い(zlib-ng 等)では圧縮バイト列だけが変わり得る。この
        # 環境の zlib が既存の IDAT を再現できるなら、差は生成手順の差=失敗。再現できない
        # 環境では、圧縮前のデータと IDAT 以外の構造が一致することを確かめる。
        cb = _png_chunks(_ico_single_png(committed)[2])
        bb = _png_chunks(_ico_single_png(built)[2])
        c_idat = b"".join(b for t, b in cb if t == b"IDAT")
        raw = zlib.decompress(c_idat)
        assert zlib.compress(raw, 9) != c_idat, "same zlib, different bytes: generator drifted"
        assert raw == zlib.decompress(b"".join(b for t, b in bb if t == b"IDAT"))
        assert [c for c in cb if c[0] != b"IDAT"] == [c for c in bb if c[0] != b"IDAT"]
        assert committed[:6] == built[:6] and committed[6:14] == built[6:14]
    # --check は書き込まずに一致を確かめる(終了コード 0)
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        assert tool.main(["--check"]) == 0


def test_off_icon_is_packaged():
    """配布物(wheel/sdist)に淡色アイコンが入る: package-data の glob に掛かること。"""
    import fnmatch
    import re
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r'(?m)^"dataplane\.gui"\s*=\s*\[([^\]]*)\]', text)
    assert m, "dataplane.gui package-data not found"
    globs = re.findall(r'"([^"]+)"', m.group(1))
    assert any(fnmatch.fnmatch("assets/DuckNet-off.ico", g) for g in globs), globs


# ── Windows 実機: 本物のトレイで set_status が窓プロシージャから適用される ──
def test_real_tray_applies_status_on_the_tray_thread():
    if not WIN:
        raise SkipTest("Win32 トレイの実起動テスト(Windows 専用)")
    from dataplane.gui import tray
    G = _G()
    with _env(DUCKNET_ICON_DIR=None):
        on, off = G._status_icons()
    tip_off, _ = G._status_view("off", "DuckNet test")
    tip_on, _ = G._status_view("on", "DuckNet test")
    t = tray.TrayIcon(on, "DuckNet test", [("Open", "open")], lambda a: None)
    t.set_status(tip_off, off)                       # 起動前の値は追加時(NIM_ADD)に反映される
    if not t.start():
        raise SkipTest("トレイを起動できない")
    try:
        assert _wait(lambda: t._nid is not None, 5.0), "tray window not created"
        if not t._added:
            raise SkipTest("通知領域が無いセッション(Shell_NotifyIcon NIM_ADD 失敗)")
        assert (t._applied_tip, t._applied_icon) == (tip_off, off), (t._applied_tip,
                                                                     t._applied_icon)
        t.set_status(tip_on, on)                     # 別スレッド(このテスト)から依頼
        assert _wait(lambda: t._applied_tip == tip_on, 5.0), t._applied_tip
        assert t._applied_icon == on
        assert t._status_error is None, t._status_error
        assert t._apply_thread == t._thread.ident    # Win32 はトレイのスレッドでだけ触る
        t.set_status(tip_on, on)                     # 変化なし=何もしない(エラーも出ない)
        t.set_status(tip_off + "!", None)            # ツールチップだけの変更
        assert _wait(lambda: t._applied_tip == tip_off + "!", 5.0)
        assert t._applied_icon == on and t._status_error is None
        tip_auth, _ = G._status_view("auth", "DuckNet test")
        assert _u16(tip_auth) > 63                   # 旧 V1 の szTip(64)には収まらない長さ
        t.set_status(tip_auth, off)
        assert _wait(lambda: t._applied_tip == tip_auth, 5.0), t._status_error
        assert t._applied_icon == off and t._status_error is None
    finally:
        t.stop()
        if t._thread:
            t._thread.join(3.0)
    assert not t._thread.is_alive()
