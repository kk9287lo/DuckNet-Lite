"""
__main__.py — DuckNet-Lite: システムトレイ常駐(トレイのみ・依存ゼロ)
====================================================================================
`python -m dataplane tray` / `python -m dataplane.gui` で起動。タスクトレイに DuckNet.ico を
常駐させ、右クリックメニューから最小操作を提供する:
  · ダッシュボードを開く … 既定ブラウザで管理ダッシュボード(DUCKNET_ADMIN_URL)を開く
  · About              … 製品/版の情報(Win32 MessageBox)
  · 無料版でできること   … このエディションで使える機能一覧(上位版との差は README/❓ヘルプ参照)
  · 終了               … 本launcher が起動した本体を停止し、トレイを外してプロセス終了
防御の状態は 5 秒ごとに管理APIから読み、アイコン(ON=通常 / それ以外=淡色)とツールチップで示す
(「防御 ON」「防御 OFF」「ゲートウェイに接続できません」「状態を確認できません(トークン不一致)」)。
ON/OFF の切替そのものはダッシュボードで行う(トレイには持たせない)。
起動時、本体(ゲートウェイ)が未起動なら子プロセスとして一緒に立ち上げる(既に稼働中なら起動しない)。
backend/listen は env DUCKNET_BACKEND / DUCKNET_LISTEN で上書き可(既定 127.0.0.1:8080 / 8443)。
上位版のようなコントロールパネルは持たない(Lite=最小構成)。Windows 専用(他 OS はトレイ非対応の旨を表示)。
"""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import webbrowser
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import tray, ASSET_ICO, ASSET_ICO_OFF

# 接続先・表示名は main() の中で(app.env の取り込み後に)読む。import 時に固めていた頃は
# `python -m dataplane.gui` で app.env の DUCKNET_ADMIN_URL / DUCKNET_COVER が効かなかった。
def _admin_url() -> str:
    return os.environ.get("DUCKNET_ADMIN_URL", "http://127.0.0.1:8081")


def _brand() -> str:
    return os.environ.get("DUCKNET_COVER", "").strip() or "DuckNet-Lite"


_ABOUT_TEXT = (
    "{brand}\n\n"
    "軽量 L7 WAF / DDoS セキュリティゲートウェイ(無償エディション・AGPL)。\n"
    "外部依存ゼロ(Python 標準ライブラリのみ)・OS 非侵襲・防御専用。\n\n"
    "コアの L7 WAF/DDoS リバースプロキシと Web 管理ダッシュボードを提供します。\n"
    "詳細は README.md / docs、ダッシュボード右上の ❓ ヘルプを参照してください。"
)                                                  # {brand} は表示時に埋める

_CAPS_TEXT = (
    "無料版(DuckNet-Lite)でできること:\n\n"
    "・WAF: SQLi / XSS / RCE / パストラバーサル / XXE / SSRF / JNDI / スキャナー等の\n"
    "  シグネチャ照合、カスタムシグネチャ追加\n"
    "・L7 DDoS 防御: レート制限・脅威スコアリング・自動BAN(拒否/BAN の2段階)\n"
    "・双方向検査: リクエストボディ(POST/JSON/GraphQL・gzip/chunked 復号)+ 応答の\n"
    "  DLP・セキュリティヘッダ付与\n"
    "・認証/濫用対策: JWT 検査・クレデンシャル単位のレート制限\n"
    "・状態の整合性: BAN/設定の HMAC 署名による改竄耐性\n\n"
    "PoW チャレンジ・DNS フィルタ・SIEM 転送・自己完全性監視・watchdog・GeoIP・\n"
    "横展開デコイ・脅威インテリジェンス・分散BAN同期・ハニーポット等は上位版(DuckNet)で。"
)


def _asset_path(name: str) -> str:
    """アイコンの場所を解決: env DUCKNET_ICON_DIR → リポジトリ/カレントの ico/ → 同梱 assets/。"""
    here = os.path.dirname(__file__)
    repo_root = os.path.dirname(os.path.dirname(here))     # …/dataplane/gui → リポジトリ直下
    cands = []
    env = os.environ.get("DUCKNET_ICON_DIR", "").strip()
    if env:
        cands.append(os.path.join(env, name))
    for root in (repo_root, os.getcwd()):
        cands.append(os.path.join(root, "ico", name))
    bundled = os.path.join(here, "assets", name)
    cands.append(bundled)
    for p in cands:
        try:
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
    return bundled


def _status_icons():
    """(通常, 淡色) アイコンのパス。淡色版は通常版と *同じ場所* から探す: DUCKNET_ICON_DIR で
    独自のアイコン(偽装名運用など)に差し替えているのに、OFF の時だけ同梱の鴨が出ると製品が
    露見する。同じ場所に淡色版が無ければ通常アイコンのまま(状態はツールチップで分かる)。"""
    on = _asset_path(ASSET_ICO)
    off = os.path.join(os.path.dirname(on), ASSET_ICO_OFF)
    try:
        return on, (off if os.path.isfile(off) else on)
    except Exception:
        return on, on


# ── 防御状態の表示(トレイのアイコン/ツールチップ) ──────────────────────
STATE_ON, STATE_OFF, STATE_DOWN, STATE_AUTH = "on", "off", "unreachable", "auth"
_POLL_SEC = 5.0                    # 状態の再取得間隔(秒)。初回は起動直後に即時
_FETCH_TIMEOUT = 2.0
_METRICS_MAX = 64 * 1024           # 読む上限(ducknet_shield_enabled は先頭近くにある)
_STATUS_TEXT = {
    STATE_ON: "防御 ON / Protection ON",
    STATE_OFF: "防御 OFF(ダッシュボードで ON にできます)/ Protection OFF",
    STATE_DOWN: "ゲートウェイに接続できません / Gateway unreachable",
    STATE_AUTH: "状態を確認できません(管理トークン不一致)/ Status unknown (token mismatch)",
}


def _status_view(state: str, brand=None):
    """防御状態 → (ツールチップ, アイコン名)。ON だけ通常アイコン、それ以外(OFF・接続不可・
    トークン不一致)は淡色=「守られていない/守られているか分からない」を同じ見た目にまとめる。
    想定外の値は接続不可と同じ扱い(ON と誤表示しない)。ブランド名は DUCKNET_COVER に従い、
    長すぎる名前はブランド側を詰めて状態の文言を残す(szTip は 127 文字)。"""
    if state not in _STATUS_TEXT:
        state = STATE_DOWN
    b = _brand() if brand is None else brand
    return (tray.fit_tip(b, " — " + _STATUS_TEXT[state]),
            ASSET_ICO if state == STATE_ON else ASSET_ICO_OFF)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """リダイレクトに従わない(管理トークンを載せた要求を別の宛先へ持ち出させない。urllib の
    既定は X-Token ごと追従する)。3xx はそのまま HTTPError になり「接続できない」扱い。"""

    def redirect_request(self, *a, **kw):
        return None


def _parse_shield_enabled(body: bytes) -> str:
    """/api/metrics(plain-text の露出形式)から `ducknet_shield_enabled 1|0` を読む。
    見つからない・値が 0/1 でない応答は「接続できない」扱い(本製品の応答ではない)。"""
    for line in body.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "ducknet_shield_enabled":
            return {"1": STATE_ON, "0": STATE_OFF}.get(parts[1], STATE_DOWN)
    return STATE_DOWN


def _fetch_shield_state(base_url: str, token: str, timeout: float = _FETCH_TIMEOUT) -> str:
    """管理APIからシールドの有効状態を 1 回読む。戻り値は STATE_*(例外は出さない)。
    使うのは GET /api/metrics: 認証付きで shield_enabled を返す中で最も軽い(/api/state は
    イベント・上位送信元・BAN 一覧まで組み立てる)。プロキシは通さない(_admin_is_ours と同じ
    理由に加え、ここは X-Token を載せる=トークンがプロキシとそのログへ平文で渡る)。"""
    try:
        from ..engine.core.netaddr import url as _url
        host, port = _admin_addr(base_url)
        req = urllib.request.Request(_url(host, port, "/api/metrics"))
        if token:
            req.add_header("X-Token", token)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(req, timeout=timeout) as r:
            body = r.read(_METRICS_MAX)
    except urllib.error.HTTPError as e:
        try:
            e.close()
        except Exception:
            pass
        return STATE_AUTH if e.code == 401 else STATE_DOWN
    except Exception:
        return STATE_DOWN                         # 接続拒否・タイムアウト・URL 不正など
    if not token:
        return STATE_DOWN                         # 本製品は無認証に 200 を返さない=別物の待受
    return _parse_shield_enabled(body)


def _poll_status(fetch, show, stop, interval: float = _POLL_SEC) -> None:
    """fetch() で防御状態を取り、*変わった時だけ* show(state) を呼ぶ。初回は即時、以後 interval
    秒ごと、stop(threading.Event)が立ったら抜ける。fetch/show の例外ではループを止めない
    (fetch の例外は接続不可として表示し、show が失敗した状態は次の周回でもう一度表示する)。"""
    last = None
    while not stop.is_set():
        try:
            state = fetch()
        except Exception:
            state = STATE_DOWN
        if state not in _STATUS_TEXT:
            state = STATE_DOWN
        if state != last and not stop.is_set():  # 終了後に消えかけのトレイを触らない
            try:
                show(state)
                last = state
            except Exception:
                pass
        stop.wait(interval)


def _msgbox(text: str, title: str) -> None:
    """Win32 MessageBox(情報アイコン)。tkinter 非依存。失敗は無害。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x40)   # MB_ICONINFORMATION
    except Exception:
        pass


# ── 本体(ゲートウェイ)の自動起動 ──────────────────────────────────────
def _admin_addr(base_url: str):
    """管理APIの (host, port) を DUCKNET_ADMIN_URL から解く。"""
    try:
        u = urlparse(base_url if "://" in base_url else "http://" + base_url)
        return (u.hostname or "127.0.0.1", int(u.port or 8081))
    except ValueError:
        # urlparse(...).port は非数値/範囲外で ValueError を投げる。DUCKNET_ADMIN_URL の
        # 綴り間違いだけでトレイが例外死するのは割に合わないので既定へ落とす。
        return ("127.0.0.1", 8081)


def _gateway_up(host: str, port: int, timeout: float = 0.5) -> bool:
    """本体(前衛+管理API)が既にそのポートで待受けているか。"""
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def _spawn_gateway(admin_port: int, token: str, admin_host: str = "127.0.0.1"):
    """本体(ゲートウェイ)を子プロセスで起動する。コンソール窓は出さない。ローカル(127.0.0.1)
    からブラウザで開けば自動でトークン Cookie が発行される。失敗時は None。"""
    backend = os.environ.get("DUCKNET_BACKEND", "127.0.0.1:8080")
    listen = os.environ.get("DUCKNET_LISTEN", "8443")
    cmd = [sys.executable, "-m", "dataplane",
           "--backend", backend, "--listen", str(listen),
           "--admin", str(admin_port), "--admin-host", admin_host or "127.0.0.1"]
    # トークンは argv ではなく env で渡す: コマンドラインは他ユーザーから読める
    # (Linux の /proc/<pid>/cmdline は world-readable、Windows は WMI で取得可)。
    # env(/proc/<pid>/environ)は同一UID/root 限定=露出面が小さい。
    child_env = dict(os.environ)
    child_env["DUCKNET_ADMIN_TOKEN"] = token
    # 終了時は標準入力の 'stop' で graceful 停止を依頼する(_stop_child)。terminate() は
    # Windows では即死で、ドレインも BAN の flush も走らない。
    child_env["DUCKNET_STDIN_STOP"] = "1"
    kw = {"stdin": subprocess.PIPE, "env": child_env,
          "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if sys.platform.startswith("win"):
        kw["creationflags"] = 0x08000000 | 0x00000200   # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    try:
        return subprocess.Popen(cmd, **kw)
    except Exception:
        return None


def _admin_is_ours(host: str, port: int, timeout: float = 1.0) -> bool:
    """待受けているのが本製品の管理APIかを *トークンを送らずに* 確かめる。無認証の
    GET /api/state は 401 + {"ok": false, "error": "token required"} を返すので、これを指紋にする。
    別プロセスのポート占有を『本体が稼働中』と誤認し、起動を諦めたり秘密を渡したりしないため。"""
    from ..engine.core.netaddr import url as _url
    url = _url(host, port, "/api/state")           # IPv6 リテラルは [] で囲う
    # 既定の opener は環境変数のプロキシ設定(http_proxy 等)を拾う。ローカルの指紋確認が
    # プロキシ経由になると別物の応答を見て「本製品ではない」と誤判定し、ゲートウェイを
    # 起動できなくなる。ここは必ず直接続する。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as _r:
            _r.read(1)
        return False                              # 200=無認証で応答する別物(本製品は 401)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return False
        try:
            body = e.read(256)
        except Exception:
            return False
    except Exception:
        return False
    return b"token required" in body


def _ensure_gateway(base_url: str, token: str):
    """本体が起動していなければ起動する。戻り値 (token, child)。child は本launcher が起動した
    子プロセス(既に稼働中なら None=触らない)。起動時は管理APIが上がるまで最大 ~6 秒待つ。"""
    host, port = _admin_addr(base_url)
    if _gateway_up(host, port):
        if not _admin_is_ours(host, port):        # 別プロセスのポート占有を稼働中と誤認しない
            print("[警告] %s:%d は本製品以外のプロセスが使用しています。ゲートウェイを起動できず、"
                  "保護は動作していません。" % (host, port), file=sys.stderr)
            return "", None                       # 占有プロセスへトークンを渡さない
        return token, None
    tok = token or secrets.token_urlsafe(24)
    # 子の管理APIは、到達確認するのと同じ host で待受けさせる(http://[::1]:PORT なのに
    # 127.0.0.1 で起動すると永遠に見つけられない)。ループバック以外は従来どおり 127.0.0.1
    # =トレイの自動起動で管理画面をネットワークへ出さない。
    child = _spawn_gateway(port, tok, host if _is_loopback(host) else "127.0.0.1")
    if child is not None:
        try:
            for _ in range(30):
                if _gateway_up(host, port):
                    break
                time.sleep(0.2)
        except BaseException:                     # 待機中の Ctrl-C 等でも子を孤児にしない
            _stop_child(child)
            raise
    return tok, child


def _is_loopback(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address((host or "").strip("[]")).is_loopback
    except ValueError:
        return False


def _stop_wait() -> float:
    """graceful 停止を待つ上限秒数: 本体のドレイン猶予(DUCKNET_DRAIN_GRACE、既定 5)+後始末の余裕。"""
    try:
        grace = float(os.environ.get("DUCKNET_DRAIN_GRACE", "") or 5.0)
    except ValueError:
        grace = 5.0
    return max(0.0, min(grace, 120.0)) + 5.0


def _stop_child(child):
    """本launcher が起動した子プロセス(本体)を穏当に停止する。None/停止済みは無視。
    まず標準入力の 'stop' で graceful 停止(ドレイン→BAN の flush)を依頼し、上限時間内に
    終わらなければ terminate → kill へ落とす。"""
    if child is None:
        return
    pipe = getattr(child, "stdin", None)
    try:
        if child.poll() is not None:
            if pipe is not None:
                pipe.close()
            return
    except Exception:
        return
    asked = False
    if pipe is not None:
        try:
            pipe.write(b"stop\n")
            pipe.flush()
            asked = True
        except Exception:
            pass                                  # 既に終了している/パイプが壊れている
        try:
            pipe.close()
        except Exception:
            pass
    if asked:
        try:
            child.wait(timeout=_stop_wait())
            return
        except Exception:
            pass
    try:
        child.terminate()
        try:
            child.wait(timeout=3)
        except Exception:
            child.kill()
            child.wait(timeout=3)
    except Exception:
        pass


def main(argv=None) -> int:
    # GUI から起動したときも app.env を効かせる(以前はシェルのランチャだけが
    # 読んでおり、ダブルクリック起動では DUCKNET_BACKEND 等が黙って無視された)。
    from ..service import load_env_file, _force_utf8_stdio
    # `python -m dataplane.gui` は service.main() を通らないため、ここでも標準出力を
    # UTF-8 に寄せる。以前はこれが無く、非 UTF-8 コンソール(英語版 Windows の cp1252 等)
    # では下の日本語警告を出そうとした瞬間に UnicodeEncodeError で落ちていた ――
    # よりによって「別プロセスがポートを占有しており保護が動作していない」と
    # 伝えようとしている、いちばん落ちてはいけない場面で。
    _force_utf8_stdio()
    load_env_file()
    if not tray.available():
        print("トレイ常駐は Windows 専用です(他 OS では非対応)。"
              "Lite は CLI + Web ダッシュボードで運用してください。", file=sys.stderr)
        return 0

    admin_url, brand = _admin_url(), _brand()      # app.env の取り込み後に読む

    # 本体(ゲートウェイ)も一緒に起動: 管理APIが未待受なら子プロセスで起動する
    # (既に稼働中なら起動しない)。gw は終了時に停止する。
    _tok, gw = _ensure_gateway(admin_url, os.environ.get("DUCKNET_ADMIN_TOKEN", ""))

    stop = threading.Event()

    items = [("ダッシュボードを開く", "dash"), None,
             ("About", "about"),
             ("無料版でできること", "caps"), None,
             ("終了", "quit")]

    ti = None

    def _on_action(aid):
        if aid == "dash":
            try:
                webbrowser.open(admin_url)
            except Exception:
                pass
        elif aid == "about":
            _msgbox(_ABOUT_TEXT.format(brand=brand), "About — " + brand)
        elif aid == "caps":
            _msgbox(_CAPS_TEXT, brand)
        elif aid == "quit":
            try:
                if ti is not None:
                    ti.stop()
            finally:
                stop.set()

    try:
        on_ico, off_ico = _status_icons()
        ti = tray.TrayIcon(on_ico, brand, items, _on_action)
    except BaseException:                          # 構築失敗でも起動した本体を孤児にしない
        _stop_child(gw)
        raise
    if not ti.start():
        print("トレイの起動に失敗しました。", file=sys.stderr)
        _stop_child(gw)
        return 1

    # 防御状態の表示: 管理APIを定期的に読み、変わった時だけアイコン/ツールチップを替える。
    # トークンは本体の起動/確認に使ったもの(_ensure_gateway の戻り値)。表示の失敗で
    # トレイや本体を巻き込まない(ポーラは例外を外へ出さない・デーモン・終了で止まる)。
    def _show(state):
        tip, name = _status_view(state, brand)
        ti.set_status(tip, on_ico if name == ASSET_ICO else off_ico)

    try:
        threading.Thread(target=_poll_status,
                         args=(lambda: _fetch_shield_state(admin_url, _tok), _show, stop),
                         kwargs={"interval": _POLL_SEC},
                         daemon=True, name="tray-status").start()
    except Exception:
        pass
    try:
        stop.wait()                      # 終了が選ばれるまでメインスレッドを生かす
    except KeyboardInterrupt:
        ti.stop()
    finally:
        stop.set()                       # Ctrl-C で抜けた時も状態ポーラを止める
        _stop_child(gw)                  # 本launcher が起動した本体を停止(既存稼働は触らない)
    return 0


if __name__ == "__main__":
    sys.exit(main())
