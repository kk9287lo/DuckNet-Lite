"""
service.py — ChickenNet L7 Security スタンドアロン・サービス本体(CLI/起動エントリ)
====================================================================================
『あなたのWebサーバの手前にポン置きするだけで DDoS / WAF 防御が完了する』軽量プロキシ。
外部依存ゼロ(標準ライブラリのみ)・OS非侵襲・防御専用。

  [攻撃] → 前衛ガード(asyncio Fail-Fast: block/denyは即TCP切断, throttleは429応答)
         → あなたのバックエンド(WordPress等)
  管理ダッシュボード(Web GUI)で ON/OFF・指標・BAN・設定をクリック操作。

使い方:
  python -m dataplane --backend 127.0.0.1:8080 --listen 8443 --admin 8081
  (Docker: イメージをポン置き。詳細は README.md)
"""
from __future__ import annotations

import argparse
import sys


def _force_utf8_stdio() -> None:
    """標準出力/エラーを UTF-8 へ。Windows の cp932/cp1252 コンソールで
    ヘルプや起動メッセージ中の非ASCII文字(— や日本語)が
    UnicodeEncodeError でクラッシュするのを防ぐ。失敗しても無害に継続。"""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if reconfig is None:
            continue
        try:
            reconfig(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass

from dataplane.engine.services.proxy import AsyncEdgeGuard
from dataplane.engine.lifeform.policy import app_firewall
from dataplane.engine.lifeform.pipeline import net_shield
from .admin import AdminDashboard


def _install_shutdown_handlers(ev) -> list:
    """SIGTERM / SIGINT(+Windows の SIGBREAK)受信で `ev`(threading.Event)をセットする。
    張れたシグナル名のリストを返す。コンテナ/オーケストレータは停止に **SIGTERM** を送るので、
    これを拾わないと終了処理(状態の永続化・接続クローズ)が走らずプロセスが即死する。
    メインスレッド以外や未対応プラットフォームでは signal.signal が失敗するので握り潰す。"""
    import signal
    installed = []

    def _handler(_signum, _frame):
        ev.set()

    for sname in ("SIGTERM", "SIGINT", "SIGBREAK"):
        sig = getattr(signal, sname, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
            installed.append(sname)
        except (ValueError, OSError):
            pass   # メインスレッド以外 / 当該プラットフォーム非対応
    return installed


def _block_until_shutdown(*stop_fns, _event=None) -> None:
    """SIGTERM / SIGINT で graceful 停止するまでブロックし、停止時に `stop_fns` を順に呼ぶ。
    各 stop_fn は独立に try で囲む(片方が失敗してももう片方=状態 flush 等を必ず走らせる)。
    シグナルハンドラを張れなかった環境では KeyboardInterrupt を保険として拾う。
    `_event` はテスト専用の差し込み口(本番は None=内部 Event にシグナルを配線する)。"""
    import threading
    ev = _event if _event is not None else threading.Event()
    if _event is None:
        _install_shutdown_handlers(ev)
    try:
        while not ev.wait(1.0):   # タイムアウト付き待機=シグナル処理の機会を挟む(Win も即応)
            pass
    except KeyboardInterrupt:
        pass
    for fn in stop_fns:
        try:
            fn()
        except Exception:
            pass


def _install_sighup(reload_fn) -> bool:
    """POSIX で SIGHUP を『設定の無停止リロード』に割り当てる。Windows 等は SIGHUP が
    無いので何もしない(正直な degraded: その場合は設定反映にプロセス再起動が要る)。"""
    import signal
    if not hasattr(signal, "SIGHUP"):
        return False
    try:
        signal.signal(signal.SIGHUP, lambda *_: reload_fn())
        return True
    except Exception:
        return False


def run(backend: str = "127.0.0.1:8080", listen: int = 8443,
        admin_port: int = 8081, host: str = "0.0.0.0",
        admin_host: str = "127.0.0.1", token: str = "",
        defaults_on: bool = True, cluster: bool = False,
        health_path: str = "", drain_grace: float = 5.0,
        config_path: str = "") -> None:
    import os as _os
    bhost, _, bport = backend.partition(":")
    bport = int(bport or 80)

    # 製品の既定は『防御ON』(売り物なので最初から守る)。設定は永続化される。
    if defaults_on:
        app_firewall().enable()
        net_shield().enable()

    # 宣言的設定ブートストラップ(env CHICKENNET_CONFIG / --config): 運用者の JSON を起動時に適用。
    # k8s ConfigMap 等の immutable infra 向け(永続 state より後＝宣言ファイルが権威)。
    _cfg_path = config_path or _os.environ.get("CHICKENNET_CONFIG", "")
    if _cfg_path:
        _res = net_shield().apply_config_file(_cfg_path)
        if _res.get("ok"):
            print(f" 宣言的設定         : {_cfg_path} 適用 → {', '.join(_res.get('applied') or []) or '(変更なし)'}")
        else:
            print(f" 宣言的設定         : [警告] {_res.get('error')}")

    admin = AdminDashboard(host=admin_host, port=admin_port, token=token)
    a = admin.start()
    print("=" * 64)
    print(" ChickenNet L7 Security — セキュリティゲートウェイ 起動")
    print("=" * 64)
    print(f" 管理ダッシュボード : {a['url']}")
    print(f" 管理トークン       : {a['token']}")
    if admin_host not in ("127.0.0.1", "localhost", "::1"):
        print(f" [警告] 管理画面を非ループバック({admin_host})で待受中。トップページは"
              " トークンを認証なしで配布します=到達できる相手に管理権限が漏れます。")
        print("        ネットワークへ直接公開しないでください(SSHトンネル/リバースプロキシ/"
              "ホストの127.0.0.1へのみポート公開を推奨)。")
    print(f" 防御中(前衛)       : 0.0.0.0:{listen}  →  バックエンド {bhost}:{bport}")
    print("=" * 64)

    guard = AsyncEdgeGuard(backend_host=bhost or "127.0.0.1", backend_port=bport,
                           listen_host=host, listen_port=listen,
                           health_path=health_path)
    if cluster:
        res = guard.serve_cluster()
        if res.get("mode") == "single":
            print(f" [note] {res.get('reason')}")
    else:
        info = guard.start()
        if not info.get("ok"):
            raise SystemExit(f"前衛ガード起動失敗: {info.get('error')}")
    if drain_grace > 0:
        print(f" 停止時ドレイン     : 最大 {drain_grace:g}s(進行中リクエストを捌いてから停止)")
    # SIGTERM(コンテナ/k8s の停止シグナル)/ SIGINT で graceful 停止。
    # guard は drain_grace 秒だけ進行中リクエストを捌いてから停止(取りこぼし回避)。停止時に
    # WAF 状態(BAN/累犯回数)も flush=再起動越しのエスカレーション記憶を取りこぼさない。
    _block_until_shutdown(lambda: guard.stop(grace=drain_grace), admin.stop,
                          net_shield().flush_state)
    print("\nChickenNet L7 Security を停止しました。")


def _strip_autostart_flags(raw) -> list:
    """raw argv から自動起動関連フラグを取り除いた serve コマンドを返す(自動起動に登録する対象)。
    --install-autostart は省略可能な値(onlogon/onstart/runkey)を取り得るので消費を判定する。
    `--flag=value` 形式にも対応。"""
    out, i = [], 0
    valued = {"--autostart-name"}                 # 別トークンで値を取る
    skip_flags = {"--uninstall-autostart"}        # 値なし
    choices = {"onlogon", "onstart", "runkey"}
    while i < len(raw):
        x = raw[i]
        base = x.split("=", 1)[0]
        if base in skip_flags:
            i += 1; continue
        if base in valued:
            i += 1 if "=" in x else 2             # =形式は1トークン、別形式は値も飛ばす
            continue
        if base == "--install-autostart":
            i += 1
            if "=" not in x and i < len(raw) and raw[i] in choices:
                i += 1                            # 省略可能な値を消費(あれば)
            continue
        out.append(x); i += 1
    return out


def main(argv=None) -> int:
    _force_utf8_stdio()
    ap = argparse.ArgumentParser(
        prog="chickennet-security",
        description="ChickenNet L7 Security — 軽量 DDoS/WAF セキュリティゲートウェイ(L7・依存ゼロ)")
    ap.add_argument("--backend", default="127.0.0.1:8080",
                    help="守る対象(あなたのWebサーバ) HOST:PORT")
    ap.add_argument("--listen", type=int, default=8443, help="前衛ガードの待受ポート")
    ap.add_argument("--host", default="0.0.0.0", help="前衛ガードの待受ホスト")
    ap.add_argument("--admin", type=int, default=8081, help="管理ダッシュボードのポート")
    ap.add_argument("--admin-host", default="127.0.0.1",
                    help="管理ダッシュボードの待受(既定=localhost限定)")
    ap.add_argument("--token", default="", help="管理トークン(空=自動生成)")
    ap.add_argument("--cluster", action="store_true",
                    help="全コアで待受(Linux/macOS。Win等は単一へ降格)")
    ap.add_argument("--no-default-on", action="store_true",
                    help="起動時に防御を自動ONにしない")
    ap.add_argument("--health-path", default="", metavar="PATH",
                    help="死活監視用パス(例 /healthz)。一致リクエストは WAF/バックエンド非経由で"
                         "即200を返す。LB/オーケストレータ用。既定OFF(env CHICKENNET_HEALTH_PATH 可)")
    import os as _os
    ap.add_argument("--drain-grace", type=float, metavar="SEC",
                    default=float(_os.environ.get("CHICKENNET_DRAIN_GRACE", "5") or 0),
                    help="停止(SIGTERM/SIGINT)時に進行中リクエストを捌く最大秒数。"
                         "0=即時停止。既定5(env CHICKENNET_DRAIN_GRACE 可)")
    ap.add_argument("--config", default="", metavar="PATH",
                    help="起動時に適用する宣言的設定 JSON(WAFルール等)。k8s ConfigMap 等の"
                         "immutable infra 向け=永続 state より後に適用(env CHICKENNET_CONFIG 可)")
    ap.add_argument("--install-autostart", nargs="?", const="onlogon", default="",
                    metavar="TRIGGER", choices=["", "onlogon", "onstart", "runkey"],
                    help="起動時自動起動を *透明な公認の場所* に登録: Windows=タスクスケジューラ"
                         "(明示名・onlogon/onstart)or 標準 Run キー(runkey)、Linux=systemd、"
                         "mac=launchd。Autoruns/Task Scheduler/systemctl で可視。隠し永続化はしない。")
    ap.add_argument("--uninstall-autostart", action="store_true",
                    help="--install-autostart で登録した自動起動を解除する。")
    ap.add_argument("--autostart-name", default="ChickenNet", metavar="NAME",
                    help="自動起動エントリの表示名(既定 ChickenNet)。")
    a = ap.parse_args(argv)
    # 自動起動の登録/解除(#58): 透明な公認の場所のみ。登録したら即終了(常駐はしない)。
    if a.uninstall_autostart:
        from .engine.core.autostart import uninstall
        import json as _json
        m = "runkey" if a.install_autostart == "runkey" else "auto"
        print(_json.dumps(uninstall(method=m, name=a.autostart_name), ensure_ascii=False))
        return 0
    if a.install_autostart:
        from .engine.core.autostart import install
        import sys as _sys
        import json as _json
        raw = list(argv) if argv is not None else _sys.argv[1:]
        serve_args = _strip_autostart_flags(raw)      # 自動起動フラグを除いた serve コマンド
        method = "runkey" if a.install_autostart == "runkey" else "auto"
        trigger = a.install_autostart if a.install_autostart in ("onlogon", "onstart") else "onlogon"
        res = install(serve_args, method=method, name=a.autostart_name, trigger=trigger)
        print(_json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    run(backend=a.backend, listen=a.listen, admin_port=a.admin, host=a.host,
        admin_host=a.admin_host, token=a.token,
        defaults_on=not a.no_default_on, cluster=a.cluster,
        health_path=a.health_path, drain_grace=a.drain_grace,
        config_path=a.config)
    return 0
