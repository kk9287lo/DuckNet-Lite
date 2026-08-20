"""
service.py — ChickenNet L7 Security スタンドアロン・サービス本体(CLI/起動エントリ)
====================================================================================
『あなたのWebサーバの手前にポン置きするだけで DDoS / WAF 防御が完了する』軽量プロキシ。
外部依存ゼロ(標準ライブラリのみ)・OS非侵襲・防御専用。

  [攻撃] → 前衛ガード(asyncio Fail-Fast: block/denyは即TCP切断, challengeはPoW)
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


def _siem_status_line() -> str:
    """SIEM/Webhook 転送が有効か(env 設定の有無)を起動バナー用に1行で返す。"""
    from dataplane.engine.lifeform.forwarders import default_fanout
    return ("有効(検知を外部へ転送)" if default_fanout().active
            else "無効(CHICKENNET_SYSLOG / CHICKENNET_WEBHOOK 未設定)")


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
        stealth: str = "", health_path: str = "", drain_grace: float = 5.0,
        config_path: str = "") -> None:
    import os as _os
    bhost, _, bport = backend.partition(":")
    bport = int(bport or 80)

    # ステルス運用: プロセス名/タイトルを汎用名へ偽装し、状態ファイルの場所を伏せ、
    # 管理画面の表示名/Server も差し替える(=侵入者にこちらの手の内を見せない)。
    # singleton(app_firewall/net_shield)生成より前に状態dirを移すのが肝。
    cover = ""
    if stealth:
        from . import profile as _st
        cover = stealth.strip() or _st.DEFAULT_COVER
        _st.apply(cover)
        _os.environ.setdefault(
            "CHICKENNET_STATE_DIR",
            _os.path.join(_os.path.expanduser("~"), ".syshealthd"))
        # 遮断ページ等が参照する表示名も伏せる(WAF応答からブランドを露見させない)。
        _os.environ["CHICKENNET_COVER"] = cover

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

    if cover:                                  # ステルス: 画面の表示名を汎用名へ
        admin = AdminDashboard(host=admin_host, port=admin_port, token=token,
                               brand=cover, logo="⚙",
                               subtitle="ステータス")
    else:
        admin = AdminDashboard(host=admin_host, port=admin_port, token=token)
    a = admin.start()
    _title = cover if cover else "ChickenNet L7 Security — セキュリティゲートウェイ 起動"
    print("=" * 64)
    print(f" {_title}")
    print("=" * 64)
    print(f" {'管理コンソール' if cover else '管理ダッシュボード'} : {a['url']}")
    print(f" {'アクセスキー' if cover else '管理トークン'}       : {a['token']}")
    if admin_host not in ("127.0.0.1", "localhost", "::1"):
        print(f" [警告] 管理画面を非ループバック({admin_host})で待受中。トップページは"
              " トークンを認証なしで配布します=到達できる相手に管理権限が漏れます。")
        print("        ネットワークへ直接公開しないでください(SSHトンネル/リバースプロキシ/"
              "ホストの127.0.0.1へのみポート公開を推奨)。")
    if cover:                                  # ステルス: 役割を伏せた最小限の表示のみ
        print(f" サービス           : 0.0.0.0:{listen}")
        print("=" * 64)
    else:
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
    print(f"\n{cover or 'ChickenNet L7 Security'} を停止しました。")


def _dns_cli(argv) -> int:
    """`chickennet-security dns ...` — DNSフィルタ(L7検知つき)を単独で起動する。

    宛先IP/ポートではなく『問い合わせの中身と発信元の振る舞い』を見て、
    トンネリング/C2/内部偵察(AD)の兆候を検知する。OS非侵襲(本機はDNSサーバを
    立てるだけ。端末/ルータの参照先を本機へ向けて使う)。既定は監査=止めず可視化。"""
    from dataplane.engine.lifeform.dns import DnsFilter
    ap = argparse.ArgumentParser(
        prog="chickennet-security dns",
        description="DNSフィルタ + L7検知(トンネリング/C2/AD偵察。OS非侵襲・依存ゼロ)")
    ap.add_argument("--listen", type=int, default=5335, help="待受ポート(既定5335)")
    ap.add_argument("--host", default="127.0.0.1", help="待受ホスト")
    ap.add_argument("--upstream", default="1.1.1.1:53",
                    help="許可クエリの転送先リゾルバ HOST:PORT")
    ap.add_argument("--mode", choices=["nxdomain", "sinkhole"], default="nxdomain",
                    help="遮断時の応答方式")
    ap.add_argument("--sinkhole-ip", default="0.0.0.0", help="sinkhole時のA応答IP")
    ap.add_argument("--block", action="append", default=[],
                    help="明示ブロックするドメイン(複数指定可)")
    ap.add_argument("--allow", action="append", default=[], metavar="CIDR",
                    help="L7検知を免除する送信元 IP/CIDR(信頼スキャナ/監視。複数可)")
    ap.add_argument("--enforce", action="store_true",
                    help="L7検知で『悪性』判定を遮断(既定は監査=止めず可視化)")
    ap.add_argument("--no-heuristics", action="store_true",
                    help="L7ヒューリスティック検知を無効化(明示ブロックリストのみ)")
    ap.add_argument("--recon", choices=["alert", "off"], default="alert",
                    help="AD偵察(SRV)の扱い: alert=可視化(既定) / off=無視(AD前段の騒音回避)")
    ap.add_argument("--dedup-window", type=float, default=60.0, metavar="SEC",
                    help="同一通知の連打を集約する窓(秒)。0で無効(既定60)")
    a = ap.parse_args(argv)
    uhost, _, uport = a.upstream.partition(":")

    f = DnsFilter(host=a.host, port=a.listen, upstream=uhost or "1.1.1.1",
                  upstream_port=int(uport or 53), mode=a.mode,
                  sinkhole_ip=a.sinkhole_ip)
    for dom in a.block:
        f.add_block(dom)
    for cidr in a.allow:
        r = f.add_allow(cidr)
        if not r.get("ok"):
            print(f" [warn] --allow 無視: {r.get('error')}")
    f.set_heuristics(enabled=not a.no_heuristics, audit=not a.enforce)
    f.set_detection(recon_mode=("ignore" if a.recon == "off" else "alert"),
                    dedup_window=a.dedup_window)
    info = f.start()
    if not info.get("ok"):
        raise SystemExit(f"DNSフィルタ起動失敗: {info.get('error')}")
    st = f.status()
    print("=" * 64)
    print(" ChickenNet L7 Security — DNSフィルタ + L7検知 起動")
    print("=" * 64)
    print(f" 待受           : {info['listen']}  →  上流 {info['upstream']}")
    print(f" SIEM転送       : {_siem_status_line()}")
    print(f" L7検知         : {'有効' if st['heuristics'] else '無効'}"
          + ("(監査=止めず可視化)" if st["heuristics_audit"] else "(強制=悪性は遮断)"))
    _recon = "可視化(alert)" if st["recon_mode"] == "alert" else "無視(off)"
    _dedup = f"{st['dedup_window']:.0f}s" if st["dedup_window"] > 0 else "無効"
    print(f" AD偵察(SRV)    : {_recon}   通知集約: {_dedup}")
    print(f" 明示ブロック   : {len(st['blocklist'])} 件")
    if st.get("allowlist"):
        print(f" 検知免除(allow): {', '.join(st['allowlist'])}")
    print(" 注記           : OSのDNS設定は変更しません(非侵襲)。参照先を本機へ向けて使用。")
    print("=" * 64)
    _block_until_shutdown(f.stop)          # SIGTERM / SIGINT で graceful 停止
    print("\nDNSフィルタを停止しました。")
    return 0


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
    args = sys.argv[1:] if argv is None else list(argv)
    # サブコマンド分岐(既定はゲートウェイ=後方互換)。
    if args and args[0] == "dns":
        return _dns_cli(args[1:])
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
    ap.add_argument("--stealth", nargs="?", const="System Health Monitor", default="",
                    metavar="NAME",
                    help="ステルス運用(防御専用の低プロファイル化): 自プロセス名/コンソール"
                         "タイトル/管理画面/Serverヘッダ/状態dirを汎用名へ偽装し、侵入者から"
                         "『これは防御ツール』と特定されにくくする。NAME で偽装名を指定"
                         "(既定: System Health Monitor)。※OS非侵襲・rootkitではない")
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
    ap.add_argument("--supervise", action="store_true",
                    help="親プロセス監督下で起動(可視・正規=systemd Restart 相当): 子サービスが"
                         "クラッシュしたら自動再起動。指数バックオフ+クラッシュループ遮断。停止は"
                         "SIGTERM/Ctrl-C で子ごと終了(終了は妨害しない)。")
    ap.add_argument("--install-autostart", nargs="?", const="onlogon", default="",
                    metavar="TRIGGER", choices=["", "onlogon", "onstart", "runkey"],
                    help="起動時自動起動を *透明な公認の場所* に登録: Windows=タスクスケジューラ"
                         "(明示名・onlogon/onstart)or 標準 Run キー(runkey)、Linux=systemd、"
                         "mac=launchd。Autoruns/Task Scheduler/systemctl で可視。隠し永続化はしない。")
    ap.add_argument("--uninstall-autostart", action="store_true",
                    help="--install-autostart で登録した自動起動を解除する。")
    ap.add_argument("--integrity-baseline", action="store_true",
                    help="現在のコード/不変ファイルを『既知良好』として完全性ベースラインに固定し"
                         "終了する。**deploy 直後に実行**=初回起動 TOFU(既に改竄済みなら改竄版を"
                         "正としてしまう)の代わりに、信頼できる時点で基準化する。")
    ap.add_argument("--integrity-check", action="store_true",
                    help="完全性ベースラインに対して現状を検査し結果を表示して終了する"
                         "(改竄/欠落の有無・マニフェスト署名の妥当性)。")
    ap.add_argument("--autostart-name", default="ChickenNet", metavar="NAME",
                    help="自動起動エントリの表示名(既定 ChickenNet。ステルス時は保守名でも可)。")
    a = ap.parse_args(argv)
    # 完全性ベースライン/検査(#59): deploy 時に既知良好を固定 → 初回起動 TOFU を回避。即終了。
    if a.integrity_baseline or a.integrity_check:
        from .engine.core.integrity import SelfIntegrity
        from .engine.core.atomic_io import default_state_dir
        import json as _json
        si = SelfIntegrity(default_state_dir())
        out = si.mon.baseline() if a.integrity_baseline else si.mon.check()
        print(_json.dumps(out, ensure_ascii=False, indent=2))
        ok = out.get("ok", False) and (not a.integrity_check or not out.get("tampered"))
        return 0 if ok else 1
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
    # 親プロセス監督(#51): --supervise の親は子サービス(同コマンドから --supervise を除いたもの)を
    # 起動・監視し、異常終了で再起動する。可視・正規=隠蔽せず、シグナルで正規に停止できる。
    if getattr(a, "supervise", False):
        import sys as _sys
        from .engine.core.resilience import Supervisor
        raw = list(argv) if argv is not None else _sys.argv[1:]
        child = [_sys.executable, "-m", "dataplane"] + [x for x in raw if x != "--supervise"]
        print("親プロセス監督(可視): 子サービスを起動し、異常終了したら再起動します。"
              "停止は Ctrl-C / SIGTERM(子も畳んで終了)。")
        res = Supervisor(child).supervise()
        print(f"監督終了: reason={res['reason']} "
              f"starts={res['metrics']['starts']} restarts={res['metrics']['restarts']}")
        return 0 if res["reason"] in ("clean_exit", "stopped") else 1
    run(backend=a.backend, listen=a.listen, admin_port=a.admin, host=a.host,
        admin_host=a.admin_host, token=a.token,
        defaults_on=not a.no_default_on, cluster=a.cluster,
        stealth=a.stealth, health_path=a.health_path, drain_grace=a.drain_grace,
        config_path=a.config)
    return 0
