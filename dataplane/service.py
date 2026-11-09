"""
service.py — DuckNet-Lite スタンドアロン・サービス本体(CLI/起動エントリ)
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
import math
import os
import sys


def _force_utf8_stdio() -> None:
    """標準出力/エラーを UTF-8 かつ行バッファへ。失敗しても無害に継続。

    · UTF-8 化: Windows の cp932/cp1252 コンソールで、ヘルプや起動メッセージ中の
      非ASCII文字(— や日本語)が UnicodeEncodeError でクラッシュするのを防ぐ。
    · 行バッファ化: サービスとして動かすと標準出力はパイプ/ファイルになり、Python は
      ブロックバッファにする。その結果 **起動して数秒経ってもログが 0 バイト** という
      状態になっていた(実測: systemd/docker 相当の環境で 4 秒後も空。内容が出るのは
      *プロセスが止まったとき*)。起動バナーには **管理トークン** が載るので、
      運用者は「起動したか」も「どのトークンで入るか」も分からない。
      データ経路は print しない(通知は数えるほど)ので、行ごとの flush で構わない。"""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if reconfig is None:
            continue
        try:
            reconfig(encoding="utf-8", errors="backslashreplace", line_buffering=True)
        except Exception:
            try:                              # line_buffering 非対応の実装向け
                reconfig(encoding="utf-8", errors="backslashreplace")
            except Exception:
                pass

from dataplane.engine.services.proxy import AsyncEdgeGuard, _MAX_DRAIN_GRACE_SEC
from dataplane.engine.lifeform.policy import app_firewall
from dataplane.engine.lifeform.pipeline import net_shield
from .admin import AdminDashboard


def _bounded_drain_grace(value) -> float:
    """Reject a shutdown wait that is negative, nonfinite or effectively endless."""
    if isinstance(value, bool):
        raise ValueError("drain grace must be a finite duration from 0 to 300 seconds")
    try:
        seconds = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("drain grace must be a finite duration from 0 to 300 seconds") from exc
    if not math.isfinite(seconds) or not 0 <= seconds <= _MAX_DRAIN_GRACE_SEC:
        raise ValueError("drain grace must be a finite duration from 0 to 300 seconds")
    return seconds


def _env_float(name: str, default: float) -> float:
    """env から有限の停止猶予を読む。不正値は既定へフォールバックし警告する。
    素の float(os.environ[...]) だと、綴り間違い 1 つでゲートウェイが起動時に生の
    ValueError で落ちる(--help すら出せない)。防御が上がらないのが最悪なので、
    設定ミスは警告して既定で動かす。"""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return float(default)
    try:
        return _bounded_drain_grace(raw)
    except ValueError:
        print(f" [警告] {name}={raw!r} は数値として読めません。既定 {default} を使います。",
              file=sys.stderr)
        return float(default)


def _split_hostport(spec: str, default_port: int):
    """"HOST:PORT" を (host, port) へ。IPv6 の "[::1]:8080" と裸の "::1" も扱う。
    旧実装は partition(":") + int() だったため、ポートの綴り間違いはもちろん
    *IPv6 アドレスを指定しただけ* で起動時に ValueError で落ちていた
    ("[::1]:8080" は port=":1]:8080" と解釈されていた)。"""
    s = (spec or "").strip()
    if s.startswith("["):                      # [IPv6]:port 形式
        end = s.find("]")
        if end == -1:
            raise SystemExit(f"アドレスの形式が不正です: {spec!r}(例 [::1]:8080)")
        host, rest = s[1:end], s[end + 1:]
        if not host or (rest and not rest.startswith(":")):
            raise SystemExit("アドレスの括弧・区切りの形式が不正です")
        port = rest[1:] if rest.startswith(":") else ""
        if rest.startswith(":") and not port:
            raise SystemExit("バックエンドのポートが空です")
    elif s.count(":") > 1:                     # 裸の IPv6(ポート指定なし)
        host, port = s, ""
    else:
        host, sep, port = s.partition(":")
        if sep and (not host or not port):
            raise SystemExit("バックエンドのホストまたはポートが空です")
    if not port:
        return (host or "127.0.0.1"), int(default_port)
    try:
        p = int(port)
    except ValueError:
        raise SystemExit(f"ポート番号が不正です: {spec!r}")
    if not (1 <= p <= 65535):
        raise SystemExit(f"ポート番号が範囲外です: {p}(1-65535)")
    return (host or "127.0.0.1"), p


def state_dir_writable(path: str = "") -> bool:
    """状態ディレクトリに *実際に書けるか* を書き込みで確かめる(モードビットは当てにならない:
    ACL・読取専用マウント・systemd の ProtectSystem/ReadOnlyPaths では権限ビットが書込可でも
    失敗する)。書けない場所を掴んだまま起動すると、BAN・累犯記録・ライセンス・完全性
    ベースラインが *毎回の再起動で黙って消える*。"""
    import tempfile
    from .engine.core.atomic_io import default_state_dir
    path = path or default_state_dir()
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".probe.", dir=path)
        os.close(fd)
        os.unlink(tmp)
        return True
    except OSError:
        return False


_ENV_FILE_MAX_BYTES = 1024 * 1024


def _env_path_exists(path: str) -> bool:
    """Only a genuinely absent app.env is optional; stat errors are not."""
    try:
        os.lstat(path)  # lstat also sees a broken symlink to an intended env file.
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SystemExit(f"app.env を確認できません: {path}") from exc
    return True


def load_env_file(path: str = "") -> int:
    """app.env(KEY=VALUE)を環境変数へ *既定値として* 取り込む。返値=取り込んだ件数。
    既に環境にある値は上書きしない(呼び出し時の指定が常に勝つ)。構文上壊れた行は
    飛ばすが、UTF-8 の破損・NUL・1 MiB 超のファイルは環境変数を一つも適用せず起動を拒否する。
    状態保存先・署名鍵・管理トークンの読み替わりを防ぐ。= の前後の空白、字下げしたコメント、CRLF、値を囲む
    引用符に対応する(シェル側の実装はここで躓いてランチャごと落ちていた)。"""
    configured_env = not path and bool(os.environ.get("DUCKNET_ENV_FILE", ""))
    p = path or os.environ.get("DUCKNET_ENV_FILE", "")
    discovered = False
    if not p:
        # ランチャは配置先へ cd してから起動するので CWD を先に見る。パッケージの親
        # (ソースツリー配置)も候補にして、どちらの置き方でも拾えるようにする。
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for cand in (os.path.join(os.getcwd(), "app.env"), os.path.join(here, "app.env")):
            if _env_path_exists(cand):
                p = cand
                discovered = True
                break
        else:
            return 0
    # A deliberately optional, absent path stays optional. Once a file has
    # been observed, losing it (or failing to read it) must not silently load
    # a different state directory or signing key.
    was_present = discovered or _env_path_exists(p)
    try:
        with open(p, "rb") as f:
            raw = f.read(_ENV_FILE_MAX_BYTES + 1)
    except FileNotFoundError as exc:
        if configured_env or was_present or _env_path_exists(p):
            raise SystemExit(f"app.env を読み込めません: {p}") from exc
        return 0
    except OSError as exc:
        raise SystemExit(f"app.env を読み込めません: {p}") from exc
    if len(raw) > _ENV_FILE_MAX_BYTES:
        raise SystemExit(f"app.env が大きすぎます (上限 {_ENV_FILE_MAX_BYTES} バイト): {p}")
    import io
    try:
        # StringIO(newline=None) keeps text-mode universal newline parsing.
        lines = io.StringIO(raw.decode("utf-8", "strict"), newline=None).readlines()
    except UnicodeDecodeError as exc:
        raise SystemExit(f"app.env は UTF-8 として読めません: {p}") from exc
    if any("\x00" in raw for raw in lines):
        raise SystemExit(f"app.env に NUL バイトがあります: {p}")
    n = 0
    for raw in lines:
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not key.replace("_", "").isalnum() or key[0].isdigit():
            continue                      # 不正なキーは飛ばす(export 失敗で落とさない)
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]               # 値を囲む引用符は外す
        if key in os.environ:
            continue                      # 呼び出し時の指定を優先
        os.environ[key] = val
        n += 1
    return n


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


def _watch_stdin_stop(ev) -> bool:
    """トレイが子として起動した本体(env DUCKNET_STDIN_STOP=1)だけ、標準入力の 'stop' 行で
    graceful 停止を受け付ける。トレイ側の終了は以前 terminate() だけで、Windows では
    TerminateProcess=即死(ドレイン・BAN の flush が走らない)。子は CREATE_NO_WINDOW なので
    CTRL_BREAK も届かない。パイプの書き口は起動した親だけが持つ。
    EOF(親の異常終了等)では止めない=トレイが落ちても防御は続ける。"""
    if os.environ.get("DUCKNET_STDIN_STOP", "").strip() != "1":
        return False
    stream = sys.stdin
    if stream is None:
        return False
    import threading

    def _reader():
        try:
            for line in stream:
                if line.strip().lower() == "stop":
                    ev.set()
                    return
        except Exception:
            pass
    threading.Thread(target=_reader, name="stdin-stop", daemon=True).start()
    return True


def _block_until_shutdown(*stop_fns, _event=None, _liveness=None) -> dict:
    """SIGTERM / SIGINT で graceful 停止するまでブロックし、停止時に `stop_fns` を順に呼ぶ。
    各 stop_fn は独立に try で囲む(片方が失敗してももう片方=状態 flush 等を必ず走らせる)。
    シグナルハンドラを張れなかった環境では KeyboardInterrupt を保険として拾う。
    `_event` はテスト専用の差し込み口(本番は None=内部 Event にシグナルを配線する)。
    `_liveness` が異常を返したら停止処理を全て実行し、非ゼロ終了を呼び出し側へ伝える。"""
    import threading
    ev = _event if _event is not None else threading.Event()
    if _event is None:
        _install_shutdown_handlers(ev)
        _watch_stdin_stop(ev)                 # トレイが起動した子だけ(env で明示)
    failure = ""
    try:
        while not ev.wait(1.0):   # タイムアウト付き待機=シグナル処理の機会を挟む(Win も即応)
            if _liveness is not None and not ev.is_set():
                try:
                    reason = _liveness()
                except Exception as exc:
                    reason = f"liveness check raised {type(exc).__name__}"
                if reason:
                    failure = "runtime liveness failure: " + str(reason)
                    break
    except KeyboardInterrupt:
        pass
    errors = [failure] if failure else []
    for fn in stop_fns:
        try:
            result = fn()
            if result is False or (isinstance(result, dict) and result.get("ok") is not True):
                errors.append(str(result.get("error") or "cleanup did not succeed")
                              if isinstance(result, dict) else "cleanup did not succeed")
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
    return {"ok": not errors, "errors": errors}


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
        admin_port: int = 8081, host: str = "127.0.0.1",
        admin_host: str = "127.0.0.1", token: str = "",
        defaults_on: bool = True, cluster: bool = False,
        health_path: str = "", drain_grace: float = 5.0,
        config_path: str = "") -> None:
    import os as _os
    try:
        drain_grace = _bounded_drain_grace(drain_grace)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if not isinstance(backend, str) or not backend.strip():
        raise SystemExit("バックエンドのアドレスが空です")
    bhost, bport = _split_hostport(backend, 80)
    # Resolve the state namespace before singletons create keys or any socket
    # is bound. The former generic default is also FalcoNet's default; its
    # signed files cannot be attributed safely to either product on this host.
    from .engine.core.atomic_io import (default_state_dir as _dsd,
                                        LegacyStateSelectionRequired)
    try:
        _sd = _dsd()
    except LegacyStateSelectionRequired as exc:
        raise SystemExit(str(exc)) from exc
    from .engine.core.serving_lease import ServingLease
    try:
        lease = ServingLease(_sd)
        if not lease.acquire(timeout=0.0):
            raise SystemExit("同じ状態保存先を使用する DuckNet-Lite が既に稼働中です。"
                             "DUCKNET_STATE_DIR を専用の保存先にしてください。")
    except BaseException as exc:
        if "lease" in locals():
            lease.close()
        if isinstance(exc, OSError):
            raise SystemExit(f"状態保存先の稼働権を取得できません: {exc}") from exc
        raise

    try:
        # 製品の既定は『防御ON』(売り物なので最初から守る)。設定は永続化される。
        if defaults_on:
            fw_result = app_firewall().enable()
            if fw_result.get("ok") is not True or fw_result.get("enabled") is not True:
                raise SystemExit("ファイアウォールの有効化・保存に失敗しました。前衛は起動しません")
            shield_result = net_shield().enable()
            if shield_result.get("ok") is not True or shield_result.get("enabled") is not True:
                raise SystemExit("シールドの有効化・保存に失敗しました。前衛は起動しません")

        # 宣言的設定ブートストラップ(env DUCKNET_CONFIG / --config): k8s ConfigMap
        # 等の immutable infra 向け(永続 state より後＝宣言ファイルが権威)。
        _cfg_path = config_path or _os.environ.get("DUCKNET_CONFIG", "")
        if _cfg_path:
            _res = net_shield().apply_config_file(_cfg_path)
            if _res.get("ok") is True and not _res.get("rejected"):
                print(f" 宣言的設定         : {_cfg_path} 適用 → {', '.join(_res.get('applied') or []) or '(変更なし)'}")
            else:
                raise SystemExit(f"宣言的設定を適用できません。前衛は起動しません: "
                                 f"{_res.get('error') or '; '.join(_res.get('errors') or [])}")
        # 壊れてはいないが直すべき設定(旧版が保存した whitelist+空 など)。status の warnings・
        # イベントにしか出ず、コンソールで起動した運用者には見えなかった。
        try:
            for _w in net_shield().config_warnings():
                print(f" 設定               : [警告] {_w.get('message')}")
        except Exception:
            pass

        # guard は admin より先に生成し、状態所有権を起動前に渡す。
        guard = AsyncEdgeGuard(backend_host=bhost or "127.0.0.1", backend_port=bport,
                               listen_host=host, listen_port=listen,
                               health_path=health_path)
        guard._serving_lease = lease
    except BaseException:
        lease.close()  # listener 未作成・worker 不在。失敗した起動を保持しない。
        raise
    # 前衛ガードを admin より *先* に起動する。--cluster は os.fork() するので、admin の
    # 待受ソケットが既に開いていると全ワーカーへ継承され、親が死んでも管理ポートが開いた
    # ままになる(実測: 親へ SIGTERM 後も管理ポート・前衛ポートとも開放されず)。
    try:
        if cluster:
            res = guard.serve_cluster()
            if res.get("mode") == "single":
                print(f" [note] {res.get('reason')}")
            if not res.get("ok"):
                raise SystemExit(f"前衛ガード起動失敗: {res.get('error') or '原因不明'}")
        else:
            info = guard.start()
            if not info.get("ok"):
                raise SystemExit(f"前衛ガード起動失敗: {info.get('error')}")
    except BaseException:
        # Failed pre-bind starts have no traffic to flush. Keep the lease if
        # a partial listener or worker still exists; its failure must not let
        # another process mutate the same state concurrently.
        try:
            still_owned = (guard.is_alive() or bool(guard._workers)
                           or guard._listen_sock is not None or guard._server is not None)
        except Exception:
            still_owned = True
        if still_owned:
            try:
                guard.stop(grace=0.0)  # successful stop flushes then releases the lease
            except Exception:
                pass                # uncertain ownership: retain until process exit
        else:
            # A failed pre-bind start may have dirty quota/BAN memory even
            # without a listener. The guard intentionally keeps ownership if
            # its final flush failed; do not undo that fail-closed decision.
            if getattr(guard, "_serving_lease", None) is lease and lease.held:
                try:
                    guard._finish_serving_lease()
                except Exception:
                    pass            # still held: process exit is the last release
            else:
                lease.close()
        raise
    try:
        admin = AdminDashboard(host=admin_host, port=admin_port, token=token, edge_guard=guard)
        a = admin.start()
        if not isinstance(a, dict) or a.get("ok") is not True:
            raise RuntimeError(a.get("error", "起動が拒否されました")
                               if isinstance(a, dict) else "起動結果が不正です")
    except Exception as e:
        # 管理ポートが塞がっている等でここが失敗すると、既に起動済みの前衛ガード
        # (--cluster では fork 済みのワーカー)が後始末されないまま親だけ死ぬ。
        # stop 自体も一過性の例外や未完了を返し得る。失敗を握り潰して
        # SystemExit すると、組込み実行では前衛 listener/worker が残る。
        # 所有する実行体がまだある場合だけ、即時停止を一度再試行する。
        cleanup_problem = ""
        for attempt in range(2):
            try:
                stopped = guard.stop(grace=0.0)
                if (isinstance(stopped, dict) and stopped.get("ok") is True
                        and stopped.get("stopped") is True):
                    cleanup_problem = ""
                    break
                cleanup_problem = "前衛の停止が完了していません"
            except Exception as stop_exc:
                cleanup_problem = f"前衛停止で {type(stop_exc).__name__}"
            if attempt == 0:
                try:
                    still_owned = (guard.is_alive() or bool(guard._workers)
                                   or guard._listen_sock is not None)
                except Exception:
                    still_owned = True  # 所有状態も読めないなら再試行する
                if not still_owned:
                    break
        detail = f"管理ダッシュボード起動失敗: {type(e).__name__}: {e}"
        if cleanup_problem:
            detail += f"; {cleanup_problem}"
        raise SystemExit(detail)
    print("=" * 64)
    print(" DuckNet-Lite — セキュリティゲートウェイ 起動")
    print("=" * 64)
    print(f" 管理ダッシュボード : {a['url']} （ブラウザで開き、管理トークンで認証）")
    if token:
        # The operator already supplied this credential. Do not duplicate it in
        # systemd, container or redirected startup logs.
        print(" 管理トークン       : 設定済み（DUCKNET_ADMIN_TOKEN 等の設定値で認証）")
    else:
        try:
            interactive = bool(sys.stdout.isatty())
        except Exception:
            interactive = False
        if interactive:
            print(f" 管理トークン       : {a['token']}")
        else:
            print(" 管理トークン       : 自動生成済み。管理操作には DUCKNET_ADMIN_TOKEN を"
                  "設定して再起動してください（自動生成値はログへ出力しません）")
    if admin_host not in ("127.0.0.1", "localhost", "::1"):
        print(f" [警告] 管理画面を非ループバック({admin_host})で待受中。管理トークンを"
              " ネットワーク上へ平文で送らないようにしてください。")
        print("        ネットワークへ直接公開しないでください(SSHトンネル/リバースプロキシ/"
              "ホストの127.0.0.1へのみポート公開を推奨)。")
    # IPv6 リテラルは [] で囲って表示する(`::1:8443` は読めないし URL にもならない)
    from .engine.core.netaddr import hostport as _hp
    print(f" 防御中(前衛)       : {_hp(host, listen)}  →  バックエンド {_hp(bhost, bport)}")
    print("=" * 64)

    # 状態ディレクトリに書けないまま起動すると、BAN も累犯記録もライセンスも
    # 再起動のたびに消える。しかも見た目は完全に正常に動くので気づけない。
    # (ハードニングした systemd ユニットや読取専用ボリュームで普通に起こる)
    if not state_dir_writable(_sd):
        print(f" 状態保存           : [警告] {_sd} へ書き込めません。BAN・累犯記録・"
              "ライセンス・完全性ベースラインは再起動で全て失われます", file=sys.stderr)
        print("        DUCKNET_STATE_DIR に書き込める場所を指定してください"
              "(systemd の ProtectSystem/ReadOnlyPaths や読取専用マウントが原因のことが多い)",
              file=sys.stderr)
    if drain_grace > 0:
        print(f" 停止時ドレイン     : 最大 {drain_grace:g}s(進行中リクエストを捌いてから停止)")
    # SIGTERM(コンテナ/k8s の停止シグナル)/ SIGINT で graceful 停止。
    # guard は drain_grace 秒だけ進行中リクエストを捌いてから停止(取りこぼし回避)。停止時に
    # WAF 状態(BAN/累犯回数)も flush=再起動越しのエスカレーション記憶を取りこぼさない。
    def _runtime_liveness():
        edge_server = guard._server
        if not guard.is_alive() or edge_server is None or not edge_server.is_serving():
            return "edge serving thread stopped"
        admin_thread = admin._thread
        if admin._server is None or admin_thread is None or not admin_thread.is_alive():
            return "admin serving thread stopped"
        return ""

    stopped = _block_until_shutdown(lambda: guard.stop(grace=drain_grace), admin.stop,
                                    _liveness=_runtime_liveness)
    if isinstance(stopped, dict) and stopped.get("ok") is not True:
        raise SystemExit("停止または状態保存に失敗しました: " + "; ".join(stopped.get("errors") or []))
    print("\nDuckNet-Lite を停止しました。")


def _strip_autostart_flags(raw) -> list:
    """raw argv から自動起動関連フラグを取り除いた serve コマンドを返す(自動起動に登録する対象)。
    --install-autostart は省略可能な値(onlogon/onstart/runkey)を取り得るので消費を判定する。
    `--flag=value` 形式にも対応。argparse は曖昧でない *略記*(--install / --install-auto /
    --autostart-n)も受理するので、略記も同一視する。完全一致だけで消していた頃は略記が
    登録コマンドに残り、ログオン/起動のたびに『自動起動を再登録して終了』するだけで
    ゲートウェイが一度も起動しなかった(登録は ok:true と報告される)。"""
    out, i = [], 0
    choices = {"onlogon", "onstart", "runkey"}

    def _is(base, flag):                          # 完全一致または曖昧でない略記
        return base.startswith("--") and len(base) > 2 and flag.startswith(base)
    while i < len(raw):
        x = raw[i]
        base = x.split("=", 1)[0]
        if _is(base, "--uninstall-autostart"):    # 値なし
            i += 1; continue
        if _is(base, "--json"):                   # 値なし。登録の結果表示の指定で、常駐側には不要
            i += 1; continue
        if _is(base, "--autostart-name"):         # 別トークンで値を取る
            i += 1 if "=" in x else 2             # =形式は1トークン、別形式は値も飛ばす
            continue
        if _is(base, "--install-autostart"):
            i += 1
            if "=" not in x and i < len(raw) and raw[i] in choices:
                i += 1                            # 省略可能な値を消費(あれば)
            continue
        out.append(x); i += 1
    return out


# ── 運用者向け CLI の結果表示(--install-autostart / --uninstall-autostart)──────────────────
# 結果の dict を JSON のまま出していたため、運用者には成功したのかも次に何をすればよいのかも
# 分からなかった。既定は平文の要約(成否の 1 行・要点・失敗時は「次の手順」)、--json は従来と
# まったく同じ JSON(スクリプト互換)。終了コードは表示と無関係に従来どおり。
_CLI_CMD = "python -m dataplane"


def _cli_ja() -> bool:
    """CLI の表示言語。サーバ側の文言と同じ規則(DUCKNET_LANG → OS ロケール → 既定 ja)。"""
    try:
        from .engine.core.i18n import lang
        return lang() != "en"
    except Exception:
        return True


def _cli_one_line(v, limit: int = 300) -> str:
    """OS の応答など外部由来の値を 1 行の表示用文字列へ。改行・端末制御文字は空白にし、長ければ切る。"""
    s = "" if v is None else str(v)
    s = " ".join("".join(c if c.isprintable() else " " for c in s).split())
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _cli_arg(s) -> str:
    """表示するコマンド例の引数。空白や記号を含む名前は "" で囲む。"""
    s = str(s)
    if s and not any(c in s for c in " \t\"'&|<>;^%$`"):
        return s
    return '"' + s.replace('"', '\\"') + '"'


def _cli_print(lines_fn, ok: bool, *args, **kw) -> None:
    """要約を表示する。表示の組み立てで想定外の形に当たっても、処理結果(終了コード)は変えない。"""
    try:
        lines = lines_fn(*args, **kw)
    except Exception:
        ja = _cli_ja()
        lines = [("完了しました" if ok else "失敗しました") + "(詳細は --json を付けて確認できます)。"
                 if ja else ("Done" if ok else "Failed") + " (run again with --json for details)."]
    for ln in lines:
        print(ln)


def _autostart_undo_cmd(name: str, runkey: bool) -> str:
    s = f"{_CLI_CMD} --uninstall-autostart"
    if runkey:
        s += " --install-autostart runkey"            # Run キーの解除はこの指定で選ぶ
    if name != "DuckNet":
        s += f" --autostart-name {_cli_arg(name)}"
    return s


def _install_autostart_lines(res: dict, *, name: str, trigger: str, ja: bool) -> list:
    """--install-autostart の結果を、運用者が読む数行へ(何をどこへ・確認方法・取り消し方)。"""
    import re as _re

    def t(j, e):
        return j if ja else e
    lines = []
    method = str(res.get("method") or "")
    nm = str(res.get("name") or name)
    if res.get("action") == "manual" and method in ("systemd", "launchd"):
        sysd = method == "systemd"
        path = str(res.get("unit_path" if sysd else "plist_path") or "")
        body = str(res.get("unit" if sysd else "plist") or "")
        lines.append(t("自動起動の設定ファイルを用意しました。まだ登録されていません ― 次の手順で"
                       "有効にしてください(管理者権限が必要です)。",
                       "Autostart file prepared, but it is not registered yet. Follow these steps "
                       "to enable it (requires root)."))
        lines.append(t(f"  1) 下の内容を {path} として保存:", f"  1) Save the text below as {path}:"))
        lines.append("-" * 64)
        lines.extend(body.rstrip("\n").splitlines())
        lines.append("-" * 64)
        lines.append(t(f"  2) 有効化: {res.get('enable', '')}", f"  2) Enable it: {res.get('enable', '')}"))
        if sysd:
            base = path.rsplit("/", 1)[-1]
            unit = base[:-len(".service")] if base.endswith(".service") else nm.lower()
            lines.append(t(f"  確認方法: systemctl status {unit}", f"  To check: systemctl status {unit}"))
            lines.append(t(f"  取り消し: systemctl disable --now {unit} を実行してから {path} を削除",
                           f"  To undo : systemctl disable --now {unit}, then delete {path}"))
            m = _re.search(r"(?m)^User=(.*)$", body)
            if m:
                lines.append(t(f"  注意    : このユニットはユーザー {m.group(1)} で動きます。そのユーザーが"
                               "無ければ作成するか、User= を書き換えてください。より厳しいユニットの例は"
                               " docs/hardening.md の 2 章にあります。",
                               f"  Note    : the unit runs as user {m.group(1)}. Create that user or "
                               "change User=. A hardened unit is shown in docs/hardening.md "
                               "section 2."))
        else:
            base = path.rsplit("/", 1)[-1]
            label = base[:-len(".plist")] if base.endswith(".plist") else base
            lines.append(t(f"  確認方法: launchctl list | grep {label}",
                           f"  To check: launchctl list | grep {label}"))
            lines.append(t(f"  取り消し: launchctl unload -w {path} を実行してから {path} を削除",
                           f"  To undo : launchctl unload -w {path}, then delete {path}"))
            lines.append(t("  詳しくは docs/hardening.md の 4 章にあります。",
                           "  See docs/hardening.md section 4 for details."))
        return lines
    if res.get("ok"):
        if method == "schtasks":
            when = (t("PC の起動時", "when the computer starts")
                    if str(res.get("trigger") or trigger) == "onstart"
                    else t("サインイン時", "when you sign in"))
            lines.append(t(f"自動起動を登録しました: Windows タスクスケジューラのタスク「{nm}」"
                           f"({when}に起動)。",
                           f'Autostart registered: Windows Task Scheduler task "{nm}" '
                           f"(starts {when})."))
            lines.append(t(f"  確認方法: schtasks /query /tn {_cli_arg(nm)}   (タスク スケジューラの画面でも確認できます)",
                           f"  To check: schtasks /query /tn {_cli_arg(nm)} (or open Task Scheduler)"))
            lines.append(t(f"  取り消し: {_autostart_undo_cmd(nm, False)}",
                           f"  To undo : {_autostart_undo_cmd(nm, False)}"))
        elif method == "runkey":
            loc = str(res.get("location") or "")
            lines.append(t("自動起動を登録しました: このユーザーのサインイン時に起動します(Windows の Run キー)。",
                           "Autostart registered: starts when this user signs in (Windows Run key)."))
            if loc:
                lines.append(t(f"  登録先  : {loc}", f"  Location: {loc}"))
            lines.append(t("  確認方法: タスク マネージャーの「スタートアップ アプリ」に表示されます。",
                           "  To check: it is listed in Task Manager > Startup apps."))
            lines.append(t(f"  取り消し: {_autostart_undo_cmd(name, True)}",
                           f"  To undo : {_autostart_undo_cmd(name, True)}"))
        else:
            lines.append(t("自動起動を登録しました。", "Autostart registered."))
            lines.append(t(f"  取り消し: {_autostart_undo_cmd(nm, False)}",
                           f"  To undo : {_autostart_undo_cmd(nm, False)}"))
        return lines
    where = {"schtasks": t("Windows タスクスケジューラ", "Windows Task Scheduler"),
             "runkey": t("Windows の Run キー", "Windows Run key")}.get(method, "")
    lines.append(t("自動起動を登録できませんでした" + (f"({where})" if where else "") + "。",
                   "Could not register autostart" + (f" ({where})" if where else "") + "."))
    reason = _cli_one_line(res.get("error") or res.get("detail") or "")
    if reason:
        lines.append(t(f"  理由    : {reason}", f"  Reason  : {reason}"))
    if str(res.get("error") or "").startswith("unsupported platform"):
        lines.append(t("次の手順: この OS には自動登録の仕組みがありません。OS のサービス管理機能で"
                       f"「{_CLI_CMD} <起動オプション>」を起動時に実行し、落ちたら再起動するよう"
                       "設定してください(docs/hardening.md)。",
                       "Next step: this OS has no automatic registration. Configure the OS service "
                       f'manager to run "{_CLI_CMD} <options>" at startup and restart it if it '
                       "stops (see docs/hardening.md)."))
    elif method == "runkey":
        lines.append(t("次の手順: ゲートウェイを動かすユーザーで実行してください(Run キーは実行した"
                       "ユーザーにだけ登録されます)。",
                       "Next step: run this as the user that will run the gateway (the Run key "
                       "is registered only for the user who runs it)."))
    elif trigger == "onstart":
        lines.append(t("次の手順: PC の起動時(onstart)の登録には管理者権限が必要です。管理者として"
                       "実行するか、サインイン時の登録(値なしの --install-autostart、または runkey)"
                       "を使ってください。",
                       "Next step: registering for computer startup (onstart) needs administrator "
                       "rights. Run as administrator, or register for sign-in instead "
                       "(--install-autostart with no value, or runkey)."))
    else:
        lines.append(t("次の手順: ゲートウェイを動かすユーザーで実行してください。権限が足りないと"
                       "出る場合は --install-autostart runkey(このユーザーだけに登録・管理者権限"
                       "不要)を試すか、docs/hardening.md の手順でサービスとして登録してください。",
                       "Next step: run this as the user that will run the gateway. If it reports "
                       "missing permissions, try --install-autostart runkey (this user only, no "
                       "administrator rights needed) or register a service as described in "
                       "docs/hardening.md."))
    return lines


def _uninstall_autostart_lines(res: dict, *, name: str, runkey: bool, ja: bool,
                               plat: str = None) -> list:
    """--uninstall-autostart の結果を、運用者が読む数行へ。"""
    def t(j, e):
        return j if ja else e
    plat = sys.platform if plat is None else plat
    nm = str(res.get("name") or name)
    lines = []
    if res.get("action") == "manual":
        unit = name.lower()
        if plat.startswith("linux"):
            lines.append(t("この OS では自動で解除しません。次の手順で解除してください(root 権限):",
                           "Autostart is not removed automatically on this OS. Remove it with "
                           "these steps (as root):"))
            lines += [f"  1) systemctl disable --now {unit}",
                      f"  2) rm /etc/systemd/system/{unit}.service",
                      "  3) systemctl daemon-reload"]
        elif plat == "darwin":
            p = f"/Library/LaunchDaemons/com.ducknet.{unit}.plist"
            lines.append(t("この OS では自動で解除しません。次の手順で解除してください(管理者権限):",
                           "Autostart is not removed automatically on this OS. Remove it with "
                           "these steps (as administrator):"))
            lines += [f"  1) launchctl unload -w {p}", f"  2) rm {p}"]
        else:
            lines.append(t("この OS では自動で解除しません。OS のサービス管理機能で登録を外してください。",
                           "Autostart is not removed automatically on this OS. Remove it with "
                           "the OS service manager."))
        return lines
    if res.get("ok"):
        lines.append(t("自動起動を解除しました: " + (f"Run キーの「{nm}」を削除しました。" if runkey
                                                   else f"タスクスケジューラのタスク「{nm}」を削除しました。"),
                       "Autostart removed: " + (f'deleted "{nm}" from the Run key.' if runkey
                                                 else f'deleted Task Scheduler task "{nm}".')))
        again = f"{_CLI_CMD} --install-autostart" + (" runkey" if runkey else "")
        lines.append(t(f"  もう一度登録するには: {again}", f"  To register again: {again}"))
        return lines
    lines.append(t("自動起動を解除できませんでした: " +
                   (f"Run キーに「{nm}」が見つからないか、削除できませんでした。" if runkey
                    else f"タスク「{nm}」が見つからないか、削除する権限がありません。"),
                   "Could not remove autostart: " +
                   (f'"{nm}" was not found in the Run key or could not be deleted.' if runkey
                    else f'task "{nm}" was not found, or you lack permission to delete it.')))
    reason = _cli_one_line(res.get("error") or res.get("detail") or "")
    if reason:
        lines.append(t(f"  理由    : {reason}", f"  Reason  : {reason}"))
    if runkey:
        lines.append(t("次の手順: 登録したときの名前が違うなら --autostart-name で指定してください"
                       "(既定 DuckNet)。タスクスケジューラに登録した場合は --install-autostart runkey を"
                       "付けずに実行してください。",
                       "Next step: if it was registered under another name, pass --autostart-name "
                       "(default DuckNet). If it was registered in Task Scheduler, run without "
                       "--install-autostart runkey."))
    else:
        lines.append(t("次の手順: 登録したときの名前が違うなら --autostart-name で指定してください"
                       "(既定 DuckNet)。Run キーに登録した場合は --install-autostart runkey を付けて"
                       "実行してください。管理者として登録したタスクは管理者として解除します。"
                       f"確認: schtasks /query /tn {_cli_arg(nm)}",
                       "Next step: if it was registered under another name, pass --autostart-name "
                       "(default DuckNet). If it was registered in the Run key, add "
                       "--install-autostart runkey. A task registered as administrator must be "
                       f"removed as administrator. To check: schtasks /query /tn {_cli_arg(nm)}"))
    return lines


def main(argv=None) -> int:
    _force_utf8_stdio()
    # 引数の既定値は env から読むので、パーサを組み立てる *前* に取り込む。
    load_env_file()
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "tray":                # システムトレイ常駐(トレイのみ・Windows)
        from .gui.__main__ import main as _tray_main
        return _tray_main(args[1:])
    ap = argparse.ArgumentParser(
        prog="ducknet-lite",
        description="DuckNet-Lite — 軽量 DDoS/WAF セキュリティゲートウェイ(L7・依存ゼロ)")
    ap.add_argument("--backend", default="127.0.0.1:8080",
                    help="守る対象(あなたのWebサーバ) HOST:PORT")
    ap.add_argument("--listen", type=int, default=8443, help="前衛ガードの待受ポート")
    ap.add_argument("--host", default="127.0.0.1",
                    help="前衛ガードの待受ホスト(既定=localhost。公開にはTLS終端を前段へ)")
    ap.add_argument("--admin", type=int, default=8081, help="管理ダッシュボードのポート")
    ap.add_argument("--admin-host", default="127.0.0.1",
                    help="管理ダッシュボードの待受(既定=localhost限定)")
    ap.add_argument("--token", default=os.environ.get("DUCKNET_ADMIN_TOKEN", ""),
                    help="管理トークン(空=自動生成)。env DUCKNET_ADMIN_TOKEN でも渡せる"
                         "(argv は他ユーザーから読めるので秘密は env 推奨)")
    ap.add_argument("--cluster", action="store_true",
                    help="Linux/macOSで複数ワーカー。有限クォータ設定時やWindows等は単一へ降格")
    ap.add_argument("--no-default-on", action="store_true",
                    help="起動時に防御を自動ONにしない")
    ap.add_argument("--health-path", default="", metavar="PATH",
                    help="死活監視用パス(例 /healthz)。一致リクエストは WAF/バックエンド非経由で"
                         "即200を返す。LB/オーケストレータ用。既定OFF(env DUCKNET_HEALTH_PATH 可)")
    ap.add_argument("--drain-grace", type=_bounded_drain_grace, metavar="SEC",
                    default=_env_float("DUCKNET_DRAIN_GRACE", 5.0),
                    help="停止(SIGTERM/SIGINT)時に進行中リクエストを捌く最大秒数。"
                         "0=即時停止、上限300。既定5(env DUCKNET_DRAIN_GRACE 可)")
    ap.add_argument("--config", default="", metavar="PATH",
                    help="起動時に適用する宣言的設定 JSON(WAFルール等)。k8s ConfigMap 等の"
                         "immutable infra 向け=永続 state より後に適用(env DUCKNET_CONFIG 可)")
    ap.add_argument("--install-autostart", nargs="?", const="onlogon", default="",
                    metavar="TRIGGER", choices=["", "onlogon", "onstart", "runkey"],
                    help="起動時自動起動を *透明な公認の場所* に登録: Windows=タスクスケジューラ"
                         "(明示名・onlogon/onstart)or 標準 Run キー(runkey)、Linux=systemd、"
                         "mac=launchd。Autoruns/Task Scheduler/systemctl で可視。隠し永続化はしない。")
    ap.add_argument("--uninstall-autostart", action="store_true",
                    help="--install-autostart で登録した自動起動を解除する。")
    ap.add_argument("--autostart-name", default="DuckNet", metavar="NAME",
                    help="自動起動エントリの表示名(既定 DuckNet)。")
    ap.add_argument("--json", action="store_true",
                    help="--install-autostart / --uninstall-autostart の結果を、人向けの要約では"
                         "なく従来どおりの JSON で出力する(スクリプト向け。終了コードは同じ)。")
    a = ap.parse_args(argv)
    # 自動起動の登録/解除(#58): 透明な公認の場所のみ。登録したら即終了(常駐はしない)。
    if a.uninstall_autostart:
        from .engine.core.autostart import uninstall
        import json as _json
        m = "runkey" if a.install_autostart == "runkey" else "auto"
        res = uninstall(method=m, name=a.autostart_name)
        if a.json:                                    # スクリプト向け: 従来どおりの JSON
            print(_json.dumps(res, ensure_ascii=False))
        else:                                         # 人向け: 成否・要点・次の手順
            _cli_print(_uninstall_autostart_lines, bool(res.get("ok")), res,
                       name=a.autostart_name, runkey=m == "runkey", ja=_cli_ja())
        return 0 if res.get("ok") is True else 1
    if a.install_autostart:
        from .engine.core.autostart import install
        import sys as _sys
        import json as _json
        raw = list(argv) if argv is not None else _sys.argv[1:]
        serve_args = _strip_autostart_flags(raw)      # 自動起動フラグを除いた serve コマンド
        method = "runkey" if a.install_autostart == "runkey" else "auto"
        trigger = a.install_autostart if a.install_autostart in ("onlogon", "onstart") else "onlogon"
        res = install(serve_args, method=method, name=a.autostart_name, trigger=trigger)
        if a.json:
            print(_json.dumps(res, ensure_ascii=False, indent=2))
        else:
            _cli_print(_install_autostart_lines, bool(res.get("ok")), res,
                       name=a.autostart_name, trigger=trigger, ja=_cli_ja())
        return 0 if res.get("ok") else 1
    run(backend=a.backend, listen=a.listen, admin_port=a.admin, host=a.host,
        admin_host=a.admin_host, token=a.token,
        defaults_on=not a.no_default_on, cluster=a.cluster,
        health_path=a.health_path, drain_grace=a.drain_grace,
        config_path=a.config)
    return 0
