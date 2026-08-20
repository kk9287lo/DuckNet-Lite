"""
integrity.py — ファイルすり替え検知と強制修復(標準ライブラリのみ・依存ゼロ)
====================================================================================
攻撃者が防御エージェント *自身* を無力化する最短路は「ファイルの差し替え」: 検査ロジック
(pipeline.py 等)を骨抜き版に、または署名/IoC 定義を空に置き換える。本モジュールは不変で
あるべきファイル群(エージェントのコード・運用者 config)を *署名付きマニフェスト* に固定し、
改竄を検知して **ベースラインから強制復元**(強制修復モード)する。

対象は『デプロイ間で不変』のファイルに限る(コード/固定 config)。常時変化する状態ファイル
(bans/usage 等)はハッシュ固定できない=別系統の責務。

正直な信頼境界: マニフェストは秘密鍵(env CHICKENNET_INTEGRITY_KEY 推奨)で HMAC 署名し、
マニフェスト自体のすり替えも検知する。ただしファイルを書ける root 攻撃者がベースライン複製も
鍵も同時に奪える状況までは userspace エージェントでは防げない(読取専用マウント/署名鍵の外部
保管/カーネル保護が最終解)。本モジュールは『検知され、自動復旧される』まで *確度高く* 引き上げる。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import time

# Windows は os.open() に O_BINARY を渡さないと既定でテキストモード(0x0A→0x0D0x0A変換)になり、
# 生のバイト列(鍵)を破損させる。POSIX には無い属性なので getattr で安全に0フォールバック。
_O_BIN = getattr(os, "O_BINARY", 0)


def file_digest(path: str, chunk: int = 65536) -> str:
    """ファイルの sha256(hex)。読めない/無ければ ""(空)。ストリーミング=大ファイルでも定メモリ。"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return ""


def build_manifest(paths) -> dict:
    """対象パス群 → {abspath: {"sha256":.., "size":..}}。読めないものは除外(missing 扱いは検証側)。"""
    man = {}
    for p in paths:
        ap = os.path.abspath(p)
        d = file_digest(ap)
        if d:
            try:
                man[ap] = {"sha256": d, "size": os.path.getsize(ap)}
            except Exception:
                man[ap] = {"sha256": d, "size": 0}
    return man


def _canonical(man: dict) -> bytes:
    """署名対象の正準バイト列(キー順安定)。"""
    return json.dumps(man, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(man: dict, secret: bytes) -> str:
    """マニフェストの HMAC-sha256 署名(hex)。"""
    return hmac.new(secret, _canonical(man), hashlib.sha256).hexdigest()


def verify_signature(man: dict, sig: str, secret: bytes) -> bool:
    """マニフェスト署名を定数時間比較で検証(マニフェストすり替えの検知)。"""
    return bool(sig) and hmac.compare_digest(sign_manifest(man, secret), str(sig))


def verify_entry(path: str, entry: dict) -> str:
    """1ファイルの現状をマニフェスト項目と照合。"ok" | "modified" | "missing"。"""
    if not os.path.exists(path):
        return "missing"
    cur = file_digest(path)
    if not cur:
        return "missing"
    return "ok" if hmac.compare_digest(cur, str(entry.get("sha256", ""))) else "modified"


def _safe_name(abspath: str) -> str:
    """abspath をベースライン複製の安全なファイル名へ(衝突しない様にハッシュ接尾辞)。"""
    base = os.path.basename(abspath) or "f"
    tag = hashlib.sha256(abspath.encode("utf-8")).hexdigest()[:12]
    return f"{base}.{tag}"


class IntegrityMonitor:
    """不変ファイル群の完全性監視+強制修復。baseline で固定し、check で改竄検知、repair で復元。

    baseline_dir 構成:
      · manifest.json  … {"manifest": {...}, "sig": "..", "ts": ..}
      · snapshots/<safe-name> … 各対象の既知良好な複製(repair の復元元)
    secret: env CHICKENNET_INTEGRITY_KEY を推奨。未指定なら baseline_dir に鍵を生成保存(正直: 鍵が
      対象と同じディスクにあると root 攻撃者には弱い=外部鍵/読取専用が望ましい)。
    """

    def __init__(self, paths, baseline_dir: str, secret: bytes = None,
                 backup_dirs=None):
        self.paths = [os.path.abspath(p) for p in paths]
        self.baseline_dir = os.path.abspath(baseline_dir)
        self._snap_dir = os.path.join(self.baseline_dir, "snapshots")
        self._man_path = os.path.join(self.baseline_dir, "manifest.json")
        # 追加のバックアップ場所(別ディスク/別ディレクトリ)。一次 snapshot が壊れても
        # ここから復元できる多重化。透明な正規の場所のみ(隠蔽用の隠し場所ではない)。
        self.backup_dirs = [os.path.abspath(b) for b in (backup_dirs or [])]
        self._secret = secret or self._resolve_secret()

    def _resolve_secret(self) -> bytes:
        """署名鍵の解決。生成は os.O_CREAT|O_EXCL で原子的に行う(#111: 旧来の open→chmod は
        作成〜権限設定の間に他ユーザーから読める窓があった。O_EXCL は他プロセスとの初回生成
        競合も検出し、その場合は相手が書いた鍵を読む)。Windows は os.chmod が実効的なACL
        制限にならない(ファイル属性のみ)=真に外部から守るには env_var を使うこと。"""
        env = os.environ.get("CHICKENNET_INTEGRITY_KEY", "")
        if env:
            return env.encode("utf-8")
        key_path = os.path.join(self.baseline_dir, ".intkey")
        try:
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    k = f.read()
                if k:
                    return k
        except Exception:
            pass
        import secrets as _s
        k = _s.token_bytes(32)
        try:
            os.makedirs(self.baseline_dir, exist_ok=True)
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BIN, 0o600)
            try:
                os.write(fd, k)
            finally:
                os.close(fd)
        except FileExistsError:
            try:                              # 他プロセスと初回生成が競合=相手の鍵を読む
                with open(key_path, "rb") as f:
                    k2 = f.read()
                if k2:
                    return k2
            except Exception:
                pass
        except Exception:
            pass
        return k

    def baseline(self) -> dict:
        """現状を『既知良好』として固定: 複製を snapshots(+追加バックアップ場所)へ、署名付き
        マニフェストを書く。バックアップ多重化で一次 snapshot 破損時も別の場所から復元できる。"""
        man = build_manifest(self.paths)
        doc = {"manifest": man, "sig": sign_manifest(man, self._secret),
               "ts": round(time.time(), 3)}
        for snap_dir in [self._snap_dir] + [os.path.join(b, "snapshots")
                                            for b in self.backup_dirs]:
            try:
                os.makedirs(snap_dir, exist_ok=True)
                for ap in man:
                    try:
                        shutil.copy2(ap, os.path.join(snap_dir, _safe_name(ap)))
                    except Exception:
                        pass
            except Exception:
                pass
        # マニフェストも各バックアップ場所へ複製(一次が壊れても検証元が残る)。
        for man_path in [self._man_path] + [os.path.join(b, "manifest.json")
                                            for b in self.backup_dirs]:
            try:
                os.makedirs(os.path.dirname(man_path), exist_ok=True)
                tmp = man_path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(doc, f)
                os.replace(tmp, man_path)            # 原子的置換(中断耐性)
            except Exception:
                pass
        return {"ok": True, "count": len(man), "baseline_dir": self.baseline_dir,
                "backups": len(self.backup_dirs)}

    def _load_manifest(self):
        try:
            with open(self._man_path, encoding="utf-8") as f:
                doc = json.load(f)
            return doc.get("manifest", {}), doc.get("sig", "")
        except Exception:
            return None, ""

    def check(self) -> dict:
        """改竄検知。返り値:
          · manifest_valid … マニフェスト署名が有効か(False=マニフェスト自体のすり替え)。
          · modified/missing/ok … 各カテゴリの対象パス。
          · tampered … modified+missing(=修復対象)があるか。"""
        man, sig = self._load_manifest()
        if man is None:
            return {"ok": False, "manifest_valid": False, "error": "no baseline",
                    "modified": [], "missing": [], "ok_files": [], "tampered": False}
        manifest_valid = verify_signature(man, sig, self._secret)
        modified, missing, okf = [], [], []
        for ap, entry in man.items():
            st = verify_entry(ap, entry)
            (okf if st == "ok" else modified if st == "modified" else missing).append(ap)
        return {"ok": True, "manifest_valid": manifest_valid,
                "modified": modified, "missing": missing, "ok_files": okf,
                "tampered": bool(modified or missing)}

    def repair(self) -> dict:
        """強制修復: 改竄/欠落した対象を snapshots の既知良好複製から復元する。
        マニフェスト署名が無効(=マニフェストもすり替え)なら復元は信頼できないため拒否し、
        fail-safe を促す(運用者の明示再 baseline が必要)。復元できた/できなかった一覧を返す。"""
        rep = self.check()
        if not rep.get("ok"):
            return {"ok": False, "error": rep.get("error", "no baseline"), "restored": []}
        if not rep["manifest_valid"]:
            return {"ok": False, "error": "manifest signature invalid (manifest tampered)",
                    "fail_safe": True, "restored": [], "failed": rep["modified"] + rep["missing"]}
        man, _ = self._load_manifest()
        restored, failed = [], []
        for ap in rep["modified"] + rep["missing"]:
            want = str(man.get(ap, {}).get("sha256", ""))
            src = self._trusted_source(ap, want)     # snapshot→各バックアップで *ハッシュ一致* する複製
            if src is None:
                failed.append(ap)
                continue
            try:
                os.makedirs(os.path.dirname(ap), exist_ok=True)
                if os.path.islink(ap):
                    # 監視対象がシンボリックリンクにすり替えられていた場合、shutil.copy2 は
                    # リンクを辿って *リンク先* に書いてしまう(confused deputy=任意ファイル
                    # 上書きに転用され得る)。リンク自体を除去し ap を正規ファイルとして
                    # 復元する(#111)。
                    os.unlink(ap)
                shutil.copy2(src, ap)
                # 復元後に再照合(コピー過程の破損も検出)
                if verify_entry(ap, man.get(ap, {})) == "ok":
                    restored.append(ap)
                else:
                    failed.append(ap)
            except Exception:
                failed.append(ap)
        return {"ok": not failed, "restored": restored, "failed": failed}

    def _trusted_source(self, ap: str, want_sha: str):
        """ap の復元元候補(一次 snapshot → 各バックアップの snapshot)から、マニフェストの
        ハッシュ want_sha に *一致* する最初の複製パスを返す。一致を必須にすることで、
        バックアップ自体がすり替えられていても汚染複製を信頼しない(verify-before-trust)。"""
        if not want_sha:
            return None
        safe = _safe_name(ap)
        cands = [os.path.join(self._snap_dir, safe)]
        cands += [os.path.join(b, "snapshots", safe) for b in self.backup_dirs]
        for c in cands:
            if os.path.exists(c) and hmac.compare_digest(file_digest(c), want_sha):
                return c
        return None


def critical_module_paths() -> list:
    """検査ロジックの中核モジュール(差し替えられると WAF が無力化される .py)の実パス。
    import 済みのものだけを集める(未ロードは対象外=現実に走っているコードを守る)。"""
    import importlib
    names = [
        "dataplane.engine.lifeform.pipeline",     # 検査/スコア/BAN の中核
        "dataplane.engine.services.proxy",        # L7 ガード本体
        "dataplane.engine.core.integrity",        # 本モジュール(自己保護)
        "dataplane.engine.core.resilience",       # watchdog
        "dataplane.admin",                        # 管理API(認可)
    ]
    paths = []
    for n in names:
        try:
            m = importlib.import_module(n)
            if getattr(m, "__file__", None):
                paths.append(os.path.abspath(m.__file__))
        except Exception:
            pass
    return paths


class SelfIntegrity:
    """エージェント自身のコード完全性を継続監視する薄いラッパ(watchdog から周期呼び出し)。
    初回はベースライン確立(trust-on-first-use)。以降は check し、改竄があれば(repair=True で)
    強制復元する。返り値レポートで上位が alert/フェイルセーフを判断できる。"""

    def __init__(self, state_dir: str, paths=None, repair: bool = True, secret: bytes = None):
        self.paths = paths if paths is not None else critical_module_paths()
        self.mon = IntegrityMonitor(self.paths, os.path.join(state_dir, ".integrity"),
                                    secret=secret)
        self.repair_enabled = bool(repair)
        self._baselined = os.path.exists(self.mon._man_path)

    def tick(self) -> dict:
        if not self._baselined:
            r = self.mon.baseline()                # TOFU: 初回起動時の現状を既知良好とする
            self._baselined = True
            return {"event": "baseline", **r}
        rep = self.mon.check()
        if not rep.get("tampered") and rep.get("manifest_valid", True):
            return {"event": "ok", "checked": len(self.paths)}
        out = {"event": "tamper", "modified": rep.get("modified", []),
               "missing": rep.get("missing", []),
               "manifest_valid": rep.get("manifest_valid", False)}
        if self.repair_enabled:
            out["repair"] = self.mon.repair()
        return out
