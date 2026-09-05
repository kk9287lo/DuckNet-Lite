"""
signed_state.py — 可変状態ファイルの改竄耐性(HMAC署名・標準ライブラリのみ・依存ゼロ)
====================================================================================
BAN リスト・カスタム署名・設定・IoC のような *常時変化する* 状態は固定ハッシュにできない。
本モジュールはそれらを **保存時に HMAC 署名・読込時に検証** して守る。攻撃者がホスト上で
blocklist.json を書き換えて自分を unban したり、rules.json を空にして検知を無効化しても、
署名が一致しないため『改竄』として弾き、安全側デフォルトへフェイルセーフする。

形式: 1ファイル原子書き込みのまま、ペイロードを署名エンベロープで包む:
    {"_sv": 1, "_sig": "<hmac-sha256 hex>", "_payload": <元のオブジェクト>}
署名は payload の正準JSON(キー順安定)に対する HMAC-SHA256。読込は (status, value) を返す:
  · "ok"       … 署名検証成功。value=payload。
  · "tampered" … 署名不一致/エンベロープ破損 → value=default(呼び出し側がフェイルセーフ)。
  · "unsigned" … 旧来の無署名プレーンファイル → value=生オブジェクト(呼び出し側が再保存で移行)。
  · "missing"  … 欠損/読めない → value=default。

鍵は再起動を跨ぐ必要があるため永続化する(env 推奨、無ければ state_dir に 0600 で生成保存)。
正直な信頼境界: 鍵が状態ファイルと同じディスクにある場合、root 攻撃者は鍵も読めて再署名し得る
=完全な保護には外部鍵(env/HSM/別権限)が要る。env DUCKNET_STATE_KEY 指定でその水準へ上げられる。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

from .atomic_io import atomic_write_json, safe_read_json

# ロールバック攻撃対策(#102): プロセス生存中に受理した最大バージョン(path 毎)。攻撃者が
# 『古い正署名ファイル』で巻き戻しても、稼働中はメモリ高水位が古い版を拒否する。再起動跨ぎは
# サイドカーの .hw ファイル(同じく署名)で補強する。正直な残余: ディスク全書込み権限+.hw の
# 存在を知る高度攻撃者が *両方* を整合的に巻き戻せば突破し得る(完全防止には外部単調カウンタ要)。
_MEM_HW: dict = {}

# Windows は os.open() に O_BINARY を渡さないと既定でテキストモード(0x0A→0x0D0x0A変換)になり、
# 生のバイト列(鍵)を破損させる。POSIX には無い属性なので getattr で安全に0フォールバック。
_O_BIN = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)   # POSIX: 最終要素が symlink なら open 失敗。Win は無し。


def _read_key_file(key_path: str):
    """鍵ファイルを *symlink 追従せず・通常ファイルのみ* 読む(#symlink-key)。返り値 bytes/None。
    共有 state_dir で攻撃者が .statekey を既知内容ファイルへの symlink にすり替え、その内容を
    HMAC 鍵として読ませ、鍵既知 → 署名済み状態(BAN/設定/署名)を偽造する攻撃を封じる。
    0600 が実効的でない Windows では O_NOFOLLOW が無いため lstat の symlink 判定で補う。"""
    import stat as _stat
    try:
        st = os.lstat(key_path)
        if _stat.S_ISLNK(st.st_mode):
            return None                       # symlink は拒否(リダイレクト無効化)
        fd = os.open(key_path, os.O_RDONLY | _O_BIN | _O_NOFOLLOW)
        try:
            fst = os.fstat(fd)
            if not _stat.S_ISREG(fst.st_mode):
                return None                   # 通常ファイル以外(FIFO/デバイス/ディレクトリ等)は拒否
            if os.name == "posix":
                # 所有者と権限も確かめる。共有 state_dir に *他ユーザーが作った* 鍵を読むと、
                # 攻撃者の知っている鍵で「署名は正しい」と判定してしまい、署名済み状態
                # (BAN/設定)の偽造を検出できなくなる。他人所有は拒否。
                if fst.st_uid != os.geteuid() and os.geteuid() != 0:
                    return None
                if fst.st_mode & 0o077:
                    # group/other から読める=鍵が漏れうる。ただしここで *拒否* すると、
                    # 既存インストール(緩い権限で作られた鍵)では読めない→O_EXCL は
                    # FileExistsError→永続化されない一時鍵を返す、という経路に落ちて
                    # 起動のたびに鍵が変わり、自分が署名した BAN/設定を自分で検証できず
                    # 既定値へ黙って戻ってしまう。自分の物なら締め直して読む(自己修復)。
                    try:
                        os.fchmod(fd, 0o600)
                    except OSError:
                        return None       # 締められない=保護できないので使わない
            return os.read(fd, 1 << 16)
        finally:
            os.close(fd)
    except Exception:
        return None


def persistent_key(state_dir: str, env_var: str = "DUCKNET_STATE_KEY",
                   filename: str = ".statekey") -> bytes:
    """状態署名用の永続鍵。env_var があればそれを使う(最も安全=外部鍵)。無ければ
    state_dir/filename を 0600 で生成保存して再利用する(再起動を跨いで検証できるように)。
    生成は os.O_CREAT|O_EXCL で原子的に行う(#111: 旧来の open→chmod は、作成〜権限設定の
    間に他ユーザーから読める窓があった。O_EXCL は他プロセスとの初回生成競合も検出し、
    その場合は相手が書いた鍵を読む)。Windows は os.chmod が実効的なACL制限にならない点に
    注意(ファイル属性のみ)=真に外部から守るには env_var を使うこと。"""
    env = os.environ.get(env_var, "")
    if env:
        return env.encode("utf-8")
    key_path = os.path.join(state_dir, filename)
    k0 = _read_key_file(key_path)             # symlink 非追従・通常ファイルのみ(#symlink-key)
    if k0:
        return k0
    import secrets as _s
    k = _s.token_bytes(32)
    try:
        os.makedirs(state_dir, exist_ok=True)
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BIN, 0o600)
        try:
            os.write(fd, k)
        finally:
            os.close(fd)
    except FileExistsError:
        # 他プロセスと初回生成が競合=相手の鍵を読む。O_EXCL 成功〜書き込み完了までの
        # 短い窓に当たると空/未完了で読める可能性があるため、諦める前に数回リトライする
        # (ここで諦めて未永続化の自前鍵 k を返すと、次回起動時にディスクの鍵と食い違い、
        # 自分が署名した状態を自分で検証できなくなる)。
        for _attempt in range(5):
            k2 = _read_key_file(key_path)
            if k2:
                return k2
            time.sleep(0.01 * (_attempt + 1))
    except Exception:
        pass
    return k


def _canon(obj) -> bytes:
    """署名対象の正準バイト列(キー順安定=再シリアライズで署名が揺れない)。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8", "replace")


def sign_payload(obj, key: bytes) -> str:
    return hmac.new(key, _canon(obj), hashlib.sha256).hexdigest()


def verify_payload(obj, sig: str, key: bytes) -> bool:
    return bool(sig) and hmac.compare_digest(sign_payload(obj, key), str(sig))


def _hw_path(path: str) -> str:
    return path + ".hw"


def _read_file_hw(path: str, key: bytes) -> int:
    """サイドカー .hw(署名済みの最大バージョン)を読む。検証失敗/欠損は 0。
    署名対象に *対象ファイルの basename* を含める(本体エンベロープの purpose 束縛と同じ考え)。
    以前は {"_ver": n} だけに署名していたため、ある state の .hw を別の state の .hw として
    そのまま置ける=低いバージョンの .hw を移植して高水位を下げ、ロールバック防止を無効化
    できた。束縛が無い旧形式は受理しない(0 扱い)=移植を将来にわたって無効化する。
    旧形式からの移行時は高水位が一度 0 に戻るが、メモリ高水位(_MEM_HW)と ms 由来の
    単調バージョンが働き、次回書込みで束縛付き .hw に置き換わる。"""
    raw = safe_read_json(_hw_path(path), None)
    if isinstance(raw, dict) and verify_payload(_hw_payload(path, raw.get("_ver", 0)),
                                                raw.get("_sig", ""), key):
        try:
            return int(raw.get("_ver", 0))
        except (TypeError, ValueError):
            return 0
    return 0


def _hw_payload(path: str, ver) -> dict:
    """.hw の署名対象。basename で束縛して別 state への移植を無効化する。"""
    try:
        ver = int(ver)
    except (TypeError, ValueError):
        ver = 0
    return {"_hw": 1, "_ver": ver, "_for": os.path.basename(path)}


def _write_file_hw(path: str, ver: int, key: bytes) -> None:
    env = {"_ver": int(ver), "_sig": sign_payload(_hw_payload(path, ver), key)}
    try:
        atomic_write_json(_hw_path(path), env, indent=0)
    except Exception:
        pass


def _next_version(path: str) -> int:
    """単調増加バージョン(ミリ秒時刻と『前回+1』の大きい方)。再起動を跨いでも必ず増える。"""
    prev = 0
    raw = safe_read_json(path, None)
    if isinstance(raw, dict):
        try:
            prev = int(raw.get("_ver", 0))
        except (TypeError, ValueError):
            prev = 0
    return max(prev + 1, int(time.time() * 1000))


def write_signed_json(path: str, obj, key: bytes, *, indent: int = 2) -> bool:
    """obj を署名エンベロープ(単調バージョン付き=ロールバック耐性)で原子的に書き込む。
    _sv:3 で **purpose(ファイル basename)を署名対象に束縛** する(#3): 全状態ファイルが同一鍵で
    署名されるため、旧 _sv:2(purpose 無し)では usage.json の正署名エンベロープを blocklist.json
    へ *移植* すると有効判定され、無警告で BAN 全消し/署名無効化ができた。purpose を署名に含め
    読込時に basename と照合することで、あるファイルの署名を別ファイルとして通せなくする。"""
    ver = _next_version(path)
    purpose = os.path.basename(path)
    env = {"_sv": 3, "_ver": ver, "_purpose": purpose,
           "_sig": sign_payload({"_ver": ver, "_purpose": purpose, "_payload": obj}, key),
           "_payload": obj}
    ok = atomic_write_json(path, env, indent=indent)
    if ok:                                       # 高水位を前進(メモリ + サイドカー)
        hw = max(ver, _read_file_hw(path, key), _MEM_HW.get(path, 0))
        _MEM_HW[path] = hw
        _write_file_hw(path, hw, key)
    return ok


def read_signed_json(path: str, key: bytes, default=None, *, check_rollback: bool = True):
    """署名付き状態を読む。返り値 (status, value)。status は
    ok / tampered / rolled_back / unsigned / missing。例外は投げない。
    rolled_back = 署名は正しいが『過去の版』への巻き戻し(古い正署名ファイルでの上書き)を検知。"""
    raw = safe_read_json(path, None)
    if raw is None:
        return ("missing", default)
    if isinstance(raw, dict) and "_sig" in raw and "_payload" in raw:
        try:
            _sv = int(raw.get("_sv", 1) or 1)
        except (TypeError, ValueError):
            return ("tampered", default)     # _sv が非数値=エンベロープ破損→フェイルセーフ(#111)
        if _sv >= 3:
            # purpose 束縛版(#3): basename が一致し、かつ {_ver,_purpose,_payload} の署名が正しいこと。
            purpose = os.path.basename(path)
            if raw.get("_purpose") != purpose:
                return ("tampered", default)     # 別ファイルからの署名エンベロープ移植=拒否
            ver = raw.get("_ver", 0)
            if not verify_payload({"_ver": ver, "_purpose": purpose,
                                   "_payload": raw["_payload"]}, raw["_sig"], key):
                return ("tampered", default)     # 署名不一致(ver/purpose/payload 改竄)
            try:
                v = int(ver)
            except (TypeError, ValueError):
                v = 0
            if check_rollback:
                hw = max(_read_file_hw(path, key), _MEM_HW.get(path, 0))
                if v < hw:
                    return ("rolled_back", default)
                _MEM_HW[path] = max(hw, v)
                _write_file_hw(path, _MEM_HW[path], key)
            return ("ok", raw["_payload"])
        if _sv >= 2 and "_ver" in raw:
            ver = raw.get("_ver", 0)
            if not verify_payload({"_ver": ver, "_payload": raw["_payload"]},
                                  raw["_sig"], key):
                return ("tampered", default)     # 署名不一致(ver/payload 改竄)
            try:
                v = int(ver)
            except (TypeError, ValueError):
                v = 0
            if check_rollback:
                hw = max(_read_file_hw(path, key), _MEM_HW.get(path, 0))
                if v < hw:
                    return ("rolled_back", default)   # 旧い正署名への巻き戻し=拒否
                _MEM_HW[path] = max(hw, v)
                _write_file_hw(path, _MEM_HW[path], key)
            return ("ok", raw["_payload"])
        # 旧 _sv:1(バージョン無し)= 後方互換: payload 署名のみ検証
        if verify_payload(raw["_payload"], raw["_sig"], key):
            if check_rollback:
                hw = max(_read_file_hw(path, key), _MEM_HW.get(path, 0))
                if hw > 0:
                    # このpathは既に _sv:2(バージョン付き)で保存された実績がある。
                    # 旧形式への「降格」は #102 のロールバック対策を素通りする巻き戻し攻撃と
                    # みなして拒否する(初回移行時=hw==0 の間は従来どおり受理・#111)。
                    return ("rolled_back", default)
            return ("ok", raw["_payload"])
        return ("tampered", default)            # 署名不一致=改竄/すり替え→フェイルセーフ
    return ("unsigned", raw)                     # 旧来の無署名(移行対象)
