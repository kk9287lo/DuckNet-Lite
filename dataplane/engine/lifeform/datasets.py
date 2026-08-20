"""
datasets.py — 本命囮の『持っていかせる』データセット + 参照トークン(依存ゼロ・ストリーム生成)
====================================================================================
最大本命デコイに『明らかに本物に見える』大容量データ(1.5–10GB 目安)を用意し、攻撃者に
*敢えて* 持ち出させる。各ファイルには一意の **参照トークン** を仕込み、開封/利用時に
こちらへビーコンさせて『誰が・どこから・いつ』持ち出したかを高度に分析する(=最高対応)。

正直な線引き(誇張しない):
  · 依存ゼロでは標準的な暗号ZIP(パスワード付き)は *生成* できない(stdlib 非対応)。よって
    「パスワード保護」分は KeePass/7z/zip 風の *高エントロピー blob*(暗号化に見える)とする。
    攻撃者は『中身のない金庫』を延々とクラックして時間を浪費する(=これも防御効果)。
  · 「未保護」分は本物そっくりの構造化データ(従業員DB/給与/顧客/SQLダンプ/鍵らしき文字列)。
  · 10GB を保存はしない=要求時にストリーム生成(ディスクを食わない)。トークンは先頭付近に置く。
  · 参照トークンは『攻撃者自身の行動が引き金』のビーコンで、こちらから攻撃はしない(防御専用)。
"""
from __future__ import annotations

import hashlib
import os
import random
import time

from .alerts import AlertSink

# 本物らしいファイル雛形: (名前テンプレ, 種別, パスワード保護か)
_TEMPLATES = [
    ("employees_{y}.csv", "csv", False),
    ("payroll_{y}.csv", "csv", False),
    ("customers_export.csv", "csv", False),
    ("db_backup_{y}.sql", "sql", False),
    ("aws_credentials.txt", "secrets", False),
    ("Passwords.kdbx", "vault", True),
    ("backup_{y}.7z", "vault", True),
    ("vpn_certs.zip", "vault", True),
    ("nas_full_backup_{y}.vhdx", "vault", True),
]
# 『いかにも本物がありそう』な設置場所(ランダムに組み直せる)。
_PLACES = ["/var/backups", "/srv/shares/hr", "/srv/shares/finance", "/home/admin",
           "/opt/app/backups", "/mnt/nas/IT", "/data/exports", "/srv/dc01/SYSVOL"]

_FIRST = ["taro", "hanako", "john", "mary", "kenji", "yuki", "admin", "svc"]
_LAST = ["sato", "suzuki", "smith", "jones", "tanaka", "ito", "backup", "dba"]
_DEPT = ["Sales", "HR", "Finance", "IT", "Legal", "R&D"]


def new_token() -> str:
    """一意の参照トークン(衝突しない短い識別子)。"""
    return "fnct_" + hashlib.blake2b(os.urandom(16), digest_size=8).hexdigest()


def _csv_row(rng: random.Random, i: int) -> str:
    f = rng.choice(_FIRST); l = rng.choice(_LAST)
    return (f"{i},{f}.{l},{f}.{l}@corp.local,{rng.choice(_DEPT)},"
            f"{rng.randint(300,1200)*1000},"  # 給与らしき数値
            f"{rng.randint(1,28):02d}/{rng.randint(1,12):02d}/{rng.randint(1990,2002)}\n")


def _sql_row(rng: random.Random, i: int) -> str:
    f = rng.choice(_FIRST); l = rng.choice(_LAST)
    h = hashlib.md5(f"{f}{l}{i}".encode()).hexdigest()   # それらしいパスワードハッシュ
    return f"INSERT INTO users VALUES ({i},'{f}.{l}','{h}','{rng.choice(_DEPT)}');\n"


def _secrets_row(rng: random.Random, i: int) -> str:
    # 本物そっくりに *見える* 鍵文字列(実際には無効。DLP対象に似せて魅力を上げる)。
    akia = "AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
    sk = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+")
                 for _ in range(40))
    return f"[profile-{i}]\naws_access_key_id = {akia}\naws_secret_access_key = {sk}\n\n"


def iter_content(spec: dict, chunk: int = 1 << 20):
    """ファイル内容をストリーム生成して yield(保存しない)。トークンは先頭付近に埋め込む。
    csv/sql/secrets=構造化された本物風データ、vault=高エントロピー(暗号化に見える)blob。"""
    size = int(spec.get("size", 0))
    token = spec.get("token", "")
    kind = spec.get("kind", "csv")
    rng = random.Random(spec.get("seed", 0) ^ 0x9E3779B9)
    produced = 0
    if kind in ("csv", "sql", "secrets"):
        # 先頭に参照トークン(トラッキングURL)を仕込む=開いた/取り込んだ側がこちらを叩けば足が付く。
        cu = token_url_base() + "/c/" + token + ".png"   # 絶対URL(未設定なら相対 /c)
        header = {
            "csv": f"# export id: {token}  source: HRIS  sync: {cu}\n"
                   "id,name,email,department,salary,dob\n",
            "sql": f"-- dump token: {token}  -- callback: {cu}\n",
            "secrets": f"# vault export {token}  # verify: {cu}\n",
        }[kind]
        buf = header.encode("utf-8", "replace")
        i = 0
        rowfn = {"csv": _csv_row, "sql": _sql_row, "secrets": _secrets_row}[kind]
        while produced < size:
            while len(buf) < chunk and produced + len(buf) < size:
                i += 1
                buf += rowfn(rng, i).encode("utf-8", "replace")
            out = buf[:chunk]
            buf = buf[chunk:]
            if produced + len(out) > size:
                out = out[:size - produced]
            produced += len(out)
            yield out
            if not out:
                break
    else:                                       # vault: 暗号化に見える高エントロピー
        magic = {"vault": b""}.get(kind, b"")
        # トークンは別途レジストリ(ファイル名で追跡)。中身は擬似乱数で『割れない金庫』。
        first = True
        while produced < size:
            n = min(chunk, size - produced)
            blob = bytearray(rng.getrandbits(8) for _ in range(min(n, 4096)))
            blob = (blob * ((n // len(blob)) + 1))[:n] if blob else bytearray(n)
            if first and len(blob) >= 8:
                blob[0:4] = magic or b"\x37\x7a\xbc\xaf"  # 7z 風マジック等で『本物』感
                first = False
            produced += len(blob)
            yield bytes(blob)


def build_manifest(total_bytes: int, randomize_names: bool = False,
                   protected_ratio: float = 0.4, year: int = 2023,
                   seed: int = None) -> list:
    """合計 ~total_bytes になるデータセット一覧を作る(名前・設置場所・トークン付き)。
    randomize_names=True で名前をランダム化(指紋化を防ぐ)。seed でレシャッフル再現可。"""
    rng = random.Random(seed)
    places = list(_PLACES)
    rng.shuffle(places)                          # 設置場所をランダムに組み直す
    templates = list(_TEMPLATES)
    rng.shuffle(templates)
    files, remaining = [], max(0, int(total_bytes))
    n = max(1, len(templates))
    base = remaining // n
    for idx, (tmpl, kind, protected) in enumerate(templates):
        if remaining <= 0:
            break
        # サイズは平均 base の周辺で散らす(最後は残り全部)
        size = remaining if idx == n - 1 else max(1, int(base * rng.uniform(0.5, 1.5)))
        size = min(size, remaining)
        remaining -= size
        name = tmpl.format(y=year)
        if randomize_names:
            stem, _, ext = name.rpartition(".")
            name = (hashlib.blake2b(f"{seed}{idx}{name}".encode(), digest_size=5).hexdigest()
                    + ("." + ext if ext else ""))
        files.append({"name": name, "path": places[idx % len(places)] + "/" + name,
                      "kind": kind, "protected": bool(protected), "size": size,
                      "token": new_token(), "seed": rng.getrandbits(32)})
    return files


class TokenLedger:
    """参照トークンの台帳 + 起動(ビーコン)記録。攻撃者が囮を開く/取り込むと足が付く。"""

    def __init__(self, state_dir: str = ""):
        self.sink = AlertSink("ledger", state_dir=state_dir, dedup_window=2.0,
                              total_key="events", metric_keys=("hit", "pull"))
        self._tokens: dict = {}                  # token -> file meta
        self._unknown_probes = 0                 # 未知トークンで /c/ を叩かれた回数(カウントのみ)

    def register(self, manifest: list) -> dict:
        """配布したデータセットのトークンを台帳へ登録。"""
        for f in manifest:
            self._tokens[f["token"]] = {"name": f["name"], "path": f["path"],
                                        "kind": f["kind"], "size": f["size"]}
        return {"ok": True, "tokens": len(self._tokens)}

    def register_canary(self, token: str, kind: str = "", memo: str = "") -> dict:
        """単体カナリアトークン(minter 発行・evolution #13)を台帳へ登録。ビーコン hit/エッジ
        作動を『どの罠が・どこに置いたか(memo)』付きで帰属できるようにする。"""
        self._tokens[token] = {"name": memo or f"canary:{kind}", "kind": kind,
                               "canary": True, "memo": memo}
        return {"ok": True}

    def record_pull(self, client: str, spec: dict, now: float = None) -> dict:
        """データが *取得(持ち出し)* された事実を高重大度で記録。"""
        meta = {"client": client, "name": spec.get("name"), "path": spec.get("path"),
                "size": spec.get("size"), "token": spec.get("token")}
        return self.sink.record((client, "pull", spec.get("token", "")), meta,
                                verdict="malicious", action="alert",
                                count_metrics=("pull",), now=now)

    def record_hit(self, token: str, client: str, ua: str = "", extra: dict = None,
                   now: float = None) -> dict:
        """トークン起動(持ち出したデータが外で開かれ /c/<token> を叩いた=接続先を分析)。
        既知トークンなら『どのファイルが・どこ(client)から・どう(UA等)』を記録して足を辿る。
        /c/ は公開・無認証・WAF 検査の手前(レート制限外)なので、*未知* トークン(=こちらが植えて
        いない=スキャン/プローブ)で AlertSink/SIEM/dedup 表をフラッドさせない。未知はカウントのみ。"""
        if token not in self._tokens:            # 未知=alert を生成しない(フラッド入口を塞ぐ)
            self._unknown_probes += 1
            return {"known": False, "recorded": False}
        meta = {"token": token, "client": client, "ua": ua,
                "file": self._tokens.get(token), "known": True}
        if extra:
            meta.update(extra)
        return self.sink.record((token, "hit", client), meta,
                                verdict="malicious", action="alert",
                                count_metrics=("hit",), now=now)

    def log(self, n: int = 100) -> list:
        return self.sink.log(n)

    def status(self) -> dict:
        return {"tokens": len(self._tokens), "metrics": dict(self.sink.metrics),
                "unknown_probes": self._unknown_probes,
                "note": "参照トークン台帳。データの持ち出し(pull)と外部での参照(hit)を記録。"}


def token_url_base() -> str:
    """参照トークンが叩く絶対URLのベース(env CHICKENNET_TOKEN_URL)。未設定なら相対 /c。
    外部環境で開かれてもビーコンが *こちら* へ届くよう、運用者は公開到達URLを設定する。"""
    return os.environ.get("CHICKENNET_TOKEN_URL", "").rstrip("/")


# ── プロセス共有シングルトン(proxy が記録、admin が可視化で共有) ──
_LEDGER: TokenLedger = None


def token_ledger() -> TokenLedger:
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = TokenLedger()
    return _LEDGER
