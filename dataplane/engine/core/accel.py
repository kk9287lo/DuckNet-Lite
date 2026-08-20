"""
accel.py — 局所的ネイティブ化の継ぎ目(PyO3/Cython 対応・純Pythonフォールバック)
==============================================================================
全書き換えはせず、**一番重い計算ループだけ**をネイティブ(Rust=PyO3 / C=Cython)へ切り出す
ための継ぎ目。任意のコンパイル済み拡張 `chickennet_accel` があればその関数を使い、無ければ
**純Python のフォールバック**で動く(ハード依存なし・未ビルドでも壊れない)。

使い方(痛み最小):
  · ここで純Python実装を提供しつつ、`chickennet_accel` が import 出来れば自動で置き換える。
  · ホットループ候補: エントロピー計算 / ハッシュ / トークナイズ内側 / エミュレータ step。
  · ネイティブ拡張は GIL を解放できるので、UI(別スレッド)と並行で重計算を回せる。

正直: ここでは拡張のビルド(toolchain)はできない。純Python実装が常に正しく動き、
`chickennet_accel` をビルドして置けば自動で高速化する、という**継ぎ目**を提供する(=設計の用意)。
"""
from __future__ import annotations

import math
import os
import sys
from collections import Counter


def _load_native():
    try:
        import chickennet_accel       # 任意: PyO3/Cython でビルドした拡張(無くてよい)
        return chickennet_accel
    except Exception:
        pass
    # build.py が生成した core/native/chickennet_accel.*.pyd/.so を探す
    nd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native")
    if os.path.isdir(nd):
        if nd not in sys.path:
            sys.path.insert(0, nd)
        try:
            import chickennet_accel
            return chickennet_accel
        except Exception:
            return None
    return None


_NATIVE = _load_native()

# 実行時に差し替えられるネイティブ実装スロット(self_transpile の継ぎ目が登録/解除する)。
# 純Pythonフォールバックは常に残す=登録解除で即元に戻る(可逆)。
_OVERRIDES: dict = {}


def set_native_override(name: str, fn) -> dict:
    """ホットループ name を、検証済みネイティブ関数 fn で実行時に差し替える(可逆)。"""
    _OVERRIDES[name] = fn
    return {"installed": name, "active": True, "note": "純Python版は保持・clear で即解除(可逆)。"}


def clear_native_override(name: str) -> dict:
    """差し替えを解除して純Python実装へ戻す(可逆)。"""
    existed = _OVERRIDES.pop(name, None) is not None
    return {"cleared": name, "was_active": existed}


def native_override_active(name: str) -> bool:
    return name in _OVERRIDES


def has_native(name: str) -> bool:
    return _NATIVE is not None and hasattr(_NATIVE, name)


def accelerate(name: str, py_impl):
    """name のネイティブ実装があればそれを、無ければ py_impl を返す(関数差し替え)。"""
    if has_native(name):
        return getattr(_NATIVE, name)
    return py_impl


# ── ホットループの純Python実装(ネイティブが無ければこれが動く) ──
def _py_shannon_entropy(data) -> float:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    n = len(data)
    if n == 0:
        return 0.0
    # ヒストグラムは C 実装の Counter で一括(Python の毎バイトループを排除)。
    # 数式は H = -Σ(c/n)log2(c/n) = log2(n) - (1/n)Σ c·log2(c)(除算を1回へ削減)。
    log2 = math.log2
    return log2(n) - sum(c * log2(c) for c in Counter(data).values()) / n


def shannon_entropy(data) -> float:
    """バイト列のシャノンエントロピー(bits/byte)。差し替え/ネイティブがあれば高速版・無ければ純Python。"""
    ov = _OVERRIDES.get("shannon_entropy")           # 継ぎ目で差し替えた検証済みネイティブ
    if ov is not None:
        try:
            return float(ov(data))
        except Exception:
            pass                                     # 失敗しても純Pythonへフォールバック(可逆)
    if has_native("shannon_entropy"):
        try:
            return float(_NATIVE.shannon_entropy(
                data.encode("utf-8", "replace") if isinstance(data, str) else data))
        except Exception:
            pass
    return _py_shannon_entropy(data)


def _py_hamming(a, b) -> int:
    """2つのバイト列のハミング距離(不一致バイト数 + 長さ差)。純Python。"""
    if isinstance(a, str):
        a = a.encode("utf-8", "replace")
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    na, nb = len(a), len(b)
    n = na if na < nb else nb
    d = 0
    for i in range(n):
        if a[i] != b[i]:
            d += 1
    d += abs(na - nb)
    return d


def hamming_distance(a, b) -> int:
    """2バイト列のハミング距離。差し替えネイティブがあれば高速版・無ければ純Python(可逆)。"""
    ov = _OVERRIDES.get("hamming_distance")
    if ov is not None:
        try:
            return int(ov(a, b))
        except Exception:
            pass
    return _py_hamming(a, b)


# ── L7防御の高速プレフィルタ(ホットパス) ────────────────────────────
# 正規化済み(小文字/空白畳み/=・;|畳み)入力に対し、攻撃シグネチャの「核となる固定語」を
# 多重部分文字列探索する。**安全条件**: 各正規表現分岐は少なくとも1つの needle を含む=
# 「正規表現が当たる ⇒ prescan>0」(スーパーセット)。よって prescan==0 なら高価な正規表現を
# 丸ごとスキップしてよい(検出を取りこぼさない)。over-match は許容(速度が落ちるだけ)。
# この純Python実装は常に正しく、Rust継ぎ目(native_prescan)が検証後に set_native_override で
# 高速版へ差し替える(ctypes呼び出し中はGIL解放=並行性も改善・clearで即可逆)。
_PRESCAN_NEEDLES = [
    b"union", b"select", b"1=1", b"--", b"drop table",
    b"script", b"onerror", b"javascript:", b"document.cookie",
    b"..", b"/etc/passwd", b"/proc/", b"windows\\",
    b";cat", b";wget", b";curl", b";bash", b";sh", b";nc", b";powershell",
    b"|nc", b"|bash", b"$(", b"`",
    b"sqlmap", b"nikto", b"nmap", b"masscan", b"acunetix", b"nessus",
    b"dirbuster", b"gobuster", b"wpscan", b"zgrab", b"nuclei", b"httpx",
    b"/.env", b"/wp-login", b"xmlrpc.php", b"phpmyadmin",
    b"/.git/", b"/.aws/", b"/actuator/", b"/.ssh/",
    # ブラインド/時間/エラーベース SQLi(sqli_blind 分岐の核語。pg_sleep は "sleep" が内包)
    b"sleep", b"benchmark", b"waitfor", b"extractvalue", b"updatexml",
    b"load_file", b"outfile", b"dumpfile", b"information_schema",
    b"[$", b"$where",                                   # NoSQL(Mongo)演算子注入
    b"php://", b"file://", b"gopher://", b"dict://",     # SSRF/LFI ラッパー
    b"expect://", b"phar://", b"netdoc://",
    b"jndi:",                                           # Log4Shell(JNDI)
    b"169.254.169.254", b"metadata.google", b"100.100.100.200",  # SSRF クラウドメタデータ
    b"fd00:ec2", b"/latest/meta-data", b"/computemetadata",
    b"vbscript:", b"data:text/html",                   # XSS(追加スキーム)
    b"__proto__", b"prototype",                        # プロトタイプ汚染
    b";set-cookie", b";location", b";refresh",          # CRLF/レスポンスヘッダ注入(正規化後 ;)
    b";content-type", b";content-length", b";content-disposition",
    b"<!entity", b"<!doctype",                          # XXE
    b"classloader",                                     # Spring4Shell(クラスローダ汚染)
    b"/etc/shadow", b"/etc/hosts", b"win.ini", b"boot.ini",  # traversal 追加LFI標的(..; は .. が内包)
    b"() {", b"<?php", b"<?=",                          # Shellshock / PHP コード注入(rce)
    b"_memberaccess", b"@java.lang.runtime",            # OGNL/Struts2
    b"@java.lang.processbuilder", b"#context[", b"ognl.",
    b"<!--#",                                           # SSI 注入
    b")(",                                              # LDAP インジェクション
    b";bcc", b";cc", b";to", b";mime-version", b";content-transfer-encoding",  # メールヘッダ注入
    b"{{", b"<%=", b"#{", b"${",                        # SSTI(オプション)
    b"127.0.0.1", b"0.0.0.0", b"localhost", b"192.168.", b"169.254.",  # 内部SSRF(オプション)
    b"0x7f", b"2130706433", b"017700000001",            # 難読化ループバック(オプション)
    b"=//",                                             # オープンリダイレクト(オプション)
]


def _py_prescan_suspicious(data) -> int:
    """正規化済みバイト列から、攻撃の核語の出現数を数える(0=無)。純Pythonフォールバック。"""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    hits = 0
    for needle in _PRESCAN_NEEDLES:
        if needle in data:
            hits += 1
    return hits


def prescan_suspicious(data) -> int:
    """L7プレフィルタ。差し替えネイティブ(Rust)があれば高速版・無ければ純Python(可逆)。"""
    ov = _OVERRIDES.get("prescan_suspicious")
    if ov is not None:
        try:
            return int(ov(data))
        except Exception:
            pass                                 # 失敗しても純Pythonへフォールバック(可逆)
    return _py_prescan_suspicious(data)


def info() -> dict:
    return {"native_module": "chickennet_accel", "native_available": _NATIVE is not None,
            "accelerated_fns": [n for n in ("shannon_entropy",) if has_native(n)],
            "runtime_overrides": list(_OVERRIDES),
            "hot_loop_candidates": ["shannon_entropy", "tokenizer_inner",
                                    "ast_pattern_scan", "emulator_step"],
            "note": "純Python実装が常に動く。chickennet_accel(PyO3/Cython)があれば自動置換。さらに "
                    "self_transpile の継ぎ目が cdylib/.dll を ctypes でロードして set_native_override で"
                    "実行時に差し替え可(検証済み・承認制・clearで即可逆)。"}
