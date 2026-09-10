"""
verify_env_matrix.py — テスト一式を「環境を変えて」繰り返し走らせる(依存ゼロ)
====================================================================================
実行:
    python tools/verify_env_matrix.py            # 全プロファイル
    python tools/verify_env_matrix.py en-cp1252  # 1 つだけ

なぜ要るか
----------
バグの多くは *コードではなく環境* で出る。実際このリポジトリでは、手元の検証環境が
すべて「日本語 Windows」か「C ロケールの Linux」だったせいで、次の 2 つを取り逃がした:

  · **非 UTF-8 端末**(英語版 Windows の cp1252 など)。ランナーが SKIP/FAIL の説明
    (日本語)を出そうとした瞬間に UnicodeEncodeError で落ち、*要約行すら出ないまま*
    exit 1 になる。「何が失敗したのか分からない」という最悪の壊れ方をする。
  · **英語ロケールの OS**。env にロケール指定が無いとき OS のロケールを見るのは設計
    どおり(英語環境では英語 UI)だが、日本語環境を前提に書かれたテストはそこで落ちる。

どちらもローカルでは一度も再現せず、CI の windows-latest(英語)でだけ落ちた。
以後は手元でも常設で当てられるようにする。

仕組み
------
OS のロケール報告(locale.setlocale / locale.getlocale)と標準入出力のエンコーディングを
プロファイルごとに差し替えた子プロセスで tests/run_all.py を実行する。
ロケールは env だけでは変えられない(特に Windows)ので、子プロセス側で差し替える。
"""
from __future__ import annotations

import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

# name -> (OS ロケールの報告値 (None = 未設定=C), 標準入出力のエンコーディング, 説明)
PROFILES = {
    "default":   (False, None,      "この機のまま(何も差し替えない)"),
    "en-cp1252": ("English_United States.1252", "cp1252",
                  "英語版 Windows のコンソール(CI の windows-latest 相当)"),
    "en-utf8":   ("English_United States.1252", "utf-8",
                  "英語ロケールだが端末は UTF-8(英語 Linux デスクトップ相当)"),
    "c-utf8":    (None, "utf-8", "ロケール未設定(systemd/コンテナ/cron の既定)"),
    "ja-cp932":  ("Japanese_Japan.932", "cp932", "日本語版 Windows のコンソール"),
    "ascii":     (None, "ascii", "非ASCIIを一切書けない端末(最も厳しい)"),
}

_LOCALE_ENV = ("DUCKNET_LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE", "LANG", "LANGUAGE")


def _child(os_locale: str) -> int:
    """子プロセス側: OS ロケールの報告を差し替えてから run_all を実行する。"""
    import locale
    import runpy

    if os_locale == "-":
        os_locale = ""
    if os_locale:
        lang = os_locale.split(".")[0]
        locale.setlocale = lambda *a, **k: os_locale
        locale.getlocale = lambda *a, **k: (lang, os_locale.split(".")[-1])
    else:
        locale.setlocale = lambda *a, **k: "C"
        locale.getlocale = lambda *a, **k: ("C", "UTF-8")
    try:                                  # 3.15 で消える予定。あれば揃えておく。
        locale.getdefaultlocale = lambda *a, **k: (lang if os_locale else "C", None)
    except Exception:
        pass
    os.chdir(_ROOT)
    sys.argv = [os.path.join(_ROOT, "tests", "run_all.py")]
    runpy.run_path(sys.argv[0], run_name="__main__")
    return 0                              # run_all が sys.exit するのでここへは来ない


def run_profile(name: str) -> tuple:
    os_locale, enc, _desc = PROFILES[name]
    env = dict(os.environ)
    for k in _LOCALE_ENV:                 # env のロケール指定は毎回まっさらにする
        env.pop(k, None)
    if enc:
        env["PYTHONIOENCODING"] = enc
    else:
        env.pop("PYTHONIOENCODING", None)
    if os_locale is False:                # default: 何も差し替えない
        cmd = [sys.executable, os.path.join(_ROOT, "tests", "run_all.py")]
    else:
        cmd = [sys.executable, os.path.abspath(__file__), "--child",
               os_locale if os_locale else "-"]
    r = subprocess.run(cmd, cwd=_ROOT, env=env, capture_output=True)
    out = (r.stdout or b"").decode("utf-8", "replace")
    err = (r.stderr or b"").decode("utf-8", "replace")
    summary = ""
    for line in out.split("\n"):
        if line.startswith("=== ") and "passed" in line:
            summary = line.strip()
    fails = [l.strip() for l in out.split("\n") if l.startswith("FAIL ")]
    return r.returncode, summary, fails, err


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--child":
        return _child(argv[1] if len(argv) > 1 else "-")

    # 親側の出力だけ行バッファにする。数分かかる検証で、リダイレクトすると進捗が
    # 一切見えないのでは使い物にならない(まさにこのツールが探している症状を
    # ツール自身がやっていた)。子側は *端末を模す* のが仕事なので触らない。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace",
                               line_buffering=True)
        except Exception:
            pass

    names = [a for a in argv if not a.startswith("-")] or list(PROFILES)
    unknown = [n for n in names if n not in PROFILES]
    if unknown:
        print("未知のプロファイル: %s" % ", ".join(unknown))
        print("使えるのは: %s" % ", ".join(PROFILES))
        return 2

    print("環境マトリクス検証 — %s" % _ROOT)
    bad = 0
    for name in names:
        _l, _e, desc = PROFILES[name]
        print("\n── %-10s %s" % (name, desc))
        rc, summary, fails, err = run_profile(name)
        if rc == 0 and summary:
            print("   OK   %s" % summary)
            continue
        bad += 1
        print("   NG   exit=%s  %s" % (rc, summary or "(要約行が出ていない)"))
        for f in fails[:5]:
            print("        %s" % f[:160])
        if not summary:
            # 要約すら出ていない=ランナー自身が途中で死んだ。ここが一番危ない。
            tail = [l for l in err.split("\n") if l.strip()][-4:]
            for l in tail:
                print("        %s" % l[:160])
    print("\n=== プロファイル %d 件中 %d 件が NG ===" % (len(names), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
