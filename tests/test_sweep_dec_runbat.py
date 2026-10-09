"""
test_sweep_dec_runbat.py — 日本語版 Windows(cp932 のコンソール)で run.bat を起動するたびに、
『'...' は、内部コマンドまたは外部コマンド、…』が 1 回出ていた件の回帰(Lite 版)。
====================================================================================
· run.bat は UTF-8 で書かれているが、chcp 65001 より前の行はコンソール既定のコードページ(cp932)で読まれる。
  cmd は読んだ文字をそのコードページでバイト数に換算し直して次の行の位置を決めるため、日本語の注釈(rem 行)が
  あると読み位置がずれ、注釈の切れ端(『...』)をコマンドとして実行していた。
· 注釈を ASCII だけにした。コマンド・echo する文言・chcp 65001 の扱いは変えていない(コマンド行がバイト単位で
  変わっていないことも、ここで固定する)。
· 本物の cmd.exe を、専用の(窓の無い)コンソール=既定のコードページのまま使う。偽の dataplane は受け取った
  引数と環境を出すだけ。入力は普通の文字列だけ。
"""
import codecs
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from unittest import SkipTest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIN = sys.platform.startswith("win")
_MARK = "DECRB"
# cmd が『コマンドとして認識できない』と言うときの文言(日本語版・英語版)。
_NEEDLES = ("内部コマンドまたは外部コマンド", "is not recognized as an internal or external command")
# 注釈行: rem / @rem(大文字小文字を問わない)と :: 。
_REM = re.compile(rb"^[ \t]*(@?rem([ \t].*)?|::.*)$", re.I)
# 注釈を英語化した時点の『注釈以外の行』(行末の改行を除いて \n で連結)の SHA-256。Full / Lite で同じ。
# コマンドや echo の文言を意図して変えたときは、ここを新しい値に更新する。
_CMD_LINES_SHA256 = "26aaf126e6e003b7aa711de01e30ab40df838cd4204f1157b141b6b91747d788"


def _bat_lines():
    with open(os.path.join(ROOT, "run.bat"), "rb") as f:
        return [ln[:-1] if ln.endswith(b"\r") else ln for ln in f.read().split(b"\n")]


def _bat_dir(d):
    """run.bat+普通の値の app.env+『受け取った引数と環境を出すだけ』の偽 dataplane を d に置く。"""
    shutil.copy(os.path.join(ROOT, "run.bat"), os.path.join(d, "run.bat"))
    with open(os.path.join(d, "app.env"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# comment line\nDUCKNET_SWEEP_DEC=plain value\n")
    pkg = os.path.join(d, "dataplane")
    os.makedirs(pkg)
    with open(os.path.join(pkg, "__init__.py"), "w", encoding="utf-8"):
        pass
    with open(os.path.join(pkg, "__main__.py"), "w", encoding="utf-8") as f:
        f.write("import json, os, sys\n"
                "env = {k.upper(): v for k, v in os.environ.items()\n"
                "       if k.upper().startswith('DUCKNET_SWEEP_') or k.upper() in ('PYTHONUTF8', 'PYTHONIOENCODING')}\n"
                "sys.stdout.write(%r + json.dumps({'argv': sys.argv[1:], 'env': env}))\n" % _MARK)


def _run_bat(d, py):
    """cmd.exe で run.bat --dec-arg を実行する。専用の(窓の無い)コンソールで動かすので、利用者が
    ダブルクリックしたときと同じ既定のコードページで始まり、このテストのコンソールには触れない。"""
    env = {k: v for k, v in os.environ.items()
           if k.upper() not in ("DUCKNET_ENV_FILE", "DUCKNET_PYTHON", "PYTHONPATH",
                                "PYTHONUTF8", "PYTHONIOENCODING")
           and not k.upper().startswith("DUCKNET_SWEEP_")}
    env["DUCKNET_PYTHON"] = py
    r = subprocess.run(["cmd.exe", "/d", "/c", os.path.join(d, "run.bat"), "--dec-arg"], cwd=d,
                       env=env, capture_output=True, timeout=120,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    out = r.stdout.decode("utf-8", "replace")
    got = json.loads(out[out.index(_MARK) + len(_MARK):].strip()) if _MARK in out else None
    return r, got


def _decodings(raw):
    """stderr を考えうる符号化(UTF-8・OEM・ANSI)で読んだもの。cmd の言葉はその時点のコードページで出る。"""
    outs = [raw.decode("utf-8", "replace")]
    for enc in ("oem", "mbcs"):                      # Windows だけにある codec(既定のコードページ)
        try:
            codecs.lookup(enc)
        except LookupError:
            continue
        outs.append(raw.decode(enc, "replace"))
    return outs


def _assert_no_stray_command(r, allowed_prefix=None):
    """cmd の『認識できないコマンド』が出ていないこと。言語に依らない形でも見る: stderr の行は
    allowed_prefix(run.bat 自身の echo)で始まるものだけ(None なら 1 行も無い)。"""
    texts = _decodings(r.stderr)
    for needle in _NEEDLES:
        assert not any(needle in t for t in texts), (needle, texts[-1][-400:])
    lines = [ln for ln in r.stderr.splitlines() if ln.strip()]
    if allowed_prefix is None:
        assert not lines, ("stderr に何か出た", texts[-1][-400:])
    else:
        assert all(ln.startswith(allowed_prefix) for ln in lines), ("余計な行", texts[-1][-400:])


def test_dec_runbat_starts_without_stray_command_error():
    """既定のコードページ(日本語版なら cp932)のまま起動しても、注釈の切れ端がコマンドとして実行されない。
    製品へは従来どおり引数・app.env の値・UTF-8 の既定が渡る。"""
    if not WIN:
        raise SkipTest("cmd.exe が無い環境")
    with tempfile.TemporaryDirectory(prefix="dec-runbat-") as d:
        _bat_dir(d)
        r, got = _run_bat(d, sys.executable)
    assert got is not None and r.returncode == 0, (r.returncode, r.stderr[-300:])
    assert got["argv"] == ["--dec-arg"], got
    assert got["env"] == {"DUCKNET_SWEEP_DEC": "plain value", "PYTHONUTF8": "1",
                          "PYTHONIOENCODING": "utf-8"}, got
    _assert_no_stray_command(r)


def test_dec_runbat_error_message_without_stray_command_error():
    """起動できない DUCKNET_PYTHON の案内(日本語の echo)を出す経路でも、余計なエラーが混ざらない
    (終了コードは従来どおり 9)。"""
    if not WIN:
        raise SkipTest("cmd.exe が無い環境")
    with tempfile.TemporaryDirectory(prefix="dec-runbat-") as d:
        _bat_dir(d)
        r, got = _run_bat(d, os.path.join(d, "no such dir", "python.exe"))
    assert got is None and r.returncode == 9, (r.returncode, r.stdout[-200:])
    assert b"DUCKNET_PYTHON" in r.stderr, r.stderr[-300:]
    _assert_no_stray_command(r, allowed_prefix=b"DuckNet: ")


def test_dec_runbat_comments_are_ascii():
    """run.bat の注釈は ASCII だけ(どの OS でも見る。cmd が読み位置を誤る元を戻さない)。"""
    bad = [i for i, ln in enumerate(_bat_lines(), 1) if _REM.match(ln) and any(c > 0x7F for c in ln)]
    assert not bad, "run.bat の注釈に ASCII 以外の文字がある行: %r" % (bad,)


def test_dec_runbat_only_comments_changed():
    """注釈を英語化したときにコマンド行(echo の文言を含む)をバイト単位で変えていない。"""
    lines = [ln for ln in _bat_lines() if not _REM.match(ln)]
    got = hashlib.sha256(b"\n".join(lines)).hexdigest()
    assert got == _CMD_LINES_SHA256, "run.bat の注釈以外の行が変わった: sha256=%s" % got
