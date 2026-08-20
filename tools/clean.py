"""
tools/clean.py — ビルド/テスト後の余計なデータを掃除(依存ゼロ・安全)
====================================================================================
リポジトリ直下のビルド副産物だけを削除する: __pycache__ / *.pyc / *.pyo /
build/ /dist/ / *.egg-info / .pytest_cache / .mypy_cache / .ruff_cache /
*.tmp。.git やソース・資産・ユーザ状態には触れない。

    python tools/clean.py            # 掃除を実行(削除件数を表示)
    python tools/clean.py --quiet    # 出力なし
"""
from __future__ import annotations

import os
import shutil
import sys

# 削除対象のディレクトリ名 / ファイル拡張子・サフィックス
_DIR_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist"}
_DIR_SUFFIX = (".egg-info",)
_FILE_SUFFIX = (".pyc", ".pyo", ".tmp")
_SKIP_TOP = {".git", ".venv", "venv"}        # 横断しない(VCS/仮想環境)


def clean(root: str) -> int:
    """root 配下のビルド副産物を削除し、削除した項目数を返す。"""
    root = os.path.abspath(root)
    removed = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        # トップ直下の .git / .venv 等には入らない
        if os.path.dirname(dirpath) == root or dirpath == root:
            dirnames[:] = [d for d in dirnames if d not in _SKIP_TOP]
        kill = [d for d in dirnames
                if d in _DIR_NAMES or d.endswith(_DIR_SUFFIX)]
        for d in kill:
            shutil.rmtree(os.path.join(dirpath, d), ignore_errors=True)
            removed += 1
            dirnames.remove(d)               # 削除済みには降りない
        for f in filenames:
            if f.endswith(_FILE_SUFFIX):
                try:
                    os.remove(os.path.join(dirpath, f))
                    removed += 1
                except OSError:
                    pass
    return removed


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    quiet = "--quiet" in argv or "-q" in argv
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    n = clean(root)
    if not quiet:
        print(f"clean: removed {n} build artifact(s) under {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
