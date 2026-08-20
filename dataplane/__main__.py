"""python -m dataplane → 製品本体(ゲートウェイ+ダッシュボード)を起動。"""
import sys

from .service import main

if __name__ == "__main__":
    sys.exit(main())
