"""
gen_sbom.py — DuckNet L7 Security の SBOM(CycloneDX 1.5)を生成する。
====================================================================================
依存ゼロ(stdlib のみ)で再実行可能。出力: リポジトリ直下 `sbom.cdx.json`。
B2B/エンタープライズ調達で要求される機械可読の部品表(SBOM)を提供する。

実行:  python tools/gen_sbom.py
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_version() -> str:
    """pyproject.toml から version を読む(3.10 でも動くよう正規表現で・tomllib非依存)。"""
    path = os.path.join(ROOT, "pyproject.toml")
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        m = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.0.0"


def build_sbom() -> dict:
    ver = _read_version()
    app_ref = f"ducknet-security@{ver}"
    # 再現可能にする(同じ入力→同じ出力):
    #   · serialNumber は version から決定的に導出(uuid5)。
    #   · timestamp は SOURCE_DATE_EPOCH があればそれを使う(無ければ生成時刻)。
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
            if epoch else datetime.datetime.now(datetime.timezone.utc))
    now = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"ducknet-security@{ver}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {"components": [
                {"type": "application", "name": "ducknet gen_sbom",
                 "version": ver}]},
            "component": {
                "type": "application",
                "bom-ref": app_ref,
                "name": "ducknet-security",
                "version": ver,
                "purl": f"pkg:pypi/ducknet-security@{ver}",
                "description": ("Lightweight L7 DDoS/WAF security gateway "
                                "(stdlib only, zero runtime dependencies)."),
                "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}],
            },
        },
        # 配布物に同梱する第三者ライブラリは無い。実行環境(Python)のみ列挙。
        "components": [
            {
                "type": "platform",
                "bom-ref": "cpython",
                "name": "CPython",
                "scope": "required",
                "description": ("Python runtime; standard library only. "
                                "Not bundled with the product."),
                "licenses": [{"license": {"id": "PSF-2.0"}}],
                "properties": [{"name": "requires-python", "value": ">=3.10"}],
            },
        ],
        "dependencies": [
            {"ref": app_ref, "dependsOn": ["cpython"]},
            {"ref": "cpython", "dependsOn": []},
        ],
    }


def main() -> int:
    sbom = build_sbom()
    out = os.path.join(ROOT, "sbom.cdx.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"SBOM 生成: {out}")
    print(f"  format=CycloneDX {sbom['specVersion']}  "
          f"app=ducknet-security@{sbom['metadata']['component']['version']}  "
          f"components={len(sbom['components'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
