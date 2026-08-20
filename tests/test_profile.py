"""
test_stealth.py — ステルス運用(低プロファイル化)の検証
====================================================================================
防御の存在を侵入者から特定されにくくする層: 偽装名の適用(no-op安全)・状態dirの移設・
管理画面/Serverヘッダ/遮断ページからの製品名秘匿。OS非侵襲・self-only であることが前提。
"""
import os
import tempfile
import urllib.request

import dataplane.engine.lifeform.policy as FW
import dataplane.engine.lifeform.pipeline as ND
from dataplane import profile as stealth
from dataplane.admin import AdminDashboard
from dataplane.engine.core.atomic_io import default_state_dir
from dataplane.engine.services.proxy import _block_page


def test_cover_thread_name_follows_stealth():
    # #81: スレッド名がステルス(CHICKENNET_COVER)に従う。未設定=従来 'chickennet-'。
    saved = os.environ.get("CHICKENNET_COVER")
    try:
        os.environ.pop("CHICKENNET_COVER", None)
        assert stealth.cover_thread_name("edge") == "chickennet-edge"   # 非ステルス=従来
        os.environ["CHICKENNET_COVER"] = "System Health Monitor"
        n = stealth.cover_thread_name("edge")
        assert n == "system-edge" and "chickennet" not in n            # 先頭語・小文字・露出なし
        os.environ["CHICKENNET_COVER"] = "Disk-Indexer!!"               # 記号はサニタイズ
        assert stealth.cover_thread_name("gsp") == "diskindexer-gsp"
    finally:
        if saved is None:
            os.environ.pop("CHICKENNET_COVER", None)
        else:
            os.environ["CHICKENNET_COVER"] = saved


def test_cover_brand():
    saved = os.environ.get("CHICKENNET_COVER")
    try:
        os.environ.pop("CHICKENNET_COVER", None)
        assert stealth.cover_brand("ChickenNet X") == "ChickenNet X"     # 未設定=既定(製品名可)
        os.environ["CHICKENNET_COVER"] = "Disk Indexer"
        assert stealth.cover_brand("ChickenNet X") == "Disk Indexer"   # ステルス=cover
    finally:
        if saved is None:
            os.environ.pop("CHICKENNET_COVER", None)
        else:
            os.environ["CHICKENNET_COVER"] = saved


def test_guard_thread_name_is_covered():
    from dataplane.engine.services.proxy import AsyncEdgeGuard
    saved = os.environ.get("CHICKENNET_COVER")
    os.environ["CHICKENNET_COVER"] = "System Health Monitor"
    try:
        g = AsyncEdgeGuard(backend_port=9, listen_port=0)
        assert g.start().get("ok")
        try:
            assert g._thread.name == "system-edge" and "chickennet" not in g._thread.name
        finally:
            g.stop()
    finally:
        if saved is None:
            os.environ.pop("CHICKENNET_COVER", None)
        else:
            os.environ["CHICKENNET_COVER"] = saved


def test_stealth_apply_is_safe_and_reports():
    # 偽装名の適用は best-effort・例外を投げない。適用手段名のリストを返す。
    r = stealth.apply("System Health Monitor")
    assert r["cover"] == "System Health Monitor"
    assert isinstance(r["applied"], list)        # 環境により空でも可(no-op安全)


def test_default_state_dir_relocatable_by_env():
    old = os.environ.get("CHICKENNET_STATE_DIR")
    try:
        os.environ["CHICKENNET_STATE_DIR"] = os.path.join(tempfile.gettempdir(), "sx")
        assert default_state_dir().endswith("sx")     # 状態の置き場を秘匿/移設できる
    finally:
        if old is None:
            os.environ.pop("CHICKENNET_STATE_DIR", None)
        else:
            os.environ["CHICKENNET_STATE_DIR"] = old
    assert default_state_dir().endswith(os.path.join(".cache", "dataplane"))  # 中立な既定


def test_block_page_hides_brand_via_cover_env():
    old = os.environ.get("CHICKENNET_COVER")
    try:
        os.environ["CHICKENNET_COVER"] = "System Health Monitor"
        page = _block_page({"remain_sec": 60})
        assert b"System Health Monitor" in page
        assert b"ChickenNet L7 Security" not in page      # 遮断ページから製品が露見しない
    finally:
        if old is None:
            os.environ.pop("CHICKENNET_COVER", None)
        else:
            os.environ["CHICKENNET_COVER"] = old


def test_admin_brand_override_hides_product():
    with tempfile.TemporaryDirectory() as tmp:
        ofw, osh = FW._FW, ND._SHIELD
        FW._FW = FW.AppFirewall(state_dir=tmp)
        ND._SHIELD = ND.NetShield(state_dir=tmp)
        adm = AdminDashboard(host="127.0.0.1", port=0, state_dir=tmp,
                             brand="System Health Monitor", logo="⚙",
                             subtitle="ステータス")
        info = adm.start()
        try:
            r = urllib.request.urlopen(info["url"] + "/")
            html = r.read()
            assert b"System Health Monitor" in html      # 偽装名で表示
            assert b"ChickenNet L7 Security" not in html    # 製品名は出さない
            # Server ヘッダも偽装名(Python/BaseHTTP のバージョンを晒さない)
            assert r.headers.get("Server") == "System Health Monitor"
        finally:
            adm.stop()
            FW._FW, ND._SHIELD = ofw, osh


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")
