"""
test_paranoia.py — 検知の段階的厳格度(evolution #16)。
====================================================================================
1ダイヤル(1=保守〜4=最大)で高FPの任意シグネチャを段階的に一括ON にすること、レベルごとに
inspect の検知が変わること(レベルが上がると追加シグネチャが反応)、clamp・永続化を回帰から守る。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield


def _hits(level, query, sig):
    """新規 NetShield を level に設定して query を1回 inspect し、sig の累積ヒット数を返す。"""
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        sh.enable()
        if level != 1:
            sh.set_paranoia(level)
        sh.inspect("9.9.9.9", path="/r", query=query)
        return sh.metrics()["sig_hits"].get(sig, 0)


def test_default_is_level1_no_optional():
    with tempfile.TemporaryDirectory() as tmp:
        st = NetShield(state_dir=tmp).paranoia_status()
        assert st["paranoia"] == 1 and st["enabled_optional"] == []


def test_set_paranoia_tiers_and_clamp():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        assert sh.set_paranoia(2)["enabled_optional"] == ["redirect"]
        assert sh.set_paranoia(3)["enabled_optional"] == ["redirect", "ssrf_internal"]
        assert sh.set_paranoia(4)["enabled_optional"] == ["redirect", "ssrf_internal", "ssti"]
        assert sh.set_paranoia(0)["paranoia"] == 1          # 下限 clamp
        assert sh.set_paranoia(9)["paranoia"] == 4          # 上限 clamp
        assert sh.set_paranoia("x")["paranoia"] == 1        # 不正入力→1


def test_redirect_signature_gated_by_level2():
    q = "next=//evil.example/path"                          # =// プロトコル相対リダイレクト
    assert _hits(1, q, "redirect") == 0                     # L1: 評価されない
    assert _hits(2, q, "redirect") >= 1                     # L2: 反応


def test_ssrf_internal_gated_by_level3():
    q = "u=http://127.0.0.1/admin"                          # 内部宛先(SSRF)
    assert _hits(2, q, "ssrf_internal") == 0                # L2: まだ評価されない
    assert _hits(3, q, "ssrf_internal") >= 1                # L3: 反応


def test_ssti_gated_by_level4():
    q = "name={{7*7}}"                                       # テンプレート注入
    assert _hits(3, q, "ssti") == 0                          # L3: まだ評価されない
    assert _hits(4, q, "ssti") >= 1                          # L4: 反応


def test_paranoia_persists_across_reload():
    with tempfile.TemporaryDirectory() as tmp:
        NetShield(state_dir=tmp).set_paranoia(3)
        sh2 = NetShield(state_dir=tmp)                       # 永続化を読み直す
        assert sh2.cfg["paranoia"] == 3
        assert sh2.cfg["optional_sigs"].get("ssrf_internal") is True
        assert sh2.paranoia_status()["enabled_optional"] == ["redirect", "ssrf_internal"]


def test_manual_optional_toggle_still_works_after_preset():
    with tempfile.TemporaryDirectory() as tmp:
        sh = NetShield(state_dir=tmp)
        sh.set_paranoia(2)                                   # プリセットで redirect ON
        sh.set_optional_signature("ssti", True)             # 個別微調整は上乗せ可
        opt = sh.cfg["optional_sigs"]
        assert opt.get("redirect") is True and opt.get("ssti") is True
