"""
test_sweep_det3_misc.py — ヘッダへ書く設定文字列の検証(sweep: det3_misc 群・Lite)。
====================================================================================
· T3 origin_header(エッジトークンのヘッダ名)と open_redirect_safe_path(Location に書く値)は
  自由入力の文字列のまま HTTP ヘッダへ書かれていた。改行/NUL などの制御文字を拒否し、
  origin_header はヘッダ名のトークン(RFC 9110 tchar)に限る。保存済みの不正値は既定値へ戻して
  記録を残す。
(Full の T1=GUI の choice 項目・T2=正モデルの監査は、Lite に該当機能が無いので対象外。)
入力は普通の文字列と無害な目印だけを使う。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield, _DEFAULTS


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


_BAD_CTRL = ("X-Edge\r\nX-Other", "X-Edge\nB", "X-Edge\rB", "X-Edge\x00", "X-Edge\tB",
             "X-Edge\x7f", "X-Edge\x85")


def test_t3_origin_header_must_be_a_header_token():
    """改行や区切り文字を含むヘッダ名がそのまま要求ヘッダとして書かれていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for bad in _BAD_CTRL + ("", "X Edge", "X-Edge:", "X-Edge;a", "(X-Edge)", "X-Édge",
                                "X/Edge", '"X-Edge"'):
            r = sh.set_config(origin_header=bad)
            assert r["ok"] is False and r.get("rejected") == ["origin_header"], (bad, r["changed"])
            assert sh.cfg["origin_header"] == _DEFAULTS["origin_header"], bad
        for good in ("X-Edge", "X-Edge-Token", "x_edge.v2", "X-Edge!#$%&'*+^`|~"):
            r = sh.set_config(origin_header=good)
            assert r["ok"] is True and r["changed"] == {"origin_header": good}, (good, r.get("rejected"))
        # 前後の空白は名前の一部になれないので落とす(タブ/空白だけ)
        assert sh.set_config(origin_header=" X-Edge ")["changed"] == {"origin_header": "X-Edge"}
        assert sh.apply_config({"origin_header": "X-Edge\nB"}).get("rejected") == ["origin_header"]
        assert sh.cfg["origin_header"] == "X-Edge"


def test_t3_open_redirect_safe_path_rejects_control_chars():
    """Location に書く値に改行などの制御文字を受け付けていた。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for bad in tuple(s.replace("X-Edge", "/home") for s in _BAD_CTRL) + (
                "/a b", "https://www.example.com/", "//evil.example/", r"/\evil.example"):
            r = sh.set_config(open_redirect_safe_path=bad)
            assert r["ok"] is False and r.get("rejected") == ["open_redirect_safe_path"], (
                bad, r["changed"])
            assert sh.cfg["open_redirect_safe_path"] == "/", bad
        for good in ("/home", "/login?next=%2F", "/a b"):
            r = sh.set_config(open_redirect_safe_path=good)
            assert r["changed"] == {"open_redirect_safe_path": good}, (good, r.get("rejected"))


def test_t3_persisted_values_load_and_invalid_ones_fall_back_with_a_record():
    """保存済みの正しい値は読み、制御文字入りの旧値は既定値へ戻して記録する(起動は止めない)。"""
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.set_config(origin_header="X-Edge", open_redirect_safe_path="/home",
                             block_score=150)["ok"] is True
        sh2 = NetShield(state_dir=d)
        assert sh2.cfg["origin_header"] == "X-Edge"
        assert sh2.cfg["open_redirect_safe_path"] == "/home"
        assert not [e for e in sh2.events(200) if e.get("kind") == "cfg_load_rejected"]
        with sh2._lock:                       # 旧版が検証せず保存した値(署名は正しい)
            sh2.cfg["origin_header"] = "X-Edge\nB"
            sh2.cfg["open_redirect_safe_path"] = "/home\r\nB"
            sh2._save()
        sh3 = NetShield(state_dir=d)
        assert sh3.cfg["origin_header"] == _DEFAULTS["origin_header"]
        assert sh3.cfg["open_redirect_safe_path"] == _DEFAULTS["open_redirect_safe_path"]
        assert sh3.cfg["block_score"] == 150                  # 他の保存値は生きる
        ev = [e for e in sh3.events(200) if e.get("kind") == "cfg_load_rejected"]
        assert len(ev) == 1, sh3.events(200)
        assert ev[0]["keys"] == ["open_redirect_safe_path", "origin_header"], ev
        # 値そのもの(制御文字入り)は記録に載せない
        assert all("\n" not in str(v) and "\r" not in str(v) for v in ev[0].values()), ev
