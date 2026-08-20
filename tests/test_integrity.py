"""
test_integrity.py — ファイルすり替え検知と強制修復(evolution #48)。
====================================================================================
不変ファイル(エージェントのコード/固定 config)の差し替えを署名付きマニフェストで検知し、
ベースラインの既知良好複製から強制復元することを回帰から守る。マニフェスト自体のすり替えは
復元を拒否して fail-safe を促す。
"""
import os
import tempfile

from dataplane.engine.core.integrity import (
    file_digest, build_manifest, sign_manifest, verify_signature, verify_entry,
    IntegrityMonitor, SelfIntegrity, critical_module_paths,
)


def _w(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def test_file_digest_and_missing():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.txt")
        _w(p, "hello")
        dig = file_digest(p)
        assert len(dig) == 64                       # sha256 hex
        assert file_digest(os.path.join(d, "nope")) == ""   # 欠落=空


def test_manifest_sign_and_verify():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.txt")
        _w(p, "x")
        man = build_manifest([p])
        assert os.path.abspath(p) in man
        sig = sign_manifest(man, b"secret")
        assert verify_signature(man, sig, b"secret")
        assert not verify_signature(man, sig, b"other")     # 鍵違い
        man2 = dict(man); man2["__extra__"] = {"sha256": "z"}
        assert not verify_signature(man2, sig, b"secret")   # マニフェスト改変


def test_verify_entry_states():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.txt")
        _w(p, "v1")
        man = build_manifest([p])
        entry = man[os.path.abspath(p)]
        assert verify_entry(p, entry) == "ok"
        _w(p, "v2-tampered")
        assert verify_entry(p, entry) == "modified"
        os.remove(p)
        assert verify_entry(p, entry) == "missing"


def test_baseline_check_repair_cycle():
    with tempfile.TemporaryDirectory() as d:
        code = os.path.join(d, "pipeline.py")
        _w(code, "WAF_LOGIC = 'real'\n")
        bdir = os.path.join(d, ".baseline")
        mon = IntegrityMonitor([code], bdir, secret=b"k")
        assert mon.baseline()["ok"]
        # 健全
        rep = mon.check()
        assert rep["manifest_valid"] and not rep["tampered"]
        assert os.path.abspath(code) in rep["ok_files"]
        # すり替え(WAF を骨抜きに)
        _w(code, "WAF_LOGIC = 'neutered'  # attacker swap\n")
        rep = mon.check()
        assert rep["tampered"] and os.path.abspath(code) in rep["modified"]
        # 強制修復
        fix = mon.repair()
        assert fix["ok"] and os.path.abspath(code) in fix["restored"]
        with open(code, encoding="utf-8") as f:
            assert f.read() == "WAF_LOGIC = 'real'\n"        # 既知良好へ復元
        assert not mon.check()["tampered"]


def test_repair_restores_missing_file():
    with tempfile.TemporaryDirectory() as d:
        rules = os.path.join(d, "rules.json")
        _w(rules, '{"sig":"xss"}')
        mon = IntegrityMonitor([rules], os.path.join(d, ".bl"), secret=b"k")
        mon.baseline()
        os.remove(rules)                            # IoC/署名定義の削除(無力化)
        rep = mon.check()
        assert os.path.abspath(rules) in rep["missing"]
        fix = mon.repair()
        assert os.path.exists(rules) and fix["ok"]


def test_manifest_tamper_refuses_repair_failsafe():
    with tempfile.TemporaryDirectory() as d:
        code = os.path.join(d, "c.py")
        _w(code, "ok\n")
        bdir = os.path.join(d, ".bl")
        mon = IntegrityMonitor([code], bdir, secret=b"k")
        mon.baseline()
        _w(code, "tampered\n")
        # マニフェスト自体をすり替え(署名と不整合に)
        import json
        mpath = os.path.join(bdir, "manifest.json")
        with open(mpath, encoding="utf-8") as f:
            doc = json.load(f)
        # 攻撃者が改竄後ファイルのハッシュでマニフェストを書換え(でも署名鍵は持たない)
        ap = os.path.abspath(code)
        doc["manifest"][ap]["sha256"] = file_digest(code)
        with open(mpath, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        rep = mon.check()
        assert rep["manifest_valid"] is False       # 署名不一致=マニフェストすり替え検知
        fix = mon.repair()
        assert fix["ok"] is False and fix.get("fail_safe")  # 信頼できない=復元拒否


def test_baseline_self_modules_roundtrip():
    # 実在のエージェントコードを baseline して健全判定できる(統合の現実性)。
    import dataplane.engine.lifeform.pipeline as P
    import dataplane.engine.services.proxy as PX
    with tempfile.TemporaryDirectory() as d:
        mon = IntegrityMonitor([P.__file__, PX.__file__],
                               os.path.join(d, ".bl"), secret=b"k")
        mon.baseline()
        rep = mon.check()
        assert rep["manifest_valid"] and not rep["tampered"]
        assert len(rep["ok_files"]) == 2


def test_backup_dirs_restore_when_primary_snapshot_lost():
    # 一次 snapshot が壊れても、別の場所のバックアップから検証付きで復元できる(多重化)。
    with tempfile.TemporaryDirectory() as d:
        code = os.path.join(d, "core.py")
        _w(code, "GOOD = 1\n")
        bdir = os.path.join(d, ".bl")
        backup = os.path.join(d, "backup_loc")
        mon = IntegrityMonitor([code], bdir, secret=b"k", backup_dirs=[backup])
        mon.baseline()
        # 一次 snapshot を破壊(攻撃者が baseline も狙う)+ 本体すり替え
        from dataplane.engine.core.integrity import _safe_name
        os.remove(os.path.join(bdir, "snapshots", _safe_name(os.path.abspath(code))))
        _w(code, "GOOD = 0  # swapped\n")
        fix = mon.repair()
        assert fix["ok"] and os.path.abspath(code) in fix["restored"]
        with open(code, encoding="utf-8") as f:
            assert f.read() == "GOOD = 1\n"           # バックアップ場所から復元


def test_repair_rejects_tampered_backup_copy():
    # バックアップ複製自体が改竄されていたら、ハッシュ不一致で信頼しない(verify-before-trust)。
    with tempfile.TemporaryDirectory() as d:
        from dataplane.engine.core.integrity import _safe_name
        code = os.path.join(d, "core.py")
        _w(code, "GOOD = 1\n")
        bdir = os.path.join(d, ".bl")
        backup = os.path.join(d, "backup_loc")
        mon = IntegrityMonitor([code], bdir, secret=b"k", backup_dirs=[backup])
        mon.baseline()
        safe = _safe_name(os.path.abspath(code))
        # 一次 snapshot とバックアップ複製の *両方* を汚染(=信頼できる復元元が無い)
        _w(os.path.join(bdir, "snapshots", safe), "EVIL\n")
        _w(os.path.join(backup, "snapshots", safe), "EVIL\n")
        _w(code, "GOOD = 0\n")
        fix = mon.repair()
        assert os.path.abspath(code) in fix["failed"]   # 汚染複製は採用しない
        assert not fix["ok"]


def test_integrity_baseline_cli(capfd=None):
    # #59: --integrity-baseline は deploy 時に既知良好を固定(初回 TOFU 回避)、--integrity-check は検査。
    import os as _os
    from dataplane.service import main
    with tempfile.TemporaryDirectory() as d:
        old = _os.environ.get("CHICKENNET_STATE_DIR")
        _os.environ["CHICKENNET_STATE_DIR"] = d
        try:
            assert main(["--integrity-baseline"]) == 0       # 固定成功
            assert _os.path.exists(_os.path.join(d, ".integrity", "manifest.json"))
            assert main(["--integrity-check"]) == 0          # 健全(改竄なし)
        finally:
            if old is None:
                _os.environ.pop("CHICKENNET_STATE_DIR", None)
            else:
                _os.environ["CHICKENNET_STATE_DIR"] = old


def test_critical_module_paths_includes_core():
    paths = critical_module_paths()
    assert paths                                    # import 済みの中核モジュールが集まる
    assert any(p.endswith("pipeline.py") for p in paths)
    assert any(p.endswith("proxy.py") for p in paths)


def test_self_integrity_tofu_then_detect_and_repair():
    with tempfile.TemporaryDirectory() as d:
        code = os.path.join(d, "mod.py")
        _w(code, "CHECK = True\n")
        si = SelfIntegrity(d, paths=[code], repair=True, secret=b"k")
        # 初回 = TOFU ベースライン確立
        r0 = si.tick()
        assert r0["event"] == "baseline"
        # 健全
        assert si.tick()["event"] == "ok"
        # すり替え → 検知 + 強制復元
        _w(code, "CHECK = False  # neutered\n")
        r2 = si.tick()
        assert r2["event"] == "tamper"
        assert r2["repair"]["ok"]
        with open(code, encoding="utf-8") as f:
            assert f.read() == "CHECK = True\n"
        # 復元後は再び健全
        assert si.tick()["event"] == "ok"


def test_self_integrity_repair_disabled_reports_only():
    with tempfile.TemporaryDirectory() as d:
        code = os.path.join(d, "mod.py")
        _w(code, "v1\n")
        si = SelfIntegrity(d, paths=[code], repair=False, secret=b"k")
        si.tick()                                   # baseline
        _w(code, "v2\n")
        r = si.tick()
        assert r["event"] == "tamper" and "repair" not in r
        with open(code, encoding="utf-8") as f:
            assert f.read() == "v2\n"               # repair=False は復元しない(報告のみ)
