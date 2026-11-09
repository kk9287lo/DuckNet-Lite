"""
test_signed_state.py — 可変状態ファイルの改竄耐性(HMAC署名・evolution #52)。
====================================================================================
攻撃者がホスト上で blocklist.json を書き換えて自分を unban したり、rules.json を空にして
検知を無効化しても、署名不一致で『改竄』として弾き安全側へフェイルセーフすることを回帰から守る。
旧来の無署名ファイルは生値を使いつつ署名済みへ自動移行する。
"""
import json
import os
import errno
import tempfile
import threading
from unittest import SkipTest
from unittest.mock import patch

import dataplane.engine.lifeform.pipeline as pipeline
from dataplane.engine.core.signed_state import (
    persistent_key, sign_payload, verify_payload, write_signed_json, read_signed_json,
)


def test_persistent_key_env_and_generated():
    with tempfile.TemporaryDirectory() as d:
        env_key = "A" * 32
        os.environ["DUCKNET_STATE_KEY"] = env_key
        try:
            assert persistent_key(d) == env_key.encode("ascii")
        finally:
            del os.environ["DUCKNET_STATE_KEY"]
        k1 = persistent_key(d)                       # 生成+永続
        k2 = persistent_key(d)                       # 同ディレクトリ=同じ鍵(再起動跨ぎ検証可)
        assert k1 == k2 and len(k1) == 32


def test_failed_key_creation_refuses_ephemeral_state():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        with patch.object(ss, "_create_key_file", side_effect=OSError("disk full")):
            try:
                pipeline.NetShield(state_dir=d)
            except OSError:
                pass
            else:
                raise AssertionError("the shield started with a volatile signing key")
        assert not os.path.exists(os.path.join(d, "state.json"))
        first = ss.persistent_key(d)
        assert len(first) == 32 and ss.persistent_key(d) == first


def test_atomic_file_fsync_failure_keeps_old_bytes_and_reports_failure():
    from dataplane.engine.core import atomic_io
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "state.txt")
        assert atomic_io.atomic_write_text(path, "old") is True
        with patch.object(atomic_io.os, "fsync",
                          side_effect=OSError(errno.EIO, "file sync failed")):
            assert atomic_io.atomic_write_text(path, "new") is False
        with open(path, encoding="utf-8") as handle:
            assert handle.read() == "old"
        assert sorted(os.listdir(d)) == ["state.txt"]
        assert atomic_io.atomic_write_text(path, "new") is True
        with open(path, encoding="utf-8") as handle:
            assert handle.read() == "new"


def test_key_file_fsync_failure_never_publishes_a_volatile_key():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, ".statekey")
        for force_fallback in (False, True):
            real_fsync = os.fsync
            calls = [0]

            def fail_second_sync(fd):
                calls[0] += 1
                if calls[0] == 2:
                    raise OSError(errno.ENOSPC, "fallback key sync failed")
                return real_fsync(fd)

            failure = fail_second_sync if force_fallback else OSError(errno.EIO, "tmp sync failed")
            with patch.object(ss.os, "fsync", side_effect=failure):
                if force_fallback:
                    with patch.object(ss.os, "link",
                                      side_effect=OSError(errno.ENOTSUP, "no hardlink")):
                        try:
                            ss.load_or_create_key(key_path)
                        except OSError:
                            pass
                        else:
                            raise AssertionError("volatile key was accepted")
                else:
                    try:
                        ss.load_or_create_key(key_path)
                    except OSError:
                        pass
                    else:
                        raise AssertionError("volatile key was accepted")
            assert os.listdir(d) == [".statekey.lock"]
            assert calls[0] == (2 if force_fallback else 0)
        key = ss.load_or_create_key(key_path)
        assert len(key) == 32 and ss.load_or_create_key(key_path) == key


def test_missing_state_defaults_on_but_signed_explicit_off_persists():
    from dataplane.engine.core import signed_state as ss
    from dataplane.engine.lifeform.policy import AppFirewall
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        fw = AppFirewall(state_dir=d)
        assert sh.is_enabled() and fw.is_enabled()
        assert sh.disable()["ok"] and fw.disable()["ok"]
        assert not pipeline.NetShield(state_dir=d).is_enabled()
        assert not AppFirewall(state_dir=d).is_enabled()
        assert sh.enable()["ok"] and fw.enable()["ok"]
        for name in ("state.json", "state.json.hw", "acl.json", "acl.json.hw"):
            os.unlink(os.path.join(d, name))
        ss._MEM_HW.clear()
        ss._MEM_MIN_SV.clear()
        restored_sh = pipeline.NetShield(state_dir=d)
        restored_fw = AppFirewall(state_dir=d)
        assert restored_sh.is_enabled() and restored_fw.is_enabled()
        assert restored_fw.evaluate("1.1.1.1")["action"] == "deny"


def test_root_does_not_trust_another_users_local_state_key():
    from types import SimpleNamespace
    import stat
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, ".statekey")
        with open(path, "wb") as f:
            f.write(b"k" * 32)
        owned = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
        foreign = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000)
        with patch.object(ss.os, "name", "posix"), \
                patch.object(ss.os, "geteuid", return_value=0, create=True), \
                patch.object(ss.os, "fstat", return_value=foreign):
            assert ss._read_key_file(path) is None
        with patch.object(ss.os, "name", "posix"), \
                patch.object(ss.os, "geteuid", return_value=0, create=True), \
                patch.object(ss.os, "fstat", return_value=owned):
            assert ss._read_key_file(path) == b"k" * 32


def test_posix_real_key_mode_repair_and_symlink_refusal():
    if os.name != "posix":
        raise SkipTest("POSIX の所有者・mode・symlink を持つ FS が必要")
    import stat
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, ".statekey")
        key = ss.load_or_create_key(path)
        assert len(key) == 32 and stat.S_IMODE(os.stat(path).st_mode) == 0o600
        os.chmod(path, 0o644)
        assert ss.load_or_create_key(path) == key
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

        target = os.path.join(d, "known-key")
        with open(target, "wb") as f:
            f.write(b"x" * 32)
        alias = os.path.join(d, "linked-key")
        os.symlink(target, alias)
        assert ss._read_key_file(alias) is None
        try:
            ss.load_or_create_key(alias)
        except OSError:
            pass
        else:
            raise AssertionError("symlink key was accepted")
        with open(target, "rb") as f:
            assert f.read() == b"x" * 32


def test_posix_fifo_key_is_rejected_without_blocking_startup():
    if os.name != "posix" or not hasattr(os, "mkfifo"):
        raise SkipTest("FIFO を作れる POSIX FS が必要")
    import subprocess
    import sys
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        fifo = os.path.join(d, ".statekey")
        os.mkfifo(fifo, 0o600)
        code = ("import sys\n"
                "from dataplane.engine.core.signed_state import load_or_create_key\n"
                "try:\n"
                " load_or_create_key(sys.argv[1])\n"
                "except OSError:\n"
                " print('rejected')\n"
                "else:\n"
                " print('accepted')\n")
        try:
            result = subprocess.run([sys.executable, "-c", code, fifo],
                                    capture_output=True, text=True, timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError("FIFO key stalled startup in os.open") from exc
        assert result.returncode == 0 and result.stdout.strip() == "rejected", result
        assert os.path.exists(fifo)

        # 通常ファイルの鍵は同じ経路で作成・再利用できる。
        normal = os.path.join(d, "normal-key")
        key = ss.load_or_create_key(normal)
        assert len(key) == 32 and ss.load_or_create_key(normal) == key


def test_posix_fifo_swap_after_key_lstat_does_not_block():
    if os.name != "posix" or not hasattr(os, "mkfifo"):
        raise SkipTest("FIFO を作れる POSIX FS が必要")
    import subprocess
    import sys
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, ".statekey")
        fifo = os.path.join(d, "replacement-fifo")
        with open(key_path, "wb") as f:
            f.write(b"k" * 32)
        os.mkfifo(fifo, 0o600)
        code = ("import os,sys\n"
                "from dataplane.engine.core import signed_state as ss\n"
                "real_open = os.open\n"
                "def swap(path, flags, *args):\n"
                " if path == sys.argv[1]: os.replace(sys.argv[2], path)\n"
                " return real_open(path, flags, *args)\n"
                "ss.os.open = swap\n"
                "print('rejected' if ss._read_key_file(sys.argv[1]) is None else 'accepted')\n")
        try:
            result = subprocess.run([sys.executable, "-c", code, key_path, fifo],
                                    capture_output=True, text=True, timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError("lstat/open FIFO swap stalled startup") from exc
        assert result.returncode == 0 and result.stdout.strip() == "rejected", result


def test_posix_real_foreign_owned_key_and_state_dir_are_rejected():
    if os.name != "posix" or os.geteuid() != 0:
        raise SkipTest("別 UID 所有の実ファイルを作れる POSIX root が必要")
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, ".statekey")
        key = ss.load_or_create_key(key_path)
        assert ss.load_or_create_key(key_path) == key       # 正規所有者の対照
        os.chown(key_path, 10001, -1)
        assert ss._read_key_file(key_path) is None
        try:
            ss.load_or_create_key(key_path)
        except OSError:
            pass
        else:
            raise AssertionError("foreign-owned state key was accepted")

        foreign = os.path.join(d, "foreign-dir")
        os.mkdir(foreign, 0o700)
        os.chown(foreign, 10001, -1)
        try:
            ss.persistent_key(foreign)
        except OSError:
            pass
        else:
            raise AssertionError("foreign-owned state directory was accepted")
        assert not os.path.exists(os.path.join(foreign, ".statekey"))


def test_posix_real_state_dir_modes_and_ancestor_boundary():
    if os.name != "posix":
        raise SkipTest("POSIX の所有者・mode を持つ FS が必要")
    import stat
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        private = os.path.join(d, "private")
        os.mkdir(private, 0o755)
        os.chmod(private, 0o755)                 # umask に依らず既存の公開読取 mode を作る
        assert len(ss.persistent_key(private)) == 32
        assert stat.S_IMODE(os.stat(private).st_mode) == 0o755

        # HOME や広い既存ディレクトリを誤指定しても権限を勝手に変えない。
        broad = os.path.join(d, "broad")
        os.mkdir(broad, 0o755)
        os.chmod(broad, 0o755)
        for i in range(33):
            with open(os.path.join(broad, f"file-{i}"), "w", encoding="utf-8"):
                pass
        assert len(ss.persistent_key(broad)) == 32
        assert stat.S_IMODE(os.stat(broad).st_mode) == 0o755

        writable = os.path.join(d, "writable")
        os.mkdir(writable, 0o700)
        os.chmod(writable, 0o777)
        try:
            ss.persistent_key(writable)
        except OSError:
            pass
        else:
            raise AssertionError("world-writable state directory was accepted")
        assert not os.path.exists(os.path.join(writable, ".statekey"))

        ancestor = os.path.join(d, "unsafe-parent")
        os.mkdir(ancestor, 0o700)
        child = os.path.join(ancestor, "state")
        os.mkdir(child, 0o700)
        os.chmod(ancestor, 0o777)
        try:
            ss.persistent_key(child)
        except OSError:
            pass
        else:
            raise AssertionError("world-writable ancestor was accepted")

        link = os.path.join(d, "state-link")
        os.symlink(private, link)
        try:
            ss.persistent_key(link)
        except OSError:
            pass
        else:
            raise AssertionError("symlink state directory was accepted")


def test_posix_real_engines_and_service_probe_create_0700_without_changing_0755():
    if os.name != "posix":
        raise SkipTest("POSIX の実ディレクトリ mode が必要")
    import stat
    from dataplane.engine.lifeform.policy import AppFirewall
    from dataplane.engine.core.atomic_io import append_jsonl
    from dataplane import service

    makers = (("shield", lambda path: pipeline.NetShield(state_dir=path)),
              ("firewall", lambda path: AppFirewall(state_dir=path)),
              ("service", lambda path: service.state_dir_writable(path)),
              ("acl-log", lambda path: append_jsonl(os.path.join(path, "audit.jsonl"),
                                                    {"action": "test"})))
    with tempfile.TemporaryDirectory() as parent:
        for name, make in makers:
            fresh = os.path.join(parent, name + "-new")
            assert not os.path.exists(fresh)
            assert make(fresh) is not False
            assert stat.S_IMODE(os.stat(fresh).st_mode) == 0o700, name

            legacy = os.path.join(parent, name + "-legacy")
            os.mkdir(legacy, 0o755)
            os.chmod(legacy, 0o755)             # umask に依存させない
            assert make(legacy) is not False
            assert stat.S_IMODE(os.stat(legacy).st_mode) == 0o755, name


def test_posix_real_lock_symlink_cannot_redirect_state_write():
    if os.name != "posix":
        raise SkipTest("POSIX O_NOFOLLOW が必要")
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        state = os.path.join(d, "state.json")
        target = os.path.join(d, "outside")
        with open(target, "wb") as f:
            f.write(b"untouched")
        os.symlink(target, state + ".lock")
        assert ss.write_signed_json(state, {"enabled": False}, b"k" * 32) is False
        assert not os.path.exists(state)
        with open(target, "rb") as f:
            assert f.read() == b"untouched"


def test_sign_verify_roundtrip():
    obj = {"bans": {"1.2.3.4": {"until": 999}}}
    sig = sign_payload(obj, b"k")
    assert verify_payload(obj, sig, b"k")
    assert not verify_payload(obj, sig, b"other")    # 鍵違い
    obj2 = {"bans": {"1.2.3.4": {"until": 0}}}        # 攻撃者が unban に書き換え
    assert not verify_payload(obj2, sig, b"k")


def test_write_read_signed_ok():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        payload = {"bans": {"9.9.9.9": {"until": 123}}}
        assert write_signed_json(p, payload, b"k")
        status, val = read_signed_json(p, b"k")
        assert status == "ok" and val == payload


def test_read_detects_tampered_payload():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        write_signed_json(p, {"bans": {"9.9.9.9": {"until": 123}}}, b"k")
        # 攻撃者がエンベロープ内の payload を書き換え(署名はそのまま=持っていない)
        with open(p, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"] = {"bans": {}}               # 全 unban を狙う
        with open(p, "w", encoding="utf-8") as f:
            json.dump(env, f)
        status, val = read_signed_json(p, b"k", default="SAFE")
        assert status == "tampered" and val == "SAFE"   # 改竄→フェイルセーフ


def test_read_legacy_unsigned():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "rules.json")
        with open(p, "w", encoding="utf-8") as f:     # 旧来の無署名プレーン
            json.dump({"signatures": [{"pattern": "x"}]}, f)
        status, val = read_signed_json(p, b"k")
        assert status == "unsigned" and val["signatures"][0]["pattern"] == "x"


def test_read_missing():
    with tempfile.TemporaryDirectory() as d:
        status, val = read_signed_json(os.path.join(d, "nope.json"), b"k", default={})
        assert status == "missing" and val == {}


# ── NetShield 統合 ──────────────────────────────────────────────────────
def _fresh_shield(d):
    from dataplane.engine.lifeform.pipeline import NetShield
    sh = NetShield(state_dir=d)
    sh.cfg["persist_bans"] = True
    return sh


def test_config_save_failure_keeps_live_and_persisted_protection():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.enable()["ok"]
        assert sh.set_path_limits([{"path": "/login", "rate": 0.5}])["ok"]
        before = dict(sh.cfg)
        changes = (
            lambda: sh.disable(),
            lambda: sh.set_config(mode="audit", rate_per_sec=0.1),
            lambda: sh.set_optional_signature("ssrf_internal", True),
            lambda: sh.set_paranoia(3),
            lambda: sh.set_path_limits([]),
            lambda: sh.set_blocked_methods(["TRACE"]),
            lambda: sh.set_sec_headers_enabled(True),
        )
        with patch.object(pipeline, "write_signed_json", return_value=False):
            for change in changes:
                result = change()
                assert result["ok"] is False, result
                assert sh.cfg == before, result
                assert sh.verify_cfg_integrity()["tampered"] is False
            result = sh.apply_config({"mode": "audit", "path_limits": []})
            assert set(result["rejected"]) == {"mode", "path_limits"}, result
            assert result["applied"] == [] and sh.cfg == before
        assert pipeline.NetShield(state_dir=d).cfg == before

    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.disable()["ok"]
        with patch.object(pipeline, "write_signed_json", side_effect=OSError("disk full")):
            result = sh.enable()
        assert result["ok"] is False and sh.is_enabled() is False
        assert sh.verify_cfg_integrity()["tampered"] is False


def test_signature_save_failure_does_not_publish_or_remove_rules():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.add_signature("existing_rule", "__CANARY_ALPHA__")["ok"]
        before = sh.list_signatures()["custom"]
        with patch.object(pipeline, "write_signed_json", side_effect=OSError("disk full")):
            assert sh.add_signature("new_rule", "__CANARY_BETA__")["ok"] is False
            assert sh.remove_signature("existing_rule")["ok"] is False
            assert sh.list_signatures()["custom"] == before
        assert pipeline.NetShield(state_dir=d).list_signatures()["custom"] == before


def test_scan_budget_config_rejects_disabled_and_unbounded_limits():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.set_config(enabled=True, body_scan_enabled=True, block_score=20)["ok"]
        attack = b"user=admin' or 1=1-- -"
        for key, (lower, upper) in pipeline._SCAN_BOUNDS.items():
            original = sh.cfg[key]
            for bad in {0, -1, lower - 1, upper + 1}:
                result = sh.set_config(**{key: bad})
                assert result["ok"] is False and result["rejected"] == [key], (key, bad, result)
                assert sh.cfg[key] == original
                declarative = sh.apply_config({key: bad})
                assert key in declarative["rejected"] and key not in declarative["applied"]
            assert sh.set_config(**{key: lower})["ok"] is True
            assert sh.cfg[key] == lower
            assert sh.set_config(**{key: upper})["ok"] is True
            assert sh.cfg[key] == upper
            assert sh.set_config(**{key: original})["ok"] is True
        assert sh.inspect_body("192.0.2.11", attack)["action"] == "block"


def test_legacy_scan_budgets_are_clamped_and_reported():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        cfg = {key: (lower - 1) if i % 2 == 0 else upper + 1
               for i, (key, (lower, upper)) in enumerate(pipeline._SCAN_BOUNDS.items())}
        assert write_signed_json(sh.path, {"cfg": cfg, "rev": pipeline._CFG_REV}, sh._state_key)
        loaded = pipeline.NetShield(state_dir=d)
        for i, (key, (_lower, upper)) in enumerate(pipeline._SCAN_BOUNDS.items()):
            expected = pipeline._DEFAULTS[key] if i % 2 == 0 else upper
            assert loaded.cfg[key] == expected, key
        events = [e for e in loaded.events() if e.get("kind") == "cfg_load_rejected"]
        assert events and set(events[-1]["bounded"]) == set(cfg)


def test_paranoia_optional_restore_is_one_persisted_change():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        result = sh.set_paranoia(3, {"ssti": True})
        assert result["paranoia"] == 3 and result["enabled_optional"] == ["ssti"]
        before = dict(sh.cfg)
        for invalid in ({"unknown": True}, {"ssti": "false"}, []):
            assert sh.set_paranoia(2, invalid)["ok"] is False
            assert sh.cfg == before
        with patch.object(pipeline, "write_signed_json", return_value=False):
            assert sh.set_paranoia(2, {"redirect": True})["ok"] is False
            assert sh.cfg == before
        loaded = pipeline.NetShield(state_dir=d)
        assert loaded.cfg["paranoia"] == 3
        assert loaded.paranoia_status()["enabled_optional"] == ["ssti"]


def test_security_time_windows_and_flood_threshold_have_safe_ranges():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        for key, (lower, upper) in pipeline._TIME_BOUNDS.items():
            original = sh.cfg[key]
            for bad in {0, -1, lower - 1, upper + 1}:
                result = sh.set_config(**{key: bad})
                assert result["ok"] is False and result["rejected"] == [key], (key, bad)
                assert sh.cfg[key] == original
            assert sh.set_config(**{key: lower})["ok"] is True
            assert sh.set_config(**{key: upper})["ok"] is True
            assert sh.set_config(**{key: original})["ok"] is True
        assert sh.set_config(enabled=True, block_score=20)["ok"]
        assert sh.penalize("192.0.2.9", weight=50)["banned"] is True

    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        cfg = {key: 0 if i % 2 == 0 else upper + 1
               for i, (key, (_lower, upper)) in enumerate(pipeline._TIME_BOUNDS.items())}
        assert write_signed_json(sh.path, {"cfg": cfg, "rev": pipeline._CFG_REV}, sh._state_key)
        loaded = pipeline.NetShield(state_dir=d)
        for i, (key, (_lower, upper)) in enumerate(pipeline._TIME_BOUNDS.items()):
            expected = (pipeline._DEFAULTS[key]
                        if i % 2 == 0 or key in pipeline._LEGACY_DEFAULT_ON_HIGH
                        else upper)
            assert loaded.cfg[key] == expected, key
        events = [e for e in loaded.events() if e.get("kind") == "cfg_load_rejected"]
        assert events and set(events[-1]["bounded"]) == set(cfg)


def test_audit_flood_history_is_bounded_without_losing_threshold():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.set_config(enabled=True, mode="audit", flood_threshold=2,
                             rate_per_sec=100000, burst=100000)["ok"]
        for _ in range(1000):
            sh.inspect("192.0.2.3", path="/safe")
        assert len(sh._ips["192.0.2.3"]["window"]) == 3
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.set_config(enabled=True, flood_threshold=2, deny_score=20,
                             block_score=1000, rate_per_sec=100, burst=100)["ok"]
        assert sh.inspect("192.0.2.4", path="/safe")["action"] == "allow"
        assert sh.inspect("192.0.2.4", path="/safe")["action"] == "allow"
        assert sh.inspect("192.0.2.4", path="/safe")["action"] == "block"


def test_positive_credential_and_response_windows_still_enforce():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.set_config(enabled=True, cred_rate_enabled=True, cred_rate_limit=1,
                             cred_rate_window_sec=1, rate_per_sec=100, burst=100)["ok"]
        assert sh.inspect("192.0.2.5", path="/safe", cred="same")["action"] == "allow"
        assert sh.inspect("192.0.2.5", path="/safe", cred="same")["action"] == "block"
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.set_config(enabled=True, resp_error_window_sec=1,
                             resp_error_threshold=2, resp_error_score=60)["ok"]
        assert sh.note_response("192.0.2.6", 404)["action"] == "track"
        assert sh.note_response("192.0.2.6", 404)["action"] == "score"


def test_ban_persistence_failure_is_reported_and_retryable():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.enable()["ok"]
        with patch.object(pipeline, "write_signed_json", return_value=False):
            result = sh.ban("192.0.2.55", permanent=True)
            assert result["ok"] is False and result["persisted"] is False
            assert result["applied_in_memory"] is True
            flush = sh.flush_state()
            assert flush["ok"] is False and flush["persisted"] is False
            assert flush["bans_dirty"] is True
        assert sh.is_banned_fast("192.0.2.55") is True
        assert pipeline.NetShield(state_dir=d).is_banned_fast("192.0.2.55") is False
        assert sh.flush_state()["persisted"] is True
        assert pipeline.NetShield(state_dir=d).is_banned_fast("192.0.2.55") is True
        with patch.object(pipeline, "write_signed_json", return_value=False):
            result = sh.unban("192.0.2.55")
            assert result["ok"] is False and result["persisted"] is False
        assert result.get("applied_in_memory") is not True
        assert sh.is_banned_fast("192.0.2.55") is True
        assert pipeline.NetShield(state_dir=d).is_banned_fast("192.0.2.55") is True
        assert sh.flush_state()["persisted"] is True
        assert pipeline.NetShield(state_dir=d).is_banned_fast("192.0.2.55") is True
        assert sh.unban("192.0.2.55")["ok"] is True
        assert pipeline.NetShield(state_dir=d).is_banned_fast("192.0.2.55") is False


def test_open_redirect_safe_path_stays_on_local_origin():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        for bad in ("", "https://evil.example/", "//evil.example/", "///evil.example/",
                    r"/\evil.example", r"\evil.example", " /safe", "/safe\r\nLocation: //evil"):
            result = sh.set_config(open_redirect_safe_path=bad)
            assert result["ok"] is False and sh.cfg["open_redirect_safe_path"] == "/", bad
        for good in ("/", "/login", "/login?next=/app"):
            assert sh.set_config(open_redirect_safe_path=good)["ok"] is True
            assert sh.cfg["open_redirect_safe_path"] == good
        assert write_signed_json(sh.path,
                                 {"cfg": {"open_redirect_safe_path": "//evil.example/"},
                                  "rev": pipeline._CFG_REV}, sh._state_key)
        loaded = pipeline.NetShield(state_dir=d)
        assert loaded.cfg["open_redirect_safe_path"] == "/"


def test_usage_log_rotation_reads_a_bounded_tail_and_rewrites_atomically():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        path = sh._usage_log_path
        last = [json.dumps({"ip": f"192.0.2.{i}", "action": "usage"}).encode() + b"\n"
                for i in range(1, 6)]
        with open(path, "wb") as f:
            f.seek(9 * 1024 * 1024)
            f.write(b"oversized-line\n")
            f.writelines(line.replace(b"\n", b"\r\n") for line in last)
        sh._rotate_usage_log(keep=2)
        with open(path, "rb") as f:
            assert f.read().replace(b"\r\n", b"\n") == b"".join(last[-2:])

        with open(path, "wb") as f:
            f.seek(5 * 1024 * 1024)
            f.write(b"oversized-line\n")
            f.writelines(last)
        size = os.path.getsize(path)
        with patch.object(pipeline, "atomic_write_text", return_value=False):
            sh._rotate_usage_log(keep=1)
        assert os.path.getsize(path) == size  # failed replace kept the old complete log
        assert sh._usage_rotate_retry_at > 0


def test_event_writer_shares_reader_lock_across_threads():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        started, done = threading.Event(), threading.Event()

        def write_event():
            started.set()
            sh._event("192.0.2.7", "probe", {"n": 1})
            done.set()

        worker = threading.Thread(target=write_event)
        with sh._lock:
            worker.start()
            assert started.wait(1)
            assert not done.wait(0.05)  # writer cannot mutate while a snapshot lock is held
        assert done.wait(1)
        worker.join(1)
        assert [e for e in sh.events() if e.get("kind") == "probe"]


def test_restriction_save_failure_keeps_ban_and_metadata_together():
    with tempfile.TemporaryDirectory() as d:
        sh = pipeline.NetShield(state_dir=d)
        assert sh.enable()["ok"]
        with patch.object(pipeline, "write_signed_json", return_value=False):
            result = sh.restrict("192.0.2.77")
        assert result["ok"] is False and result["persisted"] is False
        assert result.get("applied_in_memory") is not True
        assert sh.is_banned_fast("192.0.2.77") is False
        assert sh.list_restrictions() == []
        assert sh.submit_report("192.0.2.77", "review request")["ok"] is False
        assert sh.restrict("192.0.2.77")["ok"] is True
        assert pipeline.NetShield(state_dir=d).list_restrictions()[0]["ip"] == "192.0.2.77"


def test_netshield_saved_bans_are_signed_and_reload_ok():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.ban("203.0.113.7", permanent=True)
        sh._save_bans()
        with open(sh._bans_path, encoding="utf-8") as f:
            env = json.load(f)
        assert "_sig" in env and "_payload" in env    # 署名エンベロープ
        # 新インスタンス(再起動相当)が同じ鍵で検証して BAN を復元
        sh2 = _fresh_shield(d)
        sh2._load_bans()
        assert sh2.is_banned_fast("203.0.113.7")


def test_netshield_rejects_tampered_blocklist():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.ban("203.0.113.7", permanent=True)         # 正規BAN
        sh._save_bans()
        # 攻撃者が blocklist を改竄: 自分(攻撃者IP)を BAN から外し、被害者IPを注入
        with open(sh._bans_path, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"]["bans"] = {"10.0.0.5": {"until": None, "permanent": True,
                                                 "started": 0, "count": 1}}
        with open(sh._bans_path, "w", encoding="utf-8") as f:
            json.dump(env, f)
        # 再起動相当: 署名不一致でフェイルセーフ=改竄 blocklist を一切信頼しない
        sh2 = _fresh_shield(d)
        sh2._load_bans()
        assert not sh2.is_banned_fast("10.0.0.5")     # 注入された偽BANを採用しない
        assert not sh2.is_banned_fast("203.0.113.7")  # 改竄ファイルは丸ごと破棄(安全側)


def test_netshield_migrates_legacy_unsigned_bans():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        # 旧来の無署名 blocklist を直接設置
        with open(sh._bans_path, "w", encoding="utf-8") as f:
            json.dump({"bans": {"203.0.113.7": {"until": None, "permanent": True,
                                                "started": 0, "count": 1}}}, f)
        sh._load_bans()                               # 無署名→使用しつつ署名済みへ移行
        assert sh.is_banned_fast("203.0.113.7")
        with open(sh._bans_path, encoding="utf-8") as f:
            assert "_sig" in json.load(f)             # 移行後は署名済み


def test_netshield_rejects_plaintext_swap_after_signing():
    # #53: 署名運用が始まった後(マーカー有)に攻撃者が *平文ファイルで丸ごとすり替え* ても、
    #   無署名出現=改竄として弾く(移行受理は初回/レガシーのみ)。
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.ban("203.0.113.7", permanent=True)
        sh._save_bans()                               # 署名保存(マーカーは init で既設)
        # 攻撃者が署名エンベロープごと捨てて平文 blocklist を設置(自分仕様のBAN)
        with open(sh._bans_path, "w", encoding="utf-8") as f:
            json.dump({"bans": {"10.0.0.5": {"until": None, "permanent": True,
                                             "started": 0, "count": 1}}}, f)
        sh2 = _fresh_shield(d)                         # マーカー有=signed_before True
        sh2._load_bans()
        assert not sh2.is_banned_fast("10.0.0.5")     # 平文すり替えを信頼しない
        assert not sh2.is_banned_fast("203.0.113.7")


def test_netshield_traffic_signed_and_tamper_rejected():
    # traffic.json(DLP egress クォータの素)も署名。改竄で攻撃者のegress計上をリセットさせない。
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.record_traffic("198.51.100.9", out_bytes=5_000_000, in_bytes=1000, conn_sec=2.0)
        sh._save_traffic(force=True)
        with open(sh._traffic_path, encoding="utf-8") as f:
            assert "_sig" in json.load(f)             # 署名済み
        # 改竄: payload を空に(攻撃者が自分の集計を消す)
        with open(sh._traffic_path, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"]["traffic"] = {}
        with open(sh._traffic_path, "w", encoding="utf-8") as f:
            json.dump(env, f)
        sh2 = _fresh_shield(d)                         # 署名不一致→空(安全側)で起動・警報
        assert sh2._traffic == {}


def test_tamper_is_visualized_and_forwarded():
    # #55: 改竄検知が metrics.tamper / tamper_report に出る(ダッシュボードでの可視化)。
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh.report_tamper("state_tamper", "bans", "fail-safe(default)",
                         {"file": "blocklist.json"})
        sh.report_tamper("memory_tamper", "cfg", "restored-from-disk")
        m = sh.metrics()["tamper"]
        assert m["count"] == 2
        assert m["by_kind"]["state_tamper"] == 1 and m["by_kind"]["memory_tamper"] == 1
        assert m["last"]["kind"] == "memory_tamper"
        rep = sh.tamper_report()
        assert rep["summary"]["count"] == 2
        kinds = {e["kind"] for e in rep["events"]}
        assert {"state_tamper", "memory_tamper"} <= kinds


def test_netshield_rejects_tampered_config():
    with tempfile.TemporaryDirectory() as d:
        sh = _fresh_shield(d)
        sh._save()
        base_score = sh.cfg["flood_threshold"]
        # 攻撃者が state.json を改竄: flood_threshold を巨大化して flood 検知を実質無効化
        with open(sh.path, encoding="utf-8") as f:
            env = json.load(f)
        env["_payload"]["cfg"]["flood_threshold"] = 10 ** 9
        with open(sh.path, "w", encoding="utf-8") as f:
            json.dump(env, f)
        sh2 = _fresh_shield(d)
        sh2._load()
        assert sh2.cfg["flood_threshold"] == base_score   # 改竄設定を採らず既定を維持


# ── ロールバック攻撃対策(#102): 古い正署名ファイルへの巻き戻しを拒否 ──
def test_rollback_old_signed_file_rejected():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "blocklist.json")
        # v1: 攻撃者IPが BAN されている最新状態
        write_signed_json(p, {"bans": {"6.6.6.6": {"until": 9999}}}, b"k")
        with open(p, encoding="utf-8") as f:
            old_env = json.load(f)                  # 攻撃者がこの『正署名の現行』を退避…ではなく
        # v2: さらに更新(版が前進)
        write_signed_json(p, {"bans": {"6.6.6.6": {"until": 9999}, "7.7.7.7": {"until": 1}}}, b"k")
        s2, _ = read_signed_json(p, b"k")
        assert s2 == "ok"
        # 攻撃者が『古い正署名ファイル(v1)』で上書き=自分の BAN が無い頃へ巻き戻し
        with open(p, "w", encoding="utf-8") as f:
            json.dump(old_env, f)
        status, val = read_signed_json(p, b"k", default="SAFE")
        assert status == "rolled_back" and val == "SAFE"   # 署名は正しいが版後退=拒否


def test_legacy_unversioned_envelope_still_ok():
    # 旧 _sv:1(バージョン無し)エンベロープは後方互換で読める。
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.json")
        payload = {"a": 1}
        env = {"_sv": 1, "_sig": sign_payload(payload, b"k"), "_payload": payload}
        with open(p, "w", encoding="utf-8") as f:
            json.dump(env, f)
        status, val = read_signed_json(p, b"k")
        assert status == "ok" and val == payload


def test_version_monotonic_increases():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "y.json")
        write_signed_json(p, {"n": 1}, b"k")
        v1 = json.load(open(p, encoding="utf-8"))["_ver"]
        write_signed_json(p, {"n": 2}, b"k")
        v2 = json.load(open(p, encoding="utf-8"))["_ver"]
        assert v2 > v1                              # 版は必ず前進


def test_sidecar_failure_does_not_publish_new_state():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state.json")
        key = b"k" * 32
        assert ss.write_signed_json(p, {"v": 1}, key)
        original = open(p, "rb").read()
        real_write = ss.atomic_write_json
        calls = []

        def fail_hw(path, obj, **kw):
            calls.append(path)
            return False if path == p + ".hw" else real_write(path, obj, **kw)

        with patch.object(ss, "atomic_write_json", side_effect=fail_hw):
            assert ss.write_signed_json(p, {"v": 2}, key) is False
        assert calls == [p + ".hw"] and open(p, "rb").read() == original
        ss._MEM_HW.pop(p, None)
        ss._MEM_MIN_SV.pop(p, None)
        assert ss.read_signed_json(p, key)[1] == {"v": 1}


def test_main_failure_restores_previous_high_water_or_fails_closed():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state.json")
        key = b"k" * 32
        assert ss.write_signed_json(p, {"v": 1}, key)
        first = open(p, "rb").read()
        old_hw = json.load(open(p + ".hw", encoding="utf-8"))["_ver"]
        real_write = ss.atomic_write_json

        def fail_main(path, obj, **kw):
            return False if path == p else real_write(path, obj, **kw)

        with patch.object(ss, "atomic_write_json", side_effect=fail_main):
            assert ss.write_signed_json(p, {"v": 2}, key) is False
        assert open(p, "rb").read() == first
        assert json.load(open(p + ".hw", encoding="utf-8"))["_ver"] == old_hw
        ss._MEM_HW.pop(p, None)
        ss._MEM_MIN_SV.pop(p, None)
        assert ss.read_signed_json(p, key)[0] == "ok"

        hw_writes = 0

        def fail_main_and_restore(path, obj, **kw):
            nonlocal hw_writes
            if path == p:
                return False
            if path == p + ".hw":
                hw_writes += 1
                if hw_writes == 2:
                    return False
            return real_write(path, obj, **kw)

        with patch.object(ss, "atomic_write_json", side_effect=fail_main_and_restore):
            assert ss.write_signed_json(p, {"v": 3}, key) is False
        ss._MEM_HW.pop(p, None)
        ss._MEM_MIN_SV.pop(p, None)
        assert ss.read_signed_json(p, key, default="safe") == ("rolled_back", "safe")


def test_clock_rollback_repair_uses_verified_sidecar_floor():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state.json")
        key = b"k" * 32
        now = ss.time.time()
        assert ss.write_signed_json(p, {"v": 1}, key)
        old = open(p, "rb").read()
        with patch.object(ss.time, "time", return_value=now + 10000):
            assert ss.write_signed_json(p, {"v": 2}, key)
        ss._MEM_HW.pop(p, None)
        ss._MEM_MIN_SV.pop(p, None)
        with open(p, "wb") as f:
            f.write(old)
        assert ss.read_signed_json(p, key)[0] == "rolled_back"
        with patch.object(ss.time, "time", return_value=now):
            assert ss.write_signed_json(p, {"v": 3}, key)
        ss._MEM_HW.pop(p, None)
        ss._MEM_MIN_SV.pop(p, None)
        assert ss.read_signed_json(p, key) == ("ok", {"v": 3})


def test_legacy_v2_is_only_accepted_before_v3_history():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "blocklist.json")
        key = b"k" * 32
        assert ss.write_signed_json(target, {"bans": {"8.8.8.8": 1}}, key)
        newer = json.load(open(target, encoding="utf-8"))["_ver"] + 1
        payload = {"usage": {}}
        legacy = {"_sv": 2, "_ver": newer, "_payload": payload,
                  "_sig": ss.sign_payload({"_ver": newer, "_payload": payload}, key)}
        with open(target, "w", encoding="utf-8") as f:
            json.dump(legacy, f)
        ss._MEM_HW.pop(target, None)
        ss._MEM_MIN_SV.pop(target, None)
        assert ss.read_signed_json(target, key, default="safe") == ("rolled_back", "safe")
        assert ss.read_signed_json(target, key, default="safe",
                                   check_rollback=False) == ("rolled_back", "safe")

        fresh = os.path.join(d, "legacy.json")
        with open(fresh, "w", encoding="utf-8") as f:
            json.dump(legacy, f)
        assert ss.read_signed_json(fresh, key) == ("ok", payload)


def test_state_lock_contention_is_bounded_and_does_not_publish():
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state.json")
        key = b"k" * 32
        with patch.object(ss, "_LOCK_WAIT_SEC", 0.02):
            with ss._state_guard(p) as locked:
                assert locked
                assert ss.write_signed_json(p, {"v": 1}, key) is False
                assert ss.read_signed_json(p, key, default="safe") == ("tampered", "safe")


def test_state_lock_serializes_separate_processes():
    import subprocess
    import sys
    from dataplane.engine.core import signed_state as ss
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "state.json")
        code = ("import sys,time\n"
                "from dataplane.engine.core.signed_state import _state_guard\n"
                "with _state_guard(sys.argv[1]) as locked:\n"
                " print('locked' if locked else 'failed', flush=True)\n"
                " time.sleep(0.4)\n")
        proc = subprocess.Popen([sys.executable, "-c", code, p],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        try:
            assert proc.stdout.readline().strip() == "locked"
            with patch.object(ss, "_LOCK_WAIT_SEC", 0.05):
                assert ss.write_signed_json(p, {"v": 1}, b"k") is False
            assert proc.wait(timeout=3) == 0, proc.stderr.read()
            assert ss.write_signed_json(p, {"v": 2}, b"k")
            assert ss.read_signed_json(p, b"k") == ("ok", {"v": 2})
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
