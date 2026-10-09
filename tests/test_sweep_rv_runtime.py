"""
test_sweep_rv_runtime.py — 独立レビュー(rv_runtime)の回帰: ログのローテーション/追記が要求経路で眠らない
====================================================================================
  · #13 Windows: 読み手がログを開いている(FILE_SHARE_DELETE なし)と、ローテーションの改名が共有違反の
    再試行で 1 回あたり約 0.43 秒眠り、要求ごとの追記(アプリ層 FW の記録)で要求処理が止まっていた。
    要求経路は眠らない: 握られていればローテーションを見送り、少し後で再試行する(世代も削らない)。
    要求経路の追記は開けなくても待たない(管理操作の監査は従来どおり短く待って行を残す)。
  (フル版の同名モジュールは gossip の中継・待受の失敗表示も扱う。それらは Lite に無い)
実stateは tmp で隔離。各テストは「修正前のコードで落ちる」ことを確かめてある(Windows 固有のものは
他 OS で SkipTest)。
"""
import contextlib
import json
import os
import tempfile
import threading
import time
import unittest

from dataplane.engine.core import atomic_io as aio


def _tmpdir():
    # Windows ではワーカースレッドが閉じかけのログを掴んでいることがある=掃除失敗は無視
    return tempfile.TemporaryDirectory(ignore_cleanup_errors=True)


class _SleepSpy:
    """atomic_io の time を差し替え、sleep の呼び出しだけを記録する(実際には眠らない)。"""
    def __init__(self):
        self.calls = []

    def sleep(self, s):
        self.calls.append(s)

    def __getattr__(self, name):
        return getattr(time, name)


@contextlib.contextmanager
def _spy_sleep():
    spy, orig = _SleepSpy(), aio.time
    aio.time = spy
    try:
        yield spy
    finally:
        aio.time = orig


def _hold_exclusive(path: str, seconds: float):
    """path を共有なし(dwShareMode=0)で開き、seconds 後に閉じる(Windows の共有違反を再現)。"""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.CreateFileW(path, 0x80000000, 0, None, 3, 0x80, None)   # GENERIC_READ, OPEN_EXISTING
    if h is None or h == wintypes.HANDLE(-1).value:
        raise unittest.SkipTest("CreateFileW で排他ハンドルを取れない")
    t = threading.Timer(seconds, k32.CloseHandle, args=(h,))
    t.start()
    return t


def _all_lines(d: str) -> list:
    out = []
    for name in sorted(os.listdir(d)):
        with open(os.path.join(d, name), "rb") as f:
            out += [json.loads(ln) for ln in f.read().split(b"\n") if ln.strip()]
    return out


def test_rv13_rotation_does_not_sleep_while_a_reader_holds_the_log():
    """tail している読み手(open(path,'rb')=FILE_SHARE_DELETE なし)が居る間も、追記は眠らず行も失わない。"""
    with _tmpdir() as d:
        p = os.path.join(d, "acl_log.jsonl")
        for i in range(60):
            assert aio.append_jsonl(p, {"i": i, "pad": "x" * 20}, max_bytes=10 ** 9)
        small = os.path.getsize(p) // 2
        reader = open(p, "rb")
        try:
            with _spy_sleep() as spy:
                for i in range(5):
                    assert aio.append_jsonl(p, {"i": 100 + i}, max_bytes=small, backups=3)
        finally:
            reader.close()
        assert spy.calls == [], f"要求経路の追記が眠った: {len(spy.calls)} 回"
        assert sorted(r["i"] for r in _all_lines(d)) == list(range(60)) + list(range(100, 105))


def test_rv13_locked_rotation_keeps_generations_and_resumes_later():
    """握られていてローテーションできない間に世代(.1/.2/.3)を削らない。読み手が閉じれば再開する。"""
    if os.name != "nt":
        raise unittest.SkipTest("読み手が改名を妨げるのは Windows だけ")
    with _tmpdir() as d:
        p = os.path.join(d, "acl_log.jsonl")
        for k in (1, 2, 3):
            with open(f"{p}.{k}", "w", encoding="utf-8") as f:
                f.write(json.dumps({"gen": k}) + "\n")
        for i in range(40):
            aio.append_jsonl(p, {"gen": 0, "i": i}, max_bytes=10 ** 9)
        small = os.path.getsize(p) // 2
        reader = open(p, "rb")
        try:
            for i in range(4):
                assert aio.append_jsonl(p, {"gen": 0, "i": 100 + i}, max_bytes=small, backups=3)
        finally:
            reader.close()
        for k in (1, 2, 3):
            with open(f"{p}.{k}", encoding="utf-8") as f:
                assert json.loads(f.read()) == {"gen": k}, f"世代 .{k} が削られた"
        orig = getattr(aio, "_ROTATE_RETRY_SEC", None)
        aio._ROTATE_RETRY_SEC = 0.0                     # 見送り間隔を過ぎたことにする
        try:
            assert aio.append_jsonl(p, {"gen": "new"}, max_bytes=small, backups=3)
        finally:
            if orig is None:
                del aio._ROTATE_RETRY_SEC
            else:
                aio._ROTATE_RETRY_SEC = orig
        with open(f"{p}.1", encoding="utf-8") as f:
            rows = [json.loads(ln) for ln in f if ln.strip()]
        assert len(rows) == 44 and all(r["gen"] == 0 for r in rows), "読み手が閉じた後も回らない"
        with open(f"{p}.2", encoding="utf-8") as f:
            assert json.loads(f.read()) == {"gen": 1}


def test_rv13_hot_path_append_does_not_wait_for_a_locked_log():
    if os.name != "nt":
        raise unittest.SkipTest("共有違反は Windows 固有")
    with _tmpdir() as d:
        lp = os.path.join(d, "acl_log.jsonl")
        assert aio.append_jsonl(lp, {"i": 0})
        t = _hold_exclusive(lp, 0.5)
        try:
            with _spy_sleep() as spy:
                aio.append_jsonl(lp, {"i": 1}, wait=False)
            assert spy.calls == [], spy.calls
        finally:
            t.join()


def test_rv13_firewall_record_does_not_wait_for_a_locked_log():
    """アプリ層 FW は接続ごとに要求経路から記録する=ログを開けなくても待たない。"""
    if os.name != "nt":
        raise unittest.SkipTest("共有違反は Windows 固有")
    from dataplane.engine.lifeform.policy import AppFirewall
    with _tmpdir() as d:
        fw = AppFirewall(state_dir=d)
        aio.append_jsonl(fw.log_path, {"seed": 1})
        t = _hold_exclusive(fw.log_path, 0.5)
        try:
            with _spy_sleep() as spy:
                fw._record("192.0.2.10", 443, "internet", "allow", "rv", None)
            assert spy.calls == [], f"要求経路の記録が眠った({len(spy.calls)} 回)"
        finally:
            t.join()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    ok = 0
    for fn in fns:
        try:
            fn()
            ok += 1
            print("PASS", fn.__name__)
        except unittest.SkipTest as e:
            ok += 1
            print("SKIP", fn.__name__, "->", e)
        except Exception as e:
            print("FAIL", fn.__name__, "->", repr(e))
    print(f"--- {ok}/{len(fns)} passed ---")
