"""
test_sweep_upd_integrity.py — 同じ場所でファイルを置き換えて更新したとき、完全性監視が更新を取り消す回帰。
====================================================================================
完全性監視(Full)は初回起動時のコードを基準として保存し、基準と違えば改竄として基準の複製へ戻す。
旧版を動かしたあと同じディレクトリで新版に置き換え、--integrity-baseline を取り直さずに起動すると、
最初の周期検査で中核モジュール 7 本(pipeline/proxy/admin 等)を旧版へ戻していた。起動中のプロセスは
新版のまま動くので何も起きないように見え、次の起動から『中核だけ旧版』の混ざった版で動き続けた
(実プロセスで確認)。起動画面には何も出ず、知らせは改竄欄の 1 件だけだった。

修正後: 起動したときに読み込んだ中身のまま(=いま動いているコード)のファイルは戻さず、何が起きたかと
次にすること(更新したなら --integrity-baseline、していないなら調査)を 1 回だけ知らせる。稼働中に
書き換えられたファイルは従来どおり基準へ戻す。
各テストは一時ディレクトリに作った使い捨てのモジュールだけを使い、中身は無害な定数。
"""
import io
import os
import sys
import tempfile
from unittest import SkipTest

_OLD = "VERSION = 'old'\n"
_NEW = "VERSION = 'new'\n"
_ALT = "VERSION = \"a'b<c\"\n"           # 無害な別定数(稼働中の書き換えの代わり)


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def _si(state, paths):
    try:
        from dataplane.engine.core.integrity import SelfIntegrity
    except ImportError:
        raise SkipTest("自己完全性監視は Full 版のみ")
    return SelfIntegrity(state, paths=paths, secret=b"s" * 32, repair=True)


def test_u1_inplace_update_is_not_reverted_and_is_reported_once():
    """旧版で基準を取ったあと同じ場所で新版に置き換えて起動し直すと、最初の周期検査で旧版へ戻していた。"""
    with tempfile.TemporaryDirectory() as d:
        mod = os.path.abspath(os.path.join(d, "app", "core_mod_upd.py"))
        state = os.path.join(d, "state")
        _write(mod, _OLD)
        assert _si(state, [mod]).tick()["event"] == "baseline"      # 旧版のプロセス
        _write(mod, _NEW)                                            # 置き換えて更新
        si = _si(state, [mod])                                       # 新版のプロセスが起動
        r = si.tick()
        assert _read(mod) == _NEW, "更新したファイルを旧版へ戻した"
        assert r["event"] == "tamper", r                             # 黙らずに知らせる
        assert r.get("held") == [mod], r
        assert not (r.get("repair") or {}).get("restored"), r
        r2 = si.tick()                                               # 同じ中身のまま=毎周期は報告しない
        assert r2["event"] == "held" and r2.get("held") == [mod], r2
        assert _read(mod) == _NEW


def test_u2_files_changed_after_start_are_still_repaired():
    """起動後に書き換えられたファイルは従来どおり基準へ戻す(起動時の中身のままのファイルだけ戻さない)。"""
    with tempfile.TemporaryDirectory() as d:
        a = os.path.abspath(os.path.join(d, "app", "core_a_upd.py"))
        b = os.path.abspath(os.path.join(d, "app", "core_b_upd.py"))
        state = os.path.join(d, "state")
        _write(a, _OLD)
        _write(b, _OLD)
        assert _si(state, [a, b]).tick()["event"] == "baseline"
        _write(a, _NEW)                                              # 起動前の置き換え
        si = _si(state, [a, b])
        assert si.tick().get("held") == [a]
        _write(b, _ALT)                                              # 稼働中の書き換え
        r = si.tick()
        assert r["event"] == "tamper", r
        assert _read(b) == _OLD, "稼働中に書き換えられたファイルを戻さなかった"
        assert b in (r.get("repair") or {}).get("restored", []), r
        assert _read(a) == _NEW, "起動前に置き換えたファイルまで戻した"
        _write(a, _ALT)                                              # 起動時の中身から変わった=戻す
        si.tick()
        assert _read(a) == _OLD


def test_u3_held_report_says_what_happened_and_what_to_do_once():
    """周期検査の通知: 戻さなかったことと次の手順(--integrity-baseline / 調査)を、改竄欄と画面へ 1 回だけ出す。"""
    try:
        from dataplane.engine.services.proxy import AsyncEdgeGuard
    except ImportError:
        raise SkipTest("proxy が無い")
    import dataplane.engine.lifeform.pipeline as ND
    mod = os.path.join(tempfile.gettempdir(), "app", "pipeline.py")

    class _SI:
        def __init__(self):
            self.n = 0

        def tick(self):
            self.n += 1
            if self.n == 1:
                return {"event": "tamper", "modified": [mod], "missing": [],
                        "manifest_valid": True, "held": [mod], "repair": {"ok": True,
                                                                          "restored": []}}
            return {"event": "held", "held": [mod]}

    with tempfile.TemporaryDirectory() as d:
        old, err = ND._SHIELD, sys.stderr
        ND._SHIELD = ND.NetShield(state_dir=d)
        sys.stderr = io.StringIO()
        try:
            g = AsyncEdgeGuard()
            if not hasattr(g, "_make_integrity_tick"):
                raise SkipTest("整合性監視は Full 版のみ")
            tick = g._make_integrity_tick(_SI())
            tick()
            last = dict(ND._SHIELD._tamper["last"] or {})
            count = ND._SHIELD._tamper["count"]
            tick()
            tick()
            count2 = ND._SHIELD._tamper["count"]
            printed = sys.stderr.getvalue()
        finally:
            ND._SHIELD, sys.stderr = old, err
    assert last.get("action") == "held", last                         # 『修復した』と書かない
    assert last.get("held") == ["pipeline.py"], last
    assert "--integrity-baseline" in last.get("next_step", ""), last
    assert count2 == count, (count, count2)                           # 2 周目以降は数えない
    assert printed.count("--integrity-baseline") == 1, printed        # 画面にも 1 回だけ
    assert "pipeline.py" in printed, printed
