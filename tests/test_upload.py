"""
test_upload.py — ファイルアップロード検査(危険拡張子拒否・evolution #66)。
====================================================================================
multipart の filename= から webshell/実行体の拡張子を拒否する。二重拡張子(shell.php.jpg)・
NUL 切り(shell.php\\x00.jpg)・パス分離子も全セグメント検査で捉える。#61(本文署名)とは別関心。
"""
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield, _dangerous_upload_filename

_DENY = ["php", "jsp", "exe", "sh"]


def _mp(filename: bytes, content: bytes = b"x") -> bytes:
    return (b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
            + filename + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            + content + b"\r\n--b--\r\n")


def test_clean_upload_passes():
    assert _dangerous_upload_filename(_mp(b"photo.jpg"), _DENY) is None
    assert _dangerous_upload_filename(_mp(b"report.pdf"), _DENY) is None


def test_dangerous_extension_detected():
    hit = _dangerous_upload_filename(_mp(b"shell.php"), _DENY)
    assert hit and hit[1] == "php"


def test_double_extension_evasion():
    hit = _dangerous_upload_filename(_mp(b"shell.php.jpg"), _DENY)
    assert hit and hit[1] == "php"                       # 二重拡張子でも php を検知


def test_null_byte_trick():
    hit = _dangerous_upload_filename(_mp(b"shell.php\x00.jpg"), _DENY)
    assert hit and hit[1] == "php"


def test_path_in_filename():
    hit = _dangerous_upload_filename(_mp(b"../../var/www/x.jsp"), _DENY)
    assert hit and hit[1] == "jsp"


def test_no_filename_no_hit():
    assert _dangerous_upload_filename(b"name=foo&value=bar", _DENY) is None


def test_empty_denylist_no_hit():
    assert _dangerous_upload_filename(_mp(b"shell.php"), []) is None


def _shield(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg.update(cfg)
    return sh


def test_scan_upload_blocks_and_bans():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        r = sh.scan_upload("9.9.9.9", _mp(b"webshell.php", b"<?php system($_GET[c]);"))
        assert r["action"] == "block" and r["banned"] and r["ext"] == "php"
        assert sh.is_banned_fast("9.9.9.9")


def test_scan_upload_clean_allows():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d)
        assert sh.scan_upload("1.1.1.1", _mp(b"avatar.png"))["action"] == "allow"


def test_scan_upload_disabled():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, upload_scan_enabled=False)
        assert sh.scan_upload("2.2.2.2", _mp(b"shell.php"))["action"] == "allow"


def test_custom_denylist():
    with tempfile.TemporaryDirectory() as d:
        sh = _shield(d, upload_deny_ext=["svg"])
        assert sh.scan_upload("3.3.3.3", _mp(b"x.php"))["action"] == "allow"   # php 許可
        assert sh.scan_upload("4.4.4.4", _mp(b"x.svg"))["action"] == "block"   # svg 拒否
