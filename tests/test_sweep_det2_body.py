"""
test_sweep_det2_body.py — 本文検査の追補(sweep: det2_body 群)。
====================================================================================
· T1 クライアントが宣言するバイナリ型と制御バイトだけで本文署名を省略しない。
  型を偽った本文にも通常の署名走査を行う。
· T2(決定) アップロードの拡張子ポリシーは multipart のパートにしか効かず、要求ヘッダの
  Content-Disposition で名前を渡す生本文アップロード(WordPress REST の media 等)は素通りした。
"""
import asyncio
import random
import tempfile

from dataplane.engine.lifeform.pipeline import NetShield
from dataplane.engine.services.proxy import AsyncEdgeGuard
from test_sweep_det_body import _Reads, _post, _shield, _through

XSS_BODY = b"comment=<script>alert(document.cookie)</script>"   # test_bodyscan.test_xss_body_detected
# 圧縮画像の中身の代わり(固定シードの擬似乱数=実画像と同じくほぼ一様なバイト分布・64KiB)。
_BIN = b"\x89PNG\r\n\x1a\n" + random.Random(20261009).randbytes(65536 - 8)
_BIN_TYPES = ("application/octet-stream", "application/x-protobuf", "application/protobuf",
              "image/png", "audio/ogg", "video/mp4", "application/zip", "application/pdf",
              "Application/Octet-Stream")
_IP = "203.0.113.90"


def _sh(d, **cfg):
    sh = NetShield(state_dir=d)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    sh.cfg.update(cfg)
    return sh


def _score(sh, ip) -> float:
    return {t["ip"]: t["score"] for t in sh.top_talkers(200)}.get(ip, 0.0)


def _scan_with(buf, path="/x"):
    """差し込んだ shield の下で _scan_request_body を 1 回走らせ、blocked を返す。"""
    g = AsyncEdgeGuard()

    async def go():
        return await g._scan_request_body(buf, _Reads(), _IP, path)

    return asyncio.run(go())[1]


# ── T1: クライアント宣言のバイナリ型でも署名走査する ──────────────────────────
def test_t1_binary_type_does_not_disable_signature_scan():
    """The supplied media type cannot suppress the existing signature engine."""
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d)
        # 既存署名はランダム列にも当たり得るが、攻撃者に選べる型で無効化しない。
        r = sh.inspect_body("192.0.2.60", _BIN)
        assert r["action"] == "score" and r.get("signature"), r
        for i, ct in enumerate(_BIN_TYPES):
            ip = f"192.0.2.{61 + i}"
            r = sh.inspect_body(ip, _BIN, content_type=ct)
            assert r.get("signature") and _score(sh, ip) > 0, (ct, r)
        # A declared charset that the scanner cannot decode is not clean allow.
        r = sh.inspect_body("192.0.2.80", _BIN,
                            content_type="application/octet-stream; charset=binary")
        assert r["action"] == "block" and r.get("reason"), r


def test_t1_text_like_body_with_binary_type_is_still_scanned():
    """Text signatures remain visible even under a binary declaration."""
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d)
        for ct in ("application/octet-stream", "image/png", "application/x-protobuf"):
            r = sh.inspect_body("192.0.2.70", XSS_BODY, content_type=ct)
            assert r.get("signature") == "xss", (ct, r)
        r = sh.inspect_body("192.0.2.71", b"a=1\r\n\t" + XSS_BODY,
                            content_type="application/octet-stream")
        assert r.get("signature") == "xss", r


def test_t1_text_type_is_always_scanned():
    """T1: テキスト型(JSON/フォーム/text/*/SVG/multipart)と型無しは、中身に制御バイトが
    混じっても走査する。"""
    body = b"\x00\x01\x02" + XSS_BODY
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d)
        for ct in ("application/json", "application/x-www-form-urlencoded", "text/plain",
                   "image/svg+xml", "application/vnd.api+json",
                   "multipart/form-data; boundary=b", ""):
            r = sh.inspect_body("192.0.2.72", body, content_type=ct)
            assert r.get("signature") == "xss", (ct, r)


def test_t1_proxy_passes_request_content_type():
    """The scan helper does not trust a binary media type to skip signatures."""
    req = _post(b"/upload/raw", _BIN, b"application/octet-stream") + _BIN
    with _shield() as sh:
        assert _scan_with(req) is False
        assert _score(sh, _IP) > 0
    dup = req.replace(b"Content-Type: application/octet-stream\r\n",
                      b"Content-Type: application/octet-stream\r\nContent-Type: text/plain\r\n")
    with _shield() as sh:
        _scan_with(dup)
        assert _score(sh, _IP) > 0


# ── T2: 生本文アップロードは要求ヘッダのファイル名で検査 ───────────────────────────
def test_t2_scan_upload_checks_request_disposition_filename():
    """T2: scan_upload は要求ヘッダの Content-Disposition(filename= / filename*=)にも
    multipart と同じ拡張子規則を掛ける。"""
    jpeg = b"\xff\xd8\xff\xe0" + b"x" * 64
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d, upload_deny_ext=["xyz"])
        for cd in ('attachment; filename="note.xyz"', "attachment; filename=note.xyz",
                   "attachment; filename*=UTF-8''note%2Exyz", 'inline; filename="a/b/note.xyz. "'):
            r = sh.scan_upload("192.0.2.80", jpeg, "image/jpeg", disposition=cd)
            assert r["action"] == "block" and r.get("ext") == "xyz", (cd, r)
        ok = sh.scan_upload("192.0.2.81", jpeg, "image/jpeg",
                            disposition='attachment; filename="photo.jpg"')
        assert ok["action"] == "allow", ok
        # 値が複数本でも全部見る・本文が空でもヘッダ名は見る
        r = sh.scan_upload("192.0.2.82", b"", disposition=['attachment; filename="photo.jpg"',
                                                           'attachment; filename="note.xyz"'])
        assert r["action"] == "block", r
        assert not sh.is_banned_fast("192.0.2.81")
    with tempfile.TemporaryDirectory() as d:
        sh = _sh(d)                                   # 既定の拒否リストと二重拡張子の規則も同じ
        r = sh.scan_upload("192.0.2.83", jpeg, disposition='attachment; filename="shell.php.jpg"')
        assert r["action"] == "block" and r.get("ext") == "php", r
        r = sh.scan_upload("192.0.2.84", jpeg, disposition='attachment; filename="www.example.com.har"')
        assert r["action"] == "allow", r
        sh.cfg["upload_scan_enabled"] = False
        r = sh.scan_upload("192.0.2.85", jpeg, disposition='attachment; filename="shell.php"')
        assert r["action"] == "allow", r


def _raw_upload(fn: bytes) -> bytes:
    body = b"\xff\xd8\xff\xe0" + b"x" * 100
    return (b"POST /wp-json/wp/v2/media HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n"
            b"Content-Type: image/jpeg\r\nContent-Disposition: attachment; filename=\"" + fn
            + b"\"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def test_t2_raw_upload_with_denied_header_filename_never_reaches_backend():
    """T2: Content-Disposition ヘッダで名前を渡す生本文アップロードも、拒否拡張子なら backend へ
    何も送らない。body_scan_enabled=False でも効く(止めるのは upload_scan_enabled)。"""
    saw, _ = _through([_raw_upload(b"note.xyz")], upload_deny_ext=["xyz"])
    assert b"note.xyz" not in saw, saw[:120]
    saw, resp = _through([_raw_upload(b"photo.jpg")], upload_deny_ext=["xyz"])
    assert b"photo.jpg" in saw and resp.endswith(b"ok"), (saw[:120], resp[:80])
    with _shield(upload_deny_ext=["xyz"], body_scan_enabled=False) as sh:
        assert _scan_with(_raw_upload(b"note.xyz")) is True
        assert sh.is_banned_fast(_IP)
    with _shield(upload_deny_ext=["xyz"], upload_scan_enabled=False):
        assert _scan_with(_raw_upload(b"note.xyz")) is False
