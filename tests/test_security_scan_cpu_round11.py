"""Round 11: signature prefilters and exact NFKC speed selection."""

import random
import tempfile
import unicodedata

from dataplane.engine.lifeform import pipeline as P


_HEAD_BRANCHES = {
    "sqli": ("union select", "union distinct select", "or 1=1", "' --",
             "select name from users where id=1", "drop table users"),
    "xss": ("<script>", "onerror=", "javascript:", "vbscript:",
            "data:text/html", "<img src=x onerror=", "document.cookie"),
    "traversal": ("../../etc", "..\\..\\", "/etc/passwd", "/etc/shadow",
                  "/etc/hosts", "/proc/self", "c:\\windows\\", "win.ini",
                  "boot.ini", "..;x"),
    "rce": (";cat", "||curl", "&&bash", "$(id)", "`id`", "|python",
            "() {", "<?php", "<?="),
    "sqli_blind": ("sleep(", "benchmark(", "pg_sleep(", "waitfor delay",
                   "extractvalue(", "updatexml(", "load_file(",
                   "into outfile", "into dumpfile", "information_schema.users",
                   "and 1=(select"),
    "nosqli": ("[$ne", "$where", '"$ne":'),
    "lfi": ("php://", "gopher://", "dict://", "expect://", "phar://",
            "netdoc://", "=file://"),
    "jndi": ("${jndi:", "jndi:ldap"),
    "ssrf": ("169.254.169.254", "metadata.google.internal",
             "100.100.100.200", "fd00:ec2::254", "/latest/meta-data",
             "/latest/dynamic", "/latest/user-data", "/computemetadata/",
             "://2852039166", "@0xa9fea9fe"),
    "proto": ("__proto__", "constructor prototype", "class module classloader"),
    "crlf": (";set-cookie:", ";location:", ";refresh:",
             ";content-type:", ";content-length:", ";content-disposition:",
             ";bcc:", ";cc:", ";to:", ";mime-version:",
             ";content-transfer-encoding:"),
    "xxe": ("<!entity", '<!doctype x system "uri">',
            '<!doctype x public "id" "uri">'),
    "ognl": ("_memberaccess", "@java.lang.runtime",
             "@java.lang.processbuilder", "#context[", "ognl."),
    "ssi": ("<!--#exec", "<!--#include", "<!--#echo"),
    "ldapi": (")(|", ")(&", "*)($", ")(uid="),
}

_BODY_BRANCHES = {
    "rce": (";cat /etc/passwd", "||curl", "$(id)", "<?php"),
    "crlf": (";set-cookie: a=b", ";location: /path",
             ";content-length: 5", ";to: a@example.test"),
}


def _shield(state):
    sh = P.NetShield(state_dir=state)
    sh.cfg["enabled"] = True
    sh.cfg["persist_bans"] = False
    return sh


def test_all_guarded_branches_survive_head_and_body_prefilters():
    # Each branch family supplies at least one positive with a mandatory literal.
    # The direct scanner uses raw strings too, so mixed ASCII case is exercised.
    head, body = dict(P._SIG_RE), dict(P._SIG_RE_BODY)
    with tempfile.TemporaryDirectory() as state:
        sh = _shield(state)
        for name, cases in _HEAD_BRANCHES.items():
            guards = P._SIG_GUARD[name]
            for sample in cases:
                assert head[name].search(sample), (name, sample)
                assert any(lit in sample.lower() for lit in guards), (name, sample)
                for raw in (sample, sample.upper()):
                    assert sh._scan_signatures(raw, only=frozenset({name}))[0] == name, (name, raw)
        for name, cases in _BODY_BRANCHES.items():
            guards = P._SIG_GUARD[name]
            for sample in cases:
                assert body[name].search(sample), (name, sample)
                assert any(lit in sample.lower() for lit in guards), (name, sample)
                for raw in (sample, sample.upper()):
                    assert sh._scan_signatures(raw, only=frozenset({name}), body=True)[0] == name, (name, raw)
        # Private direct calls expect a normalized window. The production entry
        # point folds optional spaces around '=' before the literal prefilter.
        for raw in ("or 1 = 1", "OR\t1 =\t1"):
            assert sh._scan_field(raw)[0] == "sqli"


def test_unicode_ignorecase_does_not_skip_regexes():
    # CPython re.IGNORECASE has four extra ASCII-equivalent Unicode letters.
    # A byte-oriented prescan and ASCII literal guards cannot classify these.
    with tempfile.TemporaryDirectory() as state:
        sh = _shield(state)
        for raw, name in (("<\u017fcript>", "xss"),
                          ("jnd\u0131:ldap", "jndi"),
                          ("jnd\u0130:ldap", "jndi"),
                          ("ni\u212ato", "scanner_ua")):
            assert dict(P._SIG_RE)[name].search(raw), (name, raw)
            assert sh._scan_signatures(raw, only=frozenset({name}))[0] == name, (name, raw)


def test_high_expansion_nfkc_fast_path_is_exact():
    rng = random.Random(11)
    pool = ("a", "<", "\u0301", "\u0316", "\u0f73", "\uff1c", "\u1100", "\u1161") + P._HIGH_EXPAND_CHARS
    cases = ["\ufdfa" * 8000, "\ufdfa" * 4000 + "＜script＞",
             "\u0301\u0316" * 1500, "\ufdfa\u0301" * 1700]
    cases.extend("".join(rng.choice(pool) for _ in range(rng.randrange(1024, 2200)))
                 for _ in range(40))
    for sample in cases:
        assert P._nfkc_for_scan(sample) == unicodedata.normalize("NFKC", sample)
    with tempfile.TemporaryDirectory() as state:
        sh = _shield(state)
        assert sh._scan_field("\ufdfa" * 4000 + "&y=＜script＞")[0] == "xss"
        assert sh._scan_field("\ufdfa" * 100 + "&y=ordinary text")[0] is None
