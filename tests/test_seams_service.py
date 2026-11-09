"""Benign startup address syntax and normalization controls."""
from dataplane import service


def test_backend_address_rejects_discarded_bracket_suffixes():
    for value in ("[::1]ignored", "[::1]ignored:8080", "[]:8080"):
        try:
            service._split_hostport(value, 80)
        except SystemExit:
            continue
        raise AssertionError("malformed address silently accepted: " + value)


def test_backend_address_keeps_valid_bracket_and_hostname_controls():
    for value, expected in (("[::1]:8080", ("::1", 8080)),
                            ("[::1]", ("::1", 80)),
                            ("::1", ("::1", 80)),
                            ("app.example:8080", ("app.example", 8080)),
                            ("app.example", ("app.example", 80))):
        assert service._split_hostport(value, 80) == expected
