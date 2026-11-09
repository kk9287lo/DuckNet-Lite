"""A full replay cache must not rescan every nonce for every rejected MAC."""

from test_admin_browser_mac import _clocked_browser_auth


class _CountedNonces(dict):
    def __init__(self, entries):
        super().__init__(entries)
        self.scans = 0

    def items(self):
        self.scans += 1
        return super().items()


def test_full_browser_nonce_cache_rejects_without_repeated_linear_prunes():
    with _clocked_browser_auth(max_nonces=8192) as (app, clock, signed, authorize):
        first = signed("a" * 32)
        assert authorize(first) is True
        assert authorize(signed("b" * 32)) is True
        for number in range(8190):
            assert authorize(signed(f"{number:032x}")) is True
        assert len(app._browser_nonces) == 8192
        assert clock.mono < app._browser_nonce_prune_at

        # An authenticated peer can send fresh MACs after the cap fills. The
        # old path rebuilt the full cache on every rejected request, making a
        # bounded-memory defense an avoidable CPU multiplier.
        scans = 0
        for number in range(20):
            counted = _CountedNonces(app._browser_nonces)
            app._browser_nonces = counted
            assert authorize(signed(f"{number + 8190:032x}")) is False
            scans += counted.scans
        assert scans == 0, scans

        assert authorize(first) is False              # no replay after a full cache
        assert authorize({"X-Token": app.token}) is True  # CLI control remains available
        clock.mono += 61
        clock.wall += 61
        assert authorize(signed("f" * 32)) is True  # expiry still reclaims capacity
