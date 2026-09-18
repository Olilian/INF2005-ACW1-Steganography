"""Exception types A2 raises across its public surface."""
from __future__ import annotations


class A2Error(Exception):
    """Base for everything this package raises deliberately."""


class CapacityError(A2Error):
    """Payload does not fit in the cover at the chosen LSB depth."""

    def __init__(self, needed_bits: int, capacity_bits: int, n_lsb: int):
        self.needed_bits = needed_bits
        self.capacity_bits = capacity_bits
        self.n_lsb = n_lsb
        super().__init__(
            f"Payload needs {needed_bits:,} bits but the cover only offers "
            f"{capacity_bits:,} bits at {n_lsb} LSB(s)."
        )


class HeaderError(A2Error):
    """The extracted header is absent, malformed or self-inconsistent."""


class KeyError_(A2Error):
    """Key material missing, unreadable or of the wrong type."""


class DecryptionError(A2Error):
    """AES-GCM authentication failed - wrong passphrase or corrupt ciphertext."""
