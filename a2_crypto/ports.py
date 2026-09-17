"""
ports.py - the only thing A2 knows about the outside world.

Person 1 implements Bitstream, persons 3 and 4 implement Codec. A2 never
imports their modules; it is handed objects that satisfy these Protocols.
`mocks.py` ships a reference implementation of both so this layer is
testable and demoable with no teammate code present.

Unit convention (shared with the team's existing codecs):
    one "unit" = one addressable cover byte (an image channel value, or one
    byte of PCM audio). A start offset is a unit index, not a bit index.
    capacity_bits == number_of_units * n_lsb.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

# A CoverView is whatever the codec wants it to be - a numpy array, a
# (array, params) tuple, a bytearray. A2 treats it as opaque and only ever
# passes it back to the codec that produced it.
CoverView = Any


@runtime_checkable
class Codec(Protocol):
    """Implemented by the image codec (person 3) and audio codec (person 4)."""

    def load(self, path: str) -> CoverView: ...

    def save(self, view: CoverView, path: str) -> None: ...

    def capacity_bits(self, view: CoverView, n_lsb: int) -> int: ...

    def read_samples(self, view: CoverView) -> bytes:
        """Flat byte view of the cover's embeddable units."""
        ...

    def write_samples(self, view: CoverView, data: bytes) -> CoverView:
        """Return a NEW view with `data` as its units - must not mutate `view`."""
        ...


@runtime_checkable
class Bitstream(Protocol):
    """Implemented by person 1."""

    def pack(self, payload: bytes, sig: bytes, n_lsb: int, algo_id: int = 0) -> bytes: ...

    def unpack(self, stream: bytes) -> tuple[bytes, bytes]: ...

    def embed(self, samples: bytes, stream: bytes, n_lsb: int, start: int) -> bytes: ...

    def extract(self, samples: bytes, n_lsb: int, start: int, max_bits: int) -> bytes: ...

    def header_size_bits(self, n_lsb: int) -> int: ...

    def declared_total_bits(self, header: bytes) -> int:
        """Total bits (header + payload + signature) the header says follow."""
        ...

    def has_magic(self, header: bytes) -> bool: ...
