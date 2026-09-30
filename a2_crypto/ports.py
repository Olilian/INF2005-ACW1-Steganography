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

    # -- optional ------------------------------------------------------------
    # A codec MAY also provide:
    #
    #     def digest_samples(self, view: CoverView) -> bytes
    #
    # the bytes the integrity hash should cover. It defaults to read_samples()
    # and only needs implementing when the two differ.
    #
    # WHY THIS EXISTS (it is not decoration - it closed a real hole)
    #     read_samples() answers "which bytes does the carrier address?".
    #     The hash needs to answer "which bytes does integrity cover?". For
    #     the image codec those are the same set, so nothing changes. For
    #     WAV/PCM they are NOT: the audio codec only embeds into the low byte
    #     of each multi-byte sample, because flipping a bit in a HIGH byte is
    #     audible. Hashing read_samples() therefore left every high byte -
    #     the perceptually dominant half of the file - outside the integrity
    #     check, and an attacker who rewrote only high bytes could destroy
    #     the audio while it still verified as Authentic.
    #
    #     Splitting the two questions fixes that without touching the
    #     carrier: digest_samples() returns ALL the media's bytes, while
    #     read_samples() keeps returning only the embeddable ones. The masked
    #     digest stays invariant across embedding either way, because
    #     embedding only ever writes the bottom n_lsb bits of embeddable
    #     bytes and the mask clears exactly those.


@runtime_checkable
class Bitstream(Protocol):
    """Implemented by person 1."""

    def pack(self, payload: bytes, sig: bytes, n_lsb: int, algo_id: int = 0) -> bytes: ...

    def unpack(self, stream: bytes) -> tuple[bytes, bytes]: ...

    def embed(self, samples: bytes, stream: bytes, n_lsb: int, start: int) -> bytes: ...

    def extract(self, samples: bytes, n_lsb: int, start: int, max_bits: int) -> bytes: ...

    def header_size_bits(self, n_lsb: int) -> int: ...

    def capacity_check(self, cover_units: int, blob_size_bytes: int,
                       bit_depth: int) -> dict:
        """
        Does a blob of `blob_size_bytes` fit in `cover_units` units at this
        bit depth? Returns at least {"fits": bool, "required_units": int}.

        This is the bitstream engine's arithmetic, not A2's, and it belongs
        there: how many units a blob occupies is a property of how the engine
        packs bits, so the engine is the only component that can answer it
        without duplicating its own packing rules.

        A2 still decides HOW MANY units are offered - that depends on the
        keyed placement window reserving a tail (location.py), which is A2's
        concern. The split is: A2 says how much room there is, the engine
        says whether the blob fits in it.
        """
        ...

    def declared_total_bits(self, header: bytes) -> int:
        """Total bits (header + payload + signature) the header says follow."""
        ...

    def has_magic(self, header: bytes) -> bool: ...
