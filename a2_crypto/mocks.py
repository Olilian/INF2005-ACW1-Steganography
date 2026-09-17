"""
mocks.py - reference implementations of both ports.

These exist so A2 is fully testable and demoable on day one with no PNG, no
WAV and no teammate code present. When person 1's real Bitstream or persons
3 and 4's real Codecs land, they are passed into protect()/verify() instead
and NOTHING inside a2_crypto changes.

BIT ORDER (must match the team's codecs exactly, or nothing interoperates)
    Bytes are expanded MSB-first. The resulting bit string is consumed in
    groups of n_lsb, MSB-first, one group per cover unit. The trailing group
    is zero-padded. This is the same convention the existing image_codec.py
    and audio_codec.py already use, so the reference bitstream and the team's
    codecs read each other's bits identically.
"""
from __future__ import annotations

import os
import struct

from . import config
from .errors import HeaderError


# --- bit helpers ------------------------------------------------------------
_BIT_TABLES: dict[int, list[str]] = {}


def _bit_table(n_lsb: int) -> list[str]:
    """
    256-entry lookup of "low n_lsb bits as a binary string". Keeps the
    whole-cover scan in location.py fast enough to stay interactive.
    """
    tbl = _BIT_TABLES.get(n_lsb)
    if tbl is None:
        low = (1 << n_lsb) - 1
        tbl = [format(v & low, "0{}b".format(n_lsb)) for v in range(256)]
        _BIT_TABLES[n_lsb] = tbl
    return tbl


def bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)


def bits_to_bytes(bits: str) -> bytes:
    usable = len(bits) - (len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, usable, 8))


def units_for_bits(num_bits: int, n_lsb: int) -> int:
    """Ceiling division - how many cover units carry num_bits at this depth."""
    return -(-num_bits // n_lsb)


def read_bits(samples: bytes, n_lsb: int, start: int, num_units: int) -> str:
    tbl = _bit_table(n_lsb)
    end = start + num_units
    return "".join(map(tbl.__getitem__, samples[start:end]))


# --- ReferenceBitstream -----------------------------------------------------
class ReferenceBitstream:
    """
    Self-describing header, so a decoder learns the payload and signature
    lengths before it reads them:

        MAGIC "INF2" (4B) | VER u8 | ALG u8 | N_LSB u8 | FLAGS u8
                          | PAYLOAD_LEN u32 | SIG_LEN u16      = 14 bytes

    N_LSB is stored even though the verifier already supplies it: on a magic
    hit it lets the decoder confirm the depth it was told to use is the depth
    that was actually written.
    """

    MAGIC = config.MAGIC
    HEADER_SIZE = config.HEADER_SIZE_BYTES

    # -- framing ------------------------------------------------------------
    def pack(self, payload: bytes, sig: bytes, n_lsb: int, algo_id: int = 0) -> bytes:
        header = struct.pack(
            config.HEADER_STRUCT,
            self.MAGIC, config.BITSTREAM_VERSION, algo_id, n_lsb, 0,
            len(payload), len(sig),
        )
        return header + payload + sig

    def unpack(self, stream: bytes) -> tuple[bytes, bytes]:
        p_len, s_len, _ = self._parse_header(stream[:self.HEADER_SIZE])
        total = self.HEADER_SIZE + p_len + s_len
        if len(stream) < total:
            raise HeaderError(
                "Stream is {} bytes but the header declares {}.".format(len(stream), total)
            )
        payload = stream[self.HEADER_SIZE:self.HEADER_SIZE + p_len]
        sig = stream[self.HEADER_SIZE + p_len:total]
        return payload, sig

    # -- header introspection (used by the verdict tree) --------------------
    def has_magic(self, header: bytes) -> bool:
        return len(header) >= 4 and header[:4] == self.MAGIC

    def header_info(self, header: bytes) -> dict:
        p_len, s_len, fields = self._parse_header(header)
        return {
            "payload_len": p_len,
            "sig_len": s_len,
            "version": fields[1],
            "algo_id": fields[2],
            "algo": config.ALGO_BY_ID.get(fields[2], "id{}".format(fields[2])),
            "n_lsb": fields[3],
            "flags": fields[4],
        }

    def declared_total_bits(self, header: bytes) -> int:
        p_len, s_len, _ = self._parse_header(header)
        return (self.HEADER_SIZE + p_len + s_len) * 8

    def header_size_bits(self, n_lsb: int = 1) -> int:
        return self.HEADER_SIZE * 8

    def _parse_header(self, header: bytes):
        if len(header) < self.HEADER_SIZE:
            raise HeaderError(
                "Header truncated: got {} bytes, need {}.".format(
                    len(header), self.HEADER_SIZE)
            )
        fields = struct.unpack(config.HEADER_STRUCT, header[:self.HEADER_SIZE])
        if fields[0] != self.MAGIC:
            raise HeaderError("Magic bytes absent.")
        p_len, s_len = fields[5], fields[6]
        if p_len == 0 or p_len > config.MAX_PAYLOAD_BYTES:
            raise HeaderError("Declared payload length {} is out of range.".format(p_len))
        return p_len, s_len, fields

    # -- carrier ------------------------------------------------------------
    def embed(self, samples: bytes, stream: bytes, n_lsb: int, start: int) -> bytes:
        bits = bytes_to_bits(stream)
        bits += "0" * ((-len(bits)) % n_lsb)
        num_units = len(bits) // n_lsb

        if start < 0 or start + num_units > len(samples):
            raise HeaderError(
                "Stream needs {} units from offset {}, cover has {}.".format(
                    num_units, start, len(samples))
            )

        out = bytearray(samples)
        mask = 0xFF ^ ((1 << n_lsb) - 1)
        for i in range(num_units):
            chunk = int(bits[i * n_lsb:(i + 1) * n_lsb], 2)
            idx = start + i
            out[idx] = (out[idx] & mask) | chunk
        return bytes(out)

    def extract(self, samples: bytes, n_lsb: int, start: int, max_bits: int) -> bytes:
        num_units = units_for_bits(max_bits, n_lsb)
        if start < 0 or start >= len(samples):
            raise HeaderError(
                "Start offset {} outside cover of {} units.".format(start, len(samples))
            )
        available = min(num_units, len(samples) - start)
        bits = read_bits(samples, n_lsb, start, available)
        return bits_to_bytes(bits[:max_bits])


# --- MemoryCodec ------------------------------------------------------------
class MemoryCodec:
    """
    Treats a plain bytearray as the cover. No PNG, no WAV, no teammates.
    Everything in the A2 plan is buildable and demoable against this alone.
    """

    media_type = "memory"

    def __init__(self, seed: int | None = None):
        self._seed = seed

    def make_cover(self, n_units: int, seed: int | None = None) -> bytearray:
        """Pseudo-random cover, so masked digests are not degenerate."""
        import random
        rng = random.Random(seed if seed is not None else self._seed)
        return bytearray(rng.randrange(256) for _ in range(n_units))

    def load(self, path: str) -> bytearray:
        with open(path, "rb") as fh:
            return bytearray(fh.read())

    def save(self, view: bytearray, path: str) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(bytes(view))

    def capacity_bits(self, view: bytearray, n_lsb: int) -> int:
        return len(view) * n_lsb

    def read_samples(self, view: bytearray) -> bytes:
        return bytes(view)

    def write_samples(self, view: bytearray, data: bytes) -> bytearray:
        return bytearray(data)          # new object - never mutates `view`
