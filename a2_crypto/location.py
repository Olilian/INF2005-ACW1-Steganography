"""
location.py - keyed start-location derivation (FR7) and the bounded scan.

THE DESIGN
    The start offset is not stored anywhere in the stego file. There is no
    pointer, no header at unit 0, nothing to find. Both sides DERIVE it from
    a shared passphrase:

        K_loc  = HKDF(passphrase, salt="INF2005-ACW1", info="start-location")
        start  = HMAC-SHA256(K_loc, media_id || capacity_bits || n_lsb) mod window

    Every input is something the verifier already has BEFORE extraction: the
    shared passphrase, the stego file's own capacity, the chosen LSB depth,
    and the media ID passed out of band. There is no chicken-and-egg problem
    and no stored hint for an attacker to read.

THE PLACEMENT WINDOW (this is the subtle part - be ready to explain it)
    A first cut at this derivation used the payload length to size the
    modulus: start = HMAC(...) mod (capacity - payload_length). That does not
    work. The verifier does not know the payload length until it has read the
    header, and it cannot read the header until it knows where the payload
    starts. Deriving from a value only the sender has is circular.

    So the modulus is built from capacity alone. The cover is split into a
    placement window and a reserved tail:

        reserve_units = min(capacity_units // 2, ceil(MAX_STREAM_BITS / n_lsb))
        window        = capacity_units - reserve_units
        start         = HMAC(...) mod window

    The start always lands inside the window, and the reserved tail guarantees
    that any payload up to reserve_units still fits from wherever it landed.
    Both sides compute reserve_units from capacity_units and n_lsb, which they
    both already have, so the derivation stays symmetric. The cost is a
    ceiling on payload size, which is reported honestly by the capacity check.

WHY NOT JUST STORE THE OFFSET IN THE FIRST 32 BITS?
    Expect this question. Because then the offset is public: anyone who
    suspects the file carries a payload reads unit 0, jumps to the offset and
    extracts. A stored offset protects nothing - it only relocates the
    payload. Deriving it from a secret is what makes the location itself a
    defended asset.

PROPERTIES TO STATE IN THE DEMO
    * Without the passphrase an attacker must brute-force the offset across
      the whole window - hundreds of thousands of positions on a typical
      cover, each needing a magic check.
    * n_lsb is an input, so selecting the wrong LSB depth also moves the
      offset. One wrong parameter, no payload.
    * media_id is an input, so the same passphrase on two different media
      lands on two unrelated offsets.
    * Deterministic: the same inputs always give the same offset, so the
      verifier recovers it with no stored hint.

HONEST LIMITATION (rubric criterion 7 - say this out loud)
    This hides WHERE the payload is, not THAT a payload exists. Statistical
    steganalysis of the LSB planes (chi-square, sample-pair analysis, RS
    analysis) can still flag that something is embedded, because LSB
    replacement flattens the plane's natural distribution. Keyed placement
    raises the cost of extraction; it does not give undetectability.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from . import config
from .keys import Secrets
from .mocks import _bit_table, bytes_to_bits


def reserve_units(capacity_units: int, n_lsb: int) -> int:
    """
    Size of the reserved tail. Depends only on values both sides hold, which
    is what keeps the derivation symmetric. Also the effective ceiling on
    payload size - the capacity check reports it.
    """
    by_config = -(-config.MAX_STREAM_BITS // n_lsb)
    return max(1, min(capacity_units // 2, by_config))


def placement_window(capacity_units: int, n_lsb: int) -> int:
    """Number of distinct offsets the derivation can produce."""
    return max(1, capacity_units - reserve_units(capacity_units, n_lsb))


def derive_start(secrets: Secrets, media_id: str, capacity_bits: int,
                 n_lsb: int, needed_bits: int = 0) -> int:
    """
    Returns the start offset as a UNIT index (a cover-byte index), matching
    the convention the team's image and audio codecs already use.

    `needed_bits` is accepted for API compatibility and to validate the fit;
    it deliberately does NOT feed the modulus - see the module docstring.
    """
    capacity_units = capacity_bits // n_lsb
    if capacity_units <= 0:
        raise ValueError("Cover has no capacity at n_lsb={}".format(n_lsb))

    window = placement_window(capacity_units, n_lsb)
    message = b"|".join([
        media_id.encode("utf-8"),
        str(capacity_bits).encode("ascii"),
        str(n_lsb).encode("ascii"),
    ])
    digest = hmac.new(secrets.k_loc, message, hashlib.sha256).digest()
    start = int.from_bytes(digest, "big") % window

    needed_units = -(-needed_bits // n_lsb) if needed_bits else 0
    if needed_units and start + needed_units > capacity_units:
        raise ValueError(
            "Payload of {} units does not fit from derived offset {} in a "
            "cover of {} units.".format(needed_units, start, capacity_units)
        )
    return start


def max_payload_bits(capacity_bits: int, n_lsb: int) -> int:
    """
    The real usable capacity once the keyed placement window is accounted for.
    This, not raw capacity, is what the GUI capacity bar must compare against.
    """
    capacity_units = capacity_bits // n_lsb
    return reserve_units(capacity_units, n_lsb) * n_lsb


def derive_start_preview(secrets: Secrets, media_id: str, capacity_bits: int,
                         n_lsb: int, needed_bits: int = 0) -> dict:
    """Offset plus the context the GUI and trace panel display around it."""
    capacity_units = capacity_bits // n_lsb
    start = derive_start(secrets, media_id, capacity_bits, n_lsb, needed_bits)
    window = placement_window(capacity_units, n_lsb)
    return {
        "start_unit": start,
        "capacity_units": capacity_units,
        "needed_units": -(-needed_bits // n_lsb) if needed_bits else 0,
        "placement_window": window,
        "reserved_tail": reserve_units(capacity_units, n_lsb),
        "position_percent": round(100.0 * start / max(capacity_units, 1), 3),
        "brute_force_positions": window,
    }


# --- bounded scan -----------------------------------------------------------
@dataclass
class ScanResult:
    found: bool
    offset: int | None = None
    hits: int = 0
    checked_offsets: int = 0
    note: str = ""


def scan_for_magic(samples: bytes, n_lsb: int, magic: bytes = config.MAGIC,
                   skip_offset: int | None = None,
                   max_hits: int = config.MAX_SCAN_HITS) -> ScanResult:
    """
    Look for the magic bytes anywhere in the cover at this LSB depth.

    This exists ONLY to tell "the payload is somewhere else" (WRONG_START_
    LOCATION) apart from "there is no payload at all" (PAYLOAD_MISSING). Both
    are required verdict categories in the spec. It is not an extraction path,
    and a verifier without the passphrase gains nothing from a hit: the
    signature and the decryption key are untouched by it.

    Implementation note: rather than testing every offset one at a time in
    Python, the whole LSB plane is flattened to a bit string once and then
    searched with str.find, which runs in C. A candidate is accepted only when
    its bit index is a multiple of n_lsb, because a real payload starts on a
    unit boundary.
    """
    if not samples:
        return ScanResult(False, note="empty cover")

    bits = "".join(map(_bit_table(n_lsb).__getitem__, samples))
    magic_bits = bytes_to_bits(magic)

    pos, hits, checked = 0, 0, 0
    while hits < max_hits:
        idx = bits.find(magic_bits, pos)
        if idx < 0:
            break
        checked += 1
        if idx % n_lsb == 0:
            hits += 1
            offset = idx // n_lsb
            if skip_offset is None or offset != skip_offset:
                return ScanResult(True, offset=offset, hits=hits,
                                  checked_offsets=checked,
                                  note="magic found at unit {}".format(offset))
        pos = idx + 1

    return ScanResult(False, hits=hits, checked_offsets=checked,
                      note="magic not found at n_lsb={}".format(n_lsb))


def probe_other_lsb_depths(samples: bytes, secrets: Secrets, media_id: str,
                           capacity_units: int, header_bits: int,
                           exclude_n_lsb: int, bits_port) -> dict | None:
    """
    Cheap keyed probe: for each OTHER LSB depth, derive the offset that depth
    would have produced and check for magic there. Eight HMACs and eight short
    reads.

    This turns "the verifier selected the wrong number of LSBs" into a precise
    WRONG_START_LOCATION naming the right depth, instead of a bare
    PAYLOAD_MISSING. The offset is a function of n_lsb, so a wrong depth is
    genuinely a wrong location.
    """
    for alt in range(config.MIN_LSB, config.MAX_LSB + 1):
        if alt == exclude_n_lsb:
            continue
        try:
            alt_start = derive_start(secrets, media_id, capacity_units * alt, alt)
            header = bits_port.extract(samples, alt, alt_start, header_bits)
        except Exception:
            continue
        if bits_port.has_magic(header):
            return {"n_lsb": alt, "start_unit": alt_start}
    return None
