"""
selftest.py - the 18 internal test cases for the A2 layer.

    python -m a2_crypto.selftest

Everything here runs against MemoryCodec and ReferenceBitstream, so it passes
with no PNG, no WAV and no teammate code present. Anyone dropping in a
different build of A2 runs this first to confirm the replacement works.

These are unit tests of this layer only. The team's own positive/negative demo
cases (person 6) sit on top of them.
"""
from __future__ import annotations

import os
import sys
import time
import traceback

from . import config
from .errors import CapacityError
from .hashing import stable_digest
from .keys import derive_secrets, generate_keypair
from .location import derive_start, placement_window
from .mocks import MemoryCodec, ReferenceBitstream
from .payload import build_payload, canonical_bytes
from .pipeline import protect, verify
from .verdict import VerdictCode

TESTDATA = os.path.join(os.path.dirname(__file__), "testdata")
PASSPHRASE = "team-P1-4-shared-passphrase"
MEDIA_ID = "IMG-0007"
COVER_UNITS = 200_000


# --- harness ----------------------------------------------------------------
class Results:
    def __init__(self):
        self.rows = []

    def record(self, num, name, ok, note=""):
        self.rows.append((num, name, ok, note))
        mark = "PASS" if ok else "FAIL"
        line = "  [{}] {:>2}. {}".format(mark, num, name)
        if note:
            line += "  ({})".format(note)
        print(line)

    @property
    def failed(self):
        return [r for r in self.rows if not r[2]]


def _load(name: str) -> str:
    with open(os.path.join(TESTDATA, name), encoding="utf-8") as fh:
        return fh.read()


def _fresh(bf=ReferenceBitstream, seed=42, units=COVER_UNITS):
    """bf is the Bitstream factory under test - ReferenceBitstream by default,
    person 1's engine when a2_integration re-runs this suite against it."""
    codec = MemoryCodec(seed=seed)
    return codec, bf(), codec.make_cover(units, seed=seed)


def _protect(cover, codec, bits, message, n_lsb=2, priv=None, media_id=MEDIA_ID,
             passphrase=PASSPHRASE, algo=None, encrypt=True):
    return protect(cover, message, media_id, n_lsb, passphrase, priv,
                   codec=codec, bits=bits, media_type="image", algo=algo,
                   encrypt=encrypt)


def _verify(view, codec, bits, pub, n_lsb=2, media_id=MEDIA_ID, passphrase=PASSPHRASE):
    return verify(view, media_id, n_lsb, passphrase, pub, codec=codec, bits=bits)


# --- the 18 cases -----------------------------------------------------------
def run(verbose: bool = False, bits_factory=ReferenceBitstream) -> Results:
    bf = bits_factory
    r = Results()
    kb = generate_keypair("ed25519")
    short, large = _load("payload_short.txt"), _load("payload_large.txt")
    custom = _load("payload_custom.json")

    # 1 - round trip, short message, 1 LSB
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=1, priv=kb.private_key)
    v = _verify(res.stego_view, codec, bits, kb.public_key, n_lsb=1)
    r.record(1, "Round-trip short message @ n_lsb=1",
             v.code is VerdictCode.AUTHENTIC and v.message_text() == short,
             "offset {}".format(res.start_unit))

    # 2 - round trip, large message, 4 LSB
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, large, n_lsb=4, priv=kb.private_key)
    v = _verify(res.stego_view, codec, bits, kb.public_key, n_lsb=4)
    r.record(2, "Round-trip large message @ n_lsb=4",
             v.code is VerdictCode.AUTHENTIC and v.message_text() == large,
             "{} byte message".format(len(large)))

    # 3 - every LSB depth 1..8
    ok_all, notes = True, []
    for n in range(config.MIN_LSB, config.MAX_LSB + 1):
        codec, bits, cover = _fresh(bf)
        res = _protect(cover, codec, bits, short, n_lsb=n, priv=kb.private_key)
        v = _verify(res.stego_view, codec, bits, kb.public_key, n_lsb=n)
        good = v.code is VerdictCode.AUTHENTIC and v.message_text() == short
        ok_all &= good
        notes.append("{}{}".format(n, "" if good else "!"))
    r.record(3, "Round-trip across all n_lsb 1-8", ok_all, " ".join(notes))

    # 4 - masking invariance (the core identity)
    codec, bits, cover = _fresh(bf)
    before = stable_digest(codec.read_samples(cover), 3)
    res = _protect(cover, codec, bits, short, n_lsb=3, priv=kb.private_key)
    after = stable_digest(codec.read_samples(res.stego_view), 3)
    r.record(4, "stable_digest identical before and after embedding",
             before == after, before.hex()[:16] + "...")

    # 5 - canonical bytes stable under dict reordering
    s = derive_secrets(PASSPHRASE)
    p = build_payload(b"\x11" * 32, MEDIA_ID, "image", 2, short, s)
    d = p.to_dict()
    reordered = {k: d[k] for k in sorted(d, reverse=True)}
    r.record(5, "canonical_bytes stable across dict reordering",
             canonical_bytes(p) == canonical_bytes(reordered))

    # 6 - flip a high-order content bit -> TAMPERED
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=kb.private_key)
    sam = bytearray(codec.read_samples(res.stego_view))
    victim = (res.start_unit + 50_000) % len(sam)
    sam[victim] ^= 0x80                     # top bit, outside the LSB planes
    v = _verify(codec.write_samples(res.stego_view, bytes(sam)), codec, bits, kb.public_key)
    r.record(6, "Flip high-order content bit -> Tampered",
             v.code is VerdictCode.TAMPERED, str(v.code))

    # 7 - flip a bit inside the payload region -> SIGNATURE_INVALID
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=kb.private_key)
    sam = bytearray(codec.read_samples(res.stego_view))
    # a unit well inside the payload body, past the 14-byte header
    sam[res.start_unit + 200] ^= 0x01
    v = _verify(codec.write_samples(res.stego_view, bytes(sam)), codec, bits, kb.public_key)
    r.record(7, "Flip payload bit -> Signature Invalid",
             v.code is VerdictCode.SIGNATURE_INVALID, str(v.code))

    # 8 - verify under a different public key -> SIGNATURE_INVALID
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=kb.private_key)
    impostor = generate_keypair("ed25519")
    v = _verify(res.stego_view, codec, bits, impostor.public_key)
    r.record(8, "Wrong public key -> Signature Invalid",
             v.code is VerdictCode.SIGNATURE_INVALID, str(v.code))

    # 9 - wrong passphrase -> WRONG_START_LOCATION
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=kb.private_key)
    v = _verify(res.stego_view, codec, bits, kb.public_key, passphrase="not-the-passphrase")
    r.record(9, "Wrong passphrase -> Wrong Start Location",
             v.code is VerdictCode.WRONG_START_LOCATION,
             "found at {}".format(v.details.get("found_at")))

    # 10 - wrong n_lsb -> WRONG_START_LOCATION
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=kb.private_key)
    v = _verify(res.stego_view, codec, bits, kb.public_key, n_lsb=3)
    r.record(10, "Wrong n_lsb -> Wrong Start Location",
             v.code is VerdictCode.WRONG_START_LOCATION,
             "correct depth reported: {}".format(v.details.get("correct_n_lsb")))

    # 11 - clean cover with no payload -> PAYLOAD_MISSING
    codec, bits, cover = _fresh(bf)
    v = _verify(cover, codec, bits, kb.public_key)
    r.record(11, "Clean cover -> Payload Missing",
             v.code is VerdictCode.PAYLOAD_MISSING, str(v.code))

    # 12 - payload larger than capacity -> CapacityError
    codec2 = MemoryCodec(seed=5)
    tiny = codec2.make_cover(600, seed=5)
    raised = False
    try:
        _protect(tiny, codec2, bits, large * 4, n_lsb=1, priv=kb.private_key)
    except CapacityError as exc:
        raised = True
        note = "needs {:,} bits, {:,} usable".format(exc.needed_bits, exc.capacity_bits)
    r.record(12, "Oversized payload -> CapacityError", raised,
             note if raised else "no exception raised")

    # 13 - corrupt header -> CANNOT_VERIFY
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=kb.private_key)
    sam = bytearray(codec.read_samples(res.stego_view))
    # keep the magic intact, but wreck the declared payload length field
    for i in range(9 * 8 // 2, 13 * 8 // 2):
        sam[res.start_unit + i] |= 0x03
    v = _verify(codec.write_samples(res.stego_view, bytes(sam)), codec, bits, kb.public_key)
    r.record(13, "Corrupt header -> Cannot Verify",
             v.code is VerdictCode.CANNOT_VERIFY, str(v.code))

    # 14 - right signature, right hash, wrong decryption passphrase
    #      The location key and the message key come from the same passphrase,
    #      so a wrong passphrase normally fails earlier at the offset. This
    #      case isolates the decryption branch by keeping the location key and
    #      corrupting only the ciphertext's authenticity.
    codec, bits, cover = _fresh(bf)
    v14 = _decryption_failure_case(codec, bits, cover, kb, short)
    r.record(14, "Correct sig + hash, GCM tag fails -> Cannot Verify",
             v14.code is VerdictCode.CANNOT_VERIFY and "decrypt" in str(v14.details),
             str(v14.code))

    # 15 - derive_start deterministic across 1000 runs
    s = derive_secrets(PASSPHRASE)
    offs = {derive_start(s, MEDIA_ID, COVER_UNITS * 2, 2) for _ in range(1000)}
    r.record(15, "derive_start deterministic over 1000 runs", len(offs) == 1,
             "offset {}".format(offs.pop() if offs else "?"))

    # 16 - distribution across 10k media IDs, no clustering at the edges
    window = placement_window(COVER_UNITS, 1)
    samples = [derive_start(s, "ID-{}".format(i), COVER_UNITS, 1) for i in range(10_000)]
    low = sum(1 for o in samples if o < window * 0.05)
    high = sum(1 for o in samples if o > window * 0.95)
    # expect ~500 in each 5% band; allow a generous 3x band
    ok16 = 200 < low < 900 and 200 < high < 900
    r.record(16, "derive_start distribution has no edge clustering", ok16,
             "first 5%: {}, last 5%: {} (expect ~500 each)".format(low, high))

    # 17 - the whole pipeline under RSA-2048-PSS
    rsa = generate_keypair("rsa2048-pss")
    codec, bits, cover = _fresh(bf)
    res = _protect(cover, codec, bits, short, n_lsb=2, priv=rsa.private_key)
    v_ok = _verify(res.stego_view, codec, bits, rsa.public_key)
    sam = bytearray(codec.read_samples(res.stego_view))
    sam[(res.start_unit + 50_000) % len(sam)] ^= 0x80
    v_tam = _verify(codec.write_samples(res.stego_view, bytes(sam)), codec, bits, rsa.public_key)
    sam2 = bytearray(codec.read_samples(res.stego_view))
    sam2[res.start_unit + 200] ^= 0x01
    v_sig = _verify(codec.write_samples(res.stego_view, bytes(sam2)), codec, bits, rsa.public_key)
    v_key = _verify(res.stego_view, codec, bits, generate_keypair("rsa2048-pss").public_key)
    r.record(17, "RSA-2048-PSS passes cases 1, 6, 7 and 8",
             v_ok.code is VerdictCode.AUTHENTIC
             and v_tam.code is VerdictCode.TAMPERED
             and v_sig.code is VerdictCode.SIGNATURE_INVALID
             and v_key.code is VerdictCode.SIGNATURE_INVALID,
             "sig {} bytes".format(len(res.signature)))

    # 18 - no state leakage between back-to-back verifications
    codecA, bitsA, coverA = _fresh(bf, seed=1)
    codecB, bitsB, coverB = _fresh(bf, seed=2)
    resA = _protect(coverA, codecA, bitsA, short, n_lsb=2, priv=kb.private_key,
                    media_id="IMG-A", passphrase="passphrase-A")
    resB = _protect(coverB, codecB, bitsB, custom, n_lsb=5, priv=kb.private_key,
                    media_id="AUD-B", passphrase="passphrase-B")
    vA = verify(resA.stego_view, "IMG-A", 2, "passphrase-A", kb.public_key,
                codec=codecA, bits=bitsA)
    vB = verify(resB.stego_view, "AUD-B", 5, "passphrase-B", kb.public_key,
                codec=codecB, bits=bitsB)
    vA2 = verify(resA.stego_view, "IMG-A", 2, "passphrase-A", kb.public_key,
                 codec=codecA, bits=bitsA)
    r.record(18, "Back-to-back verifications do not leak state",
             vA.code is VerdictCode.AUTHENTIC and vB.code is VerdictCode.AUTHENTIC
             and vA2.message_text() == short and vB.message_text() == custom)

    return r


def _decryption_failure_case(codec, bits, cover, kb, message):
    """
    Build a stego object whose signature and cover hash are both correct but
    whose message ciphertext cannot be authenticated: sign a payload whose
    msg_tag has been corrupted BEFORE signing. The signature covers the
    corrupted record, so it verifies; the GCM tag then fails.

    This is exactly the "correct signature, correct hash, message still cannot
    be trusted" case, and it proves the payload signature and the message tag
    are two independent guarantees rather than one.
    """
    import base64
    from .payload import build_payload, canonical_bytes
    from .signing import sign_payload
    from .hashing import stable_digest
    from .location import derive_start

    s = derive_secrets(PASSPHRASE)
    samples = codec.read_samples(cover)
    n_lsb = 2
    digest = stable_digest(samples, n_lsb)
    p = build_payload(digest, MEDIA_ID, "image", n_lsb, message, s)

    tag = bytearray(base64.b64decode(p.msg_tag))
    tag[0] ^= 0xFF                                   # break authenticity only
    p.msg_tag = base64.b64encode(bytes(tag)).decode("ascii")

    canon = canonical_bytes(p)
    sig = sign_payload(canon, kb.private_key, "ed25519")
    stream = bits.pack(canon, sig, n_lsb, config.ALGO_IDS["ed25519"])
    capacity_bits = codec.capacity_bits(cover, n_lsb)
    start = derive_start(s, MEDIA_ID, capacity_bits, n_lsb, len(stream) * 8)
    stego = codec.write_samples(cover, bits.embed(samples, stream, n_lsb, start))
    return verify(stego, MEDIA_ID, n_lsb, PASSPHRASE, kb.public_key,
                  codec=codec, bits=bits)


# --- entry point ------------------------------------------------------------
def main(bits_factory=ReferenceBitstream, label: str = "ReferenceBitstream") -> int:
    print("=" * 72)
    print("a2_crypto selftest - API_VERSION {}, default signer {}".format(
        config.API_VERSION, config.DEFAULT_SIGN_ALGO))
    print("running against MemoryCodec + {} (no PNG, no WAV)".format(label))
    print("this is the plug-and-play acceptance check.")
    print("=" * 72)

    t0 = time.perf_counter()
    try:
        r = run(bits_factory=bits_factory)
    except Exception:
        traceback.print_exc()
        print("\nSELFTEST ABORTED - an unexpected exception escaped.")
        return 2
    elapsed = time.perf_counter() - t0

    print("=" * 72)
    passed = len(r.rows) - len(r.failed)
    print("{}/{} passed in {:.2f}s".format(passed, len(r.rows), elapsed))
    if r.failed:
        print("FAILED: " + ", ".join(str(n) for n, _, _, _ in r.failed))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
