# A2 — Crypto & Verdict Layer

Owner: person 2 (Pair A — Core). Covers **FR3** (payload generation), **FR4**
(digital signature), **FR7** (variable start location and its protection),
**FR9** (hash verification) and **FR10** (verdict generation).

This layer does the hashing, builds and signs the verification payload,
derives the keyed start location, and returns the verdict. It reads no PNG and
no WAV — media access arrives through the `Codec` port and bit framing through
the `Bitstream` port, which is why one code path serves both cover objects.

---

## Setup

```bash
pip install cryptography          # the only dependency of a2_crypto
pip install pillow numpy          # only needed for the real PNG/WAV codecs
```

Python 3.10+ (uses `X | Y` type syntax). Tkinter ships with Python on Windows.

## Commands

| Command | What it does | Expected output |
|---|---|---|
| `python -m a2_crypto.selftest` | 18 internal test cases against the mock codec | `18/18 passed` / `ALL CHECKS PASSED` |
| `python a2_debug_gui.py` | The A2 debug bench (Protect / Verify / Trace tabs) | A window; no console output |
| `python a2_integration.py` | Same pipeline over the real PNG **and** WAV | Two `Authentic` round trips, two `Tampered`, two `Wrong Start Location`, then `PURITY PASS` |

`a2_integration.py` writes stego files and trace JSON into `a2_out/`, and
creates `keys/demo_private.pem` + `keys/demo_public.pem` on first run.

---

## The six verdicts

The decision tree is evaluated strictly in this order and stops at the first
match.

| # | Verdict | Trigger |
|---|---|---|
| 1 | `Cannot Verify` | Missing/invalid key, unreadable input, capacity error, unexpected exception |
| 2 | `Wrong Start Location` | No magic at the derived offset, but a payload is found at another offset or under another LSB depth |
| 3 | `Payload Missing` | No magic at the derived offset and none anywhere in the cover |
| 4 | `Cannot Verify` | Header parses but declares lengths that exceed the remaining capacity |
| 5 | `Signature Invalid` | Payload recovered, public-key verification fails |
| 6 | `Tampered` | Signature valid, but the recomputed cover hash differs from the signed one |
| 7 | `Cannot Verify` | Signature and hash both fine, AES-GCM tag fails (wrong decryption passphrase) |
| 8 | `Authentic` | Everything passes; the decrypted message is returned |

**`Signature Invalid` and `Tampered` are deliberately different.**
`Signature Invalid` means someone edited the payload record or signed it with
a key we do not trust. `Tampered` means the payload record is genuine and
correctly signed, but the media itself changed after signing. Different
attacks, different responses.

---

## Three things must match between protect and verify

If any one of these differs, the derived offset moves and verification fails
with `Wrong Start Location`:

1. the **passphrase**,
2. the **media ID**,
3. the **LSB count** (`n_lsb`).

The public key must also correspond to the private key used to sign, or the
result is `Signature Invalid`.

---

## Design decisions worth knowing

### The stable-representation hash

You cannot hash a cover file and hide that hash inside the same file —
embedding changes the bytes, so the digest would never match. This layer
hashes the cover with the target LSB planes masked to zero:

```
stable_digest(samples, n_lsb) = SHA-256(samples & ~((1 << n_lsb) - 1))
```

Embedding only ever writes the bottom `n_lsb` bits, so the masked
representation is bit-identical before and after. Any edit to real picture or
audio content moves the upper bits and fails the comparison → `Tampered`.

**Limitation:** the check weakens as `n_lsb` rises, and at `n_lsb = 8` the
mask is `0x00` — every byte hashes to zero and content tampering is not
detectable at all. That is correct rather than broken: at 8 LSBs the payload
has overwritten the entire cover. `tamper_detection_strength(n_lsb)` reports
this and the pipeline records a trace warning.

### Keyed start location

The offset is never stored in the file. Both sides derive it:

```
K_loc = HKDF(passphrase, salt="INF2005-ACW1", info="start-location")
start = HMAC-SHA256(K_loc, media_id || capacity_bits || n_lsb) mod window
```

Every input is available to the verifier *before* extraction, so there is no
chicken-and-egg problem and no stored hint to read.

**Why not just store the offset in the first 32 bits?** Then it is public —
anyone who suspects the file carries a payload reads unit 0 and jumps
straight to it. A stored offset relocates the payload; it does not protect it.

**The placement window.** A first cut sized the modulus with the payload
length: `HMAC(...) mod (capacity - payload_len)`. That does not work, because
the verifier does not know the payload length until it has read the header,
and cannot read the header until it knows the offset. The modulus is therefore
built from capacity alone, with a reserved tail so any legal payload still
fits from wherever the offset lands:

```
reserve = min(capacity_units // 2, ceil(MAX_STREAM_BITS / n_lsb))
window  = capacity_units - reserve
```

The cost is a ceiling on payload size, which `capacity_report()` reports as
`usable_bits` — the honest number the GUI capacity bar compares against.

**Limitation:** this hides *where* the payload is, not *that* one exists.
Statistical steganalysis of the LSB planes (chi-square, sample-pair, RS
analysis) can still flag that something is embedded. Keyed placement raises
the cost of extraction; it does not give undetectability.

### Two separate guarantees on the message

The message is encrypted with **AES-256-GCM** under a key derived from the
same passphrase but a different HKDF label. The GCM tag proves the *message*
was not modified; the Ed25519 signature proves the *whole record* was issued
by the key holder. Two distinct claims, and the verdict tree reports them
separately (a GCM failure is `Cannot Verify`, not `Tampered`).

### Canonical serialization

A signature over JSON breaks if key order or whitespace differs between
signing and verifying. Every sign and verify routes through one
`canonical_bytes()` function pinning `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=True`. This is the most common source
of "signature invalid but nothing is wrong" bugs, so it is centralised and
never inlined.

### Ed25519 by default

64-byte signature versus RSA-2048's 256 bytes — at 1 LSB in a small WAV a
256-byte signature costs 2,048 cover bytes on its own. No padding mode or
exponent to get wrong. RSA-2048-PSS stays registered in `SIGNERS` and is
selectable from config or the GUI dropdown; selftest case 17 runs the full
pipeline under it.

---

## Package layout

```
a2_crypto/
├── __init__.py     public API surface + API_VERSION
├── config.py       every tunable; algorithm registry ids
├── ports.py        Codec + Bitstream Protocol definitions
├── errors.py       CapacityError, HeaderError, DecryptionError, KeyError_
├── keys.py         keygen, PEM save/load, HKDF secret derivation
├── hashing.py      stable_digest, masking, tamper_detection_strength
├── payload.py      Payload dataclass, canonical_bytes, AES-GCM
├── signing.py      signer registry: ed25519, rsa2048-pss
├── location.py     derive_start, placement window, bounded scan
├── verdict.py      VerdictCode, Verdict, meanings and colours
├── pipeline.py     protect() and verify() — owns the decision tree
├── trace.py        Trace, TraceStep, hexdump
├── mocks.py        MemoryCodec, ReferenceBitstream
├── selftest.py     the 18 cases
└── testdata/       short / large / custom test payloads

a2_integration.py   adapters binding a2_crypto to the real PNG/WAV codecs
a2_debug_gui.py     standalone Tkinter bench
keys/               demo keypair (demo-only, safe to submit per spec)
```

`a2_crypto/` imports nothing from any teammate package, PIL or numpy —
`a2_integration.selftest_purity()` proves this by reading the source, and it
runs at the end of `python a2_integration.py`.

---

## Keys

`keys/demo_private.pem` and `keys/demo_public.pem` are **generated for this
assignment demo only** and are safe to submit per the spec. In a real
deployment the private key would never leave the signer.

Regenerate at any time:

```python
import a2_crypto as a2
a2.save_keypair(a2.generate_keypair("ed25519"),
                "keys/demo_private.pem", "keys/demo_public.pem")
```

`keys/impostor_*.pem` exists only to demonstrate the wrong-key negative case.
