# A2 → team handoff

What the other five need from the crypto & verdict layer, plus two findings
from wiring A2 against the existing codecs.

---

## 1. What you import

```python
from a2_crypto import protect, verify, generate_keypair, load_public, load_private, API_VERSION
```

That is the whole surface for normal use. `API_VERSION` is `"1.0"`; call
`a2_crypto.check_api_version("1.0")` at startup and it warns (rather than
crashes) on a mismatch.

### Calling it

```python
from a2_crypto import protect, verify, ReferenceBitstream
from a2_integration import ImageCodecAdapter        # or AudioCodecAdapter

codec, bits = ImageCodecAdapter(), ReferenceBitstream()
cover = codec.load("cover.png")

res = protect(cover, message, media_id="IMG-0007", n_lsb=2,
              passphrase=pw, priv=priv, codec=codec, bits=bits,
              media_type="image", trace=trace)
codec.save(res.stego_view, "stego.png")

v = verify(codec.load("stego.png"), "IMG-0007", 2, pw, pub,
           codec=codec, bits=bits, trace=trace)
print(v.code, v.reason, v.message_text())
```

`verify()` never raises — a failure is a verdict, and you always get a
`Verdict` back.

### Three things must match between protect and verify

The **passphrase**, the **media ID** and the **LSB count**. Any mismatch moves
the derived offset and you get `Wrong Start Location`. The public key must
also match the signing private key, or you get `Signature Invalid`.

---

## 2. For person 5 (GUI)

- `capacity_report(codec, view, n_lsb, message, algo, encrypt)` returns the
  dict for the capacity bar. Compare against **`usable_bits`**, not
  `capacity_bits` — the keyed placement window reserves a tail, so
  `usable_bits` is the honest limit. `fits` is already computed for you.
- `Verdict.colour` gives a hex colour for the banner, `Verdict.meaning` a
  one-paragraph explanation for a tooltip, `Verdict.message_text()` the
  decrypted message.
- `VerdictCode` is a `str` Enum, so `str(v.code)` is `"Authentic"` etc.
- `a2.SIGNERS` lists the selectable signature schemes for a dropdown.
- Each scheme needs its own keypair. Switching the dropdown must reload keys —
  see `_on_algo_change()` in `a2_debug_gui.py` for the pattern.
- **Warn the user at `n_lsb = 8`**: `tamper_detection_strength(8)` reports that
  content tampering cannot be detected at that depth (the mask is `0x00`).
- `a2_debug_gui.py` is a working reference for all of the above. Lift from it
  freely; it is a throwaway bench, not a thing to preserve.

## 3. For person 1 (bitstream engine)

`a2_crypto/mocks.py::ReferenceBitstream` is what the pipeline currently uses.
To swap in yours, pass your object as `bits=`. No A2 code changes.

The `Bitstream` port needs three methods beyond the original plan, because the
pipeline must inspect a header without knowing its layout:

```python
def has_magic(self, header: bytes) -> bool: ...
def declared_total_bits(self, header: bytes) -> int: ...   # header+payload+sig, in bits
def header_info(self, header: bytes) -> dict: ...          # optional but used in the trace
```

Also: `pack()` takes an `algo_id` argument (`pack(payload, sig, n_lsb, algo_id=0)`)
so the decoder knows which verifier to use before parsing the payload. Ids are
in `config.ALGO_IDS`.

Conventions that must hold or nothing interoperates:

- **One unit = one cover byte.** A start offset is a unit index, not a bit index.
- **Bit order:** bytes expand MSB-first; the bit string is consumed in groups
  of `n_lsb`, MSB-first, one group per unit; the trailing group is zero-padded.
  This matches what `image_codec.py` and `audio_codec.py` already do.
- `extract(samples, n_lsb, start, max_bits)` returns whole bytes, truncating to
  `max_bits`, and must not raise when the magic is absent — that is a verdict,
  not an error.

## 4. For persons 3 and 4 (codecs)

Your modules are already wired in through `a2_integration.py` —
`ImageCodecAdapter` and `AudioCodecAdapter`. `python a2_integration.py` runs
the full pipeline over `tests/samples/` and currently reports `Authentic`,
`Tampered` and `Wrong Start Location` correctly for both media.

The adapters exist so nothing in your files had to change. If you prefer to
implement the `Codec` port directly (`load`, `save`, `capacity_bits`,
`read_samples`, `write_samples`), the adapters become unnecessary — see
`a2_crypto/ports.py`.

One rule: **`write_samples` must return a new view, never mutate the one passed
in.** The before/after comparison depends on the original surviving.

## 5. For person 6 (test & evidence)

Consume `trace.json` rather than screenshotting the GUI. Every `protect()` and
`verify()` call takes `trace=Trace("name")`, and `trace.save(path)` writes:

```jsonc
{
  "name": "verify",
  "total_ms": 12.4,
  "steps": [
    {"stage": "derive_start", "label": "...", "detail": {...},
     "ok": true, "ms": 0.31, "blob_hex": "...", "blob_len": 64}
  ]
}
```

Stages on the protect path: `capacity`, `hash`, `derive_secrets`, `payload`,
`canonical`, `sign`, `derive_start`, `pack`, `embed`, `verify_invariant`.
On the verify path: `capacity`, `derive_secrets`, `derive_start`,
`magic_check`, `header`, `extract_body`, `verify_sig`, `unpack`,
`compare_hash`, `decrypt`, `verdict`.

`Verdict.to_dict()` gives the whole result — verdict, reason, meaning,
details, payload and trace — as one JSON-serialisable object.

Selftest cases 6–14 in `a2_crypto/selftest.py` are already exactly the attack
simulations you need (content-bit flip, payload-bit flip, wrong key, wrong
passphrase, wrong LSB, clean cover, oversized payload, corrupt header, GCM
failure). They run against the mock codec; point them at real files and you
have most of the evidence pack.

---

## 6. Two findings from wiring this up

### a. The audio codec writes into the high byte of 16-bit samples — audible

`tests/samples/audio/sample_cover.wav` is 16-bit stereo PCM. `audio_codec.py`
treats every raw byte as an embeddable unit, so roughly half the embedded bits
land on the **high** byte of a 16-bit sample. Measured on the current
integration run at `n_lsb = 2`:

```
max sample delta  : 771       (a low-byte 2-LSB change would be <= 3)
samples changed   : 1,101 of 1,001,546
deltas > 3        : 836       i.e. 76% of changed samples took a high-byte hit
```

A delta of ~771 on a 16-bit sample is an audible click, and the demo requires
a playback comparison (criterion 3). Person 4's call, but the fix is small:
restrict embeddable units to the low byte of each sample — for `sampwidth=2`,
use byte indices `0, 2, 4, …`. That halves capacity and makes the change
genuinely inaudible.

This does not affect A2. The stable digest, the derived offsets and every
verdict work the same either way; only audio quality changes.

### b. `payload_temp.py` can be retired

`image_codec.py` and `audio_codec.py` currently import `payload_temp`, whose
`fake_sign`/`fake_verify` are HMAC — symmetric, so the same key signs and
verifies. That is not a digital signature and would not satisfy FR4.

`a2_crypto` replaces all of it: `hash_bytes` → `stable_digest`,
`build_protectable_blob` → `protect()`, `open_protected_blob` → `verify()`,
`Verdict` → `a2_crypto.VerdictCode` (same six strings, so display code does
not change). The `protect_image`/`verify_image` and `protect_audio`/
`verify_audio` wrappers at the bottom of each codec are superseded by
`a2_integration.py`; the read/write/embed/extract/compare functions above them
are still used and unchanged.

Suggested order: land person 1's bitstream, switch the codecs' wrappers over
to `a2_integration`, then delete `payload_temp.py` in one commit.

---

## 7. What is deliberately not in A2

No media file I/O, no bit packing, no GUI. Those are the Codec port, the
Bitstream port and person 5 respectively. If a change to A2 seems to need one
of them, it belongs on the other side of a port.
