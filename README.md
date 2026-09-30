# INF2005 ACW1 – Steganographic Image and Audio Integrity Verification

A desktop application that hides a digitally signed verification payload inside
PNG images and WAV audio using LSB replacement, then extracts it and proves
whether the file is authentic, tampered with, or signed by someone else.

- **Steganography:** LSB replacement, 1–8 selectable bits per byte
- **Integrity:** SHA-256 hash of the cover content, signed into the payload
- **Authenticity:** Ed25519 (default) or RSA-2048 PSS digital signatures
- **Confidentiality:** optional AES-256-GCM encryption of the hidden message
- **Keyed start location:** the payload's position is derived from a shared
  passphrase (HKDF + HMAC-SHA256) and is never stored in the file

---

## Quick start

Requires **Python 3.10+ with Tkinter**.

```bash
pip install -r requirements.txt
python gui_app.py
```

- Install `sounddevice` before demoing. The app still runs without it, but the
  audio Play/Stop buttons disable themselves, and playing the audio cover and
  stego objects is part of the required scope.
- macOS with Homebrew Python: if you get `No module named '_tkinter'`, run
  `brew install python-tk`, or use the python.org installer, which includes Tkinter.

Sample covers for a quick demo: `tests/samples/image/chelsea_cat.png` and
`tests/samples/audio/sample_cover.wav`.

---

## Using the GUI

| Tab | What it does |
|---|---|
| **Protect** | Load a PNG/WAV cover, choose a message (short / large / custom / oversized / free text), LSB depth, media ID, passphrase and signature algorithm, then embed. A live capacity bar blocks payloads that don't fit. The before/after comparison shows an amplified image diff or audio waveforms with playback. |
| **Verify** | Load a stego file (or take the last Protect result), enter the same media ID, passphrase, LSB count and public key, and get a colour-coded verdict with the recovered message and payload record. |
| **Image & audio test cases** | Runs the required test cases (positive, tampered, wrong passphrase, wrong key, capacity check, short/large/custom payloads, LSB 1–8 sweep) on a PNG or WAV cover and logs expected vs actual, matching `tests/test_image_codec.py` and `tests/test_audio_codec.py`. |
| **Attack simulation** | Applies one attack at a time to the last protected file, re-verifies it, and logs the expected verdict against the actual one. |

The **media ID, passphrase and LSB count must match** between Protect and Verify.
If any of them differs, the derived start location moves and the verdict is
*Wrong Start Location*.

A light/dark theme toggle is in the top-right corner.

### Sending a file from Party A to Party B (email)

1. **Party A:** in **Protect**, embed the message, then click **Save stego to file…**.
2. **Party A:** email the saved PNG/WAV as a normal attachment. Separately, tell
   Party B the media ID, passphrase, LSB count and signature algorithm.
3. **Party B:** download the attachment, then in **Verify** click
   **Load stego PNG/WAV…**, enter the details from Party A and click **Verify**.

Only the file travels by email. Send it as a file attachment from a desktop
mail client: messaging apps and phone "photo" sending often compress images,
which destroys the hidden bits.

### Verdicts

| Verdict | Meaning |
|---|---|
| Authentic | Signature valid and the cover content matches the signed hash |
| Tampered | Signature valid, but the cover content changed after signing |
| Signature Invalid | The payload was altered, or it was signed by a different key |
| Payload Missing | No payload found anywhere in the file |
| Wrong Start Location | A payload exists, but not where these parameters point |
| Cannot Verify | The payload header is corrupt, the key can't be loaded, or decryption failed |

If the same payload is verified twice in one session, the app flags it as a
**replay**. Each payload carries a signed nonce, and the app remembers the
nonces it has already accepted.

### Attacks in the Attack tab

| Attack | Expected verdict |
|---|---|
| Flip content bit | Tampered |
| Flip payload bit | Signature Invalid |
| Wrong passphrase | Wrong Start Location |
| Wrong public key | Signature Invalid |
| Use clean cover | Payload Missing |
| Wrong n_lsb | Wrong Start Location |
| Corrupt header | Cannot Verify |
| Substitute payload into another cover | Tampered |
| Replay (resend the same file) | Authentic + replay flagged |

---

## Running the tests

Run these from the repository root:

```bash
python -m a2_crypto.selftest                 # 18 crypto-layer cases  -> ALL CHECKS PASSED
python a2_integration.py                     # real PNG + WAV end to end -> Integration OK
python bitstream/test_bitstream_engine.py    # bitstream engine        -> All tests passed
python tests/test_image_codec.py             # image + LSB 1-8 sweep   -> All 8 depths Authentic
python tests/test_audio_codec.py             # audio + LSB 1-8 sweep   -> All 8 depths Authentic
python -m steganalysis.chi_square_attack     # steganalysis report     -> report.txt
```

The tests write evidence (stego files, diffs, traces, the steganalysis report) to
`tests/test_evidence/`. Rerunning them regenerates those files. To discard
the regenerated copies, run `git restore tests/test_evidence/`.

---

## Keys

| File | Purpose |
|---|---|
| `keys/demo_public.pem` | Ed25519 public key. Verifies every signature in the submitted evidence. Fingerprint `96e408b3103196f0` |
| `keys/demo_private.pem` | Ed25519 private key. Signs payloads during Protect |
| `keys/impostor_*.pem` | A second keypair used only to demonstrate the *Signature Invalid* case. Git-ignored and regenerated on demand |

**Why a private key is in the repository.** The assignment permits demo-only
private keys, and one is needed here: without it a marker cannot run Protect,
so they could not reproduce the workflow. This keypair was generated solely
for this assignment and is used nowhere else. In a real deployment the private
key would never leave the signing machine — only the public key is
distributed, because it can verify a signature but never create one.

### Reproducing signature verification

Verification needs the **public key only**. In the GUI: open **Verify**, load a
stego file, click **Use demo public key for this algo**, enter the media ID,
passphrase and LSB count, then **Verify**.

To check a submitted evidence file without the GUI:

```python
import a2_crypto as a2
from a2_integration import ImageCodecAdapter, A1BitstreamAdapter

codec, bits = ImageCodecAdapter(), A1BitstreamAdapter()
pub = a2.load_public("keys/demo_public.pem")

v = a2.verify(codec.load("tests/test_evidence/image/image_stego.png"),
              "IMG-TEST-001", 2, "team-P1-4-shared-passphrase", pub,
              codec=codec, bits=bits)
print(v.code, "|", v.message_text())
```

Expected output:

```
Authentic | Explain how steganography can be used to embed hidden verification data in image and audio cover objects.
```

The parameters come from `tests/test_image_codec.py`; the audio equivalent is
in `tests/test_audio_codec.py` with media ID `AUD-TEST-001`.

Selecting `rsa2048-pss` in the GUI generates a matching RSA demo keypair on
first use, so that path is reproducible too — but the signatures in the
submitted evidence are all Ed25519 and verify with `demo_public.pem`.

---

## Project structure

```
gui_app.py              entry point for the GUI
gui/                    production GUI: tabs, theme, icons, shared session state
a2_crypto/              hashing, signatures, encryption, keyed start location, verdicts
a2_integration.py       adapters that connect a2_crypto to the codecs and bitstream engine
bitstream/              header framing, bit packing and capacity maths
image/                  PNG codec
audio/                  WAV codec
steganalysis/           chi-square steganalysis attack (optional challenge)
tests/                  codec test suites, sample covers and generated evidence
keys/                   demo keypair (demo only, see Limitations)
docs/                   detailed module documentation
a2_debug_gui.py         developer test bench for the crypto layer (not the submitted GUI)
```

Generated at runtime, and git-ignored: `gui_out/`, `a2_out/`, `keys/impostor_*.pem`,
`keys/demo_*_rsa2048-pss.pem`.

---

## Optional challenges

| Challenge | Status | Where |
|---|---|---|
| Attack simulation module | Done | Attack tab (`gui/attack_tab.py`) |
| Advanced start-location security | Done | `a2_crypto/location.py`: HKDF + HMAC-SHA256 keyed start location |
| Steganalysis | Done | `steganalysis/chi_square_attack.py` |
| Video cover object | Not attempted | – |
| Robust embedding | Not attempted | – |

---

## Limitations

- **Demo keys and passphrase are public.** `keys/demo_*.pem` and the default
  passphrase are committed for the demo. Real use needs private keys and a
  passphrase shared out of band.
- **The keyed start location hides *where* the payload is, not *that* it exists.**
  Statistical steganalysis (see `steganalysis/`) can still detect LSB embedding.
- **At 8 LSBs, content tampering can't be detected.** Every bit of every byte
  carries payload, so nothing is left to hash. The GUI warns when you select 8.
- **What the integrity hash covers is wider than what the carrier writes to.**
  For WAV/PCM the payload only ever goes into the low byte of each sample
  (a flipped bit in a high byte is audible), but the hash covers *every* raw
  byte via the codec's `digest_samples()`. Hashing only the embeddable bytes
  would leave the loud half of the audio unprotected. An attacker could
  rewrite every high byte and still get an `Authentic` verdict. That case is
  now a regression test in `tests/test_audio_codec.py`.
- **Replay detection is per session.** Accepted nonces are kept in memory only,
  so closing the app forgets them.
- **Lossless formats only.** PNG and WAV survive exactly. Lossy compression
  such as JPEG or MP3 destroys the embedded bits.

---

## Ethics and Responsible Use

Steganography is a dual-use technology. While this tool is designed for legitimate security purposes, such as: protecting media integrity, verifying authenticity, and ensuring confidentiality, the same techniques can be misused. Malicious actors frequently use steganography to bypass Data Loss Prevention (DLP) systems, secretly exfiltrate sensitive data, or hide malware payloads within seemingly innocuous files. 

We recognize these ethical implications. This application was built strictly for educational purposes and authorized verification workflows as part of the INF2005 coursework. It is intended to demonstrate cryptographic and steganographic principles responsibly and should not be used in environments where undocumented hidden data channels violate organizational security policies.

---

## AI Use

Generative AI was used selectively by team members during development, mainly for:

- Debugging and reviewing individual modules (e.g. codec logic, integration
  wiring) against the project's own test suites
- Extending test/attack case coverage
- General code review, explanation, and documentation support while
  implementing assigned components

All AI-suggested code was read, tested, and verified by the responsible team
member before being merged, and nothing was used unreviewed. Design decisions
(module boundaries, the Codec/Bitstream port split, the keyed start-location
scheme, and the overall security workflow) were made by the team. AI was
used as a debugging and review aid, not as the source of the architecture.

---

## Further documentation

- [docs/A2_CRYPTO_README.md](docs/A2_CRYPTO_README.md): crypto and verdict layer
- [docs/A2_HANDOFF.md](docs/A2_HANDOFF.md): integration notes between modules
- [docs/BITSTREAM_README.md](docs/BITSTREAM_README.md): bitstream engine and header format
- [docs/STEGANALYSIS_README.md](docs/STEGANALYSIS_README.md): steganalysis method and results
