# Steganalysis — Optional Challenge

Owner: [fill in your name]. Covers the spec's optional "Steganalysis" challenge
(section 8): *"using known algorithms or methodologies, analyse a stego object
and convincingly infer the cover object is tampered or shows signs of hidden
payload."*

This is deliberately the **outsider's view** of the system the rest of the
team built. Everywhere else in this repo, "verification" means checking a
file against the passphrase and keys we were given. This module has neither —
it only reads the stego file itself, the way a real attacker or a competition
marker with no key material would.

## What it does

`steganalysis/chi_square_attack.py` implements the classic **chi-square
Pairs-of-Values (PoV) attack** (Westfeld & Pfitzmann, *Attacks on
Steganographic Systems*, 1999), the standard first-resort statistical test
against LSB-replacement steganography.

Every byte in a cover falls into a "pair of values" with its neighbour —
`(0,1)`, `(2,3)`, ... `(254,255)`. LSB replacement embeds a bit by overwriting
the last bit of a byte, which (over many bytes) pushes the counts of each pair
towards each other — an untouched photo does *not* naturally have
`count(2k) == count(2k+1)`, but a heavily LSB-replaced one starts to. A
chi-square test compares the observed counts in each pair against what
"already equal" would look like:

* **p-value near 1** → this histogram already looks equalised between
  adjacent pairs — the fingerprint LSB replacement leaves behind.
* **p-value near 0** → looks like ordinary, untouched image/audio data.

## Three tests, and why all three are here

**Test 1 — whole-file.** The textbook version — run the statistic once over
the entire cover. This is what most steganalysis writeups demonstrate, and it
works well when a large fraction of the file has been LSB-replaced. Run
against our own real evidence, it correctly finds *nothing* at every LSB
depth — not because the attack is broken, but because `a2_crypto`'s keyed
start location (`a2_crypto/location.py`) only needs a few hundred to a couple
of thousand units for a short/custom message, against a cover of hundreds of
thousands of units. A payload that small barely moves the global histogram.
That is the honest, demonstrable difference between "hard to find" and
"undetectable" — exactly the kind of limitation rubric criterion 7 asks the
team to discuss rather than gloss over.

**Test 2 — naive sliding window.** First attempt at catching a payload the
whole-file test dilutes away: repeat the same statistic over many small
overlapping windows instead of the whole file. Run against our *own real
cover image*, this test flagged roughly 98% of windows as "suspicious" —
**at every single LSB depth, including on evidence with no payload where
tested**. That is a real finding, not a bug we hid: real photographic
texture (a patch of fur, sky, shadow) has a narrow local tone range, which
starves a small window of distinct occupied byte-value pairs and destabilises
the chi-square statistic regardless of embedding. The script deliberately
keeps this test and runs it against the clean cover *and* the stego file side
by side, specifically so that false-positive rate stays visible in the report
rather than hidden.

**Test 3 — differential sliding window, multi-scale, absolute shift (the one
that actually works).** For each window, compare the stego file's local
p-value against the *clean cover's* p-value at the exact same position, and
flag a large shift — in either direction, see below. This cancels out the
texture instability from test 2, because both sides see the same local tone
range and differ only from genuine LSB change. Verified against synthetic
data before use here — including data deliberately built to reproduce the
same narrow-tone-range failure mode test 2 hit on the real cover — it locates
a small, localised embedded region precisely with zero false positives, in
cases where there is enough local variety for the statistic to be meaningful
(see limitation below).

This test went through two real, demonstrated design iterations, both driven
by our own results, not a synthetic guess:

1. *Window size.* The first version used one fixed 4000-byte window and came
   back silent at every LSB depth on our real evidence. A separate
   ground-truth byte-diff check (kept in the report, no statistics involved)
   proved that was wrong: real, non-trivial embedded regions exist at every
   depth (600–2400 bytes, depending on `n_lsb`), just much smaller than the
   4000-byte window — so a single window was mostly *unchanged* surrounding
   cover diluting the statistic. Fix: try several window sizes
   (4000/1000/400 bytes) and report the strongest result across all of them.
2. *Direction of the shift.* Even with multi-scale, the scan still found
   nothing. So we added an **oracle check** — running the differential test
   on the *exact* byte range the ground-truth diff already proved was
   changed, no window search involved, the best case this method could ever
   produce. At `n_lsb=8` (full-byte replacement, the strongest case) this
   revealed a real, large signal — cover p=1.0000 → stego p=0.0916, a delta
   of **-0.9084** — that the test had been missing entirely, because it only
   looked for the textbook-predicted *increase* in p. On a small sample of
   real photographic texture, a clean window can already look artificially
   "equalised" by coincidence (the same small-sample effect documented for
   test 2); embedding then pushes the statistic *away* from that
   coincidence, not further into it. Fix: every differential comparison
   (test 3, multi-scale, and the oracle check) now flags on the size of the
   shift regardless of sign, `abs(stego_p - cover_p)`.

## Honest limitations (say this in the demo)

* The whole-file test alone is **not sufficient evidence of security** — a
  clean result there does not mean nothing is hidden, only that nothing is
  hidden across a *large enough fraction* of the file to move the global
  statistic. This directly matches what `a2_crypto/location.py` already
  documents: keyed placement "hides *where* the payload is, not *that* one
  exists" — statistical steganalysis is a genuinely different threat model
  than guessing the offset.
* The naive sliding-window test (test 2) is **not reliable on real
  photographic content** at this window size — its own false-positive rate,
  measured against our own untouched cover, is high enough that it is kept in
  the report only as a transparency check, not as a detection claim.
* The differential test (test 3) fixes that, but trades it for a different,
  narrower honest limitation: it needs a clean reference cover to diff
  against, which a real-world attacker analysing an unknown file in isolation
  usually does not have. It is the right tool for "we want to security-test
  our own system" — this script's actual job — not proof that an outside
  analyst with no reference could do the same. It also declines to flag a
  window when either side has too few distinct byte-value pairs to trust the
  statistic (`MIN_DOF`), which means it can go silent in genuinely
  low-diversity regions rather than risk a false claim — a deliberate
  precision-over-recall choice, not a coverage guarantee.
* Trying multiple window sizes (multi-scale) narrows the dilution problem but
  does not remove it — a payload smaller than the smallest window tried
  (400 bytes here), or one that straddles a window boundary so no single
  window sees most of it, can still go undetected. This is a search over a
  fixed, small set of scales, not an adaptive one.
* All three tests operate on the *whole byte value*, applied blind — they do
  not know our own `n_lsb` selection, and do not need to. That is deliberate:
  a real attacker doing steganalysis does not get told the bit depth either.

## How to run it

```bash
python -m steganalysis.chi_square_attack
```

Run from the repo root. Reads the LSB-depth sweep already generated by
`python tests/test_image_codec.py` (`tests/test_evidence/image/lsb_sweep/`)
and the committed audio stego sample under `tests/test_evidence/audio/`.
Writes a plain-text report to `tests/test_evidence/steganalysis/report.txt`,
and (only if `matplotlib` happens to be installed — entirely optional, same
"skip if missing" pattern the GUI already uses for `sounddevice`) a bar chart
of the differential detection delta vs. LSB depth to
`tests/test_evidence/steganalysis/differential_delta_vs_lsb_depth.png`.

No extra dependency is required beyond what's already in the project
(`pillow`, `numpy`, stdlib `wave`/`math`); the chi-square p-value is computed
with a self-contained regularised-incomplete-gamma implementation rather than
pulling in `scipy`.

## Package layout

```
steganalysis/
├── __init__.py
└── chi_square_attack.py    ← the attack, standalone, imports nothing else
                                from this project

docs/
└── STEGANALYSIS_README.md  ← this file
```
