# Getting started, and what is blocked on a human

Two separate lists. The first is what you need to *run* this project. The second
is what nobody can code around — decisions, hardware and specimens that have to
come from outside the repository.

---

## 1. What is already installed on the development machine

Recorded so that nothing here gets installed twice, and so a second machine can
be brought to the same state.

| | Version | Where | On PATH? |
|---|---|---|---|
| uv | 0.12.10 | user install | yes |
| CPython | 3.12.14 | uv-managed | via uv |
| Project dependencies | see `uv.lock` | `.venv/` | via uv |
| Tesseract OCR | 5.4.0 | `C:\Program Files\Tesseract-OCR\` | **no** |

Tesseract not being on the path is handled: `extraction/ocr_adapter.py` looks in
the `SENTINELID_TESSERACT` environment variable, then the path, then the
locations its installer uses. Nothing needs fixing for it to work.

## 2. What you still need to install

### `make` — required

The gate is `make check`, and **make is not installed**, so that command cannot
run. Everything it does can be run by hand, but the four commands are easy to
run incompletely, which is exactly how a repository drifts.

```
winget install ezwinports.make
```

Open a new terminal afterwards, then:

```
make check
```

### OCR-B training data for Tesseract — needed for reliable strip reading

The installed Tesseract has two language packs, `eng` and `osd`. Neither is
trained on **OCR-B**, the typeface machine-readable strips are printed in.
Consequences are in [`roadmap.md`](roadmap.md) under phase 6: the first strip
line reads at 98% character agreement and the second does not read reliably.

The fix is `mrz.traineddata` (sometimes published as `ocrb.traineddata`), copied
into `C:\Program Files\Tesseract-OCR\tessdata\`. It needs downloading, which is
why it is not done here.

Until then the reader **refuses to vouch for a strip it cannot read cleanly**,
the case goes to a human, and the officer is told why. Nothing is guessed and
nothing silently fails.

## 3. Setting up a second machine from nothing

```
winget install --id Git.Git -e
winget install --id astral-sh.uv -e
winget install --id UB-Mannheim.TesseractOCR -e --silent
winget install ezwinports.make

git clone https://github.com/whypaulwhy/ps-188.git
cd ps-188
uv sync
make check
```

`uv sync` installs Python 3.12 itself if it is missing, so no separate Python
install is needed. Note the `--silent` on Tesseract: without it the installer
stops at an elevation prompt and reports `0x800704c7`.

## 4. Checking it works

`make check` should end with every gate passing and `core/` at 100% branch
coverage. If `pytest` reports skipped tests, read why — a skip here means a
capability is absent, not that a test is broken.

---

## 5. What is blocked on a human

These are in rough order of how much they unblock. None of them can be solved
by writing code.

### 5.1 An Aadhaar Secure QR specimen and the UIDAI certificate — highest value

**Blocks:** `detectors/rung0_crypto/aadhaar_secure_qr.py`, and with it one of
only **two** document types in [`scope.md`](scope.md) that can ever be
`CLEARED`. The other, DigiLocker, already works.

**Why it is not written:** the cryptography is ordinary RSA and already exists
in `verification.py`. What is missing is the container — the byte layout
separating signed data from signature. A wrong field boundary produces a
detector that verifies the wrong bytes and reports `PROOF_VALID` on documents it
never actually checked. That fails silently, in the worst direction, behind the
only rung that can clear a document.

**What is needed**, listed in full in that module's docstring:

1. A specimen Secure QR payload from a document known to be genuine, ideally
   several. Synthetic payloads built from our own reading of the format would
   prove only that the code agrees with itself.
2. The UIDAI public certificate in current use, and how a deployment obtains and
   pins it.
3. Confirmation of the container layout: big-integer to byte decoding, whether
   the payload is compressed and with what, the field delimiter, the length and
   position of the signature, and where the photograph begins and ends.
4. Confirmation of which byte range the signature actually covers. This is the
   detail most likely to be got wrong.

### 5.2 Chip reader hardware

**Blocks:** `epassport_sod.py`, and converts the three passport rows in
`scope.md` from Rung 1 to Rung 0 — turning "we checked the arithmetic" into "we
verified the issuer's signature" for Indian, Nepali and Bhutanese passports.

This is a procurement question. It is the single highest-value change available
to the project after the Aadhaar specimen.

### 5.3 Confirmation of document formats

`scope.md` lists these as unconfirmed, and the phase-1 fixtures for them are
**structurally plausible placeholders, not verified transcriptions**:

- the exact current Bhutanese CID format;
- the exact current Nepali citizenship certificate format, including how much it
  varies by district and issuing year;
- whether the Nepali national identity card's chip is readable with commodity
  hardware, and under what authority.

### 5.4 The document mix at the target crossings, by volume

Everything in `scope.md` assumes Nepali documents dominate. If the real traffic
is mostly Indian documents with readable Aadhaar QRs, the clearance path is far
wider than currently assumed and the priorities change.

### 5.5 Three deployment decisions the code refuses to make for you

- **Retention windows.** `RetentionPolicy` will not construct unless every
  artefact category has an explicit window. There are deliberately no defaults:
  invented day counts get read as policy. Somebody has to decide how long a face
  embedding, a document image, a case record and a ledger entry may be kept.
- **Where the hashing key lives.** Document numbers are stored as HMAC-SHA256
  digests under a per-deployment key that must be held **outside the database**.
  If the checkpoint box cannot hold a secret separately from its own data, the
  protection degrades to roughly nothing; see [ADR 0005](adr/0005-keyed-hashing-for-document-numbers.md).
  The key also needs backing up: losing it makes every stored digest
  unmatchable.
- **Whether the review volume is acceptable.** `scope.md` implies most crossings
  land in `MANUAL_REVIEW`. That is correct behaviour, and it is also an
  operational question: what is an officer's time budget per traveller? This is
  not a technical question and it decides whether the system is deployable.

---

## 6. What is incomplete in the code

Full detail in [`roadmap.md`](roadmap.md).

| | |
|---|---|
| Phase 4 leftover | Aadhaar Secure QR detector — see 5.1 |
| Phase 5 leftovers | `field_crossmatch.py` (now unblocked, the printed page is readable), `template_geometry.py` |
| Phase 6 remainder | `eval/` — **so no performance figure exists anywhere yet**; the four Rung 2 tamper detectors |
| Phase 7 | Face matching and presentation attack detection |
| Phase 8 | Rung 3 contextual advisories |
| Phase 9 | API, database, transparency ledger, officer console |

TruFor, one of the phase-6 tamper detectors, has no model weights available and
will ship reporting `INCONCLUSIVE` — which is what CLAUDE.md's testing rule asks
of an unavailable model, not a workaround.
