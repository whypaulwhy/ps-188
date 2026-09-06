# Threat model

Scope is fixed in [`scope.md`](scope.md). This document works through what an
attacker realistically does to each accepted document type, which rung answers
it, and what residual risk is left over.

Nothing here is a measurement. No detection rate is claimed for anything,
because nothing has been evaluated.

## The setting

An open crossing on the India–Nepal or India–Bhutan border. No advance
manifest. Documents arrive unannounced and diverse, many of them worn,
laminated, photocopied or photographed. The officer has minutes and no
laboratory.

Two consequences run through the whole design:

- **The system cannot assume it has seen this document type before.** Anything
  it does not recognise goes to a human. Refusing to judge is a valid answer.
- **The officer is the decision maker.** The system's job is to present
  defensible evidence, not to be trusted blindly.

## Assets

| Asset | Why it matters |
|---|---|
| The screening decision | A wrong `CLEARED` lets someone through on a forged identity. A wrong `REJECTED` strands a legitimate traveller, often a daily commuter. |
| Aadhaar numbers | Aadhaar Act 2016 s.29 and s.37. Storing one is a criminal matter, not a design preference. |
| Face embeddings | Partially invertible by model inversion. Personal data, not anonymous features. |
| The audit trail | If it can be edited after the fact, no decision this system made is defensible. |
| Issuer trust anchors | An attacker who can add a key can mint documents that clear at Rung 0. This is the only path to a forged clearance. |
| The deployment hashing key | Held outside the database. With it and the database, every stored document number is recoverable by enumeration. ADR 0005. |

## Adversaries

1. **The opportunistic traveller.** An expired document, or a relative's. No
   technical sophistication. This is the overwhelming majority.
2. **The document forger.** Alters a genuine document — portrait, date, name —
   or fabricates one from a cloned template. Economically motivated, sells to
   many people, so the same template defect recurs.
3. **The presentation attacker.** A printed photo, a screen replay or a mask
   against the live capture.
4. **The insider.** Has access to the deployment and wants one specific case to
   clear, or a past case to look different.

## Per document type

### Aadhaar with a readable Secure QR

**Features:** UIDAI signature over a payload containing the demographic fields
and the portrait. **Machine-checkable:** the signature, completely.

The signature covers the photograph, so portrait substitution and field editing
are both caught: any change invalidates it. This is the only document in scope
where a forgery is *disproven* rather than merely suspected.

**Residual risk.** The QR is often unreadable — worn cards, photocopies, phone
photographs at an angle. The document then falls back to Rung 1, where Aadhaar
has almost nothing to check, and lands in `MANUAL_REVIEW`. An attacker who
deliberately degrades the QR converts a document that would have been disproven
into one that merely goes to a human. **The system must never treat an
unreadable QR as an absent QR**: `NO_PROOF_PRESENT` on a document type known to
carry a signature is itself worth surfacing to the officer.

### DigiLocker-issued documents

**Features:** XML signature or a PKCS#7-signed PDF. **Machine-checkable:** the
signature, completely.

**Residual risk.** Trust anchor management. A forged document verifies if a
forged issuer key is in the trust store, which makes the trust store the
highest-value target in the system.

### ICAO passports — Indian, Nepali, Bhutanese

**Features:** the machine-readable strip with its own arithmetic; printed
security features; a chip on newer books. **Machine-checkable without a
reader:** the strip arithmetic only.

The strip's built-in verification numbers catch a coded field altered in place.
They catch nothing about a wholly fabricated book, because a forger computes
them correctly — the arithmetic is public. Without a chip reader, a competently
forged passport reaches at best `MANUAL_REVIEW`, never `REJECTED`.

**Residual risk.** Everything the chip would have proven. Procuring a reader is
the single highest-value change available to this project.

### Indian driving licence and EPIC voter card

**Features:** issuer layout, field formats, a QR on some driving licences whose
content and signing vary by state. **Machine-checkable:** layout geometry and
internal field consistency.

**Residual risk.** Large. A good template clone passes every check available.
Rung 2 may notice print or splice artefacts and escalate; it cannot reject.

### Nepali citizenship certificate

**Features:** paper, issuing-office stamp, handwritten and typed entries,
layout that varies by district and by issuing year. **Machine-checkable:
nothing.**

This is the most commonly presented document at these crossings and the system
can verify none of it. Every check returns `NOT_APPLICABLE` or
`NO_PROOF_PRESENT`, and the case goes to a human with an explicit statement
that nothing was confirmed. Golden cases `npl-citizenship-printed-only` pins
exactly that outcome, because the tempting implementation bug is to render "no
problems found" as a pass.

**Residual risk.** Total, with respect to document authenticity. What the
system can still contribute is Rung 3 context — has this identity been seen
before, at this crossing or another — and, from phase 7, whether the bearer
matches the portrait.

### Nepali national identity card and Bhutanese citizenship identity card

**Features:** the Nepali card carries a chip; the Bhutanese card does not.
**Machine-checkable without a reader:** layout only, and only once templates
are in the corpus.

**Residual risk.** As above. `btn-cid-printed-only` pins the honest answer.

## Attack, answering rung, and fixture

| Attack | Rung | Fixture |
|---|---|---|
| Fabricated Aadhaar QR payload | 0 | none — blocked on a real Secure QR specimen |
| Genuine Aadhaar, portrait substituted, QR intact | 0 | none — blocked on a real Secure QR specimen |
| Genuine Aadhaar, QR deliberately damaged | 0 → `NO_PROOF_PRESENT` | none — blocked on a real Secure QR specimen |
| Forged DigiLocker XML signature | 0 | `digilocker-xml-tampered` ✅ |
| DigiLocker document from an unknown authority | 0 → `NO_PROOF_PRESENT` | `digilocker-xml-unknown-issuer` ✅ |
| Signed PDF altered after signing | 0 | `pdf-signature-tampered` ✅ |
| Signed PDF from an unknown authority | 0 → `NO_PROOF_PRESENT` | `pdf-signature-unknown-issuer` ✅ |
| Passport coded field altered in place | 1 | `td3-ind-dob-altered` ✅ |
| Genuine passport, poor scan | 1 → `NOT_APPLICABLE` | `td3-ind-strip-unreadable` ✅ |
| Genuine passport, correct strip | 1 → `PASS` | `td3-icao-specimen`, `td3-ind-specimen` ✅ |
| Wholly fabricated passport with correct arithmetic | 1 cannot answer; 2 escalates | none yet, phase 6 |
| Document with nothing to verify | 1 → `NOT_APPLICABLE` | `npl-citizenship-printed-only`, `btn-cid-printed-only` ✅ |
| Expired but genuine and correctly signed | 1 | none yet, phase 5 |
| Cloned template with invented data | 1 and 2 | none yet, phase 6 |
| Print-and-rephotograph of a real document | 2 | none yet, phase 6 |
| Screen replay against the live capture | 2 | none yet, phase 7 |
| Genuine document, wrong bearer | 2 | none yet, phase 7 |
| Unrecognised document type | — | none; no detector applies, `MANUAL_REVIEW` by default |

Nine attacks have committed fixtures. The rest are named here so the gap is
visible rather than discovered later. The three Aadhaar rows are the most
consequential gap in the table: Aadhaar is one of only two document types that
can reach `CLEARED`, and none of its attacks can be tested yet.

## Attacks on the system itself

| Attack | Mitigation |
|---|---|
| Adding a forged issuer key to the trust store | Trust anchors are reviewed configuration, pinned by digest. Phase 4. This is the highest-value target in the system. |
| Taking the database to recover document numbers | Numbers are stored as HMAC-SHA256 digests under a per-deployment key held outside the database, so the database alone is not enough. ADR 0005. |
| Taking the deployment key **and** the database | Recovers every number by enumeration: an Aadhaar number has only about 9x10^11 possible values. No construction prevents this, which is why the key is listed as an asset above. |
| A raw number reaching a log, a traceback or a payload | `RawIdentifier` masks itself in `str`, `repr`, f-strings and logs, and has no Pydantic schema, so it cannot be a contract field. Its `reveal()` call sites are enforced by test. |
| Keeping biometrics after the case that justified them | `RetentionPolicy` refuses to construct if the face embedding window exceeds the case record window, and refuses to construct at all if any category is unanswered. |
| Editing a past decision in the database | Append-only transparency log with signed checkpoints published off-box. Phase 9, ADR 0003. |
| A detector reaching into the database to change what it reports | Architecture boundary, enforced by import-linter in CI. Rule 5. |
| Tuning a Rung 2 model to clear a specific document | Structurally impossible. Rung 2 has no vocabulary for a clearing result, and `Verdict` refuses a clearance without Rung 0 or Rung 1 support. |
| Editing a golden fixture to make a detector look correct | Each fixture's digest is committed in its `case.toml` and checked on every run. |
| Quietly softening officer-facing wording | `reasons` text is pinned in the goldens and compared exactly. |
| Overclaiming in a demo | Rule 2. Numbers come from `eval/run_eval.py` on a named dataset or they do not exist. |
| A model failing silently and looking like a pass | `INCONCLUSIVE` is a distinct result and lands in `Verdict.not_checked`. |

## The cost of a false rejection

A false `CLEARED` is the failure everyone designs against. A false `REJECTED`
gets less attention and, on an open border, is the more frequent harm.

The people crossing here are largely local: daily commuters, traders, workers,
students, patients travelling for treatment, families with relatives on both
sides. A wrongly rejected document is not an inconvenience at an airport once a
year. It is somebody turned back on their commute, and if the cause is a
permanent property of their document — a worn strip, an unusual district
layout, a faded card — it happens to them **every day**.

Three rules follow, and all three are already enforced:

1. **Rung 2 can never cause a rejection.** A model's suspicion escalates to a
   human and stops there. Enforced in `core/trust/ladder.py` and tested.
2. **A rejection must be explicable to the traveller.** `REJECTED` requires a
   Rung 0 or Rung 1 failure, both of which cite the published clause they
   applied. An officer can say what failed and why.
3. **A bad capture is not a failed check.** An unreadable strip returns
   `NOT_APPLICABLE`, never `FAIL`. This is pinned by
   `td3-ind-strip-unreadable`, because the natural implementation — treat a
   malformed strip as a standards violation — punishes travellers for the
   quality of the scanner.

The evaluation protocol reports both error rates separately and refuses to
average them. See [`evaluation-protocol.md`](evaluation-protocol.md).

## Open, and deliberately so

- The residual risk on Nepali and Bhutanese documents is total with respect to
  document authenticity. No amount of engineering inside this scope changes
  that. It is a procurement and policy question, raised in `scope.md`.
- Rung 3 context becomes disproportionately important precisely because Rung 0
  is unavailable for most traffic. That makes phase 8 more load-bearing than
  its position in the roadmap suggests, and it carries its own privacy risk:
  building a movement history of a border population is a serious thing to do
  and needs its own review before it is built.
