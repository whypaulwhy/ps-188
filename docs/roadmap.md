# Roadmap

Work happens in this order. CLAUDE.md forbids skipping ahead to AI features,
and the ordering is not arbitrary: every phase produces the thing the next
phase is tested against. Building a tamper detector before there is a way to
measure it produces a demo, not a system.

Each phase lists what must be true before it can be called done. A phase is not
finished because the code exists; it is finished when `make check` passes and
the exit criteria hold.

---

## Phase 0 — Skeleton and contracts ✅

The shape of the system, and the data every part of it exchanges.

- `core/contracts/`: `Evidence`, `Finding`, `Verdict`, `Provenance`, `Rung`,
  `Result`, `Decision`, `Severity`.
- `core/trust/ladder.py`: the resolution function, pure, fully tested.
- `detectors/base.py`: the `Detector` ABC and the registry.
- `make check` gate: ruff, mypy strict on `core/`, import-linter, pytest with
  100% branch coverage of `core/`.

**Exit criteria.** No detectors exist. No API routes exist. No models exist.
The ladder cannot be made to clear a document without cryptographic proof, and
there is a test that says so.

---

## Phase 1 — Scope, threat model and golden fixtures ✅

Decide what is actually in scope before writing anything that looks at pixels.

- `docs/scope.md`: eleven accepted document types, the refused list, and the
  "what this system does not do" statement.
- `docs/threat-model.md`: per document type, the realistic attacks and which
  rung answers them; the attack-to-fixture map; the cost of a false rejection.
- Fixture corpus in `tests/golden/`: six detector cases and two standards
  vector files, all synthetic or published specimens, each with a licence note,
  a provenance line and a committed digest.
- The golden harness: fixture in, exact `Evidence` out, with officer-facing
  wording pinned and only `runtime_ms` and `model_version` excluded from
  comparison.

**Exit criterion met.** `docs/scope.md` answers "what does this system not do"
in ten numbered points.

**The finding that came out of it.** Scope was set to the real SSB mandate —
the India–Nepal and India–Bhutan borders. Only two of the eleven accepted
document types can ever reach `CLEARED`, and both are Indian. Nepali and
Bhutanese documents carry nothing a machine can verify, so `MANUAL_REVIEW` is
the correct outcome for most crossings. On these borders this system is triage
and evidence, not clearance. That reframes what phase 6 has to measure.

---

## Phase 2 — The standards library and the extraction contract ✅

The deterministic groundwork. No inference anywhere in this phase, and no
pixels.

- `core/standards/mrz/`: ICAO Doc 9303 TD3 parsing and 7-3-1 check digits,
  plus a renderer so parsing is round-trip tested.
- `core/standards/verhoeff.py`, `core/standards/date_rules.py`,
  `core/standards/errors.py`.
- `core/contracts/subject.py`: what a detector is handed.

**Exit criterion met.** Property-based tests via hypothesis for the check
digits and Verhoeff. Both of Verhoeff's defining guarantees are asserted over
arbitrary input — every single-digit substitution and every adjacent
transposition is detected — and the 7-3-1 scheme's blind spot is pinned rather
than glossed over: it misses adjacent transpositions of characters differing by
five. The phase-1 vectors were derived from the standards independently of any
implementation, so agreeing with them is a real check on this phase rather than
a restatement of it.

**`extraction/` moved to phase 6.** It was listed here originally, and it does
not belong here. Preprocessing, MRZ location, QR decoding and OCR are pixel
code, and phase 1 committed data-level fixtures only, so building them now
would mean shipping pixel code that nothing tests. They move to phase 6,
alongside the synthetic images that can exercise them. See
[ADR 0004](adr/0004-extraction-contract-in-core.md).

**What that costs, and what it does not.** Phases 4 and 5 are unaffected: a
detector consumes a `Subject`, and a `Subject` can be built from the committed
data-level fixtures — MRZ text now, signed payload bytes in phase 4 — exactly
as the golden harness already does. What waits until phase 6 is the end-to-end
path from a photograph to a verdict. Nothing downstream is blocked; the
integration is simply not demonstrable until there are images.

---

## Phase 3 — Privacy

Before anything is persisted, decide what may be persisted.

- `core/privacy/hashing.py`: per-deployment salted hashing of document numbers.
- `core/privacy/masking.py`: display forms that never reveal a full number.
- `core/privacy/retention.py`: retention windows per artefact category.

**Exit criteria.** A test that fails if a raw Aadhaar number can reach any
persistence path. Aadhaar Act 2016 s.29 and s.37 are the constraint, not a
preference.

---

## Phase 4 — Rung 0, cryptographic verification

The only rung that can clear a document, so it is built before the rungs that
cannot.

- `detectors/rung0_crypto/aadhaar_secure_qr.py`, `digilocker_xml_sig.py`,
  `pdf_pkcs7.py`.
- `epassport_sod.py` stays a stub. It is blocked on chip reader hardware and the
  console must say so on every case rather than quietly omitting it.

These detectors verify signatures over payload bytes. Getting those bytes out
of a photograph is `extraction/qr_decode.py`, which is phase 6 — so the golden
fixtures here are committed payloads, in the same data-level form phase 1
established.

**Exit criteria.** Golden tests with committed fixtures for every detector.
A tampered payload produces `PROOF_INVALID`, not an exception.

---

## Phase 5 — Rung 1, deterministic detectors

- `mrz_checkdigits.py`, `field_crossmatch.py`, `template_geometry.py`.

**Exit criteria.** Golden tests. Every `FAIL` cites the clause it applied, and
every `reasons` entry is readable by someone who has never heard of a check
digit.

---

## Phase 6 — Synthetic data, extraction, evaluation, and classical tamper detection

The measuring instrument is built before the thing being measured. This is also
where the first images in the project appear, which is why extraction lands
here rather than in phase 2.

- `datagen/`: synthetic specimens and one class per forgery type, reproducible
  from a seed. **Built first**, because everything else in this phase needs
  images to be testable.
- `extraction/`: preprocessing, MRZ location, QR decoding, OCR adapters. Moved
  from phase 2; see ADR 0004. This is also where `core/contracts/subject.py` is
  expected to grow, since it was designed without real captures.
- `eval/protocol.py`, `eval/run_eval.py`, `eval/metrics.py`.
- `detectors/rung2_inference/tamper_classical.py`, `tamper_trufor.py`,
  `metadata_forensics.py`, `pdf_structure.py`.

**Exit criteria.** `eval/run_eval.py` has run on a named dataset and written a
report to `eval/reports/`. Until then, rule 2 of CLAUDE.md means no performance
figure appears anywhere in this repository — not in the README, not in a
docstring, not on a slide. Separately, a photograph of a document now produces a
verdict end to end, which nothing before this phase could demonstrate.

---

## Phase 7 — Rung 2, biometrics

- `face_match.py`: document portrait against live capture.
- `pad_liveness.py`: presentation attack detection.

**Exit criteria.** Encryption at rest for embeddings and a retention window
that is enforced by code. Nothing in this repository describes a face embedding
as anonymous, irreversible or one-way, because it is none of those things.

---

## Phase 8 — Rung 3, contextual advisories

- `repeat_identity.py`, `watchlist.py`.

**Exit criteria.** A test proving that no Rung 3 output can change a decision.
The ladder already guarantees this; the phase adds the detectors that would
break it if it did not.

---

## Phase 9 — The shell

Everything that touches the outside world, built last because `core/` and
`detectors/` must never depend on it.

- `db/`, `ledger/`, `api/`, `explain/renderer.py`, `ui/console.py`,
  `deploy/`.

**Exit criteria.** The officer console states what was not checked on every
case. A screening decision can be replayed from the ledger and produces the
same verdict.
