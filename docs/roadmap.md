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

## Phase 3 — Privacy ✅

Before anything is persisted, decide what may be persisted.

- `core/privacy/identifiers.py`: `RawIdentifier`, a number in the clear that
  masks itself in `str`, `repr`, f-strings and logs, and that Pydantic refuses
  to give a schema — so a contract field of that type fails at class definition.
- `core/privacy/hashing.py`: HMAC-SHA256 with a per-deployment key, domain
  separated by document kind. See [ADR 0005](adr/0005-keyed-hashing-for-document-numbers.md)
  for why a keyed hash rather than a salted one.
- `core/privacy/masking.py`: display forms that never reveal a full number, and
  that hide a short value completely rather than returning it intact.
- `core/privacy/retention.py`: a `RetentionPolicy` that refuses to construct
  unless every artefact category has an explicit window, with no defaults and
  no unbounded option.

**Exit criterion partly met, and the gap is real.** The criterion was a test
that fails if a raw Aadhaar number can reach any *persistence path*. There is no
persistence path: `db/` is stubs until phase 9. What phase 3 delivers instead is
three checks that can be made today, in `tests/unit/test_no_raw_identifiers.py`:

- no file committed to this repository contains a twelve-digit number that is
  Verhoeff-valid and begins 2 to 9, which is the shape of an issuable Aadhaar
  number (the phase-1 fixtures begin with 0 deliberately);
- only `core/privacy/hashing.py` and `core/privacy/identifiers.py` read a
  number in the clear, enforced by scanning for `reveal()` call sites;
- no contract field can carry a raw identifier.

The database test is listed under phase 9 and this phase is not complete
without it.

**Honesty note carried forward.** These digests are pseudonymous, not anonymous.
An Aadhaar number has about 9x10^11 possible values, so anyone holding both the
deployment key and the database recovers every number by enumeration. That is
recorded in ADR 0005 and in the threat model rather than left implicit.

---

## Phase 4 — Rung 0, cryptographic verification (partial)

The only rung that can clear a document, so it is built before the rungs that
cannot.

- `trust_store.py`: issuer anchors, each carrying its own algorithm allowlist
  and validity window. Passed in by the caller, never loaded by a detector.
- `verification.py`: the format-agnostic core. Three outcomes, and only one
  path reaches the one that can clear a document.
- `digilocker_xml_sig.py` and `pdf_pkcs7.py`: **done**, with committed golden
  fixtures for a valid signature, a tampered document and an unknown issuer.
- `aadhaar_secure_qr.py`: **still a stub, deliberately.** The cryptography is
  ordinary RSA and already exists in `verification.py`; what is missing is the
  container layout, and there is no specimen to check a parser against. The
  module docstring lists the four things needed to finish it.
- `epassport_sod.py` stays a stub. Blocked on chip reader hardware, and the
  console must say so on every case rather than quietly omitting it.

These detectors verify signatures over payload bytes. Getting those bytes out
of a photograph is `extraction/qr_decode.py`, which is phase 6 — so the golden
fixtures here are committed payloads, in the same data-level form phase 1
established.

**Exit criteria met for what shipped.** Golden fixtures for both implemented
detectors, and a tampered document produces `PROOF_INVALID` rather than an
exception. Not met for Aadhaar, which has no detector to test.

**What this cost.** `docs/scope.md` lists two document types that can reach
`CLEARED`: Aadhaar with a readable Secure QR, and DigiLocker issued documents.
Only the second of those works. Until a real Secure QR specimen is available,
an Aadhaar card reaches at best `MANUAL_REVIEW`, and the practical clearance
rate at an SSB crossing is lower than the scope table implies.

**One bug worth remembering.** The PDF library reports a tampered document as
`valid`, because the signature object is still well formed; only `intact` says
the bytes still match. It also drops `trusted` to false whenever a document is
not intact, so trust alone cannot tell a tampered document from one signed by an
unknown authority — two cases with opposite outcomes. The detector therefore
recognises the signer independently of validation. Both behaviours are pinned by
golden fixtures.

---

## Phase 5 — Rung 1, deterministic detectors (partial) ✅

- `mrz_checkdigits.py`: **done**. Recomputes every verification number on the
  strip. The six golden cases committed back in phase 1 now run for real, and
  the detector reproduces their pinned officer-facing wording exactly — which
  is what a golden corpus authored before the implementation is for.
- `expiry.py`: **done**, a module the original file list did not name. CLAUDE.md
  lists expiry logic under Rung 1 and the threat model had it as an open gap.
  An expired document is a `FAIL`, which rejects; see below.
- `field_crossmatch.py`: **moved to phase 6.** Cross-checking the strip against
  the printed page needs *structured* visual inspection fields, and `Subject`
  carries the printed page as free text lines. What turns a photograph into
  named fields is extraction, which is phase 6.
- `template_geometry.py`: **moved to phase 6.** Pixel work plus per-issuer
  template specifications, neither of which exists. Same reasoning as ADR 0004.

**Exit criteria met for what shipped.** Golden tests for both detectors, every
`FAIL` cites `ICAO Doc 9303 Part 3 s.4.2.2`, and a test asserts no reason
contains the phrase "check digit" — the corpus-wide jargon ban already covered
it, and the detector tests check it again at the point of production.

**The expiry decision, and what it costs.** An expired document fails, and a
Rung 1 failure rejects. `docs/threat-model.md` records that the people crossing
here are largely daily commuters, so a card that expired last month turns the
same person back every morning until they renew it, without a human forming a
view first. It was taken deliberately: an expired travel document is not valid
for travel, the date is not arguable, the officer is shown exactly which date
failed, and the alternative would let a document that expired twenty years ago
clear on its signature alone.

**One thing that turned out not to be checkable.** There is no date-of-birth
plausibility check, because there cannot usefully be one. The century rule in
`core.standards.date_rules` resolves a two-digit year into the hundred years
ending on the day of the crossing, so every resolution is already a plausible
living age by construction and the test would pass unconditionally. Saying so
is better than shipping a check that always passes and looks like coverage.

---

## Phase 6 — Synthetic data, extraction, evaluation, and classical tamper detection ✅

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

### Done in this slice

- `datagen/`: reproducible specimens for a **fictional issuing state**, and five
  forgery generators each stating what it altered. No real issuer is imitated
  and no synthetic face is generated.
- `extraction/`: preprocessing, strip location, QR decoding, and a two-backend
  reader. Plus `pipeline.py`, which turns a capture into a `Subject`.
- **The end-to-end path is closed.** A photograph now flows through extraction
  into the detectors written in phases 4 and 5 and out as a verdict. That is
  the gap ADR 0004 opened, and it is shut.

### The finding that matters

**A general text recogniser cannot read the machine-readable strip.** Measured
on this project's own specimens, RapidOCR reads the first strip line at 100%
character agreement and the second at 32% — and reads it **backwards**, with the
filler character `<` recovered as `>`. Feeding it a cropped single line does not
help; its direction classifier flips a dense alphanumeric run because there is
no linguistic context to orient it.

This is exactly what the stack in CLAUDE.md already specified — *"Tesseract with
an OCR-B whitelist for the MRZ zone only"* — and it is now demonstrated rather
than assumed.

**Tesseract 5.4 is now installed and wired in**, found through an explicit
override, then the path, then the handful of locations its installer uses — the
Windows installer does not amend the path, and a checkpoint box is not somewhere
anyone wants to be debugging environment variables.

It reads the first strip line at 98% character agreement. It does not reliably
read the second, and the reason is **our renderer, not the reader**: a real
strip is set in OCR-B, which exists precisely to disambiguate `O` from `0`, and
the synthetic specimens are drawn in a font that is not. Rendered in a monospace
font the coded data fields come back exactly — `9001011M3501014` character for
character — and the errors are confined to the long filler runs, where the
reader inserts and merges characters. That breaks the line length, which
destroys the alignment of every field after it.

**The reader therefore refuses to vouch for a reading it cannot trust.** A line
of forty-six characters where forty-four are expected has had something
inserted; passing it downstream would put a plausible, incorrect strip in front
of the check-digit detector and fail a genuine document. Nothing is repaired —
trimming a filler run until the length comes out is a guess dressed as
arithmetic. Either two well-formed lines come back, or nothing does with a
stated reason. There is no third outcome, and a test asserts it.

**What would close the remaining gap**, in order of cost: OCR-B-trained data for
Tesseract, which is what production MRZ readers use and which could not be
fetched offline here; or a specimen renderer using a licensed OCR-B face, which
would make the synthetic corpus representative of what a real strip looks
like.

The strip is deliberately **not** repaired by reversing the string and mapping
`>` back to `<`. Individual characters are also substituted, so a repaired strip
would be plausible and wrong, and would manufacture check-digit failures on
genuine documents — the first-order harm in `docs/threat-model.md`.

### The evaluation, and what it found

`eval/` is built and has run. The report is committed under `eval/reports/` and
is the **only** place in this repository a performance figure may come from.

It reports per detector and **per forgery type**, never pooled, and it leads
with what the numbers are not. Three findings are worth carrying forward.

**The first version of `tamper_classical` escalated 100% of genuine documents.**
The evaluation caught it immediately. The cause was arithmetic, not tuning: the
signals were normalised against the median block variance of the whole image,
and most of a document is blank paper with a variance of essentially zero, so
every ratio divided by noise and saturated. Restricting the measurement to
textured blocks fixed it. Genuine documents now score 0.37 and escalate 0% of
the time.

**Only one of the three classical signals separates anything, and it separates
exactly one attack.** Error level localisation catches `recapture` at +0.32
above genuine. Noise localisation and block duplication separate nothing, so
they are computed as diagnostics and deliberately **not scored**. Scoring a
signal that does not discriminate buys false escalations and nothing else.

**Why the other four forgeries are invisible is a property of the dataset, not
proof that they are undetectable.** The specimens are lossless images, edited
losslessly and saved losslessly, so there is no compression history for these
techniques to find an inconsistency in. `recapture` is the only generator that
introduces a compression round trip. Making the others measurable means
modelling a realistic capture chain in `datagen` -- photographed as JPEG,
edited, re-saved -- which is the next piece of work here, and it is a change to
the data rather than to any detector.

`separation()` itself had to be corrected mid-phase: it first pooled every
forgery type into one median and reported `+0.03` for a detector that separates
one attack by `+0.32` and is blind to four. That is the same error as a single
headline accuracy figure, committed inside a function whose own docstring
forbids it.

### Deferred out of phase 6

`template_geometry.py` measures a document against its issuer's template, and
the only template available is the one `datagen` draws. A detector built against
it would pass its own fixtures perfectly and say nothing about a real document:
the code agreeing with itself. It waits alongside the Aadhaar container and the
Bhutanese and Nepali formats, all blocked on the same thing, a real specimen.

**Exit criteria.** `eval/run_eval.py` has run on a named dataset and written a
report to `eval/reports/`. Until then, rule 2 of CLAUDE.md means no performance
figure appears anywhere in this repository — not in the README, not in a
docstring, not on a slide.

**One calibration to redo against real captures.** The strip locator uses a row
ink-density threshold measured on synthetic specimens: strip rows read 0.15–0.26
there and printed-field rows reach 0.05. Real captures vary in lighting and
print contrast, and this constant is the first thing to re-measure. A strip it
misses is reported as unread, which is the safe direction.

---

## Phase 7 — Rung 2, biometrics (partial)

### Exit criteria met, in full

- `core/privacy/biometrics.py`: an embedding leaves the module only as
  `EncryptedEmbedding`, AES-256-GCM under a key held **separately from the
  identifier hashing key** — different sensitivity, different retention,
  different reasons to rotate, so compromising one must not compromise the
  other. There is no code path that persists a vector in the clear, because
  nothing accepts one.
- `created_at`, `model_version` and `dimension` are bound into the ciphertext
  as authenticated data. Editing the timestamp to extend a retention window
  breaks decryption, so the cheapest attack on retention — changing one field
  in a database row — does not work.
- Retention is enforced in code: `EncryptedEmbedding.is_due_for_deletion` reads
  the window from a `RetentionPolicy` that already refuses to construct without
  an explicit answer for face embeddings.
- **A repository-wide scan** fails on any sentence describing an embedding with
  a word that is not true of it; the words are listed in the test rather than
  here. Same enforcement pattern as the Aadhaar-shaped-number scan, applied to
  rule 4 — and it caught three of this project's own sentences, two in code and
  one in this file.

### What does not work, and why the second reason is the harder one

`face_match.py` and `pad_liveness.py` are registered and report `INCONCLUSIVE`
on every document. Two blockers:

1. **No model weights.** InsightFace `buffalo_l` is a large download and none is
   present. ONNX Runtime is installed, so the runtime is there; the model is
   not. Identical to TruFor.
2. **No faces, deliberately.** `datagen` draws a flat placeholder panel rather
   than a portrait, because producing images of people who do not exist in
   order to test a border system is a line this project does not cross. So even
   with weights there is nothing here to validate against.

The second is not solved by a download. Validating face matching needs a corpus
of real faces, and obtaining one is a question of lawful basis and consent
before it is a question of data. The constraint is recorded in `docs/scope.md`
so the decision gets made deliberately rather than by whoever first needs a test
to pass.

Both detectors report on **every** document rather than declining when there is
no live capture, so that a crossing where the bearer was never checked reads
differently from one where they were.

---

## Phase 8 — Rung 3, contextual advisories ✅

- `context_store.py`: a crossing history and a watchlist, both built by the
  caller and handed in. Rule 5 requires it, and it also means a detector cannot
  widen its own view of a traveller.
- `repeat_identity.py`, `watchlist.py`.

**Exit criterion met.** Both advisories, raised as loudly as they can be, are
run through the real ladder against every decision the system can reach —
including a clearance and a rejection — and nothing moves.

### Two boundaries, chosen rather than inherited

**Repeat identity links documents, not people.** A crossing is matched on the
salted digest of the document number, so the same person presenting a second
document is a second history. Linking across documents would need biometrics,
which turns a document log into a movement history of a border population. That
is a different system and would need its own review; `docs/threat-model.md`
names it.

**The watchlist matches on exact digest only.** No name matching. Name matching
catches aliases, and it also flags an innocent person who shares a name with
someone listed — on a border where the same people cross every morning, that
advisory would appear in front of an officer daily, indefinitely, with no way to
clear it. Exact matching misses more, and what it reports is true.

Neither structure holds a document number. An operator's watchlist arrives as
numbers and is hashed on load; `Crossing` refuses to construct on anything that
is not a full digest.

### A contract change this phase forced

Rung 3's vocabulary was `FLAG_RAISED` and `NO_FLAG`. Building the detectors
showed that was not enough: a checkpoint holding no watchlist, or a document
whose number could not be read, would have had to report `NO_FLAG` — which an
officer reads as "checked, nothing found". That is silence about a check that
did not happen, which CLAUDE.md calls a defect.

So Rung 3 gained `NOT_CHECKED`, mapped into the ladder's `SILENT` set so it
lands in `Verdict.not_checked` alongside `NO_PROOF_PRESENT` and `INCONCLUSIVE`.
It weakens no guarantee: a silent result clears nothing and rejects nothing by
construction. The phase-0 exhaustive test found the change immediately and
demanded a declared expectation for the new value, which is the test design
working as intended.

---

## Phase 9 — The shell ✅

Everything that touches the outside world, built last because `core/` and
`detectors/` must never depend on it. Split in two: the audit trail first,
because the exit criteria are about it, then the interfaces that sit on top.

### Slice A — ledger, database, renderer ✅

- `ledger/hashchain.py`: a Merkle log with RFC 6962 domain separation, and
  Ed25519 signed checkpoints.
- `ledger/interface.py`: what is logged, and the canonical serialisation a
  replay is compared against.
- `db/models.py`, `db/session.py`, `db/guards.py`: SQLite in WAL mode, with a
  guard that refuses to flush a raw document number.
- `explain/renderer.py`: the officer-facing report.

**All three exit criteria met.**

*Every report states what was not checked.* The section is emitted on every
case, including clearances and including cases where nothing was left
unchecked — where it says so in words rather than disappearing. A vanishing
section teaches an officer to stop looking for it. Tested against every shape
of verdict the ladder can produce.

*A decision can be replayed from the ledger.* A synthetic document is screened,
stored, and screened again; the log recognises the second result. The stored
verdict is checked against the log too, which is the stronger claim: the
database has not drifted since. And the tamper this exists to catch is tested
directly — deleting one line about what was not checked, which changes no
decision and makes a case look cleaner, no longer matches the logged digest.

*No raw document number reaches persistence.* Carried over from phase 3, which
built the machinery but could not test the criterion because there was no
persistence path to test it against. There is one now, and the guard is checked
against a real database: every column of every table, on insert and on update,
with the caught number masked in the refusal. Half of `test_persistence.py` is
about what the guard must **allow** — hex digests, fixture numbers, whole
serialised verdicts — because a guard that blocks ordinary writes is switched
off within a week, and then the rule is enforced by nothing.

### What the ledger stores, and what that costs

A log entry is a **digest** of a verdict, not the verdict. Append-only storage
and an enforceable retention policy cannot both apply to the same record, and
holding a digest resolves it: the log is permanent, the verdict expires with the
case record. The cost is stated rather than buried — once retention destroys a
case, the log still proves a decision was made at a time and has not been
altered, but not what it said. [ADR 0006](adr/0006-the-ledger-stores-a-digest.md)
records the decision, the alternatives, and when to revisit it.

### A bug worth recording

The first version of the integration test rebuilt the log from the database and
got a different Merkle root. SQLite has no timestamp type: `DateTime(timezone=
True)` writes an offset and reads back a naive value. The instant survives, the
offset does not, and the ledger commits to `isoformat()` — so a log rebuilt
after a restart would have disagreed with every checkpoint ever published, with
nothing to point at.

`db.models.UtcDateTime` fixes it at the column type, and refuses a naive
timestamp on the way in rather than assuming UTC. Guessing a timezone in an
audit record is how a case ends up dated five and a half hours from when it
happened. It was caught only because the test rebuilt from storage rather than
from memory, which is the difference between testing a log and testing a list.

### Slice B — the interfaces ✅

- `api/settings.py`: configuration that refuses to invent a database, a
  checkpoint identity or a signing key.
- `api/screening.py`: the runner that assembles the deployment's detectors and
  converts a detector that raises into evidence saying so.
- `api/routes.py`, `api/schemas.py`, `api/deps.py`, `api/app.py`.
- `db/recording.py`: the case and its ledger entry written in one transaction.
- `ui/console.py` and `ui/templates/`: server-rendered, no JavaScript.
- `db/migrations/`: a real Alembic chain, tested against the models.
- `deploy/`: an entrypoint, a healthcheck and file-mounted secrets.

**What the shell refuses to do**, each because returning something would be
worse than returning nothing:

*It will not sign a checkpoint without a key.* `/ledger/checkpoint` answers 503.
A signature made with a key generated at start-up cannot be checked against
anything published, and it would read as proof.

*It will not invent a checkpoint identity or a database path.* Both are refused
at start-up. A placeholder identity puts a false crossing on real audit records;
a default database path creates a second database rather than opening the real
one.

*It will not drop an unreadable capture.* Bytes that are not an image still
produce a case, a verdict of `MANUAL_REVIEW`, and a stated reason. A border that
ignores malformed input has a gap exactly where someone would push.

*It will not edit an officer's note.* A note containing something shaped like a
document number is refused with advice about what to remove. Stripping it
silently would leave a review whose reasoning had been edited by a regular
expression.

*It will not answer a failure with silence.* Any unhandled error returns 503 and
says the document is unscreened, because the one reading that must never be
available is "nothing came back, so nothing was wrong".

### An officer's decision is a record, not an edit

Most cases resolve to `MANUAL_REVIEW`, so the officer's decision is the normal
outcome rather than an edge case. It is stored as its own record and its own
ledger entry; the verdict is never rewritten.
[ADR 0007](adr/0007-officer-decisions-are-appended.md) has the reasoning, of
which the short form is that overwriting `Verdict.decision` would make the
record claim the system verified something it did not, and would set off the
ledger's own tamper detection as a matter of routine.

An officer may clear a document the checks could not, and may reject one nothing
was found wrong with. Refusing that would not prevent the override; it would
move it onto paper. What is required is a named officer and a note.

### Three tests worth knowing about

**A third party verifies the log using only HTTP.**
`tests/integration/test_api.py` fetches the signed checkpoint, the public key,
the leaf and its proof over the API, and verifies them without touching the
database. That is the claim the whole ledger exists to support.

**Every registered detector is assembled.** A detector that exists but is never
built produces no evidence, not even to say it did not run — the same defect as
a missing check, wearing different clothes. The test compares the registry
against what the deployment assembles.

**The migration and the models are compared, not assumed.** Alembic's own
comparison runs against a freshly migrated database. Without it, a column added
to `db/models.py` would pass every test — they build their schema with
`create_all` — and fall over on the next deployment.

### What phase 9 leaves for a real deployment

- Authentication. There is none: the console trusts the officer identifier it is
  given. That is a decision about how a checkpoint authenticates staff, and it
  needs an answer from the deployment before this is exposed beyond localhost.
- Checkpoint publication. The system signs checkpoints; nothing yet carries them
  off the box, and ADR 0003 is explicit that an unpublished checkpoint proves
  nothing.
- Retention enforcement. `core/privacy/retention.py` decides what may be kept;
  nothing yet runs on a schedule to delete it.
