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
- ~~Retention enforcement.~~ **Done, phase 10.** See below.


---

## Phase 10 — Retention, enforced (partial)

Phase 9 shipped three named gaps. This phase closes the first of them.

`core/privacy/retention.py` had decided what may be kept since phase 3, and
nothing acted on it, so a deployment kept every case forever. Rules 3 and 4 of
CLAUDE.md put limits on how long identifiers and biometrics may be held; those
limits were written down and enforced by nothing.

- `core/contracts/destruction.py`: `DestructionRecord`, the tombstone.
- `db/retention.py`: which cases are due, and what destroying one would record.
- `db.recording.record_destruction`: the four-part write, atomic.
- `api/retention_job.py`: `python -m api.retention_job`, with `--dry-run`.
- `ui/templates/destroyed.html`: what an officer sees instead of a 404.

**Exit criteria met.** A case past its window is destroyed, its officer reviews
with it. A case inside its window is untouched. Every ledger leaf that existed
before a sweep still verifies its own inclusion afterwards, which is the claim
this had to not break. The destruction is itself appended to the log.

### Five decisions, taken deliberately

**The decision does not survive retention.** The tombstone carries no
`CLEARED`, no `REJECTED`, no verdict. ADR 0006 already accepted that a destroyed
case leaves a log proving a decision was made but not what it said; carrying the
outcome forward here would have quietly reversed that and made the policy
cosmetic. A test asserts none of those strings appears in what is stored.

**Officer reviews die with their case.** A review is a named officer and a note
in their own words. It belongs to the case and has no meaning without it.

**Destruction is an appended entry, never a deletion.** No ledger leaf is ever
removed — deleting one breaks the Merkle chain for every entry after it and
invalidates every checkpoint ever published.

**410, not 404, for a destroyed case.** The identifier was valid and the thing
it named is deliberately gone. `missing.html` already said a missing case "is
not the same as the case having been cleared, rejected or deleted", and that
sentence only became true once destruction had a page of its own.

**No scheduler.** A command, not a daemon. What deletes records at a border post
should be visible in a crontab, disablable, and runnable by hand while somebody
watches the output — not a timer firing inside a web server that nobody
configured. The command refuses to run without a policy and exits 2, so a
scheduler cannot report healthy while keeping everything.

### One thing found by running it

The policy loader reads `utf-8-sig` rather than `utf-8`. Windows PowerShell
writes a byte order mark by default, so the first policy file written on the
development machine was refused over an invisible character. The refusal was
correct and the message was clear; accepting a mark is still the right
behaviour, because the alternative is an operator debugging an encoding at a
checkpoint.

### What phase 10 leaves

- Retention applies to `CASE_RECORD` only. The other five categories have
  windows and nothing sweeps them, because nothing yet stores a document image,
  a portrait crop or an embedding to sweep. When something does, it goes here.
- Checkpoint publication and authentication, both still open from phase 9.


---

## Phase 11 — The console's front door

Phase 9 built an officer console that could read cases and record decisions, and
no way to create one. The only intake was `POST /screenings`, which means curl or
Postman. An officer at a checkpoint cannot use either, and neither can a demo
driven from a phone.

- `api/intake.py`: `record_capture`, the one intake path.
- `api.deps.Context.screen_capture`: the seam the console calls.
- `ui/console.py`: `GET` and `POST /console/submit`.
- `ui/templates/submit.html`, and a link from the queue.

**The interesting constraint.** Rule 5 forbids `ui` from importing `api`,
`detectors` or `extraction`, and screening lives in all three. The console
therefore does not screen anything: it calls a method on the duck-typed context
it already holds, and the API decides what that method does. `ui/console.py` has
a comment from phase 9 explaining that the context is loosely typed precisely so
that the package which renders records does not depend on the package that
produces them; this is the first time that decision paid for itself. A test
greps the console's source for a forbidden import, so the seam cannot quietly
close.

**Both intake paths are now the same code.** `record_capture` was extracted from
the JSON route rather than written beside it. Two intake paths that drifted would
mean the same document screened from the console and over HTTP could produce
different records, which is the kind of difference nobody notices until an audit.

**What the form does not do.** It does not resize, rotate, enhance or re-encode
the photograph. The bytes screened are the bytes the camera produced, because the
provenance digest has to be of something that exists, and a document the system
quietly improved is not the document that was presented.

**On using it from a phone.** The form carries `capture="environment"`, so a
phone opens the rear camera directly. Reaching it from a phone means binding the
server to the local network, and there is still no authentication — that pairing
is a demonstration setting, not a deployment. `deploy/compose.yaml` continues to
bind to localhost.


---

## Phase 12 — Trust anchors, configurable

`trust_store.py` calls itself the highest-value target in the system, and it was
also the emptiest. Outside tests, no anchor was ever added: `Deployment` built a
default `TrustStore()` and there was no configuration path to populate it. So
Rung 0 — the only rung that can clear a document — could never answer, and every
crossing reached at best `MANUAL_REVIEW`.

That is correct fail-closed behaviour and it is documented as such. It is also
half a system: a ladder that can only ever refuse is a queue.

- `api/trust.py`: `read_trust_anchors`, from `SENTINELID_TRUST_ANCHORS_FILE`.
- `api.settings.Settings.trust_store`, and `NO_TRUST_ANCHORS` in `unavailable()`.
- `api.deps.build_context` now hands the store to the `Deployment`.

### Three rules the reader enforces

**Nothing is discovered.** The anchors file is a path an operator supplied, and
certificates are files they put there. There is deliberately no fallback to the
operating system's certificate store: those roots exist to authenticate web
servers, and inheriting them would mean trusting several hundred commercial
authorities to attest to identity documents.

**Permitted algorithms are stated, never derived.** A certificate contains a key
that several constructions would accept; it does not say which are intended.
Inferring the set would silently widen trust whenever a key type gained a new
construction, so the file has to name them and an unknown name is refused with
the list of valid ones.

**A validity window may be narrowed, never widened.** The window comes from the
certificate. An operator may stop trusting an issuer early; one who tries to
extend trust past the certificate's own expiry is refused, because that is not
configuring an anchor, it is overriding the issuer.

Both encodings are accepted — a `.cer` exported from Windows is DER, a `.pem`
from anything else is base64 — because requiring one means converting files at a
checkpoint. A byte order mark is accepted for the same reason it is in the
retention policy reader.

**Exit criteria.** A deployment given an anchor file holds anchors and stops
saying it cannot confirm any document. A deployment given none says so on every
case. Widening is refused, narrowing works, and a malformed anchors file refuses
the start-up rather than quietly producing an empty store — the failure that
would otherwise reject genuine documents with no explanation.

### What this does not do

It does not add a real issuer. Nobody has yet supplied a genuine DigiLocker or
UIDAI certificate, so the only anchors that exist are generated in tests. The
machinery is ready; the trust decision is a human one, and the anchors file is
where somebody makes it deliberately and on the record.


---

## Phase 13 — Checkpoint publication

The last of the three gaps phase 9 named. The system signed checkpoints on
request and nothing carried them off the box, which ADR 0003 says makes them
worth nothing: whoever holds the database can recompute the whole Merkle chain,
so a root this system shows you is a number it chose.

- `api/publish_checkpoint.py`: `python -m api.publish_checkpoint --out DIR`.
- `tools/verify_checkpoint.py`: the file a recipient runs.

**The published file is self-describing.** It carries the public key, the
checkpoint identity, the tree size, the root, the timestamp and the signature.
A recipient needs nothing the operator holds — not the database, not this
repository, not a key fetched from the operator's own server.

**The verifier re-implements the byte layout rather than importing it.** A check
that shares code with the thing it checks agrees with it by construction, so
`tools/verify_checkpoint.py` builds the signed bytes itself and imports nothing
from this project. `test_the_standalone_verifier_agrees_with_the_system` pins the
two together, because independence is only useful if drift is caught: if that
test ever fails, every checkpoint already in somebody else's hands is about to
stop verifying.

**Nothing is automated, deliberately.** `CLAUDE.md` forbids cloud services, and
a checkpoint uploaded to storage the operator controls has not left the
operator's control. The command writes a file. Carrying it to a second
organisation is a procedure, and the procedure belongs to the deployment.

### What a series shows, and what it does not

Given several checkpoints, the verifier reports whether the log only ever grew,
and names the two ways it can fail: a tree that shrank, and a tree that stayed
the same size with a different root — entries removed, and history rewritten.

**This is deliberately described as weaker than it looks.** It is not an RFC 6962
consistency proof, which this version does not produce: `ledger/hashchain.py` has
`inclusion_proof` and no `consistency_proof`. A growing series is *consistent
with* an append-only log and is not proof of one. The verifier says so in those
words rather than implying more, and a consistency proof is the obvious next
piece of work on the ledger.

**Exit criteria.** A checkpoint is written to a file; the standalone verifier
accepts a real one and rejects a changed root, a changed entry count, an unknown
format and an incomplete file; a series that shrinks or is rewritten is reported.
Publishing without a signing key is refused with exit 2 and writes nothing,
because an unsigned substitute would look like proof.


---

## Phase 14 — Consistency proofs

Phase 13 could publish a checkpoint and a recipient could check its signature.
What a recipient still could not check was the thing the log exists for: that
nothing it was told earlier had been withdrawn.

**Why inclusion proofs are not enough.** Whoever holds the database can
recompute an entirely different history, and in that history every individual
inclusion proof still verifies. Inclusion says an entry is present in the log
being shown; it says nothing about whether that log is the same one as
yesterday's.

- `ledger.hashchain.consistency_proof` and `verify_consistency`, RFC 6962.
- `TransparencyLog.consistency`, and `GET /ledger/consistency/{old_size}`.
- `python -m api.publish_checkpoint --since PREVIOUS.json`, so a published
  checkpoint carries a proof that it extends the last one.
- `tools/verify_checkpoint.py` checks those proofs, with its own independent
  implementation.

### The finding that made this safe to build

The tree in `merkle_root` is built level by level, carrying an unpaired node up
unchanged. That is not how RFC 6962 describes its tree, which splits recursively
at the largest power of two — so the standard's consistency algorithm could not
simply be assumed to apply.

**They are the same tree.** A test written directly from RFC 6962 section 2.1
compares the two constructions at every size from 0 to 64 and they agree
everywhere. That is what licensed using the standard's well-understood algorithm
instead of inventing one for a bespoke tree, which for this particular piece of
code is the difference between a proof and a decoration.

### Tested as a property, not as examples

A consistency proof is exactly the kind of code that is correct on the cases its
author thought of. So `tests/unit/test_consistency_proof.py` asserts, over
hypothesis-generated size pairs, that a genuine extension always verifies and
that changing any entry the earlier checkpoint covered always fails. Truncated
proofs, extended proofs, proofs from a different log, dropped entries and
shrinking logs each have their own refusal.

### What the published file now carries

`--since` embeds `from_size`, `from_root` and the proof. A recipient holding a
series verifies the whole chain **offline**, with no access to the operator at
all. A checkpoint published without `--since` carries no proof, and the verifier
says so in those words rather than letting silence read as a proof that passed.

**Exit criteria.** A series published with `--since` reports `PROVED to extend
the previous checkpoint`. A forged proof, a proof naming a different earlier
root, and a log that shrank are each reported as problems. Publishing against a
checkpoint larger than the current log is refused, because a log smaller than one
it claims to extend has lost entries.

---

## Phase 15 — A preflight check for demonstrations

`tools/demo_preflight.py`. Not part of the system; a tool for the person running
it. From a phone, every network failure looks identical — "this site can't be
reached" — whether the server is bound to loopback, the firewall is blocking the
port, or the port is open on the wrong profile. This distinguishes them.

It changes nothing: opening a firewall port is a security decision that needs
administrator rights, so the tool prints the command and a person runs it. It
also states the thing that is easy to forget while getting a demonstration to
work, which is that reaching the console from another device means running it
with no authentication on a shared network.


---

## Phase 16 — Aadhaar number validation (slice A)

The first slice of the four-day push toward a demonstration a person can
operate. Chosen first because it needs nothing from outside the repository and
it is the one check that can say a document is false rather than unproven.

**What was there.** `core/standards/verhoeff.py` has existed since phase 2 with
property-based tests, and `core/privacy/identifiers.py` used it to *recognise* an
Aadhaar-shaped number so the repository scan could refuse to commit one. **No
detector used it.** The single most demonstrable honest check in the system was
implemented and wired to nothing.

- `detectors/rung1_deterministic/aadhaar_number.py`, Rung 1.
- Assembled in `api.screening.assemble`, so it runs on every screening.

**What it may conclude.** An issued Aadhaar number derives its last digit from
the other eleven, so most numbers a person can invent are numbers UIDAI could
never have issued. That is arithmetic, so it is Rung 1, so it can reject.

A pass means the number is *well formed*. It is not evidence that the number was
issued, that it belongs to the bearer, or that the card is genuine — only the
signature in the Secure QR can say that, and that is Rung 0. The officer wording
says so in its own sentence, because "the number checked out" is exactly the kind
of line that gets over-read.

### Three guards against refusing a genuine card

The number comes from general text recognition on a photograph, and a single
misread digit fails the arithmetic on a real card — the first-order harm in
`docs/threat-model.md`. So it judges only a document *declared* to be an Aadhaar
card; only when the printed page was read completely; and if several candidate
numbers are found and any one is well formed, that one is taken as the number
and the rest are treated as recognition noise. The failure wording also tells the
officer that a poor photograph can cause this, before they treat it as a forgery.

### What rule 3 did to the golden corpus

There is no committed golden case for a number that passes. A passing number is a
Verhoeff-valid number beginning 2 to 9, which is an issuable Aadhaar number, and
`tests/unit/test_no_raw_identifiers.py` fails the build if one appears in any
committed file. The passing case is therefore a unit test that computes the
number at runtime — which is also a small proof that the detector and the
repository scan agree on what "issuable" means.

Committed: `aadhaar-number-not-issuable` (FAIL) and `aadhaar-number-unreadable`
(NOT_APPLICABLE).

### The check that made this real rather than theatre

Whether any of this works depends on one thing nobody had tested: can the
extraction pipeline read a twelve-digit number off a photograph at all? A card
rendered at 1012x638 and put through `preprocess` and `read_printed_text` came
back with the grouped number recovered exactly, digit for digit. Unlike the
machine-readable strip, a printed Aadhaar number is large, well separated and not
set in OCR-B, so it reads cleanly.

**Exit criteria.** An invented number is rejected with an officer-facing reason;
a well-formed one passes without claiming the card is genuine; nothing the
detector reads reaches the evidence in the clear; and a document not declared as
an Aadhaar card is never judged by this rule.


---

## Phase 16 slice C — a card that can actually be cleared

Slice A gave a red verdict on an invented number. This is the green one: a
specimen card an issuing authority signed, and a Rung 0 detector that checks it,
so the path from a photograph to a cryptographic clearance exists rather than
being described.

- `detectors/rung0_crypto/signed_qr.py`, Rung 0, assembled into every screening.
- `datagen/signed_card.py`, a specimen for the same fictional state the rest of
  `datagen` issues for.
- Golden cases `signed-qr-valid`, `signed-qr-tampered`, `signed-qr-unknown-issuer`.
- `segno` added: a pure-Python QR encoder with no transitive dependencies. None
  of the things CLAUDE.md forbids without an ADR.

**This is not the Aadhaar Secure QR format**, and does not pretend to be. That
detector is still a stub and stays one until a real specimen exists to check a
parser against. What this reads is a container defined by this project, for an
issuer that adopts it. The cryptography is genuine — a real ECDSA signature over
exact bytes, checked through the same `verification.py` every Rung 0 detector
uses — but a format we define and then parse is, in that narrow sense, code
agreeing with itself. The value is the surrounding machinery, which is format
independent: anchors, validity windows, algorithm allowlists, the ladder.

Verified end to end from a rendered card, not asserted:

| | |
|---|---|
| genuine card, anchor installed | `CLEARED` |
| genuine card, no anchor | `MANUAL_REVIEW` |
| card edited after signing | `REJECTED` |
| anchor that forbids the algorithm | `MANUAL_REVIEW` |

### Three things this slice found

**A golden case can be silently skipped.** `test_the_detector_reproduces_the_golden`
skips when a detector is absent from the `BUILDERS` map, which is how a case
stays pending before its detector exists. Slice A's Aadhaar cases were reported
as passing when only their digest and legality checks had run; the exact-Evidence
comparison had never executed. Both detectors are now registered and the corpus
runs with **no skips at all**.

**ECDSA rather than RSA, because of the camera.** An RSA-2048 signature is 256
bytes, which pushes the container past 660 characters and the QR to version 20 —
105 modules that must fit on a card. The first version pasted a 630px symbol onto
a 638px card at a negative offset, where it was clipped, decoded to nothing, and
made every card come back unread. A P-256 signature is about 70 bytes, so the
same card carries a version 13 symbol with wider modules. The scale is now
computed from the symbol rather than assumed.

**The tamper detector is sensitive to how evenly a document is printed.** The
first card saturated `tamper_classical` at 1.0 and was escalated. It was not the
QR — removing it changed nothing — and it was not a shortage of textured blocks;
the card had proportionally more than the evaluation corpus. The signal is error
level *localisation*, the ratio of the worst blocks to the typical one, and a
document mixing large flat areas with sharp graphics has an uneven ratio without
having been tampered with at all: 3.11 against the corpus's 1.75, and the score
saturates above 3.0.

Giving the card the guilloche and microprint a real identity document carries
brought it to 0.137, below the corpus itself. So the sparse first draft was the
unrealistic thing rather than the detector being broken.

**The limitation is real and is recorded here rather than closed.** Every
specimen in `datagen` is uniformly printed, so `eval/reports/` has never measured
a document with large flat areas or mixed content — and its "0% false escalation
on genuine documents" is narrower than it sounds. A genuine document that is
sparsely printed would be escalated. Covering that means new specimens in the
evaluation corpus, which is a change to the data rather than to the detector.


---

## Phase 17 — Face comparison and liveness

Phase 7 built the privacy machinery for biometrics and left both detectors
abstaining, blocked on two things: model weights, and the absence of any face to
compare. The weights now exist. The second blocker has not moved and is not
pretended to have.

- `detectors/rung2_inference/face_engine.py`: loads InsightFace `buffalo_l`
  through ONNX Runtime, once, shared by both detectors.
- `face_match.py`: compares the document portrait with a live capture.
- `pad_liveness.py`: a landmark-motion challenge across frames.
- `tools/face_check.py`: point the models at your own images and see the numbers.

**Both stay on Rung 2, so neither can clear anybody.** That is what makes the
rest of this defensible.

### Two uncalibrated thresholds, said out loud

`face_match.SUSPICION_THRESHOLD` and `pad_liveness.STILLNESS_THRESHOLD` are
placeholders. Calibrating either needs a corpus — of faces for one, of real
presentation attacks for the other — and obtaining one is a question of lawful
basis and consent before it is a question of data. No accuracy figure for either
detector exists anywhere in this repository and rule 2 forbids writing one until
`eval/run_eval.py` produces it on a named dataset.

Shipping an uncalibrated threshold is defensible **only** because of the rung.
The worst a badly chosen number can do here is send more cases to a person. It
cannot clear anybody and it cannot reject anybody. On Rung 0 or Rung 1 the same
choice would be indefensible.

### What the liveness check actually is

Not a trained anti-spoofing model, and it does not claim to be one. It is a
challenge: several frames a moment apart, and the movement of the five facial
landmarks between them, divided by the width of the face so that holding the
camera closer does not read as movement.

**As first shipped it did not defeat a printed photograph, despite what this said — see phase 18. It does not defeat a video
replay**, and the officer wording says so in its own sentence, because somebody
told "the liveness check passed" will otherwise read more into it than it can
carry.

**A single frame reports `INCONCLUSIVE`.** A still image of a still image is
indistinguishable from a still image of a person, so there is nothing to measure
and nothing is claimed.

### Rule 4, inside the detector

An embedding is partially invertible by model inversion. These detectors compute
two, compare them, and drop them: none is written to disk, put into the evidence
or persisted anywhere. `face_engine` has no code path that stores one. Anything
that wanted to keep one would go through `core.privacy.biometrics`, which
encrypts it under a key held separately from the identifier hashing key and
carries a retention window the code enforces.

### What is still not validated

Whether any of this recognises an actual face. There are no faces in this
repository to check it against, by decision rather than by oversight, so the
tests cover contract compliance only — which is what `CLAUDE.md` asks of a Rung
2 detector, and is all that can honestly be claimed. `tools/face_check.py` exists
so that a person can point the models at images they are entitled to use and see
the numbers for themselves.


### First contact with real faces

The face models were run over images supplied by the owner and held outside the
repository: document portraits first, then the owner's own photographs from
several angles. Faces were found in almost all of them, which is the first
evidence in this project that the recogniser works on anything at all — every
test before it covered contract compliance only, because there is deliberately
no face in the corpus.

The check showed that the first `SUSPICION_THRESHOLD`, 0.55, sat so low that
different people read as "consistent with the photograph" — the impostor attack
this detector exists to notice. It was moved to 0.33, where ArcFace recognisers
are conventionally operated. On the owner's own photographs the same person then
read as consistent with themselves across every angle tried, and document
portraits were escalated against them.

**That is not a calibration, and no rate from it is recorded here.** Rule 2
admits only figures `eval/run_eval.py` produces on a named dataset; a one-off
check on one person's photographs is not one. The false-escalation and
missed-impostor rates for this threshold are TBD.

---

## Phase 18 — Liveness that a photograph cannot pass

**Phase 17 shipped a liveness check that a printed photograph defeats**, while
its own documentation said the opposite. Found by testing the claim rather than
trusting it.

The first version measured how far the five facial landmarks moved between
frames. A photograph held in a hand moves every landmark — shake, tilt, drift —
so it read as a face that moved, and passed. Warps of a still photograph
imitating a hand-held print, by shift, rotation, scale and a slight perspective
tilt, all passed it. The only thing it caught was one frame repeated exactly,
which is not an attack anybody would make.

**What it measures now is change of shape, not change of position.** Each pair of
frames is aligned by orthogonal Procrustes — translation, rotation and scale
removed — and what is left is how much the arrangement of eyes, nose and mouth
changed. A flat photograph keeps its arrangement however it is moved; a real head
turning in three dimensions projects to a different one. The same simulated
prints now fall far below the threshold, and the owner's own frames of a turning
head far above it.

- `detectors/rung2_inference/pad_liveness.py`, version 2.0.0. The version bump
  matters: `model_version` is part of what the ledger digests.
- Tests that pin the property rather than examples: moving a face rigidly is not
  movement; a change of shape is, even while the camera shakes; the measure does
  not depend on how close the camera was; a mirror image is not the same face;
  fewer than three landmarks cannot show movement and read as still, which
  escalates.

**What it still does not defeat**, stated in the officer wording: a video replay,
and a photograph *bent* between frames, since bending changes its shape. **It has
not been tried against a real printed photograph filmed by a real camera** —
paper curvature, glare and focus all differ from a warp. That is the next thing
to try, and it takes one printed selfie.

**One consequence for the capture page.** The check needs the head to turn. A
person holding perfectly still is escalated — the safe direction, and a nuisance
at a barrier — so when the capture page takes live frames it must ask the bearer
to turn their head slowly.

**A correction to phase 17's follow-up.** That commit recorded pass and escalate
counts from an ad-hoc local check in `face_match.py` and in this file. Rule 2
admits no figure that `eval/run_eval.py` did not produce on a named dataset, so
they have been removed. The check is described, not quantified.
