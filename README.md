# SENTINEL ID

AI-assisted identity document screening for SSB border checkpoints.
SIH 2026, problem statement SIH26188. Team VOID MATRIX.

---

## What this is

The SSB guards the India–Nepal and India–Bhutan borders. The India–Nepal border
is open: under the 1950 Treaty of Peace and Friendship, Nepali nationals cross
without a passport or visa, presenting a citizenship certificate, a voter card,
or whatever identity document they carry. There is no advance manifest, traffic
is heavy and local, and the document mix is far wider than at an airport.

SENTINEL ID screens what is presented and hands an officer **evidence they can
act on and defend afterwards** — what was checked, what was found, what could
not be checked, and which published rule each conclusion rests on.

It does not replace the officer. On these borders it mostly cannot: see below.

## The one thing to understand first

Most documents crossing these borders carry **nothing a machine can verify**. A
Nepali citizenship certificate has no machine-readable strip, no barcode and no
digital signature. Neither does a Bhutanese citizenship card.

So the system is built around a **trust ladder** in which the safe answer is the
default:

| Rung | What it is | Can it clear a document? | Can it reject one? |
|---|---|---|---|
| 0 · Cryptographic | An issuer's signature, verified against a pinned key | **Yes** | Yes |
| 1 · Deterministic | Arithmetic and rules from a published standard | No | Yes |
| 2 · Inference | A learned model's score | **Never** | **Never** |
| 3 · Contextual | History, watchlists | No | No |

Three outcomes exist: `CLEARED`, `MANUAL_REVIEW`, `REJECTED`. Anything not
positively established goes to a human, and on these borders that will be the
common case by a wide margin. **The value here is triage and evidence, not
clearance.**

Two properties are enforced structurally rather than by review:

- **Inference can never clear a document.** A Rung 2 detector has no vocabulary
  for asserting authenticity — its score is *suspicion*, where a larger number
  can only make a case worse — and `Verdict` refuses to construct a clearance
  without an affirmative Rung 0 or Rung 1 result behind it.
- **Adding inference or context never softens a decision.** Stated as a property
  and tested over arbitrary evidence sets, not with a handful of examples.

Full reasoning: [`docs/trust-ladder.md`](docs/trust-ladder.md).

## What it does not do

Ten numbered points, in [`docs/scope.md`](docs/scope.md). The short version:

- It does not establish who a person is.
- It does not clear anyone without cryptographic proof of issuance.
- It does not read passport chips — there is no reader.
- It does not check anything against an issuer's database. No network, no cloud.
- It does not certify a Nepali or Bhutanese document as genuine, because there
  is nothing in one for a machine to verify. "Nothing was found wrong" is not
  the same sentence as "this is genuine", and the console must never render it
  as though it were.
- **It has no measured real-world accuracy.** `eval/run_eval.py` has now run,
  and its report is in [`eval/reports/`](eval/reports/) -- but every number in
  it describes synthetic documents this repository generated, in a font that is
  not OCR-B. Nothing here has ever seen a real document. Any figure quoted about
  this system's real-world performance is invented, whoever quotes it. That is
  rule 2 of [`CLAUDE.md`](CLAUDE.md).

## Status

Built in phases, in the order set by [`docs/roadmap.md`](docs/roadmap.md).

| Phase | | |
|---|---|---|
| 0 | Skeleton and contracts | ✅ |
| 1 | Scope, threat model, golden fixtures | ✅ |
| 2 | Standards library and the extraction contract | ✅ |
| 3 | Privacy: hashing, masking, retention | ✅ |
| 4 | Rung 0, cryptographic verification | ◐ partial |
| 5 | Rung 1, deterministic detectors | ◐ partial |
| 6 | Synthetic data, extraction, evaluation, tamper detection | ✅ |
| 7 | Rung 2, biometrics | ◐ partial |
| 8 | Rung 3, contextual advisories | ✅ |
| 9 | Ledger, database, officer report | ◐ partial |

**Working today:** the trust ladder and evidence contract; ICAO 9303 TD3 parsing
and check-digit arithmetic; Verhoeff; two-digit-year century recovery; keyed
identifier hashing, masking and retention; DigiLocker XML signature and signed
PDF verification; MRZ check-digit, expiry and strip-versus-page detectors;
synthetic specimen and forgery generation; extraction, so a photograph produces
a verdict end to end; four Rung 2 tamper detectors; Rung 3 repeat-crossing and
watchlist advisories that provably cannot change a decision; encrypted-at-rest
face embeddings with a retention window enforced in code; an evaluation
harness that has run and produced a committed report; and an audit trail --
a Merkle transparency log with signed checkpoints, a guarded SQLite store, and
an officer report that states what was not checked on every case.

**Known gaps, deliberately:**

- **Aadhaar Secure QR is not implemented.** The cryptography is ordinary RSA and
  already exists; the container layout does not, and there is no specimen to
  check a parser against. Writing a guess behind the only rung that can clear a
  document fails silently in the worst direction. One of only two document types
  that can reach `CLEARED` therefore does not work yet. This is the single
  highest-value thing to unblock.
- **The machine-readable strip does not read reliably.** Tesseract is installed
  and wired in, and reads the first strip line at 98% character agreement. It
  needs OCR-B training data, which the stock install does not ship, before the
  second line reads dependably. Until then the reader refuses to vouch for a
  strip it cannot read cleanly, and the case goes to a human saying so — rather
  than guessing and failing a genuine document.
- **No chip reading.** Blocked on hardware, and every case says so rather than
  omitting the check.
- **No API and no console yet.** The audit trail underneath them is built and
  tested: a case is screened, stored, replayed and proved. What is missing is
  the shell around it -- HTTP routes, the officer screen, and Alembic
  migrations. `create_all` is a test convenience, not a deployment path. See
  phase 9 slice B in [`docs/roadmap.md`](docs/roadmap.md).
- **No face matching.** The storage side is done — embeddings are encrypted at
  rest under their own key, with a retention window the code enforces and a test
  that fails if any file calls an embedding anonymous. The matching side has no
  model weights and, more importantly, no lawfully obtained face corpus to
  validate against. Both detectors abstain and say why.

## Running it

Python 3.12 only, managed by [uv](https://docs.astral.sh/uv/). There is no Node
in this project.

```bash
uv sync
make check
```

A fresh machine needs `make` and Tesseract as well; see
[`docs/getting-started.md`](docs/getting-started.md), which also lists what is
waiting on a decision, a specimen or a piece of hardware rather than on code.

`make check` is the gate: ruff, `mypy --strict` over `core/`, import-linter, and
pytest. `core/` is held at 100% branch coverage — it is pure functions, so there
is no excuse. CI runs the same command on every push.

## Layout

```
core/          pure decision logic — no I/O, no framework, no models
  contracts/     Evidence, Finding, Verdict, Provenance, Subject
  standards/     ICAO 9303, Verhoeff, date rules
  trust/         the ladder
  privacy/       hashing, masking, retention
detectors/     every check, grouped by rung; each returns Evidence
extraction/    capture to text and codes (phase 6)
ledger/        append-only Merkle audit trail, signed checkpoints
db/            SQLite in WAL mode, guarded against storing a raw number
explain/       the officer-facing report
api/ ui/       the outward-facing shell (phase 9 slice B)
datagen/       synthetic specimens and forgeries (phase 6)
eval/          the only sanctioned source of performance numbers
tests/         unit, golden fixtures, integration
docs/          scope, threat model, trust ladder, ADRs
```

`core/` and `detectors/` may not import `api/`, `db/` or `ui/`. This is checked
by import-linter in CI, not left to review.

## Documentation

| | |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | The project's non-negotiable rules. Read first. |
| [`docs/getting-started.md`](docs/getting-started.md) | Setting up, and what is blocked on a human rather than on code. |
| [`docs/scope.md`](docs/scope.md) | What is accepted, what is refused, what the system does not do. |
| [`docs/trust-ladder.md`](docs/trust-ladder.md) | How evidence resolves into one decision. |
| [`docs/evidence-contract.md`](docs/evidence-contract.md) | What every detector returns, and why each field exists. |
| [`docs/threat-model.md`](docs/threat-model.md) | Attacks per document type, and the cost of a false rejection. |
| [`docs/evaluation-protocol.md`](docs/evaluation-protocol.md) | How performance will be measured, once it is. |
| [`docs/roadmap.md`](docs/roadmap.md) | The build order and why it is that order. |
| [`docs/adr/`](docs/adr/) | One record per decision that would be expensive to reverse. |

## A note on the fixtures

Every committed fixture is synthetic or a published specimen, carries a licence
and provenance line, and is pinned by digest. No real person's document is in
this repository, and no private key: the phase-4 signature fixtures were signed
once with ephemeral keys that were not retained. A test scans the whole tree on
every run and fails if any file contains a number with the shape of an issuable
Aadhaar number.
