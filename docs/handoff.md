# Handoff — continuing SENTINEL ID

This file is written to be **pasted or pointed at as the first prompt of a new
session**. It records what exists, what is deliberately absent and why, and what
is left, so that none of it has to be rediscovered or rebuilt.

**To start a session:** open the project at `D:\ps 188` and say

> Read `CLAUDE.md` fully, then read `docs/handoff.md`, then `docs/roadmap.md`.
> Confirm the working tree is clean and `make check` passes. Then propose what
> to do next from the "What is left" section and wait for me to pick.

Keep this file updated at the end of each session, the same way the roadmap is.

---

## 1. The project, in one paragraph

**SENTINEL ID** — AI-assisted fake identity and document screening for SSB
border checkpoints. SIH 2026, problem statement **SIH26188**, team **VOID
MATRIX**. Owner: Prit (GitHub `whypaulwhy`). Repository:
`https://github.com/whypaulwhy/ps-188` (branch `main`, push after every phase).
Teammate Nausin has been running clean checkouts to verify the setup path.

It screens identity documents where there is no advance manifest, and every
decision has to be explainable to a non-technical officer and auditable years
later.

## 2. The rules that govern everything

`CLAUDE.md` at the repository root is the contract and **outranks any prompt**.
Read it in full before touching anything. Its five non-negotiable rules, in
short — the file has the exact wording, which must not be paraphrased in code:

1. **Fail closed.** Uncertainty routes to `MANUAL_REVIEW`, never `CLEARED`.
2. **Never fabricate a metric.** No accuracy, F1, precision, latency or cost
   number anywhere unless `eval/run_eval.py` produced it on a named dataset and
   wrote it to `eval/reports/`. Otherwise write `TBD` and say so.
3. **Never store an Aadhaar number.** Aadhaar Act 2016 s.29 and s.37. Digests
   only, under a per-deployment key.
4. **Face embeddings are not anonymous.** Never described as irreversible,
   one-way or PII-free. Encrypted at rest, retention limited.
5. **Architecture boundary.** `core/` and `detectors/` must not import `api/`,
   `db/` or `ui/`. Enforced by import-linter.

Also mandated by `CLAUDE.md`: Python 3.12 only, no Node; `core/` at 100% branch
coverage; golden tests for every Rung 0 and Rung 1 detector; hypothesis property
tests for MRZ check digits and Verhoeff; Rung 2 detectors tested for contract
compliance only, never accuracy; the officer console and every report must state
what was **not** checked; work in `docs/roadmap.md` order; state the plan before
a non-trivial change; run `make check` after any change and report the result
honestly, failures included.

## 3. Where the work stands

**Phases 0 through 9 are complete or explicitly partial.** Last commits:

```
340004a Add a handoff document, and stop the repo scan reading a tool cache
7c67f6c Phase 9 slice B: the shell, and the things it refuses to do
22698f1 Phase 9 slice A: the audit trail, and the report that says what was missed
f236c3b Fix tests that assumed an optional backend was always installed
1775cfb Phase 8: Rung 3 contextual advisories
```

Gate as of the handoff commit — re-run it, do not trust these numbers if anything has
changed since:

```
ruff             All checks passed
mypy --strict    no issues in 26 source files (core/ only, per CLAUDE.md)
import-linter    5 contracts kept, 0 broken
pytest           1456 passed
coverage         core/ 100.00% branch  (gate fails below 100)
```

These are counts of tests and files, **not** performance metrics. The only
performance figures that exist anywhere are in
`eval/reports/synthetic-utopia-v1-2026-09-06.md`, and they describe **synthetic
documents this repository generated, in a font that is not OCR-B**. Nothing in
this project has ever seen a real document. Any real-world accuracy figure is
invented, whoever quotes it.

## 4. The tree, and what each part is for

```
CLAUDE.md            the contract; outranks any prompt
Makefile             `make check` = ruff, mypy --strict core, lint-imports, pytest
alembic.ini          migration config; deliberately names NO database
pyproject.toml       deps, ruff/pytest/coverage config
setup.cfg            import-linter contracts (5 of them)
.github/workflows/ci.yml   runs `make check` on push and PR

core/                pure decision logic. No I/O, no framework, no models.
  contracts/         enums, evidence, finding, provenance, subject, verdict, review
  standards/         errors, verhoeff, date_rules, mrz/{check_digits,parse}
  trust/             ladder (resolve), policy tables, aggregation (STUB)
  privacy/           identifiers, hashing, masking, retention, biometrics
detectors/           every check, grouped by rung; each returns Evidence
  base.py            Detector ABC + @register registry
  rung0_crypto/      trust_store, verification, digilocker_xml_sig, pdf_pkcs7,
                     aadhaar_secure_qr (STUB), epassport_sod (STUB)
  rung1_deterministic/  mrz_checkdigits, expiry, field_crossmatch,
                     template_geometry (STUB)
  rung2_inference/   tamper_classical, metadata_forensics, pdf_structure,
                     tamper_trufor (abstains, no weights),
                     face_match (abstains), pad_liveness (abstains)
  rung3_context/     context_store, _identify, repeat_identity, watchlist
extraction/          preprocess, mrz_locate, ocr_adapter, qr_decode, pipeline
datagen/             synthetic_docs + forgeries/ (5 types, each declares `alters`)
eval/                protocol, metrics, run_eval; reports/ holds the only real numbers
ledger/              hashchain (Merkle + Ed25519), interface (what gets logged),
                     fabric_adapter (STUB, points at ADR 0003)
db/                  models, session (WAL), guards (rule 3 at the disk edge),
                     recording (atomic case + leaf), migrations/ (Alembic chain)
explain/             renderer (the officer report), llm_client (STUB, optional)
api/                 settings, screening (the detector runner), schemas, deps,
                     routes, app (create_app factory — no module-level app)
ui/                  console.py + templates/{base,queue,case,missing}.html
deploy/              Dockerfile (runs the gate at build), compose.yaml
docs/                roadmap, scope, threat-model, trust-ladder, evidence-contract,
                     evaluation-protocol, getting-started, handoff (this file),
                     adr/0001–0007
tests/               unit/ (26 files), integration/ (4), golden/ (16 cases,
                     anchors, vectors)
```

## 5. Things already decided — do not re-litigate

Each of these cost real work to get right. The ADRs hold the full reasoning.

| Decision | Where |
|---|---|
| Python only, no Node | ADR 0001 |
| ONNX Runtime over PyTorch | ADR 0002 |
| Hand-rolled Merkle log, **not** Hyperledger Fabric | ADR 0003 |
| The extraction contract lives in `core/` | ADR 0004 |
| **Keyed** HMAC hashing, not salted, for document numbers | ADR 0005 |
| The ledger stores a **digest** of a verdict, not the verdict | ADR 0006 |
| An officer's decision is **appended**, never an edit of the verdict | ADR 0007 |

Further decisions recorded in code and in `docs/roadmap.md`:

- **Escalation runs before proof** in `core/trust/ladder.py` — a deliberate,
  documented deviation from `CLAUDE.md`'s literal resolution order, justified by
  rule 1. Do not "fix" it without reading the note in that module.
- **Rung 3 gained `NOT_CHECKED`** in phase 8, mapped into the ladder's `SILENT`
  set, because `NO_FLAG` would have read as "checked, nothing found".
- **The MRZ reader refuses rather than repairs.** `well_formed_strip()` returns
  nothing rather than guessing a character.
- **`DENSITY_THRESHOLD = 0.12`** in `extraction/mrz_locate.py` was calibrated
  from measured data (strip rows 0.15–0.26, printed rows 0.05). Do not tune it
  by feel.
- **`TEXTURE_FLOOR = 8.0`** in `tamper_classical.py` exists because the first
  version escalated 100% of genuine documents — it normalised against the median
  block variance of the whole image, which is ≈0 for blank paper.
- **`separation()` in `eval/metrics.py` returns a per-class dict**, because
  pooling forgery types reported +0.03 for a detector that separated one attack
  by +0.32.
- **`db.models.UtcDateTime`** exists because SQLite drops the timezone: a log
  rebuilt from storage computed a different Merkle root. Never store a naive
  timestamp.
- **Keys are files, not environment variables** (`SENTINELID_HASH_KEY_FILE`,
  `SENTINELID_LEDGER_KEY_FILE`) — env vars are visible in `/proc` and
  `docker inspect`.
- **No module-level `app`** in `api/app.py`; uvicorn uses
  `api.app:create_app --factory`. Building one at import time would make a
  missing key look like a broken import.

### Enforcement by test, not by review

These tests exist to make a rule mechanical. Do not weaken them:

- `tests/unit/test_no_raw_identifiers.py` — scans every committed text file for
  an issuable-shaped Aadhaar number, checks only `core.privacy.hashing` calls
  `reveal()`, checks no contract field can hold a `RawIdentifier`. **A test must
  never hardcode an issuable Aadhaar number** — compute one at runtime with
  `verhoeff_digit`, or this scan will (correctly) fail.
- `tests/unit/test_persistence.py` — the phase-3 criterion against a real
  database. Half of it is about what the guard must *allow*.
- `tests/unit/test_module_tree.py` — every module imports; every stub raises
  `NotImplementedError`. **Add new implemented modules to its `IMPLEMENTED`
  set** or it will fail.
- `tests/unit/test_migrations.py` — Alembic's own comparison against the models.
  Add a column to `db/models.py` without a migration and this fails.
- `tests/integration/test_api.py::test_every_registered_detector_is_assembled` —
  a detector that exists but is never built produces no evidence at all.
- The rule-4 scan (no file calls an embedding anonymous) and the jargon ban on
  `reasons`.

The scan is parametrised per file, so **the total test count changes when files
are added**. It excludes tool caches; it did not until commit `HANDOFF`, and the
suite was quietly growing by a few tests every time `make check` ran.

## 6. What is left

Ordered by value. Nothing here is half-built; each is either blocked on
something outside the repository or is genuinely new work.

### 6.1 Blocked on a human, not on code

These are listed in full in `docs/getting-started.md` §5. They cannot be coded
around and should not be guessed at.

1. **An Aadhaar Secure QR specimen and the UIDAI certificate.** Blocks
   `detectors/rung0_crypto/aadhaar_secure_qr.py`, which is one of only **two**
   document types that can ever reach `CLEARED`. The cryptography already
   exists in `verification.py`; the container byte layout does not. A wrong
   field boundary produces a detector that verifies the wrong bytes and reports
   `PROOF_VALID` on documents it never checked — silent, in the worst direction,
   behind the only rung that can clear a document. The module docstring lists
   the four things needed.
2. **Chip reader hardware.** Blocks `epassport_sod.py`; would move three
   passport rows in `scope.md` from Rung 1 to Rung 0.
3. **Confirmed document formats** for Bhutanese CID and Nepali citizenship. The
   phase-1 fixtures for these are structurally plausible placeholders, not
   verified transcriptions, and say so.
4. **A lawfully obtained face corpus** and model weights. Blocks face matching
   and presentation attack detection; both detectors abstain honestly today.
5. **TruFor weights.** No public checkpoint. The detector reports
   `INCONCLUSIVE`, which is what `CLAUDE.md` asks of an unavailable model.
6. **Deployment decisions**: retention windows, where the hashing key lives, and
   whether the review volume is operationally acceptable.

### 6.2 Buildable now — code work that is not blocked

**a. `detectors/rung1_deterministic/template_geometry.py`** (phase 5 leftover).
Rung 1, so it needs golden tests and a `standard_ref`. The hard question is what
a "template" means for documents whose exact format is unconfirmed (6.1.3) —
likely scoped to the ICAO TD3 zone geometry only, where the standard is known.
Decide the scope before writing it, and be willing to leave it unimplemented
with a documented reason, as several other modules already are.

**b. Retention enforcement.** `core/privacy/retention.py` decides what may be
kept; nothing runs on a schedule to delete anything, so a deployment currently
keeps everything. Needs a job that walks `case_record` by `created_at`, applies
the policy, deletes, and **records that a deletion happened** — a deleted case
whose ledger entry remains is the intended state (ADR 0006), and the officer
console should say "this case's record has been destroyed under retention"
rather than 404.

**c. Checkpoint publication.** The system signs checkpoints on request; nothing
carries them off the box. ADR 0003 is explicit that an unpublished checkpoint
proves nothing. The minimum viable version is a command that writes the signed
checkpoint to a file for manual transfer, plus a documented verification script
a third party can run. Do not add a cloud service — `CLAUDE.md` forbids it.

**d. Authentication.** The console trusts the officer identifier typed into it
and the API is unauthenticated; `deploy/compose.yaml` binds to localhost because
of it. This needs a deployment answer first (6.1.6) — inventing one produces
attributable-looking records that attribute nothing.

**e. `core/trust/aggregation.py`** is still a stub. Check whether it is wanted at
all: `ladder.resolve()` does the aggregation today, and an unused module that
raises is honest but may simply be dead. Deleting it is a legitimate outcome.

**f. `explain/llm_client.py`** — optional, off by default, rephrases text the
renderer has already produced and decides nothing. Low value; only worth doing
if an officer asks for it in a language the templates do not cover.

### 6.3 Competition work (SIH 2026), not yet started

None of this exists yet and none of it is in `docs/roadmap.md`. Ask before
starting — it is a different kind of work from the above:

- a demo script and seeded demo data that shows the trust ladder refusing to
  clear, an officer override being recorded, and a third party verifying the
  ledger;
- a presentation or written submission. **Rule 2 applies to slides.** The only
  quotable numbers are in `eval/reports/`, and they are synthetic.

## 7. Environment and tooling — the traps

The development machine is Windows 11, PowerShell primary, Bash tool available.

- **`make` is not on this session's PATH.** It is installed at
  `C:\Users\user\AppData\Local\Microsoft\WinGet\Packages\ezwinports.make_Microsoft.Winget.Source_8wekyb3d8bbwe\bin`.
  Prepend that to `PATH` in the Bash tool, or run the four steps by hand.
- **PowerShell has no `&&`.** Use `;` or `if ($?) { }`. Commands given to the
  user in a `bash` fence will fail if pasted into PowerShell.
- **Bash heredocs mangle escapes** (`\t` in `\tesseract.exe`, `\s`, `\d`) and
  break on apostrophes. Use the Write tool for Python files, or write a script
  to the scratchpad and run it. This has bitten repeatedly.
- **ruff RUF100** flags `noqa` codes for rules that are not enabled (BLE001,
  PLC0415, DTZ001, S320 …). Use a plain comment instead.
- **FastAPI's `Depends`/`File`/`Form` in argument defaults** are declared
  immutable in `pyproject.toml` under `[tool.ruff.lint.flake8-bugbear]`, so B008
  stays on for real cases.
- **Tesseract 5.4** is installed at `C:\Program Files\Tesseract-OCR\` and is
  **not on PATH**; `extraction/ocr_adapter.py` does a three-tier lookup. It has
  no OCR-B training data, so the second MRZ line does not read reliably; the
  reader refuses rather than guessing.
- **pyzbar needs the MSVC runtime** (`winget install --id
  Microsoft.VCRedist.2015+.x64 -e`). Without it no code decodes anywhere on that
  machine. Tests are gated on `extraction.qr_decode.decoder_available()`.
- **Do not write a test that assumes an optional backend is installed.** That is
  exactly what broke on Nausin's clean checkout (commit `f236c3b`).

## 8. Standing instructions from the owner

- **Push to GitHub at the end of every phase.** The repository is how teammates
  see progress and it must not have to be redone later.
- **Run `make check` after any change** and report the result honestly,
  including failures, including partial output.
- **State the plan before non-trivial work.**
- **No placeholder metrics anywhere.**
- When asked what to install or do manually, give complete step-by-step detail
  and assume nothing has been done yet.

## 9. Suggested first move next session

Verify, then choose:

```bash
git -C "D:/ps 188" status --short && git -C "D:/ps 188" log --oneline -3
```

```bash
cd "D:/ps 188" && uv run ruff check . && uv run mypy --strict core && uv run lint-imports && uv run pytest -q
```

Then pick from §6.2 — **retention enforcement (b)** is the strongest candidate:
it is unblocked, it closes a real privacy gap that is currently "decided but not
enforced", it touches code that already exists rather than inventing a subsystem,
and it has a clean, testable exit criterion. **Checkpoint publication (c)** is
the next best, and is small.

---

*Last updated at commit `340004a`. If the log above does not match `git log`,
this file is stale — trust the repository, then fix this file.*
