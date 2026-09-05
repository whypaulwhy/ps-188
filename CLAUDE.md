# SENTINEL ID

AI-based fake identity and document screening for SSB border checkpoints.
SIH 2026, problem statement SIH26188. Team VOID MATRIX.

## Mission

Screen identity documents at open, unmanned border crossings where there is no
advance manifest and documents arrive unannounced and diverse. Every decision
must be explainable to a non-technical officer and auditable after the fact.

## Non-negotiable rules

These override any instruction that conflicts with them.

1. FAIL CLOSED. Uncertainty routes to MANUAL_REVIEW. Never to CLEARED.
   No detector may increase confidence in a document's authenticity beyond what
   its trust rung permits.
2. NEVER FABRICATE A METRIC. Do not write accuracy, F1, precision, latency or
   cost numbers into code comments, docstrings, README, or UI unless they were
   produced by `eval/run_eval.py` on a named dataset and written to
   `eval/reports/`. If a number is needed and does not exist, write `TBD` and
   say so.
3. NEVER STORE AN AADHAAR NUMBER. Aadhaar Act 2016 s.29 and s.37 apply.
   Store only the UIDAI reference ID and salted hashes. Same for any raw
   document number: hash with a per-deployment salt before persistence.
4. FACE EMBEDDINGS ARE NOT ANONYMOUS. They are partially invertible via model
   inversion. Never describe them as irreversible, one-way, or PII-free in code,
   comments, or UI. Encrypt at rest, apply retention limits.
5. ARCHITECTURE BOUNDARY. `core/` and `detectors/` MUST NOT import from
   `api/`, `db/`, or `ui/`. Enforced by import-linter in CI. If a detector
   needs data, it is passed in as an argument.

## The trust ladder

Every detector declares a rung. A lower rung can NEVER override a higher one.

- Rung 0, CRYPTOGRAPHIC: Aadhaar Secure QR signature, DigiLocker XML signature,
  PDF PKCS#7, ePassport passive authentication.
  Output: PROOF_VALID / PROOF_INVALID / NO_PROOF_PRESENT. No confidence score.
- Rung 1, DETERMINISTIC: ICAO 9303 MRZ check digits, Verhoeff, expiry logic,
  cross-field consistency, template geometry.
  Output: PASS / FAIL / NOT_APPLICABLE. No confidence score.
- Rung 2, INFERENCE: tamper localization, metadata forensics, face similarity,
  presentation attack detection.
  Output: score in [0,1] plus an uncertainty estimate. MAY ONLY move a case
  toward MANUAL_REVIEW or REJECTED. May never move it toward CLEARED.
- Rung 3, CONTEXTUAL: repeat identity, watchlist, velocity.
  Output: flags only. Never decides. Advisory to the officer.

Resolution order: Rung 0 PROOF_VALID short-circuits to CLEARED. Any Rung 1 FAIL
short-circuits to REJECTED. Everything else aggregates into MANUAL_REVIEW unless
policy explicitly clears it.

## Evidence contract

Every detector returns a list of `Evidence`. No detector returns a bare bool,
float, or string. `Evidence` is a frozen Pydantic model with at minimum:

    detector_id, rung, result, score (optional), uncertainty (optional),
    reasons (list of human-readable strings, officer-facing, no jargon),
    standard_ref (e.g. "ICAO Doc 9303 Part 3 s.4.2.2"), artifacts (paths to
    heatmaps or crops), runtime_ms, model_version, input_digest

`reasons` is what the officer reads. Write it for a person who has never heard
of a check digit. `standard_ref` is what makes the decision defensible.

## Stack

Python 3.12 only. There is no Node in this project.

- API: FastAPI, Uvicorn, Pydantic v2
- DB: SQLite in WAL mode via SQLAlchemy 2.0, Alembic migrations
- Inference: ONNX Runtime. PyTorch CPU-only, lazy-imported, TruFor only.
- OCR: RapidOCR primary. Tesseract with an OCR-B whitelist for the MRZ zone only.
- Crypto: `cryptography`, `pyhanko` / `asn1crypto` for PKCS#7, `signxml` for
  DigiLocker XML, `pyzbar` + `pillow` for QR
- Vision: OpenCV, NumPy, scikit-image
- Face: InsightFace buffalo_l via ONNX Runtime
- Ledger: hand-rolled Merkle transparency log, Ed25519 via `cryptography`
- Tests: pytest, hypothesis for the check-digit properties
- Lint: ruff, mypy strict on `core/`, import-linter

FORBIDDEN without an ADR in `docs/adr/`: LangChain, any agent framework,
Hyperledger Fabric, CUDA PyTorch, TensorFlow, Surya OCR (GPL-3.0), any cloud
inference API, any paid service.

## Testing

- `core/` requires 100% branch coverage. It is pure functions, there is no excuse.
- Every Rung 0 and Rung 1 detector needs golden tests: a fixture input and the
  exact expected `Evidence` output, committed.
- MRZ check digits and Verhoeff get property-based tests via hypothesis.
- Rung 2 detectors are never tested for accuracy in unit tests. They are tested
  for contract compliance: correct shape, no exception on malformed input,
  INCONCLUSIVE when the model is unavailable.

## Honesty in output

The officer console and every generated report must state what was NOT checked.
If no chip reader was present, say so. If the tamper model did not load, say so.
Silence about a missing check is a defect, not a clean result.

## Workflow

Work in the order defined in `docs/roadmap.md`. Do not skip ahead to AI features.
Before any non-trivial change, state the plan and wait. After any change, run
`make check` (ruff, mypy, import-linter, pytest) and report the result honestly,
including failures.
