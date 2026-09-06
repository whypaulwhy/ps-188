# ADR 0006 — The ledger stores a digest of a verdict, not the verdict

- **Status:** Accepted
- **Date:** 2026-09-07
- **Supersedes:** —
- **Superseded by:** —
- **Refines:** [ADR 0003](0003-transparency-log-over-fabric.md)

> **Note on authorship.** Written from the constraints fixed in CLAUDE.md
> rather than from a recorded discussion. Correct it if the reasoning that
> actually drove the decision differs.

## Context

Two requirements land on the same records and pull in opposite directions.

**The ledger must be append-only.** ADR 0003 accepted a Merkle transparency log
precisely so that a decision recorded on a date can be shown not to have changed
since. Deleting a leaf destroys the chain for every entry after it, so a log
that permits deletion is not a log.

**Case records must be destroyed on schedule.** `core/privacy/retention.py`
refuses to construct without an explicit window for every artefact category, and
a verdict contains a great deal about a specific person at a specific border on
a specific day. Rule 4 of CLAUDE.md applies to embeddings; the same reasoning
applies to the whole record.

A log holding verdicts cannot honour both. Either retention is unenforceable
because the verdicts survive in the log, or the log is not append-only because
retention reaches into it. Neither is acceptable, and the failure mode of not
deciding is the worse of the two: a retention policy that quietly does not apply
to the one store that keeps everything forever.

## Decision

**A ledger entry holds a digest of the verdict, the case identifier and a
timestamp. It does not hold the verdict.** The verdict lives in the case record
in `db/`, under the retention window that applies to case records.

Concretely, in `ledger/interface.py`:

- `canonical_verdict_bytes` serialises a verdict with sorted keys, so two
  faithful runs of one case produce identical bytes;
- `runtime_ms` is stripped before digesting, because it differs on every run and
  is not part of the decision. Committing to it would mean an honest replay
  never matched its own log entry;
- `model_version` is **not** stripped. A different model is a different basis
  for the decision, and the log should say so;
- `TransparencyLog.matches` is the replay check: re-run a case, digest the
  result, compare against what was logged.

## Consequences

**Accepted:**

- **After retention destroys a case record, the log proves that a decision was
  made at a time and has not been altered — but not what it said.** This is a
  real limit on "a decision can be replayed from the ledger", and it is stated
  in the module docstring, in `docs/roadmap.md` and here rather than left for
  someone to discover during an audit.
- Two stores must be written together for a case to be fully auditable. If the
  case record write succeeds and the ledger write fails, the audit trail has a
  hole in it. `tests/integration/test_audit_trail.py` asserts both rows exist;
  making the pair atomic is API work in the next slice.
- Replay depends on the pipeline being deterministic. Anything non-deterministic
  that reaches a verdict — a model with a random seed, a clock read inside a
  detector — breaks the match, and the failure will look like tampering. Every
  detector is a pure function over its `Subject` for this reason.

**Gained:**

- The log is genuinely append-only. Nothing ever has to be deleted from it.
- Retention is enforceable without qualification.
- The log stays small: three short fields per case, whatever the verdict weighs.
- The tamper that matters is still caught. Editing a stored verdict — including
  quietly dropping a line that says what was *not* checked, which changes no
  decision and makes a case look cleaner — no longer matches the logged digest.
  That case is tested directly.

## Alternatives considered

**Store the whole verdict in the log.** Replay becomes trivial and survives
retention. Rejected: it makes retention unenforceable, and an append-only store
of full screening records is exactly the thing the privacy rules exist to
prevent.

**Store the verdict encrypted in the log, and destroy the key at the end of the
retention window.** Crypto-shredding. Genuinely appealing, and it would preserve
replay for the full window without a second store. Rejected for now because it
moves the retention guarantee onto key management at a checkpoint that,
per `docs/getting-started.md` §5.5, has not yet demonstrated it can hold one
secret outside its own database. Worth revisiting once that question is settled.

**Two logs, one short-lived and one permanent.** Rejected as strictly more
machinery for the same guarantee, and a second log is a second thing that can
be forgotten during an incident.

## Revisit when

- **The key-custody question in `getting-started.md` §5.5 is answered.** If a
  deployment can hold a key outside the database, crypto-shredding becomes the
  better design and this ADR should be superseded rather than amended.
- **A regulator requires the full record to be retrievable for longer than the
  retention window allows it to be kept.** That is a conflict between two
  external requirements, and it must be resolved by whoever owns them, not by
  quietly extending the window.
