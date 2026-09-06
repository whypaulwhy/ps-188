# ADR 0007 — An officer's decision is appended, never an edit

- **Status:** Accepted
- **Date:** 2026-09-07
- **Supersedes:** —
- **Superseded by:** —
- **Related:** [ADR 0003](0003-transparency-log-over-fabric.md),
  [ADR 0006](0006-the-ledger-stores-a-digest.md)

> **Note on authorship.** Written from the constraints fixed in CLAUDE.md
> rather than from a recorded discussion. Correct it if the reasoning that
> actually drove the decision differs.

## Context

Most cases resolve to `MANUAL_REVIEW`, which is the system working as designed:
`scope.md` says only two document types can ever be cleared cryptographically,
and rule 1 sends everything else to a person. So the officer's decision is not
an edge case in this system. It is the normal outcome, and it needs somewhere
to live.

The obvious implementation is to update the case: set `decision = CLEARED` and
move on. It is one column, and every queue-and-approve system in the world does
it. Here it breaks three things at once.

**It makes the verdict lie.** `Verdict.decision` means "what the automated
checks established". Overwriting it with `CLEARED` would have the record claim
the system verified something it did not — and the structural guard in
`core/contracts/verdict.py`, which refuses a clearance without a Rung 0 or
Rung 1 affirmative result, would be bypassed by an `UPDATE` statement.

**It edits an audited record.** The transparency log holds a digest of the
verdict. Change the verdict and the digest stops matching, which is exactly the
signal the log exists to raise. The system would be generating its own tamper
alarms as a matter of routine, and staff would learn to ignore them.

**It loses the sequence.** A supervisor revisiting a call is a second decision,
not a correction of the first. Overwriting keeps only the latest, and "who
decided what, and when" is the first question at an inquiry.

## Decision

**An officer review is a separate record and a separate ledger entry.**

- `core.contracts.review.OfficerReview` is a frozen contract carrying the
  outcome, the officer, a required note, **and the system's decision at the
  time**, so an override is visible as one without a join.
- `db.models.ReviewRecord` stores it. `CaseRecord` is never updated.
- `ledger.interface.TransparencyLog.record_review` appends its digest after the
  verdict's entry, so the log holds the sequence of what happened to a case.
- `CaseView.standing_decision` computes what the case currently amounts to: the
  latest review, or the system's verdict if there is none. It is computed rather
  than stored, because a stored copy is a second source of truth and the two
  eventually disagree.

**An officer may reach any conclusion the system did not**, including clearing a
document that failed a check digit. The alternative is not that the override
stops happening; it is that it happens on paper, where nothing is recorded.
What the contract insists on is that it be attributable and explained: a named
officer and a note, both required, neither blank.

**`MANUAL_REVIEW` is not an available outcome.** It is the state the case is
already in, and allowing it would let a queue be emptied without anything being
decided.

## Consequences

**Accepted:**

- Two places to look to know a case's current state. The `CaseView` property
  exists so no caller has to reconstruct the rule, and the console and API both
  go through it.
- The ledger grows faster: a reviewed case is two entries, not one.
- An officer's free-text note is stored, and free text is where a document
  number ends up. The `db.guards` check applies to it like any other column; the
  API and console both turn that refusal into advice about what to remove
  rather than editing the note silently.

**Gained:**

- The verdict keeps meaning one thing, permanently.
- Overrides are countable. "How often do officers clear what the system would
  not, and at which crossing" is a query, and it is the number that says whether
  this system is calibrated or is being worked around.
- Nothing routine trips the tamper detection, so an alarm from it still means
  something.

## Alternatives considered

**Update the case and keep an audit table alongside.** The common pattern.
Rejected because the two records can diverge — an audit row written after a
failed update, or an update with no audit row — and the divergence is silent.
Here there is one write path and the ledger entry is in the same transaction.

**Store `standing_decision` on the case as a denormalised column.** Faster
queue queries. Rejected for now: it is a second source of truth for the one
value people will act on, and the queue is a few hundred rows at a checkpoint.
Revisit if a real deployment shows the query is a problem.

## Revisit when

- **A deployment needs decisions to expire** — a clearance valid only for one
  crossing, say. That is a genuinely different model and would need its own
  record, not a flag on this one.
- **Reviews need to be attributed to a rank or a role** rather than an
  individual, for example where a shift signs collectively. That changes what
  "attributable" means and should be decided deliberately, not by widening the
  `officer_id` field.
