# The trust ladder

Four rungs. A detector declares which one it sits on, and that declaration
fixes what it is allowed to say. The implementation is
[`core/trust/ladder.py`](../core/trust/ladder.py); the tables it resolves
against are [`core/trust/policy.py`](../core/trust/policy.py).

## The rungs

| Rung | Name | What it is | What it may report | May it clear? | May it reject? |
|---|---|---|---|---|---|
| 0 | Cryptographic | An issuer signature verified against a trusted key | `PROOF_VALID`, `PROOF_INVALID`, `NO_PROOF_PRESENT` | Yes | Yes |
| 1 | Deterministic | Arithmetic or logic fixed by a published standard | `PASS`, `FAIL`, `NOT_APPLICABLE` | No | Yes |
| 2 | Inference | A learned model's score plus an uncertainty | `NO_FINDING`, `SUSPICIOUS`, `INCONCLUSIVE` | No | No |
| 3 | Contextual | History, watchlists, velocity | `FLAG_RAISED`, `NO_FLAG` | No | No |

The rung number counts down from the top of the ladder, so a **smaller number
means more authority**. `Rung.CRYPTOGRAPHIC < Rung.INFERENCE` is true and reads
as "cryptographic proof outranks inference".

The result vocabularies do not overlap. That is deliberate: a result value
alone identifies the rung that produced it, so a Rung 2 detector cannot report
`PROOF_VALID` and have it believed. `Evidence` rejects the combination at
construction time rather than trusting review to catch it.

## Resolution order

```
1. Any Rung 0 PROOF_INVALID, or any Rung 1 FAIL   ->  REJECTED
2. Any Rung 2 SUSPICIOUS                          ->  MANUAL_REVIEW
3. Any Rung 0 PROOF_VALID                         ->  CLEARED
4. Anything else, including no evidence at all    ->  MANUAL_REVIEW
```

Rung 3 does not appear. Contextual signals are attached to the verdict as
advisories, in a separate field from the findings, so they cannot be read as
reasons for the decision.

### Rejection outranks proof

Step 1 runs before step 3, so a document that carries a genuine issuer
signature **and** violates a fixed standard is rejected. This is the fail-closed
tie-break required by rule 1 of CLAUDE.md. A signature proves who issued a
document; it does not prove the document is currently usable. An expired
passport with a perfectly valid chip signature is the ordinary case.

### Concern holds back a clearance

Step 2 runs before step 3. This is **stricter than the resolution order written
in CLAUDE.md**, which has `PROOF_VALID` short-circuit immediately, and the
deviation is deliberate. Three reasons:

1. Rule 1 of CLAUDE.md — uncertainty routes to `MANUAL_REVIEW`, never to
   `CLEARED` — is in the non-negotiable section, which states that it overrides
   anything that conflicts with it. The resolution-order paragraph is not.
2. Rule 1 also grants Rung 2 permission to move a case *toward*
   `MANUAL_REVIEW`. If a valid signature short-circuited first, that permission
   would be dead in exactly the cases where it matters most.
3. A Rung 0 detector proves a fact about the **document**. A Rung 2 face check
   reports on the **bearer**. Someone presenting another person's genuine,
   correctly signed Aadhaar card would clear under the literal reading. That is
   the single most likely attack at an open crossing.

This is not a lower rung overriding a higher one. The signature is still
recorded as valid and still appears as a finding. No Rung 2 detector can cause
a `REJECTED`. What happens is that the system declines to clear a case a human
has not looked at.

**If you disagree**, the change is one block in `core/trust/ladder.py`: move the
`proving` branch above the `escalating` branch. `test_suspicion_escalates_a_document_that_would_otherwise_clear`
pins the current behaviour and would need to change with it.

## The two guarantees

**No clearance without authority.** `CLEARED` is reachable only through step 3,
which consults nothing but Rung 0. This is enforced twice over:

- A Rung 2 detector has no vocabulary for asserting authenticity. `score` is
  defined as *suspicion*, where `0.0` means "nothing wrong" and `1.0` means
  "maximally alarmed", so a larger number can only ever make a case worse.
- `Verdict` refuses to construct a `CLEARED` decision unless the evidence
  contains an affirmative Rung 0 or Rung 1 result. Even a future policy change
  cannot produce a clearance resting on inference alone without first deleting
  that validator.

**Monotonicity.** Adding Rung 2 or Rung 3 evidence to a case never moves the
decision toward `CLEARED`. Stated as a property and tested over arbitrary
evidence sets with hypothesis, not as a handful of examples.

## What was not checked

Three results establish nothing at all: `NO_PROOF_PRESENT`, `NOT_APPLICABLE`
and `INCONCLUSIVE`. Each becomes a line in `Verdict.not_checked` rather than a
finding, and the console has to display them. A document with no signature to
verify and a tamper model that failed to load is not a clean document; it is an
unexamined one, and the officer is told exactly that.
