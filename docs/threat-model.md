# Threat model

> **Status: skeleton.** The per-document-type analysis is phase 1 work. What is
> written here is the frame it gets filled into, plus the attacks that already
> shaped the phase-0 design. Nothing below is a measurement.

## The setting

An open, unmanned or lightly manned border crossing. There is no advance
manifest. Documents arrive unannounced, in whatever condition they are in:
laminated, faded, photographed on a phone, folded, printed at home. The officer
has minutes and no laboratory.

Two consequences run through the whole design:

- **The system cannot assume it has seen this document type before.** Anything
  it does not recognise goes to a human. Refusing to judge is a valid answer.
- **The officer is the decision maker.** The system's job is to present
  defensible evidence, not to be trusted blindly.

## Assets

| Asset | Why it matters |
|---|---|
| The screening decision | A wrong `CLEARED` lets someone through on a forged identity. A wrong `REJECTED` strands a legitimate traveller. |
| Aadhaar numbers | Aadhaar Act 2016 s.29 and s.37. Storing one is a criminal matter, not a design preference. |
| Face embeddings | Partially invertible by model inversion. They are personal data, not anonymous features. |
| The audit trail | If it can be edited after the fact, no decision made by this system is defensible. |
| Issuer trust anchors | If an attacker can add a key, they can mint documents that clear at Rung 0. |

## Adversaries

1. **The opportunistic traveller.** An expired or borrowed document. No
   technical sophistication. Caught deterministically at Rung 1 or by the
   bearer check at Rung 2.
2. **The document forger.** Alters a genuine document — the portrait, a date, a
   name — or fabricates one from a cloned template. This is the main target of
   Rungs 0 and 2.
3. **The presentation attacker.** Uses a printed photo, a screen replay or a
   mask against the live capture. Target of `pad_liveness`.
4. **The insider.** Has access to the deployment. Motivated to make one specific
   case clear, or to make a past case look different. Target of the transparency
   log and of the architecture boundary that keeps detectors away from the
   database.

## Attack classes and which rung answers them

| Attack | Rung that answers | Notes |
|---|---|---|
| Forged Aadhaar with fabricated QR | 0 | Signature fails to verify → `PROOF_INVALID` → `REJECTED`. |
| Genuine Aadhaar, substituted portrait | 0 and 2 | The Secure QR carries the portrait, so the signature catches it. Where no QR is present, only Rung 2 sees it, and Rung 2 cannot clear or reject — the case goes to a human. |
| Genuine document, wrong bearer | 2 | Face match. Escalates only. This is the case that drove step 2 of the resolution order; see `trust-ladder.md`. |
| Edited date of birth or expiry | 1 | Check digits and cross-field consistency. |
| Fabricated document from a cloned template | 1 and 2 | Template geometry, then tamper signals. |
| Print-and-rephotograph of a real document | 2 | Metadata forensics and PAD. Escalates only. |
| Screen replay of a stored document image | 2 | PAD. |
| Expired but genuine and correctly signed | 1 | Rejection outranks proof, which is why step 1 precedes step 3. |
| Document type the system has never seen | — | No detector applies. `MANUAL_REVIEW` by default. |

## Attacks on the system itself

| Attack | Mitigation |
|---|---|
| Adding a forged issuer key to the trust store | Trust anchors are configuration, reviewed and pinned. Phase 4. |
| Editing a past decision in the database | Append-only transparency log with signed checkpoints. Phase 9, ADR 0003. |
| A detector reaching into the database to change what it reports | Architecture boundary, enforced by import-linter in CI. Rule 5. |
| A Rung 2 model being tuned to clear a specific document | Structurally impossible: Rung 2 cannot express a clearing result, and `Verdict` refuses a clearance without Rung 0 or Rung 1 support. |
| Overclaiming in a demo | Rule 2. Numbers come from `eval/run_eval.py` on a named dataset or they do not exist. |
| A model silently failing and looking like a pass | `INCONCLUSIVE` is a distinct result and lands in `Verdict.not_checked`. |

## Out of scope, stated plainly

- **Chip reading.** No ePassport passive authentication without reader
  hardware. `epassport_sod.py` stays a stub, and every case says so rather than
  omitting the check silently.
- **Liveness against a determined, well-funded attacker** with custom masks.
  Phase 7 targets print and replay.
- **Documents from issuers whose templates are not in the corpus.** These are
  routed to a human by design, not handled.
- **Network verification against issuer APIs.** No cloud services; see ADR 0001.

## To be completed in phase 1

- One section per accepted document type, listing its security features, which
  are machine-checkable, and which are not.
- For each attack above, the specific detector that answers it and the golden
  fixture that proves it.
- The false-rejection cost. A stranded legitimate traveller is a real harm and
  belongs in this document, not only in the evaluation protocol.
