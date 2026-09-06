# Evaluation protocol

> **Status: running.** `eval/run_eval.py` is built and has been run on the
> `synthetic-utopia-v1` protocol. Its report is in
> [`../eval/reports/`](../eval/reports/) and is the only place in this
> repository a performance figure may come from. That is rule 2 of CLAUDE.md.
>
> **Every number that exists today describes synthetic documents this
> repository generated.** Nothing in this project has ever seen a real
> document, so no figure here is a claim about real-world performance.

## The rule

A number describing how well this system performs may appear in code, comments,
docstrings, the README, the console or a slide **only if**:

1. it was produced by `eval/run_eval.py`,
2. on a named dataset defined in `eval/protocol.py`,
3. and written to `eval/reports/`.

If a number is needed and does not exist, write `TBD` and say so out loud. An
invented accuracy figure in a border screening system is not an optimistic
estimate; it is a false assurance that someone may act on.

## What gets measured

Different rungs need different measurements, and averaging them into one
headline figure would be meaningless.

**Rung 0 and Rung 1 are not scored for accuracy.** They are deterministic. A
check digit either matches or it does not; a signature either verifies or it
does not. What is measured is *conformance*: golden fixtures in, exact
`Evidence` out. A failure there is a bug, not a lower score.

**Rung 2 is scored**, per detector and per forgery type, never as a single
aggregate:

- Detection rate at a fixed false-escalation rate, and the reverse.
- Calibration: does a suspicion of 0.8 mean anything consistent?
- Behaviour under degradation: low light, low resolution, print-and-scan,
  compression. A detector that works only on clean scans is not deployable at
  an open crossing.
- Rate of `INCONCLUSIVE`, reported separately and never folded into an error
  rate. A model that abstains half the time may still be useful, but the
  abstention has to be visible.

**The system as a whole** is measured on decision outcomes:

- Rate of `CLEARED` on genuine documents.
- Rate of `REJECTED` on forged documents.
- **`MANUAL_REVIEW` volume**, which is the real operational constraint. A
  system that sends every case to a human is safe and useless.
- False `CLEARED` rate. This is the number that matters most and it is reported
  on its own, never averaged with anything.

## The two costs, kept separate

A false `CLEARED` lets someone through on a forged identity. A false `REJECTED`
strands a legitimate traveller at a border, possibly for hours, possibly
repeatedly. These are not commensurable and will not be traded off inside a
single metric. Both are reported; the operator decides the threshold, and the
protocol records which threshold was in force for each run.

## Datasets

Named in `eval/protocol.py`, each with a fixed split and a seed so a run is
reproducible. Two kinds:

- **Synthetic**, from `datagen/`, with one class per forgery type. Ground truth
  is exact because the forgery was generated. Nothing here derives from a real
  person's document.
- **Specimen**, from published specimen documents and consenting-issuer
  samples. Every fixture carries a licence note and a provenance line.

No real traveller's document enters an evaluation dataset. If field data is
ever used, it needs its own approval, its own retention window, and its own
section in this document.

## Reporting

Each run writes to `eval/reports/<protocol>-<date>-<commit>.md` and records:

- The protocol name, dataset digest, git commit and model versions.
- Every metric above, disaggregated, with the count behind each.
- What failed, what abstained, and what was not run.
- Explicitly, the conditions under which the numbers do **not** hold.

A report that lists only the good numbers is not a report.

## To be completed in phase 6

- The exact metric definitions and their formulas.
- The degradation conditions and how they are simulated.
- The operating points the deployment will actually use.
