# The evidence contract

Every detector returns a list of `Evidence`. No detector returns a bare `bool`,
`float` or `str`. This document explains why each field exists; the enforcement
lives in [`core/contracts/evidence.py`](../core/contracts/evidence.py).

## Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `detector_id` | `str` | yes | Dotted lowercase, e.g. `rung1.mrz_checkdigits`. Unique across the registry. |
| `rung` | `Rung` | yes | Fixes what results are permitted. |
| `result` | `Result` | yes | Must belong to this rung's vocabulary. |
| `score` | `float \| None` | Rung 2 only | **Suspicion** in [0, 1]. Higher is worse. |
| `uncertainty` | `float \| None` | Rung 2 only | How little the detector trusts its own score. |
| `reasons` | `tuple[str, ...]` | yes, non-empty | What the officer reads. |
| `standard_ref` | `str \| None` | Rung 0 and 1 | The clause applied, e.g. `ICAO Doc 9303 Part 3 s.4.2.2`. |
| `artifacts` | `tuple[str, ...]` | no | Paths to heatmaps, crops, decoded payloads. |
| `runtime_ms` | `float` | yes | Wall-clock time this detector spent. |
| `model_version` | `str` | yes | Model weights at Rung 2, detector code elsewhere. |
| `input_digest` | `str` | yes | Lowercase hex SHA-256 of the exact bytes examined. |

## Why `score` means suspicion, not authenticity

If `score` meant "probability the document is genuine", a high number would
argue for clearing, and the ladder would have to be careful to ignore it.
Defining it as suspicion removes the possibility. A Rung 2 detector has no way
to express "this document is genuine" because it has no standing to say so; the
best it can do is `NO_FINDING` with a score of `0.0`, which the ladder treats
as inert.

## Why `reasons` is a list of sentences

`reasons` is the text an officer reads on the console, under time pressure,
possibly at night, about a person standing in front of them. Write for someone
who has never heard of a check digit.

- No: `MRZ line 2 CD mismatch at offset 13 (computed 4, printed 7)`
- Yes: `The date of birth printed on this passport does not match the coded
  version at the bottom of the page.`

The offset and the computed digit belong in `artifacts` or the ledger, where an
auditor can find them. They do not belong on the officer's screen.

## Why `standard_ref` is required at Rung 0 and 1

Those two rungs decide cases. A decision that ends a person's crossing has to
be traceable to a published rule that a third party can look up and check. At
Rung 2 there is no such clause, and the contract does not pretend otherwise —
`standard_ref` stays `None` rather than citing a paper about the model.

## Why `input_digest` is on every piece of evidence

Preprocessing changes pixels. Without a digest recorded per detector, an audit
cannot tell whether the tamper model saw the original capture or a deskewed,
denoised derivative of it. `Provenance.sha256` records the artefact as
received; `Evidence.input_digest` records what that particular detector
actually looked at.

## Structural rules

These are enforced at construction. Violating one raises `ValidationError`
rather than producing an object that later code has to be careful with.

1. A result must belong to the declared rung's vocabulary.
2. Only Rung 2 may carry `score` or `uncertainty`.
3. A conclusive Rung 2 result requires **both** a score and an uncertainty. A
   score without a caveat is a claim the detector is not entitled to make.
4. An `INCONCLUSIVE` result must carry **neither**. A model that could not
   answer must not leave a number behind for someone to misread.
5. Rung 0 and Rung 1 must cite a standard.
6. `reasons` must be non-empty and must not be blank strings.
7. Everything is frozen. Evidence is a record of what happened.

## Failure is evidence too

A detector that cannot run returns evidence saying so. It does not return
`None`, does not return an empty list to mean "fine", and does not raise past
its own boundary. A silent detector is indistinguishable from a passing one,
and CLAUDE.md calls that a defect rather than a clean result.

```python
Evidence(
    detector_id="rung2.tamper_trufor",
    rung=Rung.INFERENCE,
    result=Result.INCONCLUSIVE,
    reasons=("The alteration detection model did not load, so no check was made.",),
    runtime_ms=3.1,
    model_version="trufor/unavailable",
    input_digest=digest,
)
```

That lands in `Verdict.not_checked` and appears on the officer's screen.
