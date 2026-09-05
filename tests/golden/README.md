# Golden fixtures

A golden case is a committed input and the exact `Evidence` a named detector
must produce from it. Every Rung 0 and Rung 1 detector needs them, per
CLAUDE.md.

## Adding a case

Create `cases/<case-id>/` with three files.

**`case.toml`**

```toml
[case]
id = "td3-ind-dob-altered"
description = "One sentence saying what this case is."
detector = "rung1.mrz_checkdigits"
phase = 5
input = "input.mrz.txt"

[fixture]
licence = "Synthetic. Authored for this repository and released under CC0-1.0."
provenance = "How this fixture came to exist, and how its expected values were derived."
sha256 = "<sha256 of the input file>"
```

**The input file**, named by `case.toml`.

**`expected.json`** — a list of `Evidence` records. Set `runtime_ms` to `0.0`
and `model_version` to `"any"`; both are ignored by the harness.

## Rules the tests enforce

- Every fixture carries a non-empty `licence` and `provenance`.
- The declared `sha256` matches the file on disk. Editing a fixture without
  updating its expectation fails the build.
- Every expectation is a valid `Evidence` record, names the case's detector,
  and carries the digest of the fixture beside it.
- Rung 0 and Rung 1 expectations cite a `standard_ref`.
- No `reasons` text contains jargon. The banned list is `JARGON` in
  `harness.py`; add to it rather than working around it.
- No twelve-digit Verhoeff vector may have the shape of an issuable Aadhaar
  number. All of them start with `0`, which UIDAI never issues.

## What is compared

Everything except `runtime_ms` and `model_version`. That includes the
officer-facing `reasons` text, so wording cannot drift once committed. If you
need to change the wording, change the golden in the same commit and say why.

## Pending cases

A case whose detector is not yet registered is reported as skipped, naming the
detector and the phase it lands in. It starts running for real the moment the
detector is registered; nothing in the case or the harness needs to change.

Six cases are pending as of phase 1. All six are for
`rung1.mrz_checkdigits`, which lands in phase 5.

## Deriving expected values

Expected values are derived **from the standard, not from our implementation**.
The phase-1 MRZ check digits and Verhoeff vectors were computed by a standalone
script written against ICAO Doc 9303 Part 3 and the published Verhoeff tables,
before `core/standards/` existed, and the five ICAO specimen digits it produced
match the published specimen exactly. That is what makes them an independent
check on phase 2 rather than a restatement of it.

Do not regenerate a golden from the code it is meant to test.

## Vectors

`vectors/` holds standards test vectors for `core/standards/` — arithmetic in,
primitive out — as distinct from detector cases. Same licence and provenance
obligations.
