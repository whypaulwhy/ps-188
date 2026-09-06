# Evaluation report — synthetic-utopia-v1

- **Dataset:** `synthetic-utopia-v1`, seed `20260906`
- **Commit:** `a67b618`
- **Run:** 2026-09-06

## Read this before quoting any number below

These figures measure **synthetic documents this repository generated**,
rendered for a fictional issuing state in a font that is not OCR-B. They
describe how the detectors behave on our own output.

They are **not** a claim about real documents, they are **not** an accuracy
figure for this system, and they must not be quoted as one. No real
document has ever been screened by this project.

There is no single headline number here on purpose. Averaging detection
across forgery types hides which attacks a detector is blind to.

Synthetic specimens for the fictional state Utopia, and one document per forgery type derived from each. Measures whether a detector separates altered documents from unaltered ones on data this repository generated.

## Results

`escalated` is how often the detector said a person should look. On
`genuine` rows that is the false-escalation rate — the number that decides
whether an officer can work. `abstained` is how often it could not judge at
all, reported separately and never folded into an error rate.

| Detector | Documents | n | escalated | abstained | score q1 / median / q3 |
|---|---|---|---|---|---|
| `rung2.metadata_forensics` | genuine | 12 | 0% | 100% | — |
| `rung2.metadata_forensics` | copy_move | 12 | 0% | 100% | — |
| `rung2.metadata_forensics` | photo_substitution | 12 | 0% | 100% | — |
| `rung2.metadata_forensics` | recapture | 12 | 0% | 100% | — |
| `rung2.metadata_forensics` | template_clone | 12 | 0% | 100% | — |
| `rung2.metadata_forensics` | text_field_edit | 12 | 0% | 100% | — |
| `rung2.tamper_classical` | genuine | 12 | 0% | 0% | 0.32 / 0.37 / 0.40 |
| `rung2.tamper_classical` | copy_move | 12 | 0% | 0% | 0.33 / 0.37 / 0.41 |
| `rung2.tamper_classical` | photo_substitution | 12 | 0% | 0% | 0.36 / 0.39 / 0.42 |
| `rung2.tamper_classical` | recapture | 12 | 83% | 0% | 0.59 / 0.69 / 0.89 |
| `rung2.tamper_classical` | template_clone | 12 | 0% | 0% | 0.33 / 0.37 / 0.39 |
| `rung2.tamper_classical` | text_field_edit | 12 | 0% | 0% | 0.34 / 0.39 / 0.42 |
| `rung2.tamper_trufor` | genuine | 12 | 0% | 100% | — |
| `rung2.tamper_trufor` | copy_move | 12 | 0% | 100% | — |
| `rung2.tamper_trufor` | photo_substitution | 12 | 0% | 100% | — |
| `rung2.tamper_trufor` | recapture | 12 | 0% | 100% | — |
| `rung2.tamper_trufor` | template_clone | 12 | 0% | 100% | — |
| `rung2.tamper_trufor` | text_field_edit | 12 | 0% | 100% | — |

## Does any signal actually separate?

- `rung2.metadata_forensics`: produced no scores at all, so there is nothing to separate. See its abstention rate above.
- `rung2.tamper_classical`: separates `recapture` +0.32 (median score above genuine).
- `rung2.tamper_classical`: **blind to** `copy_move`, `photo_substitution`, `template_clone`, `text_field_edit` — no threshold makes these detectable on this dataset.
- `rung2.tamper_trufor`: produced no scores at all, so there is nothing to separate. See its abstention rate above.
