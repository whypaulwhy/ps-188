# START HERE — the master prompt for a new session

Paste everything between the rules below as the **first message** of a new
session. It is written to be self-contained: nothing in it has to be explained
again, and nothing in it should be taken on trust without re-checking against
the repository.

Keep this file updated whenever `docs/roadmap.md` is.

---

Open the project at `D:\ps 188`.

Read `CLAUDE.md` in full first — it is the contract and it outranks anything I
say. Then read `docs/roadmap.md` from **phase 16 onward** (the earlier phases are
history and you do not need them to continue). Confirm the working tree is clean
and `make check` passes, and tell me the real numbers rather than the ones
written down.

**Do not re-explore the repository, re-run the demo, or re-audit anything.** It
was audited twice on 2026-09-10 and everything below is current as of commit
`af317d9`. Start from "What is left" at the bottom of this file.

Here is what you need to know so I do not have to explain it again.

**The project.** SENTINEL ID — AI-assisted fake identity and document screening
for SSB border checkpoints. Smart India Hackathon 2026, problem statement
SIH26188, team VOID MATRIX. I am Prit (GitHub `whypaulwhy`). Repository
`https://github.com/whypaulwhy/ps-188`, branch `main`, and you push at the end
of every phase because that is how my teammates see progress.

**The idea, in one paragraph.** It screens identity documents at open, unmanned
border crossings where there is no advance manifest. Every check declares a
*rung* on a trust ladder, and a lower rung can never override a higher one.
Rung 0 is cryptographic proof and is the only rung that can clear a document.
Rung 1 is deterministic arithmetic and can only reject. Rung 2 is the machine
learning, and it can only ever push a case *toward* a human or a rejection — it
can never clear one, whatever it scores. Rung 3 is advisory and decides nothing.
Uncertainty always routes to `MANUAL_REVIEW`, never to `CLEARED`.

**Where it stands.** Phases 0–17 done. `make check` is the gate: ruff, `ruff
format --check`, `mypy --strict core`, `lint-imports`, pytest with `core/` at
100% branch coverage. At `af317d9`: **1820 passed, zero skipped.**

**I am four days from a demonstration.** Days 1–3 of that push are done. What
remains is the last wiring and a rehearsal — see "What is left".

**What is deliberately absent, and must never be quietly filled in.** No real
document has ever been screened. Aadhaar Secure QR is a stub because there is no
specimen and guessing the container layout would produce a detector that reports
`PROOF_VALID` on bytes it never checked. ePassport chip reading is blocked on
hardware. TruFor reports `INCONCLUSIVE` — no public weights. There is no
authentication. No *real* issuer certificate is installed, so no real document
can reach `CLEARED`; the fictional-issuer card can, through genuine
cryptography.

**How I want you to work.**

- State the plan before any non-trivial change, and wait.
- Run `make check` after any change and report the result honestly, failures
  included. Never report a number you did not just see.
- Never invent a metric. The only performance figures that may be quoted are in
  `eval/reports/`, and they describe synthetic documents this repository
  generated. Everything else is `TBD`.
- Push to GitHub at the end of every phase, and update `docs/roadmap.md` and
  this file as you go, so nothing has to be re-explained.
- I am on Windows 11 and my terminal is **PowerShell, which has no `&&`**. Give
  me PowerShell syntax, one command per line. This has wasted my time twice.
- Explain things to me as if I am not a specialist. I have to present this.

**Traps that have already cost time:** `make` is not on PATH (it is at the
ezwinports winget path — prepend it in the Bash tool); `pathlib.write_text`
defaults to cp1252 on this machine, so always pass `encoding="utf-8"`; bash
heredocs mangle backslash escapes, so use the Write tool for Python files; the
API does not create its own schema, so `uv run alembic upgrade head` comes
first; the console case URL is `/console/case/<id>`, singular.

**Demo files never go in the repository.** Document images, face samples and
case databases live in `D:\sentinel-local`. Committing one would contradict the
whole project.

Now read "What is left" below, propose what to do next, and wait for me to pick.

---

## Where things actually are

### Runs today, verified end to end

| | |
|---|---|
| `uv run python tools/demo.py` | the whole story offline, ~15s, no network |
| `/console/capture` | phone-first camera page, renders the verdict inline |
| `/console/submit` | plain file upload, no JavaScript |
| `python -m api.publish_checkpoint --out DIR [--since PREV.json]` | signed checkpoints |
| `python tools/verify_checkpoint.py A.json B.json` | what a **third party** runs |
| `python -m api.retention_job [--dry-run]` | destroy expired case records |
| `python tools/demo_preflight.py` | why a phone cannot reach the console |
| `python tools/face_check.py DOC.jpg FACE1.jpg FACE2.jpg` | face + liveness on your own images |

### The three verdicts, all confirmed from photographed cards

- **REJECTED** — an invented Aadhaar number fails the Verhoeff arithmetic
  (`rung1.aadhaar_number`, phase 16A).
- **CLEARED** — a signed specimen card verifies against an installed anchor
  (`rung0.signed_qr` + `datagen/signed_card.py`, phase 16C). Fictional issuer,
  genuine ECDSA.
- **MANUAL_REVIEW** — everything else, including a genuine card with no anchor
  installed.

### Environment for a full-capability run

```powershell
$env:SENTINELID_DB_URL = "sqlite:///D:/sentinel-local/demo.sqlite3"
$env:SENTINELID_CHECKPOINT_ID = "DEMO-POST-01"
$env:SENTINELID_FACE_MODEL_ROOT = "C:\Users\user\.insightface"
```

Optional and each stated on every case when absent:
`SENTINELID_LEDGER_KEY_FILE`, `SENTINELID_HASH_KEY_FILE`,
`SENTINELID_TRUST_ANCHORS_FILE`, `SENTINELID_RETENTION_POLICY_FILE`.

Face models are already downloaded to `C:\Users\user\.insightface\models\buffalo_l`
(det_10g, w600k_r50, 2d106det, 1k3d68, genderage). There is a redundant 275 MB
`buffalo_l.zip` beside them that can be deleted.

---

## What is left

### 1. The last wiring — this is the next job

**`/console/capture` sends one document image and no live frames.** So
`face_match` reports "no photograph of the person was taken" and `pad_liveness`
reports the same, on every case. The detectors work; nothing feeds them.

What is needed: after the document, capture the bearer — front camera, **two or
more frames a moment apart**, because `pad_liveness` reports `INCONCLUSIVE` on a
single frame by design. Post them as additional files with role `live_capture`.
`api/intake.py::record_capture` takes one capture today and will need to accept
the extra artefacts.

That is the last thing standing between the current state and the full
demonstration.

### 2. Then: rehearse

`docs/demonstration.md` is the running order, the fallbacks, the numbers that
may be said out loud, and the questions to expect. Run it once end to end and
record it.

### 3. Blocked on a human, not on code

1. **A real issuer certificate.** A DigiLocker-issued signed PDF and its signing
   certificate — Sagnik's driving licence was the plan, with his consent. Until
   one exists, no *real* document can reach `CLEARED`.
2. An Aadhaar Secure QR specimen and the UIDAI certificate. **I have declined to
   share a photograph of my own Aadhaar and that decision stands.**
3. Chip reader hardware.
4. Confirmed Bhutanese CID and Nepali citizenship formats.
5. **A labelled face corpus** — see the open question below.
6. Deployment decisions: retention windows, where the hashing key lives, how
   staff authenticate.

### 4. Open questions worth a decision

**The face threshold is not calibrated.** `SUSPICION_THRESHOLD` was moved from
0.55 to 0.33 on 2026-09-10 after the models were run over eleven images I
supplied. Eight had faces; all thirty-six pairs scored between -0.14 and +0.18,
the spread of *different* people. At 0.55 only two of thirty-six escalated — an
impostor would have read as "consistent with the photograph". 0.33 fails closed.

**Nothing has ever compared two pictures of the same person**, so the rate at
which this escalates a *genuine* bearer is unmeasured. Two photographs of the
same person, taken minutes apart, would settle it in one command with
`tools/face_check.py`.

**The evaluation corpus has never contained a document with large flat areas.**
Found in phase 16C: `tamper_classical` saturated at 1.0 on the first signed card
and it was neither the QR nor a shortage of texture — the signal is error-level
*localisation*, and a document mixing flat areas with sharp graphics scores 3.11
against the corpus's 1.75 with no tampering at all. Adding print density brought
it to 0.137. So `eval/reports/`'s "0% false escalation on genuine documents" is
narrower than it sounds. Fixing it means new specimens, not a new detector.

### 5. Small and buildable

- `core/trust/aggregation.py` is a dead stub — `ladder.resolve()` does the
  aggregation. Deleting it is a legitimate outcome, ten minutes.
- `template_geometry.py`, scoped to the ICAO TD3 zone only. Deferred with a
  documented reason.
- Authentication, once §3.6 has an answer.
- The written SIH submission. **Rule 2 applies to slides.**

---

## Reading order for a new session

1. `CLAUDE.md` — the contract.
2. This file.
3. `docs/roadmap.md`, phases 16–17 and the section after them.
4. `docs/demonstration.md` when the demo is the subject.
5. `docs/how-it-works.html` is the plain-English explanation, for presenting
   rather than maintaining. Open it in a browser.
