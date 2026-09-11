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
was audited twice on 2026-09-10 and everything below is current as of phase 18
(2026-09-11). Start from "What is left" at the bottom of this file.

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

**Where it stands.** Phases 0–18 done. `make check` is the gate: ruff, `ruff
format --check`, `mypy --strict core`, `lint-imports`, pytest with `core/` at
100% branch coverage. At the end of phase 18: **1829 passed, zero
skipped.**

**I am close to a demonstration.** The detectors are built and verified. What
remains is the last wiring — the capture page does not yet send photographs of
the person — and a rehearsal. See "What is left".

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
  generated. **This includes docstrings and the roadmap**: counts from an ad-hoc
  local check are not admissible there either, and phase 18 had to remove some.
  Everything else is `TBD`.
- Push to GitHub at the end of every phase, and update `docs/roadmap.md` and
  this file as you go, so nothing has to be re-explained.
- I am on Windows 11 and my terminal is **PowerShell, which has no `&&`**. Give
  me PowerShell syntax, one command per line. This has wasted my time twice.
- Explain things to me as if I am not a specialist. I have to present this.
- **Test a claim before writing it down.** Phase 17 documented that liveness
  defeats a printed photograph; one experiment showed it did not.

**Traps that have already cost time:** `make` is not on PATH (it is at the
ezwinports winget path — prepend it in the Bash tool); `pathlib.write_text`
defaults to cp1252 on this machine, so always pass `encoding="utf-8"`; bash
heredocs mangle backslash escapes, so use the Write tool for Python files; the
API does not create its own schema, so `uv run alembic upgrade head` comes
first; the console case URL is `/console/case/<id>`, singular; a golden case
**silently skips** unless its detector is registered in `BUILDERS` in
`tests/golden/test_golden_corpus.py`.

**Demo files never go in the repository.** Document images, face photographs and
case databases live in `D:\sentinel-local`. Committing one would contradict the
whole project. My own photographs are in `D:\sentinel-local\samples\` as
`prit_*.jpg`, used with my consent; the other images there are document scans.
Report counts and scores from them, never describe them.

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

### The face checks, confirmed on real photographs

- **Face match** (`rung2.face_match`): my own photographs read as consistent
  with each other across every angle tried; document portraits were escalated
  against them.
- **Liveness** (`rung2.pad_liveness`, v2.0.0): measures change of facial *shape*
  between frames, after removing how the picture moved. A turning head passes;
  a photograph shifted, rotated, scaled or tilted in the hand is escalated.
  Verified on my frames and on warps of them.

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

**`/console/capture` sends one document image and no photographs of the
person.** So `face_match` and `pad_liveness` both report that the bearer was
never photographed, on every case. The detectors work; nothing feeds them.

What is needed:

- After the document, open the **front** camera and take **two or more frames a
  moment apart** — `pad_liveness` reports `INCONCLUSIVE` on a single frame by
  design.
- **The page must tell the person to turn their head slowly while it takes
  them.** Liveness now measures change of shape, and a person holding perfectly
  still is escalated. That is the safe direction, but it is the wrong experience
  at a barrier, and it would make the demonstration look broken.
- Post the frames as additional files with role `live_capture`.
  `api/intake.py::record_capture` takes one capture today and needs to accept
  the extra artefacts; `POST /screenings` needs to receive them.

That is the last thing standing between the current state and the full
demonstration.

### 2. Then: two tests with a real printed photograph

Liveness v2 has been verified against warps of a still photograph, **not against
a real printed photograph filmed by a real camera** — paper curvature, glare and
focus all differ. Print a selfie on paper and, once the capture page takes live
frames, try:

- holding it still — should escalate;
- moving and tilting it in the hand — should escalate;
- **bending it** between frames — may pass. That is a known limitation and is in
  the officer wording; knowing whether it does on paper is worth a minute.

### 3. Then: rehearse

`docs/demonstration.md` is the running order, the fallbacks, the numbers that
may be said out loud, and the questions to expect. It predates phases 16–18 and
needs the face and liveness moment added. Run it once end to end and record it.

### 4. Blocked on a human, not on code

1. **A real issuer certificate.** A DigiLocker-issued signed PDF and its signing
   certificate — Sagnik's driving licence was the plan, with his consent. Until
   one exists, no *real* document can reach `CLEARED`.
2. An Aadhaar Secure QR specimen and the UIDAI certificate. **I have declined to
   share a photograph of my own Aadhaar and that decision stands.**
3. Chip reader hardware.
4. Confirmed Bhutanese CID and Nepali citizenship formats.
5. Deployment decisions: retention windows, where the hashing key lives, how
   staff authenticate.

### 5. Open questions worth a decision

**Neither face threshold has a quotable number behind it.**
`face_match.SUSPICION_THRESHOLD = 0.33` and `pad_liveness.STILLNESS_THRESHOLD =
0.07` were both set against a local check on my own photographs, and both behave
correctly on it. But rule 2 admits only figures `eval/run_eval.py` produces on a
named dataset, so their error rates are `TBD`. **If the submission needs a number
for either, the route is an evaluation report**, run on a dataset held outside
the repository and named in the report — not a figure copied from a chat.

**The evaluation corpus has never contained a document with large flat areas.**
Found in phase 16C: `tamper_classical` saturates on a sparsely printed document
with no tampering at all, because its signal is error-level *localisation*. So
`eval/reports/`'s "0% false escalation on genuine documents" is narrower than it
sounds. Fixing it means new specimens, not a new detector.

### 6. Small and buildable

- `core/trust/aggregation.py` is a dead stub — `ladder.resolve()` does the
  aggregation. Deleting it is a legitimate outcome, ten minutes.
- `template_geometry.py`, scoped to the ICAO TD3 zone only. Deferred with a
  documented reason.
- Authentication, once §4.5 has an answer.
- The written SIH submission. **Rule 2 applies to slides.**

---

## Reading order for a new session

1. `CLAUDE.md` — the contract.
2. This file.
3. `docs/roadmap.md`, phases 16–18.
4. `docs/demonstration.md` when the demo is the subject.
5. `docs/how-it-works.html` is the plain-English explanation, for presenting
   rather than maintaining. Open it in a browser. It also predates phases 16–18.
