# START HERE — the master prompt for a new session

Paste everything between the rules below as the **first message** of a new
session. It is written to be self-contained: nothing in it has to be explained
again, and nothing in it should be taken on trust without re-checking against
the repository.

Keep this file updated whenever `docs/roadmap.md` is.

---

Open the project at `D:\ps 188`.

Read `CLAUDE.md` in full first — it is the contract and it outranks anything I
say. Then read `docs/handoff.md` and `docs/roadmap.md`. Then confirm the working
tree is clean and `make check` passes, and tell me the real numbers rather than
the ones written down.

Here is what you need to know so I do not have to explain it again.

**The project.** SENTINEL ID — AI-assisted fake identity and document screening
for SSB border checkpoints. Smart India Hackathon 2026, problem statement
SIH26188, team VOID MATRIX. I am Prit (GitHub `whypaulwhy`). Repository
`https://github.com/whypaulwhy/ps-188`, branch `main`, and you push at the end
of every phase because that is how my teammates see progress.

**The idea, in one paragraph.** It screens identity documents at open,
unmanned border crossings where there is no advance manifest. Every check
declares a *rung* on a trust ladder, and a lower rung can never override a
higher one. Rung 0 is cryptographic proof and is the only rung that can clear a
document. Rung 1 is deterministic arithmetic and can only reject. Rung 2 is the
machine learning, and it can only ever push a case *toward* a human or a
rejection — it can never clear one, whatever it scores. Rung 3 is advisory and
decides nothing. Uncertainty always routes to `MANUAL_REVIEW`, never to
`CLEARED`.

**Where it stands.** Phases 0 through 15 are complete or explicitly partial, and
the roadmap has been carried past its original end. Everything unblocked from
the original plan is finished. `make check` is the gate: ruff, `ruff format
--check`, `mypy --strict core`, `lint-imports`, and pytest with `core/` held at
100% branch coverage.

**What is deliberately absent, and must never be quietly filled in.** No real
document has ever been screened by this project. Aadhaar Secure QR is a stub
because there is no specimen and guessing the container layout would produce a
detector that reports `PROOF_VALID` on bytes it never checked. ePassport chip
reading is blocked on hardware. Face matching and liveness abstain on every
document: no model weights, and deliberately no synthetic faces. TruFor reports
`INCONCLUSIVE` because no public checkpoint exists. There is no authentication.
No real issuer certificate has been installed, so **nothing can currently reach
`CLEARED`** — which is correct fail-closed behaviour, and every case says so.

**How I want you to work.**

- State the plan before any non-trivial change, and wait.
- Run `make check` after any change and report the result honestly, failures
  included. Never report a number you did not just see.
- Never invent a metric. The only performance figures that may be quoted are in
  `eval/reports/`, and they describe synthetic documents this repository
  generated. Everything else is `TBD`.
- Push to GitHub at the end of every phase, and update `docs/roadmap.md`,
  `docs/handoff.md` and this file as you go, so nothing has to be re-explained.
- I am on Windows 11 and my terminal is **PowerShell, which has no `&&`**. Give
  me PowerShell syntax, one command per line. This has wasted my time twice.
- Explain things to me as if I am not a specialist. I have to present this.

**Traps that have already cost time** (all recorded in `docs/handoff.md` §7):
`make` is not on PATH; `pathlib.write_text` defaults to cp1252 on this machine,
so always pass `encoding="utf-8"`; bash heredocs mangle backslash escapes, so
use the Write tool for Python; the API does not create its own schema, so
`uv run alembic upgrade head` comes first; the console case URL is
`/console/case/<id>`, singular.

**Demo files never go in the repository.** Document images and case databases
live outside it, in `D:\sentinel-local`. Committing a document image to a public
repository would contradict the whole project.

Now propose what to do next, and wait for me to pick.

---

## What is left, at the time of writing

**Blocked on a human, not on code.** These cannot be coded around.

1. A real issuer certificate — a DigiLocker-issued signed PDF and its signing
   certificate. Phase 12 built the way to install one and nothing real is in it,
   so no document can reach `CLEARED`. This is the highest-value thing available.
2. An Aadhaar Secure QR specimen and the UIDAI certificate.
3. Chip reader hardware, for ePassport passive authentication.
4. Confirmed Bhutanese CID and Nepali citizenship certificate formats.
5. A lawfully obtained face corpus, and model weights.
6. Deployment decisions: retention windows, where the hashing key lives, how
   staff authenticate, and whether the review volume is operationally acceptable.

**Buildable now.**

- `core/trust/aggregation.py` is a dead stub. `ladder.resolve()` does the
  aggregation. Deleting it is a legitimate outcome and takes ten minutes.
- `detectors/rung1_deterministic/template_geometry.py`, scoped to the ICAO TD3
  zone only, where the standard is published. Deferred with a documented reason:
  the only template available is the one `datagen` draws, so a detector built
  against it would agree with itself.
- Authentication, once §6 above has an answer.
- The written SIH submission. Rule 2 applies to slides.

## The demonstration

`uv run python tools/demo.py` runs the whole story offline in one command and
cannot fail on the day. `docs/demonstration.md` has the running order, the
fallbacks, and the questions to expect.
