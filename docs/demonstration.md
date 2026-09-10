# Running the demonstration

Written to be followed under pressure, by somebody who did not write the code.

The governing principle: **never demonstrate anything that needs a network.**
Wifi at a competition venue is hostile, shared and unpredictable. Everything
below runs on one laptop with the network switched off.

---

## Before you leave the house

Run these three, in order. If all three pass, nothing on the day can surprise
you. Each is a separate PowerShell line — PowerShell has no `&&`.

```powershell
cd "D:\ps 188"
make check
```

```powershell
cd "D:\ps 188"
uv run python tools/demo.py
```

```powershell
cd "D:\ps 188"
uv run python tools/demo.py --work "D:\sentinel-local\dress-rehearsal" --keep
```

The third keeps its working files, so you can open the published checkpoint
files and look at them beforehand rather than for the first time in front of a
judge.

**Take a screen recording of the second one.** If the laptop dies you still have
the demonstration.

---

## Plan A — the one to actually use

One command, no network, no server, about fifteen seconds:

```powershell
cd "D:\ps 188"
uv run python tools/demo.py
```

It prints five sections. Talk over them in this order.

**1. A genuine document is screened.** It comes back `MANUAL_REVIEW`, not
`CLEARED`. Say this before anyone asks: *"It refused to clear a document it
could not prove. That is the whole design."* Point at the `WHAT WAS NOT CHECKED`
block — ten things, each in a sentence an officer can act on, each saying
whether it reflects on the document or on the equipment.

**2. A forged document is screened.** The tamper detector escalates it and, in
the same breath, says *"This is a machine's impression, not proof."* Say: *"The
AI is allowed to raise its hand. It is not allowed to condemn anyone."*

**3. An officer overrides the system.** The system said `MANUAL_REVIEW`; the
officer said `REJECTED`. The verdict is **not** rewritten — the officer's
decision is a second record beside it. Say: *"Overwriting the first would make
the record claim the system verified something it did not."*

**4. Checkpoints are published, each proving it extends the last.**

**5. A third party verifies the log using none of this system.** This is your
strongest moment. `tools/verify_checkpoint.py` imports nothing from the project
and needs only Python and one library. Offer the judge the two checkpoint files
and let them run it on their own laptop, with yours closed.

---

## Plan B — the live console, if a judge wants to submit something

Only if it is asked for. It needs a server, and a phone needs the network.

```powershell
cd "D:\ps 188"
$env:SENTINELID_DB_URL = "sqlite:///D:/sentinel-local/demo.sqlite3"
$env:SENTINELID_CHECKPOINT_ID = "DEMO-POST-01"
uv run alembic upgrade head
uv run uvicorn api.app:create_app --factory --port 8188
```

Leave that window open — closing it stops the server. Then open
`http://127.0.0.1:8188/console/submit` **on the laptop**, and drag a file in.

`uv run alembic upgrade head` is not optional. Without it, every page fails with
`no such table: case_record`.

### Only if the phone is genuinely needed

Use `--host 0.0.0.0` instead of the default, then:

```powershell
cd "D:\ps 188"
uv run python tools/demo_preflight.py
```

It prints the exact address to type on the phone and tells you which of the
three failure modes you have, because from the phone they all look identical.

Two things that will bite:

- **It must be `http://`, never `https://`.** There is no TLS. Browsers
  increasingly force https and then fail silently.
- **Windows Firewall blocks the port** until an Administrator PowerShell runs
  the `New-NetFirewallRule` line that the preflight tool prints. The rule must
  match the network's profile: a `Private` rule does nothing on a network
  Windows has classified `Public`.

**Say plainly that this mode has no authentication.** Anyone on that network can
screen documents and record decisions under any name. It is a demonstration
setting, not a deployment; `deploy/compose.yaml` binds to localhost for exactly
this reason. Turn the server off afterwards.

---

## If something breaks anyway

| What happened | What to do |
|---|---|
| The demo script errors | Show the screen recording. Then say what the error was — you will be believed more, not less. |
| The laptop will not start | The repository is on GitHub. Anything with Python and `uv sync` reproduces it. |
| A judge doubts the audit trail | Hand them the two checkpoint files and `tools/verify_checkpoint.py`. That is the point of it existing. |
| Someone asks for an accuracy figure | See below. Do not invent one. |
| The console shows an empty queue | You are pointed at a different database. Check `SENTINELID_DB_URL`. |

---

## The numbers you may say out loud

Only these. Everything else is invented, whoever says it.

**Counts of code and tests** — safe in any room, and not performance claims:
1,680 tests passing; 100% branch coverage on `core/`; 5 architecture contracts
enforced in CI; 7 architecture decision records; 13 detectors assembled at
runtime; 11 accepted document types, of which only 2 can ever reach `CLEARED`.

**The one evaluation that exists**, `eval/reports/synthetic-utopia-v1`, on
documents this repository generated: the classical tamper detector escalated 0%
of genuine documents, separates the `recapture` attack by +0.32 median score,
and is **blind to four of the five** forgery types. Say the blindness out loud —
the report does.

**Never say** an accuracy percentage, an F1 score, a false-acceptance rate, or
anything about real documents. No real document has ever been screened by this
project.

---

## Questions to expect

**"What's your accuracy?"**
Against real documents, unknown, and anyone quoting a figure is inventing it. We
have never seen a real document. What we can tell you is the false-escalation
rate on our own synthetic corpus — zero — and exactly which of five forgery
types the detector catches, which is one. There is a rule in the repository that
a number may not appear anywhere unless the evaluation harness produced it on a
named dataset. That rule is why the numbers we do quote can be defended.

**"Where is the AI? This looks like rule checking."**
The AI is on rung 2, and it is deliberately the least powerful layer. It can
escalate a document to a human or contribute to rejecting it. It cannot clear
one. That constraint is the contribution: a model that can clear a document is a
model whose false positives wave forgeries through a border.

**"So it doesn't actually clear anything?"**
Not today, because no real issuer certificate has been installed. Phase 12 built
the way to install one. And on these borders that is closer to the truth than it
sounds: of eleven accepted document types, only two carry anything a machine can
verify, and a Nepali citizenship certificate carries nothing at all. Here the
system is triage and evidence, not clearance.

**"Isn't a hand-rolled Merkle tree a red flag?"**
It would be if it were improvised. It is RFC 6962, and there is a test that
compares our tree against an implementation written directly from the standard
at every size from 0 to 64. Hyperledger Fabric was considered and rejected in
ADR 0003: it needs multiple organisations running ordering nodes to mean
anything, and a single-operator Fabric network is a slow database.

**"Why SQLite at a border post?"**
One box, offline, thousands of crossings — not millions. A Postgres dependency
is one more thing to fail where there is no network. One bug worth telling them
about: SQLite has no timezone type, so a log rebuilt from disk once computed a
*different Merkle root*. There is now a column type that refuses a naive
timestamp. It was caught only because the test rebuilt from disk rather than
from memory.

**"What stops someone storing an Aadhaar number?"**
Four layers: a type that masks itself in logs and that Pydantic refuses to give
a schema, so a contract field of that type fails at class definition; a database
guard that inspects every column on insert and update; a repository-wide scan
that fails the build if any committed file contains a twelve-digit
Verhoeff-valid number; and storage as an HMAC under a key held outside the
database. And the honest caveat, which is in ADR 0005: about 9×10¹¹ possible
values, so anyone holding both the key and the database can enumerate. The
digests are pseudonymous, not anonymous.

**"Most documents end up in manual review. Isn't that a failure?"**
It is the correct answer, and finding it out was the most valuable result of the
scoping phase. See the third question above.

**"What would you do with another month?"**
Nothing on the model side. The three highest-value items are all outside the
code: a real issuer certificate, a chip reader, and OCR-B training data for the
machine-readable strip.
