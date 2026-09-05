# ADR 0001 — Python 3.12 only, no Node

- **Status:** Accepted
- **Date:** 2026-09-06
- **Supersedes:** —
- **Superseded by:** —

> **Note on authorship.** This ADR was written from the constraints already
> fixed in CLAUDE.md rather than from a recorded discussion. If the reasoning
> that actually drove the decision differs, correct this file — an ADR that
> records a rationalisation is worse than no ADR.

## Context

SENTINEL ID is built by a small team, on a deadline, for a deployment target
that is an offline or intermittently connected box at a border checkpoint. Two
things follow from that setting.

**Every artefact has to be auditable by one reviewer.** A screening decision
must be defensible after the fact, which means a person has to be able to read
the code that produced it. A codebase split across two languages, two package
managers, two dependency lock formats and two toolchains doubles the surface a
reviewer has to hold in their head, and doubles the places a supply-chain
problem can enter.

**The deployment is constrained.** A checkpoint box is not a cloud environment.
It has no reliable network, limited operator skill on site, and a long
maintenance interval. Every additional runtime is another thing that can fail
at 2 a.m. in a place where nobody can fix it.

The pull toward Node is the officer console. A React or Vue front end is the
default reflex for anything with a UI, and it would make the console nicer to
build.

## Decision

**Python 3.12 is the only language in this project.** There is no Node, no
package.json, no bundler and no JavaScript build step.

The officer console is server-rendered from Python. Where interactivity is
genuinely needed, it is hand-written JavaScript served as a static asset, small
enough to read in one sitting, with no build pipeline behind it.

Python 3.12 specifically, not "3.12 or newer": the version is pinned in
`pyproject.toml` as `>=3.12,<3.13` so that CI, the developer machines and the
deployment image agree exactly. `uv` manages both the interpreter and the lock
file.

## Consequences

**Accepted:**

- The console will be plainer than a single-page application. Server-rendered
  pages, full reloads, no client-side state machine. For a queue-and-detail
  screen that an officer uses under time pressure, this is a small loss.
- Some front-end work becomes more manual. That is the intended trade.

**Gained:**

- One toolchain: `uv` for the interpreter, dependencies and lock file; `ruff`,
  `mypy` and `pytest` over one language.
- One dependency graph to audit. `uv.lock` is the whole supply chain.
- One artefact to ship. No `node_modules`, no bundle, no separate build stage
  in the deployment image.
- `make check` covers the entire repository. Nothing is checked by a different
  tool with different rules.

## Alternatives considered

**Python backend with a React front end.** The conventional choice. Rejected
because it doubles the toolchain and the audit surface for a UI that is a
queue, a detail view and two buttons.

**Python with HTMX served from Python.** A reasonable middle ground and still
available: HTMX is a static asset with no build step, so adopting it would not
reopen this ADR. Noted here so a future reader knows it is permitted.

**A compiled language for the detectors.** Real performance headroom, but the
whole ecosystem this project depends on — ONNX Runtime bindings, OpenCV,
`pyhanko`, `signxml`, RapidOCR, InsightFace — is Python-first. The cost of
leaving that ecosystem is far larger than any gain, and no measurement exists
showing Python is the bottleneck. If one ever does, it will name a specific hot
path, and that path can be addressed without changing the project language.

## Revisit when

- The console needs genuinely rich client-side interaction — live video
  overlays, a canvas annotation tool — that hand-written JavaScript cannot
  carry.
- A measured, reported bottleneck in `eval/reports/` shows Python is the
  limiting factor for throughput at a checkpoint.

Neither has happened. Until one does, this ADR stands.
