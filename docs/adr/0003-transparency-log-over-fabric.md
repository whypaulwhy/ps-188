# ADR 0003 — A Merkle transparency log, not Hyperledger Fabric

- **Status:** Accepted
- **Date:** 2026-09-06
- **Supersedes:** —
- **Superseded by:** —

> **Note on authorship.** Written from the constraints fixed in CLAUDE.md
> rather than from a recorded discussion. Correct it if the reasoning that
> actually drove the decision differs.

## Context

Every screening decision has to be auditable after the fact. Specifically, a
reviewer must be able to establish that a verdict recorded on a given date has
not been altered since — including by someone with database access, which is
the insider case in `docs/threat-model.md`.

"Auditable and tamper-evident" reliably attracts the suggestion of a blockchain,
and Hyperledger Fabric is the usual name attached to it in a government context.
It is worth being precise about what the requirement actually is, because the
two are not the same thing.

**What is required:** append-only, tamper-evident storage. Given a record and a
published checkpoint, anyone can verify that the record was in the log at that
time and has not changed since.

**What is not required:** distributed consensus among mutually distrusting
parties. There is one operator. The SSB runs the checkpoint, owns the hardware
and owns the data. There is no second organisation whose agreement is needed to
accept a record, and no Byzantine fault model to defend against, because there
is no set of peers to disagree.

A permissioned blockchain solves the second problem. Paying its cost to get the
first is paying for machinery that does nothing here.

The cost is not abstract. Fabric brings orderers, peers, membership service
providers, certificate authorities, channel configuration and a chaincode
lifecycle. It has to run somewhere — at a checkpoint that may be offline for
long stretches, maintained by people who are not distributed-systems engineers.
Every one of those components is something that can fail in a way that stops
screening. And an insider with root on a single-operator Fabric deployment can
in practice do what an insider with root on a database can do; the ceremony
does not change the trust model when all the keys live on one box.

## Decision

**The audit trail is a hand-rolled Merkle transparency log**, in `ledger/`:

- Each verdict is canonically serialised and hashed to a leaf.
- Leaves are appended to a Merkle tree. Nothing is ever updated or deleted.
- Checkpoints — a tree size and a root hash — are signed with Ed25519 at a
  fixed interval, using the `cryptography` package.
- Signed checkpoints are published outside the box, so a later reviewer is
  comparing against something the operator cannot retroactively change.
- Inclusion and consistency proofs are computable, and verifiable by a short
  script that does not require the original system.

`ledger/interface.py` keeps the backend behind a narrow interface, so this is a
decision about the default backend rather than a permanent exclusion.

`ledger/fabric_adapter.py` exists as a stub and raises `NotImplementedError`
pointing at this ADR. It is a placeholder for the multi-agency case below, not
work in progress.

**Hyperledger Fabric is forbidden without an ADR superseding this one**, as is
any other distributed ledger.

## Consequences

**Accepted:**

- Cryptographic code written in this project rather than adopted. The mitigation
  is scope: a Merkle tree over SHA-256 with Ed25519 signatures is a few hundred
  lines of pure functions, in `core`-adjacent code with property-based tests and
  published test vectors. This is a well-specified construction, not novel
  cryptography.
- Tamper *evidence*, not tamper *prevention*. An insider with root can still
  delete the database. What they cannot do is alter a record and have it agree
  with a checkpoint that was published elsewhere. Detection, not prevention, is
  the honest goal for a single-operator system, and this ADR says so rather
  than implying otherwise.
- The word "blockchain" is not available for a pitch. If a stakeholder requires
  it, the answer is this document, not a change of architecture.

**Gained:**

- No orderers, peers, MSPs, CAs or chaincode lifecycle at a checkpoint.
- Works fully offline. Checkpoint publication is the only step that needs a
  link, and it can be batched.
- Verifiable by a third party with a short script and the public key, without
  standing up any part of this system.
- Small enough to audit end to end.

## Alternatives considered

**Hyperledger Fabric.** Rejected above: solves multi-party consensus, which is
not the problem, at an operational cost the deployment cannot carry.

**An append-only SQL table with a hash chain, no external checkpoints.** Cheaper
still, and genuinely append-only in the application. Rejected because an
attacker with database access can recompute the whole chain. Without a
checkpoint published outside the operator's control there is nothing to compare
against, and the tamper evidence is illusory.

**A managed cloud transparency log or timestamping service.** Would give strong
external anchoring. Rejected because it requires connectivity that an open
crossing may not have, and CLAUDE.md forbids cloud services. Publishing signed
checkpoints to such a service later is compatible with this design and does not
require superseding this ADR.

## Revisit when

- **Multiple independent agencies** need to write to and rely on the same
  ledger, without one of them being the trusted operator. That is the situation
  a permissioned blockchain actually addresses, and it would justify reopening
  this decision.
- A regulator or procurement requirement names a specific ledger technology as
  mandatory. In that case the requirement is the reason, and the ADR that
  supersedes this one should say so plainly rather than reverse-engineering a
  technical justification.
