# ADR 0005 — Document numbers are keyed with HMAC-SHA256, not salted

- **Status:** Accepted
- **Date:** 2026-09-06
- **Supersedes:** —
- **Superseded by:** —

## Context

Rule 3 of CLAUDE.md says to store "only the UIDAI reference ID and salted
hashes", and the same for any raw document number. Implementing that literally
runs into a problem the word "salted" hides.

**The input keyspace is tiny.** An Aadhaar number is twelve digits, and UIDAI
issues none beginning with 0 or 1, so there are roughly 9x10^11 possible
values. That is not a large number. Given a digest and the salt that produced
it, an attacker enumerates the whole space on ordinary hardware in a short
time. The strength of the hash function is irrelevant, because what is being
attacked is the input, not the function.

A salt is, by construction, **unique but not secret**. It is normally stored
beside the data it protects — in the same database, or in the same
configuration file that ships with it. Its job is to stop precomputation and
cross-database correlation, not to stop enumeration. Against a twelve-digit
input, a public salt buys almost nothing: whoever takes the database takes the
salt with it, and then takes every number.

So the real question is not which hash function, but whether the secret is
public or secret.

## Decision

**HMAC-SHA256 with a per-deployment key**, held outside the database.

- The key is at least 32 bytes from a secure random source.
- Key material never leaves `DeploymentKey`: callers ask the object to derive a
  digest rather than reading the bytes out, and its `repr` is redacted so a key
  cannot reach a traceback or a log.
- Digests are **domain-separated by document kind**, so the same digits
  recorded as a voter card number and as a driving licence number produce
  different values and do not silently link two unrelated records.
- Digest comparison uses a constant-time function, because phase 8 compares
  digests to find repeat crossings.

**This is pseudonymisation, not anonymisation, and the documentation says so.**
Compromise of the key *and* the database recovers every number by enumeration.
No construction available here changes that, and claiming otherwise would be
the same error as calling a face embedding irreversible, which rule 4 forbids
for exactly the same reason.

The raw number never reaches this module as a bare `str`. It arrives as a
`RawIdentifier`, which masks itself in `str`, `repr`, f-strings and logs, and
which Pydantic refuses to give a schema — so a contract field of that type
fails at class definition rather than leaking at serialisation time.

## Consequences

**Accepted:**

- **Key management becomes a deployment responsibility**, and a real one. The
  key must be backed up, stored outside the database, and kept out of the
  configuration that ships alongside it. Losing it makes every existing digest
  unmatchable.
- **Rotating the key invalidates every stored digest.** Repeat-identity
  matching across a rotation is not possible without keeping the old key, which
  is a decision for whoever rotates, not something this module hides.
- The threat model gains a new high-value target: key plus database. It is
  listed in `docs/threat-model.md` alongside the issuer trust store.
- A checkpoint box that cannot hold a secret outside its own database gets
  weaker protection than this design assumes. That is worth knowing before
  deployment rather than after.

**Gained:**

- Digests are not reversible by an attacker who obtains only the database,
  which is the realistic theft scenario.
- Two deployments cannot correlate their records without sharing a key.
- Domain separation prevents accidental linkage between document types.
- Standard library only: `hmac`, `hashlib`, `secrets`. No new dependency, and
  `core` stays free of anything the purity contract forbids.

## Alternatives considered

**Plain SHA-256 with a per-deployment salt.** The literal reading of rule 3 and
the simplest thing that works. Rejected because a fast unkeyed hash over a
twelve-digit space is reversed by anyone who obtains the salt, and the salt
normally travels with the data. This would satisfy the letter of the rule while
providing close to none of its intent.

**Argon2id with a per-deployment salt.** Memory-hard, so enumeration stays
expensive even when the salt is known — genuinely stronger against the specific
scenario where the secret leaks. Rejected on three grounds: it adds a
dependency (`argon2-cffi`); it makes every lookup slow, which matters in phase 8
where digests are compared across a day's crossings; and against a twelve-digit
keyspace a determined attacker with the parameters can still enumerate, so it
raises the cost without changing the conclusion. A keyed construction addresses
the realistic threat — database theft — more directly.

**Argon2id keyed and salted.** Strictly the strongest option, and the honest
answer to "what if the key leaks too". Not taken now because the lookup cost is
paid on every crossing for a benefit that only applies after the key is already
compromised. Revisit if a threat assessment says key compromise is likely.

**Store nothing at all, not even a digest.** Would make repeat-identity
detection impossible, which is a Rung 3 capability the system is expected to
have — and which matters more here than usual, since Rung 0 is unavailable for
most traffic on these borders (see `docs/scope.md`).

## Revisit when

- A threat assessment concludes that key compromise is a likely scenario rather
  than a catastrophic-but-unlikely one. The answer then is keyed Argon2id, and
  the lookup cost becomes worth paying.
- The deployment environment turns out to have no way to hold a secret outside
  the database, which would make the key and the data share a fate and reduce
  this to the salted case.
- UIDAI reference identifiers replace digests for the Aadhaar path entirely, at
  which point the Aadhaar branch of this decision may no longer be needed.
