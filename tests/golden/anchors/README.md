# Golden trust anchors

Self-signed test issuer certificates, used to build a `TrustStore` for the
Rung 0 golden cases. Each was created with an ephemeral RSA-2048 key that
was **not retained**, so no private key exists anywhere in this repository
and these fixtures cannot be re-signed, only verified.

These are not real issuer certificates and must never be loaded by a
deployment. Real anchors are reviewed configuration; see ADR 0005 and
`docs/threat-model.md`, which names the trust store as the highest-value
target in the system.
