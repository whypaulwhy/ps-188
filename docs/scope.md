# Scope

What SENTINEL ID accepts, what it refuses to judge, and what it does not do.

This document exists because the most dangerous failure mode of a screening
system is not a missed forgery. It is an officer believing the system checked
something it did not check.

## The setting

The SSB guards the India–Nepal and India–Bhutan borders. The India–Nepal border
is open: under the 1950 Treaty of Peace and Friendship, Nepali nationals cross
without a passport or visa, presenting a citizenship certificate, a voter card,
or in practice whatever identity document they carry. Traffic is heavy, largely
local, and the document mix is far wider than at an airport.

This has a consequence that shapes everything below, and it is stated here
rather than discovered in phase 6:

> **Most documents presented at these crossings carry nothing a machine can
> verify.** A Nepali citizenship certificate has no machine-readable strip, no
> barcode and no digital signature. Neither does a Bhutanese citizenship card.
> For those documents the highest achievable outcome is `MANUAL_REVIEW`, and
> that is the correct answer, not a limitation to be engineered away.

The value of this system on these borders is therefore **triage and evidence**,
not clearance. It tells an officer what it checked, what it could not check,
and what looked wrong. Clearance is the exception, available only where an
issuer has signed something.

## Accepted documents

| Document | Issuer | Machine-verifiable feature | Highest rung reachable | Best achievable outcome |
|---|---|---|---|---|
| Aadhaar with a readable Secure QR | UIDAI | UIDAI signature over the QR payload | 0 | `CLEARED` |
| DigiLocker-issued document | DigiLocker / issuing authority | XML signature or signed PDF | 0 | `CLEARED` |
| Aadhaar as photocopy or with unreadable QR | UIDAI | Number format only | 1 | `MANUAL_REVIEW` |
| Indian passport | MEA | ICAO 9303 strip arithmetic; chip only with a reader | 1 (0 with hardware) | `MANUAL_REVIEW` |
| Nepali passport | Nepal DoP | ICAO 9303 strip arithmetic; chip only with a reader | 1 (0 with hardware) | `MANUAL_REVIEW` |
| Bhutanese passport | Bhutan DoI | ICAO 9303 strip arithmetic; chip only with a reader | 1 (0 with hardware) | `MANUAL_REVIEW` |
| Indian driving licence | State transport authority | Layout and field consistency; QR content varies by state | 1 | `MANUAL_REVIEW` |
| EPIC voter card | ECI | Layout and field consistency | 1 | `MANUAL_REVIEW` |
| Nepali citizenship certificate | District Administration Office | **None** | 1 (`NOT_APPLICABLE` only) | `MANUAL_REVIEW` |
| Nepali national identity card | Nepal DoNIDCR | Chip only with a reader | 1 | `MANUAL_REVIEW` |
| Bhutanese citizenship identity card | Bhutan DCRC | **None** | 1 (`NOT_APPLICABLE` only) | `MANUAL_REVIEW` |

Read the last column. Under the current scope, **exactly two of eleven accepted
document types can ever be cleared automatically**, and both are Indian.

## Refused documents

These are not screened. The system reports that it does not recognise the
document and routes the case to an officer with that stated plainly. Refusing
is a valid answer and is preferable to producing a judgement the system has no
basis for.

- Any document type not listed above.
- Handwritten or hand-amended documents, including certificates with manual
  corrections. There is no machine-checkable template.
- Documents for which no issuer template exists in the corpus.
- Non-identity documents offered as identity: employer cards, student cards,
  ration cards, club or association cards.
- Photographs of a screen showing a document. The presentation attack detector
  may flag these from phase 7, but the document itself is not screened.
- Documents belonging to a third party, presented on someone else's behalf.

## What this system does not do

This is the phase-1 exit criterion, and the section to read first if you are
deciding whether to trust it.

1. **It does not establish who a person is.** It examines a document. It does
   **not** currently compare the portrait against the person presenting it:
   face matching is built but has no model and no lawful face corpus to
   validate against, so it abstains on every crossing and says so. Even when it
   works, a face comparison is not proof of identity.
2. **It does not clear anyone without cryptographic proof of issuance.** No
   volume of clean checks adds up to a clearance. Both the trust ladder and the
   `Verdict` contract refuse it.
3. **It does not read chips.** There is no reader at the checkpoint, so
   ePassport passive authentication never runs. Every case involving a chipped
   document says so explicitly rather than omitting the check.
4. **It does not decide.** `MANUAL_REVIEW` means a human decides, and it will
   be the most common outcome by a wide margin.
5. **It does not detect every forgery, and it does not claim to.** Rung 2 can
   only escalate. A forgery it misses produces `MANUAL_REVIEW` at worst, never
   `CLEARED`, because Rung 2 never participates in clearing.
6. **It does not check anything against an issuer's database.** No network
   calls, no cloud services, no UIDAI authentication API. Everything is
   verified offline from the document itself and pinned public keys.
7. **It does not certify a Nepali or Bhutanese document as genuine.** There is
   nothing in those documents for a machine to verify. "Nothing was found
   wrong" is not the same statement as "this is genuine", and the console must
   never render it as though it were.
8. **It does not store Aadhaar numbers, or any raw document number.** Only a
   salted hash and, where applicable, the UIDAI reference identifier.
9. **It does not score people.** Scores exist only inside Rung 2 evidence,
   describe suspicion about an artefact, and never reach the officer as a
   number.
10. **It has no measured accuracy.** `eval/run_eval.py` has not been run. Any
    figure quoted about this system today is invented, whoever quotes it.

## Facts to confirm with the deploying unit

Written without access to the operational environment. Each affects scope and
should be confirmed before the remaining Rung 0 work can proceed:

- **A decision on face data, before any face matching is validated.** No face
  corpus may be used without a documented lawful basis and a consent record.
  This is recorded now, unresolved, so that it is decided deliberately rather
  than by whoever first needs a test to pass. It governs both `face_match` and
  `pad_liveness`, and it is a question about people rather than about data.
- **A real Aadhaar Secure QR specimen, and the UIDAI certificate.** This is
  the single blocking item for clearance. Without it the Aadhaar detector cannot be written,
  and one of the two document types in this table that can reach `CLEARED` does
  not work. See `detectors/rung0_crypto/aadhaar_secure_qr.py` for exactly what
  is needed.
- The actual document mix at the target crossings, by volume. The table above
  assumes Nepali documents dominate; if it is mostly Indian documents with
  readable Aadhaar QRs, the clearance path is far wider than assumed here.
- Whether chip reader hardware could be procured. It converts three passport
  rows in the table from Rung 1 to Rung 0 and is the single highest-value
  change available to this project.
- Whether the Nepali national identity card's chip is readable with commodity
  hardware, and under what authority.
- The exact current formats of the Bhutanese CID and the Nepali citizenship
  certificate, including regional variation. The phase-1 fixtures are
  structurally plausible placeholders, not verified transcriptions.
- Whether `MANUAL_REVIEW` at the rate this scope implies is operationally
  acceptable, and what the officer's throughput budget per traveller actually
  is.

The last one is not a technical question, and it decides whether this system is
deployable.
