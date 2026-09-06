# ADR 0004 — The extraction contract lives in `core`, and pixel extraction waits for fixtures

- **Status:** Accepted
- **Date:** 2026-09-06
- **Supersedes:** —
- **Superseded by:** —

## Context

A detector has to be handed something. Until phase 2 that something was typed
`object`, with a note in `detectors/base.py` saying the real type would be
designed "in phase 2 against real captures".

Phase 2 arrived and there are no real captures. Phase 1 deliberately committed
**data-level fixtures only** — MRZ strings, check-digit vectors, printed-field
records — and deferred images to phase 6, where `datagen/` generates them. That
left two questions that turned out to be the same question.

**Where does the contract live?** The obvious home is `extraction/`, next to
the code that produces it. But `setup.cfg` forbids `core` from importing NumPy,
OpenCV, ONNX Runtime, PyTorch or Pillow, and CLAUDE.md rule 5 forbids `core` and
`detectors` from reaching into the outer shell. If the type a detector receives
lives in `extraction/` and holds a decoded image, then every detector imports
NumPy and OpenCV transitively the moment it imports its own input type. The
purity rule survives in `setup.cfg` and dies in practice.

**Can `extraction/` itself be built now?** Preprocessing, MRZ location, QR
decoding and OCR are pixel code. With no image fixtures, none of it can be
meaningfully tested. Writing it anyway means shipping untested pixel code into a
border screening system and marking a phase complete on the strength of it. It
also means adding OpenCV, NumPy, Pillow and RapidOCR — which pulls ONNX Runtime
— to a project that does not yet need any of them.

## Decision

**The extraction contract is `core/contracts/subject.py`.** A `Subject` carries
provenance, a declared document type, decoded codes, located text zones, the raw
artefact bytes, and an explicit `not_extracted` list. Image data is carried
**opaquely, as bytes**. A detector that needs pixels decodes them with its own
libraries; `core` never does, and the import-linter contract stays true rather
than nominal.

**`extraction/` moves to phase 6**, alongside the synthetic images that can
exercise it. `qr_decode.py` moves with it, even though phase 4 was originally
written as needing it: the Rung 0 detectors verify signatures over payload
bytes, and those payloads can be committed as data-level fixtures exactly as the
MRZ strings were.

**The contract is deliberately minimal and is expected to grow in phase 6.**
Growing it then is not a redesign and does not supersede this ADR. What is fixed
here is where it lives and that images stay opaque to `core`; what is provisional
is the field list.

## Consequences

**Accepted:**

- `Subject` was designed without real captures, against what phases 4 and 5
  need. Phase 6 will find it incomplete. That is planned for, not a surprise.
- Carrying artefact bytes in the contract means a case holds its images in
  memory. For one document at a time at a checkpoint this is fine; if batch
  processing ever appears, this is the field to revisit.
- The roadmap now has a phase that did not deliver the file list it originally
  advertised. Recording that plainly is the point of this document.
- The end-to-end path from photograph to verdict is not demonstrable until
  phase 6. For a competition deliverable that is a real scheduling risk, and it
  is called out in the roadmap rather than discovered late.

**Gained:**

- `core` and `detectors` genuinely import no image library. The boundary is
  enforceable, not aspirational.
- Detectors are unit-testable against constructed `Subject`s with no fixtures,
  no I/O and no model runtime.
- Phases 4 and 5 are unblocked and can proceed on committed data-level
  fixtures, which is how the golden harness already builds subjects.
- No image dependency enters the project until something can test it.

## Alternatives considered

**Put the contract in `extraction/`.** Conventional, and it keeps the type next
to its producer. Rejected because it makes every detector depend transitively on
the vision stack and hollows out rule 5.

**Keep `subject: object` and defer the whole question to phase 6.** Honest about
the uncertainty, but leaves phases 4 and 5 with no typed input, so every detector
and every golden case would need rewriting later. The cost of a minimal contract
that grows is much lower than the cost of no contract at all.

**Hold a decoded image in the contract behind a protocol.** Would let `core`
describe pixels without importing NumPy. Rejected as premature: no consumer
exists yet, and designing an abstraction for pixel access before any code reads a
pixel is guessing.

**Pull image generation forward into phase 2** so extraction could be built and
tested immediately. This was genuinely considered and is the main alternative.
Rejected because it pulls a large part of phase 6 forward, adds four heavy
dependencies before anything needs them, and means designing the extraction
contract against images this project generated rather than real captures — which
is the same weakness, with more code built on top of it.

## Revisit when

- Real captures exist and `Subject` is found to be the wrong shape rather than
  merely incomplete. Growing the field list does not need a new ADR; changing
  where the contract lives, or letting `core` decode an image, does.
- Batch processing makes carrying artefact bytes in memory a problem.
