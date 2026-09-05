# ADR 0002 — ONNX Runtime for inference, PyTorch only for TruFor

- **Status:** Accepted
- **Date:** 2026-09-06
- **Supersedes:** —
- **Superseded by:** —

> **Note on authorship.** Written from the constraints fixed in CLAUDE.md
> rather than from a recorded discussion. Correct it if the reasoning that
> actually drove the decision differs.

## Context

SENTINEL ID runs several learned models: tamper localisation, face embedding
and matching, presentation attack detection, and OCR. They run on a checkpoint
box with **no GPU**, and they have to produce the same answer today, next
month, and when a decision is replayed from the audit ledger two years from now.

Three constraints shape the choice of runtime.

**Reproducibility is a legal requirement here, not an engineering preference.**
`Evidence.model_version` goes into the audit trail. If a decision is challenged,
the system has to be able to demonstrate what the model did. A framework whose
result can shift with a minor version bump, a different BLAS backend or a
kernel-selection heuristic makes that demonstration weaker.

**The install has to be small and offline-installable.** A CUDA-enabled PyTorch
wheel is a multi-gigabyte download that pulls in a GPU stack the checkpoint box
will never use. It has to be shipped, stored and updated over a link that may
be a phone tether.

**Model artefacts should be inspectable.** An `.onnx` file is a graph with a
declared opset and fixed weights. It can be hashed, pinned and diffed. A
`.pt` checkpoint loaded through arbitrary Python is a different kind of object,
and `torch.load` on an untrusted file is an execution risk.

Against this: TruFor, the tamper localisation model this project intends to
use, is published as PyTorch. No ONNX export exists that this project has
validated as faithful, and exporting it is real work that has not been done.

## Decision

**ONNX Runtime, CPU execution provider, is the inference runtime.** Every model
ships as a pinned `.onnx` artefact with a recorded SHA-256 and a
`model_version` string that reaches the audit record.

**PyTorch is permitted in exactly one module**, `detectors/rung2_inference/tamper_trufor.py`,
subject to three conditions:

1. **CPU-only builds.** CUDA PyTorch is forbidden without a superseding ADR.
2. **Lazy import.** The `import torch` happens inside the function that needs
   it, not at module import. Nothing else in the system pays for it, and a
   deployment without TruFor does not need it installed at all.
3. **Honest degradation.** If the import or the weights fail, the detector
   returns `Evidence` with `result=INCONCLUSIVE` and a reason an officer can
   read. It never raises past its own boundary and never silently reports
   `NO_FINDING`. A missing model is reported as a missing check, which lands in
   `Verdict.not_checked`.

TensorFlow and any cloud inference API are forbidden outright — the first
because it is a third full framework for no gain, the second because it puts a
traveller's document on someone else's server and makes screening depend on a
link that may not exist.

## Consequences

**Accepted:**

- Any new model must be exportable to ONNX, or it goes through the same
  narrow exception TruFor has. This will occasionally rule out a model that
  would otherwise be a good fit.
- Export is real work: verifying that the exported graph agrees with the
  original across the operating range is a task, not a command.
- Two inference paths exist, which is two things to keep working.

**Gained:**

- One small CPU-only runtime for almost everything.
- Model artefacts that can be hashed and pinned, so `model_version` in the
  audit record means something specific.
- No GPU stack in the deployment image.
- Degradation that is visible: a model that will not load produces a stated
  missing check rather than an absence.

**Explicitly not claimed:** no latency, throughput or memory figure appears in
this ADR, because none has been measured. Rule 2 of CLAUDE.md applies to
architecture documents exactly as it applies to code. When `eval/run_eval.py`
has run, the numbers go in `eval/reports/` and can be cited from here.

## Alternatives considered

**PyTorch CPU everywhere.** Simpler — one framework, no export step, direct use
of published research models. Rejected on install size, on the weaker
reproducibility story for an audited decision, and because `torch.load` on
model files is a larger attack surface than loading a graph.

**TorchScript or `torch.compile` artefacts.** Better than raw checkpoints for
pinning, but still ties the deployment to the full PyTorch install, which is
the main cost being avoided.

**A cloud inference API.** Forbidden by CLAUDE.md and by the setting. An open
crossing may have no usable link, and sending a traveller's identity document
to a third party is not acceptable regardless of latency.

## Revisit when

- A validated ONNX export of TruFor exists and agrees with the PyTorch model
  across the evaluation set. At that point the exception in
  `tamper_trufor.py` is removed and PyTorch leaves the dependency list.
- A measured bottleneck reported in `eval/reports/` shows ONNX Runtime CPU
  cannot meet the throughput a checkpoint needs. The answer then is most likely
  a smaller model or better hardware, not a different framework — but the
  question would be genuinely open.
