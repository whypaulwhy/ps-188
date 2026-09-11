#!/usr/bin/env python3
"""Check the face models on your own images, without a server or a database.

    python tools/face_check.py DOCUMENT.jpg SELFIE.jpg
    python tools/face_check.py DOCUMENT.jpg FRAME1.jpg FRAME2.jpg FRAME3.jpg

The first image is the document. The rest are photographs of the person. Two or
more of those and the liveness check runs as well, because a single photograph
cannot show whether a real person was present.

**Why this exists.** Nothing in this repository can validate face comparison:
there is no lawfully obtained corpus of faces here, and `datagen` deliberately
draws a flat panel rather than a portrait, because generating images of people
who do not exist in order to test a border system is a line this project does
not cross. So the only way to see whether the models work is to point them at
faces you are entitled to use — yours.

**Your images stay where they are.** This reads them, compares in memory, and
prints numbers. Nothing is written, stored or sent anywhere. The embeddings it
computes are dropped when the process ends: they are partially invertible
representations of a face, never anonymous ones, and this tool has nowhere to
put one even if it wanted to.

Set `SENTINELID_FACE_MODEL_ROOT` to the directory holding `models/buffalo_l/`
first, or nothing here can run.
"""

from __future__ import annotations

import pathlib
import sys


def main(argv: list[str]) -> int:
    """Compare a document photograph against one or more photographs of a person."""
    from detectors.rung2_inference import face_engine, face_match, pad_liveness

    if len(argv) < 2:
        print(__doc__)
        return 2

    if not face_engine.available():
        print(
            f"The face models are not configured. Set {face_engine.MODEL_ROOT_ENV} to the\n"
            "directory that holds models/buffalo_l/, for example:\n"
            '  $env:SENTINELID_FACE_MODEL_ROOT = "C:\\Users\\you\\.insightface"'
        )
        return 2

    paths = [pathlib.Path(name) for name in argv]
    for path in paths:
        if not path.is_file():
            print(f"Not a file: {path}")
            return 2

    print(f"Models: {face_engine.model_root()}\n")

    document, *captures = paths
    on_document = face_engine.faces(document.read_bytes())
    print(f"{document.name}: {len(on_document)} face(s) found")
    if not on_document:
        print("  No face on the document. Nothing can be compared.")
        return 1
    print(f"  confidence {on_document[0].confidence:.3f}")

    frames = []
    for capture in captures:
        found = face_engine.faces(capture.read_bytes())
        print(f"{capture.name}: {len(found)} face(s) found")
        if found:
            print(f"  confidence {found[0].confidence:.3f}")
            frames.append(found[0])

    if not frames:
        print("\nNo face in any photograph of the person. Nothing can be compared.")
        return 1

    similarity = face_engine.similarity(on_document[0], frames[0])
    suspicion = face_match.suspicion(similarity)
    print("\n--- face comparison ---")
    print(f"  similarity  {similarity:+.4f}   (higher means more alike)")
    print(f"  suspicion   {suspicion:.4f}   (higher sends it to a person)")
    print(f"  threshold   {face_match.SUSPICION_THRESHOLD}  <- uncalibrated, see the module")
    print(f"  would escalate: {suspicion >= face_match.SUSPICION_THRESHOLD}")

    print("\n--- liveness ---")
    if len(frames) < pad_liveness.MINIMUM_FRAMES:
        print("  Only one photograph of the person, so liveness was not established.")
        print("  Pass two or more frames taken a moment apart to run this check.")
        return 0

    moved = pad_liveness.movement(frames)
    print(f"  shape change {moved:.5f}   (after removing how the picture moved)")
    print(f"  threshold   {pad_liveness.STILLNESS_THRESHOLD}  <- uncalibrated")
    if moved < pad_liveness.STILLNESS_THRESHOLD:
        print("  would escalate: True - the face only moved as a whole, like a held picture")
        print("  If this is a real person, they need to turn their head between frames.")
    else:
        print("  would escalate: False - the face changed shape, as a turning head does")
        print("  This does not establish a live person. A video replay would move too.")
    return 0


if __name__ == "__main__":  # pragma: no cover - the process entry point
    raise SystemExit(main(sys.argv[1:]))
