"""Optional local language model used only to rephrase rendered text; it never decides anything."""

from __future__ import annotations


def rephrase(text: str) -> str:
    """Rephrase already-rendered officer text. Optional, off by default, never decides."""
    raise NotImplementedError("explain.llm_client is optional and lands after phase 9")
