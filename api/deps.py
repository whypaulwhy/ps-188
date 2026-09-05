"""FastAPI dependency providers: database session, detector registry, deployment settings."""

from __future__ import annotations


def get_settings() -> object:
    """Return the deployment settings object. Not yet implemented."""
    raise NotImplementedError("api.deps lands in phase 9")
