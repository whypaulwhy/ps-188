"""The application, assembled from settings and refusing to run misconfigured.

There is no module-level `app`. Building one at import time would mean that
importing this module reads key files and opens a database, so a test that
merely imports the tree would fail on a machine with no deployment, and the
error would look like a broken import rather than a missing configuration.
`create_app` is the entry point, and uvicorn is told to call it.

**Every unhandled failure is answered as a failure, not as a result.** The
handler below returns 503 and says no decision was reached. The alternative is
an empty 500 body that a client is free to interpret, and the one interpretation
that must never be available is "nothing came back, so nothing was wrong".
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from api import settings as settings_module
from api.deps import Context, build_context
from api.routes import build_router
from api.settings import Settings
from ui.console import build_console

TITLE = "SENTINEL ID"
SUMMARY = "Document screening for SSB border checkpoints. Nothing here clears a person."

NO_DECISION = (
    "No decision was reached for this request, so nothing has been recorded. "
    "Treat the document as unscreened and refer it to an officer."
)


def create_app(context: Context | None = None) -> FastAPI:
    """Build the application.

    Args:
        context: A prepared context. Omitted in a deployment, where it is built
            from the environment; supplied by tests, which have their own
            database and keys.

    Returns:
        The application, with the API and the officer console mounted.

    Raises:
        ConfigurationError: If no context is given and the environment does not
            supply what has no safe default.
    """
    resolved = context if context is not None else build_context(settings_module.from_environment())

    app = FastAPI(title=TITLE, summary=SUMMARY, version=version())
    app.state.context = resolved
    app.include_router(build_router())
    app.mount("/console", build_console(resolved))

    @app.exception_handler(Exception)
    async def _fail_closed(_request: Request, _error: Exception) -> JSONResponse:
        """Answer an unhandled failure as a refusal, never as an empty success."""
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": NO_DECISION},
        )

    return app


def version() -> str:
    """Return the running version.

    Returns:
        The distribution version, or ``"unknown"`` when the package is not
        installed. Never a guess: an audit record that named the wrong version
        is worse than one that admits it does not know.
    """
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as installed_version

    try:
        return installed_version("sentinelid")
    except PackageNotFoundError:  # pragma: no cover - the package is installed in this repo
        return "unknown"


def app_for(settings: Settings, **kwargs: Any) -> FastAPI:  # noqa: ANN401 - passthrough
    """Build an application from settings directly.

    Args:
        settings: The deployment configuration.
        **kwargs: Passed to :func:`api.deps.build_context`.

    Returns:
        The application.
    """
    return create_app(build_context(settings, **kwargs))
