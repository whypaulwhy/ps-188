# SENTINEL ID deployment image.
#
# Phase 0 builds the environment and runs the gate. There is no application
# entrypoint yet: api/ and ui/ are stubs until phase 9, and this file will grow
# a CMD when there is something to serve. Building it now keeps the deployment
# path honest — if the image cannot be built, we find out today rather than in
# phase 9.

FROM python:3.12-slim-bookworm

# uv manages the interpreter, the dependencies and the lock file. Pinned by
# digest-free tag here; pin exactly before any real deployment.
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first, so a source change does not invalidate the layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

# The gate runs inside the image. An image that cannot pass `make check` is not
# a deployable image.
RUN uv run ruff check . \
    && uv run mypy --strict core \
    && uv run lint-imports \
    && uv run pytest -q

# No CMD yet. Phase 9 adds:
#   CMD ["uv", "run", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
