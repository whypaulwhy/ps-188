# SENTINEL ID deployment image.
#
# The gate runs inside the image: one that cannot pass `make check` is not a
# deployable image. That is checked at build time rather than trusted.
#
# The container serves the API and the officer console from one process. It does
# not migrate on start-up — see the note by the CMD.

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

# Migrations are NOT run here. A container that migrates on start-up will, on a
# checkpoint that restarts two instances after a power cut, run two migrations
# against one SQLite file. Run it deliberately, once, before starting:
#
#   docker compose run --rm sentinelid uv run alembic upgrade head
#
# `--factory` because api.app has no module-level app: building one at import
# time would read key files and open a database just to import the module, and
# a missing key would surface as a broken import rather than as a missing key.
EXPOSE 8000
CMD ["uv", "run", "uvicorn", "api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
