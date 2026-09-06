"""How Alembic reaches this deployment's database.

The URL is read from the environment, never from `alembic.ini`. A URL committed
to a configuration file is a URL somebody eventually runs a migration against
by accident, and the wrong database here means either a schema change applied
to live case records or a migration that silently did nothing.

`render_as_batch` is on because SQLite cannot alter a column in place: Alembic
rebuilds the table instead. Without it, the first migration that changes a
column would fail on the one database this system actually runs on.

`render_item` writes our own column types out as the SQLAlchemy types they are
built on. A generated migration would otherwise say `db.models.UtcDateTime`,
which makes every historical migration depend on code that is still being
edited — delete or rename that class in a year and the migration chain stops
replaying. The emitted DDL is identical either way.
"""

from __future__ import annotations

import os
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

from db.models import Base, UtcDateTime

config = context.config
target_metadata = Base.metadata

URL_VARIABLE = "SENTINELID_DB_URL"


def database_url() -> str:
    """Return the URL to migrate, refusing to invent one.

    Returns:
        The configured URL.

    Raises:
        RuntimeError: If the environment does not name a database. There is no
            default: a migration against a guessed path would create a second
            database rather than upgrading the real one.
    """
    url = os.environ.get(URL_VARIABLE, "").strip() or config.get_main_option("sqlalchemy.url", "")
    if not url:
        msg = f"{URL_VARIABLE} is not set, so there is no database to migrate"
        raise RuntimeError(msg)
    return url


def render_item(type_: str, obj: Any, autogen_context: Any) -> str | bool:  # noqa: ANN401
    """Render a custom column type as the SQLAlchemy type it is built on.

    Args:
        type_: What is being rendered.
        obj: The object being rendered.
        autogen_context: Alembic's rendering context.

    Returns:
        The replacement source, or False to let Alembic render it normally.
    """
    if type_ == "type" and isinstance(obj, UtcDateTime):
        autogen_context.imports.add("import sqlalchemy as sa")
        return "sa.DateTime(timezone=True)"
    return False


def run_migrations_offline() -> None:
    """Emit SQL for review rather than running it, for a change that needs sign-off."""
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against the configured database."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = database_url()
    engine = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            render_item=render_item,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
