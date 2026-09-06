"""The migration chain, and whether it still agrees with the models.

`create_all` is a test convenience. A deployment migrates, and the failure this
file exists to catch is the quiet one: somebody adds a column to `db/models.py`,
the tests pass because they build their schema with `create_all`, and the
migration is never written. The next deployment then upgrades to a schema
missing that column and falls over on the first write.

So the check is not "does the migration run". It is "does the schema the
migration produces differ from the models", asked by Alembic's own comparison,
which is the same machinery `--autogenerate` uses.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from db.models import Base

REPO = pathlib.Path(__file__).parents[2]
CONFIG = REPO / "alembic.ini"
EXPECTED_TABLES = {"case_record", "ledger_leaf", "review_record"}


@pytest.fixture
def migrated(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the URL of a database brought up to head by the real migrations."""
    url = f"sqlite+pysqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    monkeypatch.setenv("SENTINELID_DB_URL", url)
    command.upgrade(_config(), "head")
    return url


def _config() -> Config:
    """Return the project's Alembic configuration, with paths resolved."""
    config = Config(str(CONFIG))
    config.set_main_option("script_location", str(REPO / "db" / "migrations"))
    return config


def test_the_configuration_names_no_database() -> None:
    """A URL in the ini file is a URL somebody eventually migrates by accident."""
    assert _config().get_main_option("sqlalchemy.url", "") == ""


def test_there_is_exactly_one_head() -> None:
    """Two heads mean two people wrote a migration and neither merged them."""
    assert len(ScriptDirectory.from_config(_config()).get_heads()) == 1


def test_the_migration_creates_every_table(migrated: str) -> None:
    """The ordinary path, so the comparison below is comparing something real."""
    tables = set(inspect(create_engine(migrated)).get_table_names())

    assert tables >= EXPECTED_TABLES
    assert "alembic_version" in tables


def test_the_migration_and_the_models_agree(migrated: str) -> None:
    """The check that catches a model change nobody wrote a migration for.

    Alembic's own comparison, which is what `--autogenerate` uses. An empty
    result means a fresh deployment and a migrated one reach the same schema.
    """
    engine = create_engine(migrated)
    with engine.connect() as connection:
        differences: list[Any] = compare_metadata(
            MigrationContext.configure(connection), Base.metadata
        )

    assert differences == [], f"the models and the migrations disagree: {differences}"


def test_the_chain_can_be_undone_and_redone(migrated: str) -> None:
    """A migration that cannot be rolled back cannot be tested before it is run."""
    engine = create_engine(migrated)
    config = _config()

    command.downgrade(config, "base")
    assert EXPECTED_TABLES & set(inspect(engine).get_table_names()) == set()

    command.upgrade(config, "head")
    assert set(inspect(engine).get_table_names()) >= EXPECTED_TABLES


def test_migrating_without_a_database_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A guessed path would create a second database rather than upgrade the real one."""
    monkeypatch.delenv("SENTINELID_DB_URL", raising=False)

    with pytest.raises(RuntimeError, match="SENTINELID_DB_URL"):
        command.upgrade(_config(), "head")
