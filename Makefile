# SENTINEL ID developer entry points.
#
# `make check` is the gate. CLAUDE.md requires it to be run after any change and
# its result reported honestly, including failures.

UV ?= uv
RUN := $(UV) run

.PHONY: check lint format types imports test sync clean

check: lint types imports test

## Install the locked environment, including the dev dependency group.
sync:
	$(UV) sync

## Style and static rules over the whole repository.
lint:
	$(RUN) ruff check .
	$(RUN) ruff format --check .

## Rewrite formatting in place. Not part of `check`.
format:
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

## Strict typing over the decision logic only, per CLAUDE.md.
types:
	$(RUN) mypy --strict core

## Architecture boundary: core/ and detectors/ cannot reach api/, db/ or ui/.
imports:
	$(RUN) lint-imports

## Tests, with branch coverage of core/ gated at 100%.
test:
	$(RUN) pytest

clean:
	$(RUN) python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage
