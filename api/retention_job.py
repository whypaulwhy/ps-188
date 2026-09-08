"""The retention sweep, as a command.

    python -m api.retention_job --dry-run
    python -m api.retention_job

Run it from a scheduler: a `cron` entry, a `systemd` timer, a Windows scheduled
task. It is deliberately not a daemon and not a background thread inside the
API. What deletes records at a border post should be something an operator can
see in a crontab, disable, and run by hand while watching the output — not a
timer nobody configured firing inside a web server.

**It refuses to run without a policy.** `SENTINELID_RETENTION_POLICY_FILE` must
name a JSON file giving a window for every artefact category. There are no
default windows anywhere in this system, and this command does not invent one:
a sweep that guessed how long a face embedding may be kept would be destroying
records under a policy nobody agreed to.

**Why it lives in `api/`.** This package is the shell: everything that reads
the deployment's configuration and touches the outside world. The sweep itself
is in `db.retention`, which knows nothing about environment variables. Putting
the command here keeps the dependency pointing one way, api to db to core, the
same direction every other entry point in this system points.

Exit codes: 0 if the sweep ran, 2 if it was refused for want of configuration.
The distinction matters to whatever is running it — a scheduler that treats
"never configured" as success will report healthy forever while keeping
everything.
"""

from __future__ import annotations

import argparse
import datetime
import sys
from collections.abc import Sequence

from api.settings import RETENTION_POLICY_FILE, ConfigurationError, from_environment
from db.recording import RecordingError
from db.retention import SweepResult, sweep
from db.session import create_session_factory

REFUSED: int = 2
"""Exit code for a sweep that could not run. Distinct from a sweep that ran."""


def _report(result: SweepResult, *, dry_run: bool) -> str:
    """Describe what happened, in the same plain register the console uses."""
    if not result.anything_happened:
        return (
            f"Examined {result.examined} case records. "
            "None had passed its retention window, so nothing was destroyed."
        )

    verb = "would be destroyed" if dry_run else "destroyed"
    lines = [
        f"Examined {result.examined} case records. "
        f"{len(result.destroyed)} {verb}, "
        f"along with {result.reviews_destroyed} officer review(s)."
    ]
    lines.extend(f"  {case_id}" for case_id in result.destroyed)
    if dry_run:
        lines.append("Nothing was changed. Run without --dry-run to destroy these.")
    else:
        lines.append(
            "The transparency log is unchanged except for one new entry per "
            "destruction. Destroyed cases can no longer be read."
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one retention sweep against the configured database.

    Args:
        argv: Command line arguments, for testing. Defaults to `sys.argv`.

    Returns:
        A process exit code: 0 if the sweep ran, `REFUSED` if it could not.
    """
    parser = argparse.ArgumentParser(
        prog="python -m api.retention_job",
        description="Destroy case records that have passed their retention window.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be destroyed, and destroy nothing.",
    )
    arguments = parser.parse_args(argv)

    try:
        settings = from_environment()
    except ConfigurationError as error:
        print(f"Refused: {error}", file=sys.stderr)
        return REFUSED

    if settings.retention_policy is None:
        print(
            "Refused: no retention policy is configured, so this sweep does not "
            f"know how long anything may be kept. Set {RETENTION_POLICY_FILE} to a "
            "JSON file giving a window in days for every artefact category. "
            "There is deliberately no default.",
            file=sys.stderr,
        )
        return REFUSED

    factory = create_session_factory(settings.database_url)
    now = datetime.datetime.now(tz=datetime.UTC)
    try:
        with factory() as session:
            result = sweep(
                session,
                policy=settings.retention_policy,
                now=now,
                dry_run=arguments.dry_run,
            )
    except RecordingError as error:
        print(
            f"The sweep stopped: {error}\n"
            "Cases destroyed before this point stay destroyed and stay logged. "
            "Running the sweep again is safe.",
            file=sys.stderr,
        )
        return REFUSED

    print(_report(result, dry_run=arguments.dry_run))
    return 0


if __name__ == "__main__":  # pragma: no cover - the process entry point
    raise SystemExit(main())
