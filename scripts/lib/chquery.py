"""Run read-only queries against the ep database in the NSM lab's ClickHouse container.

Everything goes through `docker exec ... clickhouse-client`, so no credentials live in this repository and no port is
exposed. Only SELECTs belong here; writing is done by load-dataset.sh.
"""
import json
import os
import shutil
import subprocess

CONTAINER = os.environ.get("EP_CH_CONTAINER", "nsm-clickhouse")


class QueryError(Exception):
    """ClickHouse is unreachable or the query failed."""


def query(sql: str, params: dict | None = None) -> list[dict]:
    """Run a SELECT and return its rows as dicts.

    Parameters are passed as ClickHouse query parameters ({name:String} in the SQL), never string-formatted, so a
    dataset id or a host name out of the data cannot change the query.
    """
    if shutil.which("docker") is None:
        raise QueryError("docker is not installed")
    command = ["docker", "exec", "-i", CONTAINER, "clickhouse-client", "--database", "ep",
               "--format", "JSONEachRow", "--query", sql]
    for name, value in (params or {}).items():
        command.insert(-2, f"--param_{name}={value}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QueryError(f"could not run clickhouse-client: {exc}") from None
    if result.returncode != 0:
        # clickhouse-client echoes the whole query after the error, so pick the exception line, not the last line
        lines = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
        detail = next((line for line in lines if "Exception" in line), lines[0] if lines else "")
        raise QueryError(detail or f"clickhouse-client exited {result.returncode}")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def scalar(sql: str, params: dict | None = None):
    rows = query(sql, params)
    return next(iter(rows[0].values())) if rows else None
