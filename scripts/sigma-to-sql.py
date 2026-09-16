#!/usr/bin/env python3
"""Convert a Sigma rule to the ClickHouse SQL this project validates with — and optionally run it.

    scripts/sigma-to-sql.py rules/sigma/my-rule.yml                 # print the SELECT
    scripts/sigma-to-sql.py rules/sigma/my-rule.yml --dataset X     # restrict to one dataset
    scripts/sigma-to-sql.py rules/sigma/my-rule.yml --run           # run it and show the matching events

The same rule converts to Splunk, Elastic or Sentinel with sigma-cli; this backend exists so the rules can be checked
against the recordings in ep.win_events. Anything the backend cannot translate faithfully is an error, never a guess.
"""
import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
from chquery import QueryError, query  # noqa: E402
from sigma import SigmaError, rule_to_sql, techniques  # noqa: E402

try:
    import yaml
except ImportError:
    print("sigma-to-sql: error: PyYAML is missing (Debian: sudo apt-get install -y python3-yaml)", file=sys.stderr)
    raise SystemExit(2) from None

COLUMNS = ("ts", "hostname", "event_id", "image", "command_line", "parent_image", "target_object", "destination_ip",
           "user")


def load_rule(path: Path) -> dict:
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SigmaError(f"{path}: cannot read ({exc.strerror})") from None
    except yaml.YAMLError as exc:
        raise SigmaError(f"{path}: invalid YAML ({exc})") from None
    if not isinstance(rule, dict):
        raise SigmaError(f"{path}: a Sigma rule must be a YAML mapping")
    return rule


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rule", help="path to a Sigma rule (.yml)")
    parser.add_argument("--dataset", help="restrict the query to one dataset id")
    parser.add_argument("--run", action="store_true", help="run the query and print the matching events")
    parser.add_argument("--limit", type=int, default=20, help="rows to show with --run (default 20)")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be at least 1")

    try:
        rule = load_rule(Path(args.rule))
        where = rule_to_sql(rule)
    except SigmaError as exc:
        print(f"sigma-to-sql: error: {exc}", file=sys.stderr)
        return 1

    scope = f"dataset = '{args.dataset}' AND " if args.dataset else ""
    sql = f"SELECT {', '.join(COLUMNS)}\nFROM ep.win_events\nWHERE {scope}{where}\nORDER BY ts"
    print(f"-- {rule.get('title', '(no title)')}  [{', '.join(techniques(rule)) or 'no ATT&CK tag'}]")
    print(sql + ("" if args.run else ";"))

    if args.run:
        try:
            rows = query(sql + f" LIMIT {int(args.limit)}")
        except QueryError as exc:
            print(f"sigma-to-sql: error: {exc}", file=sys.stderr)
            return 1
        print(f"\n{len(rows)} matching events" + (" (limit reached)" if len(rows) == args.limit else ""))
        for row in rows:
            interesting = {k: v for k, v in row.items() if v not in ("", 0, None)}
            print("  " + "  ".join(f"{k}={str(v)[:70]}" for k, v in interesting.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
