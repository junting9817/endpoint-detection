#!/usr/bin/env python3
"""Lint the Sigma rules, run each one over every loaded dataset, and score the result (docs/workflow.md step 8).

A rule is only useful if it fires where it must and stays quiet everywhere else. Every other dataset in ep.win_events
is the control group: a credential-theft rule firing on an execution recording is a finding, not a coincidence.

Writes rules/validation.txt and rules/validation.json. Called by scripts/validate-rules.sh.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
from chquery import QueryError, query  # noqa: E402
from sigma import SigmaError, rule_to_sql, techniques  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LEVELS = ("informational", "low", "medium", "high", "critical")
REQUIRED = ("title", "id", "description", "author", "date", "logsource", "detection", "falsepositives", "level", "tags")


class PlanError(Exception):
    """Unusable input: exit 2."""


# --------------------------------------------------------------------------- rules
def load_rules(directory: Path) -> list[dict]:
    """Every rules/sigma/*.yml with its parsed content, SQL and lint findings."""
    rules = []
    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        entry = {"path": path, "name": path.stem, "rule": None, "sql": None, "lint": []}
        try:
            content = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            entry["lint"].append(("FAIL", f"cannot read as YAML ({exc})"))
            rules.append(entry)
            continue
        if not isinstance(content, dict):
            entry["lint"].append(("FAIL", "a Sigma rule must be a YAML mapping"))
            rules.append(entry)
            continue
        entry["rule"] = content
        try:
            entry["sql"] = rule_to_sql(content)
        except SigmaError as exc:
            entry["lint"].append(("FAIL", f"cannot be converted: {exc}"))
        rules.append(entry)
    return rules


def lint_rules(rules: list[dict], readme: Path) -> None:
    """Fill each entry's lint list: required fields, ids, ATT&CK tags, documentation."""
    documented = ""
    if readme.is_file():
        documented = re.sub(r"<!--.*?-->", "", readme.read_text(encoding="utf-8"), flags=re.S)
    seen_ids: dict[str, str] = {}
    for entry in rules:
        rule = entry["rule"]
        if not rule:
            continue
        add = entry["lint"].append
        for field in REQUIRED:
            if not rule.get(field):
                add(("FAIL", f"missing '{field}'"))
        rule_id = str(rule.get("id", ""))
        if rule_id and not UUID_RE.match(rule_id):
            add(("FAIL", "id must be a UUID (uuidgen)"))
        if rule_id in seen_ids and seen_ids[rule_id] != entry["name"]:
            add(("FAIL", f"id is already used by {seen_ids[rule_id]}"))
        seen_ids[rule_id] = entry["name"]
        if rule.get("date") and not DATE_RE.match(str(rule["date"])):
            add(("FAIL", "date must be YYYY-MM-DD"))
        if rule.get("level") and str(rule["level"]).lower() not in LEVELS:
            add(("FAIL", f"level must be one of {', '.join(LEVELS)}"))
        if not techniques(rule):
            add(("WARN", "no attack.tXXXX tag, so this rule cannot count towards ATT&CK coverage"))
        if isinstance(rule.get("falsepositives"), list) and any(
                str(fp).strip().lower() in ("unknown", "none", "") for fp in rule["falsepositives"]):
            add(("WARN", "falsepositives says 'unknown': name the legitimate behaviour or say why there is none"))
        title = str(rule.get("title", "")).strip()
        if title and f"## {title}" not in documented:
            add(("FAIL", f"no '## {title}' entry in rules/README.md (add it in the same commit)"))
        if str(rule.get("status", "")).lower() not in ("experimental", "test", "stable"):
            add(("WARN", "status should be experimental, test or stable"))


# --------------------------------------------------------------------------- expected.yaml
def load_expected(path: Path, rule_names: set[str]) -> dict:
    if yaml is None:
        raise PlanError("PyYAML is not installed (Debian: sudo apt-get install -y python3-yaml)")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PlanError(f"{path}: cannot read ({exc.strerror})") from None
    except yaml.YAMLError as exc:
        raise PlanError(f"{path}: invalid YAML ({exc})") from None
    errors: list[str] = []
    if not isinstance(data, dict):
        raise PlanError(f"{path}: must be a mapping with 'version' and 'rules'")
    for key in data:
        if key not in ("version", "rules"):
            errors.append(f"unknown key '{key}'")
    if data.get("version") != 1:
        errors.append("version must be 1")
    entries = data.get("rules") or []
    if not isinstance(entries, list):
        raise PlanError(f"{path}: 'rules' must be a list")

    expectations: dict[str, dict] = {}
    for index, entry in enumerate(entries):
        where = f"rules[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        for key in entry:
            if key not in ("rule", "expect", "allow", "note"):
                errors.append(f"{where}: unknown key '{key}'")
        name = entry.get("rule")
        if not isinstance(name, str) or not name:
            errors.append(f"{where}.rule: required (the rule file name without .yml)")
            continue
        where = f"rules[{index}] ({name})"
        if name not in rule_names:
            errors.append(f"{where}: no such rule in rules/sigma/")
        if name in expectations:
            errors.append(f"{where}: listed twice")
        expect, allow = [], []
        for key, target in (("expect", expect), ("allow", allow)):
            items = entry.get(key) or []
            if not isinstance(items, list):
                errors.append(f"{where}.{key}: must be a list")
                continue
            for j, item in enumerate(items):
                spot = f"{where}.{key}[{j}]"
                if not isinstance(item, dict):
                    errors.append(f"{spot}: must be a mapping")
                    continue
                allowed_keys = {"dataset", "min", "max", "note"} if key == "expect" else {"dataset", "reason"}
                for k in item:
                    if k not in allowed_keys:
                        errors.append(f"{spot}: unknown key '{k}' (allowed: {', '.join(sorted(allowed_keys))})")
                if not isinstance(item.get("dataset"), str) or not item.get("dataset"):
                    errors.append(f"{spot}.dataset: required")
                if key == "expect":
                    for bound in ("min", "max"):
                        value = item.get(bound)
                        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                            errors.append(f"{spot}.{bound}: must be an integer >= 0")
                    if not str(item.get("note", "")).strip():
                        errors.append(f"{spot}.note: required: what this expectation proves")
                    if isinstance(item.get("max"), int) and item["max"] < item.get("min", 1):
                        errors.append(f"{spot}: max is below min")
                elif not str(item.get("reason", "")).strip():
                    errors.append(f"{spot}.reason: required: why this hit is acceptable")
                target.append(item)
        expectations[name] = {"expect": expect, "allow": allow, "note": entry.get("note", "")}
    if errors:
        raise PlanError("rules/expected.yaml has errors:\n  " + "\n  ".join(errors))
    return expectations


# --------------------------------------------------------------------------- run
def datasets_loaded() -> list[dict]:
    return query("SELECT dataset, events, first_ts, last_ts FROM ep.datasets FINAL ORDER BY dataset")


def hits_for(sql: str) -> dict[str, int]:
    rows = query(f"SELECT dataset, count() AS hits FROM ep.win_events WHERE ({sql}) GROUP BY dataset")
    return {row["dataset"]: row["hits"] for row in rows}


def table(headers: list[str], rows: list[list]) -> list[str]:
    if not rows:
        return ["  (none)"]
    cells = [[str(c) for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in cells)) for i, h in enumerate(headers)]

    def line(row):
        return "  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)).rstrip()
    return [line(headers)] + [line(r) for r in cells]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=str(REPO))
    parser.add_argument("--strict", action="store_true", help="warnings fail too")
    parser.add_argument("--no-write", action="store_true", help="print the report without updating rules/validation.*")
    args = parser.parse_args()
    repo = Path(args.repo)

    try:
        if yaml is None:
            raise PlanError("PyYAML is not installed (Debian: sudo apt-get install -y python3-yaml)")
        rules = load_rules(repo / "rules" / "sigma")
        if not rules:
            raise PlanError("no rules in rules/sigma/")
        lint_rules(rules, repo / "rules" / "README.md")
        expectations = load_expected(repo / "rules" / "expected.yaml", {r["name"] for r in rules})
        loaded = datasets_loaded()
        if not loaded:
            raise PlanError("no datasets loaded; run scripts/load-dataset.sh first")
    except (PlanError, QueryError) as exc:
        print(f"validate-rules: error: {exc}", file=sys.stderr)
        return 2

    dataset_ids = [d["dataset"] for d in loaded]
    results, fp_candidates, allowed_hits, expectation_rows = [], [], [], []
    for entry in rules:
        name = entry["name"]
        plan = expectations.get(name, {"expect": [], "allow": []})
        expected = {e["dataset"]: e for e in plan["expect"]}
        allowed = {a["dataset"]: a["reason"] for a in plan["allow"]}
        hits: dict[str, int] = {}
        error = None
        if entry["sql"]:
            try:
                hits = hits_for(entry["sql"])
            except QueryError as exc:
                error = str(exc)
                entry["lint"].append(("FAIL", f"query failed: {exc}"))

        for dataset, spec in sorted(expected.items()):
            count = hits.get(dataset, 0)
            low, high = spec.get("min", 1), spec.get("max")
            bounds = f">= {low}" + (f", <= {high}" if high is not None else "")
            if dataset not in dataset_ids:
                result, why = "FAIL", "dataset is not loaded"
            elif error:
                result, why = "FAIL", "rule could not be run"
            elif count < low or (high is not None and count > high):
                result, why = "FAIL", f"{count} hits, expected {bounds}"
            else:
                result, why = "PASS", ""
            expectation_rows.append({"rule": name, "dataset": dataset, "result": result, "hits": count,
                                     "expected": bounds, "why": why, "note": spec.get("note", "")})
        for dataset, count in sorted(hits.items()):
            if dataset in expected or count == 0:
                continue
            record = {"rule": name, "dataset": dataset, "hits": count}
            (allowed_hits if dataset in allowed else fp_candidates).append(
                {**record, **({"reason": allowed[dataset]} if dataset in allowed else {})})

        rule_fails = [text for level, text in entry["lint"] if level == "FAIL"]
        mine = [r for r in expectation_rows if r["rule"] == name]
        failed = [r for r in mine if r["result"] == "FAIL"]
        fps = [f for f in fp_candidates if f["rule"] == name]
        status = ("FAIL" if rule_fails or failed else "FP" if fps else "PASS" if mine else "UNTESTED")
        results.append({"rule": name, "title": (entry["rule"] or {}).get("title", ""), "status": status,
                        "techniques": techniques(entry["rule"] or {}), "hits": hits,
                        "lint": [f"{level}: {text}" for level, text in entry["lint"]]})

    n_pass = sum(1 for r in expectation_rows if r["result"] == "PASS")
    n_fail = sum(1 for r in expectation_rows if r["result"] == "FAIL") + \
        sum(1 for e in rules for level, _ in e["lint"] if level == "FAIL")
    warnings = [f"{e['name']}: {text}" for e in rules for level, text in e["lint"] if level == "WARN"]
    untested = [r["rule"] for r in results if r["status"] == "UNTESTED"]
    verdict = "PASSED" if not n_fail and not fp_candidates and not (args.strict and (warnings or untested)) else "FAILED"

    out = ["# Sigma rule validation", "",
           f"Rules:     {len(rules)} in rules/sigma/",
           f"Datasets:  {len(loaded)} loaded ({', '.join(dataset_ids)})", "",
           f"Result:    {verdict} — {n_pass} PASS, {n_fail} FAIL, {len(fp_candidates)} false-positive candidates, "
           f"{len(warnings) + len(untested)} warnings" + ("  (--strict: warnings fail)" if args.strict else ""),
           "", "## Rules", ""]
    out += table(["rule", "status", "ATT&CK", "title"],
                 [[r["rule"], r["status"], ", ".join(r["techniques"]) or "-", r["title"][:60]] for r in results])
    out += ["", "## Expectations", ""]
    out += table(["rule", "dataset", "result", "hits", "expected", "why", "what it proves"],
                 [[r["rule"], r["dataset"], r["result"], r["hits"], r["expected"], r["why"] or "-", r["note"][:44]]
                  for r in expectation_rows])
    out += ["", "## False-positive candidates (a rule fired on a dataset where it was not expected)", ""]
    out += table(["rule", "dataset", "hits"], [[f["rule"], f["dataset"], f["hits"]] for f in fp_candidates])
    if fp_candidates:
        out.append("  Resolve each one: narrow the rule, or add an allow entry with a reason after reviewing the events.")
    out += ["", "## Allowed hits (reviewed in expected.yaml)", ""]
    out += table(["rule", "dataset", "hits", "reason"],
                 [[a["rule"], a["dataset"], a["hits"], a["reason"][:60]] for a in allowed_hits])
    out += ["", "## Lint", ""]
    out += table(["rule", "level", "finding"],
                 [[e["name"], level, text] for e in rules for level, text in e["lint"]])
    if untested:
        out += ["", f"## Untested rules: {', '.join(untested)}", "",
                "  No dataset expects these, so nothing proves they detect what they claim."]
    out += ["", "## Coverage matrix", ""]
    out += table(["rule"] + dataset_ids,
                 [[r["rule"]] + [cell(r, d, expectation_rows, fp_candidates, allowed_hits) for d in dataset_ids]
                  for r in results])
    out.append("  P expected and fired · F expected but missing · ! fired unexpectedly · a allowed · . silent")
    out.append("")
    text_out = "\n".join(out)
    print(text_out)

    if not args.no_write:
        (repo / "rules" / "validation.txt").write_text(text_out, encoding="utf-8")
        (repo / "rules" / "validation.json").write_text(json.dumps(
            {"version": 1, "verdict": verdict,
             "counts": {"pass": n_pass, "fail": n_fail, "fp_candidates": len(fp_candidates),
                        "warnings": len(warnings) + len(untested), "rules": len(rules), "datasets": len(loaded)},
             "rules": results, "expectations": expectation_rows, "fp_candidates": fp_candidates,
             "allowed_hits": allowed_hits}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print("written: rules/validation.txt, rules/validation.json", file=sys.stderr)
    return 0 if verdict == "PASSED" else 1


def cell(result: dict, dataset: str, expectations: list[dict], fps: list[dict], allowed: list[dict]) -> str:
    for row in expectations:
        if row["rule"] == result["rule"] and row["dataset"] == dataset:
            return "P" if row["result"] == "PASS" else "F"
    if any(f["rule"] == result["rule"] and f["dataset"] == dataset for f in fps):
        return "!"
    if any(a["rule"] == result["rule"] and a["dataset"] == dataset for a in allowed):
        return "a"
    return "."


if __name__ == "__main__":
    sys.exit(main())
