#!/usr/bin/env python3
"""Regenerate the generated blocks of README.md and the ATT&CK layers (docs/workflow.md step 10).

Sources:
  analyses/*/report.md        front matter: title, date, technique, dataset, summary, attack, rules, status
  analyses/*/dataset.txt      which recording each case used, and how many events it held
  rules/sigma/*.yml           the rules, their ATT&CK tags and level
  rules/validation.json       the last scripts/validate-rules.sh result

Writes rules/attack-coverage.json (this repository) and, when the network project is next door,
rules/attack-coverage-combined.json — one Navigator layer showing what is covered on the endpoint, on the network, or
on both. Only reports with `status: final` count in the totals; drafts stay listed.

The text between each pair of `<!-- ep:<name> -->` and `<!-- /ep:<name> -->` markers is replaced; everything else in
README.md is hand-written. Output is deterministic, so a re-run changes nothing. Reads local files only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "lib"))
from reports import TECHNIQUE_RE, load_reports  # noqa: E402
from sigma import techniques as rule_techniques  # noqa: E402

try:
    import yaml
except ImportError:
    yaml = None

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def escape(text) -> str:
    return str(text).replace("|", "\\|").strip()


def technique_link(technique: str) -> str:
    if not TECHNIQUE_RE.match(technique):
        return escape(technique)
    return f"[{technique}]({ATTACK_URL.format(technique.replace('.', '/'))})"


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def load_rules(repo: Path) -> list[dict]:
    rules = []
    for path in sorted((repo / "rules" / "sigma").glob("*.yml")):
        try:
            content = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            content = None
        if isinstance(content, dict):
            rules.append({"name": path.stem, "title": content.get("title", path.stem),
                          "level": str(content.get("level", "")), "techniques": rule_techniques(content)})
    return rules


def dataset_of(case_dir: Path) -> tuple[str, str]:
    """(dataset id, events loaded) from the case's dataset.txt."""
    info = case_dir / "dataset.txt"
    if not info.is_file():
        return "", ""
    fields = dict(line.split(": ", 1) for line in info.read_text(encoding="utf-8").splitlines() if ": " in line)
    return fields.get("dataset", ""), fields.get("events_loaded", "")


def build_blocks(repo: Path, network_repo: Path | None) -> tuple[dict[str, str], list[str], dict, dict | None]:
    notes: list[str] = []
    reports = load_reports(repo)
    for report in reports:
        notes += [f"{report.path.relative_to(repo)}: {problem}" for problem in report.problems]

    rules = load_rules(repo)
    validation = {}
    path = repo / "rules" / "validation.json"
    if path.is_file():
        try:
            validation = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            notes.append(f"rules/validation.json: invalid JSON ({exc.msg})")
    elif rules:
        notes.append("rules/validation.json is missing: run scripts/validate-rules.sh")
    rule_status = {r["rule"]: r for r in validation.get("rules", [])}
    counts = validation.get("counts", {})

    final = [r for r in reports if r.final]
    drafts = [r for r in reports if not r.final]
    validated = [r["name"] for r in rules if rule_status.get(r["name"], {}).get("status") == "PASS"]
    endpoint_techniques = sorted({t for r in rules for t in r["techniques"]})
    covered = sorted({t for r in rules if r["name"] in validated for t in r["techniques"]})
    for report in final:
        for name in report.rules:
            if name not in {r["name"] for r in rules}:
                notes.append(f"{report.case}: report lists rule '{name}', which is not in rules/sigma/")

    # ---------------------------------------------------------------- stats
    if validation:
        rule_line = (f"{len(rules)} in the library · {len(validated)} validated · "
                     f"{counts.get('fp_candidates', 0)} false-positive candidates")
        validation_line = (f"**{validation.get('verdict', '?')}** — {plural(counts.get('pass', 0), 'expectation')} met, "
                           f"{counts.get('fail', 0)} failed, over {plural(counts.get('datasets', 0), 'recording')} "
                           f"([rules/validation.txt](rules/validation.txt))")
    else:
        rule_line, validation_line = f"{len(rules)} in the library", "not run yet"
    stats = ["| | |", "|---|---|",
             f"| Techniques analysed | {len(final)} published" + (f", {len(drafts)} in progress" if drafts else "") + " |",
             f"| Sigma rules | {rule_line} |",
             f"| ATT&CK techniques | {len(endpoint_techniques)} tagged · {len(covered)} covered by a validated rule |",
             f"| Rule validation | {validation_line} |"]

    # ---------------------------------------------------------------- analyses
    analyses = []
    if final:
        analyses += ["| Date | Analysis | Technique | Recording | Rules | ATT&CK |", "|---|---|---|---|---|---|"]
        for r in final:
            dataset, events = dataset_of(repo / "analyses" / r.case)
            analyses.append(
                f"| {r.date} | [{escape(r.title)}](analyses/{r.case}/report.md) | {escape(r.technique)} | "
                f"`{escape(dataset or r.dataset)}`" + (f" ({events} events)" if events else "") + " | "
                + (", ".join(f"`{escape(x)}`" for x in r.rules) or "—") + " | "
                + (", ".join(technique_link(t) for t in r.techniques) or "—") + " |")
    else:
        analyses.append("*No published analyses yet.*")
    if drafts:
        analyses += ["", "In progress: " + ", ".join(f"`{r.case}`" for r in drafts) + "."]

    # ---------------------------------------------------------------- rules
    rows = ["| Rule | Title | ATT&CK | Level | Validation |", "|---|---|---|---|---|"]
    for rule in rules:
        state = rule_status.get(rule["name"], {})
        status = state.get("status", "not validated")
        detail = {"PASS": "fires where expected, silent elsewhere", "FAIL": "failing — see rules/validation.txt",
                  "FP": "false-positive candidate to resolve", "UNTESTED": "no recording expects it yet",
                  }.get(status, status)
        rows.append(f"| `{escape(rule['name'])}` | {escape(rule['title'])} | "
                    + (", ".join(technique_link(t) for t in rule["techniques"]) or "—")
                    + f" | {escape(rule['level'])} | {detail} |")
    if len(rows) == 2:
        rows = ["*No rules yet.*"]

    # ---------------------------------------------------------------- coverage across both projects
    network = read_network_coverage(network_repo, notes) if network_repo else None
    coverage_lines, combined_layer = coverage_block(covered, endpoint_techniques, network)
    layer = attack_layer(rules, rule_status, final,
                         name="EP — endpoint detection coverage",
                         description="Generated by scripts/update-readme.py from rules/sigma and the analyses.")
    return ({"stats": "\n".join(stats), "analyses": "\n".join(analyses), "rules": "\n".join(rows),
             "coverage": "\n".join(coverage_lines)}, notes, layer, combined_layer)


def read_network_coverage(network_repo: Path, notes: list[str]) -> dict | None:
    """The network project's ATT&CK layer, if it is next door."""
    path = network_repo / "rules" / "attack-coverage.json"
    if not path.is_file():
        notes.append(f"{path} not found: the combined ATT&CK coverage skips the network project")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        notes.append(f"{path}: invalid JSON ({exc.msg})")
        return None


def coverage_block(endpoint_covered: list[str], endpoint_tagged: list[str], network: dict | None):
    """The combined table, and the combined Navigator layer (None when the network project is absent)."""
    network_covered = sorted({t["techniqueID"] for t in (network or {}).get("techniques", []) if t.get("score") == 2})
    network_seen = sorted({t["techniqueID"] for t in (network or {}).get("techniques", [])})
    if network is None:
        lines = ["| Technique | Endpoint | Network |", "|---|---|---|"]
        for technique in endpoint_tagged:
            lines.append(f"| {technique_link(technique)} | "
                         + ("validated rule" if technique in endpoint_covered else "rule written") + " | — |")
        lines.append("")
        lines.append("*The network project was not found next door, so only endpoint coverage is shown.*")
        return lines, None

    both = sorted(set(endpoint_tagged) | set(network_seen))
    lines = ["| Technique | Endpoint | Network |", "|---|---|---|"]
    for technique in both:
        endpoint = ("validated rule" if technique in endpoint_covered
                    else "rule written" if technique in endpoint_tagged else "—")
        net = ("validated rule" if technique in network_covered
               else "seen in traffic" if technique in network_seen else "—")
        lines.append(f"| {technique_link(technique)} | {endpoint} | {net} |")
    lines += ["", f"{len(set(endpoint_covered) & set(network_covered))} techniques are covered on both sides, "
                  f"{len(set(endpoint_covered) - set(network_covered))} on the endpoint only, "
                  f"{len(set(network_covered) - set(endpoint_covered))} on the network only."]

    techniques = []
    for technique in both:
        endpoint = technique in endpoint_covered
        net = technique in network_covered
        if not endpoint and not net and technique not in endpoint_tagged and technique not in network_seen:
            continue
        score = 3 if endpoint and net else 2 if endpoint or net else 1
        where = ", ".join(filter(None, ["validated endpoint rule" if endpoint else "",
                                        "validated network rule" if net else ""])) or "seen, no validated rule yet"
        techniques.append({"techniqueID": technique, "score": score, "comment": where, "enabled": True,
                           "showSubtechniques": False})
    combined = {
        "name": "Endpoint and network detection coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": ("Generated by EP/scripts/update-readme.py from the endpoint rules and the network project's "
                        "layer. 3 = validated rules on both sides, 2 = one side, 1 = seen but not covered."),
        "sorting": 3, "layout": {"layout": "side", "showID": True, "showName": True}, "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#f5d76e", "#8fc98f", "#2e8b57"], "minValue": 1, "maxValue": 3},
        "legendItems": [{"label": "seen, no validated rule", "color": "#f5d76e"},
                        {"label": "covered on one side", "color": "#8fc98f"},
                        {"label": "covered on endpoint and network", "color": "#2e8b57"}],
    }
    return lines, combined


def attack_layer(rules: list[dict], rule_status: dict, final_reports, name: str, description: str) -> dict:
    by_technique: dict[str, list[str]] = {}
    for rule in rules:
        for technique in rule["techniques"]:
            by_technique.setdefault(technique, []).append(rule["name"])
    cases: dict[str, list[str]] = {}
    for report in final_reports:
        for technique in report.techniques:
            cases.setdefault(technique, []).append(report.case)

    techniques = []
    for technique in sorted(t for t in set(by_technique) | set(cases) if TECHNIQUE_RE.match(t)):
        validated = [n for n in by_technique.get(technique, []) if rule_status.get(n, {}).get("status") == "PASS"]
        comment = "; ".join(filter(None, [
            f"validated rule {', '.join(sorted(validated))}" if validated else
            (f"rule {', '.join(sorted(by_technique[technique]))} not validated yet" if technique in by_technique
             else "seen in a recording, no rule yet"),
            f"analysed in {', '.join(sorted(cases.get(technique, [])))}" if cases.get(technique) else ""]))
        techniques.append({"techniqueID": technique, "score": 2 if validated else 1, "comment": comment,
                           "enabled": True, "showSubtechniques": False})
    return {
        "name": name, "versions": {"layer": "4.5", "navigator": "5.1.0"}, "domain": "enterprise-attack",
        "description": f"{description} Techniques: {len(techniques)}; "
                       f"with a validated rule: {sum(1 for t in techniques if t['score'] == 2)}.",
        "sorting": 3, "layout": {"layout": "side", "showID": True, "showName": True}, "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#f5d76e", "#66b86a"], "minValue": 1, "maxValue": 2},
        "legendItems": [{"label": "rule written, not validated", "color": "#f5d76e"},
                        {"label": "covered by a validated rule", "color": "#66b86a"}],
    }


def apply_blocks(text: str, blocks: dict[str, str]) -> tuple[str, list[str]]:
    problems = []
    for name, content in blocks.items():
        pattern = re.compile(rf"<!-- ep:{name} -->.*?<!-- /ep:{name} -->", re.S)
        if not pattern.search(text):
            problems.append(f"README.md has no '<!-- ep:{name} -->' … '<!-- /ep:{name} -->' block")
            continue
        replacement = f"<!-- ep:{name} -->\n{content}\n<!-- /ep:{name} -->"
        text = pattern.sub(lambda _: replacement, text, count=1)  # a function: no escape handling
    return text, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--readme", default=str(REPO / "README.md"))
    parser.add_argument("--network-repo", default=str(Path.home() / "GY"),
                        help="the network project, for combined ATT&CK coverage ('' to skip)")
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if a file is out of date")
    parser.add_argument("--strict", action="store_true", help="also exit 1 when a report has problems")
    args = parser.parse_args()
    if yaml is None:
        print("update-readme: error: PyYAML is missing (Debian: sudo apt-get install -y python3-yaml)", file=sys.stderr)
        return 2

    readme = Path(args.readme)
    if not readme.is_file():
        print(f"update-readme: error: {readme} not found", file=sys.stderr)
        return 2
    network_repo = Path(args.network_repo) if args.network_repo else None
    blocks, notes, layer, combined = build_blocks(REPO, network_repo)
    text, problems = apply_blocks(readme.read_text(encoding="utf-8"), blocks)
    notes += problems

    changed = []
    if text != readme.read_text(encoding="utf-8"):
        changed.append(str(readme.relative_to(REPO) if readme.is_relative_to(REPO) else readme))
        if not args.check:
            readme.write_text(text, encoding="utf-8")
    for path, content in ((REPO / "rules" / "attack-coverage.json", layer),
                          (REPO / "rules" / "attack-coverage-combined.json", combined)):
        if content is None:
            continue
        serialised = json.dumps(content, indent=2) + "\n"
        if not path.is_file() or path.read_text(encoding="utf-8") != serialised:
            changed.append(str(path.relative_to(REPO)))
            if not args.check:
                path.write_text(serialised, encoding="utf-8")

    for note in notes:
        print(f"update-readme: warning: {note}", file=sys.stderr)
    if args.check:
        print("out of date: " + ", ".join(changed) if changed else "up to date")
    else:
        print("updated: " + ", ".join(changed) if changed else "no changes")
    if problems:
        return 2
    if args.check and changed:
        return 1
    return 1 if args.strict and notes else 0


if __name__ == "__main__":
    sys.exit(main())
