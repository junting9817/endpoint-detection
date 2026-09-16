"""Read the front matter of analyses/*/report.md. Used by scripts/update-readme.py.

Front matter is the block between the first two '---' lines: one 'key: value' per line, lists comma-separated
(see TEMPLATE.md). Deliberately simple, so a write-up stays readable and hand-editable.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

REQUIRED = ("title", "date", "technique", "dataset", "summary", "status")
KNOWN = REQUIRED + ("attack", "rules")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PLACEHOLDER_RE = re.compile(r"<[^>]{2,}>")


@dataclass
class Report:
    case: str
    path: Path
    fields: dict = field(default_factory=dict)
    problems: list = field(default_factory=list)

    @property
    def final(self) -> bool:
        return self.fields.get("status") == "final"

    @property
    def date(self) -> str:
        return self.fields.get("date", "")

    @property
    def title(self) -> str:
        return self.fields.get("title", self.case)

    @property
    def technique(self) -> str:
        return self.fields.get("technique", "")

    @property
    def dataset(self) -> str:
        return self.fields.get("dataset", "")

    @property
    def summary(self) -> str:
        return self.fields.get("summary", "")

    @property
    def techniques(self) -> list:
        return split_list(self.fields.get("attack", ""))

    @property
    def rules(self) -> list:
        return split_list(self.fields.get("rules", ""))


def split_list(value: str) -> list:
    return [part.strip() for part in str(value).split(",") if part.strip()]


def read_front_matter(path: Path) -> tuple[dict, list]:
    """(fields, problems). Missing or malformed front matter is a problem, never an exception."""
    problems: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {}, [f"cannot read ({exc.strerror})"]
    if not lines or lines[0].strip() != "---":
        return {}, ["no front matter (the report must start with a '---' line, see TEMPLATE.md)"]
    fields: dict[str, str] = {}
    for number, line in enumerate(lines[1:], 2):
        if line.strip() == "---":
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(":")
        key = key.strip()
        if not sep or not key:
            problems.append(f"line {number}: expected 'key: value'")
            continue
        if key in fields:
            problems.append(f"line {number}: '{key}' appears twice")
        fields[key] = value.strip()
    else:
        problems.append("front matter is not closed with a '---' line")
    for key in REQUIRED:
        if not fields.get(key):
            problems.append(f"missing '{key}'")
    for key in fields:
        if key not in KNOWN:
            problems.append(f"unknown key '{key}' (known: {', '.join(KNOWN)})")
    if fields.get("status") not in (None, "draft", "final"):
        problems.append(f"status '{fields['status']}' must be draft or final")
    if fields.get("date") and not DATE_RE.match(fields["date"]):
        problems.append(f"date '{fields['date']}' must be YYYY-MM-DD")
    for technique in split_list(fields.get("attack", "")):
        if not TECHNIQUE_RE.match(technique):
            problems.append(f"attack '{technique}' must look like T1059 or T1059.001")
    return fields, problems


def load_reports(repo: Path) -> list[Report]:
    """Every analyses/<case>/report.md, newest first."""
    reports = []
    for path in sorted((repo / "analyses").glob("*/report.md")):
        fields, problems = read_front_matter(path)
        report = Report(case=path.parent.name, path=path, fields=fields, problems=problems)
        if fields.get("date") and not report.case.startswith(fields["date"]):
            report.problems.append(f"date '{fields['date']}' does not match the folder name")
        if report.final:
            for key in ("title", "technique", "summary"):
                if PLACEHOLDER_RE.search(fields.get(key, "")):
                    report.problems.append(f"'{key}' still contains a <placeholder> but status is final")
        reports.append(report)
    reports.sort(key=lambda r: (r.date, r.case), reverse=True)
    return reports
