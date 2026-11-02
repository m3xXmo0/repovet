"""Compare fingerprinted findings on pinned repositories and inert reconstructions.

Usage: python scripts/corpus_counts.py [--only NAME]... [--offline-only]
                                       [--baseline FILE] [--update-baseline]
                                       [--save FILE] [--compare FILE]

Real repositories are fetched at the commits in tests/corpus/corpus.yaml and scanned
offline. Reconstructions are scanned without network access. Nothing from either set
is executed. Baseline schema 2.0 stores individual fingerprints plus derived counts;
counts-only baselines must be deliberately regenerated with --update-baseline.

Stored finding records retain structure and identity, but discard payload text and
references from external repositories. The normal report parser and diff matcher
provide the comparison; no second definition of finding identity is used here.
"""

import argparse
import hashlib
import json
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

import reconstructions
from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.comparison import ComparisonScope, compare_findings
from repovet.engine.loader import load_rules
from repovet.report.json_in import coverage_from_data, finding_from_data, snapshot_from_data
from repovet.report.sanitize import sanitize, sanitize_path, sanitize_uri

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests" / "corpus" / "corpus.yaml"
BASELINE = Path(__file__).resolve().parent / "corpus-baseline.json"
SCHEMA_VERSION = "2.0"
CONFIDENCES = ("high", "medium", "low")
SECTIONS = {"real": "real repositories", "reconstructions": "reconstructions"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_REASON_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_MAX_RECORDS = 100_000

type Counts = dict[str, dict[str, dict[str, int]]]
type Records = dict[str, list[dict[str, Any]]]


@dataclass(frozen=True)
class Section:
    version: str
    ruleset_digest: str
    records: Records
    coverage: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    snapshots: dict[str, dict[str, str] | None] = field(default_factory=dict)

    @property
    def counts(self) -> Counts:
        return {
            name: reconstructions.rule_counts(findings) for name, findings in self.records.items()
        }

    def data(self) -> dict[str, Any]:
        records = {
            name: [compact_finding(finding) for finding in findings]
            for name, findings in self.records.items()
        }
        return {
            "tool": {"name": "repovet", "version": self.version},
            "ruleset_digest": self.ruleset_digest,
            "counts": self.counts,
            "findings": records,
            "coverage": {
                name: [compact_coverage(item) for item in self.coverage.get(name, [])]
                for name in records
            },
            "snapshots": {
                name: None
                if self.snapshots.get(name) is None
                else {
                    sanitize_uri(path): entry
                    for path, entry in (self.snapshots.get(name) or {}).items()
                }
                for name in records
            },
        }


def current_digest() -> str:
    return load_rules().digest


def compact_finding(value: object) -> dict[str, Any]:
    """Keep validated identity/structure, never a foreign payload or secret excerpt."""
    finding = finding_from_data(value)
    location = finding.location
    return {
        "rule_id": finding.rule_id,
        "title": "",
        "category": finding.category,
        "area": finding.area,
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
        "location": None
        if location is None
        else {
            "path": sanitize_path(location.path),
            "uri": sanitize_uri(location.path),
            "line": location.line,
            "column": location.column,
        },
        "message": "",
        "evidence": None,
        "rationale": "",
        "recommendation": "",
        "references": [],
        "context": finding.context,
        "chain": None
        if finding.chain is None
        else {
            "id": finding.chain.id,
            "steps": [
                {
                    "path": sanitize_path(step.path),
                    "uri": sanitize_uri(step.path),
                    "line": step.line,
                }
                for step in finding.chain.steps
            ],
        },
        "in_chain": finding.in_chain,
        "fingerprint": finding.fingerprint,
    }


def compact_coverage(value: object) -> dict[str, Any]:
    """Store a stable reason digest, not foreign parser excerpts or payload text."""
    item = coverage_from_data(value)
    reason = item.reason
    if not _REASON_DIGEST.fullmatch(reason):
        reason = "sha256:" + hashlib.sha256(reason.encode("utf-8", "surrogatepass")).hexdigest()
    sample = item.paths[:5] if item.paths else item.sample
    return {
        "scope": sanitize(item.scope, None),
        "status": item.status.value,
        "reason": reason,
        "count": item.count,
        "sample": [sanitize_path(path) for path in sample],
        "paths": [sanitize_path(path) for path in item.paths],
        "uris": [sanitize_uri(path) for path in item.paths],
    }


@dataclass(frozen=True)
class EntryReport:
    records: list[dict[str, Any]]
    coverage: list[dict[str, Any]]
    snapshot: dict[str, str] | None


def _report(report: object, version: str, digest: str) -> EntryReport:
    records = _records(report, version, digest)
    if not isinstance(report, dict):
        raise ValueError("scan report must be an object")
    coverage, scan = report.get("coverage"), report.get("scan")
    if not isinstance(coverage, list) or len(coverage) > _MAX_RECORDS or not isinstance(scan, dict):
        raise ValueError("scan report has invalid coverage/snapshot metadata")
    return EntryReport(
        records,
        [compact_coverage(item) for item in coverage],
        snapshot_from_data(scan.get("snapshot")),
    )


def load_manifest(path: Path) -> list[dict[str, Any]]:
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise SystemExit(f"{path}: expected a list of repositories")
    if any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("name"), str)
        or not _NAME.fullmatch(entry["name"])
        for entry in entries
    ):
        raise SystemExit(f"{path}: repository entries need simple, non-empty names")
    return entries


def _records(report: object, version: str, digest: str) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        raise ValueError("scan report must be an object")
    if report.get("tool") != {"name": "repovet", "version": version}:
        raise ValueError("scanner metadata changed during the corpus run (version)")
    if report.get("ruleset_digest") != digest:
        raise ValueError("scanner metadata changed during the corpus run (ruleset digest)")
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > _MAX_RECORDS:
        raise ValueError("scan report has invalid findings")
    return [compact_finding(finding) for finding in findings]


def scan_entry_report(entry: Mapping[str, Any], workdir: Path, digest: str) -> EntryReport | str:
    report = workdir / f"{entry['name']}.json"
    url = f"https://github.com/{entry['repo']}"
    args = ["scan", url, "--ref", str(entry["commit"]), "--offline", "--format", "json"]
    code = main([*args, "-o", str(report)])
    if code not in (EXIT_OK, EXIT_FINDINGS):
        return f"scan failed with exit code {code}"
    try:
        return _report(json.loads(report.read_text(encoding="utf-8")), __version__, digest)
    except (OSError, ValueError) as exc:
        return str(exc)


def scan_entry(entry: Mapping[str, Any], workdir: Path) -> dict[str, dict[str, int]] | str:
    """Compatibility wrapper: counts per rule/confidence, or an error text."""
    outcome = scan_entry_report(entry, workdir, current_digest())
    return outcome if isinstance(outcome, str) else reconstructions.rule_counts(outcome.records)


def reconstruction_section() -> Section:
    digest = current_digest()
    records: Records = {}
    coverage: dict[str, list[dict[str, Any]]] = {}
    snapshots: dict[str, dict[str, str] | None] = {}
    with tempfile.TemporaryDirectory(prefix="repovet-corpus-reconstructions-") as tmp:
        for entry in reconstructions.load_entries():
            outcome = _report(reconstructions.scan(entry, Path(tmp)), __version__, digest)
            records[entry.id], coverage[entry.id], snapshots[entry.id] = (
                outcome.records,
                outcome.coverage,
                outcome.snapshot,
            )
    return Section(__version__, digest, records, coverage, snapshots)


def reconstruction_counts() -> Counts:
    return reconstruction_section().counts


def totals(counts: Counts) -> dict[str, int]:
    result: dict[str, int] = {}
    for per_repo in counts.values():
        for rule_id, by_confidence in per_repo.items():
            result[rule_id] = result.get(rule_id, 0) + sum(by_confidence.values())
    return result


def print_table(counts: Counts) -> None:
    names = list(counts)
    width = max([len(n) for n in names] + [5])
    print(f"{'rule':<13} {'total':>6}  {'h/m/l':>12}  " + "  ".join(f"{n:>{width}}" for n in names))
    for rule_id in sorted({r for per_repo in counts.values() for r in per_repo}):
        split = [sum(counts[n].get(rule_id, {}).get(c, 0) for n in names) for c in CONFIDENCES]
        cells = "  ".join(f"{sum(counts[n].get(rule_id, {}).values()):>{width}}" for n in names)
        print(f"{rule_id:<13} {sum(split):>6}  {'/'.join(map(str, split)):>12}  {cells}")


def print_list(counts: Counts) -> None:
    width = max([len(n) for n in counts] + [5])
    for name, per_rule in counts.items():
        cells = ", ".join(f"{r} {sum(per_rule[r].values())}" for r in sorted(per_rule)) or "-"
        print(f"{name:<{width}}  {cells}")


def print_comparison(old: Counts, new: Counts) -> None:
    before, after = totals(old), totals(new)
    changed = sorted(r for r in before.keys() | after.keys() if before.get(r) != after.get(r))
    if not changed:
        print("no change in the number of findings per rule")
        return
    print(f"{'rule':<13} {'before':>7} {'after':>7} {'change':>7}")
    for rule_id in changed:
        b, a = before.get(rule_id, 0), after.get(rule_id, 0)
        print(f"{rule_id:<13} {b:>7} {a:>7} {a - b:>+7}")


def changes(old: Counts, new: Counts) -> list[tuple[str, str, int, int]]:
    rows = []
    for name in sorted(old.keys() | new.keys()):
        before = {r: sum(c.values()) for r, c in old.get(name, {}).items()}
        after = {r: sum(c.values()) for r, c in new.get(name, {}).items()}
        for rule_id in sorted(before.keys() | after.keys()):
            b, a = before.get(rule_id, 0), after.get(rule_id, 0)
            if a != b:
                rows.append((name, rule_id, b, a))
    return rows


def print_changes(old: Counts, new: Counts) -> None:
    rows = changes(old, new)
    if not rows:
        print("no change against the baseline")
        return
    width = max(len(name) for name, *_ in rows)
    print(f"{'':<{width}}  {'rule':<13} {'before':>7} {'after':>7} {'change':>7}")
    for name, rule_id, b, a in rows:
        print(f"{name:<{width}}  {rule_id:<13} {b:>7} {a:>7} {a - b:>+7}")


def print_finding_changes(old: Section, new: Section) -> int:
    if old.version != new.version:
        print("warning: scanner version differs; results may reflect tool changes", file=sys.stderr)
    if old.ruleset_digest != new.ruleset_digest:
        print("warning: ruleset digest differs; results may reflect rule changes", file=sys.stderr)
    different = False
    incomplete = False
    for name in sorted(old.records.keys() | new.records.keys()):
        if old.snapshots.get(name) is None or new.snapshots.get(name) is None:
            print(
                f"warning: {sanitize(name, None)} has no Git snapshot; "
                "comparing reported identities without proof of file changes",
                file=sys.stderr,
            )
        scope = ComparisonScope(
            old.snapshots.get(name) or {},
            new.snapshots.get(name) or {},
            [coverage_from_data(value) for value in old.coverage.get(name, [])],
            [coverage_from_data(value) for value in new.coverage.get(name, [])],
        )
        comparison = compare_findings(
            [finding_from_data(value) for value in old.records.get(name, [])],
            [finding_from_data(value) for value in new.records.get(name, [])],
            scope,
        )
        per_rule: dict[str, Counter[str]] = {}
        for change in comparison.changes:
            status = change.status.value
            if status == "unchanged":
                continue
            finding = change.after or change.before
            if finding is not None:
                counts = per_rule.setdefault(finding.rule_id, Counter())
                counts["worsened" if change.worsened else status] += 1
        for rule_id, counts in sorted(per_rule.items()):
            different = True
            shown = ", ".join(f"{status} {counts[status]}" for status in sorted(counts))
            print(f"{sanitize(name, None)}  {rule_id}  {shown}")
        if comparison.issues:
            incomplete = incomplete or comparison.incomplete
            print(
                f"{sanitize(name, None)}: {len(comparison.issues)} unresolved comparison issue(s)"
            )
    if not different and not incomplete:
        print("no change in finding identities")
    return EXIT_ABORTED if incomplete else EXIT_OK


def _section(value: object) -> Section:
    if not isinstance(value, dict) or set(value) != {
        "tool",
        "ruleset_digest",
        "counts",
        "findings",
        "coverage",
        "snapshots",
    }:
        raise ValueError(
            "a corpus section needs tool, ruleset_digest, counts, findings, coverage and snapshots"
        )
    tool, digest, records = value["tool"], value["ruleset_digest"], value["findings"]
    if not isinstance(tool, dict) or set(tool) != {"name", "version"} or tool["name"] != "repovet":
        raise ValueError("invalid corpus tool metadata")
    version = tool["version"]
    if (
        not isinstance(version, str)
        or not version
        or not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
    ):
        raise ValueError("invalid corpus version or ruleset digest")
    if not isinstance(records, dict) or len(records) > _MAX_RECORDS:
        raise ValueError("invalid corpus findings")
    parsed: Records = {}
    for name, findings in records.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(findings, list)
            or len(findings) > _MAX_RECORDS
        ):
            raise ValueError("invalid corpus entry")
        parsed[name] = [compact_finding(finding) for finding in findings]
        if parsed[name] != findings:
            raise ValueError("stored corpus records must omit payload text and references")
    coverage_data, snapshot_data = value["coverage"], value["snapshots"]
    if (
        not isinstance(coverage_data, dict)
        or not isinstance(snapshot_data, dict)
        or set(coverage_data) != set(parsed)
        or set(snapshot_data) != set(parsed)
    ):
        raise ValueError("coverage/snapshot entry names must match finding entries")
    coverage: dict[str, list[dict[str, Any]]] = {}
    for name, items in coverage_data.items():
        if not isinstance(items, list) or len(items) > _MAX_RECORDS:
            raise ValueError("invalid corpus coverage records")
        coverage[name] = [compact_coverage(item) for item in items]
        if coverage[name] != items:
            raise ValueError("stored corpus coverage must use compact reason digests")
    snapshots = {name: snapshot_from_data(item) for name, item in snapshot_data.items()}
    section = Section(version, digest, parsed, coverage, snapshots)
    counts = value["counts"]
    if not isinstance(counts, dict) or counts != section.counts:
        raise ValueError("corpus counts disagree with stored findings")
    for per_repo in counts.values():
        for by_confidence in per_repo.values():
            if any(type(count) is not int for count in by_confidence.values()):
                raise ValueError("corpus counts must be integers derived from findings")
    return section


def load_baseline(path: Path, *, replace_legacy: bool = False) -> dict[str, Section]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        if replace_legacy:
            print(f"warning: obsolete baseline discarded; regenerating {path}", file=sys.stderr)
            return {}
        raise ValueError(
            f"{path}: obsolete counts-only baseline; regenerate with --update-baseline"
        )
    if not set(data) <= {"schema_version", *SECTIONS} or not set(data) & set(SECTIONS):
        raise ValueError(f"{path}: expected at least one named corpus section")
    return {key: _section(data[key]) for key in SECTIONS if key in data}


def write_baseline(path: Path, baseline: Mapping[str, Section]) -> None:
    ordered = {"schema_version": SCHEMA_VERSION}
    payload: dict[str, object] = dict(ordered)
    payload.update({key: baseline[key].data() for key in SECTIONS if key in baseline})
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument("--offline-only", action="store_true", help="scan only the reconstructions")
    parser.add_argument("--baseline", type=Path, default=BASELINE, metavar="FILE")
    parser.add_argument(
        "--update-baseline", action="store_true", help="regenerate the versioned findings baseline"
    )
    parser.add_argument(
        "--save", type=Path, metavar="FILE", help="write a versioned real-corpus record"
    )
    parser.add_argument(
        "--compare", type=Path, metavar="FILE", help="earlier schema 2.0 --save output"
    )
    return parser


def scan_real_section(manifest: Path, only: Sequence[str]) -> tuple[Section, dict[str, str]]:
    entries = [entry for entry in load_manifest(manifest) if not only or entry["name"] in only]
    digest = current_digest()
    records: Records = {}
    coverage: dict[str, list[dict[str, Any]]] = {}
    snapshots: dict[str, dict[str, str] | None] = {}
    errors: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="repovet-corpus-") as tmp:
        for entry in entries:
            print(f"scanning {entry['repo']} @ {str(entry['commit'])[:12]} ...", file=sys.stderr)
            outcome = scan_entry_report(entry, Path(tmp), digest)
            if isinstance(outcome, str):
                errors[entry["name"]] = outcome
            else:
                name = entry["name"]
                records[name], coverage[name], snapshots[name] = (
                    outcome.records,
                    outcome.coverage,
                    outcome.snapshot,
                )
    return Section(__version__, digest, records, coverage, snapshots), errors


def scan_real(manifest: Path, only: Sequence[str]) -> tuple[Counts, dict[str, str]]:
    section, errors = scan_real_section(manifest, only)
    return section.counts, errors


def _limited(section: Section, names: Mapping[str, object]) -> Section:
    return Section(
        section.version,
        section.ruleset_digest,
        {k: v for k, v in section.records.items() if k in names},
        {k: v for k, v in section.coverage.items() if k in names},
        {k: v for k, v in section.snapshots.items() if k in names},
    )


def run(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.update_baseline and args.only:
        print("--update-baseline needs the whole corpus; leave out --only", file=sys.stderr)
        return EXIT_USAGE
    if args.offline_only and (args.only or args.save or args.compare):
        print("--only, --save and --compare need the real repositories", file=sys.stderr)
        return EXIT_USAGE
    try:
        baseline = load_baseline(args.baseline, replace_legacy=args.update_baseline)
        earlier = load_baseline(args.compare) if args.compare else {}
        if args.compare and "real" not in earlier:
            raise ValueError(f"{args.compare}: no schema 2.0 real-corpus records")
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    scanned: dict[str, Section] = {}
    errors: dict[str, str] = {}
    compare_code = EXIT_OK
    if not args.offline_only:
        scanned["real"], errors = scan_real_section(args.manifest, args.only)
        actual = scanned["real"]
        print(f"repovet {__version__}, {len(actual.records)} repositories")
        print_table(actual.counts)
        for name, error in errors.items():
            print(f"{name}: {error}", file=sys.stderr)
        if args.save and not errors:
            write_baseline(args.save, {"real": actual})
        if args.compare:
            old = _limited(earlier["real"], actual.records)
            print(f"\ncompared with repovet {old.version} ({args.compare})")
            print_comparison(old.counts, actual.counts)
            compare_code = max(compare_code, print_finding_changes(old, actual))
    print("scanning the reconstructions ...", file=sys.stderr)
    try:
        scanned["reconstructions"] = reconstruction_section()
    except (OSError, ValueError) as exc:
        errors["reconstructions"] = str(exc)
        print(f"reconstructions: {sanitize(str(exc), None)}", file=sys.stderr)
        scanned["reconstructions"] = Section(__version__, current_digest(), {})
    current = scanned["reconstructions"]
    metadata = {(section.version, section.ruleset_digest) for section in scanned.values()}
    if len(metadata) > 1:
        errors["metadata"] = "scanner metadata changed between corpus sections"
        print(errors["metadata"], file=sys.stderr)
    print(f"\nrepovet {__version__}, {len(current.records)} reconstructions")
    print_list(current.counts)
    for key, actual in scanned.items():
        previous = baseline.get(key)
        if previous is None:
            print(f"\nno baseline for the {SECTIONS[key]} in {args.baseline}")
            continue
        if key == "real" and args.only:
            previous = _limited(previous, actual.records)
        print(f"\n{SECTIONS[key]} against the baseline (repovet {previous.version}):")
        print_changes(previous.counts, actual.counts)
        compare_code = max(compare_code, print_finding_changes(previous, actual))
    if errors:
        if args.update_baseline:
            print("baseline not updated: some scans failed", file=sys.stderr)
        return 1
    if compare_code:
        if args.update_baseline:
            print("baseline not updated: comparison is unresolved", file=sys.stderr)
        return compare_code
    if args.update_baseline:
        baseline.update(scanned)
        write_baseline(args.baseline, baseline)
        print(f"\nbaseline written: {args.baseline} ({', '.join(scanned)})")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
