"""False-positive benchmark: scan the most-starred public GitHub repositories.

Usage: python scripts/fp_benchmark.py [-n N] [--max-clone-size SIZE]
                                      [--render-only] [--compare FILE]

The N most-starred public repositories (default 50) are listed with the GitHub search
API (repovet's own client; a token is optional and read from GITHUB_TOKEN or GH_TOKEN).
Each is scanned at the current commit of its default branch like ``repovet scan URL
--offline`` with all built-in rules. Repositories larger than the clone size limit
(by the size GitHub reports, or because the download hit the limit) and failed scans
are recorded as skipped.

The results are written to ``docs/fp-benchmark.json`` (data) and
``docs/fp-benchmark.md`` (rendered from the data; ``--render-only`` renders it again
without scanning). The repositories are popular, maintained projects, so every finding
is a candidate false positive or an accurate finding of something the project does on
purpose; the benchmark does not judge them one by one.

This needs the network and is not part of the test suite. Nothing from the repositories
is run; they are read from Git objects in a temporary folder that is deleted after each
scan. Schema 2.0 stores compact individual findings, coverage and a ruleset digest.
--compare uses the shared finding matcher; counts-only data is explicitly compared
only as aggregates. Commit drift is reported rather than attributed to rule changes.
"""

import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from corpus_counts import (
    Section,
    compact_coverage,
    compact_finding,
    print_changes,
    print_finding_changes,
)

from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.engine.loader import load_rules
from repovet.github.client import ApiError, GitHubClient, token_from_env
from repovet.github.transport import UrllibTransport
from repovet.limits import format_size, parse_size
from repovet.models import AREAS
from repovet.report.json_in import snapshot_from_data
from repovet.report.sanitize import sanitize, sanitize_uri
from repovet.sources.remote import DEFAULT_MAX_CLONE_SIZE

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "fp-benchmark.json"
MARKDOWN = ROOT / "docs" / "fp-benchmark.md"
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
SCHEMA_VERSION = "2.0"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
_MAX_RECORDS = 100_000
# Owner and repository names as GitHub allows them; anything else is not scanned.
_FULL_NAME = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")
_PER_PAGE = 100
TOP_RULES = 10


def most_starred(client: GitHubClient, count: int) -> list[dict[str, Any]]:
    """The ``count`` most-starred public repositories: full name, stars, size in KiB."""
    found: list[dict[str, Any]] = []
    page = 1
    per_page = min(_PER_PAGE, count)
    while len(found) < count:
        params: dict[str, str | int] = {
            "q": "stars:>1000",
            "sort": "stars",
            "order": "desc",
            "per_page": per_page,
            "page": page,
        }
        data = client.get("/search/repositories", params).data
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list) or not items:
            break
        for item in items:
            name = item.get("full_name") if isinstance(item, dict) else None
            if isinstance(name, str) and _FULL_NAME.fullmatch(name):
                found.append(
                    {
                        "repo": name,
                        "stars": int(item.get("stargazers_count") or 0),
                        "size_kib": int(item.get("size") or 0),
                    }
                )
        if len(items) < per_page:
            break
        page += 1
    return found[:count]


def _highest(severities: Mapping[str, int]) -> str:
    return min(severities, key=SEVERITIES.index)


def summarize(report: Mapping[str, Any], *, include_records: bool = False) -> dict[str, Any]:
    """Commit, file count and findings per rule: confidence split, findings per severity
    (a finding can be reported below its rule's severity) and the highest severity.
    Parts of a chain are not counted again, as in the report's summary; their number is
    kept as ``chain_parts``."""
    rules: dict[str, dict[str, Any]] = {}
    parts = sum(1 for f in report["findings"] if f.get("in_chain"))
    for finding in report["findings"]:
        if finding.get("in_chain"):
            continue
        entry = rules.setdefault(
            finding["rule_id"],
            {"severity": finding["severity"], **dict.fromkeys(CONFIDENCES, 0), "severities": {}},
        )
        entry[finding["confidence"]] += 1
        severities = entry["severities"]
        severities[finding["severity"]] = severities.get(finding["severity"], 0) + 1
        entry["severity"] = _highest(severities)
    source = report.get("facts", {}).get("source") or {}
    summary: dict[str, Any] = {
        "commit": str(source.get("commit") or ""),
        "files": int(report["scan"]["files_scanned"]),
        "findings": dict(sorted(rules.items())),
    }
    if parts:
        summary["chain_parts"] = parts
    if include_records:
        tool, digest = report.get("tool"), report.get("ruleset_digest")
        if (
            not isinstance(tool, dict)
            or tool.get("name") != "repovet"
            or not isinstance(tool.get("version"), str)
            or not tool["version"]
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            or not _COMMIT.fullmatch(summary["commit"])
        ):
            raise ValueError("fingerprinted report needs version, digest and full commit metadata")
        findings, gaps = report["findings"], report.get("coverage")
        if (
            not isinstance(findings, list)
            or len(findings) > _MAX_RECORDS
            or not isinstance(gaps, list)
            or len(gaps) > _MAX_RECORDS
        ):
            raise ValueError("fingerprinted report needs bounded findings and coverage")
        summary["finding_records"] = [
            compact_finding(finding) for finding in findings if not finding.get("in_chain")
        ]
        summary["coverage_records"] = [compact_coverage(value) for value in gaps]
        snapshot = snapshot_from_data(report["scan"].get("snapshot"))
        summary["snapshot"] = (
            None
            if snapshot is None
            else {sanitize_uri(path): oid for path, oid in snapshot.items()}
        )
        summary["tool_version"] = tool["version"]
        summary["ruleset_digest"] = digest
    return summary


def scan_repository(
    repo: Mapping[str, Any], workdir: Path, max_clone_size: int
) -> dict[str, Any] | str:
    """Summary of one scan, or the reason it was skipped."""
    if repo["size_kib"] * 1024 > max_clone_size:
        size = format_size(repo["size_kib"] * 1024)
        return f"larger than the clone limit ({size} > {format_size(max_clone_size)})"
    report = workdir / "report.json"
    report.unlink(missing_ok=True)
    args = ["scan", f"https://github.com/{repo['repo']}", "--offline", "--format", "json"]
    args += ["--max-clone-size", str(max_clone_size), "-o", str(report)]
    errors = io.StringIO()
    with contextlib.redirect_stderr(errors):
        code = main(args)
    if code not in (EXIT_OK, EXIT_FINDINGS):
        lines = [line for line in errors.getvalue().splitlines() if line.strip()]
        detail = sanitize(lines[-1], 200) if lines else "no message"
        return f"scan failed (exit code {code}): {detail}"
    try:
        return summarize(json.loads(report.read_text(encoding="utf-8")), include_records=True)
    except (OSError, ValueError, KeyError, TypeError):
        return "scan failed: invalid fingerprinted report"


def rule_table(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Per rule: severity, repositories with a finding, findings, confidence split;
    most widespread first."""
    rows: dict[str, dict[str, Any]] = {}
    for repo in data["repositories"]:
        for rule_id, counts in repo["findings"].items():
            row = rows.setdefault(
                rule_id,
                {"rule": rule_id, "severity": counts["severity"], "repos": 0, "findings": 0}
                | dict.fromkeys(CONFIDENCES, 0)
                | {"severities": {}},
            )
            row["repos"] += 1
            for confidence in CONFIDENCES:
                row[confidence] += counts[confidence]
                row["findings"] += counts[confidence]
            for severity, number in _by_severity(counts).items():
                row["severities"][severity] = row["severities"].get(severity, 0) + number
            row["severity"] = _highest(row["severities"])
    return sorted(rows.values(), key=lambda r: (-r["repos"], -r["findings"], r["rule"]))


def _by_severity(per_rule: Mapping[str, Any]) -> dict[str, int]:
    """Findings of one rule per severity (data without the split: all at its severity)."""
    if "severities" in per_rule:
        return {str(s): int(n) for s, n in per_rule["severities"].items()}
    return {per_rule["severity"]: sum(int(per_rule[c]) for c in CONFIDENCES)}


def severity_cell(row: Mapping[str, Any]) -> str:
    """The severity, or the split when a rule's findings have several ("high 1, low 7")."""
    severities = _by_severity(row) if "severities" in row else {}
    if len(severities) <= 1:
        return next(iter(severities), str(row["severity"]))
    return ", ".join(f"{s} {severities[s]}" for s in SEVERITIES if s in severities)


def severity_counts(findings: Mapping[str, Mapping[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for per_rule in findings.values():
        for severity, number in _by_severity(per_rule).items():
            counts[severity] += number
    return counts


def headline(data: Mapping[str, Any]) -> dict[str, int]:
    """Numbers for the summary and the README: scanned, skipped, repositories with at
    least one finding at high or critical, and findings by severity."""
    totals = dict.fromkeys(SEVERITIES, 0)
    serious = 0
    for repo in data["repositories"]:
        counts = severity_counts(repo["findings"])
        for severity in SEVERITIES:
            totals[severity] += counts[severity]
        serious += bool(counts["critical"] or counts["high"])
    return {
        "scanned": len(data["repositories"]),
        "skipped": len(data["skipped"]),
        "repos_high": serious,
        **totals,
    }


def area_of(rule_id: str) -> str:
    prefix = rule_id.split("-")[1] if rule_id.count("-") == 2 else ""
    return next((name for name, info in AREAS.items() if info.prefix == prefix), "other")


def area_table(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Per area (in the order of the areas): findings per severity and repositories with
    a finding of the area."""
    rows: dict[str, dict[str, Any]] = {
        name: {"area": name, "repos": 0, **dict.fromkeys(SEVERITIES, 0)} for name in AREAS
    }
    for repo in data["repositories"]:
        seen: set[str] = set()
        for rule_id, per_rule in repo["findings"].items():
            row = rows.setdefault(
                area_of(rule_id),
                {"area": area_of(rule_id), "repos": 0, **dict.fromkeys(SEVERITIES, 0)},
            )
            for severity, number in _by_severity(per_rule).items():
                row[severity] += number
            seen.add(row["area"])
        for name in seen:
            rows[name]["repos"] += 1
    return list(rows.values())


def area_lines(data: Mapping[str, Any]) -> list[str]:
    """The per-area table as Markdown rows (with header)."""
    lines = [
        "| Area | critical | high | medium | low | info | Repositories |",
        "|------|---------:|-----:|-------:|----:|-----:|-------------:|",
    ]
    for row in area_table(data):
        cells = " | ".join(str(row[s]) for s in SEVERITIES)
        lines.append(f"| {row['area']} | {cells} | {row['repos']} |")
    return lines


def _titles() -> dict[str, str]:
    return {rule.id: rule.title for rule in load_rules().rules}


def render_markdown(data: Mapping[str, Any]) -> str:
    """The benchmark report; generated, never edited by hand."""
    titles = _titles()
    head = headline(data)
    rules = rule_table(data)
    scanned = head["scanned"]
    lines = [
        "# False-positive benchmark",
        "",
        "<!-- Generated by scripts/fp_benchmark.py from docs/fp-benchmark.json. "
        "Do not edit by hand. -->",
        "",
        f"- Date: {data['date']}",
        f"- repovet version: {data['repovet']}",
        f"- Selection: the {data['requested']} most-starred public repositories on GitHub "
        f"(search API, {data['date']})",
        f"- Scan: `repovet scan URL --offline` at the default branch, all "
        f"{data['rules_loaded']} built-in rules; the trust area (GitHub API) is off",
        f"- Clone limit: {format_size(int(data['max_clone_size']))}",
        f"- Scanned: {scanned} · skipped: {head['skipped']}",
        "",
        "These are popular, maintained projects. Every finding below is either a false "
        "positive or an accurate finding of something the project does on purpose (an "
        "install script, a prebuilt binary, test data); the findings are not reviewed one "
        "by one here. A repository without findings is not thereby safe: repovet reports "
        "only what its rules detect in the checked scope.",
        "",
        "## Summary",
        "",
        f"- Repositories with at least one high or critical finding: {head['repos_high']} "
        f"of {scanned}",
        "- Findings by severity: " + ", ".join(f"{head[s]} {s}" for s in SEVERITIES),
        "",
        "## Findings per area",
        "",
        *area_lines(data),
        "",
        "## Rules that fire most often",
        "",
        "By number of repositories with at least one finding of the rule.",
        "",
        "| Rule | Severity | Title | Repositories | Findings |",
        "|------|----------|-------|-------------:|---------:|",
    ]
    if data.get("schema_version") == SCHEMA_VERSION:
        lines.insert(6, f"- Ruleset digest: `{data['ruleset_digest']}`")
    for row in rules[:TOP_RULES]:
        lines.append(
            f"| {row['rule']} | {severity_cell(row)} | {titles.get(row['rule'], '?')} "
            f"| {row['repos']} of {scanned} | {row['findings']} |"
        )
    if not rules:
        lines.append("| - | | no findings | | |")
    lines += [
        "",
        "## Findings per rule",
        "",
        "| Rule | Severity | Repositories | Findings | Confidence high/medium/low |",
        "|------|----------|-------------:|---------:|---------------------------:|",
    ]
    for row in sorted(rules, key=lambda r: r["rule"]):
        split = "/".join(str(row[c]) for c in CONFIDENCES)
        lines.append(
            f"| {row['rule']} | {severity_cell(row)} | {row['repos']} | {row['findings']} "
            f"| {split} |"
        )
    lines += [
        "",
        "## Findings per repository",
        "",
        "| Repository | Stars | Commit | Files | critical | high | medium | low | info | Rules |",
        "|------------|------:|--------|------:|---------:|-----:|-------:|----:|-----:|-------|",
    ]
    for repo in data["repositories"]:
        counts = severity_counts(repo["findings"])
        cells = " | ".join(str(counts[s]) for s in SEVERITIES)
        fired = ", ".join(
            f"{r} ({sum(int(c[k]) for k in CONFIDENCES)})" for r, c in repo["findings"].items()
        )
        lines.append(
            f"| {repo['repo']} | {repo['stars']} | `{repo['commit'][:12]}` | {repo['files']} "
            f"| {cells} | {fired or '-'} |"
        )
    lines += ["", "## Skipped", ""]
    if data["skipped"]:
        lines += ["| Repository | Stars | Reason |", "|------------|------:|--------|"]
        lines += [f"| {s['repo']} | {s['stars']} | {s['reason']} |" for s in data["skipped"]]
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def _validated(data: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], Section | None]:
    version = data.get("repovet")
    repositories, skipped = data.get("repositories"), data.get("skipped")
    if not isinstance(version, str) or not version:
        raise ValueError("benchmark needs a scanner version")
    if (
        not isinstance(repositories, list)
        or len(repositories) > 1000
        or not isinstance(skipped, list)
        or len(skipped) > 1000
    ):
        raise ValueError("benchmark needs bounded repository lists")
    by_name: dict[str, dict[str, Any]] = {}
    for repo in repositories:
        if not isinstance(repo, dict):
            raise ValueError("invalid benchmark repository")
        name, commit, findings = repo.get("repo"), repo.get("commit"), repo.get("findings")
        if not isinstance(name, str) or not _FULL_NAME.fullmatch(name) or name in by_name:
            raise ValueError("invalid or duplicate benchmark repository name")
        if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
            raise ValueError("benchmark repository needs its full commit id")
        if not isinstance(findings, dict):
            raise ValueError("invalid benchmark aggregates")
        for rule_id, entry in findings.items():
            if not isinstance(rule_id, str) or not isinstance(entry, dict):
                raise ValueError("invalid benchmark rule counts")
            if entry.get("severity") not in SEVERITIES or any(
                type(entry.get(c)) is not int or entry[c] < 0 for c in CONFIDENCES
            ):
                raise ValueError("invalid benchmark confidence or severity counts")
            split = entry.get("severities", {})
            if not isinstance(split, dict) or any(
                severity not in SEVERITIES or type(count) is not int or count < 0
                for severity, count in split.items()
            ):
                raise ValueError("invalid benchmark severity counts")
        by_name[name] = repo
    for item in skipped:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("repo"), str)
            or not _FULL_NAME.fullmatch(item["repo"])
        ):
            raise ValueError("invalid skipped repository")
    schema = data.get("schema_version")
    if schema is None:
        return by_name, None
    digest = data.get("ruleset_digest")
    if schema != SCHEMA_VERSION or not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ValueError("benchmark needs schema 2.0 and a valid ruleset digest")
    records: dict[str, list[dict[str, Any]]] = {}
    coverage: dict[str, list[dict[str, Any]]] = {}
    snapshots: dict[str, dict[str, str] | None] = {}
    total = 0
    for name, repo in by_name.items():
        raw = repo.get("finding_records")
        if not isinstance(raw, list) or len(raw) > _MAX_RECORDS:
            raise ValueError("benchmark needs bounded individual finding records")
        total += len(raw)
        if total > _MAX_RECORDS:
            raise ValueError("benchmark has too many individual records")
        parsed = [compact_finding(value) for value in raw]
        if parsed != raw:
            raise ValueError("stored benchmark records must omit payload text and references")
        if any(finding["in_chain"] is not None for finding in parsed):
            raise ValueError("benchmark records must count chains only once")
        derived = summarize({"findings": parsed, "scan": {"files_scanned": 0}})["findings"]
        if derived != repo["findings"]:
            raise ValueError("benchmark aggregates disagree with individual records")
        records[name] = parsed
        gaps = repo.get("coverage_records")
        if not isinstance(gaps, list) or len(gaps) > _MAX_RECORDS or "snapshot" not in repo:
            raise ValueError("benchmark needs coverage records and snapshot metadata")
        parsed_gaps = [compact_coverage(value) for value in gaps]
        if parsed_gaps != gaps:
            raise ValueError("stored benchmark coverage must omit external payload text")
        coverage[name] = parsed_gaps
        snapshots[name] = snapshot_from_data(repo["snapshot"])
    return by_name, Section(version, digest, records, coverage, snapshots)


def _read_recorded(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("benchmark data must be a JSON object")
    _validated(value)
    return value


def compare_runs(before: Mapping[str, Any], after: Mapping[str, Any]) -> int:
    """Compare only successful common repos; commit drift is never attributed to rules."""
    old, old_section = _validated(before)
    new, new_section = _validated(after)
    common = set(old) & set(new)
    names = set(old) | set(new)
    names.update(item["repo"] for data in (before, after) for item in data["skipped"])
    for name in sorted(names - common):
        print(
            f"warning: {name} not comparable: no successful scan in both runs",
            file=sys.stderr,
        )
    for name in sorted(common):
        if old[name]["commit"].lower() != new[name]["commit"].lower():
            print(
                f"warning: {name} commit differs; changes may reflect repository snapshots",
                file=sys.stderr,
            )
    if not common:
        print("no common successful repositories to compare", file=sys.stderr)
        return EXIT_ABORTED
    print(f"comparing {len(common)} common successful repositories")
    if old_section is not None and new_section is not None:
        return print_finding_changes(_subset(old_section, common), _subset(new_section, common))
    print("aggregate comparison only; finding identities unavailable in counts-only data")
    if before["repovet"] != after["repovet"]:
        print("warning: scanner version differs", file=sys.stderr)
    counts = []
    for repositories in (old, new):
        counts.append(
            {
                name: {
                    rule: {c: entry[c] for c in CONFIDENCES}
                    for rule, entry in repositories[name]["findings"].items()
                }
                for name in sorted(common)
            }
        )
    print_changes(counts[0], counts[1])
    areas = [
        {
            row["area"]: row
            for row in area_table({"repositories": [repos[n] for n in sorted(common)]})
        }
        for repos in (old, new)
    ]
    for area in sorted(areas[0].keys() | areas[1].keys()):
        for severity in SEVERITIES:
            old_count, new_count = (a.get(area, {}).get(severity, 0) for a in areas)
            if old_count != new_count:
                print(f"{area} {severity}: {old_count} -> {new_count}")
    return EXIT_OK


def _subset(section: Section, names: set[str]) -> Section:
    return Section(
        section.version,
        section.ruleset_digest,
        {name: section.records[name] for name in sorted(names)},
        {name: section.coverage.get(name, []) for name in sorted(names)},
        {name: section.snapshots.get(name) for name in sorted(names)},
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-n", type=int, default=50, metavar="N", help="number of repositories")
    parser.add_argument(
        "--max-clone-size",
        type=parse_size,
        default=DEFAULT_MAX_CLONE_SIZE,
        metavar="SIZE",
        help=f"skip larger repositories (default: {format_size(DEFAULT_MAX_CLONE_SIZE)})",
    )
    parser.add_argument("--data", type=Path, default=DATA, metavar="FILE")
    parser.add_argument("--markdown", type=Path, default=MARKDOWN, metavar="FILE")
    parser.add_argument(
        "--compare", type=Path, metavar="FILE", help="earlier benchmark data to compare"
    )
    parser.add_argument(
        "--render-only", action="store_true", help="render the Markdown from the data file"
    )
    return parser


def run(argv: Sequence[str], client: GitHubClient | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        previous = _read_recorded(args.compare) if args.compare else None
    except (OSError, ValueError):
        print("comparison needs valid recorded benchmark data", file=sys.stderr)
        return EXIT_USAGE
    if args.render_only:
        try:
            recorded = _read_recorded(args.data)
            args.markdown.write_text(render_markdown(recorded), encoding="utf-8")
            print("\n".join(area_lines(recorded)))
            return compare_runs(previous, recorded) if previous is not None else EXIT_OK
        except (OSError, ValueError):
            print("could not render or compare the recorded benchmark", file=sys.stderr)
            return EXIT_USAGE
    if not 1 <= args.n <= 1000:
        print("-n must be between 1 and 1000", file=sys.stderr)
        return EXIT_USAGE
    if client is None:
        token, _ = token_from_env(os.environ)
        client = GitHubClient(UrllibTransport(), token=token, budget=args.n // _PER_PAGE + 2)
    try:
        repos = most_starred(client, args.n)
    except ApiError as exc:
        print(f"GitHub search failed: {exc}", file=sys.stderr)
        return EXIT_ABORTED
    rules = load_rules()
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "date": datetime.now(UTC).date().isoformat(),
        "repovet": __version__,
        "ruleset_digest": rules.digest,
        "requested": args.n,
        "rules_loaded": len(rules.active()),
        "max_clone_size": args.max_clone_size,
        "repositories": [],
        "skipped": [],
    }
    with tempfile.TemporaryDirectory(prefix="repovet-benchmark-") as tmp:
        for number, repo in enumerate(repos, 1):
            print(f"[{number}/{len(repos)}] {repo['repo']} ...", file=sys.stderr)
            outcome = scan_repository(repo, Path(tmp), args.max_clone_size)
            known = {"repo": repo["repo"], "stars": repo["stars"]}
            if isinstance(outcome, str):
                data["skipped"].append(known | {"reason": outcome})
            else:
                if (
                    outcome.pop("ruleset_digest", None) != data["ruleset_digest"]
                    or outcome.pop("tool_version", None) != __version__
                ):
                    print(
                        "scanner metadata changed during the benchmark; data not written",
                        file=sys.stderr,
                    )
                    return EXIT_ABORTED
                data["repositories"].append(known | outcome)
    if load_rules().digest != data["ruleset_digest"]:
        print("ruleset changed during the benchmark; data not written", file=sys.stderr)
        return EXIT_ABORTED
    try:
        _validated(data)
        args.data.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        args.markdown.write_text(render_markdown(data), encoding="utf-8")
    except (OSError, ValueError):
        print("could not validate or write the benchmark data", file=sys.stderr)
        return EXIT_ABORTED
    head = headline(data)
    print("\n".join(area_lines(data)))
    print(f"{head['scanned']} scanned, {head['skipped']} skipped; written {args.markdown}")
    return compare_runs(previous, data) if previous is not None else EXIT_OK


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
