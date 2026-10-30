"""False-positive benchmark: scan the most-starred public GitHub repositories.

Usage: python scripts/fp_benchmark.py [-n N] [--max-clone-size SIZE] [--render-only]

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
scan.
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

from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.engine.loader import load_rules
from repovet.github.client import ApiError, GitHubClient, token_from_env
from repovet.github.transport import UrllibTransport
from repovet.limits import format_size, parse_size
from repovet.report.sanitize import sanitize
from repovet.sources.remote import DEFAULT_MAX_CLONE_SIZE

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "fp-benchmark.json"
MARKDOWN = ROOT / "docs" / "fp-benchmark.md"
SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
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


def summarize(report: Mapping[str, Any]) -> dict[str, Any]:
    """Commit, file count and findings per rule: confidence split, findings per severity
    (a finding can be reported below its rule's severity) and the highest severity."""
    rules: dict[str, dict[str, Any]] = {}
    for finding in report["findings"]:
        entry = rules.setdefault(
            finding["rule_id"],
            {"severity": finding["severity"], **dict.fromkeys(CONFIDENCES, 0), "severities": {}},
        )
        entry[finding["confidence"]] += 1
        severities = entry["severities"]
        severities[finding["severity"]] = severities.get(finding["severity"], 0) + 1
        entry["severity"] = _highest(severities)
    source = report.get("facts", {}).get("source") or {}
    return {
        "commit": str(source.get("commit") or ""),
        "files": int(report["scan"]["files_scanned"]),
        "findings": dict(sorted(rules.items())),
    }


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
    return summarize(json.loads(report.read_text(encoding="utf-8")))


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
        "## Rules that fire most often",
        "",
        "By number of repositories with at least one finding of the rule.",
        "",
        "| Rule | Severity | Title | Repositories | Findings |",
        "|------|----------|-------|-------------:|---------:|",
    ]
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
        "--render-only", action="store_true", help="render the Markdown from the data file"
    )
    return parser


def run(argv: Sequence[str], client: GitHubClient | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.render_only:
        recorded = json.loads(args.data.read_text(encoding="utf-8"))
        args.markdown.write_text(render_markdown(recorded), encoding="utf-8")
        return EXIT_OK
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
    data: dict[str, Any] = {
        "date": datetime.now(UTC).date().isoformat(),
        "repovet": __version__,
        "requested": args.n,
        "rules_loaded": len(load_rules().active()),
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
                data["repositories"].append(known | outcome)
    args.data.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(render_markdown(data), encoding="utf-8")
    head = headline(data)
    print(f"{head['scanned']} scanned, {head['skipped']} skipped; written {args.markdown}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
