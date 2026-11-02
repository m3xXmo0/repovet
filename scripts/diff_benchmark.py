"""Diff benchmark: how often ``repovet diff`` ends with an incomplete comparison.

Usage: python scripts/diff_benchmark.py [-n N] [--max-clone-size SIZE] [--render-only]

N repositories (default 12) are taken from the successful scans in
``docs/fp-benchmark.json``, spread evenly over their file counts. Each is fetched once
with its history through repovet's own clone code (dulwich: object store only, no
checkout, no hooks, no submodules). Its default branch is then compared like
``repovet diff PATH --base HEAD~20`` and ``--base HEAD~1`` with the default
``--fail-on``; ``HEAD~N`` follows first parents and is resolved here, because diff only
accepts full revision names. Only the fetch uses the network; the comparisons run
offline. A repository that cannot be fetched, is larger than the clone limit or has
too short a history is recorded as skipped and replaced by its nearest neighbour.

Per run the script records the exit code, the new and worsened findings and, for an
incomplete comparison, the cause of every blocking issue. It also records what two
possible gate refinements would have returned; these are measurements only, the gate
itself is unchanged. The results are written to ``docs/diff-benchmark.json`` (data)
and ``docs/diff-benchmark.md`` (rendered from the data; ``--render-only`` renders it
again without fetching).

This needs the network and is not part of the test suite. Nothing from the
repositories is run; the temporary folders are deleted after each repository.
"""

import argparse
import contextlib
import io
import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from repovet import __version__
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.engine.loader import load_rules
from repovet.limits import format_size, parse_size
from repovet.models import Severity
from repovet.report.sanitize import sanitize, sanitize_path
from repovet.sources import remote
from repovet.sources.gitobjects import GitObjectError, GitObjects

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "fp-benchmark.json"
DATA = ROOT / "docs" / "diff-benchmark.json"
MARKDOWN = ROOT / "docs" / "diff-benchmark.md"
SCHEMA_VERSION = "1.0"
DEPTHS = (20, 1)
FAIL_ON = "high"
EXIT_CODES = (EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_ABORTED)
CAUSES = (
    "global gap",
    "changed file unchecked",
    "previous finding unknown",
    "ambiguity",
    "budget",
    "aborted",
)
_ATTEMPTS = 3
_SAMPLE = 2
_BLOCKING = {"skipped", "partial", "failed"}
_AMBIGUOUS = "Finding occurrences have equally plausible matches"
_OVER_BUDGET = "Finding comparison exceeds its bounded matching budget"
_UNKNOWN = "A previous finding is no longer in a checked scope"


def spread(repositories: Sequence[Mapping[str, Any]], count: int) -> list[list[str]]:
    """``count`` slots evenly spread over the repositories sorted by file count; each slot
    lists its repository first, then its nearest neighbours as replacements."""
    ordered = [r["repo"] for r in sorted(repositories, key=lambda r: (r["files"], r["repo"]))]
    if not ordered or count < 1:
        return []
    last = len(ordered) - 1
    targets = [round(i * last / (count - 1)) if count > 1 else 0 for i in range(count)]
    return [
        [ordered[j] for j in sorted(range(len(ordered)), key=lambda j: (abs(j - t), j))]
        for t in targets
    ]


def first_parent(objects: GitObjects, commit: bytes, steps: int) -> bytes | None:
    """The commit ``steps`` first parents back (``HEAD~steps``), or None if too short."""
    for _ in range(steps):
        parents = objects.commit(commit).parents
        if not parents:
            return None
        commit = bytes(parents[0])
    return commit


def _inside(path: str, parent: str) -> bool:
    parent = parent.rstrip("/")
    return parent in {"", "."} or path == parent or path.startswith(parent + "/")


def _gaps(coverage: Sequence[Mapping[str, Any]]) -> tuple[dict[str, set[str]], set[str]]:
    """Unchecked paths with their reasons and reasons without complete paths, as the
    comparison derives them from the Head report."""
    paths: dict[str, set[str]] = {}
    global_gaps: set[str] = set()
    for item in coverage:
        scope, status, reason = item["scope"], item["status"], item["reason"]
        if scope == "scan" and status in _BLOCKING:
            global_gaps.add(reason)
            continue
        if not (scope == "file" and status in _BLOCKING) and scope != "git:submodules":
            continue
        known = item["paths"] or item["sample"]
        if not known or item["count"] > len(known):
            global_gaps.add(reason)
        for path in known:
            paths.setdefault(path, set()).add(reason)
    return paths, global_gaps


def classify(issue: Mapping[str, Any], coverage: Sequence[Mapping[str, Any]]) -> str:
    """The cause of one blocking issue of a diff report."""
    reason, paths = issue["reason"], issue["paths"]
    if reason == _AMBIGUOUS:
        return "ambiguity"
    if reason == _OVER_BUDGET:
        return "budget"
    if reason == _UNKNOWN:
        return "previous finding unknown"
    by_path, global_gaps = _gaps(coverage)
    if len(paths) == 1 and "; ".join(sorted(by_path.get(paths[0], ()))) == reason:
        return "changed file unchecked"
    if reason.startswith("Time limit"):
        return "budget"
    return "global gap" if reason in global_gaps else "changed file unchecked"


def _counted(change: Mapping[str, Any]) -> bool:
    after = change["after"]
    return after is not None and after["in_chain"] is None


def _gated(change: Mapping[str, Any], fail_on: Severity) -> bool:
    return (
        _counted(change)
        and Severity.parse(change["after"]["severity"]) >= fail_on
        and (change["status"] == "new" or change["worsened"])
    )


def _serious_before(report: Mapping[str, Any], fail_on: Severity) -> list[str]:
    return [
        f["location"]["path"]
        for f in report["findings"]
        if f["location"] is not None and Severity.parse(f["severity"]) >= fail_on
    ]


def evaluate(diff: Mapping[str, Any], fail_on: Severity) -> dict[str, Any]:
    """Counts, blocking causes and the outcome of both proposed refinements:
    (a) a new or worsened finding at ``fail_on`` returns 1 even when incomplete;
    (b) a coverage gap blocks only where a Base finding at ``fail_on`` lies in a gap."""
    changes = diff["changes"]
    coverage = diff["head"]["report"]["coverage"]
    serious = _serious_before(diff["base"]["report"], fail_on)
    gated = sum(_gated(c, fail_on) for c in changes)
    issues: list[dict[str, Any]] = []
    still_blocking = False
    for issue in diff["issues"]:
        if not issue["blocking"]:
            continue
        cause = classify(issue, coverage)
        issues.append(
            {
                "cause": cause,
                "reason": sanitize(issue["reason"], 160),
                "paths": len(issue["paths"]),
                "sample": [sanitize_path(p) for p in issue["paths"][:_SAMPLE]],
            }
        )
        hits = any(_inside(path, gap) for gap in issue["paths"] for path in serious)
        if cause in {"ambiguity", "budget"} or hits:
            still_blocking = True
    code = int(diff["exit_code"])
    return {
        "exit_code": code,
        "new": sum(_counted(c) and c["status"] == "new" for c in changes),
        "worsened": sum(_counted(c) and bool(c["worsened"]) for c in changes),
        "gated": gated,
        "summary": dict(diff["summary"]),
        "causes": sorted({i["cause"] for i in issues}),
        "issues": issues,
        "option_a": EXIT_FINDINGS if gated else code,
        "option_b": EXIT_ABORTED if still_blocking else (EXIT_FINDINGS if gated else EXIT_OK),
    }


def _aborted(code: int, errors: str) -> dict[str, Any]:
    """A run without a diff report: aborted (3) or a usage error (2)."""
    lines = [line for line in errors.splitlines() if line.strip()]
    detail = sanitize(lines[-1], 200) if lines else "no message"
    issues: list[dict[str, Any]] = []
    if code == EXIT_ABORTED:
        cause = "budget" if "limit" in detail else "aborted"
        issues.append({"cause": cause, "reason": detail, "paths": 0, "sample": []})
    return {
        "exit_code": code,
        "new": 0,
        "worsened": 0,
        "gated": 0,
        "summary": {},
        "causes": [issue["cause"] for issue in issues],
        "issues": issues,
        "option_a": code,
        "option_b": code,
    }


def compare(root: Path, base: str, head: str, output: Path) -> dict[str, Any]:
    """Run ``repovet diff`` on a prepared repository and evaluate its JSON report."""
    output.unlink(missing_ok=True)
    args = ["diff", str(root), "--base", base, "--head", head, "--offline"]
    args += ["--fail-on", FAIL_ON, "--format", "json", "-o", str(output)]
    errors = io.StringIO()
    with contextlib.redirect_stderr(errors):
        code = main(args)
    if not output.exists():
        return _aborted(code, errors.getvalue())
    result = evaluate(json.loads(output.read_text(encoding="utf-8")), Severity.parse(FAIL_ON))
    if result["exit_code"] != code:
        raise ValueError("diff report and exit code disagree")
    return result


def measure(
    name: str,
    workdir: Path,
    max_clone_size: int,
    transport: remote.Transport | None = None,
) -> list[dict[str, Any]] | str:
    """Both runs for one repository, or the reason it was skipped."""
    repo = remote.parse_github_url(f"https://github.com/{name}")
    # The object store is kept after the fetch so that it can be opened as a local
    # repository; it is deleted here in every case.
    kept: list[Path] = []
    try:
        with remote.clone(
            repo,
            max_bytes=max_clone_size,
            keep=True,
            transport=transport,
            on_cleanup=lambda path, _error: kept.append(path),
        ) as fetched:
            head = fetched.commit.decode("ascii")
            bases = [
                (depth, first_parent(fetched.objects, fetched.commit, depth)) for depth in DEPTHS
            ]
        resolved = [(depth, base.decode("ascii")) for depth, base in bases if base is not None]
        if len(resolved) < len(DEPTHS):
            return f"fewer than {max(DEPTHS) + 1} commits on the first-parent line"
        workspace = kept[0]
        git_dir = workspace / ".git"
        git_dir.mkdir()
        (workspace / "objects").rename(git_dir / "objects")
        (git_dir / "HEAD").write_text(head + "\n", encoding="ascii")
        return [
            {"repo": name, "range": f"HEAD~{depth}..HEAD", "base": base, "head": head}
            | compare(workspace, base, head, workdir / "diff.json")
            for depth, base in resolved
        ]
    except (remote.CloneError, GitObjectError) as exc:
        return sanitize(f"fetch failed: {exc}", 200)
    finally:
        for path in kept:
            remote._remove_workspace(path)


def totals(data: Mapping[str, Any], key: str = "exit_code") -> dict[str, dict[int, int]]:
    """Exit codes (or a simulated option) per range and in total."""
    rows: dict[str, dict[int, int]] = {}
    for run in data["runs"]:
        for label in (run["range"], "all"):
            row = rows.setdefault(label, dict.fromkeys(EXIT_CODES, 0))
            row[run[key]] = row.get(run[key], 0) + 1
    return rows


def cause_counts(data: Mapping[str, Any]) -> dict[str, int]:
    """Runs with exit 3 per cause (a run can have several causes)."""
    counts = dict.fromkeys(CAUSES, 0)
    for run in data["runs"]:
        if run["exit_code"] == EXIT_ABORTED:
            for cause in run["causes"]:
                counts[cause] = counts.get(cause, 0) + 1
    return counts


def _exit_rows(rows: Mapping[str, Mapping[int, int]]) -> list[str]:
    lines = ["| Range | 0 | 1 | 2 | 3 | Runs |", "|-------|--:|--:|--:|--:|-----:|"]
    for label in [*(f"HEAD~{d}..HEAD" for d in DEPTHS), "all"]:
        row = rows.get(label, dict.fromkeys(EXIT_CODES, 0))
        cells = " | ".join(str(row.get(code, 0)) for code in EXIT_CODES)
        lines.append(f"| {label} | {cells} | {sum(row.values())} |")
    return lines


def render_markdown(data: Mapping[str, Any]) -> str:
    """The benchmark report; generated, never edited by hand."""
    runs = data["runs"]
    lines = [
        "# Diff benchmark",
        "",
        "<!-- Generated by scripts/diff_benchmark.py from docs/diff-benchmark.json. "
        "Do not edit by hand. -->",
        "",
        f"- Date: {data['date']}",
        f"- repovet version: {data['repovet']}",
        f"- Ruleset digest: `{data['ruleset_digest']}`",
        f"- Selection: {data['requested']} repositories from the false-positive benchmark "
        f"of {data['source_date']}, spread over their file counts",
        "- Runs: `repovet diff PATH --base HEAD~20` and `--base HEAD~1` on the default "
        f"branch (first parents), `--fail-on {data['fail_on']}`, all built-in rules",
        f"- Clone limit: {format_size(int(data['max_clone_size']))}",
        f"- Runs: {len(runs)} · skipped repositories: {len(data['skipped'])}",
        "",
        "Exit code 3 means the comparison was incomplete: a blocking coverage gap, an "
        "unresolved match or a limit. Exit code 0 only means that no new or worsened "
        "finding reached the threshold in the checked scope.",
        "",
        "## Exit codes",
        "",
        *_exit_rows(totals(data)),
        "",
        "## Causes of exit code 3",
        "",
        "Runs per cause; one run can have several causes.",
        "",
        "| Cause | Runs |",
        "|-------|-----:|",
        *(f"| {cause} | {count} |" for cause, count in cause_counts(data).items()),
        "",
        "## Possible refinements (measured, not implemented)",
        "",
        "(a) A new or worsened finding at `--fail-on` returns 1 even when the comparison "
        "is incomplete. (b) A coverage gap blocks only where a Base finding at `--fail-on` "
        "lies inside the unchecked path; ambiguity and limits still block.",
        "",
        "| Gate | 0 | 1 | 2 | 3 |",
        "|------|--:|--:|--:|--:|",
    ]
    for label, key in (("current", "exit_code"), ("(a)", "option_a"), ("(b)", "option_b")):
        row = totals(data, key).get("all", dict.fromkeys(EXIT_CODES, 0))
        lines.append(f"| {label} | " + " | ".join(str(row.get(c, 0)) for c in EXIT_CODES) + " |")
    lines += [
        "",
        "## Runs",
        "",
        "| Repository | Files | Range | Base | Exit | New | Worsened | At threshold "
        "| Causes | (a) | (b) |",
        "|------------|------:|-------|------|-----:|----:|---------:|-------------:"
        "|--------|----:|----:|",
    ]
    for run in runs:
        lines.append(
            f"| {run['repo']} | {run['files']} | {run['range']} | `{run['base'][:12]}` "
            f"| {run['exit_code']} | {run['new']} | {run['worsened']} | {run['gated']} "
            f"| {', '.join(run['causes']) or '-'} | {run['option_a']} | {run['option_b']} |"
        )
    lines += ["", "## Blocking issues", "", "Grouped per run by cause and reason."]
    lines.append("")
    grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for run in runs:
        for issue in run["issues"]:
            key = (run["repo"], run["range"], issue["cause"], issue["reason"])
            grouped.setdefault(key, []).append(issue)
    if grouped:
        lines += [
            "| Repository | Range | Cause | Issues | Example | Reason |",
            "|------------|-------|-------|-------:|---------|--------|",
        ]
        for (repo, label, cause, reason), issues in grouped.items():
            example = next((f"`{i['sample'][0]}`" for i in issues if i["sample"]), "-")
            lines.append(f"| {repo} | {label} | {cause} | {len(issues)} | {example} | {reason} |")
    else:
        lines.append("None.")
    lines += ["", "## Skipped", ""]
    if data["skipped"]:
        lines += ["| Repository | Reason |", "|------------|--------|"]
        lines += [f"| {s['repo']} | {s['reason']} |" for s in data["skipped"]]
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-n", type=int, default=12, metavar="N", help="number of repositories")
    parser.add_argument(
        "--max-clone-size",
        type=parse_size,
        default=remote.DEFAULT_MAX_CLONE_SIZE,
        metavar="SIZE",
        help=f"skip larger repositories (default: {format_size(remote.DEFAULT_MAX_CLONE_SIZE)})",
    )
    parser.add_argument("--source", type=Path, default=SOURCE, metavar="FILE")
    parser.add_argument("--data", type=Path, default=DATA, metavar="FILE")
    parser.add_argument("--markdown", type=Path, default=MARKDOWN, metavar="FILE")
    parser.add_argument(
        "--render-only", action="store_true", help="render the Markdown from the data file"
    )
    return parser


def run(argv: Sequence[str], transport: remote.Transport | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.render_only:
        try:
            recorded = json.loads(args.data.read_text(encoding="utf-8"))
            args.markdown.write_text(render_markdown(recorded), encoding="utf-8")
        except (OSError, ValueError, KeyError, TypeError):
            print("could not render the recorded benchmark", file=sys.stderr)
            return EXIT_USAGE
        return EXIT_OK
    if not 1 <= args.n <= 100:
        print("-n must be between 1 and 100", file=sys.stderr)
        return EXIT_USAGE
    try:
        source = json.loads(args.source.read_text(encoding="utf-8"))
        files = {r["repo"]: int(r["files"]) for r in source["repositories"]}
        slots = spread(source["repositories"], args.n)
    except (OSError, ValueError, KeyError, TypeError):
        print("the source benchmark data could not be read", file=sys.stderr)
        return EXIT_USAGE
    digest = load_rules().digest
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "date": datetime.now(UTC).date().isoformat(),
        "repovet": __version__,
        "ruleset_digest": digest,
        "source_date": source.get("date", ""),
        "requested": args.n,
        "fail_on": FAIL_ON,
        "max_clone_size": args.max_clone_size,
        "runs": [],
        "skipped": [],
    }
    used: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="repovet-diff-benchmark-") as tmp:
        for number, slot in enumerate(slots, 1):
            tried = 0
            for name in slot:
                if name in used or tried == _ATTEMPTS:
                    continue
                used.add(name)
                tried += 1
                print(f"[{number}/{len(slots)}] {name} ...", file=sys.stderr)
                outcome = measure(name, Path(tmp), args.max_clone_size, transport)
                if isinstance(outcome, str):
                    data["skipped"].append({"repo": name, "reason": outcome})
                    continue
                data["runs"] += [entry | {"files": files[name]} for entry in outcome]
                break
    if load_rules().digest != digest:
        print("ruleset changed during the benchmark; data not written", file=sys.stderr)
        return EXIT_ABORTED
    try:
        args.data.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        args.markdown.write_text(render_markdown(data), encoding="utf-8")
    except OSError:
        print("could not write the benchmark data", file=sys.stderr)
        return EXIT_ABORTED
    print("\n".join(_exit_rows(totals(data))))
    print(f"{len(data['runs'])} runs, {len(data['skipped'])} skipped; written {args.markdown}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
