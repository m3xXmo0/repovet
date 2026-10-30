"""Compare repovet's scan of its own repository with a baseline of expected findings.

Usage: python scripts/self_scan.py REPORT [--baseline FILE] [--update] [--root DIR]

REPORT is the JSON report of ``repovet scan . --offline --format json``. This
repository contains detection patterns and test data on purpose, so some findings are
expected; they are listed in ``tests/self-scan-baseline.json`` as rule + path with a
count. The check fails (exit 1) only when a rule reports more findings in a file than
the baseline allows. Lines are not compared: they move with every edit.

Repository-wide findings (from the Git history, without a file) are not compared: they
depend on the commits, not on the content. Findings that disappeared are listed, so the
baseline can be tightened with ``--update``. ``--update`` writes the baseline from the
report and leaves out paths that Git ignores in this checkout (``.gitignore`` at the
root and ``.git/info/exclude``), so local files never end up in it. Only a simple
subset of the ignore syntax is supported: no negation (``!``) and no nested
``.gitignore`` files.
"""

import argparse
import fnmatch
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from repovet import __version__

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "self-scan-baseline.json"
EXIT_OK, EXIT_NEW, EXIT_USAGE = 0, 1, 2

type Key = tuple[str, str]


def file_findings(report: Mapping[str, Any]) -> Counter[Key]:
    """(rule, path) -> number of findings, for findings that have a file."""
    counts: Counter[Key] = Counter()
    for finding in report["findings"]:
        location = finding.get("location")
        if location and location.get("path"):
            counts[(str(finding["rule_id"]), str(location["path"]))] += 1
    return counts


def load_baseline(path: Path) -> Counter[Key]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Counter({(e["rule"], e["path"]): int(e["count"]) for e in data["expected"]})


def baseline_json(counts: Mapping[Key, int]) -> str:
    data = {
        "description": (
            "Findings that repovet's scan of its own repository is expected to report: "
            "detection patterns and test data. Written by scripts/self_scan.py --update."
        ),
        "repovet": __version__,
        "expected": [
            {"rule": rule, "path": path, "count": count}
            for (rule, path), count in sorted(counts.items())
        ],
    }
    return json.dumps(data, indent=2) + "\n"


def ignore_patterns(root: Path) -> list[str]:
    patterns: list[str] = []
    for name in (".gitignore", ".git/info/exclude"):
        path = root / name
        if path.is_file():
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if line and not line.startswith(("#", "!")):
                    patterns.append(line)
    return patterns


def is_ignored(path: str, patterns: Iterable[str]) -> bool:
    """Whether ``path`` (relative, with '/') or one of its folders matches a pattern."""
    parts = path.split("/")
    for raw in patterns:
        directory_only = raw.endswith("/")
        pattern = raw.rstrip("/")
        anywhere = pattern.startswith("**/")
        pattern = pattern.removeprefix("**/").removeprefix("/")
        anchored = not anywhere and "/" in raw.rstrip("/")
        width = pattern.count("/") + 1
        starts = [0] if anchored else range(len(parts))
        for start in starts:
            end = start + width
            # A directory pattern must match a folder, not the file itself.
            if end > len(parts) or (directory_only and end == len(parts)):
                continue
            if fnmatch.fnmatchcase("/".join(parts[start:end]), pattern):
                return True
    return False


def compare(found: Counter[Key], expected: Counter[Key]) -> tuple[list[str], list[str]]:
    """Lines for new findings (beyond the baseline) and for fewer findings than expected."""
    new = [
        f"{rule} {path}: {count} finding(s), baseline {expected[(rule, path)]}"
        for (rule, path), count in sorted(found.items())
        if count > expected[(rule, path)]
    ]
    gone = [
        f"{rule} {path}: {found[(rule, path)]} finding(s), baseline {count}"
        for (rule, path), count in sorted(expected.items())
        if found[(rule, path)] < count
    ]
    return new, gone


def run(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="JSON report of the self-scan")
    parser.add_argument("--baseline", type=Path, default=BASELINE, metavar="FILE")
    parser.add_argument("--update", action="store_true", help="write the baseline")
    parser.add_argument("--root", type=Path, default=ROOT, help="checkout with the ignore files")
    args = parser.parse_args(argv)

    found = file_findings(json.loads(args.report.read_text(encoding="utf-8")))
    if args.update:
        patterns = ignore_patterns(args.root)
        kept = Counter({key: n for key, n in found.items() if not is_ignored(key[1], patterns)})
        args.baseline.write_text(baseline_json(kept), encoding="utf-8")
        left_out = sum(found.values()) - sum(kept.values())
        print(f"baseline written: {sum(kept.values())} findings ({left_out} in ignored paths)")
        return EXIT_OK
    if not args.baseline.is_file():
        print(f"no baseline at {args.baseline}; create it with --update", file=sys.stderr)
        return EXIT_USAGE

    new, gone = compare(found, load_baseline(args.baseline))
    if gone:
        print("Fewer findings than in the baseline (run --update to tighten it):")
        print("\n".join(f"  {line}" for line in gone))
    if new:
        print("New findings that are not in the baseline:")
        print("\n".join(f"  {line}" for line in new))
        return EXIT_NEW
    print(f"no new findings ({sum(found.values())} expected findings in files)")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
