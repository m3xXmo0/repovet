"""Scan the false-positive corpus by URL and count the findings per rule.

Usage: python scripts/corpus_counts.py [--only NAME]... [--save FILE] [--compare FILE]

Every repository from ``tests/corpus/corpus.yaml`` is fetched at its pinned commit and
scanned offline (no GitHub API), exactly like ``repovet scan URL --ref COMMIT
--offline``. The table lists the findings per rule and per repository, split by
confidence. ``--save`` writes the counts as JSON; ``--compare`` prints the difference
to such a file from an earlier run (for example of the previous version), so changes
in false positives show up rule by rule.

This needs the network and is not part of the test suite. Nothing from the
repositories is run; they are read from Git objects in a temporary folder that is
deleted after each scan.
"""

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from repovet import __version__
from repovet.cli import EXIT_FINDINGS, EXIT_OK, main

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests" / "corpus" / "corpus.yaml"
CONFIDENCES = ("high", "medium", "low")

# {repository name: {rule id: {confidence: count}}}
type Counts = dict[str, dict[str, dict[str, int]]]


def load_manifest(path: Path) -> list[dict[str, Any]]:
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise SystemExit(f"{path}: expected a list of repositories")
    return entries


def scan_entry(entry: Mapping[str, Any], workdir: Path) -> dict[str, dict[str, int]] | str:
    """Counts per rule and confidence, or an error text."""
    report = workdir / f"{entry['name']}.json"
    url = f"https://github.com/{entry['repo']}"
    args = ["scan", url, "--ref", str(entry["commit"]), "--offline", "--format", "json"]
    code = main([*args, "-o", str(report)])
    if code not in (EXIT_OK, EXIT_FINDINGS):
        return f"scan failed with exit code {code}"
    data = json.loads(report.read_text(encoding="utf-8"))
    counts: dict[str, dict[str, int]] = {}
    for finding in data["findings"]:
        per_rule = counts.setdefault(finding["rule_id"], dict.fromkeys(CONFIDENCES, 0))
        per_rule[finding["confidence"]] += 1
    return counts


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument("--save", type=Path, metavar="FILE", help="write the counts as JSON")
    parser.add_argument("--compare", type=Path, metavar="FILE", help="earlier --save output")
    return parser


def run(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(argv)

    entries = [e for e in load_manifest(args.manifest) if not args.only or e["name"] in args.only]
    counts: Counts = {}
    errors: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="repovet-corpus-") as tmp:
        for entry in entries:
            print(f"scanning {entry['repo']} @ {str(entry['commit'])[:12]} ...", file=sys.stderr)
            outcome = scan_entry(entry, Path(tmp))
            if isinstance(outcome, str):
                errors[entry["name"]] = outcome
            else:
                counts[entry["name"]] = outcome
    print(f"repovet {__version__}, {len(counts)} repositories")
    print_table(counts)
    for name, error in errors.items():
        print(f"{name}: {error}", file=sys.stderr)
    if args.save:
        payload = {"repovet": __version__, "counts": counts}
        args.save.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.compare:
        earlier = json.loads(args.compare.read_text(encoding="utf-8"))
        print(f"\ncompared with repovet {earlier.get('repovet', '?')} ({args.compare})")
        print_comparison({k: v for k, v in earlier["counts"].items() if k in counts}, counts)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
