"""Count findings per rule on the false-positive corpus and the reconstructions.

Usage: python scripts/corpus_counts.py [--only NAME]... [--offline-only]
                                       [--baseline FILE] [--update-baseline]
                                       [--save FILE] [--compare FILE]

Two sets are scanned with all built-in rules:

- the real repositories from ``tests/corpus/corpus.yaml``, each fetched at its pinned
  commit and scanned offline (no GitHub API), exactly like ``repovet scan URL --ref
  COMMIT --offline``. This needs the network.
- the inert reconstructions of documented attack techniques from
  ``tests/reconstructions/`` (see ``reconstructions.py``), scanned offline.
  ``--offline-only`` scans only these.

Both are compared with the committed baseline (``scripts/corpus-baseline.json``): the
output lists every repository or reconstruction whose count for a rule changed. The
baseline is written only with ``--update-baseline``; with ``--offline-only`` only its
reconstruction part is replaced. ``--save`` / ``--compare`` keep and compare the counts
of the real repositories between arbitrary runs, for example of two versions.

This is not part of the test suite. Nothing from the repositories is run; they are read
from Git objects in a temporary folder that is deleted after each scan.
"""

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

import reconstructions
from repovet import __version__
from repovet.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests" / "corpus" / "corpus.yaml"
BASELINE = Path(__file__).resolve().parent / "corpus-baseline.json"
CONFIDENCES = ("high", "medium", "low")
SECTIONS = {"real": "real repositories", "reconstructions": "reconstructions"}

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


def reconstruction_counts() -> Counts:
    """Findings per rule for every reconstruction (offline)."""
    return {
        evaluation.entry.id: reconstructions.rule_counts(evaluation.findings)
        for evaluation in reconstructions.evaluate_all(reconstructions.load_entries())
    }


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
    """One line per entry with its rules: for many entries with few findings each."""
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
    """(name, rule, before, after) for every entry and rule whose count changed;
    entries only on one side count as 0 on the other."""
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


def load_baseline(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not set(data) <= set(SECTIONS):
        raise SystemExit(f"{path}: expected an object with the keys {sorted(SECTIONS)}")
    return data


def write_baseline(path: Path, baseline: Mapping[str, Any]) -> None:
    ordered = {key: baseline[key] for key in SECTIONS if key in baseline}
    path.write_text(json.dumps(ordered, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--only", action="append", default=[], metavar="NAME")
    parser.add_argument(
        "--offline-only",
        action="store_true",
        help="scan only the reconstructions (no network)",
    )
    parser.add_argument("--baseline", type=Path, default=BASELINE, metavar="FILE")
    parser.add_argument(
        "--update-baseline", action="store_true", help="write the counts to the baseline"
    )
    parser.add_argument("--save", type=Path, metavar="FILE", help="write the counts as JSON")
    parser.add_argument("--compare", type=Path, metavar="FILE", help="earlier --save output")
    return parser


def scan_real(manifest: Path, only: Sequence[str]) -> tuple[Counts, dict[str, str]]:
    entries = [e for e in load_manifest(manifest) if not only or e["name"] in only]
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
    return counts, errors


def run(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.update_baseline and args.only:
        print("--update-baseline needs the whole corpus; leave out --only", file=sys.stderr)
        return EXIT_USAGE
    if args.offline_only and (args.only or args.save or args.compare):
        print("--only, --save and --compare need the real repositories", file=sys.stderr)
        return EXIT_USAGE
    baseline = load_baseline(args.baseline)
    scanned: dict[str, Counts] = {}
    errors: dict[str, str] = {}

    if not args.offline_only:
        scanned["real"], errors = scan_real(args.manifest, args.only)
        print(f"repovet {__version__}, {len(scanned['real'])} repositories")
        print_table(scanned["real"])
        for name, error in errors.items():
            print(f"{name}: {error}", file=sys.stderr)
        if args.save:
            payload = {"repovet": __version__, "counts": scanned["real"]}
            args.save.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if args.compare:
            earlier = json.loads(args.compare.read_text(encoding="utf-8"))
            print(f"\ncompared with repovet {earlier.get('repovet', '?')} ({args.compare})")
            print_comparison(
                {k: v for k, v in earlier["counts"].items() if k in scanned["real"]},
                scanned["real"],
            )

    print("scanning the reconstructions ...", file=sys.stderr)
    scanned["reconstructions"] = reconstruction_counts()
    count = len(scanned["reconstructions"])
    print(f"\nrepovet {__version__}, {count} reconstructions")
    print_list(scanned["reconstructions"])

    for key, counts in scanned.items():
        section = baseline.get(key)
        if section is None:
            print(f"\nno baseline for the {SECTIONS[key]} in {args.baseline}")
            continue
        earlier = section["counts"]
        if key == "real" and args.only:
            earlier = {k: v for k, v in earlier.items() if k in counts}
        print(f"\n{SECTIONS[key]} against the baseline (repovet {section.get('repovet', '?')}):")
        print_changes(earlier, counts)

    if errors:
        if args.update_baseline:
            print("baseline not updated: some scans failed", file=sys.stderr)
        return 1
    if args.update_baseline:
        for key, counts in scanned.items():
            baseline[key] = {"repovet": __version__, "counts": counts}
        write_baseline(args.baseline, baseline)
        print(f"\nbaseline written: {args.baseline} ({', '.join(scanned)})")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
