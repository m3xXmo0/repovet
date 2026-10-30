"""Inert reconstructions of documented attack techniques: load, scan and evaluate them.

Usage: python scripts/reconstructions.py [--only ID]...

Each file in ``tests/reconstructions/`` describes one publicly documented supply-chain
incident or repository-based attack technique: a short description, public sources,
and files that rebuild only the *shape* of the technique (placeholder hosts, harmless
commands, no working payload). It names the rules that must fire, the rules that must
not fire, and known gaps: rules that should fire but do not (yet).

``variants`` are hand-written rewrites of one or more fixture files with an evasion
technique (indirection through a variable, another downloader, a helper script ...).
A variant counts as detected when the findings in the files it rewrites reach at least
the highest severity that the expected findings of the canonical fixture reach in those
files. A variant that stays below must be listed under ``known_gaps`` as
``{variant: ID, reason: ...}``; no variant falls below silently.

The files are written to a temporary folder and scanned offline with the normal
pipeline (``repovet scan DIR --offline --format json``). Nothing is ever run.
``tests/test_reconstructions.py`` checks every entry; ``corpus_counts.py`` and
``evidence.py`` use the same results.
"""

import argparse
import base64
import json
import re
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from repovet.cli import EXIT_FINDINGS, EXIT_OK, main

ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "tests" / "reconstructions"
CONFIDENCES = ("high", "medium", "low")
SEVERITIES = ("info", "low", "medium", "high", "critical")
KINDS = ("incident", "technique")
_REQUIRED = {"id", "title", "kind", "year", "technique", "sources", "reconstruction", "files"}
_OPTIONAL = {"must_fire", "must_not_fire", "known_gaps", "not_covered", "variants"}
_VARIANT_KEYS = {"id", "technique", "files"}
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_RULE_ID = re.compile(r"RC-[A-Z]+-\d{3}")
_REPEAT_KEYS = {"prefix", "repeat", "count", "suffix"}

# {rule id: {confidence: count}}
type RuleCounts = dict[str, dict[str, int]]


@dataclass(frozen=True)
class Expectation:
    """A rule, optionally at one path. ``reason`` explains a known gap."""

    rule: str
    path: str | None = None
    reason: str = ""

    def matches(self, finding: Mapping[str, Any]) -> bool:
        if finding["rule_id"] != self.rule:
            return False
        location = finding.get("location") or {}
        return self.path is None or location.get("path") == self.path

    def label(self) -> str:
        return self.rule if self.path is None else f"{self.rule} at {self.path}"


@dataclass(frozen=True)
class Variant:
    """A rewrite of fixture files: ``files`` replace the canonical files of the same
    name (``null`` removes one) and may add new ones."""

    id: str
    technique: str
    files: Mapping[str, object]


@dataclass(frozen=True)
class Entry:
    id: str
    title: str
    kind: str
    year: int
    technique: str
    sources: tuple[str, ...]
    reconstruction: str
    files: Mapping[str, object]
    must_fire: tuple[Expectation, ...]
    must_not_fire: tuple[str, ...]
    known_gaps: tuple[Expectation, ...]
    not_covered: str
    variants: tuple[Variant, ...] = ()
    # Variants that stay below the canonical severity: {variant id: reason}.
    variant_gaps: Mapping[str, str] = field(default_factory=dict)

    def variant_files(self, variant: Variant) -> dict[str, object]:
        """The canonical files with the rewrites of ``variant`` applied."""
        merged = {**self.files, **variant.files}
        return {rel: content for rel, content in merged.items() if content is not None}


@dataclass(frozen=True)
class VariantResult:
    """``target``: the highest severity of the canonical fixture's expected findings in
    the files the variant rewrites; ``reached``: the highest severity of any finding in
    those files after the rewrite (``None``: no finding)."""

    variant: Variant
    target: str | None
    reached: str | None
    gap: str | None = None
    unreadable: tuple[str, ...] = ()

    @property
    def detected(self) -> bool:
        if self.target is None or self.reached is None:
            return False
        return SEVERITIES.index(self.reached) >= SEVERITIES.index(self.target)

    @property
    def ok(self) -> bool:
        return not self.problems()

    def problems(self) -> list[str]:
        name = f"variant {self.variant.id}"
        if self.target is None:
            return [f"{name} rewrites no file with an expected finding of the canonical fixture"]
        lines = [f"{name}: fixture file could not be read or parsed: {p}" for p in self.unreadable]
        if not self.detected and self.gap is None:
            lines.append(
                f"{name} reaches {self.reached or 'no finding'}, below {self.target}: "
                "fix the rules or list it under known_gaps"
            )
        if self.detected and self.gap is not None:
            lines.append(f"known gap closed, remove it from known_gaps: {name}")
        return lines


@dataclass(frozen=True)
class Evaluation:
    """``missing``: expected hits without a finding; ``unexpected``: findings of rules
    that must not fire; ``closed_gaps``: known gaps that now have a finding;
    ``unreadable``: fixture files the scan could not read or parse (for example
    because antivirus software blocked them); ``variants``: results per variant."""

    entry: Entry
    findings: tuple[Mapping[str, Any], ...]
    missing: tuple[Expectation, ...]
    unexpected: tuple[str, ...]
    closed_gaps: tuple[Expectation, ...]
    unreadable: tuple[str, ...] = ()
    variants: tuple[VariantResult, ...] = ()

    @property
    def ok(self) -> bool:
        return not (
            self.missing
            or self.unexpected
            or self.closed_gaps
            or self.unreadable
            or any(not v.ok for v in self.variants)
        )

    @property
    def status(self) -> str:
        """``detected``, ``partly detected`` (some expected rules are known gaps) or
        ``not detected`` (no expected rule fires)."""
        if not self.entry.must_fire:
            return "not detected"
        return "partly detected" if self.entry.known_gaps else "detected"

    @property
    def variants_detected(self) -> int:
        return sum(v.detected for v in self.variants)

    def fired_rules(self) -> list[str]:
        return sorted({str(f["rule_id"]) for f in self.findings})


def _expectation(raw: object, where: str, *, gap: bool) -> Expectation:
    if isinstance(raw, str) and not gap:
        return Expectation(raw)
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: expected a rule id or a mapping, got {raw!r}")
    allowed = {"rule", "path", "reason"} if gap else {"rule", "path"}
    if not set(raw) <= allowed or "rule" not in raw:
        raise ValueError(f"{where}: keys must be {sorted(allowed)}, got {sorted(raw)}")
    if gap and not str(raw.get("reason") or "").strip():
        raise ValueError(f"{where}: a known gap needs a reason")
    path = raw.get("path")
    return Expectation(
        str(raw["rule"]), None if path is None else str(path), str(raw.get("reason") or "")
    )


def _variant(raw: object, where: str) -> Variant:
    if not isinstance(raw, dict) or set(raw) != _VARIANT_KEYS:
        raise ValueError(f"{where}: a variant needs exactly the keys {sorted(_VARIANT_KEYS)}")
    variant_id = str(raw["id"])
    if not _ID.fullmatch(variant_id):
        raise ValueError(
            f"{where}: variant id {variant_id!r} must be lowercase words joined by '-'"
        )
    technique = " ".join(str(raw["technique"] or "").split())
    if not technique:
        raise ValueError(f"{where}: variant {variant_id} needs a technique")
    files = raw["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError(f"{where}: variant {variant_id} needs files")
    return Variant(variant_id, technique, files)


def _variant_gaps(
    raw_gaps: list[object], variants: Sequence[Variant], source: str
) -> dict[str, str]:
    gaps: dict[str, str] = {}
    for raw in raw_gaps:
        if not (isinstance(raw, dict) and "variant" in raw):
            continue
        if set(raw) != {"variant", "reason"}:
            raise ValueError(f"{source}: a variant gap needs exactly the keys variant and reason")
        reason = " ".join(str(raw["reason"] or "").split())
        if not reason:
            raise ValueError(f"{source}: known_gaps: a known gap needs a reason")
        gaps[str(raw["variant"])] = reason
    unknown = sorted(set(gaps) - {v.id for v in variants})
    if unknown:
        raise ValueError(f"{source}: known_gaps name unknown variants {unknown}")
    return gaps


def parse_entry(data: object, source: str) -> Entry:
    """Validate one reconstruction file; raises ValueError naming the problem."""
    if not isinstance(data, dict):
        raise ValueError(f"{source}: expected a mapping")
    keys = set(data)
    unknown = keys - _REQUIRED - _OPTIONAL
    if not keys >= _REQUIRED or unknown:
        raise ValueError(f"{source}: missing {sorted(_REQUIRED - keys)}, unknown {sorted(unknown)}")
    entry_id = str(data["id"])
    if not _ID.fullmatch(entry_id):
        raise ValueError(f"{source}: id {entry_id!r} must be lowercase words joined by '-'")
    if data["kind"] not in KINDS:
        raise ValueError(f"{source}: kind must be one of {KINDS}")
    sources = data["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError(f"{source}: sources must be a non-empty list")
    if any(not isinstance(s, str) or not s.startswith("https://") for s in sources):
        raise ValueError(f"{source}: every source must be an https:// link")
    files = data["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError(f"{source}: files must be a non-empty mapping")
    must_fire = tuple(
        _expectation(raw, f"{source}: must_fire", gap=False) for raw in data.get("must_fire") or []
    )
    raw_gaps = list(data.get("known_gaps") or [])
    gaps = tuple(
        _expectation(raw, f"{source}: known_gaps", gap=True)
        for raw in raw_gaps
        if not (isinstance(raw, dict) and "variant" in raw)
    )
    raw_variants = data.get("variants") or []
    if not isinstance(raw_variants, list):
        raise ValueError(f"{source}: variants must be a list")
    variants = tuple(_variant(raw, f"{source}: variants") for raw in raw_variants)
    if len({v.id for v in variants}) != len(variants):
        raise ValueError(f"{source}: duplicate variant ids")
    must_not = tuple(str(rule) for rule in data.get("must_not_fire") or [])
    if not must_fire and not gaps:
        raise ValueError(f"{source}: name the rules that should fire (must_fire or known_gaps)")
    for rule in [e.rule for e in must_fire + gaps] + list(must_not):
        if not _RULE_ID.fullmatch(rule):
            raise ValueError(f"{source}: {rule!r} is not a rule id")
    if {e.rule for e in must_fire + gaps} & set(must_not):
        raise ValueError(f"{source}: a rule is both expected and in must_not_fire")
    return Entry(
        id=entry_id,
        title=str(data["title"]),
        kind=str(data["kind"]),
        year=int(data["year"]),
        technique=" ".join(str(data["technique"]).split()),
        sources=tuple(sources),
        reconstruction=" ".join(str(data["reconstruction"]).split()),
        files=files,
        must_fire=must_fire,
        must_not_fire=must_not,
        known_gaps=gaps,
        not_covered=" ".join(str(data.get("not_covered") or "").split()),
        variants=variants,
        variant_gaps=_variant_gaps(raw_gaps, variants, source),
    )


def load_entries(directory: Path = DIRECTORY) -> list[Entry]:
    entries = [
        parse_entry(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
        for path in sorted(directory.glob("*.yaml"))
    ]
    ids = [e.id for e in entries]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate reconstruction ids: {duplicates}")
    return entries


def all_files(entry: Entry) -> list[tuple[str, object]]:
    """Every fixture file of the entry and of its variants (for content checks)."""
    files = list(entry.files.items())
    for variant in entry.variants:
        files += [(rel, content) for rel, content in variant.files.items() if content is not None]
    return files


def file_content(rel: str, content: object) -> bytes:
    """Bytes of one fixture file: text as UTF-8, ``{base64: ...}`` as raw bytes,
    ``{prefix, repeat, count, suffix}`` for long lines without huge fixtures."""
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, dict) and set(content) == {"base64"}:
        return base64.b64decode(str(content["base64"]), validate=True)
    if isinstance(content, dict) and {"repeat", "count"} <= set(content) <= _REPEAT_KEYS:
        text = (
            str(content.get("prefix", ""))
            + str(content["repeat"]) * int(content["count"])
            + str(content.get("suffix", ""))
        )
        return text.encode("utf-8")
    raise TypeError(f"unsupported fixture content for {rel!r}")


def materialize(root: Path, files: Mapping[str, object]) -> Path:
    """Write the fixture files below ``root`` (never outside it)."""
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        parts = rel.split("/")
        if rel.startswith("/") or "\\" in rel or ":" in rel or ".." in parts or "" in parts:
            raise ValueError(f"fixture path must stay inside the repository: {rel!r}")
        target = root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(file_content(rel, content))
    return root


def _scan_files(name: str, files: Mapping[str, object], workdir: Path) -> dict[str, Any]:
    repo = materialize(workdir / name / "repo", files)
    report = workdir / name / "report.json"
    code = main(["scan", str(repo), "--offline", "--format", "json", "-o", str(report)])
    if code not in (EXIT_OK, EXIT_FINDINGS):
        raise RuntimeError(f"{name}: scan failed with exit code {code}")
    data: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    return data


def scan(entry: Entry, workdir: Path) -> dict[str, Any]:
    """Materialize the entry under ``workdir`` and return the JSON report of an offline
    scan with all built-in rules."""
    return _scan_files(entry.id, entry.files, workdir)


def scan_variant(entry: Entry, variant: Variant, workdir: Path) -> dict[str, Any]:
    """The JSON report of the entry's files with ``variant`` applied."""
    return _scan_files(f"{entry.id}--{variant.id}", entry.variant_files(variant), workdir)


def _unreadable(report: Mapping[str, Any]) -> tuple[str, ...]:
    failed = [c for c in report.get("coverage", []) if c["status"] == "failed"]
    return tuple(sorted({str(p) for c in failed for p in c["sample"]}))


def evaluate(entry: Entry, report: Mapping[str, Any]) -> Evaluation:
    findings: list[Mapping[str, Any]] = report["findings"]

    def hit(expectation: Expectation) -> bool:
        return any(expectation.matches(f) for f in findings)

    fired = {str(f["rule_id"]) for f in findings}
    return Evaluation(
        entry=entry,
        findings=tuple(findings),
        missing=tuple(e for e in entry.must_fire if not hit(e)),
        unexpected=tuple(rule for rule in entry.must_not_fire if rule in fired),
        closed_gaps=tuple(e for e in entry.known_gaps if hit(e)),
        unreadable=_unreadable(report),
    )


def _highest(findings: Iterable[Mapping[str, Any]]) -> str | None:
    levels = [SEVERITIES.index(str(f["severity"])) for f in findings]
    return SEVERITIES[max(levels)] if levels else None


def _path(finding: Mapping[str, Any]) -> str | None:
    location = finding.get("location") or {}
    path = location.get("path")
    return None if path is None else str(path)


def _reaches(finding: Mapping[str, Any], paths: set[str]) -> bool:
    """True if the finding is in one of ``paths`` or, for a chain, passes through one."""
    steps = (finding.get("chain") or {}).get("steps") or []
    return _path(finding) in paths or any(step.get("path") in paths for step in steps)


def evaluate_variant(
    entry: Entry, variant: Variant, canonical: Mapping[str, Any], report: Mapping[str, Any]
) -> VariantResult:
    """Compare the findings in the files that ``variant`` rewrites (including chains
    that pass through them) with the canonical fixture's expected findings there."""
    touched = set(variant.files)
    expected = [
        f
        for f in canonical["findings"]
        if _path(f) in touched and any(e.matches(f) for e in entry.must_fire)
    ]
    return VariantResult(
        variant=variant,
        target=_highest(expected),
        reached=_highest(f for f in report["findings"] if _reaches(f, touched)),
        gap=entry.variant_gaps.get(variant.id),
        unreadable=_unreadable(report),
    )


def rule_counts(findings: Iterable[Mapping[str, Any]]) -> RuleCounts:
    counts: RuleCounts = {}
    for finding in findings:
        per_rule = counts.setdefault(str(finding["rule_id"]), dict.fromkeys(CONFIDENCES, 0))
        per_rule[str(finding["confidence"])] += 1
    return counts


def evaluate_all(entries: Sequence[Entry], *, variants: bool = True) -> list[Evaluation]:
    """Evaluate every entry and (unless ``variants`` is false) its variants."""
    results = []
    with tempfile.TemporaryDirectory(prefix="repovet-reconstructions-") as tmp:
        workdir = Path(tmp)
        for entry in entries:
            canonical = scan(entry, workdir)
            checked = tuple(
                evaluate_variant(entry, v, canonical, scan_variant(entry, v, workdir))
                for v in (entry.variants if variants else ())
            )
            results.append(replace(evaluate(entry, canonical), variants=checked))
    return results


def describe(evaluation: Evaluation) -> list[str]:
    """Problems of one evaluation, as lines for a test failure or the console."""
    lines = [f"fixture file could not be read or parsed: {p}" for p in evaluation.unreadable]
    lines += [f"expected but missing: {e.label()}" for e in evaluation.missing]
    lines += [f"must not fire, but fired: {rule}" for rule in evaluation.unexpected]
    lines += [
        f"known gap closed, move it to must_fire: {e.label()}" for e in evaluation.closed_gaps
    ]
    for variant in evaluation.variants:
        lines += variant.problems()
    return lines


def run(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", action="append", default=[], metavar="ID")
    args = parser.parse_args(argv)
    entries = [e for e in load_entries() if not args.only or e.id in args.only]
    failed = 0
    evaluations = evaluate_all(entries)
    for evaluation in evaluations:
        entry = evaluation.entry
        print(
            f"{entry.id:<28} {evaluation.status:<16} {', '.join(evaluation.fired_rules()) or '-'}"
        )
        for gap in entry.known_gaps:
            print(f"{'':<28} known gap: {gap.label()}")
        if evaluation.variants:
            count = f"{evaluation.variants_detected} of {len(evaluation.variants)}"
            print(f"{'':<28} variants detected: {count}")
        for result in evaluation.variants:
            mark = "ok " if result.detected else "gap" if result.gap else "LOW"
            levels = f"{result.reached or 'none'}/{result.target or '?'}"
            print(f"{'':<30}{mark} {result.variant.id:<26} {levels:<16} {result.variant.technique}")
        for line in describe(evaluation):
            failed += 1
            print(f"{'':<28} PROBLEM: {line}")
    total = sum(len(e.variants) for e in evaluations)
    detected = sum(e.variants_detected for e in evaluations)
    print(f"\nvariants detected: {detected} of {total}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
