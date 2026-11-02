"""Scan Base and Head with one current ruleset and compare their static findings."""

import json
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from repovet.comparison import ComparisonScope, DiffResult, compare_findings
from repovet.engine.loader import RuleSet
from repovet.github import target as github_target
from repovet.limits import Limits
from repovet.models import CoverageCollector, ScanResult
from repovet.report.json_in import scan_from_data
from repovet.scanning import ScanOptions, UsageError, _analyze, _prepare, is_url, local_root
from repovet.sources import gitmeta, revisions
from repovet.sources.gitobjects import is_hex_id
from repovet.sources.gittree import GitTree

_MAX_REPORT = 64 * 1024 * 1024


@dataclass
class RevisionReport:
    commit: str
    result: ScanResult


@dataclass
class ComparedScan:
    base: RevisionReport
    head: RevisionReport
    rules: RuleSet
    comparison: DiffResult
    warnings: list[str]


def _stored(path: Path) -> RevisionReport:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_REPORT + 1)
        if len(raw) > _MAX_REPORT:
            raise ValueError("saved report exceeds the 64 MiB limit")
        data = json.loads(raw)
        # The Head side of a previous diff is also a complete saved scan report.
        if isinstance(data, dict) and data.get("schema_version") == "1.0":
            data = data["head"]["report"]
        result = scan_from_data(data)
        source = result.facts.get("source")
        commit = source.get("commit") if isinstance(source, dict) else None
        if not isinstance(commit, str) or not is_hex_id(commit):
            raise ValueError("saved baseline must name the exact scanned Git commit")
        if result.snapshot is None:
            raise ValueError("saved baseline requires a Git tree snapshot, not a working folder")
        return RevisionReport(commit, result)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise UsageError(
            "invalid saved baseline; regenerate an unfiltered schema 1.5 Git report "
            "with fingerprints, ruleset digest and snapshot"
        ) from None


def _revision(
    source: gitmeta.GitSource, commit: bytes, rules: RuleSet, limits: Limits, root: Path
) -> RevisionReport:
    coverage = CoverageCollector()
    text = commit.decode("ascii")
    tree = GitTree(source.objects, commit, limits, coverage, f"{root} @ {text}")
    current = gitmeta.GitSource(source.objects, commit, source.origin, source.shallow)
    scanned = _analyze(
        tree,
        "local Git revision",
        rules,
        limits,
        coverage,
        datetime.now(UTC),
        time.monotonic(),
        git=current,
        trust=github_target.setup(None, offline=True, environ={}),
        facts={"source": {"type": "local_git", "commit": text}},
    )
    return RevisionReport(text, scanned.result)


def _scope_lost(
    before: ScanResult, after: ScanResult, rules: RuleSet
) -> frozenset[tuple[str, str]]:
    left, right = before.snapshot or {}, after.snapshot or {}
    removed: dict[str, list[str]] = defaultdict(list)
    added: dict[str, list[str]] = defaultdict(list)
    for path in left.keys() - right.keys():
        removed[left[path]].append(path)
    for path in right.keys() - left.keys():
        added[right[path]].append(path)
    renamed = {
        paths[0]: added[identity][0]
        for identity, paths in removed.items()
        if len(paths) == 1 and len(added.get(identity, [])) == 1
    }
    lost = set()
    for finding in before.findings:
        if finding.location is None:
            continue
        path = finding.location.path
        counterpart = renamed.get(path, path)
        rule = rules.get(finding.rule_id)
        if (
            rule is None
            or rule.deprecated
            or (counterpart in right and not rule.applies_to(counterpart))
        ):
            lost.add((finding.rule_id, path))
    return frozenset(lost)


def compare_revisions(
    options: ScanOptions, base: str | None, head: str = "HEAD", *, base_report: Path | None = None
) -> ComparedScan:
    if is_url(options.target):
        raise UsageError("diff requires a local Git repository with both revisions available")
    root = local_root(options.target).resolve()
    rules, limits = _prepare(options)
    saved = _stored(base_report) if base_report is not None else None
    selected = saved.commit if saved is not None else base
    if selected is None:
        raise UsageError("diff requires --base or --base-report")
    with revisions.open_pair(root, selected, head, limits) as pair:
        if saved is not None:
            expected = "40000:" + pair.source.objects.commit(pair.base).tree.decode("ascii")
            if (saved.result.snapshot or {}).get(".") != expected:
                raise UsageError(
                    "saved baseline snapshot does not match its Git commit; regenerate it"
                )
        before = saved or _revision(pair.source, pair.base, rules, limits, root)
        after = _revision(pair.source, pair.head, rules, limits, root)
    warnings = []
    if before.result.tool_version != after.result.tool_version:
        warnings.append("Saved baseline and Head use different repovet versions")
    if before.result.ruleset_digest != after.result.ruleset_digest:
        warnings.append(
            "Saved baseline and Head use different ruleset digests; changes may be caused by rules"
        )
    scope = ComparisonScope(
        before.result.snapshot or {},
        after.result.snapshot or {},
        before.result.coverage,
        after.result.coverage,
        _scope_lost(before.result, after.result, rules),
    )
    comparison = compare_findings(before.result.findings, after.result.findings, scope)
    return ComparedScan(before, after, rules, comparison, warnings)
