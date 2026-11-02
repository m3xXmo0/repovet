"""Scan Base and Head with one current ruleset and compare their static findings."""

import json
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from repovet.comparison import ComparisonScope, DiffResult, compare_findings
from repovet.engine.checks.base import REASON_BINARY, reason_too_large
from repovet.engine.loader import RuleSet
from repovet.github import target as github_target
from repovet.limits import Limits
from repovet.models import CoverageCollector, CoverageStatus, ScanResult
from repovet.report.json_in import scan_from_data
from repovet.scanning import ScanOptions, UsageError, _analyze, _prepare, is_url, local_root
from repovet.sources import gitmeta, revisions
from repovet.sources.gitobjects import GitObjectError, GitObjects, is_hex_id
from repovet.sources.gittree import GitTree

_MAX_REPORT = 64 * 1024 * 1024
_IMAGE_HEADER = 32
_IMAGE_EXTENSIONS = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".webp": "webp",
    ".bmp": "bmp",
    ".ico": "ico",
}
# Sizes of the BMP info headers (BITMAPCOREHEADER up to BITMAPV5HEADER).
_BMP_HEADERS = {12, 16, 40, 52, 56, 64, 108, 124}
_REGULAR_MODES = {"100644", "100755"}


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


def image_type(header: bytes) -> str | None:
    """The image format whose signature starts ``header``, or None."""
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    if header[:2] == b"BM" and int.from_bytes(header[14:18], "little") in _BMP_HEADERS:
        return "bmp"
    # Reserved 0, type 1 (icon), at least one image, first entry's reserved byte 0.
    if header[:4] == b"\x00\x00\x01\x00" and header[4:6] != b"\x00\x00" and header[9:10] == b"\x00":
        return "ico"
    return None


def _images(
    objects: GitObjects, before: ScanResult, after: ScanResult, limits: Limits
) -> frozenset[str]:
    """Changed Head files that are unchecked only because they are binary or too large,
    carry an image signature that matches their extension and have no finding. Only
    the first bytes are read, whatever the file size."""
    accepted = {
        (CoverageStatus.SKIPPED, REASON_BINARY),
        (CoverageStatus.SKIPPED, reason_too_large(limits.max_file_size)),
    }
    gaps: dict[str, set[tuple[CoverageStatus, str]]] = defaultdict(set)
    for item in after.coverage:
        if item.scope in {"file", "git:submodules"}:
            for path in item.paths or item.sample:
                gaps[path].add((item.status, item.reason))
    flagged = {f.location.path for f in after.findings if f.location is not None}
    old, new = before.snapshot or {}, after.snapshot or {}
    images = set()
    for path, reasons in gaps.items():
        entry = new.get(path)
        expected = _IMAGE_EXTENSIONS.get(PurePosixPath(path).suffix.lower())
        if entry is None or old.get(path) == entry or expected is None:
            continue
        if path in flagged or not reasons <= accepted:
            continue
        mode, _, sha = entry.partition(":")
        if mode not in _REGULAR_MODES or not is_hex_id(sha):
            continue
        try:
            header = objects.read_prefix(sha.encode("ascii"), _IMAGE_HEADER)
        except GitObjectError:
            continue
        if image_type(header) == expected:
            images.add(path)
    return frozenset(images)


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
        images = _images(pair.source.objects, before.result, after.result, limits)
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
        images,
    )
    comparison = compare_findings(before.result.findings, after.result.findings, scope)
    return ComparedScan(before, after, rules, comparison, warnings)
