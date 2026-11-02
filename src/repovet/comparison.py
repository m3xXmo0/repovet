"""Deterministic, coverage-aware comparison of two sets of static findings."""

import enum
from bisect import bisect_left
from collections import defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from repovet.identity import fingerprint, normalize_content
from repovet.models import CoverageItem, CoverageStatus, Finding, Severity

_MAX_CANDIDATE_PAIRS = 10_000


class DiffStatus(enum.StrEnum):
    NEW = "new"
    UNCHANGED = "unchanged"
    UPDATED = "updated"
    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FindingChange:
    status: DiffStatus
    before: Finding | None
    after: Finding | None

    @property
    def worsened(self) -> bool:
        if self.before is None or self.after is None:
            return False
        promoted = self.before.context in {"test", "docs", "example", "vendored"} and (
            self.after.context is None
        )
        return self.after.severity > self.before.severity or promoted


@dataclass(frozen=True)
class ComparisonIssue:
    paths: tuple[str, ...]
    reason: str
    blocking: bool = True


@dataclass(frozen=True)
class ComparisonScope:
    before_files: Mapping[str, str] = field(default_factory=dict)
    after_files: Mapping[str, str] = field(default_factory=dict)
    before_coverage: Sequence[CoverageItem] = ()
    after_coverage: Sequence[CoverageItem] = ()
    # (rule id, path in the base) when the current counterpart was outside that rule.
    scope_lost: frozenset[tuple[str, str]] = frozenset()


@dataclass
class DiffResult:
    changes: list[FindingChange] = field(default_factory=list)
    issues: list[ComparisonIssue] = field(default_factory=list)

    @property
    def incomplete(self) -> bool:
        return any(issue.blocking for issue in self.issues)


def _identity(finding: Finding) -> str:
    return finding.fingerprint or fingerprint(finding)


def _path(finding: Finding) -> str:
    return finding.location.path if finding.location else ""


def _position(finding: Finding) -> tuple[int, int]:
    loc = finding.location
    return (loc.line or 0, loc.column or 0) if loc else (0, 0)


def _sort_key(
    finding: Finding,
) -> tuple[str, int, int, str, str, str, int, int, str, str, str, tuple[str, ...]]:
    return (
        _path(finding),
        *_position(finding),
        _identity(finding),
        finding.context or "",
        finding.message,
        int(finding.severity),
        int(finding.confidence),
        finding.title,
        finding.rationale,
        finding.recommendation,
        finding.references,
    )


def _change_sort_key(
    change: FindingChange,
) -> tuple[tuple[str, int, int, str, str, str, int, int, str, str, str, tuple[str, ...]], str]:
    finding = change.after or change.before
    key = (
        _sort_key(finding) if finding is not None else ("", 0, 0, "", "", "", 0, 0, "", "", "", ())
    )
    return key, change.status.value


def _message(finding: Finding) -> str:
    path = _path(finding)
    return normalize_content(finding.message.replace(path, "<path>") if path else finding.message)


def _signature(finding: Finding) -> tuple[object, ...]:
    return (
        finding.severity,
        finding.confidence,
        finding.context,
        finding.title,
        _message(finding),
        finding.rationale,
        finding.recommendation,
        finding.references,
    )


def _cost(before: Finding, after: Finding) -> tuple[int, int, int, int, int]:
    left, right = _path(before), _path(after)
    lp, rp = left.split("/"), right.split("/")
    common = 0
    for a, b in zip(lp, rp, strict=False):
        if a != b:
            break
        common += 1
    old_line, old_col = _position(before)
    new_line, new_col = _position(after)
    return (
        int(left != right),
        int(lp[-1] != rp[-1]),
        len(lp) + len(rp) - 2 * common,
        abs(old_line - new_line),
        abs(old_col - new_col),
    )


def _unique_best(finding: Finding, candidates: list[Finding], *, reverse: bool) -> Finding | None:
    costs = [(_cost(other, finding) if reverse else _cost(finding, other)) for other in candidates]
    best = min(costs)
    indexes = [index for index, cost in enumerate(costs) if cost == best]
    return candidates[indexes[0]] if len(indexes) == 1 else None


def _paired(before: Finding, after: Finding) -> FindingChange:
    status = DiffStatus.UNCHANGED if _signature(before) == _signature(after) else DiffStatus.UPDATED
    return FindingChange(status, before, after)


def _inside(path: str, parent: str) -> bool:
    parent = parent.rstrip("/")
    return parent in {"", "."} or path == parent or path.startswith(parent + "/")


def _changed_inside(paths: list[str], parent: str) -> bool:
    if parent in {"", "."}:
        return bool(paths)
    index = bisect_left(paths, parent)
    if index < len(paths) and paths[index] == parent:
        return True
    index = bisect_left(paths, parent.rstrip("/") + "/")
    return index < len(paths) and _inside(paths[index], parent)


def _covered(path: str, gaps: Mapping[str, set[str]]) -> bool:
    if "" in gaps or "." in gaps:
        return True
    while path:
        if path in gaps:
            return True
        path = path.rpartition("/")[0]
    return False


def _exact_matches(
    before: list[Finding], after: list[Finding], renames: Mapping[str, str] | None = None
) -> tuple[list[FindingChange], list[Finding], list[Finding]]:
    positions: dict[tuple[str, tuple[int, int]], deque[int]] = defaultdict(deque)
    for index, finding in enumerate(after):
        positions[(_path(finding), _position(finding))].append(index)
    used: set[int] = set()
    changes, remaining = [], []
    for old in before:
        path = (renames or {}).get(_path(old), _path(old))
        indexes = positions.get((path, _position(old)))
        if indexes:
            index = indexes.popleft()
            used.add(index)
            changes.append(_paired(old, after[index]))
        else:
            remaining.append(old)
    return changes, remaining, [new for index, new in enumerate(after) if index not in used]


def _unique_matches(
    before: list[Finding], after: list[Finding], key: Callable[[Finding], str]
) -> tuple[list[FindingChange], list[Finding], list[Finding]]:
    old_keys: dict[str, list[int]] = defaultdict(list)
    new_keys: dict[str, list[int]] = defaultdict(list)
    for index, finding in enumerate(before):
        old_keys[key(finding)].append(index)
    for index, finding in enumerate(after):
        new_keys[key(finding)].append(index)
    used_old: set[int] = set()
    used_new: set[int] = set()
    changes = []
    for value in sorted(old_keys.keys() & new_keys.keys()):
        if len(old_keys[value]) == len(new_keys[value]) == 1:
            old_index, new_index = old_keys[value][0], new_keys[value][0]
            used_old.add(old_index)
            used_new.add(new_index)
            changes.append(_paired(before[old_index], after[new_index]))
    return (
        changes,
        [old for index, old in enumerate(before) if index not in used_old],
        [new for index, new in enumerate(after) if index not in used_new],
    )


def _gaps(items: Sequence[CoverageItem]) -> tuple[dict[str, set[str]], set[str]]:
    paths: dict[str, set[str]] = defaultdict(set)
    global_gaps: set[str] = set()
    for item in items:
        if item.scope == "scan" and item.status in {
            CoverageStatus.SKIPPED,
            CoverageStatus.PARTIAL,
            CoverageStatus.FAILED,
        }:
            global_gaps.add(item.reason)
            continue
        blocking_file = item.scope == "file" and item.status in {
            CoverageStatus.SKIPPED,
            CoverageStatus.PARTIAL,
            CoverageStatus.FAILED,
        }
        if not blocking_file and item.scope != "git:submodules":
            continue
        known_paths = item.paths or item.sample
        if not known_paths or item.count > len(known_paths):
            global_gaps.add(item.reason)
        for path in known_paths:
            paths[path].add(item.reason)
    return dict(paths), global_gaps


def _renames(scope: ComparisonScope) -> dict[str, str]:
    removed: dict[str, list[str]] = defaultdict(list)
    added: dict[str, list[str]] = defaultdict(list)
    for path in scope.before_files.keys() - scope.after_files.keys():
        removed[scope.before_files[path]].append(path)
    for path in scope.after_files.keys() - scope.before_files.keys():
        added[scope.after_files[path]].append(path)
    return {
        old_paths[0]: added[identity][0]
        for identity, old_paths in removed.items()
        if len(old_paths) == 1 and len(added.get(identity, [])) == 1
    }


def _coverage_issues(scope: ComparisonScope) -> list[ComparisonIssue]:
    before_gaps, before_global = _gaps(scope.before_coverage)
    after_gaps, after_global = _gaps(scope.after_coverage)
    changed = sorted(
        {
            path
            for path in scope.before_files.keys() | scope.after_files.keys()
            if scope.before_files.get(path) != scope.after_files.get(path)
        }
    )
    issues = []
    for path, reasons in sorted(after_gaps.items()):
        touched = _changed_inside(changed, path)
        newly_unchecked = not reasons <= before_gaps.get(path, set())
        if touched or newly_unchecked:
            issues.append(ComparisonIssue((path,), "; ".join(sorted(reasons))))
        else:
            issues.append(ComparisonIssue((path,), "; ".join(sorted(reasons)), False))
    for reason in sorted(after_global):
        blocking = bool(changed) or reason not in before_global
        issues.append(ComparisonIssue(tuple(sorted(changed)), reason, blocking))
    return issues


def _missing(
    finding: Finding,
    scope: ComparisonScope,
    renames: Mapping[str, str],
    gaps: Mapping[str, set[str]],
    global_gaps: set[str],
) -> FindingChange:
    path = _path(finding)
    counterpart = renames.get(path, path)
    unknown = (finding.rule_id, path) in scope.scope_lost or _covered(counterpart, gaps)
    if global_gaps and (not path or counterpart in scope.after_files):
        unknown = True
    return FindingChange(DiffStatus.UNKNOWN if unknown else DiffStatus.ABSENT, finding, None)


def compare_findings(
    before: Sequence[Finding], after: Sequence[Finding], scope: ComparisonScope | None = None
) -> DiffResult:
    """Match semantic buckets as multisets; lexical order never resolves a real tie."""
    scope = scope or ComparisonScope()
    result = DiffResult(issues=_coverage_issues(scope))
    old_buckets: dict[str, list[Finding]] = defaultdict(list)
    new_buckets: dict[str, list[Finding]] = defaultdict(list)
    for finding in before:
        old_buckets[_identity(finding)].append(finding)
    for finding in after:
        new_buckets[_identity(finding)].append(finding)
    renames = _renames(scope)
    after_gaps, after_global = _gaps(scope.after_coverage)
    for identity in sorted(old_buckets.keys() | new_buckets.keys()):
        left = sorted(old_buckets[identity], key=_sort_key)
        right = sorted(new_buckets[identity], key=_sort_key)
        pairs, left, right = _exact_matches(left, right)
        result.changes.extend(pairs)
        pairs, left, right = _unique_matches(left, right, _path)
        result.changes.extend(pairs)
        pairs, left, right = _exact_matches(left, right, renames)
        result.changes.extend(pairs)
        pairs, left, right = _unique_matches(left, right, lambda f: _path(f).rsplit("/", 1)[-1])
        result.changes.extend(pairs)
        over_budget = len(left) * len(right) > _MAX_CANDIDATE_PAIRS
        remaining_budget = _MAX_CANDIDATE_PAIRS
        while left and right and not over_budget:
            work = len(left) * len(right)
            if work > remaining_budget:
                over_budget = True
                break
            remaining_budget -= work
            reverse_best = {id(new): _unique_best(new, left, reverse=True) for new in right}
            pair = None
            for old in left:
                new = _unique_best(old, right, reverse=False)
                if new is not None and reverse_best[id(new)] is old:
                    pair = old, new
                    break
            if pair is None:
                break
            old, new = pair
            result.changes.append(_paired(old, new))
            del left[left.index(old)]
            del right[right.index(new)]
        if left and right:
            paths = tuple(sorted({_path(f) for f in [*left, *right]}))
            reason = (
                "Finding comparison exceeds its bounded matching budget"
                if over_budget
                else "Finding occurrences have equally plausible matches"
            )
            result.issues.append(ComparisonIssue(paths, reason))
            status = DiffStatus.UNKNOWN if over_budget else DiffStatus.AMBIGUOUS
            result.changes.extend(FindingChange(status, old, None) for old in left)
            result.changes.extend(FindingChange(status, None, new) for new in right)
        else:
            for old in left:
                change = _missing(old, scope, renames, after_gaps, after_global)
                result.changes.append(change)
                if change.status is DiffStatus.UNKNOWN:
                    result.issues.append(
                        ComparisonIssue(
                            (_path(old),), "A previous finding is no longer in a checked scope"
                        )
                    )
            result.changes.extend(FindingChange(DiffStatus.NEW, None, new) for new in right)
    result.changes.sort(key=_change_sort_key)
    result.issues = sorted(
        set(result.issues), key=lambda issue: (not issue.blocking, issue.paths, issue.reason)
    )
    return result


def diff_exit_code(result: DiffResult, fail_on: Severity) -> int:
    if result.incomplete:
        return 3
    for change in result.changes:
        after = change.after
        if after is None or after.in_chain is not None:
            continue
        if after.severity >= fail_on and (change.status is DiffStatus.NEW or change.worsened):
            return 1
    return 0
