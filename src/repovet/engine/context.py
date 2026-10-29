"""Everything an analyzer gets for one scan."""

import time
from dataclasses import dataclass, field

from repovet.engine.loader import RuleSet
from repovet.github.target import TrustTarget
from repovet.limits import Limits
from repovet.models import CoverageCollector, CoverageStatus, Finding
from repovet.sources.gitmeta import GitSource
from repovet.sources.tree import FileTree, GlobSet

# Labels for findings in code that usually does not run (file sets in _filesets.yaml).
# A label never hides a finding; the first matching set wins.
PATH_CONTEXTS = (
    ("vendored", "context_vendored"),
    ("test", "context_test"),
    ("example", "context_example"),
    ("docs", "context_docs"),
)


@dataclass
class ScanContext:
    tree: FileTree
    rules: RuleSet
    limits: Limits
    coverage: CoverageCollector = field(default_factory=CoverageCollector)
    deadline: float = 0.0
    # Git history for provenance (a clone or a local .git); otherwise why there is none.
    git: GitSource | None = None
    git_note: str | None = None
    # Findings of file rules from the shared pass (``runner.prepare_file_rules``).
    prepared: dict[str, list[Finding]] | None = None
    # Per-area state collected during the shared pass (e.g. the provenance profile).
    observed: dict[str, object] = field(default_factory=dict)
    # The repository the trust area asks the GitHub API about (None: not set up).
    trust: TrustTarget | None = None
    # Facts of the areas that already ran (trust reads the provenance profile).
    facts: dict[str, object] = field(default_factory=dict)
    _timed_out: bool = False
    _contexts: list[tuple[str, GlobSet]] | None = None

    def __post_init__(self) -> None:
        if not self.deadline:
            self.deadline = time.monotonic() + self.limits.max_scan_seconds

    def out_of_time(self) -> bool:
        if not self._timed_out and time.monotonic() > self.deadline:
            self._timed_out = True
            self.coverage.add(
                "scan",
                CoverageStatus.PARTIAL,
                f"Time limit of {self.limits.max_scan_seconds:.0f} s reached; "
                "remaining files were not checked",
            )
        return self._timed_out

    def path_context(self, path: str) -> str | None:
        """The context label of ``path`` (``vendored``, ``test``, ``example``, ``docs``)."""
        if self._contexts is None:
            filesets = self.rules.filesets
            self._contexts = [
                (label, GlobSet(filesets[name]))
                for label, name in PATH_CONTEXTS
                if filesets.get(name)
            ]
        return next((label for label, globs in self._contexts if globs.matches(path)), None)
