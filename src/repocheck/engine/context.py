"""Everything an analyzer gets for one scan."""

import time
from dataclasses import dataclass, field

from repocheck.engine.loader import RuleSet
from repocheck.github.target import TrustTarget
from repocheck.limits import Limits
from repocheck.models import CoverageCollector, CoverageStatus, Finding
from repocheck.sources.gitmeta import GitSource
from repocheck.sources.tree import FileTree


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
