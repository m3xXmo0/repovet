from pathlib import Path

from helpers import materialize, write_rule
from repocheck.analyzers import ANALYZERS, run_all
from repocheck.engine.context import ScanContext
from repocheck.engine.loader import load_rules
from repocheck.limits import DEFAULT_LIMITS
from repocheck.models import AREAS, CoverageCollector, CoverageStatus
from repocheck.sources.local import LocalTree


def context(repo: Path, extra: list[Path] | None = None) -> ScanContext:
    coverage = CoverageCollector()
    return ScanContext(
        LocalTree(repo, DEFAULT_LIMITS, coverage), load_rules(extra or []), DEFAULT_LIMITS, coverage
    )


def test_implemented_areas() -> None:
    assert set(ANALYZERS) == {
        "autorun",
        "agents",
        "obfuscation",
        "download_exec",
        "binaries",
        "dependencies",
        "provenance",
        "trust",
    }


def test_run_all_reports_findings_and_missing_areas(tmp_path: Path) -> None:
    repo = materialize(
        tmp_path / "repo",
        {
            "package.json": '{"scripts": {"postinstall": "x"}}',
            "CLAUDE.md": "a\U000e0041\n",
            "build.rs": "fn main() {}\n",
        },
    )
    ctx = context(repo)
    results = run_all(ctx)
    assert {r.area for r in results} == set(ANALYZERS)
    ids = sorted(f.rule_id for r in results for f in r.findings)
    assert ids == ["RC-AGENT-001", "RC-AGENT-002", "RC-AUTO-001", "RC-AUTO-082"]
    items = ctx.coverage.items()
    missing = {c.scope for c in items if c.status == CoverageStatus.NOT_IMPLEMENTED}
    assert missing == {f"area:{name}" for name in AREAS if name not in ANALYZERS} == set()
    # Without a trust target (no GitHub repository known) the trust area is skipped.
    assert any(c.scope == "area:trust" and c.status == CoverageStatus.SKIPPED for c in items)
    assert any(c.scope == "ecosystem:rust" for c in items)


def test_user_file_rules_of_the_trust_area_run_without_the_api(tmp_path: Path) -> None:
    rules_dir = write_rule(
        tmp_path / "rules",
        rule_id="RC-TRUST-901",
        area="trust",
        check="{type: filename, name_regex: '\\.exe$'}",
    )
    repo = materialize(tmp_path / "repo", {"tool.exe": "not really an executable\n"})
    results = run_all(context(repo, [rules_dir]))
    found = [r for r in results if r.area == "trust"]
    assert [f.rule_id for f in found[0].findings] == ["RC-TRUST-901"]
