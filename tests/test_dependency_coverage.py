"""Named dependency ecosystems have explicit coverage boundaries, without findings."""

from pathlib import Path

import pytest

from helpers import materialize
from repovet.models import CoverageStatus
from repovet.scanning import ScanOptions, scan_local


@pytest.mark.parametrize(
    ("path", "scope"),
    [
        ("Cargo.toml", "dependencies:rust"),
        ("Cargo.lock", "dependencies:rust"),
        ("go.mod", "dependencies:go"),
        ("Gemfile", "dependencies:ruby"),
        ("composer.json", "dependencies:php"),
        ("pom.xml", "dependencies:jvm"),
        ("build.gradle.kts", "dependencies:jvm"),
        ("demo.csproj", "dependencies:dotnet"),
        ("packages.lock.json", "dependencies:dotnet"),
    ],
)
def test_named_unsupported_dependency_ecosystem(tmp_path: Path, path: str, scope: str) -> None:
    root = materialize(tmp_path / "repo", {path: "{}\n"})
    result = scan_local(ScanOptions(str(root), offline=True)).result
    assert any(
        item.scope == scope and item.status is CoverageStatus.UNSUPPORTED
        for item in result.coverage
    )
    assert not any(finding.rule_id == "RC-DEP-014" for finding in result.findings)


def test_supported_manifest_does_not_claim_unknown_ecosystems(tmp_path: Path) -> None:
    root = materialize(tmp_path / "repo", {"package.json": '{"dependencies": {}}\n'})
    result = scan_local(ScanOptions(str(root), offline=True)).result
    assert not any(
        item.scope
        in {
            "dependencies:rust",
            "dependencies:go",
            "dependencies:ruby",
            "dependencies:php",
            "dependencies:jvm",
            "dependencies:dotnet",
        }
        for item in result.coverage
    )
    assert any(item.scope == "dependencies:contents" for item in result.coverage)
