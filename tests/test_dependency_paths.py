"""Lexical local dependency facts, without resolving or reading their targets."""

import json
from pathlib import Path

import pytest

from helpers import builtin_rules, materialize
from repovet.analyzers import provenance
from repovet.engine.context import ScanContext
from repovet.limits import DEFAULT_LIMITS
from repovet.models import AreaResult, CoverageCollector, CoverageStatus
from repovet.parsers.dependency_paths import local_sources
from repovet.parsers.manifests import Dependency, Manifest, parse_manifest
from repovet.parsers.structured import parse
from repovet.sources.local import LocalTree


@pytest.mark.parametrize(
    ("manifest_path", "source", "kind", "inside"),
    [
        ("package.json", "file:packages/lib", "relative", True),
        ("package.json", "file:../shared", "relative", False),
        ("package.json", "link:../shared", "relative", False),
        ("package.json", "portal:packages/lib", "relative", True),
        ("package.json", "file:packages/../lib", "relative", True),
        ("apps/app/package.json", "file:../../shared", "relative", True),
        ("package.json", "file:%2e%2e/shared", "relative", False),
        ("package.json", "file:/opt/example/lib", "posix_absolute", None),
        ("package.json", "file:///opt/example/lib", "posix_absolute", None),
        ("package.json", "file://localhost/opt/example/lib", "posix_absolute", None),
        ("package.json", r"C:\example\lib", "windows_absolute", None),
        ("package.json", "file:///C:/example/lib", "windows_absolute", None),
        ("package.json", "file://C:/example/lib", "windows_absolute", None),
        ("package.json", r"C:lib", "windows_drive_relative", None),
        ("package.json", r"\example\lib", "windows_root_relative", None),
        ("package.json", r"\\example.invalid\share\lib", "unc", None),
        ("package.json", "file://example.invalid/share/lib", "unc", None),
        ("package.json", "file:./${DUMMY_ROOT}/lib", "environment", None),
        ("package.json", "file:%DUMMY_ROOT%/lib", "environment", None),
        ("package.json", "file:~/lib", "environment", None),
    ],
)
def test_local_source_classification(
    manifest_path: str, source: str, kind: str, inside: bool | None
) -> None:
    # A Windows path is not classified as `path` by every package format parser.
    manifest = Manifest(dependencies=[Dependency("npm", "demo", source, "registry")])
    records = list(local_sources(manifest_path, manifest))
    assert len(records) == 1
    assert records[0]["manifest"] == manifest_path
    assert records[0]["package"] == "demo"
    assert records[0]["kind"] == kind
    assert records[0]["within_repository"] is inside


@pytest.mark.parametrize("source", ["workspace:*", "npm:demo@1", "https://example.invalid/a.tgz"])
def test_registry_urls_and_workspace_references_are_not_path_facts(source: str) -> None:
    manifest = Manifest(dependencies=[Dependency("npm", "demo", source, "path")])
    assert list(local_sources("package.json", manifest)) == []


def test_python_file_reference_reuses_manifest_parser() -> None:
    text = "demo @ file:///opt/example/lib\n"
    manifest = parse_manifest("requirements.txt", text, lambda _fmt: None)
    assert manifest is not None
    record = next(local_sources("requirements.txt", manifest))
    assert record["package"] == "demo"
    assert (record["kind"], record["within_repository"]) == ("posix_absolute", None)


def test_link_backslashes_reuse_npm_manifest_parser() -> None:
    text = json.dumps({"dependencies": {"demo": r"link:..\..\shared"}})
    manifest = parse_manifest("package.json", text, lambda fmt: parse(text, fmt, DEFAULT_LIMITS))
    assert manifest is not None
    record = next(local_sources("apps/app/package.json", manifest))
    assert (record["kind"], record["within_repository"]) == ("relative", True)


def test_file_uri_credentials_and_query_are_not_profiled() -> None:
    source = "file://dummy:NOT_A_REAL_PASSWORD@example.invalid/share?DUMMY_TOKEN=example#part"
    manifest = Manifest(dependencies=[Dependency("pypi", "demo", source, "path")])
    record = next(local_sources("requirements.txt", manifest))
    assert record["source"] == "file://example.invalid/share"
    assert record["kind"] == "unc"


def test_malformed_file_uri_is_unresolved() -> None:
    manifest = Manifest(dependencies=[Dependency("pypi", "demo", "file://[broken", "path")])
    record = next(local_sources("requirements.txt", manifest))
    assert record["kind"] == "unresolved"
    assert record["within_repository"] is None


def _profile(tmp_path: Path, files: dict[str, str]) -> tuple[AreaResult, CoverageCollector]:
    root = materialize(tmp_path / "repo", files)
    coverage = CoverageCollector()
    ctx = ScanContext(
        LocalTree(root, DEFAULT_LIMITS, coverage), builtin_rules(), DEFAULT_LIMITS, coverage
    )
    return provenance.analyze(ctx), coverage


def test_profile_records_facts_and_coverage_without_findings(tmp_path: Path) -> None:
    result, coverage = _profile(
        tmp_path,
        {
            "package.json": json.dumps(
                {"dependencies": {"inside": "file:packages/lib", "outside": "link:../shared"}}
            ),
        },
    )
    facts = result.facts["provenance"]
    assert isinstance(facts, dict)
    sources = facts["dependency_sources"]
    assert isinstance(sources, list) and len(sources) == 2
    assert not result.findings
    assert any(label == "Local deps" for label, _ in result.summary)
    assert any(c.scope == "dependencies:local-sources" for c in coverage.items())


def test_internal_workspace_paths_add_no_local_source_gap(tmp_path: Path) -> None:
    result, coverage = _profile(
        tmp_path,
        {
            "apps/app/package.json": json.dumps(
                {"dependencies": {"demo": "file:../../shared", "w": "workspace:*"}}
            )
        },
    )
    facts = result.facts["provenance"]
    assert isinstance(facts, dict)
    assert facts["dependency_sources"][0]["within_repository"] is True
    assert not [c for c in coverage.items() if c.scope == "dependencies:local-sources"]


def test_record_limit_is_reported_as_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provenance, "_DEPENDENCY_SOURCE_LIMIT", 2)
    result, coverage = _profile(
        tmp_path,
        {"package.json": json.dumps({"dependencies": {str(n): f"file:p{n}" for n in range(3)}})},
    )
    facts = result.facts["provenance"]
    assert isinstance(facts, dict)
    assert len(facts["dependency_sources"]) == 2
    assert any(
        c.scope == "dependencies:local-sources" and c.status is CoverageStatus.PARTIAL
        for c in coverage.items()
    )


def test_broken_manifests_record_parse_failure_without_crashing(tmp_path: Path) -> None:
    result, coverage = _profile(tmp_path, {"setup.cfg": "[broken", "package.json": "{"})
    facts = result.facts["provenance"]
    assert isinstance(facts, dict)
    assert not facts.get("dependency_sources")
    assert any(c.status is CoverageStatus.FAILED for c in coverage.items())


def test_windows_and_unc_sources_do_not_access_the_file_system(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("local dependency targets must not be accessed")

    sources = [r"C:\example\lib", r"C:lib", r"\example\lib", r"\\example.invalid\share\lib"]
    with monkeypatch.context() as patch:
        for name in ("resolve", "stat", "exists", "open"):
            patch.setattr(Path, name, forbidden)
        for source in sources:
            manifest = Manifest(dependencies=[Dependency("npm", "demo", source, "registry")])
            records = list(local_sources("package.json", manifest))
            assert len(records) == 1
            assert records[0]["within_repository"] is None
