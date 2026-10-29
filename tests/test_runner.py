from pathlib import Path

from helpers import materialize, scan, write_rule
from repocheck.engine.context import ScanContext
from repocheck.engine.loader import load_rules
from repocheck.engine.runner import record_unsupported, render_message, run_rules
from repocheck.limits import DEFAULT_LIMITS, Limits
from repocheck.models import CoverageCollector, CoverageStatus
from repocheck.sources.local import LocalTree

REGEX_RULE = "{type: regex, pattern: 'TODO'}"


def test_render_message_sanitizes_and_shortens() -> None:
    message = render_message("value: {value} at {path}", {"value": "a\x1bb" * 50, "path": "p"}, 20)
    assert "\x1b" not in message
    assert message.startswith("value: a<U+001B>b")
    assert message.endswith(" at p")
    assert render_message("{missing}!", {}, 10) == "!"


def test_one_finding_per_line_and_cap(tmp_path: Path) -> None:
    rules = load_rules([write_rule(tmp_path / "rules", check=REGEX_RULE, message="todo {line}")])
    rule = rules.get("RC-AUTO-901")
    assert rule is not None
    repo = materialize(tmp_path / "repo", {"a.txt": "TODO TODO\n" * 8})
    findings = scan(repo, [rule], rules).findings
    assert len(findings) == DEFAULT_LIMITS.max_matches_per_file
    assert [f.location.line for f in findings if f.location] == [1, 2, 3, 4, 5]
    assert findings[-1].message == "todo 5 (and 3 more in this file)"
    assert findings[0].evidence == "TODO TODO"


def test_deprecated_rules_do_not_run(tmp_path: Path) -> None:
    folder = write_rule(tmp_path / "rules", check=REGEX_RULE)
    path = folder / "test_rules.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "  deprecated: true\n", encoding="utf-8")
    rules = load_rules([folder])
    repo = materialize(tmp_path / "repo", {"a.txt": "TODO\n"})
    assert not scan(repo, rules.rules, rules).findings
    assert rules.get("RC-AUTO-901") is not None
    assert "RC-AUTO-901" not in {r.id for r in rules.active()}


def test_content_rules_skip_binary_and_large_files(tmp_path: Path) -> None:
    rules = load_rules([write_rule(tmp_path / "rules", check=REGEX_RULE)])
    rule = rules.get("RC-AUTO-901")
    assert rule is not None
    repo = materialize(
        tmp_path / "repo",
        {"bin.dat": {"base64": "AAEC"}, "big.txt": "TODO " * 100, "ok.txt": "TODO\n"},
    )
    outcome = scan(repo, [rule], rules, Limits(max_file_size=100))
    assert [f.location.path for f in outcome.findings if f.location] == ["ok.txt"]
    reasons = {c.reason: c.sample for c in outcome.coverage}
    assert any(sample == ("bin.dat",) and "Binary" in reason for reason, sample in reasons.items())
    assert any(sample == ("big.txt",) and "larger" in reason for reason, sample in reasons.items())


def test_time_limit_is_recorded(tmp_path: Path) -> None:
    repo = materialize(tmp_path / "repo", {"package.json": '{"scripts": {"install": "x"}}'})
    rules = load_rules()
    coverage = CoverageCollector()
    tree = LocalTree(repo, DEFAULT_LIMITS, coverage)
    ctx = ScanContext(tree, rules, DEFAULT_LIMITS, coverage, deadline=1.0)
    assert run_rules(rules.active(), ctx) == []
    (item,) = coverage.items()
    assert item.status == CoverageStatus.PARTIAL and "Time limit" in item.reason


def test_unsupported_surfaces_are_recorded(tmp_path: Path) -> None:
    repo = materialize(
        tmp_path / "repo",
        {
            "build.rs": "fn main() {}\n",
            "node_modules/x/build.rs": "fn main() {}\n",
            "gen.go": "package x\n//go:generate echo hi\n",
            "plain.go": "package x\n",
            ".github/workflows/ci.yml": "on: push\n",
        },
    )
    coverage = CoverageCollector()
    # Walk node_modules too, so the surface's own `exclude: vendored` is exercised.
    limits = Limits(skip_env_dirs=False)
    ctx = ScanContext(LocalTree(repo, limits, coverage), load_rules(), limits, coverage)
    record_unsupported(ctx)
    found = {c.scope: c.sample for c in coverage.items()}
    assert found == {
        "ci:github-actions": (".github/workflows/ci.yml",),
        "ecosystem:go": ("gen.go",),
        "ecosystem:rust": ("build.rs",),
    }
    assert all(c.status == CoverageStatus.UNSUPPORTED for c in coverage.items())
