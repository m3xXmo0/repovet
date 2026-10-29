"""Shared test helpers: fixtures are materialized only under tmp_path."""

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from github_fake import case_target
from repovet.analyzers import provenance, trust
from repovet.engine.checks import BUILDERS
from repovet.engine.checks.base import BuildEnv, FactCheck, FileView, Match, Params
from repovet.engine.context import ScanContext
from repovet.engine.loader import Rule, RuleSet, load_rules
from repovet.engine.runner import run_rules
from repovet.limits import DEFAULT_LIMITS, Limits
from repovet.models import CoverageCollector, CoverageItem, Finding
from repovet.sources import gitmeta
from repovet.sources.local import LocalTree

_RULES: RuleSet | None = None
_REPEAT_KEYS = {"prefix", "repeat", "count", "suffix"}


def can_create(tmp_path: Path, requirement: str) -> bool:
    """Whether this machine can create what a fixture needs: ``symlinks``,
    ``case_sensitive_fs`` (two names differing only in case) or ``reserved_names``
    (Windows device names such as ``aux``)."""
    probe = tmp_path / f"probe-{requirement}"
    probe.mkdir(parents=True, exist_ok=True)
    try:
        if requirement == "symlinks":
            (probe / "link").symlink_to("target")
            return True
        if requirement == "case_sensitive_fs":
            (probe / "a").write_bytes(b"1")
            (probe / "A").write_bytes(b"2")
            return (probe / "a").read_bytes() == b"1"
        if requirement == "reserved_names":
            (probe / "aux").mkdir()
            (probe / "con.c").write_bytes(b"x")
            return (probe / "aux").is_dir() and (probe / "con.c").read_bytes() == b"x"
    except OSError:
        return False
    raise ValueError(f"unknown fixture requirement {requirement!r}")


def builtin_rules() -> RuleSet:
    global _RULES  # noqa: PLW0603 - load the package rules once per test session
    if _RULES is None:
        _RULES = load_rules()
    return _RULES


def materialize(root: Path, files: Mapping[str, object]) -> Path:
    """Write fixture files. Text is written as UTF-8 bytes (no newline translation);
    ``{base64: ...}`` gives raw bytes; ``{prefix, repeat, count, suffix}`` gives
    ``prefix + repeat * count + suffix`` (long lines without huge fixtures);
    ``{symlink: target}`` creates a symbolic link (never followed by repovet)."""
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        parts = rel.split("/")
        if rel.startswith("/") or "\\" in rel or ":" in rel or ".." in parts:
            raise ValueError(f"fixture path must stay inside the repo: {rel!r}")
        target = root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            target.write_bytes(content.encode("utf-8"))
        elif isinstance(content, dict) and set(content) == {"base64"}:
            target.write_bytes(base64.b64decode(str(content["base64"])))
        elif isinstance(content, dict) and {"repeat", "count"} <= set(content) <= _REPEAT_KEYS:
            text = (
                str(content.get("prefix", ""))
                + str(content["repeat"]) * int(content["count"])
                + str(content.get("suffix", ""))
            )
            target.write_bytes(text.encode("utf-8"))
        elif isinstance(content, dict) and set(content) == {"symlink"}:
            target.symlink_to(str(content["symlink"]))
        else:
            raise TypeError(f"unsupported fixture content for {rel!r}")
    return root


@dataclass
class Outcome:
    findings: list[Finding]
    coverage: list[CoverageItem]


def scan(
    root: Path,
    rules: Sequence[Rule] | None = None,
    ruleset: RuleSet | None = None,
    limits: Limits = DEFAULT_LIMITS,
    github: Mapping[str, Any] | None = None,
) -> Outcome:
    """Scan ``root`` with ``rules``. ``github`` (see ``github_fake.case_answers``) gives
    the trust area recorded API answers for example-org/example-repo."""
    ruleset = ruleset or builtin_rules()
    selected = ruleset.active() if rules is None else rules
    coverage = CoverageCollector()
    tree = LocalTree(root, limits, coverage)
    git = gitmeta.open_local(root)
    source = git if isinstance(git, gitmeta.GitSource) else None
    ctx = ScanContext(tree, ruleset, limits, coverage, git=source)
    try:
        # Fact rules (metric) need the facts the analyzers compute.
        facts: dict[str, object] | None = None
        if any(isinstance(r.check, FactCheck) for r in selected):
            facts = provenance.profile(ctx)[0]
            if github is not None:
                ctx.facts.update(facts)
                ctx.trust = case_target(github, source)
                facts.update(trust.profile(ctx)[0])
        findings = run_rules(selected, ctx, facts=facts)
    finally:
        if source is not None:
            source.objects.close()
    return Outcome(findings, coverage.items())


@dataclass
class MemFile:
    path: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    def read_bytes(self, limit: int) -> bytes:
        return self.data[:limit]


def view_of(path: str, content: str | bytes, limits: Limits = DEFAULT_LIMITS) -> FileView:
    data = content.encode("utf-8") if isinstance(content, str) else content
    return FileView(MemFile(path, data), limits, CoverageCollector())


def run_check(
    spec: Mapping[str, object],
    path: str,
    content: str | bytes,
    *,
    patterns: Mapping[str, str] | None = None,
    case_sensitive: bool = False,
    limits: Limits = DEFAULT_LIMITS,
) -> list[Match]:
    check_type = str(spec["type"])
    env = BuildEnv(dict(patterns or {}), case_sensitive)
    check = BUILDERS[check_type](Params(spec), env)
    view = view_of(path, content, limits)
    if check.needs_text and view.text() is None:
        return []
    return list(check.matches(view))


RULE_TEMPLATE = """\
- id: {id}
  title: Test rule
  area: {area}
  severity: {severity}
  confidence: high
  files: {files}
  check: {check}
  message: "{message}"
  rationale: Test rationale.
  recommendation: Test recommendation.
"""


def write_rule(
    directory: Path,
    *,
    rule_id: str = "RC-AUTO-901",
    area: str = "autorun",
    severity: str = "high",
    files: str = '["**"]',
    check: str = "{type: filename, name_regex: '^marker\\.txt$'}",
    message: str = "found {path}",
    name: str = "test_rules.yaml",
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    text = RULE_TEMPLATE.format(
        id=rule_id, area=area, severity=severity, files=files, check=check, message=message
    )
    (directory / name).write_text(text, encoding="utf-8")
    return directory
