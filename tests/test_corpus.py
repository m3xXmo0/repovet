"""False-positive corpus: real repositories must not produce unjustified high/critical
findings. Skipped unless REPOVET_CORPUS_DIR is set; see
tests/corpus/README.md."""

import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from helpers import builtin_rules, scan
from repovet.models import Severity

MANIFEST = Path(__file__).parent / "corpus" / "corpus.yaml"
ENTRIES: list[dict[str, Any]] = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
CORPUS_DIR = os.environ.get("REPOVET_CORPUS_DIR")


def test_manifest_is_complete() -> None:
    assert len(ENTRIES) >= 5
    known = {rule.id for rule in builtin_rules().rules}
    for entry in ENTRIES:
        assert {"name", "repo", "commit", "why", "accepted"} <= set(entry), entry
        for accepted in entry["accepted"]:
            assert accepted["rule"] in known and accepted["reason"], accepted


def repository_root(name: str) -> Path:
    assert CORPUS_DIR is not None
    folder = Path(CORPUS_DIR) / name
    if not folder.is_dir():
        pytest.skip(f"{name} not downloaded into {CORPUS_DIR}")
    children = [p for p in folder.iterdir() if p.is_dir()]
    # Archives from GitHub contain one top folder (owner-repo-commit).
    return children[0] if len(children) == 1 else folder


@pytest.mark.corpus
@pytest.mark.skipif(CORPUS_DIR is None, reason="REPOVET_CORPUS_DIR is not set")
@pytest.mark.parametrize("entry", ENTRIES, ids=[e["name"] for e in ENTRIES])
def test_no_unjustified_high_findings(entry: dict[str, Any]) -> None:
    root = repository_root(entry["name"])
    findings = scan(root).findings
    accepted = {(a["rule"], a.get("path")) for a in entry["accepted"]}
    unexpected = []
    for finding in findings:
        path = finding.location.path if finding.location else None
        if (
            finding.severity < Severity.HIGH
            or {(finding.rule_id, path), (finding.rule_id, None)} & accepted
        ):
            continue
        line = finding.location.line if finding.location else None
        unexpected.append(f"{finding.rule_id} {path}:{line}")
    assert unexpected == []
