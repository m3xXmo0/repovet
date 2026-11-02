"""Effective rule digests are independent of installation paths and YAML layout."""

import re
from pathlib import Path

from helpers import write_rule
from repovet.engine.loader import load_rules


def test_digest_is_stable_and_tracks_ignored_rules() -> None:
    rules = load_rules()
    assert re.fullmatch(r"[a-f0-9]{64}", rules.digest)
    assert rules.digest == load_rules().digest
    assert rules.without(["RC-AUTO-020"]).digest != rules.digest


def test_digest_ignores_rule_installation_path_and_comments(tmp_path: Path) -> None:
    left = write_rule(tmp_path / "left", rule_id="RC-AUTO-901", check="{type: filename}")
    right = write_rule(tmp_path / "right", rule_id="RC-AUTO-901", check="{type: filename}")
    for path in right.glob("*.yaml"):
        path.write_text(
            "# An incidental comment.\n" + path.read_text(encoding="utf-8"), encoding="utf-8"
        )
    assert load_rules([left]).digest == load_rules([right]).digest
