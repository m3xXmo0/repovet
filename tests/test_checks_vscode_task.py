import json

import pytest

from helpers import run_check
from repovet.engine.checks.base import CheckError


def test_os_arguments_inherit_the_base_command() -> None:
    text = json.dumps(
        {
            "tasks": [
                {
                    "command": "node",
                    "windows": {"args": ["setup.js"]},
                    "runOptions": {"runOn": "folderOpen"},
                }
            ]
        }
    )
    spec = {"type": "vscode_task", "mode": "code", "pattern": r"\.js\Z"}
    (match,) = run_check(spec, ".vscode/tasks.json", text)
    assert match.values["match"] == "node setup.js"


def test_malformed_dependencies_do_not_abort_the_scan() -> None:
    text = json.dumps({"tasks": [{"dependsOn": 123, "runOptions": {"runOn": "folderOpen"}}]})
    spec = {"type": "vscode_task", "mode": "inventory"}
    assert len(run_check(spec, ".vscode/tasks.json", text)) == 1


def test_code_mode_requires_a_pattern() -> None:
    with pytest.raises(CheckError):
        run_check({"type": "vscode_task", "mode": "code"}, "a.json", "{}")
