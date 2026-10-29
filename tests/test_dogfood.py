"""Dogfooding: repocheck checks its own repository without crashing."""

from pathlib import Path

import pytest

from repocheck.cli import EXIT_FINDINGS, EXIT_OK, main

PROJECT = Path(__file__).parent.parent


def test_scan_own_repository(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(PROJECT), "--no-color"])
    out = capsys.readouterr().out
    assert code in (EXIT_OK, EXIT_FINDINGS)
    assert "NOT CHECKED" in out
