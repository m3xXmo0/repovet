"""Stored report comparisons reject missing identities and filtered inputs."""

import copy

import pytest

from repovet.report import json_in, json_out
from test_terminal import sample_findings, sample_result


def test_saved_finding_keeps_its_central_fingerprint() -> None:
    data = json_out.build(sample_result(sample_findings()))["findings"]
    assert isinstance(data, list)
    parsed = json_in.finding_from_data(data[0])
    assert parsed.fingerprint == data[0]["fingerprint"]


def test_old_count_or_unidentified_finding_is_rejected() -> None:
    with pytest.raises(ValueError):
        json_in.finding_from_data({"rule_id": "RC-AUTO-020", "count": 1})


def test_filtered_saved_report_is_rejected() -> None:
    data = copy.deepcopy(json_out.build(sample_result([])))
    scan = data["scan"]
    assert isinstance(scan, dict)
    scan["min_severity"] = "high"
    with pytest.raises(ValueError, match="filtered"):
        json_in.scan_from_data(data)
