"""Regression tests for preserving raw finding evidence."""

import json

from sentinelforge.modules.base import Finding, Severity


def test_finding_to_dict_preserves_raw_data():
    raw = {
        "protocol": "dns",
        "transport": "udp",
        "success": True,
        "response_code": 0,
        "answers": ["example.test A 192.0.2.10"],
    }
    finding = Finding(
        module="network",
        title="DNS response observed",
        severity=Severity.INFO,
        target="example.test",
        raw_data=raw,
    )

    serialized = finding.to_dict()

    assert serialized["raw_data"] == raw
    assert json.loads(json.dumps(serialized))["raw_data"] == raw


def test_finding_to_dict_defaults_raw_data_to_empty_dict():
    finding = Finding(
        module="network",
        title="Service observed",
        severity=Severity.INFO,
        target="example.test",
    )

    assert finding.to_dict()["raw_data"] == {}
