"""Tests for the Warden platform upload bridge (warden_upload)."""

import warden_upload as wu


def test_severity_mapping():
    assert wu._map_finding({"severity": "CRITICAL", "description": "x"})["severity"] == "Critical"
    assert wu._map_finding({"severity": "high", "description": "x"})["severity"] == "High"
    assert wu._map_finding({"severity": "Moderate", "description": "x"})["severity"] == "Medium"
    # Unknown severity falls back to Medium rather than dropping the finding.
    assert wu._map_finding({"severity": "weird", "description": "x"})["severity"] == "Medium"


def test_map_finding_full():
    raw = {
        "severity": "HIGH",
        "file": "app/db.py",
        "line": 12,
        "description": "SQL injection via unsanitized id.",
        "exploit_scenario": "Attacker injects ' OR 1=1.",
        "recommendation": "Use parameterized queries.",
        "cwe": "CWE-89",
    }
    f = wu._map_finding(raw)
    assert f["name"] == "SQL injection via unsanitized id."
    assert "Exploit scenario" in f["description"]
    assert f["recommendation"] == "Use parameterized queries."
    assert f["ruleId"] == "CWE-89"
    assert f["location"] == {"path": "app/db.py", "startLine": 12, "endLine": 12}
    # Identity is stable for the same input.
    assert f["identity"] == wu._map_finding(raw)["identity"]
    assert f["identity"].startswith("warden-ai:")


def test_map_finding_minimal_no_location():
    f = wu._map_finding({"severity": "LOW", "description": "Weak hash."})
    assert "location" not in f
    assert f["category"] == "ai-security-review"
    assert f["severity"] == "Low"


def test_first_sentence():
    assert wu._first_sentence("Hello world. More text.") == "Hello world."
    assert wu._first_sentence("") == "AI security finding"


def test_alt_field_names():
    # Accept file_path/line_number/message/remediation aliases too.
    f = wu._map_finding(
        {
            "severity": "MEDIUM",
            "file_path": "x.js",
            "line_number": 5,
            "message": "Issue here.",
            "remediation": "Fix it.",
        }
    )
    assert f["location"]["path"] == "x.js"
    assert f["location"]["startLine"] == 5
    assert f["recommendation"] == "Fix it."
