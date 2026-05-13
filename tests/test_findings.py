"""Tests for the central findings module — severity ordering, the
:func:`make_finding` constructor, and shape validation inside
:func:`sort_findings`.
"""

import pytest

from familiar.findings import (
    SEVERITY_ORDER,
    Finding,
    make_finding,
    severity_counts,
    sort_findings,
)


class TestSeverityOrder:
    def test_canonical_order(self):
        assert SEVERITY_ORDER == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_sort_findings_orders_descending(self):
        findings = [
            {"severity": "LOW", "finding": "x"},
            {"severity": "CRITICAL", "finding": "y"},
            {"severity": "MEDIUM", "finding": "z"},
        ]
        sorted_ = sort_findings(findings)
        assert [f["severity"] for f in sorted_] == ["CRITICAL", "MEDIUM", "LOW"]

    def test_sort_is_stable_for_ties(self):
        findings = [
            {"severity": "HIGH", "finding": "first"},
            {"severity": "HIGH", "finding": "second"},
            {"severity": "HIGH", "finding": "third"},
        ]
        assert [f["finding"] for f in sort_findings(findings)] == [
            "first", "second", "third",
        ]


class TestSeverityCounts:
    def test_counts_initialised_to_zero(self):
        c = severity_counts([])
        assert c == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def test_counts_each_tier(self):
        c = severity_counts([
            {"severity": "CRITICAL", "finding": "a"},
            {"severity": "HIGH", "finding": "b"},
            {"severity": "HIGH", "finding": "c"},
        ])
        assert c["CRITICAL"] == 1
        assert c["HIGH"] == 2
        assert c["MEDIUM"] == 0


class TestMakeFinding:
    def test_minimal_construction(self):
        f = make_finding("HIGH", "Open port detected")
        assert f["severity"] == "HIGH"
        assert f["finding"] == "Open port detected"
        assert "detail" not in f
        assert "recommendation" not in f

    def test_full_construction(self):
        f = make_finding(
            "MEDIUM",
            "Weak cipher",
            detail="TLS 1.0 enabled",
            recommendation="Disable TLS 1.0",
            category="SSL",
            source="ssl_deep_scan",
        )
        assert f["severity"] == "MEDIUM"
        assert f["detail"] == "TLS 1.0 enabled"
        assert f["category"] == "SSL"
        assert f["source"] == "ssl_deep_scan"

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="Unknown severity"):
            make_finding("BOGUS", "x")

    def test_lowercase_severity_raises(self):
        # Severities are uppercase by convention; lowercase is a typo class.
        with pytest.raises(ValueError):
            make_finding("high", "x")

    def test_empty_finding_text_raises(self):
        with pytest.raises(ValueError, match="non-empty string"):
            make_finding("HIGH", "")

    def test_whitespace_only_finding_raises(self):
        with pytest.raises(ValueError):
            make_finding("HIGH", "   ")


class TestSortFindingsValidation:
    """sort_findings raises in test/strict mode for malformed input."""

    def test_invalid_severity_raises_under_pytest(self):
        bad = [{"severity": "WHOOPS", "finding": "x"}]
        # PYTEST_CURRENT_TEST is set automatically by pytest, so strict mode is on.
        with pytest.raises(ValueError, match="invalid severity"):
            sort_findings(bad)

    def test_missing_finding_text_raises(self):
        bad = [{"severity": "HIGH"}]
        with pytest.raises(ValueError, match="missing or empty"):
            sort_findings(bad)

    def test_finding_typed_dict_accepts_extras(self):
        # Finding is total=False with extras allowed — verify a real
        # production-style entry round-trips through sort_findings cleanly.
        f: Finding = {
            "severity": "LOW",
            "finding": "CAA iodef missing",
            "detail": "...",
            "recommendation": "...",
            "category": "CAA",
        }
        assert sort_findings([f]) == [f]
