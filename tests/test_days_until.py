"""Test 1: days_until() date parsing accuracy and reliability.

Validates that WHOIS/RDAP dates in various formats are correctly parsed and
that the days-remaining calculation is accurate for future, past, and edge-case inputs.
"""

from datetime import datetime, timedelta, timezone

import pytest

from familiar.utils import days_until


class TestIso8601FullParsing:
    """Full ISO 8601 datetime strings with timezone info."""

    def test_future_date_utc(self):
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        result = days_until(future)
        assert result is not None
        # Allow +-1 day tolerance for boundary rounding
        assert 89 <= result <= 90

    def test_past_date_returns_negative(self):
        past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        result = days_until(past)
        assert result is not None
        assert -31 <= result <= -30

    def test_today_returns_zero_or_negative_one(self):
        now = datetime.now(timezone.utc).isoformat()
        result = days_until(now)
        assert result is not None
        assert result in (0, -1)

    def test_positive_tz_offset(self):
        """RDAP dates sometimes include +05:30 etc."""
        future = datetime.now(timezone.utc) + timedelta(days=60)
        # Format with explicit +00:00
        date_str = future.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        result = days_until(date_str)
        assert result is not None
        assert 59 <= result <= 60


class TestDateOnlyFallback:
    """Date-only strings (YYYY-MM-DD) common in WHOIS responses."""

    def test_date_only_future(self):
        future = (datetime.now(timezone.utc) + timedelta(days=45)).strftime("%Y-%m-%d")
        result = days_until(future)
        assert result is not None
        assert 44 <= result <= 45

    def test_date_only_past(self):
        past = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%d")
        result = days_until(past)
        assert result is not None
        assert -366 <= result <= -365

    def test_known_date(self):
        """A far-future date should yield a large positive number."""
        result = days_until("2099-12-31")
        assert result is not None
        assert result > 25000  # ~70 years from 2026


class TestNaiveDatetimeHandling:
    """Naive datetimes (no tzinfo) should be treated as UTC."""

    def test_naive_iso_treated_as_utc(self):
        future = (datetime.now(timezone.utc) + timedelta(days=10))
        naive_str = future.strftime("%Y-%m-%dT%H:%M:%S")
        result = days_until(naive_str)
        assert result is not None
        assert 9 <= result <= 10


class TestInvalidInputs:
    """Malformed or non-date inputs should return None, not raise."""

    @pytest.mark.parametrize("bad_input", [
        "",
        "not-a-date",
        "2024-13-01",  # invalid month
        "abcdefghij",
        None,
        12345,
        [],
        {},
    ])
    def test_returns_none_for_garbage(self, bad_input):
        result = days_until(bad_input)
        assert result is None


class TestEdgeCases:
    """Boundary and unusual but valid inputs."""

    def test_leap_year_date(self):
        result = days_until("2028-02-29")
        assert result is not None  # 2028 is a leap year

    def test_non_leap_year_feb29_returns_none(self):
        result = days_until("2027-02-29")
        assert result is None  # 2027 is not a leap year

    def test_string_coercion_of_numeric(self):
        """days_until calls str() on input; verify numeric doesn't crash."""
        result = days_until(20260101)
        # str(20260101) == "2026010" -> first 10 chars fallback -> likely invalid
        # Just ensure no crash
        assert result is None or isinstance(result, int)
