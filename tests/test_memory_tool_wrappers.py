"""Test 16: Memory tool wrappers — create_report, explanation mode, and watchlist_check alerts.

Tests the LangChain @tool wrappers in memory_tools.py, focusing on
create_report markdown generation, explanation mode toggling, and
watchlist_check alert threshold accuracy.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from familiar.tools.memory_tools import (
    create_report,
    get_explanation_mode,
    set_explanation_mode,
    watchlist_check,
)


class TestCreateReport:
    """create_report must generate valid markdown from JSON sections."""

    def test_valid_sections(self):
        sections = json.dumps([
            {"heading": "Summary", "content": "Domain is healthy."},
            {"heading": "DNS", "content": "All records present."},
        ])
        result = json.loads(create_report.invoke({"title": "Test Report", "sections": sections}))
        assert result["title"] == "Test Report"
        assert "timestamp" in result
        report = result["report"]
        assert "# Test Report" in report
        assert "## Summary" in report
        assert "Domain is healthy." in report
        assert "## DNS" in report
        assert "All records present." in report
        assert "Familiar" in report  # footer

    def test_empty_sections(self):
        sections = json.dumps([])
        result = json.loads(create_report.invoke({"title": "Empty", "sections": sections}))
        assert "# Empty" in result["report"]

    def test_invalid_json_sections(self):
        result = json.loads(create_report.invoke({"title": "Bad", "sections": "not json"}))
        assert "error" in result

    def test_section_missing_heading(self):
        sections = json.dumps([{"content": "No heading here"}])
        result = json.loads(create_report.invoke({"title": "Test", "sections": sections}))
        assert "Untitled Section" in result["report"]

    def test_timestamp_in_utc(self):
        sections = json.dumps([])
        result = json.loads(create_report.invoke({"title": "T", "sections": sections}))
        assert "UTC" in result["timestamp"]


class TestExplanationMode:
    """Explanation mode toggle must persist and read correctly."""

    @patch("familiar.tools.memory_tools.get_memory")
    def test_enable_explanation_mode(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        result = json.loads(set_explanation_mode.invoke({"enabled": True}))
        assert result["explanation_mode"] is True
        mock_mem.set_preference.assert_called_once_with("explanation_mode", "true")

    @patch("familiar.tools.memory_tools.get_memory")
    def test_disable_explanation_mode(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        result = json.loads(set_explanation_mode.invoke({"enabled": False}))
        assert result["explanation_mode"] is False
        mock_mem.set_preference.assert_called_once_with("explanation_mode", "false")

    @patch("familiar.tools.memory_tools.get_memory")
    def test_get_explanation_mode_true(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.get_preference.return_value = "true"
        mock_get_memory.return_value = mock_mem
        result = json.loads(get_explanation_mode.invoke({}))
        assert result["explanation_mode"] is True

    @patch("familiar.tools.memory_tools.get_memory")
    def test_get_explanation_mode_false(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.get_preference.return_value = "false"
        mock_get_memory.return_value = mock_mem
        result = json.loads(get_explanation_mode.invoke({}))
        assert result["explanation_mode"] is False


class TestWatchlistCheckAlerts:
    """watchlist_check must generate correct alerts based on data thresholds."""

    @patch("familiar.tools.memory_tools.get_memory")
    @patch("familiar.tools.memory_tools.parallel_calls")
    def test_empty_watchlist(self, mock_parallel, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_list.return_value = []
        mock_get_memory.return_value = mock_mem
        result = json.loads(watchlist_check.invoke({}))
        assert result["message"] == "Watchlist is empty"
        assert result["alerts"] == []

    @patch("familiar.tools.memory_tools.get_memory")
    @patch("familiar.tools.memory_tools.parallel_calls")
    def test_expired_domain_critical_alert(self, mock_parallel, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_list.return_value = [{"domain": "expired.com"}]
        mock_get_memory.return_value = mock_mem

        # Simulate expired domain (expiration date in past)
        mock_parallel.return_value = [
            [{"success": True, "data": {"http_status": 200, "certificate": {"is_valid": True, "days_until_expiry": 90}}}],
            [{"success": True, "data": {"source": "whois", "data": {"expiration_date": "2020-01-01"}}}],
        ]

        result = json.loads(watchlist_check.invoke({}))
        assert result["checked"] == 1
        # Should have expiration alert
        if result["domains_with_alerts"] > 0:
            alerts = result["alerts"][0]["alerts"]
            expiry_alerts = [a for a in alerts if a["type"] == "expiration"]
            assert len(expiry_alerts) > 0
            assert expiry_alerts[0]["severity"] == "critical"

    @patch("familiar.tools.memory_tools.get_memory")
    @patch("familiar.tools.memory_tools.parallel_calls")
    def test_http_unreachable_warning(self, mock_parallel, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_list.return_value = [{"domain": "down.com"}]
        mock_get_memory.return_value = mock_mem

        mock_parallel.return_value = [
            [{"success": True, "data": {"http_status": None}}],
            [{"success": True, "data": {"source": "whois", "data": {}}}],
        ]

        result = json.loads(watchlist_check.invoke({}))
        if result["domains_with_alerts"] > 0:
            alerts = result["alerts"][0]["alerts"]
            http_alerts = [a for a in alerts if a["type"] == "http"]
            assert len(http_alerts) > 0
            assert http_alerts[0]["severity"] == "warning"

    @patch("familiar.tools.memory_tools.get_memory")
    @patch("familiar.tools.memory_tools.parallel_calls")
    def test_invalid_ssl_critical_alert(self, mock_parallel, mock_get_memory):
        mock_mem = MagicMock()
        mock_mem.watchlist_list.return_value = [{"domain": "badssl.com"}]
        mock_get_memory.return_value = mock_mem

        mock_parallel.return_value = [
            [{"success": True, "data": {"http_status": 200, "certificate": {"is_valid": False, "days_until_expiry": 30}}}],
            [{"success": True, "data": {"source": "whois", "data": {}}}],
        ]

        result = json.loads(watchlist_check.invoke({}))
        if result["domains_with_alerts"] > 0:
            alerts = result["alerts"][0]["alerts"]
            ssl_alerts = [a for a in alerts if a["type"] == "ssl"]
            assert len(ssl_alerts) > 0
            assert ssl_alerts[0]["severity"] == "critical"
