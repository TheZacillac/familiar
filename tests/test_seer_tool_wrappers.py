"""Test 14: Seer tool wrappers — JSON output and error handling.

Mocks the seer library to verify that each tool wrapper returns valid JSON
and that exceptions are caught and wrapped in {"error": ...} format.
"""

import json
from unittest.mock import patch

import pytest

from familiar.tools.seer_tools import (
    seer_availability,
    seer_dig,
    seer_lookup,
    seer_rdap_domain,
    seer_ssl,
    seer_status,
    seer_whois,
)


class TestSeerToolSuccessOutput:
    """Successful calls must return valid JSON strings."""

    @patch("familiar.tools.seer_tools.seer")
    def test_lookup_returns_json(self, mock_seer):
        mock_seer.lookup.return_value = {"source": "rdap", "data": {"ldhName": "example.com"}}
        result = seer_lookup.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["source"] == "rdap"

    @patch("familiar.tools.seer_tools.seer")
    def test_whois_returns_json(self, mock_seer):
        mock_seer.whois.return_value = {"domain": "example.com", "registrar": "Test"}
        result = seer_whois.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["registrar"] == "Test"

    @patch("familiar.tools.seer_tools.seer")
    def test_dig_returns_json(self, mock_seer):
        mock_seer.dig.return_value = [{"data": {"address": "1.2.3.4"}}]
        result = seer_dig.invoke({"domain": "example.com", "record_type": "A"})
        parsed = json.loads(result)
        assert isinstance(parsed, list)

    @patch("familiar.tools.seer_tools.seer")
    def test_status_returns_json(self, mock_seer):
        mock_seer.status.return_value = {"http_status": 200, "certificate": {"is_valid": True}}
        result = seer_status.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["http_status"] == 200

    @patch("familiar.tools.seer_tools.seer")
    def test_availability_returns_json(self, mock_seer):
        mock_seer.availability.return_value = {"available": True, "method": "rdap"}
        result = seer_availability.invoke({"domain": "newdomain.com"})
        parsed = json.loads(result)
        assert parsed["available"] is True

    @patch("familiar.tools.seer_tools.seer")
    def test_ssl_returns_json(self, mock_seer):
        mock_seer.ssl.return_value = {"valid": True, "days_until_expiry": 90}
        result = seer_ssl.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert parsed["valid"] is True


class TestSeerToolErrorHandling:
    """Exceptions must be caught and returned as {"error": ...} JSON."""

    @patch("familiar.tools.seer_tools.seer")
    def test_lookup_error(self, mock_seer):
        mock_seer.lookup.side_effect = ConnectionError("timeout")
        result = seer_lookup.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "timeout" in parsed["error"]

    @patch("familiar.tools.seer_tools.seer")
    def test_whois_error(self, mock_seer):
        mock_seer.whois.side_effect = RuntimeError("WHOIS server unavailable")
        result = seer_whois.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.seer_tools.seer")
    def test_dig_error(self, mock_seer):
        mock_seer.dig.side_effect = Exception("DNS resolution failed")
        result = seer_dig.invoke({"domain": "fail.com", "record_type": "A"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.seer_tools.seer")
    def test_rdap_domain_error(self, mock_seer):
        mock_seer.rdap_domain.side_effect = ValueError("Invalid domain")
        result = seer_rdap_domain.invoke({"domain": "!!!"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.seer_tools.seer")
    def test_status_error(self, mock_seer):
        mock_seer.status.side_effect = OSError("Network unreachable")
        result = seer_status.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestSeerToolJsonValidity:
    """All return values must be parseable JSON, even for edge cases."""

    @patch("familiar.tools.seer_tools.seer")
    def test_none_result_serializable(self, mock_seer):
        mock_seer.lookup.return_value = None
        result = seer_lookup.invoke({"domain": "test.com"})
        # Should not raise
        json.loads(result)

    @patch("familiar.tools.seer_tools.seer")
    def test_empty_dict_result(self, mock_seer):
        mock_seer.status.return_value = {}
        result = seer_status.invoke({"domain": "test.com"})
        parsed = json.loads(result)
        assert parsed == {}
