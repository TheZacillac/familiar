"""Test 17: Advisor helper functions — _unwrap_bulk and _get_cert.

Tests the BulkResult unwrapping and certificate extraction helpers
that are used throughout the advisor and memory tools.
"""

import pytest

from familiar.tools.advisor_tools import _get_cert, _unwrap_bulk


class TestUnwrapBulk:
    """_unwrap_bulk must extract .data from successful BulkResult wrappers."""

    def test_successful_result(self):
        raw = {"success": True, "data": {"domain": "example.com"}, "error": None}
        assert _unwrap_bulk(raw) == {"domain": "example.com"}

    def test_failed_result_returns_none(self):
        raw = {"success": False, "data": None, "error": "timeout"}
        assert _unwrap_bulk(raw) is None

    def test_none_input(self):
        assert _unwrap_bulk(None) is None

    def test_empty_dict(self):
        assert _unwrap_bulk({}) is None

    def test_missing_success_key(self):
        raw = {"data": {"domain": "test.com"}}
        assert _unwrap_bulk(raw) is None

    def test_success_false_with_data(self):
        """Even if data is present, success=False should return None."""
        raw = {"success": False, "data": {"partial": True}}
        assert _unwrap_bulk(raw) is None

    def test_non_dict_input(self):
        assert _unwrap_bulk("string") is None
        assert _unwrap_bulk(42) is None
        assert _unwrap_bulk([]) is None

    def test_data_is_list(self):
        raw = {"success": True, "data": [1, 2, 3]}
        assert _unwrap_bulk(raw) == [1, 2, 3]

    def test_data_is_none_but_success_true(self):
        raw = {"success": True, "data": None}
        assert _unwrap_bulk(raw) is None


class TestGetCert:
    """_get_cert must extract the certificate dict from seer.status() output."""

    def test_valid_certificate(self):
        status = {
            "http_status": 200,
            "certificate": {
                "is_valid": True,
                "days_until_expiry": 90,
                "issuer": "Let's Encrypt",
            },
        }
        cert = _get_cert(status)
        assert cert["is_valid"] is True
        assert cert["days_until_expiry"] == 90

    def test_no_certificate(self):
        status = {"http_status": 200}
        assert _get_cert(status) == {}

    def test_certificate_is_none(self):
        status = {"http_status": 200, "certificate": None}
        assert _get_cert(status) == {}

    def test_none_input(self):
        assert _get_cert(None) == {}

    def test_non_dict_input(self):
        assert _get_cert("string") == {}
        assert _get_cert(42) == {}

    def test_empty_dict(self):
        assert _get_cert({}) == {}

    def test_certificate_is_not_dict(self):
        status = {"certificate": "invalid"}
        assert _get_cert(status) == {}

    def test_certificate_with_all_fields(self):
        status = {
            "certificate": {
                "is_valid": True,
                "days_until_expiry": 30,
                "issuer": "DigiCert",
                "subject": "*.example.com",
                "san": ["example.com", "*.example.com"],
            },
        }
        cert = _get_cert(status)
        assert cert["issuer"] == "DigiCert"
        assert len(cert["san"]) == 2
