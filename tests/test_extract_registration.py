"""Test 7: _extract_registration() WHOIS/RDAP normalization accuracy.

Validates that both WHOIS and RDAP response formats are correctly
normalized into a flat registration dict with consistent field names.
"""

import pytest

from familiar.tools.advisor_tools import _extract_registration


class TestWhoisExtraction:
    """WHOIS-sourced lookup results."""

    def test_full_whois_record(self):
        raw = {
            "source": "whois",
            "data": {
                "domain": "example.com",
                "registrar": "Example Registrar, Inc.",
                "registrant": "John Doe",
                "organization": "Example Corp",
                "creation_date": "2000-01-15T00:00:00Z",
                "expiration_date": "2030-01-15T00:00:00Z",
                "updated_date": "2024-06-01T00:00:00Z",
                "nameservers": ["ns1.example.com", "ns2.example.com"],
                "status": ["clientTransferProhibited"],
                "dnssec": "unsigned",
            },
        }
        result = _extract_registration(raw)
        assert result["source"] == "whois"
        assert result["domain"] == "example.com"
        assert result["registrar"] == "Example Registrar, Inc."
        assert result["creation_date"] == "2000-01-15T00:00:00Z"
        assert result["expiration_date"] == "2030-01-15T00:00:00Z"
        assert len(result["nameservers"]) == 2
        assert result["statuses"] == ["clientTransferProhibited"]
        assert result["dnssec"] == "unsigned"

    def test_whois_missing_optional_fields(self):
        raw = {
            "source": "whois",
            "data": {
                "domain": "minimal.com",
                "registrar": "Some Registrar",
            },
        }
        result = _extract_registration(raw)
        assert result["source"] == "whois"
        assert result["domain"] == "minimal.com"
        assert result["creation_date"] is None
        assert result["nameservers"] == []

    def test_whois_empty_data(self):
        raw = {"source": "whois", "data": {}}
        result = _extract_registration(raw)
        assert result["source"] == "whois"
        assert result.get("domain") is None


class TestRdapExtraction:
    """RDAP-sourced lookup results with RFC 7483 structure."""

    def test_full_rdap_record(self):
        raw = {
            "source": "rdap",
            "data": {
                "ldhName": "example.com",
                "status": ["active"],
                "events": [
                    {"eventAction": "registration", "eventDate": "2000-01-15T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-01-15T00:00:00Z"},
                    {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Registrar, Inc."]],
                        ],
                    }
                ],
                "nameservers": [
                    {"ldhName": "ns1.example.com"},
                    {"ldhName": "ns2.example.com"},
                ],
                "secureDNS": {"delegationSigned": True},
            },
        }
        result = _extract_registration(raw)
        assert result["source"] == "rdap"
        assert result["domain"] == "example.com"
        assert result["creation_date"] == "2000-01-15T00:00:00Z"
        assert result["expiration_date"] == "2030-01-15T00:00:00Z"
        assert result["updated_date"] == "2024-06-01T00:00:00Z"
        assert result["registrar"] == "Example Registrar, Inc."
        assert result["nameservers"] == ["ns1.example.com", "ns2.example.com"]
        assert result["dnssec"] == "yes"

    def test_rdap_unsigned_dnssec(self):
        raw = {
            "source": "rdap",
            "data": {
                "ldhName": "unsigned.com",
                "status": [],
                "secureDNS": {"delegationSigned": False},
            },
        }
        result = _extract_registration(raw)
        assert result["dnssec"] == "unsigned"

    def test_rdap_registrar_from_handle_fallback(self):
        """When vcardArray is missing, should fall back to entity handle."""
        raw = {
            "source": "rdap",
            "data": {
                "ldhName": "example.com",
                "status": [],
                "entities": [
                    {"roles": ["registrar"], "handle": "REG-1234"},
                ],
            },
        }
        result = _extract_registration(raw)
        assert result["registrar"] == "REG-1234"

    def test_rdap_unicode_name_fallback(self):
        raw = {
            "source": "rdap",
            "data": {
                "unicodeName": "example.com",
                "status": [],
            },
        }
        result = _extract_registration(raw)
        assert result["domain"] == "example.com"

    def test_rdap_whois_fallback_fills_gaps(self):
        raw = {
            "source": "rdap",
            "data": {"ldhName": "example.com", "status": []},
            "whois_fallback": {
                "registrar": "Fallback Registrar",
                "expiration_date": "2030-12-31",
                "creation_date": "2000-01-01",
            },
        }
        result = _extract_registration(raw)
        assert result["registrar"] == "Fallback Registrar"
        assert result["expiration_date"] == "2030-12-31"
        assert result["creation_date"] == "2000-01-01"


class TestEdgeCases:
    """Malformed, missing, or unexpected inputs."""

    def test_none_input(self):
        assert _extract_registration(None) == {}

    def test_empty_dict(self):
        assert _extract_registration({}) == {}

    def test_non_dict_input(self):
        assert _extract_registration("not a dict") == {}

    def test_unknown_source(self):
        raw = {"source": "unknown", "data": {"domain": "x.com"}}
        result = _extract_registration(raw)
        assert result == {"source": "unknown"}

    def test_missing_data_key(self):
        raw = {"source": "whois"}
        result = _extract_registration(raw)
        assert result == {"source": "whois"}

    def test_data_is_none(self):
        raw = {"source": "whois", "data": None}
        result = _extract_registration(raw)
        assert result == {"source": "whois"}
