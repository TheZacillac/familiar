"""Test 15: Tome tool wrappers — JSON output and None handling.

Mocks the tome library to verify that each tool wrapper returns valid JSON,
that None results produce user-friendly error messages, and that exceptions
are caught.
"""

import json
from unittest.mock import patch

import pytest

from familiar.tools.tome_tools import (
    tome_glossary_lookup,
    tome_glossary_search,
    tome_record_lookup,
    tome_record_search,
    tome_tld_count,
    tome_tld_list_by_type,
    tome_tld_lookup,
    tome_tld_overview,
    tome_tld_search,
)


class TestTomeToolSuccess:
    """Successful calls must return valid JSON."""

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_lookup_returns_data(self, mock_tome):
        mock_tome.tld_lookup.return_value = {"tld": "com", "type": "gTLD"}
        result = tome_tld_lookup.invoke({"tld": "com"})
        parsed = json.loads(result)
        assert parsed["tld"] == "com"

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_search_returns_list(self, mock_tome):
        mock_tome.tld_search.return_value = [{"tld": "tech"}, {"tld": "technology"}]
        result = tome_tld_search.invoke({"query": "tech"})
        parsed = json.loads(result)
        assert len(parsed) == 2

    @patch("familiar.tools.tome_tools.tome")
    def test_record_lookup_returns_data(self, mock_tome):
        mock_tome.record_lookup.return_value = {"type": "A", "rfc": "RFC 1035"}
        result = tome_record_lookup.invoke({"query": "A"})
        parsed = json.loads(result)
        assert parsed["type"] == "A"

    @patch("familiar.tools.tome_tools.tome")
    def test_glossary_lookup_returns_data(self, mock_tome):
        mock_tome.glossary_lookup.return_value = {"term": "DNSSEC", "definition": "DNS Security Extensions"}
        result = tome_glossary_lookup.invoke({"term": "DNSSEC"})
        parsed = json.loads(result)
        assert parsed["term"] == "DNSSEC"

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_count_returns_count(self, mock_tome):
        mock_tome.tld_count.return_value = 1500
        result = tome_tld_count.invoke({})
        parsed = json.loads(result)
        assert parsed["count"] == 1500

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_overview_returns_data(self, mock_tome):
        mock_tome.tld_overview.return_value = {"tld": "com", "registry": "Verisign"}
        result = tome_tld_overview.invoke({"tld": "com"})
        parsed = json.loads(result)
        assert parsed["registry"] == "Verisign"


class TestTomeToolNoneHandling:
    """None results from tome must produce user-friendly error messages."""

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_lookup_none(self, mock_tome):
        mock_tome.tld_lookup.return_value = None
        result = tome_tld_lookup.invoke({"tld": "zzz"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "zzz" in parsed["error"]

    @patch("familiar.tools.tome_tools.tome")
    def test_record_lookup_none(self, mock_tome):
        mock_tome.record_lookup.return_value = None
        result = tome_record_lookup.invoke({"query": "BOGUS"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "BOGUS" in parsed["error"]

    @patch("familiar.tools.tome_tools.tome")
    def test_glossary_lookup_none(self, mock_tome):
        mock_tome.glossary_lookup.return_value = None
        result = tome_glossary_lookup.invoke({"term": "nonexistent"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "nonexistent" in parsed["error"]

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_overview_none(self, mock_tome):
        mock_tome.tld_overview.return_value = None
        result = tome_tld_overview.invoke({"tld": "nope"})
        parsed = json.loads(result)
        assert "error" in parsed


class TestTomeToolErrorHandling:
    """Exceptions must be caught and returned as {"error": ...} JSON."""

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_lookup_exception(self, mock_tome):
        mock_tome.tld_lookup.side_effect = RuntimeError("DB error")
        result = tome_tld_lookup.invoke({"tld": "com"})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "DB error" in parsed["error"]

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_search_exception(self, mock_tome):
        mock_tome.tld_search.side_effect = Exception("search failed")
        result = tome_tld_search.invoke({"query": "test"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.tome_tools.tome")
    def test_record_search_exception(self, mock_tome):
        mock_tome.record_search.side_effect = ValueError("bad query")
        result = tome_record_search.invoke({"query": "?"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.tome_tools.tome")
    def test_glossary_search_exception(self, mock_tome):
        mock_tome.glossary_search.side_effect = OSError("disk error")
        result = tome_glossary_search.invoke({"query": "test"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_list_by_type_exception(self, mock_tome):
        mock_tome.tld_list_by_type.side_effect = TypeError("invalid type")
        result = tome_tld_list_by_type.invoke({"tld_type": "gTLD"})
        parsed = json.loads(result)
        assert "error" in parsed

    @patch("familiar.tools.tome_tools.tome")
    def test_tld_count_exception(self, mock_tome):
        mock_tome.tld_count.side_effect = RuntimeError("connection lost")
        result = tome_tld_count.invoke({})
        parsed = json.loads(result)
        assert "error" in parsed
