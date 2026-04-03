"""Test 6: Memory tag search accuracy and preference storage.

Validates exact tag matching (not substring), case insensitivity,
SQL wildcard escaping, and preference get/set with defaults.
"""

import pytest


class TestTagSearch:
    """tag_search must match exact tags, not substrings."""

    def test_exact_match(self, memory):
        memory.remember_domain("a.com", tags="dns")
        memory.remember_domain("b.com", tags="dnssec")
        results = memory.tag_search("dns")
        domains = [r["domain"] for r in results]
        assert "a.com" in domains
        assert "b.com" not in domains  # "dnssec" != "dns"

    def test_case_insensitive(self, memory):
        memory.remember_domain("a.com", tags="Security")
        results = memory.tag_search("security")
        assert len(results) == 1
        assert results[0]["domain"] == "a.com"

    def test_case_insensitive_query(self, memory):
        memory.remember_domain("a.com", tags="ssl")
        results = memory.tag_search("SSL")
        assert len(results) == 1

    def test_no_matches(self, memory):
        memory.remember_domain("a.com", tags="dns,ssl")
        assert memory.tag_search("nonexistent") == []

    def test_multiple_domains_same_tag(self, memory):
        memory.remember_domain("a.com", tags="important")
        memory.remember_domain("b.com", tags="important,other")
        memory.remember_domain("c.com", tags="other")
        results = memory.tag_search("important")
        domains = {r["domain"] for r in results}
        assert domains == {"a.com", "b.com"}

    def test_sql_wildcard_percent_escaped(self, memory):
        """A tag containing '%' should not act as a SQL wildcard."""
        memory.remember_domain("a.com", tags="100%")
        memory.remember_domain("b.com", tags="other")
        results = memory.tag_search("100%")
        assert len(results) == 1
        assert results[0]["domain"] == "a.com"

    def test_sql_wildcard_underscore_escaped(self, memory):
        """A tag containing '_' should not match single characters."""
        memory.remember_domain("a.com", tags="test_tag")
        memory.remember_domain("b.com", tags="testXtag")
        results = memory.tag_search("test_tag")
        assert len(results) == 1
        assert results[0]["domain"] == "a.com"


class TestPreferences:
    """Preference get/set with defaults."""

    def test_default_when_unset(self, memory):
        assert memory.get_preference("missing", "fallback") == "fallback"

    def test_default_empty_string(self, memory):
        assert memory.get_preference("missing") == ""

    def test_set_and_get(self, memory):
        memory.set_preference("theme", "dark")
        assert memory.get_preference("theme") == "dark"

    def test_overwrite_preference(self, memory):
        memory.set_preference("mode", "beginner")
        memory.set_preference("mode", "expert")
        assert memory.get_preference("mode") == "expert"

    def test_multiple_independent_preferences(self, memory):
        memory.set_preference("key1", "val1")
        memory.set_preference("key2", "val2")
        assert memory.get_preference("key1") == "val1"
        assert memory.get_preference("key2") == "val2"
