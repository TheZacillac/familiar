"""Test 11: Tool inventory completeness and integrity.

Verifies that ALL_TOOLS exports the expected number of tools, has no
duplicates, and every entry is a callable LangChain tool with a name.
"""

import pytest

from familiar.tools import (
    ALL_TOOLS,
    ADVISOR_TOOLS,
    COMPOSITE_ADVISOR_TOOLS,
    MEMORY_TOOLS,
    PENTEST_TOOLS,
    SEER_TOOLS,
    TOME_TOOLS,
    WORKFLOW_TOOLS,
)


class TestToolListIntegrity:
    """ALL_TOOLS must contain every tool group with no duplicates."""

    def test_all_tools_is_nonempty(self):
        assert len(ALL_TOOLS) > 0

    def test_all_tools_is_sum_of_groups(self):
        expected = (
            len(SEER_TOOLS)
            + len(TOME_TOOLS)
            + len(ADVISOR_TOOLS)
            + len(COMPOSITE_ADVISOR_TOOLS)
            + len(PENTEST_TOOLS)
            + len(MEMORY_TOOLS)
            + len(WORKFLOW_TOOLS)
        )
        assert len(ALL_TOOLS) == expected

    def test_no_duplicate_tools(self):
        names = [t.name for t in ALL_TOOLS]
        assert len(names) == len(set(names)), f"Duplicate tool names: {[n for n in names if names.count(n) > 1]}"

    def test_every_tool_has_name(self):
        for t in ALL_TOOLS:
            assert hasattr(t, "name"), f"Tool missing name: {t}"
            assert isinstance(t.name, str)
            assert len(t.name) > 0


class TestToolGroupCounts:
    """Verify each tool group has the expected number of tools."""

    def test_seer_tools_count(self):
        assert len(SEER_TOOLS) == 20

    def test_tome_tools_count(self):
        assert len(TOME_TOOLS) == 9

    def test_advisor_tools_count(self):
        assert len(ADVISOR_TOOLS) == 6

    def test_composite_advisor_tools_count(self):
        assert len(COMPOSITE_ADVISOR_TOOLS) == 6

    def test_pentest_tools_count(self):
        assert len(PENTEST_TOOLS) == 7

    def test_memory_tools_count(self):
        assert len(MEMORY_TOOLS) == 9

    def test_workflow_tools_count(self):
        assert len(WORKFLOW_TOOLS) == 4


class TestToolCallability:
    """Every tool must be callable (LangChain @tool decorator creates StructuredTool)."""

    def test_all_tools_invocable(self):
        for t in ALL_TOOLS:
            assert hasattr(t, "invoke"), f"Tool not invocable: {t.name}"

    def test_all_tools_have_description(self):
        for t in ALL_TOOLS:
            desc = getattr(t, "description", None)
            assert desc and len(desc) > 10, f"Tool {t.name} missing or short description"


class TestExpectedToolNames:
    """Spot-check that key tools are present in ALL_TOOLS."""

    @pytest.mark.parametrize("expected_name", [
        "seer_lookup",
        "seer_whois",
        "seer_dig",
        "seer_bulk_lookup",
        "tome_tld_lookup",
        "tome_glossary_search",
        "appraise_domain",
        "security_audit",
        "subdomain_takeover_scan",
        "exposure_report",
        "remember_domain",
        "watchlist_check",
        "create_report",
        "compare_domains",
    ])
    def test_tool_present(self, expected_name):
        names = {t.name for t in ALL_TOOLS}
        assert expected_name in names
