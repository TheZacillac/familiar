"""Test 11: Tool inventory completeness and integrity.

Verifies that ALL_TOOLS exports the expected number of tools, has no
duplicates, every entry is a callable LangChain tool with a name, and
that CLAUDE.md stays in sync with the actual tool surface.
"""

from pathlib import Path

import pytest

from familiar.tools import (
    ALL_TOOLS,
    ADVISOR_TOOLS,
    COMPOSITE_ADVISOR_TOOLS,
    ESCALATION_TOOLS,
    MEMORY_TOOLS,
    PENTEST_TOOLS,
    SECURITY_TOOLS,
    SEER_TOOLS,
    SNAPSHOT_TOOLS,
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
            + len(SECURITY_TOOLS)
            + len(MEMORY_TOOLS)
            + len(WORKFLOW_TOOLS)
            + len(SNAPSHOT_TOOLS)
            + len(ESCALATION_TOOLS)
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
        assert len(SEER_TOOLS) == 25

    def test_tome_tools_count(self):
        assert len(TOME_TOOLS) == 10

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

    def test_escalation_tools_count(self):
        assert len(ESCALATION_TOOLS) == 1


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
        "escalate",
    ])
    def test_tool_present(self, expected_name):
        names = {t.name for t in ALL_TOOLS}
        assert expected_name in names


class TestClaudeMdSync:
    """CLAUDE.md must stay aligned with the actual tool surface.

    Drift between docs and code silently misleads future maintainers
    (and the LLM). These tests fail loudly so adding/removing a tool
    forces a CLAUDE.md update in the same commit.
    """

    @pytest.fixture
    def claude_md(self) -> str:
        path = Path(__file__).resolve().parent.parent / "CLAUDE.md"
        return path.read_text()

    def test_total_count_line_matches(self, claude_md):
        expected = f"## Tools ({len(ALL_TOOLS)} total)"
        assert expected in claude_md, (
            f"CLAUDE.md tool count is out of date — expected line {expected!r} "
            f"(ALL_TOOLS now has {len(ALL_TOOLS)} entries)."
        )

    def test_every_tool_name_appears_in_claude_md(self, claude_md):
        missing = [t.name for t in ALL_TOOLS if f"`{t.name}`" not in claude_md]
        assert not missing, (
            f"{len(missing)} tool(s) missing from CLAUDE.md tool listing: {missing}"
        )
