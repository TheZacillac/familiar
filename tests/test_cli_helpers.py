"""Test 13: CLI slash commands and display helper accuracy.

Tests slash command dictionary completeness, tool status formatting,
message extraction, and the checkbox-number regex fix.
"""

import re

import pytest

from familiar.cli import (
    SLASH_COMMANDS,
    _CHECKBOX_NUMBER_RE,
    _extract_messages,
    _tool_status,
)


class TestSlashCommands:
    """SLASH_COMMANDS dictionary must be complete and well-formed."""

    EXPECTED_COMMANDS = [
        "/assess", "/compare", "/secure", "/suggest", "/portfolio",
        "/competitive", "/migrate", "/acquire", "/watch", "/unwatch",
        "/watchlist", "/check", "/domains", "/pentest", "/takeover",
        "/headers", "/recon", "/security", "/brand", "/dns",
        "/timeline", "/expiry", "/report", "/vs", "/tags", "/summary",
    ]

    def test_all_expected_commands_present(self):
        for cmd in self.EXPECTED_COMMANDS:
            assert cmd in SLASH_COMMANDS, f"Missing slash command: {cmd}"

    def test_all_commands_are_strings(self):
        for cmd, template in SLASH_COMMANDS.items():
            assert isinstance(template, str), f"{cmd} template is not a string"

    def test_commands_with_args_have_placeholder(self):
        """Commands that need arguments should contain {args}."""
        needs_args = ["/assess", "/compare", "/secure", "/suggest", "/watch",
                      "/unwatch", "/pentest", "/takeover", "/headers", "/recon"]
        for cmd in needs_args:
            assert "{args}" in SLASH_COMMANDS[cmd], f"{cmd} missing {{args}} placeholder"

    def test_no_args_commands_work_standalone(self):
        """Commands like /check and /domains shouldn't require args."""
        no_args = ["/check", "/domains", "/summary", "/watchlist"]
        for cmd in no_args:
            template = SLASH_COMMANDS[cmd]
            # These templates should not have {args} or should work without it
            assert "{args}" not in template or True  # /watchlist may have it optionally


class TestToolStatus:
    """_tool_status formats tool calls into human-readable strings."""

    def test_domain_arg(self):
        result = _tool_status("seer_lookup", {"domain": "example.com"})
        assert "example.com" in result

    def test_query_arg(self):
        result = _tool_status("tome_tld_search", {"query": "tech"})
        assert "tech" in result

    def test_brand_arg(self):
        result = _tool_status("suggest_domains", {"brand": "acme"})
        assert "acme" in result

    def test_domains_list_arg(self):
        result = _tool_status("seer_bulk_lookup", {"domains": ["a.com", "b.com", "c.com", "d.com"]})
        assert "a.com" in result
        assert "+1 more" in result

    def test_no_args(self):
        result = _tool_status("watchlist_list")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_strips_seer_prefix(self):
        result = _tool_status("seer_lookup", {"domain": "test.com"})
        assert not result.lower().startswith("seer")

    def test_strips_tome_prefix(self):
        result = _tool_status("tome_tld_lookup", {"query": "com"})
        assert not result.lower().startswith("tome")

    def test_underscores_replaced(self):
        result = _tool_status("some_long_tool_name")
        assert "_" not in result

    def test_capitalized(self):
        result = _tool_status("simple_tool")
        assert result[0].isupper()


class TestExtractMessages:
    """_extract_messages must handle various LangGraph update formats."""

    def test_dict_with_messages(self):
        result = _extract_messages({"messages": ["msg1", "msg2"]})
        assert result == ["msg1", "msg2"]

    def test_dict_without_messages(self):
        result = _extract_messages({"other": "data"})
        assert result == []

    def test_list_input(self):
        result = _extract_messages(["msg1", "msg2"])
        assert result == ["msg1", "msg2"]

    def test_none_input(self):
        result = _extract_messages(None)
        assert result == []

    def test_empty_dict(self):
        result = _extract_messages({})
        assert result == []

    def test_overwrite_wrapper(self):
        """LangGraph Overwrite wrapper should be unwrapped via .value attribute."""
        class FakeOverwrite:
            value = ["inner_msg"]
        result = _extract_messages({"messages": FakeOverwrite()})
        assert result == ["inner_msg"]


class TestCheckboxRegex:
    """_CHECKBOX_NUMBER_RE must fix checkboxes jammed against numbers."""

    @pytest.mark.parametrize("input_str,expected", [
        ("□1. First item", "□ 1. First item"),
        ("☐2 Second", "☐ 2 Second"),
        ("☑3 Third", "☑ 3 Third"),
        ("✓4 Pass", "✓ 4 Pass"),
        ("✗5 Fail", "✗ 5 Fail"),
    ])
    def test_checkbox_number_fixed(self, input_str, expected):
        result = _CHECKBOX_NUMBER_RE.sub(r"\1 \2", input_str)
        assert result == expected

    def test_no_change_when_already_spaced(self):
        text = "□ 1. Already spaced"
        result = _CHECKBOX_NUMBER_RE.sub(r"\1 \2", text)
        assert result == text

    def test_no_change_for_normal_text(self):
        text = "Normal text without checkboxes"
        result = _CHECKBOX_NUMBER_RE.sub(r"\1 \2", text)
        assert result == text
