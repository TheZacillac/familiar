"""Tests for CLI handler functions: _handle_slash, _handle_teach, _handle_export, _startup_check.

Covers slash command dispatch, explanation mode toggling, response export,
watchlist startup checks, and _tool_status edge cases.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from familiar.cli import (
    SLASH_COMMANDS,
    _handle_export,
    _handle_slash,
    _handle_teach,
    _startup_check,
    _tool_status,
)


# ---------------------------------------------------------------------------
# _handle_slash
# ---------------------------------------------------------------------------

class TestHandleSlash:
    """Slash command dispatch logic."""

    def _make_agent_and_config(self):
        agent = MagicMock()
        config = {"configurable": {"thread_id": "test-thread"}}
        return agent, config

    @patch("familiar.cli._invoke_agent")
    def test_known_command_with_args(self, mock_invoke):
        """Known command '/assess example.com' returns True and invokes agent."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/assess example.com", agent, config)
        assert result is True
        mock_invoke.assert_called_once()
        call_args = mock_invoke.call_args
        # The expanded prompt should contain "example.com"
        assert "example.com" in call_args[0][1]

    @patch("familiar.cli._invoke_agent")
    def test_known_command_no_args_needed(self, mock_invoke):
        """/check does not require args and should invoke agent."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/check", agent, config)
        assert result is True
        mock_invoke.assert_called_once()

    @patch("familiar.cli._invoke_agent")
    @patch("familiar.cli.console")
    def test_command_needs_args_but_none_given(self, mock_console, mock_invoke):
        """/assess with no args prints usage and returns True without invoking."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/assess", agent, config)
        assert result is True
        mock_invoke.assert_not_called()
        mock_console.print.assert_called_once()
        printed = mock_console.print.call_args[0][0]
        assert "Usage" in printed or "usage" in printed.lower()

    @patch("familiar.cli._invoke_agent")
    def test_unknown_command_returns_false(self, mock_invoke):
        """/bogus is not in SLASH_COMMANDS or special handlers."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/bogus", agent, config)
        assert result is False
        mock_invoke.assert_not_called()

    @patch("familiar.cli._show_help")
    def test_help_command(self, mock_help):
        """/help calls _show_help and returns True."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/help", agent, config)
        assert result is True
        mock_help.assert_called_once()

    @patch("familiar.cli._handle_export")
    def test_export_command(self, mock_export):
        """/export dispatches to _handle_export."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/export report.md", agent, config)
        assert result is True
        mock_export.assert_called_once_with("report.md")

    @patch("familiar.cli._handle_teach")
    def test_teach_command(self, mock_teach):
        """/teach on dispatches to _handle_teach."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/teach on", agent, config)
        assert result is True
        mock_teach.assert_called_once_with("on")

    @patch("familiar.cli._invoke_agent")
    def test_extra_whitespace_handled(self, mock_invoke):
        """Leading/trailing/extra whitespace should not break dispatch."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("  /assess  example.com  ", agent, config)
        assert result is True
        mock_invoke.assert_called_once()
        prompt = mock_invoke.call_args[0][1]
        assert "example.com" in prompt

    @patch("familiar.cli._invoke_agent")
    def test_mixed_case_lowercased(self, mock_invoke):
        """Commands are case-insensitive (lowercased before lookup)."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/ASSESS example.com", agent, config)
        assert result is True
        mock_invoke.assert_called_once()

    @patch("familiar.cli._invoke_agent")
    def test_template_expansion(self, mock_invoke):
        """Verify {args} placeholder is replaced with the actual arguments."""
        agent, config = self._make_agent_and_config()
        _handle_slash("/watch mydomain.io", agent, config)
        prompt = mock_invoke.call_args[0][1]
        # The template for /watch contains {args} which should be replaced
        assert "{args}" not in prompt
        assert "mydomain.io" in prompt


# ---------------------------------------------------------------------------
# _handle_teach
# ---------------------------------------------------------------------------

class TestHandleTeach:
    """Explanation mode toggle."""

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_on_sets_true(self, mock_get_mem, mock_console):
        mem = MagicMock()
        mock_get_mem.return_value = mem
        _handle_teach("on")
        mem.set_preference.assert_called_once_with("explanation_mode", "true")

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_off_sets_false(self, mock_get_mem, mock_console):
        mem = MagicMock()
        mock_get_mem.return_value = mem
        _handle_teach("off")
        mem.set_preference.assert_called_once_with("explanation_mode", "false")

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_yes_and_1_set_true(self, mock_get_mem, mock_console):
        """'yes' and '1' are aliases for enabling explanation mode."""
        for arg in ("yes", "1"):
            mem = MagicMock()
            mock_get_mem.return_value = mem
            _handle_teach(arg)
            mem.set_preference.assert_called_once_with("explanation_mode", "true")

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_empty_reads_status(self, mock_get_mem, mock_console):
        """Empty string reads current status without setting."""
        mem = MagicMock()
        mem.get_preference.return_value = "false"
        mock_get_mem.return_value = mem
        _handle_teach("")
        mem.set_preference.assert_not_called()
        mem.get_preference.assert_called_once_with("explanation_mode", "false")

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_garbage_reads_status(self, mock_get_mem, mock_console):
        """Unrecognized argument shows current status instead of toggling."""
        mem = MagicMock()
        mem.get_preference.return_value = "true"
        mock_get_mem.return_value = mem
        _handle_teach("garbage")
        mem.set_preference.assert_not_called()
        mem.get_preference.assert_called_once()


# ---------------------------------------------------------------------------
# _handle_export
# ---------------------------------------------------------------------------

class TestHandleExport:
    """Last-response export to file."""

    @patch("familiar.cli.console")
    def test_no_last_response(self, mock_console):
        """When no response has been generated, prints a warning."""
        import familiar.cli as cli_mod

        original = cli_mod._last_response
        try:
            cli_mod._last_response = None
            _handle_export("")
            printed = mock_console.print.call_args[0][0]
            assert "No response" in printed or "no response" in printed.lower()
        finally:
            cli_mod._last_response = original

    @patch("familiar.cli.console")
    def test_default_filename(self, mock_console, tmp_path):
        """With a last response and no custom path, writes to default filename."""
        import familiar.cli as cli_mod
        import os

        original = cli_mod._last_response
        original_cwd = os.getcwd()
        try:
            cli_mod._last_response = "# Test Report\nSome content here."
            os.chdir(tmp_path)
            _handle_export("")
            # Find the exported file
            exported = list(tmp_path.glob("familiar-export-*.md"))
            assert len(exported) == 1
            assert exported[0].read_text(encoding="utf-8") == "# Test Report\nSome content here."
        finally:
            cli_mod._last_response = original
            os.chdir(original_cwd)

    @patch("familiar.cli.console")
    def test_custom_path(self, mock_console, tmp_path):
        """With a custom path, writes to that specific file."""
        import familiar.cli as cli_mod

        original = cli_mod._last_response
        try:
            cli_mod._last_response = "Custom export content."
            target = tmp_path / "my-report.md"
            _handle_export(str(target))
            assert target.exists()
            assert target.read_text(encoding="utf-8") == "Custom export content."
        finally:
            cli_mod._last_response = original

    @patch("familiar.cli.console")
    def test_invalid_path_handled(self, mock_console):
        """An invalid/unwritable path should print an error, not raise."""
        import familiar.cli as cli_mod

        original = cli_mod._last_response
        try:
            cli_mod._last_response = "Some content."
            # /dev/null/impossible is not a writable directory
            _handle_export("/dev/null/impossible/file.md")
            printed = mock_console.print.call_args[0][0]
            assert "failed" in printed.lower() or "error" in printed.lower()
        finally:
            cli_mod._last_response = original

    @patch("familiar.cli.console")
    def test_nested_directory_created(self, mock_console, tmp_path):
        """Export to a nested path should create intermediate directories."""
        import familiar.cli as cli_mod

        original = cli_mod._last_response
        try:
            cli_mod._last_response = "Nested content."
            target = tmp_path / "deep" / "nested" / "report.md"
            _handle_export(str(target))
            assert target.exists()
            assert target.read_text(encoding="utf-8") == "Nested content."
        finally:
            cli_mod._last_response = original


# ---------------------------------------------------------------------------
# _startup_check
# ---------------------------------------------------------------------------

class TestStartupCheck:
    """Watchlist status display on startup."""

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_empty_watchlist(self, mock_get_mem, mock_console):
        """Empty watchlist produces no output."""
        mem = MagicMock()
        mem.watchlist_list.return_value = []
        mock_get_mem.return_value = mem
        _startup_check()
        mock_console.print.assert_not_called()

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_never_checked_shows_need_checking(self, mock_get_mem, mock_console):
        """Domains that have never been checked should trigger 'need checking'."""
        mem = MagicMock()
        mem.watchlist_list.return_value = [
            {"domain": "a.com", "added": "2025-01-01", "last_checked": None},
            {"domain": "b.com", "added": "2025-01-01", "last_checked": None},
        ]
        mock_get_mem.return_value = mem
        _startup_check()
        mock_console.print.assert_called_once()
        output = mock_console.print.call_args[0][0]
        assert "2 domain" in output
        assert "checking" in output.lower()

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_recently_checked_shows_count_only(self, mock_get_mem, mock_console):
        """Domains checked recently should show count without 'need checking'."""
        now = datetime.now(timezone.utc).isoformat()
        mem = MagicMock()
        mem.watchlist_list.return_value = [
            {"domain": "a.com", "added": "2025-01-01", "last_checked": now},
            {"domain": "b.com", "added": "2025-01-01", "last_checked": now},
        ]
        mock_get_mem.return_value = mem
        _startup_check()
        mock_console.print.assert_called_once()
        output = mock_console.print.call_args[0][0]
        assert "2 domain" in output
        assert "checking" not in output.lower()

    @patch("familiar.cli.console")
    @patch("familiar.cli.get_memory")
    def test_exception_returns_silently(self, mock_get_mem, mock_console):
        """If memory access raises, _startup_check returns without crashing."""
        mock_get_mem.side_effect = RuntimeError("DB broken")
        _startup_check()
        mock_console.print.assert_not_called()


# ---------------------------------------------------------------------------
# _tool_status edge cases
# ---------------------------------------------------------------------------

class TestToolStatusEdgeCases:
    """Additional edge cases for _tool_status."""

    def test_domains_list_more_than_3(self):
        """A 'domains' list with >3 items shows first 3 and '+N more'."""
        result = _tool_status(
            "seer_bulk_lookup",
            {"domains": ["a.com", "b.com", "c.com", "d.com", "e.com"]},
        )
        assert "a.com" in result
        assert "b.com" in result
        assert "c.com" in result
        assert "+2 more" in result
        assert "d.com" not in result

    def test_domains_list_exactly_3(self):
        """A 'domains' list with exactly 3 items shows all without '+N more'."""
        result = _tool_status(
            "seer_bulk_lookup",
            {"domains": ["a.com", "b.com", "c.com"]},
        )
        assert "a.com" in result
        assert "b.com" in result
        assert "c.com" in result
        assert "more" not in result

    def test_long_domain_value_ignored(self):
        """A domain value >= 80 chars is not used as the target."""
        long_val = "x" * 80
        result = _tool_status("seer_lookup", {"domain": long_val})
        assert long_val not in result

    def test_empty_domains_list(self):
        """An empty 'domains' list should not crash."""
        result = _tool_status("seer_bulk_lookup", {"domains": []})
        assert isinstance(result, str)
        assert len(result) > 0
