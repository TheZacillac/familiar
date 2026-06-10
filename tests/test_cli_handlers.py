"""Tests for CLI handlers: _handle_slash dispatch plus the cli_common
engine-agnostic handlers (handle_teach, export_last_response, startup_check).

Covers slash command dispatch, explanation mode toggling, response export,
watchlist startup checks, and tool_status edge cases.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from familiar.cli import _handle_slash
from familiar.cli_common import (
    SLASH_COMMANDS,
    export_last_response,
    handle_teach,
    startup_check,
    tool_status,
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

    @patch("familiar.cli.show_help")
    def test_help_command(self, mock_help):
        """/help calls show_help and returns True."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/help", agent, config)
        assert result is True
        mock_help.assert_called_once()

    @patch("familiar.cli.export_last_response")
    def test_export_command(self, mock_export):
        """/export dispatches to export_last_response with the filename arg."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/export report.md", agent, config)
        assert result is True
        mock_export.assert_called_once()
        assert mock_export.call_args[0][2] == "report.md"

    @patch("familiar.cli.handle_teach")
    def test_teach_command(self, mock_teach):
        """/teach on dispatches to handle_teach with the toggle arg."""
        agent, config = self._make_agent_and_config()
        result = _handle_slash("/teach on", agent, config)
        assert result is True
        mock_teach.assert_called_once()
        assert mock_teach.call_args[0][1] == "on"

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
# handle_teach
# ---------------------------------------------------------------------------

class TestHandleTeach:
    """Explanation mode toggle."""

    @patch("familiar.cli_common.get_memory")
    def test_on_sets_true(self, mock_get_mem):
        mem = MagicMock()
        mock_get_mem.return_value = mem
        handle_teach(MagicMock(), "on")
        mem.set_preference.assert_called_once_with("explanation_mode", "true")

    @patch("familiar.cli_common.get_memory")
    def test_off_sets_false(self, mock_get_mem):
        mem = MagicMock()
        mock_get_mem.return_value = mem
        handle_teach(MagicMock(), "off")
        mem.set_preference.assert_called_once_with("explanation_mode", "false")

    @patch("familiar.cli_common.get_memory")
    def test_yes_and_1_set_true(self, mock_get_mem):
        """'yes' and '1' are aliases for enabling explanation mode."""
        for arg in ("yes", "1"):
            mem = MagicMock()
            mock_get_mem.return_value = mem
            handle_teach(MagicMock(), arg)
            mem.set_preference.assert_called_once_with("explanation_mode", "true")

    @patch("familiar.cli_common.get_memory")
    def test_empty_reads_status(self, mock_get_mem):
        """Empty string reads current status without setting."""
        mem = MagicMock()
        mem.get_preference.return_value = "false"
        mock_get_mem.return_value = mem
        handle_teach(MagicMock(), "")
        mem.set_preference.assert_not_called()
        mem.get_preference.assert_called_once_with("explanation_mode", "false")

    @patch("familiar.cli_common.get_memory")
    def test_garbage_reads_status(self, mock_get_mem):
        """Unrecognized argument shows current status instead of toggling."""
        mem = MagicMock()
        mem.get_preference.return_value = "true"
        mock_get_mem.return_value = mem
        handle_teach(MagicMock(), "garbage")
        mem.set_preference.assert_not_called()
        mem.get_preference.assert_called_once()


# ---------------------------------------------------------------------------
# export_last_response
# ---------------------------------------------------------------------------

class TestExportLastResponse:
    """Last-response export to file."""

    def test_no_last_response(self):
        """When no response has been generated, prints a warning."""
        console = MagicMock()
        export_last_response(console, None, "")
        printed = console.print.call_args[0][0]
        assert "No response" in printed or "no response" in printed.lower()

    def test_default_filename(self, tmp_path, monkeypatch):
        """With a last response and no custom path, writes to export_dir."""
        from familiar import config

        monkeypatch.setattr(config, "export_dir", lambda: tmp_path)
        export_last_response(MagicMock(), "# Test Report\nSome content here.", "")
        exported = list(tmp_path.glob("familiar-export-*.md"))
        assert len(exported) == 1
        assert exported[0].read_text(encoding="utf-8") == "# Test Report\nSome content here."

    def test_custom_filename(self, tmp_path, monkeypatch):
        """With a custom filename, writes to export_dir with that name."""
        from familiar import config

        monkeypatch.setattr(config, "export_dir", lambda: tmp_path)
        export_last_response(MagicMock(), "Custom export content.", "my-report.md")
        target = tmp_path / "my-report.md"
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "Custom export content."

    def test_path_components_stripped(self, tmp_path, monkeypatch):
        """Directory components are stripped — only filename is used."""
        from familiar import config

        monkeypatch.setattr(config, "export_dir", lambda: tmp_path)
        export_last_response(MagicMock(), "Some content.", "/some/deep/path/file.md")
        # Should write to export_dir/file.md, not /some/deep/path/file.md
        assert (tmp_path / "file.md").exists()
        assert (tmp_path / "file.md").read_text(encoding="utf-8") == "Some content."

    def test_unwritable_dir_handled(self, monkeypatch):
        """An unwritable export directory should print an error, not raise."""
        from pathlib import Path

        from familiar import config

        console = MagicMock()
        # Point export_dir to a path that can't be written to
        monkeypatch.setattr(config, "export_dir", lambda: Path("/dev/null/impossible"))
        export_last_response(console, "Some content.", "report.md")
        printed = console.print.call_args[0][0]
        assert "failed" in printed.lower() or "error" in printed.lower()


# ---------------------------------------------------------------------------
# startup_check
# ---------------------------------------------------------------------------

class TestStartupCheck:
    """Watchlist status display on startup."""

    @patch("familiar.cli_common.get_memory")
    def test_empty_watchlist(self, mock_get_mem):
        """Empty watchlist produces no output."""
        console = MagicMock()
        mem = MagicMock()
        mem.watchlist_list.return_value = []
        mock_get_mem.return_value = mem
        startup_check(console)
        console.print.assert_not_called()

    @patch("familiar.cli_common.get_memory")
    def test_never_checked_shows_need_checking(self, mock_get_mem):
        """Domains that have never been checked should trigger 'need checking'."""
        console = MagicMock()
        mem = MagicMock()
        mem.watchlist_list.return_value = [
            {"domain": "a.com", "added": "2025-01-01", "last_checked": None},
            {"domain": "b.com", "added": "2025-01-01", "last_checked": None},
        ]
        mock_get_mem.return_value = mem
        startup_check(console)
        console.print.assert_called_once()
        output = console.print.call_args[0][0]
        assert "2 domain" in output
        assert "checking" in output.lower()

    @patch("familiar.cli_common.get_memory")
    def test_recently_checked_shows_count_only(self, mock_get_mem):
        """Domains checked recently should show count without 'need checking'."""
        console = MagicMock()
        now = datetime.now(timezone.utc).isoformat()
        mem = MagicMock()
        mem.watchlist_list.return_value = [
            {"domain": "a.com", "added": "2025-01-01", "last_checked": now},
            {"domain": "b.com", "added": "2025-01-01", "last_checked": now},
        ]
        mock_get_mem.return_value = mem
        startup_check(console)
        console.print.assert_called_once()
        output = console.print.call_args[0][0]
        assert "2 domain" in output
        assert "checking" not in output.lower()

    @patch("familiar.cli_common.get_memory")
    def test_exception_prints_warning(self, mock_get_mem):
        """If memory access raises, startup_check warns instead of crashing.

        Failure visibility is deliberate (audit batch 0b312ce) — a broken DB
        should be surfaced at startup, not hidden.
        """
        console = MagicMock()
        mock_get_mem.side_effect = RuntimeError("DB broken")
        startup_check(console)  # must not raise
        console.print.assert_called_once()
        output = console.print.call_args[0][0]
        assert "failed" in output.lower()


# ---------------------------------------------------------------------------
# tool_status edge cases
# ---------------------------------------------------------------------------

class TestToolStatusEdgeCases:
    """Additional edge cases for tool_status."""

    def test_domains_list_more_than_3(self):
        """A 'domains' list with >3 items shows first 3 and '+N more'."""
        result = tool_status(
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
        result = tool_status(
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
        result = tool_status("seer_lookup", {"domain": long_val})
        assert long_val not in result

    def test_empty_domains_list(self):
        """An empty 'domains' list should not crash."""
        result = tool_status("seer_bulk_lookup", {"domains": []})
        assert isinstance(result, str)
        assert len(result) > 0
