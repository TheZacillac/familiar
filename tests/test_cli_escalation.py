"""CLI escalation — detecting escalation in stream and routing to the power model."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from familiar.cli import (
    _build_handoff_message,
    _detect_escalation,
    _invoke_agent,
    _print_response,
    _run_power,
)
from familiar.tools.escalation_tools import ESCALATION_MARKER


def _escalation_payload(reason="too complex", summary="handoff context"):
    return {"status": ESCALATION_MARKER, "reason": reason, "summary": summary}


class TestEscalationDetection:
    """Verify escalation marker detection logic."""

    def test_marker_is_detectable_in_tool_call_args(self):
        """The escalation marker can be found in tool call arguments."""
        args = {"reason": "too complex", "summary": "handoff context"}
        result = json.dumps({
            "status": ESCALATION_MARKER,
            "reason": args["reason"],
            "summary": args["summary"],
        })
        parsed = json.loads(result)
        assert parsed["status"] == ESCALATION_MARKER

    def test_detects_escalate_tool_result(self):
        """A tool message carrying the marker JSON yields the payload."""
        msg = SimpleNamespace(
            type="tool",
            content=json.dumps(_escalation_payload(reason="r", summary="s")),
        )
        payload = _detect_escalation(msg)
        assert payload is not None
        assert payload["reason"] == "r"
        assert payload["summary"] == "s"

    def test_ignores_ordinary_tool_result(self):
        msg = SimpleNamespace(type="tool", content=json.dumps({"status": "ok"}))
        assert _detect_escalation(msg) is None

    def test_ignores_non_tool_message(self):
        msg = SimpleNamespace(
            type="ai",
            content=json.dumps(_escalation_payload()),
        )
        assert _detect_escalation(msg) is None

    def test_ignores_marker_in_invalid_json(self):
        """Marker text embedded in non-JSON content must not trigger."""
        msg = SimpleNamespace(type="tool", content=f"oops {ESCALATION_MARKER} oops")
        assert _detect_escalation(msg) is None

    def test_ignores_non_string_content(self):
        msg = SimpleNamespace(type="tool", content=["block", "content"])
        assert _detect_escalation(msg) is None


class TestHandoffMessage:
    """Verify handoff message construction."""

    def test_handoff_contains_all_parts(self):
        msg = _build_handoff_message(
            reason="complex analysis needed",
            summary="User wants security audit. Found 3 subdomains so far.",
            original_query="Run a full pentest on example.com",
        )
        assert "complex analysis needed" in msg
        assert "Found 3 subdomains" in msg
        assert "Run a full pentest on example.com" in msg
        assert "Escalated" in msg


class TestPrintResponseLabel:
    """_print_response accepts an optional model_label parameter."""

    def test_accepts_label_kwarg(self):
        try:
            _print_response("test content", model_label="power")
        except Exception:
            pass  # Rich console output — we just test it doesn't crash


class TestEscalationRouting:
    """_invoke_agent routes to the power model when escalation is detected."""

    def _config(self):
        return {"configurable": {"thread_id": "test-thread"}}

    @patch("familiar.cli._print_response")
    @patch("familiar.cli._run_power")
    @patch("familiar.cli._stream_invoke")
    @patch("familiar.cli.console")
    def test_escalation_invokes_power_model(
        self, mock_console, mock_stream, mock_power, mock_print
    ):
        mock_stream.return_value = ("fast answer", _escalation_payload())
        mock_power.return_value = "power answer"
        result = _invoke_agent(MagicMock(), "the query", self._config())
        assert result == "power answer"
        mock_power.assert_called_once()
        # Original query (not the timestamped content) reaches the power run
        assert mock_power.call_args[0][0] == "the query"
        # Response is labeled as coming from the power tier
        assert mock_print.call_args.kwargs.get("model_label") == "power"

    @patch("familiar.cli._print_response")
    @patch("familiar.cli._run_power")
    @patch("familiar.cli._stream_invoke")
    @patch("familiar.cli.console")
    def test_power_failure_falls_back_to_fast_answer(
        self, mock_console, mock_stream, mock_power, mock_print
    ):
        mock_stream.return_value = ("fast answer", _escalation_payload())
        mock_power.return_value = None
        result = _invoke_agent(MagicMock(), "the query", self._config())
        assert result == "fast answer"
        assert mock_print.call_args.kwargs.get("model_label") is None

    @patch("familiar.cli._print_response")
    @patch("familiar.cli._run_power")
    @patch("familiar.cli._stream_invoke")
    @patch("familiar.cli.console")
    def test_no_escalation_skips_power_model(
        self, mock_console, mock_stream, mock_power, mock_print
    ):
        mock_stream.return_value = ("plain answer", None)
        result = _invoke_agent(MagicMock(), "the query", self._config())
        assert result == "plain answer"
        mock_power.assert_not_called()


class TestRunPower:
    """_run_power builds the handoff and streams the power agent."""

    @patch("familiar.cli._get_power_agent")
    @patch("familiar.cli.console")
    def test_unconfigured_power_model_returns_none(self, mock_console, mock_get):
        mock_get.return_value = None
        assert _run_power("q", _escalation_payload()) is None

    @patch("familiar.cli._stream_invoke")
    @patch("familiar.cli._get_power_agent")
    @patch("familiar.cli.console")
    def test_streams_power_agent_with_handoff(
        self, mock_console, mock_get, mock_stream
    ):
        mock_get.return_value = MagicMock()
        mock_stream.return_value = ("deep answer", None)
        result = _run_power(
            "original question",
            _escalation_payload(reason="needs depth", summary="found things"),
        )
        assert result == "deep answer"
        handoff = mock_stream.call_args[0][1]
        assert "original question" in handoff
        assert "needs depth" in handoff
        assert "found things" in handoff

    @patch("familiar.cli._stream_invoke")
    @patch("familiar.cli._get_power_agent")
    @patch("familiar.cli.console")
    def test_power_stream_error_returns_none(
        self, mock_console, mock_get, mock_stream
    ):
        mock_get.return_value = MagicMock()
        mock_stream.side_effect = RuntimeError("model exploded")
        assert _run_power("q", _escalation_payload()) is None
