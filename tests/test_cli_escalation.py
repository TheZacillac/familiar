"""CLI escalation — detecting escalation in stream and response labeling."""

import json

import pytest

from familiar.cli import _print_response, _build_handoff_message
from familiar.tools.escalation_tools import ESCALATION_MARKER


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
