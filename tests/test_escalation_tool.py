"""Escalation tool — sentinel that signals model escalation."""

import json

import pytest

from familiar.tools.escalation_tools import ESCALATION_TOOLS, escalate


ESCALATION_MARKER = "__ESCALATION_REQUESTED__"


class TestEscalateTool:
    """The escalate tool returns a sentinel marker."""

    def test_returns_marker(self):
        result = escalate.invoke({
            "reason": "complex analysis",
            "summary": "User wants a deep security audit of example.com",
        })
        parsed = json.loads(result)
        assert parsed["status"] == ESCALATION_MARKER

    def test_echoes_reason(self):
        result = escalate.invoke({
            "reason": "too complex",
            "summary": "some context",
        })
        parsed = json.loads(result)
        assert parsed["reason"] == "too complex"

    def test_echoes_summary(self):
        result = escalate.invoke({
            "reason": "need help",
            "summary": "detailed handoff context",
        })
        parsed = json.loads(result)
        assert parsed["summary"] == "detailed handoff context"

    def test_has_name(self):
        assert escalate.name == "escalate"

    def test_has_description(self):
        assert len(escalate.description) > 20


class TestEscalationToolsList:
    """ESCALATION_TOOLS exports the tool list."""

    def test_contains_escalate(self):
        names = [t.name for t in ESCALATION_TOOLS]
        assert "escalate" in names

    def test_length(self):
        assert len(ESCALATION_TOOLS) == 1
