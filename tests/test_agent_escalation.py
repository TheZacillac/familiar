"""Agent escalation — system prompt and power agent builder."""

import pytest

from familiar.agent import SYSTEM_PROMPT, _build_system_prompt


class TestEscalationPrompt:
    """System prompt must include escalation guidance."""

    def test_prompt_mentions_escalate_tool(self):
        assert "escalate" in SYSTEM_PROMPT

    def test_prompt_mentions_when_to_escalate(self):
        assert "exceeds your capabilities" in SYSTEM_PROMPT

    def test_prompt_mentions_hand_off(self):
        assert "hand off" in SYSTEM_PROMPT


class TestBuildPowerAgent:
    """build_power_agent constructs an agent without the escalate tool."""

    def test_importable(self):
        from familiar.agent import build_power_agent
        assert callable(build_power_agent)
