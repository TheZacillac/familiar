"""Escalation tool — sentinel for triggering model escalation."""

import json

from langchain_core.tools import tool

ESCALATION_MARKER = "__ESCALATION_REQUESTED__"


@tool
def escalate(reason: str, summary: str) -> str:
    """Call for backup from a more capable model.

    Use this when a task exceeds your capabilities — for example, complex
    multi-domain analysis, nuanced security assessments requiring careful
    cross-referencing, detailed advisory opinions, or any task where you
    are uncertain about the quality of your answer.

    When in doubt, escalate. It is better to hand off than to give a weak answer.

    Args:
        reason: Why you are escalating (e.g., "multi-step security analysis
                requiring cross-referencing multiple tool results").
        summary: Structured handoff for the power model — include the user's
                 original intent, what you have learned so far, and what the
                 power model should focus on.
    """
    return json.dumps({
        "status": ESCALATION_MARKER,
        "reason": reason,
        "summary": summary,
    })


ESCALATION_TOOLS = [escalate]
