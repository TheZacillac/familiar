# Dynamic Model Escalation

**Date:** 2026-04-02
**Status:** Approved

## Summary

Add a two-tier model system where Familiar starts with a small/fast model and can self-escalate to a larger/more capable model when the task exceeds its abilities. The fast model calls an `escalate` tool with a structured handoff; the system intercepts this, builds a power agent, and re-invokes with the handoff context. The power model's response goes directly to the user.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Escalation trigger | Agent self-assessment | The small model decides when it's out of its depth, most elegant pattern |
| Model hierarchy | Two-tier (fast + power) | Explicit naming, self-documenting config, no recursive escalation risk |
| Handoff format | Structured summary | Small model writes reason + context summary; avoids polluting big model with confused reasoning, avoids wasting the small model's assessment |
| User visibility | Transparent | Spinner shows "Escalating to power model...", response panel tagged with "(power)" |
| Power model escalation | Terminal | Power model never gets the escalate tool, hard stop at two tiers |
| Implementation approach | Tool-triggered re-invocation | Power model response goes directly to user, no round-trip through fast model |

## Configuration

New keys in `config.toml` under `[model]`:

```toml
[model]
fast = "ollama:gemma4:e4b"      # small/efficient first-attempt
power = "ollama:gemma4:31b"     # bigger model for escalation
```

- If `fast` is not set, `default` is used as the fast model (backward compatible). If neither `fast` nor `default` is set, falls through to the hardcoded default (`ollama:nemotron-3-nano:latest`).
- If `power` is not set, escalation is disabled — the `escalate` tool returns a message saying no power model is configured. The tool is still registered so the system prompt is always accurate.

New config helpers:
- `fast_model_id() -> str` — returns `model.fast`, falls back to `model.default`
- `power_model_id() -> str | None` — returns `model.power` or `None`
- `model_kwargs(model_id: str) -> dict` — parameterized version of existing helper

## Escalate Tool

New file: `tools/escalation_tools.py`

```python
@tool
def escalate(reason: str, summary: str) -> str:
```

- `reason`: why the model is escalating (e.g., "complex multi-domain security analysis")
- `summary`: structured handoff — user's original intent, what was learned, what power model should focus on
- The tool is a **sentinel** — returns a marker string. Actual escalation logic lives in the stream handler.

### System Prompt Addition

The fast model's system prompt includes guidance on when to escalate:

> You have access to an `escalate` tool. Use it when a task exceeds your capabilities — for example, complex multi-domain analysis, nuanced security assessments requiring careful cross-referencing, detailed advisory opinions, or any task where you're uncertain about the quality of your answer. When in doubt, escalate. It's better to hand off than to give a weak answer.

## Stream Interception Flow

Handled in `cli.py`'s `_stream_invoke`:

1. Fast model streams normally (tool calls, status updates)
2. Stream handler watches for `escalate` tool calls
3. On detection: capture `reason` and `summary`, abandon fast model stream
4. Spinner updates to "Escalating to power model..." with reason
5. Power agent built on the fly — `build_power_agent()` uses `power_model_id()`, same tools minus `escalate`, same system prompt
6. Handoff message constructed:
   ```
   [Escalated from fast model]
   Reason: {reason}

   Context from initial analysis:
   {summary}

   Original user message:
   {original_query}
   ```
7. Power model streams to completion with same UX
8. Response panel title shows "familiar (power)" instead of "familiar"

### Key Details

- Power agent is **stateless** — fresh invocation, no checkpointer, no conversation history
- The handoff message contains everything the power model needs
- Fast model remains the primary for ongoing REPL conversation
- Follow-up messages go through the fast model (which can escalate again if needed)

## File Changes

| File | Change |
|------|--------|
| `config.py` | Add `fast_model_id()`, `power_model_id()`, parameterize `model_kwargs()`. Update `DEFAULTS` with `fast`/`power` keys. |
| `config.default.toml` | Add `fast` and `power` keys under `[model]`, with comments |
| `tools/escalation_tools.py` | New file — `escalate` tool (sentinel) |
| `tools/__init__.py` | Add `escalate` to `ALL_TOOLS` |
| `agent.py` | Add `build_power_agent()`. Update `build_agent()` to use `fast_model_id()`. Add escalation guidance to system prompt. |
| `cli.py` | Modify `_stream_invoke` to detect escalation and re-invoke with power agent. Update `_print_response` to accept model tier label. |

No new dependencies. No changes to memory, seer tools, tome tools, or existing tool behavior.
