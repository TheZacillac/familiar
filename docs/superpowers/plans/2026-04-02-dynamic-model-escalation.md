# Dynamic Model Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-tier model system where Familiar starts with a fast model and can self-escalate to a power model via a tool-triggered re-invocation with structured handoff.

**Architecture:** The fast model runs as the main agent with an `escalate` sentinel tool. When called, `cli.py`'s stream handler intercepts the escalation, builds a fresh power agent (same tools minus `escalate`), and re-invokes with a handoff message containing the original query plus the fast model's context summary. The power model's response goes directly to the user.

**Tech Stack:** LangChain `init_chat_model`, deepagents `create_deep_agent`, existing config system (TOML + env overrides)

---

### Task 1: Config — add fast/power model helpers

**Files:**
- Modify: `src/familiar/config.py:15-49` (DEFAULTS dict)
- Modify: `src/familiar/config.py:171-185` (model_id, model_kwargs)
- Test: `tests/test_config_escalation.py`

- [ ] **Step 1: Write failing tests for new config helpers**

Create `tests/test_config_escalation.py`:

```python
"""Config helpers for two-tier model escalation."""

import pytest

from familiar import config


class TestFastModelId:
    """fast_model_id returns model.fast, falling back to model.default."""

    def test_returns_fast_when_set(self, monkeypatch):
        config.reload()
        config._cfg["model"]["fast"] = "ollama:gemma4:e4b"
        assert config.fast_model_id() == "ollama:gemma4:e4b"

    def test_falls_back_to_default(self, monkeypatch):
        config.reload()
        config._cfg["model"].pop("fast", None)
        config._cfg["model"]["default"] = "ollama:fallback:latest"
        assert config.fast_model_id() == "ollama:fallback:latest"

    def test_falls_back_to_hardcoded(self, monkeypatch):
        config.reload()
        config._cfg["model"].pop("fast", None)
        config._cfg["model"].pop("default", None)
        result = config.fast_model_id()
        assert "ollama:" in result  # hardcoded default


class TestPowerModelId:
    """power_model_id returns model.power or None."""

    def test_returns_power_when_set(self):
        config.reload()
        config._cfg["model"]["power"] = "ollama:gemma4:31b"
        assert config.power_model_id() == "ollama:gemma4:31b"

    def test_returns_none_when_not_set(self):
        config.reload()
        config._cfg["model"].pop("power", None)
        assert config.power_model_id() is None


class TestModelKwargsParameterized:
    """model_kwargs accepts an optional model_id argument."""

    def test_ollama_model_gets_base_url(self):
        config.reload()
        config._cfg["model"]["ollama"] = {"base_url": "http://test:11434"}
        kwargs = config.model_kwargs("ollama:gemma4:e4b")
        assert kwargs["base_url"] == "http://test:11434"

    def test_non_ollama_model_gets_empty(self):
        config.reload()
        kwargs = config.model_kwargs("anthropic:claude-sonnet-4-20250514")
        assert kwargs == {}

    def test_default_uses_fast_model(self):
        config.reload()
        config._cfg["model"]["fast"] = "ollama:gemma4:e4b"
        config._cfg["model"]["ollama"] = {"base_url": "http://test:11434"}
        kwargs = config.model_kwargs()
        assert kwargs["base_url"] == "http://test:11434"


class TestEnvOverrideFastPower:
    """Environment variables override fast/power config."""

    def test_familiar_model_fast_override(self, monkeypatch):
        monkeypatch.setenv("FAMILIAR_MODEL_FAST", "ollama:tiny:latest")
        config.reload()
        assert config.fast_model_id() == "ollama:tiny:latest"

    def test_familiar_model_power_override(self, monkeypatch):
        monkeypatch.setenv("FAMILIAR_MODEL_POWER", "anthropic:claude-sonnet-4-20250514")
        config.reload()
        assert config.power_model_id() == "anthropic:claude-sonnet-4-20250514"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_config_escalation.py -v`
Expected: FAIL — `fast_model_id`, `power_model_id` not defined, `model_kwargs` doesn't accept positional arg

- [ ] **Step 3: Implement config changes**

In `src/familiar/config.py`, update `DEFAULTS` to add `fast` and `power` keys:

```python
DEFAULTS = {
    "model": {
        "default": "ollama:nemotron-3-nano:latest",
        "fast": "",
        "power": "",
        "ollama": {
            "base_url": "http://localhost:11434",
        },
    },
    # ... rest unchanged
}
```

Add env override support in `_apply_env_overrides`:

```python
if val := os.environ.get("FAMILIAR_MODEL_FAST"):
    cfg.setdefault("model", {})["fast"] = val
if val := os.environ.get("FAMILIAR_MODEL_POWER"):
    cfg.setdefault("model", {})["power"] = val
```

Add new public helpers and update `model_kwargs`:

```python
def fast_model_id() -> str:
    """The fast-tier model. Falls back to model.default."""
    fast = get("model", "fast", "")
    if fast:
        return fast
    return model_id()


def power_model_id() -> str | None:
    """The power-tier model for escalation, or None if not configured."""
    power = get("model", "power", "")
    return power or None


def model_kwargs(model_id_override: str | None = None) -> dict:
    """Provider-specific kwargs derived from config.

    Args:
        model_id_override: If provided, derive kwargs for this model instead
            of the configured default.
    """
    mid = model_id_override or fast_model_id()
    kwargs = {}
    provider = mid.split(":")[0] if ":" in mid else None
    if provider == "ollama":
        base_url = get("model", key=None, default={}).get("ollama", {}).get("base_url")
        if base_url:
            kwargs["base_url"] = base_url
    return kwargs
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_config_escalation.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/familiar/config.py tests/test_config_escalation.py
git commit -m "feat: add fast/power model config helpers for escalation"
```

---

### Task 2: Config file — add fast/power keys to config.default.toml

**Files:**
- Modify: `config.default.toml:5-10`

- [ ] **Step 1: Update config.default.toml**

Replace the `[model]` section:

```toml
[model]
# Two-tier model system: "fast" handles most queries, "power" is called
# when the fast model decides it needs backup.
# Format: provider:model (e.g., ollama:gemma4:e4b, openai:gpt-4o)
fast = "ollama:gemma4:e4b"
power = "ollama:gemma4:31b"

# Fallback if "fast" is not set (backward compatible):
# default = "ollama:nemotron-3-nano:latest"
```

- [ ] **Step 2: Commit**

```bash
git add config.default.toml
git commit -m "docs: add fast/power model keys to config.default.toml"
```

---

### Task 3: Escalate tool — sentinel tool for self-escalation

**Files:**
- Create: `src/familiar/tools/escalation_tools.py`
- Test: `tests/test_escalation_tool.py`

- [ ] **Step 1: Write failing test for escalate tool**

Create `tests/test_escalation_tool.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_escalation_tool.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement escalation tool**

Create `src/familiar/tools/escalation_tools.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_escalation_tool.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/familiar/tools/escalation_tools.py tests/test_escalation_tool.py
git commit -m "feat: add escalate sentinel tool for model escalation"
```

---

### Task 4: Wire escalation tool into ALL_TOOLS

**Files:**
- Modify: `src/familiar/tools/__init__.py`
- Modify: `tests/test_tool_inventory.py`

- [ ] **Step 1: Update test_tool_inventory.py to expect the new tool**

Add `ESCALATION_TOOLS` to imports and sum, add tool name check:

In the imports, add `ESCALATION_TOOLS`, `SECURITY_TOOLS`, and `SNAPSHOT_TOOLS` (the latter two are already in `__init__.py` but missing from the test):

```python
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
```

Update `test_all_tools_is_sum_of_groups` to include all groups:

```python
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
```

Add to `TestToolGroupCounts`:

```python
def test_escalation_tools_count(self):
    assert len(ESCALATION_TOOLS) == 1
```

Add `"escalate"` to the parametrized `test_tool_present` list.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_tool_inventory.py -v`
Expected: FAIL — `ESCALATION_TOOLS` not importable from `familiar.tools`

- [ ] **Step 3: Update tools/__init__.py**

```python
"""All LangChain tools for the Familiar agent."""

from .advisor_tools import ADVISOR_TOOLS, COMPOSITE_ADVISOR_TOOLS
from .escalation_tools import ESCALATION_TOOLS
from .memory_tools import MEMORY_TOOLS, SNAPSHOT_TOOLS, WORKFLOW_TOOLS
from .pentest_tools import PENTEST_TOOLS
from .security_tools import SECURITY_TOOLS
from .seer_tools import SEER_TOOLS
from .tome_tools import TOME_TOOLS

ALL_TOOLS = (
    SEER_TOOLS
    + TOME_TOOLS
    + ADVISOR_TOOLS
    + COMPOSITE_ADVISOR_TOOLS
    + PENTEST_TOOLS
    + SECURITY_TOOLS
    + MEMORY_TOOLS
    + WORKFLOW_TOOLS
    + SNAPSHOT_TOOLS
    + ESCALATION_TOOLS
)

__all__ = [
    "ALL_TOOLS",
    "SEER_TOOLS",
    "TOME_TOOLS",
    "ADVISOR_TOOLS",
    "COMPOSITE_ADVISOR_TOOLS",
    "PENTEST_TOOLS",
    "SECURITY_TOOLS",
    "MEMORY_TOOLS",
    "WORKFLOW_TOOLS",
    "SNAPSHOT_TOOLS",
    "ESCALATION_TOOLS",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_tool_inventory.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/familiar/tools/__init__.py tests/test_tool_inventory.py
git commit -m "feat: wire escalation tool into ALL_TOOLS"
```

---

### Task 5: Agent — add escalation prompt and build_power_agent

**Files:**
- Modify: `src/familiar/agent.py:12-107` (SYSTEM_PROMPT addition)
- Modify: `src/familiar/agent.py:205-229` (build_agent, new build_power_agent)
- Test: `tests/test_agent_escalation.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_agent_escalation.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_agent_escalation.py -v`
Expected: FAIL — "escalate" not in SYSTEM_PROMPT, `build_power_agent` not importable

- [ ] **Step 3: Add escalation guidance to SYSTEM_PROMPT**

Append to the end of `SYSTEM_PROMPT` in `agent.py`, before the closing `"""`:

```python
## Model Escalation

You have access to an `escalate` tool. Use it when a task exceeds your capabilities — \
for example, complex multi-domain analysis, nuanced security assessments requiring careful \
cross-referencing of multiple tool results, detailed advisory opinions, or any task where \
you are uncertain about the quality of your answer. When in doubt, escalate — it is better \
to hand off than to give a weak answer.

When escalating, provide:
- **reason**: a concise explanation of why this task needs a more capable model
- **summary**: a structured handoff including the user's original intent, what you have \
learned so far from any tool calls, and what the power model should focus on
```

- [ ] **Step 4: Update build_agent to use fast_model_id**

In `agent.py`, update `build_agent()`:

```python
def build_agent(checkpointer=None):
    """Construct and return the LangGraph Deep Agent using the fast model."""
    _load_env()
    config.load()
    _configure_tracing()

    model = init_chat_model(
        model=config.fast_model_id(),
        **config.model_kwargs(),
    )

    agent = create_deep_agent(
        model=model,
        tools=ALL_TOOLS,
        system_prompt=_build_system_prompt(),
        checkpointer=checkpointer,
    )

    return agent
```

- [ ] **Step 5: Add build_power_agent function**

Add to `agent.py`:

```python
def build_power_agent():
    """Construct a stateless agent using the power model, without the escalate tool.

    Returns None if no power model is configured.
    """
    power_id = config.power_model_id()
    if not power_id:
        return None

    model = init_chat_model(
        model=power_id,
        **config.model_kwargs(power_id),
    )

    # All tools except escalate — power model is the terminal tier
    from .tools.escalation_tools import escalate
    power_tools = [t for t in ALL_TOOLS if t is not escalate]

    agent = create_deep_agent(
        model=model,
        tools=power_tools,
        system_prompt=_build_system_prompt(),
    )

    return agent
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_agent_escalation.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/familiar/agent.py tests/test_agent_escalation.py
git commit -m "feat: add escalation prompt and build_power_agent"
```

---

### Task 6: CLI — stream interception and power model re-invocation

**Files:**
- Modify: `src/familiar/cli.py:194-281` (_stream_invoke)
- Modify: `src/familiar/cli.py:288-300` (_print_response)
- Test: `tests/test_cli_escalation.py`

- [ ] **Step 1: Write failing tests for escalation detection**

Create `tests/test_cli_escalation.py`:

```python
"""CLI escalation — detecting escalation in stream and response labeling."""

import json

import pytest

from familiar.cli import _print_response
from familiar.tools.escalation_tools import ESCALATION_MARKER


class TestEscalationDetection:
    """Verify escalation marker detection logic."""

    def test_marker_is_detectable_in_tool_call_args(self):
        """The escalation marker can be found in tool call arguments."""
        args = {"reason": "too complex", "summary": "handoff context"}
        # Simulate what the tool returns
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
        from familiar.cli import _build_handoff_message
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
        # Should not raise — we're just testing the signature accepts it
        # (actual rendering tested manually since it writes to console)
        try:
            _print_response("test content", model_label="power")
        except Exception:
            pass  # Rich console output — we just test it doesn't crash
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_cli_escalation.py -v`
Expected: FAIL — `_build_handoff_message` not found, `_print_response` doesn't accept `model_label`

- [ ] **Step 3: Add _build_handoff_message to cli.py**

Add to `cli.py` (before `_stream_invoke`):

```python
def _build_handoff_message(reason: str, summary: str, original_query: str) -> str:
    """Construct the handoff message for the power model."""
    return (
        f"[Escalated from fast model]\n"
        f"Reason: {reason}\n\n"
        f"Context from initial analysis:\n{summary}\n\n"
        f"Original user message:\n{original_query}"
    )
```

- [ ] **Step 4: Update _print_response to accept model_label**

Update `_print_response` in `cli.py`:

```python
def _print_response(content: str, model_label: str | None = None):
    """Render agent response as markdown in a styled panel."""
    content = _CHECKBOX_NUMBER_RE.sub(r"\1 \2", content)
    md = Markdown(content)
    title = "[title]familiar[/title]"
    if model_label:
        title = f"[title]familiar[/title] [muted]({model_label})[/muted]"
    console.print(
        Panel(
            md,
            title=title,
            title_align="left",
            border_style="border",
        )
    )
```

- [ ] **Step 5: Update _stream_invoke to detect escalation and return signal**

Modify `_stream_invoke` to return escalation info when detected. Change its return type from `str | None` to `dict`:

```python
def _stream_invoke(agent, content: str, config: dict) -> dict:
    """Stream agent execution, showing tool activity on the status line.

    Returns a dict with keys:
        - "content": final AI response text (or None)
        - "escalation": dict with "reason" and "summary" if escalation
                        was requested (or None)
    """
    final_content = None
    escalation = None
    tool_count = 0

    # Pre-seed with all message IDs already in the checkpoint ...
    seen_ids: set[str] = set()
    try:
        snapshot = agent.get_state(config)
        if snapshot and snapshot.values:
            for msg in snapshot.values.get("messages", []):
                msg_id = getattr(msg, "id", None)
                if msg_id:
                    seen_ids.add(msg_id)
    except Exception:
        pass

    with console.status("[spinner]Thinking...[/spinner]", spinner="dots") as status:
        for chunk in agent.stream(
            {"messages": [{"role": "user", "content": content}]},
            config,
            stream_mode="updates",
        ):
            if not isinstance(chunk, dict):
                continue
            for _node_name, update in chunk.items():
                for msg in _extract_messages(update):
                    msg_id = getattr(msg, "id", None)
                    if msg_id:
                        if msg_id in seen_ids:
                            continue
                        seen_ids.add(msg_id)

                    # AI message with tool calls — check for escalation
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        calls = msg.tool_calls
                        tool_count += len(calls)

                        # Check if any call is an escalation
                        for tc in calls:
                            if tc["name"] == "escalate":
                                args = tc.get("args", {})
                                escalation = {
                                    "reason": args.get("reason", ""),
                                    "summary": args.get("summary", ""),
                                }
                                status.update(
                                    f"[spinner]Escalating to power model — "
                                    f"{escalation['reason']}...[/spinner]"
                                )
                                # Don't break yet — let the stream finish
                                # the tool call node so state is consistent

                        if not escalation:
                            if len(calls) == 1:
                                label = _tool_status(
                                    calls[0]["name"], calls[0].get("args"),
                                )
                                status.update(f"[spinner]{label}...[/spinner]")
                            elif len(calls) <= 3:
                                labels = [
                                    _tool_status(tc["name"], tc.get("args"))
                                    for tc in calls
                                ]
                                status.update(
                                    f"[spinner]Running {len(calls)} tools: "
                                    f"{', '.join(labels)}...[/spinner]"
                                )
                            else:
                                status.update(
                                    f"[spinner]Running {len(calls)} tools...[/spinner]"
                                )

                    # Tool result returned
                    elif hasattr(msg, "type") and msg.type == "tool":
                        if escalation:
                            # Escalation tool result received — stop streaming
                            return {"content": None, "escalation": escalation}
                        status.update("[spinner]Analyzing results...[/spinner]")

                    # Final AI response
                    elif (
                        hasattr(msg, "content")
                        and msg.content
                        and hasattr(msg, "type")
                        and msg.type == "ai"
                        and not getattr(msg, "tool_calls", None)
                    ):
                        if final_content:
                            final_content += "\n\n" + msg.content
                        else:
                            final_content = msg.content
                        if tool_count > 0:
                            status.update(
                                "[spinner]Composing response...[/spinner]"
                            )

    return {"content": final_content, "escalation": None}
```

- [ ] **Step 6: Update _invoke_agent to handle escalation**

Update `_invoke_agent` in `cli.py`:

```python
def _invoke_agent(agent, query: str, config: dict) -> str | None:
    """Invoke the agent with streaming status and print the response."""
    global _last_response
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    content = f"[Current date/time: {now}]\n\n{query}"
    try:
        result = _stream_invoke(agent, content, config)
    except Exception as e:
        console.print(f"[error]Error: {e}[/error]")
        return None

    # Handle escalation
    if result["escalation"]:
        return _handle_escalation(result["escalation"], query)

    if result["content"]:
        console.print()
        _print_response(result["content"])
        console.print()
        _last_response = result["content"]
    return result["content"]
```

- [ ] **Step 7: Add _handle_escalation function**

Add to `cli.py`:

```python
def _handle_escalation(escalation: dict, original_query: str) -> str | None:
    """Build a power agent and re-invoke with the structured handoff."""
    global _last_response
    from .agent import build_power_agent

    power_agent = build_power_agent()
    if power_agent is None:
        console.print(
            "[warning]Escalation requested but no power model configured. "
            "Set model.power in ~/.familiar/config.toml[/warning]"
        )
        return None

    handoff = _build_handoff_message(
        reason=escalation["reason"],
        summary=escalation["summary"],
        original_query=original_query,
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    handoff_content = f"[Current date/time: {now}]\n\n{handoff}"

    power_config = {"configurable": {"thread_id": uuid.uuid4().hex}}
    try:
        result = _stream_invoke(power_agent, handoff_content, power_config)
    except Exception as e:
        console.print(f"[error]Power model error: {e}[/error]")
        return None

    if result["content"]:
        console.print()
        _print_response(result["content"], model_label="power")
        console.print()
        _last_response = result["content"]
    return result["content"]
```

- [ ] **Step 8: Update _run_once to handle new return format**

Update `_run_once` in `cli.py`:

```python
def _run_once(agent, query: str):
    """Run a single query and print the response."""
    config = {"configurable": {"thread_id": uuid.uuid4().hex}}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    content = f"[Current date/time: {now}]\n\n{query}"
    try:
        result = _stream_invoke(agent, content, config)
    except Exception as e:
        console.print(f"[error]Error: {e}[/error]")
        sys.exit(1)

    if result.get("escalation"):
        _handle_escalation(result["escalation"], query)
    elif result.get("content"):
        _print_response(result["content"])
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/test_cli_escalation.py -v`
Expected: All PASS

- [ ] **Step 10: Run full test suite**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/ -v`
Expected: All PASS (existing tests may need minor updates due to `_stream_invoke` return type change — see Task 7)

- [ ] **Step 11: Commit**

```bash
git add src/familiar/cli.py tests/test_cli_escalation.py
git commit -m "feat: add escalation detection and power model re-invocation in CLI"
```

---

### Task 7: Fix existing tests for API changes

**Files:**
- Modify: `tests/test_agent_config.py`
- Modify: `tests/test_tool_inventory.py` (if not already updated in Task 4)

- [ ] **Step 1: Run full test suite and identify failures**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/ -v 2>&1 | tail -40`
Expected: Some tests may fail due to removed `DEFAULT_MODEL` / changed `_build_model_kwargs` signature

- [ ] **Step 2: Fix test_agent_config.py imports**

Update `test_agent_config.py` to reflect the new config-based approach. The `DEFAULT_MODEL` constant and `_build_model_kwargs` function in `agent.py` may have been removed in favor of config helpers. Update imports and tests accordingly:

- If `DEFAULT_MODEL` was removed: test `config.fast_model_id()` instead
- If `_build_model_kwargs` was removed from agent.py: test `config.model_kwargs()` instead (already covered in Task 1 tests)
- Keep system prompt tests as-is (they still apply)

- [ ] **Step 3: Run full test suite to confirm all pass**

Run: `cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/pytest tests/ -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add tests/
git commit -m "test: fix existing tests for escalation API changes"
```

---

### Task 8: End-to-end smoke test

- [ ] **Step 1: Verify config loads with new keys**

Run:
```bash
cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/python -c "
from familiar import config
config.reload()
print('Fast:', config.fast_model_id())
print('Power:', config.power_model_id())
print('Fast kwargs:', config.model_kwargs())
print('Power kwargs:', config.model_kwargs(config.power_model_id()))
"
```

Expected output:
```
Fast: ollama:gemma4:e4b
Power: ollama:gemma4:31b
Fast kwargs: {'base_url': 'http://localhost:11434'}
Power kwargs: {'base_url': 'http://localhost:11434'}
```

- [ ] **Step 2: Verify escalate tool is in ALL_TOOLS**

Run:
```bash
cd /home/zac/Projects/arcanum_suite/familiar && .venv/bin/python -c "
from familiar.tools import ALL_TOOLS
names = [t.name for t in ALL_TOOLS]
print('escalate' in names, len(ALL_TOOLS), 'tools total')
"
```

Expected: `True <N> tools total`

- [ ] **Step 3: Manual REPL test (if Ollama models available)**

Run `familiar` and try a query that the small model should escalate on, e.g.:
```
Run a comprehensive penetration test and strategic acquisition analysis of example.com with competitive intelligence on all their TLD variants
```

Observe:
- Spinner shows "Escalating to power model — ..."
- Response panel shows "familiar (power)"

- [ ] **Step 4: Commit any final adjustments**

```bash
git add -A
git commit -m "test: end-to-end smoke test for model escalation"
```
