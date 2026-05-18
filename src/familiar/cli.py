"""CLI entry point for the Familiar agent (LangChain Deep Agents engine)."""

import logging
import sys
import uuid
import warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore", message="Core Pydantic V1")

logger = logging.getLogger("familiar")

# Configure logging before any other imports that might emit logs.
try:
    from arcanum._logging import configure_logging
    configure_logging("familiar")
except ImportError:
    pass

from langgraph.checkpoint.memory import MemorySaver
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme

from . import config
from .agent import build_agent
from .cli_common import (
    CHECKBOX_NUMBER_RE,
    SLASH_COMMANDS,
    export_last_response,
    handle_teach,
    show_help,
    startup_check,
    tool_status,
)

console = Console(theme=Theme(config.theme_dict()))

# Track the last agent response for /export
_last_response: str | None = None


def _extract_messages(update) -> list:
    """Extract a message list from a stream update, unwrapping LangGraph channel types."""
    if isinstance(update, dict):
        raw = update.get("messages", [])
    elif isinstance(update, list):
        raw = update
    else:
        raw = []

    # Unwrap LangGraph channel wrappers (e.g., Overwrite)
    if not isinstance(raw, list):
        if hasattr(raw, "value"):
            raw = raw.value
        if not isinstance(raw, list):
            raw = [raw] if raw else []

    return raw


def _stream_invoke(agent, content: str, config: dict) -> str | None:
    """Stream agent execution, showing tool activity on the status line.

    With ``stream_mode="updates"`` LangGraph emits the full checkpoint
    state (including prior turns) in every node update.  We pre-seed
    ``seen_ids`` from the existing checkpoint so that only genuinely
    *new* messages from this invocation are captured.
    """
    final_content = None
    tool_count = 0

    # Pre-seed with all message IDs already in the checkpoint so that
    # prior-turn messages replayed in the stream are ignored.
    seen_ids: set[str] = set()
    try:
        snapshot = agent.get_state(config)
        if snapshot and snapshot.values:
            for msg in snapshot.values.get("messages", []):
                msg_id = getattr(msg, "id", None)
                if msg_id:
                    seen_ids.add(msg_id)
    except (KeyError, AttributeError, ValueError):
        # No checkpoint yet (first invocation) — seen_ids stays empty.
        pass
    except Exception as e:
        # Something genuinely broke (corrupt checkpoint, version mismatch).
        # An empty seen_ids set causes prior-turn messages to be re-emitted
        # as duplicates, so make the failure visible.
        logger.warning("agent.get_state failed: %s", e)

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
                    # De-duplicate: skip messages we have already processed.
                    msg_id = getattr(msg, "id", None)
                    if msg_id:
                        if msg_id in seen_ids:
                            continue
                        seen_ids.add(msg_id)

                    # AI message with tool calls — show what's being invoked
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        calls = msg.tool_calls
                        tool_count += len(calls)
                        if len(calls) == 1:
                            label = tool_status(
                                calls[0]["name"], calls[0].get("args"),
                            )
                            status.update(f"[spinner]{label}...[/spinner]")
                        elif len(calls) <= 3:
                            labels = [
                                tool_status(tc["name"], tc.get("args"))
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

                    # Tool result returned — back to analysis
                    elif hasattr(msg, "type") and msg.type == "tool":
                        status.update("[spinner]Analyzing results...[/spinner]")

                    # Final AI response (no tool calls) — accumulate in
                    # case the agent emits multiple non-tool AI messages
                    # within a single invocation.
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

    return final_content


def _print_response(content: str):
    """Render agent response as markdown in a styled panel."""
    # Fix checkboxes jammed against numbers (e.g. "□1" → "□ 1")
    content = CHECKBOX_NUMBER_RE.sub(r"\1 \2", content)
    md = Markdown(content)
    console.print(
        Panel(
            md,
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )


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

    if result:
        console.print()
        _print_response(result)
        console.print()
        _last_response = result
    return result


def _handle_slash(query: str, agent, config: dict) -> bool:
    """Handle slash commands. Returns True if the command was handled."""
    parts = query.strip().split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    if cmd == "/help":
        show_help(console)
        return True

    if cmd == "/export":
        export_last_response(console, _last_response, args)
        return True

    if cmd == "/teach":
        handle_teach(console, args)
        return True

    if cmd in SLASH_COMMANDS:
        template = SLASH_COMMANDS[cmd]
        if "{args}" in template and not args:
            console.print(f"[warning]Usage: {cmd} <arguments>[/warning]")
            return True
        prompt = template.replace("{args}", args)
        _invoke_agent(agent, prompt, config)
        return True

    return False


def main():
    if len(sys.argv) > 1:
        agent = build_agent()
        query = " ".join(sys.argv[1:])
        _run_once(agent, query)
    else:
        checkpointer = MemorySaver()
        agent = build_agent(checkpointer=checkpointer)
        _repl(agent)


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

    if result:
        _print_response(result)


def _repl(agent):
    """Interactive chat loop with conversation memory."""
    thread_id = uuid.uuid4().hex
    config = {"configurable": {"thread_id": thread_id}}

    console.print(
        Panel(
            "[muted]Domain intelligence advisor — type [bold]/help[/bold] for commands, "
            "[bold]quit[/bold] to exit[/muted]",
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )
    console.print()

    startup_check(console)

    while True:
        try:
            query = Prompt.ask("[prompt]you[/prompt]", console=console)
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not query.strip() or query.strip().lower() in ("quit", "exit"):
            break

        # Handle slash commands
        if query.strip().startswith("/"):
            if _handle_slash(query, agent, config):
                continue

        # Normal agent invocation
        _invoke_agent(agent, query, config)
