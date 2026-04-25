"""CLI entry point for the Claude Agent SDK variant of Familiar.

Mirrors the look and slash-command behavior of `cli.py` but drives the agent
through Anthropic's Claude Agent SDK instead of LangGraph Deep Agents.
"""

from __future__ import annotations

import asyncio
import sys
import warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore", message="Core Pydantic V1")

# Configure logging before importing modules that emit logs.
try:
    from arcanum._logging import configure_logging
    configure_logging("familiar")
except ImportError:
    pass

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme

from . import config
from .agent_claude import bootstrap
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

_last_response: str | None = None


def _print_response(content: str) -> None:
    """Render an agent response as markdown in a styled panel."""
    content = CHECKBOX_NUMBER_RE.sub(r"\1 \2", content)
    console.print()
    console.print(
        Panel(
            Markdown(content),
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )
    console.print()


def _unprefix(tool_name: str) -> str:
    """Strip the `mcp__server__` prefix from an SDK tool name for display."""
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) == 3:
            return parts[2]
    return tool_name


def _wrap_query(content: str) -> str:
    """Prepend the current UTC timestamp, matching cli.py's behavior."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"[Current date/time: {now}]\n\n{content}"


async def _consume_response(client: ClaudeSDKClient, status) -> str | None:
    """Drive the SDK message stream, update the status line, return final text."""
    final_chunks: list[str] = []
    error: str | None = None

    async for message in client.receive_response():
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    label = tool_status(_unprefix(block.name), block.input or {})
                    status.update(f"[spinner]{label}...[/spinner]")
                elif isinstance(block, TextBlock) and block.text:
                    final_chunks.append(block.text)
                    status.update("[spinner]Composing response...[/spinner]")
        elif isinstance(message, ResultMessage):
            if getattr(message, "subtype", "success") != "success":
                error = (
                    getattr(message, "result", None)
                    or getattr(message, "error", None)
                    or "agent stopped without success"
                )

    if error:
        console.print(f"[error]Agent error: {error}[/error]")
        return None
    return "\n\n".join(c.strip() for c in final_chunks if c.strip()) or None


async def _ask(client: ClaudeSDKClient, content: str) -> None:
    """Send a user turn, stream the response, render it."""
    global _last_response
    await client.query(_wrap_query(content))
    try:
        with console.status("[spinner]Thinking...[/spinner]", spinner="dots") as status:
            result = await _consume_response(client, status)
    except Exception as e:
        console.print(f"[error]Error: {e}[/error]")
        return

    if result:
        _print_response(result)
        _last_response = result


async def _handle_slash(client: ClaudeSDKClient, query_str: str) -> bool:
    """Handle slash commands. Returns True if handled."""
    parts = query_str.strip().split(None, 1)
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
        await _ask(client, prompt)
        return True
    return False


async def _run_once(prompt: str) -> None:
    options = bootstrap()
    async with ClaudeSDKClient(options=options) as client:
        await _ask(client, prompt)


async def _repl() -> None:
    options = bootstrap()
    console.print(
        Panel(
            "[muted]Domain intelligence advisor (Claude Agent SDK) — type "
            "[bold]/help[/bold] for commands, [bold]quit[/bold] to exit[/muted]",
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )
    console.print()
    startup_check(console)

    async with ClaudeSDKClient(options=options) as client:
        while True:
            try:
                q = Prompt.ask("[prompt]you[/prompt]", console=console)
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if not q.strip() or q.strip().lower() in ("quit", "exit"):
                break

            if q.strip().startswith("/"):
                if await _handle_slash(client, q):
                    continue

            await _ask(client, q)


def main() -> None:
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
        asyncio.run(_run_once(prompt))
    else:
        asyncio.run(_repl())


if __name__ == "__main__":
    main()
