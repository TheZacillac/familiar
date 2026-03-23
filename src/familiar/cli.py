"""CLI entry point for the Familiar agent."""

import sys
import uuid
import warnings

warnings.filterwarnings("ignore", message="Core Pydantic V1")

from langgraph.checkpoint.memory import MemorySaver
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.theme import Theme

from .agent import build_agent

# Catppuccin Mocha palette
CATPPUCCIN = Theme(
    {
        "info": "#8caaee",        # Blue
        "warning": "#e5c890",     # Yellow
        "error": "#e78284",       # Red
        "success": "#a6d189",     # Green
        "prompt": "bold #a6d189", # Green
        "title": "bold #ca9ee6",  # Mauve
        "border": "#babbf1",      # Lavender
        "muted": "#a5adce",       # Subtext0
        "spinner": "#81c8be",     # Teal
        "accent": "#f4b8e4",      # Pink
        "peach": "#ef9f76",       # Peach
        "sky": "#99d1db",         # Sky
    }
)

console = Console(theme=CATPPUCCIN)


def _print_response(content: str):
    """Render agent response as markdown in a styled panel."""
    md = Markdown(content)
    console.print(
        Panel(
            md,
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )


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
    try:
        with console.status("[spinner]Thinking...[/spinner]", spinner="dots"):
            result = agent.invoke({"messages": [{"role": "user", "content": query}]})
    except Exception as e:
        console.print(f"[error]Error: {e}[/error]")
        sys.exit(1)

    msg = result["messages"][-1]
    if msg.content:
        _print_response(msg.content)


def _repl(agent):
    """Interactive chat loop with conversation memory."""
    thread_id = uuid.uuid4().hex
    config = {"configurable": {"thread_id": thread_id}}

    console.print(
        Panel(
            "[muted]Domain intelligence agent — type [bold]quit[/bold] to exit[/muted]",
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )
    console.print()

    while True:
        try:
            query = Prompt.ask("[prompt]you[/prompt]", console=console)
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not query.strip() or query.strip().lower() in ("quit", "exit"):
            break

        try:
            with console.status("[spinner]Thinking...[/spinner]", spinner="dots"):
                result = agent.invoke(
                    {"messages": [{"role": "user", "content": query}]},
                    config,
                )
        except Exception as e:
            console.print(f"[error]Error: {e}[/error]")
            console.print()
            continue

        msg = result["messages"][-1]
        if msg.content:
            console.print()
            _print_response(msg.content)
            console.print()
