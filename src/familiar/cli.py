"""CLI entry point for the Familiar agent."""

import sys
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.filterwarnings("ignore", message="Core Pydantic V1")

from langgraph.checkpoint.memory import MemorySaver
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.theme import Theme

from .agent import build_agent
from .tools.memory_tools import get_memory

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

# Slash commands that get expanded into agent prompts ({args} is replaced)
SLASH_COMMANDS = {
    "/assess": (
        "Provide a comprehensive assessment of {args}. Use appraise_domain to gather "
        "registration data, DNS footprint, web presence, and valuation signals. "
        "Present a thorough analysis with your advisory opinion on the domain's "
        "quality and value."
    ),
    "/compare": (
        "Compare these domains side by side: {args}. For each domain, check registration, "
        "DNS records, HTTP/SSL status, and email auth. Present a clear comparison "
        "highlighting the relative strengths and weaknesses of each."
    ),
    "/secure": (
        "Run a comprehensive security audit on {args}. Check DNSSEC status, CAA records, "
        "SPF record, DMARC policy, SSL certificate validity, and HTTP headers. "
        "Flag all issues with severity levels."
    ),
    "/suggest": (
        "Suggest available domain names for the brand '{args}'. Use suggest_domains to "
        "generate candidates and check availability. Present the best options with your "
        "recommendation on which to register and why."
    ),
    "/portfolio": (
        "Run a full portfolio health audit on: {args}. Use audit_portfolio. Present a "
        "comprehensive dashboard with expiration timeline, security gaps, and "
        "prioritized action items."
    ),
    "/competitive": (
        "Map the domain footprint of {args}. Use competitive_intel to check TLD variants, "
        "analyze infrastructure, and identify defensive registrations. Provide strategic "
        "insights about their domain strategy."
    ),
    "/migrate": (
        "Run a migration pre-flight check for {args}. Use migration_preflight. Walk through "
        "every step of the migration checklist, flag any blockers, and provide a recommended "
        "migration sequence."
    ),
    "/acquire": (
        "Analyze {args} for acquisition. Use plan_acquisition to check registration status, "
        "registrar, lock status, parking indicators, and web presence. Provide a strategic "
        "acquisition recommendation."
    ),
    "/watch": "Add {args} to my watchlist. Use watchlist_add. Confirm what was added.",
    "/unwatch": "Remove {args} from my watchlist. Use watchlist_remove.",
    "/watchlist": "Show my full watchlist. Use watchlist_list. Format it clearly.",
    "/check": (
        "Check all my watched domains for issues. Use watchlist_check. Present any alerts "
        "with severity levels and recommended actions. If everything is healthy, say so."
    ),
    "/domains": (
        "Show all domains in your notebook. Use recall_all_domains. Format as a clear list "
        "with notes and tags."
    ),
    "/pentest": (
        "Run a full penetration test-style exposure report on {args}. Use exposure_report "
        "to scan for subdomain takeover, HTTP security, email authentication, SSL/TLS, "
        "DNS zone security, and infrastructure reconnaissance. Present all findings "
        "organized by severity with remediation steps."
    ),
    "/takeover": (
        "Scan {args} for subdomain takeover vulnerabilities. Use subdomain_takeover_scan "
        "to enumerate subdomains via CT logs and check for dangling CNAME records pointing "
        "to claimable services. Flag all vulnerable subdomains with severity ratings."
    ),
    "/headers": (
        "Run an HTTP security scan on {args}. Use http_security_scan to check HTTPS "
        "enforcement, SSL certificate health, CAA records, and generate a security "
        "header checklist. Grade the domain's HTTP security posture."
    ),
    "/recon": (
        "Run infrastructure reconnaissance on {args}. Use infrastructure_recon to identify "
        "CDN/WAF providers, hosting platforms, email infrastructure, DNS providers, and "
        "technology signals. Map the full external footprint."
    ),
}

# Track the last agent response for /export
_last_response: str | None = None


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


def _invoke_agent(agent, query: str, config: dict) -> str | None:
    """Invoke the agent and print the response. Returns content or None."""
    global _last_response
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    content = f"[Current date/time: {now}]\n\n{query}"
    try:
        with console.status("[spinner]Thinking...[/spinner]", spinner="dots"):
            result = agent.invoke(
                {"messages": [{"role": "user", "content": content}]},
                config,
            )
    except Exception as e:
        console.print(f"[error]Error: {e}[/error]")
        return None

    msg = result["messages"][-1]
    if msg.content:
        console.print()
        _print_response(msg.content)
        console.print()
        _last_response = msg.content
        return msg.content
    return None


def _show_help():
    """Display the slash command help table."""
    table = Table(
        title="Familiar Commands",
        border_style="border",
        title_style="title",
        show_lines=True,
    )
    table.add_column("Command", style="accent", no_wrap=True)
    table.add_column("Description", style="muted")

    table.add_row("/assess <domain>", "Full domain assessment with valuation signals")
    table.add_row("/compare <d1, d2, ...>", "Side-by-side domain comparison")
    table.add_row("/secure <domain>", "Security audit (DNSSEC, SSL, SPF/DMARC)")
    table.add_row("/suggest <brand>", "Generate & check domain name suggestions")
    table.add_row("/acquire <domain>", "Acquisition strategy analysis")
    table.add_row("/portfolio <d1, d2, ...>", "Portfolio health dashboard")
    table.add_row("/competitive <domain>", "Competitor domain footprint analysis")
    table.add_row("/migrate <domain>", "DNS migration pre-flight checklist")
    table.add_row("/watch <domain>", "Add domain to watchlist")
    table.add_row("/unwatch <domain>", "Remove domain from watchlist")
    table.add_row("/watchlist", "Show all watched domains")
    table.add_row("/check", "Run watchlist health check")
    table.add_row("/domains", "Show all remembered domains")
    table.add_row("/teach on|off", "Toggle explanation/teaching mode")
    table.add_row("/export [path]", "Save last response to markdown file")
    table.add_row("/help", "Show this help")

    console.print()
    console.print(table)
    console.print()


def _handle_export(args: str):
    """Save the last response to a file."""
    global _last_response
    if not _last_response:
        console.print("[warning]No response to export yet.[/warning]")
        return

    filename = args.strip() or f"familiar-export-{datetime.now():%Y%m%d-%H%M%S}.md"
    out_path = Path(filename).expanduser().resolve()
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_last_response, encoding="utf-8")
        console.print(f"[success]Exported to {out_path}[/success]")
    except OSError as e:
        console.print(f"[error]Export failed: {e}[/error]")


def _handle_teach(args: str):
    """Toggle explanation mode locally."""
    mem = get_memory()
    arg = args.strip().lower()
    if arg in ("on", "true", "yes", "1"):
        mem.set_preference("explanation_mode", "true")
        console.print(
            "[success]Explanation mode enabled — responses will include "
            "educational context.[/success]"
        )
    elif arg in ("off", "false", "no", "0"):
        mem.set_preference("explanation_mode", "false")
        console.print(
            "[success]Explanation mode disabled — responses will be concise.[/success]"
        )
    else:
        current = mem.get_preference("explanation_mode", "false")
        status = "on" if current == "true" else "off"
        console.print(
            f"[info]Explanation mode is [bold]{status}[/bold]. "
            f"Use [bold]/teach on[/bold] or [bold]/teach off[/bold].[/info]"
        )


def _handle_slash(query: str, agent, config: dict) -> bool:
    """Handle slash commands. Returns True if the command was handled."""
    parts = query.strip().split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    if cmd == "/help":
        _show_help()
        return True

    if cmd == "/export":
        _handle_export(args)
        return True

    if cmd == "/teach":
        _handle_teach(args)
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


def _startup_check():
    """Show watchlist status on startup if there are watched domains."""
    try:
        mem = get_memory()
        watched = mem.watchlist_list()

        if not watched:
            return

        count = len(watched)
        stale = 0
        for w in watched:
            last = w.get("last_checked")
            if not last:
                stale += 1
            else:
                try:
                    checked = datetime.fromisoformat(last)
                    if checked.tzinfo is None:
                        checked = checked.replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - checked).days >= 1:
                        stale += 1
                except (ValueError, TypeError):
                    stale += 1

        parts = [f"[info]{count} domain{'s' if count != 1 else ''} on watchlist"]
        if stale:
            parts.append(
                f" ({stale} need{'s' if stale == 1 else ''} checking — "
                f"type [bold]/check[/bold])"
            )
        parts.append("[/info]")
        console.print("".join(parts))
    except Exception:
        return


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
    try:
        with console.status("[spinner]Thinking...[/spinner]", spinner="dots"):
            result = agent.invoke(
                {"messages": [{"role": "user", "content": query}]}, config
            )
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
            "[muted]Domain intelligence advisor — type [bold]/help[/bold] for commands, "
            "[bold]quit[/bold] to exit[/muted]",
            title="[title]familiar[/title]",
            title_align="left",
            border_style="border",
        )
    )
    console.print()

    _startup_check()

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
