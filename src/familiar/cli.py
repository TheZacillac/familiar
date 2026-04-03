"""CLI entry point for the Familiar agent."""

import re
import sys
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.filterwarnings("ignore", message="Core Pydantic V1")

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
from rich.table import Table
from rich.theme import Theme

from . import config
from .agent import build_agent
from .tools.memory_tools import get_memory

console = Console(theme=Theme(config.theme_dict()))

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
        "Run a comprehensive security audit on {args}. Use security_audit for SSL health, "
        "DNSSEC, SPF, DMARC, DKIM, and HTTP configuration. Flag all issues with severity "
        "levels and prioritized recommendations."
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
    "/security": (
        "Run a comprehensive security audit on {args}. Use security_audit for SSL health, "
        "DNSSEC, SPF, DMARC, DKIM, and HTTP configuration. Present all findings with "
        "severity levels and prioritized recommendations."
    ),
    "/brand": (
        "Run a brand protection scan for {args}. Use brand_protection_scan to check for "
        "typosquatting variants, TLD coverage, and subdomain exposure via CT logs."
    ),
    "/dns": (
        "Run a DNS health check on {args}. Use dns_health_check to audit record completeness, "
        "nameserver redundancy, SPF, CAA, SOA configuration, and IPv6 support."
    ),
    "/timeline": (
        "Build a domain timeline for {args}. Use domain_timeline to show registration, "
        "update, SSL, and expiry events chronologically with current state summary."
    ),
    "/expiry": (
        "Check expiration dates for {args}. Use expiration_alert to scan domains for "
        "upcoming or past-due expirations with urgency levels."
    ),
    "/report": (
        "Generate a polished markdown report about {args}. Use create_report to compile "
        "your findings into an exportable document."
    ),
    "/vs": (
        "Compare the security posture of these two domains: {args}. Use compare_security "
        "to run deep side-by-side audits of SSL, DNSSEC, email auth, CAA, nameservers, "
        "CDN/WAF, and HTTP. Present the field-by-field comparison clearly with the overall winner."
    ),
    "/tags": "Search your domain notebook by tag: {args}. Use tag_search.",
    "/summary": "Generate a session summary. Use session_summary to list all domains discussed, tools used, and key findings.",
}

# Track the last agent response for /export
_last_response: str | None = None


def _tool_status(name: str, args: dict | None = None) -> str:
    """Format a tool call into a human-readable status string."""
    target = ""
    if args:
        for key in ("domain", "query", "name", "term", "brand"):
            val = args.get(key)
            if isinstance(val, str) and len(val) < 80:
                target = val
                break
        if not target:
            val = args.get("domains")
            if isinstance(val, list) and val:
                preview = ", ".join(str(v) for v in val[:3])
                if len(val) > 3:
                    preview += f" (+{len(val) - 3} more)"
                target = preview

    # Clean up tool name for display
    display = name.replace("_", " ")
    for prefix in ("seer ", "tome "):
        if display.startswith(prefix):
            display = display[len(prefix):]
            break

    if target:
        return f"{display.capitalize()} — {target}"
    return display.capitalize()


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
    except Exception:
        pass  # No checkpoint yet (first invocation) — seen_ids stays empty

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


# Checkbox-like characters that LLMs place directly before digits
_CHECKBOX_NUMBER_RE = re.compile(r"([□☐☑☒✓✗✘▢◻◽])\s*(\d)")


def _print_response(content: str):
    """Render agent response as markdown in a styled panel."""
    # Fix checkboxes jammed against numbers (e.g. "□1" → "□ 1")
    content = _CHECKBOX_NUMBER_RE.sub(r"\1 \2", content)
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
    table.add_row("/vs <domain_a, domain_b>", "Side-by-side security comparison")
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

    safe_dir = config.export_dir()
    raw_name = args.strip() or f"familiar-export-{datetime.now():%Y%m%d-%H%M%S}.md"
    # Restrict to filename only — strip any directory components for safety
    out_path = safe_dir / Path(raw_name).name
    try:
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
