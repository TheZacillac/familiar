"""Shared CLI primitives used by both `cli` (LangChain) and `cli_claude` (SDK).

Holds the slash-command catalog, status formatting, and the engine-agnostic
slash handlers (`/help`, `/teach`) plus the watchlist startup banner. Lives
here so neither CLI needs to import the other (which would pull in the wrong
agent stack).
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

from . import config
from .tools.memory_tools import get_memory

logger = logging.getLogger("familiar")

# Slash commands that get expanded into agent prompts ({args} is replaced).
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

# Checkbox-like characters that LLMs place directly before digits.
CHECKBOX_NUMBER_RE = re.compile(r"([□☐☑☒✓✗✘▢◻◽])\s*(\d)")


def tool_status(name: str, args: dict | None = None) -> str:
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

    display = name.replace("_", " ")
    for prefix in ("seer ", "tome "):
        if display.startswith(prefix):
            display = display[len(prefix):]
            break

    if target:
        return f"{display.capitalize()} — {target}"
    return display.capitalize()


def show_help(console: Console) -> None:
    """Display the slash-command help table."""
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


def handle_teach(console: Console, args: str) -> None:
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


def startup_check(console: Console) -> None:
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
                        checked = checked.replace(tzinfo=UTC)
                    if (datetime.now(UTC) - checked).days >= 1:
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
    except Exception as e:
        # Don't break REPL startup, but make the failure visible.
        logger.warning("startup_check failed: %s", e)
        console.print(
            f"[warning]Watchlist startup check failed: {e}[/warning]"
        )


def export_last_response(
    console: Console, last_response: str | None, args: str
) -> None:
    """Save the last response to a file under the configured export dir."""
    from pathlib import Path

    if not last_response:
        console.print("[warning]No response to export yet.[/warning]")
        return

    safe_dir = config.export_dir()
    raw_name = args.strip() or f"familiar-export-{datetime.now():%Y%m%d-%H%M%S}.md"
    out_path = safe_dir / Path(raw_name).name
    try:
        out_path.write_text(last_response, encoding="utf-8")
        console.print(f"[success]Exported to {out_path}[/success]")
    except OSError as e:
        console.print(f"[error]Export failed: {e}[/error]")


__all__ = [
    "CHECKBOX_NUMBER_RE",
    "SLASH_COMMANDS",
    "export_last_response",
    "handle_teach",
    "show_help",
    "startup_check",
    "tool_status",
]
