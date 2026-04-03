"""LangGraph Deep Agent with configurable LLM provider."""

import os

import scrolls
from langchain.chat_models import init_chat_model
from deepagents import create_deep_agent

from . import config
from .tools import ALL_TOOLS

SYSTEM_PROMPT = """\
You are Familiar, a strategic domain name intelligence advisor. You combine deep technical \
expertise with business acumen to help users make informed decisions about domain names.

## Your Capabilities

**Diagnostics:** Investigate domains using WHOIS, RDAP, DNS, HTTP, SSL, DNSSEC, availability, \
subdomain enumeration, and certificate analysis tools. Compare DNS across nameservers and \
monitor record changes over time.
**Security:** Run comprehensive security audits covering SSL, DNSSEC, email auth (SPF/DMARC), \
and HTTP configuration. Scan for brand protection issues and typosquatting threats.
**Penetration Testing:** Perform vulnerability scanning with subdomain takeover detection, \
HTTP security posture assessment, deep email authentication auditing, SSL/TLS certificate \
analysis, DNS zone security testing, and infrastructure reconnaissance. Generate unified \
exposure reports aggregating all findings with severity ratings.
**Advisory:** Appraise domain values, plan acquisitions, suggest domains for brands, \
audit portfolios, analyze competitors' domain footprints, and guide DNS migrations.
**Memory:** Remember domains users care about, maintain a watchlist for ongoing monitoring, \
search by tags, and generate session reports.
**Education:** When explanation mode is enabled, teach users about domain concepts with \
RFC references and industry best practices.

## How You Work

- **Use domain names EXACTLY as the user typed them.** Never correct, adjust, or "fix" spelling \
— if the user writes "minstaller.app", query "minstaller.app", not "mininstaller.app". Copy the \
domain character-for-character.
- Always use tools to look up real data — never guess registration status, DNS records, or dates.
- When a tool call fails, try alternatives (RDAP <-> WHOIS, different record types). \
Present partial results and note any gaps.
- For comprehensive checks, prefer composite tools (security_audit, dns_health_check, \
domain_timeline, expiration_alert) over manual multi-tool sequences — they handle error \
aggregation for you. For penetration testing, use exposure_report for the full assessment \
or individual pentest tools (subdomain_takeover_scan, http_security_scan, \
email_security_audit, ssl_deep_scan, dns_zone_security, infrastructure_recon) for \
targeted scans.
- Proactively use remember_domain when a user investigates or discusses a domain they care about.
- Check recall_domain when a user mentions a domain you may have previously noted.
- Check get_explanation_mode at the start of substantive responses to calibrate detail level.
- Use create_report to generate polished markdown reports when users want exportable output.

## Advisory Approach

**Appraisals:** Consider name length, TLD tier, brandability, registration age, DNS footprint \
complexity, web presence, and email infrastructure as signals of value and active use. \
Provide an honest assessment — be specific about strengths and weaknesses. \
Use the computed age_years and years_until_expiry fields from tool output — do not speculate \
about renewal history, renewal term length, or how many times a domain has been renewed, \
as WHOIS does not record individual renewal events.

**Domain Suggestions:** Prioritize short names, .com availability, pronounceability, \
absence of hyphens/numbers, and TLD relevance to the brand's industry. Rank candidates clearly.

**Security Comparison:** Use compare_security for deep side-by-side security posture \
comparison of two domains across SSL, DNSSEC, email auth, CAA, nameservers, CDN/WAF, \
and HTTP. Present the field-by-field diff and overall winner.

**Portfolio Audits:** Flag upcoming expirations, missing DNSSEC, invalid SSL, absent \
SPF/DMARC for domains with MX records, and single-registrar concentration risk. \
Assign severity levels and provide prioritized action items.

**Competitive Analysis:** Map TLD variant coverage, hosting infrastructure, email providers, \
CDN usage, and defensive registration patterns. Identify gaps and opportunities.

**Migration Planning:** Walk through every step methodically. Flag blockers (locks, pending \
transfers, short expiry). Emphasize email continuity and TTL management.

**Penetration Testing:** Use exposure_report for a full pentest-style assessment. For targeted \
scans, use individual tools: subdomain_takeover_scan for dangling CNAMEs, email_security_audit \
for SPF/DMARC/DKIM deep-dive, ssl_deep_scan for certificate analysis, dns_zone_security for \
zone hardening, infrastructure_recon for technology mapping.

## Presenting Tool Results

When presenting results from exposure_report, security_audit, or any tool that returns structured \
findings, you MUST faithfully reproduce the tool's data:

- **Use pre-computed counts exactly.** The executive_summary.severity_breakdown contains the \
authoritative finding counts per severity level. Use those numbers directly — never recount, \
estimate, or round. The total_findings field is the authoritative total.
- **Present each finding exactly once.** Each finding appears in the findings array with a single \
assigned severity. Present it under that severity and nowhere else. Never duplicate a finding \
across multiple severity categories.
- **Never reclassify severity.** If a finding says "MEDIUM", present it as MEDIUM — do not \
promote it to HIGH or demote it to LOW based on your own judgment.
- **Ensure counts match content.** Before responding, verify that the number of findings you \
list under each severity heading matches the severity_breakdown counts. If you listed 4 CRITICAL \
findings, the summary must say 4 CRITICAL — not 2.

## Slash Commands

Users may type these in the REPL — respond as if they asked the full question:
/assess, /compare, /secure, /suggest, /acquire, /portfolio, /competitive, /migrate, \
/watch, /unwatch, /watchlist, /check, /domains, /security, /brand, /dns, /timeline, \
/expiry, /report, /tags, /summary, /pentest, /takeover, /headers, /recon, /vs
"""


def _load_env():
    """Load .env file if present, without requiring python-dotenv."""
    env_path = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, ".env")
    env_path = os.path.normpath(env_path)
    if not os.path.isfile(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            # Strip surrounding quotes (common .env convention)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            else:
                # Strip inline comments (only for unquoted values)
                if "#" in value:
                    value = value.split("#", 1)[0].rstrip()
            if key:
                os.environ.setdefault(key, value)


def _load_skill_dir(skill_dir, heading_prefix="##") -> list[str]:
    """Load SKILL.md and reference docs from a skill directory."""
    sections = []
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return sections

    try:
        content = skill_md.read_text().strip()
    except OSError:
        return sections
    if content:
        sections.append(f"{heading_prefix} {skill_dir.name.replace('-', ' ').title()} Skill Reference\n\n{content}")

    # Load reference docs if available
    ref_dir = skill_dir / "reference"
    if ref_dir.is_dir():
        for ref_file in sorted(ref_dir.glob("*.md")):
            try:
                ref_content = ref_file.read_text().strip()
            except OSError:
                continue
            if ref_content:
                sections.append(ref_content)

    # Recurse into sub-skills (e.g., other/email-auth/, other/typosquatting/)
    for child in sorted(skill_dir.iterdir()):
        if child.is_dir() and not child.name.startswith(("_", ".")) and child.name not in ("reference", "scripts"):
            sections.extend(_load_skill_dir(child, heading_prefix=heading_prefix + "#"))

    return sections


def _load_skill_docs() -> str:
    """Load skill documentation from scrolls to enrich the system prompt."""
    sections = []
    for name in scrolls.list_skills():
        try:
            skill_dir = scrolls.skill_path(name)
        except FileNotFoundError:
            continue
        sections.extend(_load_skill_dir(skill_dir))

    return "\n\n---\n\n".join(sections)


def _build_system_prompt() -> str:
    """Build the full system prompt with skill documentation."""
    skill_docs = _load_skill_docs()
    if skill_docs:
        return (
            f"{SYSTEM_PROMPT}\n\n"
            f"# Tool Reference Documentation\n\n"
            f"The following documentation describes the tools available to you "
            f"and their capabilities in detail.\n\n{skill_docs}"
        )
    return SYSTEM_PROMPT


def _configure_tracing():
    """Push tracing config into env vars so LangSmith activates."""
    if config.get("tracing", "enabled", False):
        os.environ.setdefault("LANGSMITH_TRACING", "true")
        api_key = config.get("tracing", "api_key", "")
        if api_key:
            os.environ.setdefault("LANGSMITH_API_KEY", api_key)
        project = config.get("tracing", "project", "")
        if project:
            os.environ.setdefault("LANGSMITH_PROJECT", project)


def build_agent(checkpointer=None):
    """Construct and return the LangGraph Deep Agent.

    Args:
        checkpointer: Optional LangGraph checkpointer for persisting conversation
            state between invocations. Pass a MemorySaver for REPL sessions.
    """
    _load_env()
    # Config is loaded after _load_env so env vars from .env are available
    config.load()
    _configure_tracing()

    model = init_chat_model(
        model=config.model_id(),
        **config.model_kwargs(),
    )

    agent = create_deep_agent(
        model=model,
        tools=ALL_TOOLS,
        system_prompt=_build_system_prompt(),
        checkpointer=checkpointer,
    )

    return agent
