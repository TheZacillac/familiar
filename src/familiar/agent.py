"""LangGraph Deep Agent with configurable LLM provider."""

import os

import scrolls
from langchain.chat_models import init_chat_model
from deepagents import create_deep_agent

from .tools import ALL_TOOLS

DEFAULT_MODEL = "ollama:nemotron-3-nano:latest"

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

- Always use tools to look up real data — never guess registration status, DNS records, or dates.
- When a tool call fails, try alternatives (RDAP <-> WHOIS, different record types). \
Present partial results and note any gaps.
- For comprehensive checks, prefer composite tools (security_audit, dns_health_check, \
domain_timeline, exposure_report) over manual multi-tool sequences — they handle error \
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
Provide an honest assessment — be specific about strengths and weaknesses.

**Domain Suggestions:** Prioritize short names, .com availability, pronounceability, \
absence of hyphens/numbers, and TLD relevance to the brand's industry. Rank candidates clearly.

**Portfolio Audits:** Flag upcoming expirations, missing DNSSEC, invalid SSL, absent \
SPF/DMARC for domains with MX records, and single-registrar concentration risk. \
Assign severity levels and provide prioritized action items.

**Competitive Analysis:** Map TLD variant coverage, hosting infrastructure, email providers, \
CDN usage, and defensive registration patterns. Identify gaps and opportunities.

**Migration Planning:** Walk through every step methodically. Flag blockers (locks, pending \
transfers, short expiry). Emphasize email continuity and TTL management.

**Penetration Testing:** Use exposure_report for a full pentest-style assessment. Present \
findings organized by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO) with specific \
remediation steps. For targeted scans, use individual tools: subdomain_takeover_scan for \
dangling CNAMEs, email_security_audit for SPF/DMARC/DKIM deep-dive, ssl_deep_scan for \
certificate analysis, dns_zone_security for zone hardening, infrastructure_recon for \
technology mapping.

## Slash Commands

Users may type these in the REPL — respond as if they asked the full question:
/assess, /compare, /secure, /suggest, /acquire, /portfolio, /competitive, /migrate, \
/watch, /unwatch, /watchlist, /check, /domains, /security, /brand, /dns, /timeline, \
/expiry, /report, /tags, /summary, /pentest, /takeover, /headers, /recon
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
        if child.is_dir() and not child.name.startswith(("_", ".")) and child.name != "reference":
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


def _build_model_kwargs(model_id: str) -> dict:
    """Build provider-specific kwargs from environment variables."""
    kwargs = {}
    provider = model_id.split(":")[0] if ":" in model_id else None

    if provider == "ollama":
        base_url = os.environ.get("OLLAMA_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url

    return kwargs


def build_agent(checkpointer=None):
    """Construct and return the LangGraph Deep Agent.

    Args:
        checkpointer: Optional LangGraph checkpointer for persisting conversation
            state between invocations. Pass a MemorySaver for REPL sessions.
    """
    _load_env()
    model_id = os.environ.get("FAMILIAR_MODEL", DEFAULT_MODEL)

    model = init_chat_model(
        model=model_id,
        **_build_model_kwargs(model_id),
    )

    agent = create_deep_agent(
        model=model,
        tools=ALL_TOOLS,
        system_prompt=_build_system_prompt(),
        checkpointer=checkpointer,
    )

    return agent
