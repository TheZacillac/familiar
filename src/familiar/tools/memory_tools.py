"""Memory and watchlist tools for persistent domain knowledge."""

import atexit
import json
from datetime import datetime, timezone

import seer
from langchain_core.tools import tool

from ..memory import Memory
from ..utils import days_until as _days_until, safe_call

# Module-level singleton, initialized lazily
_memory: Memory | None = None


def get_memory() -> Memory:
    """Get the shared Memory singleton. Registered for cleanup at process exit."""
    global _memory
    if _memory is None:
        _memory = Memory()
        atexit.register(_memory.close)
    return _memory


# --- Domain Notebook ---


@tool
def remember_domain(domain: str, notes: str = "", tags: str = "") -> str:
    """Save a domain to Familiar's notebook with optional notes and comma-separated tags.
    If the domain already exists, notes are appended and tags are merged. Use this to
    track domains the user cares about."""
    result = get_memory().remember_domain(domain, notes, tags)
    return json.dumps(result, default=str)


@tool
def recall_domain(domain: str) -> str:
    """Recall what Familiar knows about a specific domain from its notebook. Returns
    notes, tags, and when it was first and last discussed."""
    result = get_memory().recall_domain(domain)
    if result is None:
        return json.dumps({"domain": domain, "found": False})
    return json.dumps({**result, "found": True}, default=str)


@tool
def recall_all_domains() -> str:
    """List all domains in Familiar's notebook, ordered by most recently discussed."""
    results = get_memory().recall_all_domains()
    return json.dumps({"total": len(results), "domains": results}, default=str)


# --- Watchlist ---


@tool
def watchlist_add(domain: str) -> str:
    """Add a domain to the watchlist for ongoing monitoring. Watched domains are checked
    for expiration, SSL issues, and HTTP accessibility when the user runs /check."""
    result = get_memory().watchlist_add(domain)
    return json.dumps(result, default=str)


@tool
def watchlist_remove(domain: str) -> str:
    """Remove a domain from the watchlist."""
    result = get_memory().watchlist_remove(domain)
    return json.dumps(result, default=str)


@tool
def watchlist_list() -> str:
    """List all domains currently on the watchlist with their last check status."""
    results = get_memory().watchlist_list()
    return json.dumps({"total": len(results), "domains": results}, default=str)


@tool
def watchlist_check() -> str:
    """Check all watched domains for issues: expiring registrations, SSL certificate
    problems, and HTTP accessibility. Returns alerts for anything needing attention."""
    mem = get_memory()
    watched = mem.watchlist_list()

    if not watched:
        return json.dumps({"message": "Watchlist is empty", "alerts": []})

    domains = [w["domain"] for w in watched]
    alerts = []

    bulk_status_raw = safe_call(seer.bulk_status, domains) or [None] * len(domains)
    bulk_lookup_raw = safe_call(seer.bulk_lookup, domains) or [None] * len(domains)

    for i, domain in enumerate(domains):
        domain_alerts = []

        # Unwrap BulkResult → .data for lookup
        raw_reg = bulk_lookup_raw[i] if i < len(bulk_lookup_raw) else None
        reg = None
        if raw_reg and isinstance(raw_reg, dict) and raw_reg.get("success"):
            reg = raw_reg.get("data")

        # Unwrap BulkResult → .data for status
        raw_st = bulk_status_raw[i] if i < len(bulk_status_raw) else None
        st = None
        if raw_st and isinstance(raw_st, dict) and raw_st.get("success"):
            st = raw_st.get("data")

        # Expiration check — field is nested under data for whois source
        if reg and isinstance(reg, dict):
            inner = reg.get("data", reg)
            expiry = (
                inner.get("expiration_date") or inner.get("expiry")
                if isinstance(inner, dict) else None
            )
            if expiry:
                days_left = _days_until(expiry)
                if days_left is not None:
                    if days_left < 30:
                        domain_alerts.append({
                            "type": "expiration",
                            "severity": "critical",
                            "message": f"Expires in {days_left} days ({expiry})",
                        })
                    elif days_left < 90:
                        domain_alerts.append({
                            "type": "expiration",
                            "severity": "warning",
                            "message": f"Expires in {days_left} days ({expiry})",
                        })

        # SSL check — certificate info is nested under .certificate
        if st and isinstance(st, dict):
            cert = st.get("certificate")
            if cert and isinstance(cert, dict):
                if not cert.get("is_valid", True):
                    domain_alerts.append({
                        "type": "ssl",
                        "severity": "critical",
                        "message": "SSL certificate is invalid or missing",
                    })
                ssl_days = cert.get("days_until_expiry")
                if ssl_days is not None and ssl_days < 14:
                    domain_alerts.append({
                        "type": "ssl_expiry",
                        "severity": "warning",
                        "message": f"SSL certificate expires in {ssl_days} days",
                    })
            elif cert is None:
                # No certificate at all
                domain_alerts.append({
                    "type": "ssl",
                    "severity": "warning",
                    "message": "No SSL certificate detected",
                })

            if st.get("http_status") is None:
                domain_alerts.append({
                    "type": "http",
                    "severity": "warning",
                    "message": "Domain is not responding to HTTP requests",
                })

        # Save check status
        mem.watchlist_update_status(domain, {
            "registration": reg,
            "status": st,
            "alerts": domain_alerts,
        })

        if domain_alerts:
            alerts.append({"domain": domain, "alerts": domain_alerts})

    return json.dumps({
        "checked": len(domains),
        "domains_with_alerts": len(alerts),
        "alerts": alerts,
    }, default=str)


# --- Explanation Mode ---


@tool
def set_explanation_mode(enabled: bool) -> str:
    """Toggle explanation/teaching mode. When enabled, Familiar provides detailed
    educational context — explaining WHY recommendations are made, referencing RFCs,
    industry terminology, and best practices. When disabled, responses are concise."""
    get_memory().set_preference("explanation_mode", "true" if enabled else "false")
    return json.dumps({
        "explanation_mode": enabled,
        "message": f"Explanation mode {'enabled' if enabled else 'disabled'}",
    })


@tool
def get_explanation_mode() -> str:
    """Check whether explanation/teaching mode is currently enabled."""
    value = get_memory().get_preference("explanation_mode", "false")
    return json.dumps({"explanation_mode": value == "true"})


MEMORY_TOOLS = [
    remember_domain,
    recall_domain,
    recall_all_domains,
    watchlist_add,
    watchlist_remove,
    watchlist_list,
    watchlist_check,
    set_explanation_mode,
    get_explanation_mode,
]


# --- Workflow Tools ---


@tool
def tag_search(tag: str) -> str:
    """Search remembered domains by exact tag match (case-insensitive). Returns all
    domains that have the given tag. Useful for finding domains grouped by purpose,
    project, or category."""
    try:
        results = get_memory().tag_search(tag)
        return json.dumps({"tag": tag, "total": len(results), "domains": results}, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def create_report(title: str, sections: str) -> str:
    """Generate a formatted markdown report from provided sections. Pass sections
    as a JSON string containing a list of {heading, content} objects. Returns a
    complete markdown document with title, timestamp, and footer."""
    try:
        section_list = json.loads(sections)
    except (json.JSONDecodeError, TypeError) as e:
        return json.dumps({"error": f"Invalid sections JSON: {e}"})

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# {title}",
        "",
        f"*Generated: {timestamp}*",
        "",
    ]

    for section in section_list:
        heading = section.get("heading", "Untitled Section")
        content = section.get("content", "")
        lines.append(f"## {heading}")
        lines.append("")
        lines.append(content)
        lines.append("")

    lines.append("---")
    lines.append("*Report generated by Familiar — domain intelligence agent*")

    report = "\n".join(lines)
    return json.dumps({"title": title, "timestamp": timestamp, "report": report}, default=str)


@tool
def compare_domains(domain_a: str, domain_b: str) -> str:
    """Side-by-side comparison of two domains. Checks registration (WHOIS),
    DNS A records, and HTTP/SSL status for both domains and returns a structured
    comparison showing differences."""
    domain_a = domain_a.lower().strip()
    domain_b = domain_b.lower().strip()

    comparison = {"domain_a": domain_a, "domain_b": domain_b}

    # Registration comparison
    try:
        reg_a = safe_call(seer.lookup, domain_a)
        reg_b = safe_call(seer.lookup, domain_b)
        comparison["registration"] = {"a": reg_a, "b": reg_b}
    except Exception as e:
        comparison["registration"] = {"error": str(e)}

    # DNS A record comparison
    try:
        dns_a = safe_call(seer.dig, domain_a, "A")
        dns_b = safe_call(seer.dig, domain_b, "A")
        comparison["dns_a_records"] = {"a": dns_a, "b": dns_b}
    except Exception as e:
        comparison["dns_a_records"] = {"error": str(e)}

    # Status comparison
    try:
        status_a = safe_call(seer.status, domain_a)
        status_b = safe_call(seer.status, domain_b)
        comparison["status"] = {"a": status_a, "b": status_b}
    except Exception as e:
        comparison["status"] = {"error": str(e)}

    return json.dumps(comparison, default=str)


@tool
def session_summary() -> str:
    """List all domains in Familiar's notebook, most recently discussed first, with
    their tags, plus any watchlist items currently being monitored."""
    try:
        mem = get_memory()
        domains = mem.recall_all_domains()
        watched = mem.watchlist_list()

        domain_list = [
            {"domain": d["domain"], "tags": d["tags"], "last_updated": d["last_seen"]}
            for d in domains
        ]

        return json.dumps({
            "total_domains": len(domains),
            "domains": domain_list,
            "watchlist_count": len(watched),
            "watchlist": [w["domain"] for w in watched],
        }, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


WORKFLOW_TOOLS = [
    tag_search,
    create_report,
    compare_domains,
    session_summary,
]
