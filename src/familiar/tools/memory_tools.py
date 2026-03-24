"""Memory and watchlist tools for persistent domain knowledge."""

import atexit
import json

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
    for expiration, SSL issues, and DNS changes when the user runs /check."""
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

    bulk_status = safe_call(seer.bulk_status, domains) or [None] * len(domains)
    bulk_lookup = safe_call(seer.bulk_lookup, domains) or [None] * len(domains)

    for i, domain in enumerate(domains):
        domain_alerts = []

        # Expiration check
        reg = bulk_lookup[i] if i < len(bulk_lookup) else None
        if reg and isinstance(reg, dict):
            expiry = reg.get("expiry") or reg.get("expiration_date")
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

        # SSL check
        st = bulk_status[i] if i < len(bulk_status) else None
        if st and isinstance(st, dict):
            if not st.get("ssl_valid", False):
                domain_alerts.append({
                    "type": "ssl",
                    "severity": "critical",
                    "message": "SSL certificate is invalid or missing",
                })
            ssl_expiry = st.get("ssl_expiry")
            if ssl_expiry:
                ssl_days = _days_until(ssl_expiry)
                if ssl_days is not None and ssl_days < 14:
                    domain_alerts.append({
                        "type": "ssl_expiry",
                        "severity": "warning",
                        "message": f"SSL certificate expires in {ssl_days} days",
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
