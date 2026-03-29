"""Memory and watchlist tools for persistent domain knowledge."""

import atexit
import json
import threading
from datetime import datetime, timezone

import seer
from langchain_core.tools import tool

from ..memory import Memory
from ..utils import days_until as _days_until, parallel_calls, safe_call

# Module-level singleton, initialized lazily with double-checked locking
_memory: Memory | None = None
_memory_lock = threading.Lock()


def get_memory() -> Memory:
    """Get the shared Memory singleton. Registered for cleanup at process exit."""
    global _memory
    if _memory is None:
        with _memory_lock:
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

    _bs, _bl = parallel_calls(
        (seer.bulk_status, domains),
        (seer.bulk_lookup, domains),
    )
    bulk_status_raw = _bs if _bs is not None else [None] * len(domains)
    bulk_lookup_raw = _bl if _bl is not None else [None] * len(domains)

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
                    if days_left < 0:
                        domain_alerts.append({
                            "type": "expiration",
                            "severity": "critical",
                            "message": f"Expired {abs(days_left)} days ago ({expiry})",
                        })
                    elif days_left < 30:
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

        # HTTP + SSL checks — certificate info is nested under .certificate
        if st and isinstance(st, dict):
            http_unreachable = st.get("http_status") is None

            if http_unreachable:
                domain_alerts.append({
                    "type": "http",
                    "severity": "warning",
                    "message": "Domain is not responding to HTTP requests",
                })
                # SSL absence is a consequence of HTTP unreachability — don't
                # report it as a separate issue.
            else:
                cert = st.get("certificate")
                if cert and isinstance(cert, dict):
                    if not cert.get("is_valid", True):
                        domain_alerts.append({
                            "type": "ssl",
                            "severity": "critical",
                            "message": "SSL certificate is invalid or missing",
                        })
                    ssl_days = cert.get("days_until_expiry")
                    if ssl_days is not None and ssl_days < 0:
                        domain_alerts.append({
                            "type": "ssl_expiry",
                            "severity": "critical",
                            "message": f"SSL certificate expired {abs(ssl_days)} days ago",
                        })
                    elif ssl_days is not None and ssl_days < 14:
                        domain_alerts.append({
                            "type": "ssl_expiry",
                            "severity": "warning",
                            "message": f"SSL certificate expires in {ssl_days} days",
                        })
                elif cert is None:
                    domain_alerts.append({
                        "type": "ssl",
                        "severity": "warning",
                        "message": "No SSL certificate detected",
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

    # Run all lookups concurrently (all 6 calls are independent)
    reg_a, reg_b, dns_a, dns_b, status_a, status_b = parallel_calls(
        (seer.lookup, domain_a),
        (seer.lookup, domain_b),
        (seer.dig, domain_a, "A"),
        (seer.dig, domain_b, "A"),
        (seer.status, domain_a),
        (seer.status, domain_b),
    )
    comparison["registration"] = {"domain_a": reg_a, "domain_b": reg_b}
    comparison["dns_a_records"] = {"domain_a": dns_a, "domain_b": dns_b}
    comparison["status"] = {"domain_a": status_a, "domain_b": status_b}

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
            {"domain": d["domain"], "tags": d["tags"], "last_seen": d["last_seen"]}
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


# --- Snapshot Tools ---


@tool
def snapshot_domain(domain: str) -> str:
    """Capture a structured snapshot of a domain's current state: registration data,
    DNS nameservers, HTTP status, SSL validity, and DNSSEC status. Snapshots are stored
    persistently and can be compared with diff_snapshots to track changes over time."""
    domain = domain.lower().strip()

    # Gather current domain state concurrently
    lookup_data, status_data, ns_records, dnssec_data = parallel_calls(
        (seer.lookup, domain),
        (seer.status, domain),
        (seer.dig, domain, "NS"),
        (seer.dnssec, domain),
    )

    # Build snapshot data dict
    snapshot_data = {"domain": domain}

    # Registration data
    if lookup_data and isinstance(lookup_data, dict):
        inner = lookup_data.get("data", lookup_data)
        if isinstance(inner, dict):
            snapshot_data["registrar"] = inner.get("registrar")
            snapshot_data["expiration_date"] = inner.get("expiration_date") or inner.get("expiry")
            snapshot_data["creation_date"] = inner.get("creation_date") or inner.get("created")
            snapshot_data["source"] = lookup_data.get("source")

    # Nameservers
    if ns_records and isinstance(ns_records, list):
        ns_list = []
        for rec in ns_records:
            if isinstance(rec, dict):
                data = rec.get("data", rec)
                ns = data.get("nameserver", str(data)) if isinstance(data, dict) else str(data)
                ns_list.append(ns.rstrip("."))
        snapshot_data["nameservers"] = sorted(ns_list)

    # HTTP/SSL status
    if status_data and isinstance(status_data, dict):
        snapshot_data["http_status"] = status_data.get("http_status")
        cert = status_data.get("certificate")
        if cert and isinstance(cert, dict):
            snapshot_data["ssl_valid"] = cert.get("is_valid")
            snapshot_data["ssl_issuer"] = cert.get("issuer")
            snapshot_data["ssl_expiry"] = cert.get("expiry") or cert.get("not_after")
            snapshot_data["ssl_days_remaining"] = cert.get("days_until_expiry")

    # DNSSEC
    if dnssec_data and isinstance(dnssec_data, dict):
        snapshot_data["dnssec_status"] = dnssec_data.get("status")

    # Save the snapshot
    mem = get_memory()
    save_result = mem.save_snapshot(domain, snapshot_data)

    # Also auto-remember the domain in the notebook
    safe_call(mem.remember_domain, domain, "", "snapshot")

    return json.dumps(save_result, default=str)


@tool
def diff_snapshots(snapshot_id_a: int, snapshot_id_b: int) -> str:
    """Compare two domain snapshots by their IDs and show what changed. Use
    snapshot_domain first to capture snapshots at different times, then diff_snapshots
    to see registration, DNS, SSL, or other changes between them."""
    try:
        result = get_memory().diff_snapshots(int(snapshot_id_a), int(snapshot_id_b))
        return json.dumps(result, default=str)
    except (ValueError, TypeError) as e:
        return json.dumps({"error": str(e)})


@tool
def list_domain_snapshots(domain: str) -> str:
    """List all stored snapshots for a domain, most recent first. Each entry includes
    the snapshot ID (for use with diff_snapshots) and the capture timestamp."""
    snapshots = get_memory().list_snapshots(domain.lower().strip())
    return json.dumps({
        "domain": domain,
        "total": len(snapshots),
        "snapshots": [
            {"snapshot_id": s["snapshot_id"], "captured_at": s["captured_at"]}
            for s in snapshots
        ],
    }, default=str)


SNAPSHOT_TOOLS = [
    snapshot_domain,
    diff_snapshots,
    list_domain_snapshots,
]
