"""Security analysis tools for domain reputation, transport security, and zone hardening.

These tools extend Familiar's pentest capabilities with blocklist checking,
zone transfer testing, MTA-STS/TLS-RPT validation, DANE/TLSA verification,
and website technology fingerprinting.
"""

import json
import re

import seer
from langchain_core.tools import tool

from ..utils import parallel_calls, safe_call

# --- DNS-based blocklist providers ---
# Each entry: (name, zone_suffix, query_type, description)
# query_type: "ip" means reverse the IP octets, "domain" means prepend the domain directly
_BLOCKLISTS = [
    ("Spamhaus ZEN", "zen.spamhaus.org", "ip", "Combined Spamhaus IP blocklist (SBL+XBL+PBL)"),
    ("Spamhaus DBL", "dbl.spamhaus.org", "domain", "Spamhaus Domain Block List"),
    ("SURBL", "multi.surbl.org", "domain", "Spam URI Realtime Blocklist"),
    ("URIBL", "multi.uribl.com", "domain", "URI-based blocklist"),
    ("Barracuda", "b.barracudacentral.org", "ip", "Barracuda Reputation Block List"),
    ("SpamCop", "bl.spamcop.net", "ip", "SpamCop Blocking List"),
    ("CBL", "cbl.abuseat.org", "ip", "Composite Blocking List (malware/botnet)"),
    ("PSBL", "psbl.surriel.com", "ip", "Passive Spam Block List"),
    ("Mailspike", "bl.mailspike.net", "ip", "Mailspike IP reputation"),
    ("SORBS", "dnsbl.sorbs.net", "ip", "SORBS combined blocklist"),
]


def _reverse_ip(ip: str) -> str:
    """Reverse IP octets for DNSBL query (e.g. 1.2.3.4 -> 4.3.2.1)."""
    return ".".join(reversed(ip.split(".")))


def _extract_address(record) -> str:
    """Extract IP address string from a seer dig record."""
    if isinstance(record, dict):
        data = record.get("data", record)
        if isinstance(data, dict):
            return data.get("address", "")
        return str(data)
    return str(record)


@tool
def domain_reputation_check(domain: str) -> str:
    """Check a domain's reputation across DNS-based blocklists (DNSBL). Queries
    Spamhaus (ZEN+DBL), SURBL, URIBL, Barracuda, SpamCop, and others. Checks both
    the domain directly and its resolved IP addresses against IP-based blocklists."""
    domain = domain.lower().strip()

    # Step 1: Resolve the domain's A records to get IPs for IP-based blocklists
    a_records = safe_call(seer.dig, domain, "A") or []
    ips = []
    for rec in (a_records if isinstance(a_records, list) else []):
        addr = _extract_address(rec)
        if addr and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", addr):
            ips.append(addr)

    # Step 2: Build all DNSBL queries
    queries = []
    query_meta = []  # Track which blocklist and target each query maps to

    for name, zone, qtype, desc in _BLOCKLISTS:
        if qtype == "domain":
            query = f"{domain}.{zone}"
            queries.append((seer.dig, query, "A"))
            query_meta.append({"name": name, "zone": zone, "target": domain, "type": "domain", "description": desc})
        elif qtype == "ip":
            for ip in ips:
                query = f"{_reverse_ip(ip)}.{zone}"
                queries.append((seer.dig, query, "A"))
                query_meta.append({"name": name, "zone": zone, "target": ip, "type": "ip", "description": desc})

    # Step 3: Execute all queries concurrently
    results = parallel_calls(*queries) if queries else []

    # Step 4: Interpret results
    checks = []
    listed_count = 0

    for i, raw in enumerate(results):
        meta = query_meta[i]
        listed = False
        return_code = None

        if raw and isinstance(raw, list) and len(raw) > 0:
            addr = _extract_address(raw[0])
            if addr.startswith("127."):
                listed = True
                return_code = addr
                listed_count += 1

        checks.append({
            "blocklist": meta["name"],
            "description": meta["description"],
            "target": meta["target"],
            "query_type": meta["type"],
            "listed": listed,
            "return_code": return_code,
        })

    # Step 5: Determine overall status
    if listed_count == 0:
        overall_status = "clean"
        severity = "INFO"
    elif listed_count <= 2:
        overall_status = "listed"
        severity = "MEDIUM"
    else:
        overall_status = "widely_listed"
        severity = "HIGH"

    findings = []
    for check in checks:
        if check["listed"]:
            findings.append({
                "severity": "HIGH" if "spamhaus" in check["blocklist"].lower() else "MEDIUM",
                "finding": f"Listed on {check['blocklist']} ({check['query_type']} check: {check['target']})",
                "detail": f"{check['description']}. Return code: {check['return_code']}",
                "recommendation": f"Investigate listing at {check['blocklist']} and request delisting if legitimate",
            })

    return json.dumps({
        "domain": domain,
        "resolved_ips": ips,
        "overall_status": overall_status,
        "overall_severity": severity,
        "listed_count": listed_count,
        "total_checks": len(checks),
        "checks": checks,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)


SECURITY_TOOLS = [
    domain_reputation_check,
]
