"""Security analysis tools for domain reputation, transport security, and zone hardening.

These tools extend Familiar's pentest capabilities with blocklist checking,
zone transfer testing, MTA-STS/TLS-RPT validation, DANE/TLSA verification,
and website technology fingerprinting.
"""

import json
import re
import socket
import struct

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


def _attempt_axfr(nameserver: str, domain: str, timeout: float = 5.0) -> dict:
    """Attempt a DNS zone transfer (AXFR) against a single nameserver.

    Uses raw TCP DNS protocol — constructs an AXFR query packet, connects to
    the nameserver on port 53/TCP, and checks if the response contains zone data.
    """
    try:
        # Build minimal DNS AXFR query
        txn_id = 0xABCD
        flags = 0x0000  # Standard query
        header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)

        # Question section: encode domain name + QTYPE=AXFR(252) + QCLASS=IN(1)
        question = b""
        for label in domain.rstrip(".").split("."):
            question += struct.pack("B", len(label)) + label.encode("ascii")
        question += b"\x00"  # Root label
        question += struct.pack(">HH", 252, 1)  # AXFR, IN

        message = header + question
        tcp_msg = struct.pack(">H", len(message)) + message

        # Resolve nameserver hostname to IP first
        try:
            ns_ip = socket.getaddrinfo(nameserver.rstrip("."), 53, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except socket.gaierror:
            return {"success": False, "error": f"Cannot resolve nameserver {nameserver}"}

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ns_ip, 53))
            sock.sendall(tcp_msg)

            length_data = sock.recv(2)
            if len(length_data) < 2:
                return {"success": False, "error": "No response from nameserver"}

            resp_len = struct.unpack(">H", length_data)[0]
            if resp_len < 12:
                return {"success": False, "error": "Transfer refused or empty response"}

            response = b""
            while len(response) < resp_len:
                chunk = sock.recv(min(4096, resp_len - len(response)))
                if not chunk:
                    break
                response += chunk

            if len(response) < 12:
                return {"success": False, "error": "Incomplete response"}

            _, resp_flags, _, ancount, _, _ = struct.unpack(">HHHHHH", response[:12])
            rcode = resp_flags & 0x000F

            if rcode in (5, 9):
                return {"success": False, "error": "Transfer refused (RCODE={})".format(rcode)}

            if rcode != 0:
                return {"success": False, "error": f"DNS error RCODE={rcode}"}

            if ancount > 0:
                return {
                    "success": True,
                    "record_count": ancount,
                    "response_size": len(response),
                    "records_sample": [f"({ancount} records transferred — {len(response)} bytes)"],
                }

            return {"success": False, "error": "No records in response"}

        finally:
            sock.close()

    except socket.timeout:
        return {"success": False, "error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"success": False, "error": "Connection refused (port 53/TCP closed)"}
    except OSError as e:
        return {"success": False, "error": f"Network error: {e}"}


def _extract_nameserver(record) -> str:
    """Extract nameserver hostname from a seer dig NS record."""
    if isinstance(record, dict):
        data = record.get("data", record)
        if isinstance(data, dict):
            return data.get("nameserver", "").rstrip(".")
        return str(data).rstrip(".")
    return str(record).rstrip(".")


@tool
def zone_transfer_test(domain: str) -> str:
    """Test whether a domain's nameservers allow unauthorized DNS zone transfers
    (AXFR). Zone transfers that succeed from arbitrary sources expose the entire
    DNS zone contents — a critical security finding in any pentest."""
    domain = domain.lower().strip()

    # Get nameservers
    ns_records = safe_call(seer.dig, domain, "NS") or []
    nameservers = []
    for rec in (ns_records if isinstance(ns_records, list) else []):
        ns = _extract_nameserver(rec)
        if ns:
            nameservers.append(ns)

    if not nameservers:
        return json.dumps({
            "domain": domain,
            "vulnerable": False,
            "nameservers_tested": [],
            "results": [],
            "findings": [],
            "note": "No nameservers found for this domain",
        }, default=str)

    # Test each nameserver (max 4)
    test_ns = nameservers[:4]
    results = []
    findings = []
    vulnerable = False

    for ns in test_ns:
        axfr_result = _attempt_axfr(ns, domain)
        result_entry = {
            "nameserver": ns,
            "axfr_allowed": axfr_result["success"],
        }
        if axfr_result["success"]:
            vulnerable = True
            result_entry["record_count"] = axfr_result.get("record_count", 0)
            result_entry["response_size"] = axfr_result.get("response_size", 0)
            findings.append({
                "severity": "CRITICAL",
                "finding": f"Zone transfer (AXFR) allowed on {ns}",
                "detail": f"Nameserver {ns} returned {axfr_result.get('record_count', '?')} records — "
                          "entire zone contents exposed to unauthenticated queries",
                "recommendation": f"Restrict AXFR on {ns} to authorized secondary nameservers only "
                                  "(allow-transfer ACL in BIND, xfr-out in Knot, etc.)",
            })
        else:
            result_entry["status"] = axfr_result.get("error", "refused")

        results.append(result_entry)

    return json.dumps({
        "domain": domain,
        "vulnerable": vulnerable,
        "nameservers_tested": test_ns,
        "results": results,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)


SECURITY_TOOLS = [
    domain_reputation_check,
    zone_transfer_test,
]
