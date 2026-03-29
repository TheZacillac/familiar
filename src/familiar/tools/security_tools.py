"""Security analysis tools for domain reputation, transport security, and zone hardening.

These tools extend Familiar's pentest capabilities with blocklist checking,
zone transfer testing, MTA-STS/TLS-RPT validation, DANE/TLSA verification,
and website technology fingerprinting.
"""

import json
import re
import socket
import struct
from urllib.error import URLError
from urllib.request import Request, urlopen

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


def _extract_txt_value(record) -> str:
    """Extract text value from a seer dig TXT record."""
    if isinstance(record, dict):
        data = record.get("data", record)
        if isinstance(data, dict):
            return data.get("text", data.get("value", str(data)))
        return str(data)
    return str(record)


def _fetch_mta_sts_policy(domain: str, timeout: float = 5.0) -> dict:
    """Fetch the MTA-STS policy file from .well-known/mta-sts.txt."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        req = Request(url, headers={"User-Agent": "familiar/0.1"})
        with urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = resp.read(8192).decode("utf-8", errors="replace")
                return {"success": True, "policy": body.strip()}
            return {"success": False, "error": f"HTTP {resp.status}"}
    except URLError as e:
        return {"success": False, "error": str(e)}
    except OSError as e:
        return {"success": False, "error": str(e)}


@tool
def mta_sts_check(domain: str) -> str:
    """Check MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) configuration. MTA-STS
    enforces TLS for inbound email, preventing downgrade attacks. TLS-RPT enables
    reporting of TLS negotiation failures. Checks the _mta-sts TXT record, the
    .well-known/mta-sts.txt policy file, and the _smtp._tls TXT record."""
    domain = domain.lower().strip()

    # Fetch all DNS records and the policy file concurrently
    sts_txt, tlsrpt_txt, mx_records, policy_raw = parallel_calls(
        (seer.dig, f"_mta-sts.{domain}", "TXT"),
        (seer.dig, f"_smtp._tls.{domain}", "TXT"),
        (seer.dig, domain, "MX"),
        (_fetch_mta_sts_policy, domain),
    )

    findings = []
    has_mx = bool(mx_records and isinstance(mx_records, list) and len(mx_records) > 0)

    # --- MTA-STS TXT Record ---
    sts_txt_info = {"found": False}
    if sts_txt and isinstance(sts_txt, list):
        for rec in sts_txt:
            txt = _extract_txt_value(rec)
            if "v=stsv1" in txt.lower():
                sts_txt_info = {"found": True, "record": txt.strip()}
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("id="):
                        sts_txt_info["id"] = part.split("=", 1)[1].strip()
                break

    # --- MTA-STS Policy File ---
    sts_policy_info = {"found": False}
    if policy_raw and isinstance(policy_raw, dict) and policy_raw.get("success"):
        raw_policy = policy_raw["policy"]
        sts_policy_info["found"] = True
        sts_policy_info["raw"] = raw_policy

        for line in raw_policy.splitlines():
            line = line.strip()
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key == "mode":
                    sts_policy_info["mode"] = val
                elif key == "max_age":
                    sts_policy_info["max_age"] = val
                elif key == "mx":
                    sts_policy_info.setdefault("mx_patterns", []).append(val)

        mode = sts_policy_info.get("mode", "")
        if mode == "none":
            findings.append({
                "severity": "MEDIUM",
                "finding": "MTA-STS policy mode is 'none' — no enforcement",
                "detail": "Policy exists but does not enforce TLS for inbound email",
                "recommendation": "Set mode to 'testing' then 'enforce' after validating delivery",
            })
        elif mode == "testing":
            findings.append({
                "severity": "LOW",
                "finding": "MTA-STS policy mode is 'testing' — monitoring only",
                "detail": "TLS failures are reported but mail is still delivered over plaintext",
                "recommendation": "Upgrade to 'enforce' mode after confirming all MX servers support TLS",
            })

        max_age = sts_policy_info.get("max_age", "")
        try:
            if max_age and int(max_age) < 86400:
                findings.append({
                    "severity": "LOW",
                    "finding": f"MTA-STS max_age is short ({max_age}s / {int(max_age) // 3600}h)",
                    "detail": "Short max_age means senders must re-fetch the policy frequently",
                    "recommendation": "Consider max_age of at least 86400 (1 day), ideally 604800 (1 week)",
                })
        except ValueError:
            pass

    # --- Consistency checks ---
    if sts_txt_info["found"] and not sts_policy_info["found"]:
        findings.append({
            "severity": "HIGH",
            "finding": "MTA-STS TXT record exists but policy file is missing",
            "detail": f"The _mta-sts TXT record advertises STS, but https://mta-sts.{domain}/.well-known/mta-sts.txt is unreachable",
            "recommendation": "Publish the MTA-STS policy file at the .well-known URL on the mta-sts subdomain",
        })
    elif not sts_txt_info["found"] and sts_policy_info["found"]:
        findings.append({
            "severity": "HIGH",
            "finding": "MTA-STS policy file exists but TXT record is missing",
            "detail": f"Senders will not discover the policy without the _mta-sts TXT record",
            "recommendation": f"Add a TXT record at _mta-sts.{domain} with v=STSv1; id=<unique-id>",
        })
    elif not sts_txt_info["found"] and not sts_policy_info["found"] and has_mx:
        findings.append({
            "severity": "MEDIUM",
            "finding": "No MTA-STS configured for domain with MX records",
            "detail": "Without MTA-STS, email can be delivered over unencrypted connections (STARTTLS downgrade)",
            "recommendation": f"Deploy MTA-STS: add _mta-sts TXT record and publish policy at .well-known/mta-sts.txt",
        })

    # --- TLS-RPT Record ---
    tlsrpt_info = {"found": False}
    if tlsrpt_txt and isinstance(tlsrpt_txt, list):
        for rec in tlsrpt_txt:
            txt = _extract_txt_value(rec)
            if "v=tlsrptv1" in txt.lower():
                tlsrpt_info = {"found": True, "record": txt.strip()}
                for part in txt.split(";"):
                    part = part.strip()
                    if part.lower().startswith("rua="):
                        tlsrpt_info["reporting_uri"] = part.split("=", 1)[1].strip()
                break

    if not tlsrpt_info["found"] and has_mx:
        findings.append({
            "severity": "LOW",
            "finding": "No TLS-RPT (RFC 8460) record configured",
            "detail": "Without TLS-RPT, you won't receive reports about TLS negotiation failures for inbound email",
            "recommendation": f"Add a TXT record at _smtp._tls.{domain} with v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
        })

    return json.dumps({
        "domain": domain,
        "has_mx": has_mx,
        "mta_sts": {
            "txt_record": sts_txt_info,
            "policy": sts_policy_info,
        },
        "tls_rpt": tlsrpt_info,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)


# DANE TLSA usage field descriptions
_TLSA_USAGE = {
    0: "CA constraint (PKIX-TA) — certificate must chain to specified CA",
    1: "Service certificate constraint (PKIX-EE) — must match leaf cert + pass PKIX validation",
    2: "Trust anchor assertion (DANE-TA) — specified cert is trust anchor (no PKIX required)",
    3: "Domain-issued certificate (DANE-EE) — must match leaf cert exactly (no PKIX required)",
}

_TLSA_SELECTOR = {
    0: "Full certificate",
    1: "SubjectPublicKeyInfo (public key only)",
}

_TLSA_MATCHING = {
    0: "Exact match (no hash)",
    1: "SHA-256 hash",
    2: "SHA-512 hash",
}


@tool
def dane_tlsa_check(domain: str, port: int = 443) -> str:
    """Check DANE TLSA records (RFC 6698/7671) for a domain and port. DANE binds
    TLS certificates to DNS via DNSSEC, preventing CA compromise attacks. Checks
    _<port>._tcp.<domain> for TLSA records and validates against the actual
    certificate. Common ports: 443 (HTTPS), 25 (SMTP), 587 (submission)."""
    domain = domain.lower().strip()
    port = int(port)

    tlsa_name = f"_{port}._tcp.{domain}"

    # Fetch TLSA records, DNSSEC status, and the actual certificate concurrently
    tlsa_records, dnssec_data, ssl_data = parallel_calls(
        (seer.dig, tlsa_name, "TLSA"),
        (seer.dnssec, domain),
        (seer.ssl, domain),
    )

    findings = []

    # --- Parse TLSA records ---
    parsed_tlsa = []
    if tlsa_records and isinstance(tlsa_records, list):
        for rec in tlsa_records:
            if isinstance(rec, dict):
                data = rec.get("data", rec)
                if isinstance(data, dict):
                    usage = data.get("usage", data.get("certificate_usage"))
                    selector = data.get("selector")
                    matching = data.get("matching_type")
                    cert_data = data.get("certificate_data", data.get("certificate_association_data", ""))

                    entry = {
                        "usage": usage,
                        "usage_description": _TLSA_USAGE.get(usage, f"Unknown ({usage})"),
                        "selector": selector,
                        "selector_description": _TLSA_SELECTOR.get(selector, f"Unknown ({selector})"),
                        "matching_type": matching,
                        "matching_description": _TLSA_MATCHING.get(matching, f"Unknown ({matching})"),
                        "certificate_data": str(cert_data)[:64] + ("..." if len(str(cert_data)) > 64 else ""),
                    }
                    parsed_tlsa.append(entry)

                    if usage in (0, 1):
                        findings.append({
                            "severity": "INFO",
                            "finding": f"TLSA usage {usage} (PKIX-based) — requires both DANE match and CA validation",
                            "detail": _TLSA_USAGE.get(usage, ""),
                            "recommendation": "Ensure the certificate chain satisfies both PKIX and DANE constraints",
                        })
                    elif usage == 3:
                        findings.append({
                            "severity": "INFO",
                            "finding": "TLSA usage 3 (DANE-EE) — strongest DANE mode, bypasses CA system",
                            "detail": "The leaf certificate must match the TLSA record exactly. PKIX validation is not required.",
                            "recommendation": "Update the TLSA record whenever the certificate is renewed",
                        })

                    if matching == 0:
                        findings.append({
                            "severity": "LOW",
                            "finding": "TLSA uses full certificate match (matching type 0) instead of a hash",
                            "detail": "Full certificate data in DNS increases record size and is less common",
                            "recommendation": "Consider SHA-256 (matching type 1) for smaller, more standard TLSA records",
                        })

    dane_configured = len(parsed_tlsa) > 0

    # --- DNSSEC dependency ---
    dnssec_ok = False
    if dnssec_data and isinstance(dnssec_data, dict):
        dnssec_status = dnssec_data.get("status", "unknown")
        dnssec_ok = dnssec_status == "secure"
        if dane_configured and not dnssec_ok:
            findings.append({
                "severity": "CRITICAL",
                "finding": "DANE TLSA records exist but DNSSEC is not fully validated",
                "detail": f"DNSSEC status: {dnssec_status}. DANE requires a secure DNSSEC chain to prevent "
                          "spoofed TLSA records from being used in MitM attacks.",
                "recommendation": "Enable and validate DNSSEC before relying on DANE for certificate pinning",
            })

    if dane_configured and dnssec_ok:
        findings.append({
            "severity": "INFO",
            "finding": "DANE is properly configured with DNSSEC validation",
            "detail": "TLSA records are protected by a secure DNSSEC chain",
            "recommendation": "Maintain DNSSEC signing and update TLSA records on certificate renewal",
        })

    # --- Certificate info ---
    cert_info = {}
    if ssl_data and isinstance(ssl_data, dict):
        chain = ssl_data.get("chain", [])
        if chain and isinstance(chain, list) and isinstance(chain[0], dict):
            leaf = chain[0]
            cert_info = {
                "subject": leaf.get("subject"),
                "issuer": leaf.get("issuer"),
                "key_type": leaf.get("key_type"),
                "key_bits": leaf.get("key_bits"),
                "valid_until": leaf.get("valid_until"),
                "is_valid": ssl_data.get("is_valid", False),
            }

    if not dane_configured:
        findings.append({
            "severity": "INFO",
            "finding": f"No DANE TLSA records at {tlsa_name}",
            "detail": "DANE is not configured for this domain/port combination",
            "recommendation": "Consider adding DANE TLSA records if DNSSEC is enabled — provides certificate "
                              "pinning independent of the CA system",
        })

    return json.dumps({
        "domain": domain,
        "port": port,
        "tlsa_name": tlsa_name,
        "dane_configured": dane_configured,
        "dnssec_validated": dnssec_ok,
        "tlsa_records": parsed_tlsa,
        "certificate": cert_info,
        "findings": sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f["severity"])),
    }, default=str)


# Technology fingerprint patterns: (header_field, pattern, tech_name, category)
_TECH_FINGERPRINTS = [
    # Web servers
    ("server", r"nginx", "nginx", "Web Server"),
    ("server", r"apache", "Apache", "Web Server"),
    ("server", r"cloudflare", "Cloudflare", "CDN/Web Server"),
    ("server", r"microsoft-iis", "IIS", "Web Server"),
    ("server", r"litespeed", "LiteSpeed", "Web Server"),
    ("server", r"caddy", "Caddy", "Web Server"),
    ("server", r"openresty", "OpenResty", "Web Server"),
    ("server", r"gunicorn", "Gunicorn", "WSGI Server"),
    ("server", r"uvicorn", "Uvicorn", "ASGI Server"),
    ("server", r"cowboy", "Cowboy (Erlang)", "Web Server"),
    # Languages/runtimes
    ("x-powered-by", r"php", "PHP", "Language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "Framework"),
    ("x-powered-by", r"express", "Express.js", "Framework"),
    ("x-powered-by", r"next\.js", "Next.js", "Framework"),
    ("x-powered-by", r"nuxt", "Nuxt.js", "Framework"),
    # CMS platforms
    ("x-powered-by", r"wordpress", "WordPress", "CMS"),
    ("x-powered-by", r"drupal", "Drupal", "CMS"),
    ("x-generator", r"wordpress", "WordPress", "CMS"),
    ("x-generator", r"drupal", "Drupal", "CMS"),
    ("x-generator", r"joomla", "Joomla", "CMS"),
    ("x-generator", r"hugo", "Hugo", "Static Site Generator"),
    ("x-generator", r"gatsby", "Gatsby", "Static Site Generator"),
    ("x-generator", r"astro", "Astro", "Static Site Generator"),
    # CDN/proxy
    ("x-served-by", r"cache", "Varnish/CDN Cache", "Caching"),
    ("x-cache", r".", "CDN Cache Layer", "Caching"),
    ("cf-ray", r".", "Cloudflare", "CDN"),
    ("x-vercel-id", r".", "Vercel", "Platform"),
    ("x-netlify", r".", "Netlify", "Platform"),
    ("x-amz-cf-id", r".", "AWS CloudFront", "CDN"),
    ("x-azure-ref", r".", "Azure Front Door", "CDN"),
    # Security headers
    ("x-xss-protection", r".", "XSS Protection Header", "Security Header"),
    ("x-content-type-options", r"nosniff", "X-Content-Type-Options", "Security Header"),
    ("strict-transport-security", r".", "HSTS", "Security Header"),
    ("content-security-policy", r".", "CSP", "Security Header"),
    ("permissions-policy", r".", "Permissions-Policy", "Security Header"),
    ("referrer-policy", r".", "Referrer-Policy", "Security Header"),
]

# Cookie-based CMS detection patterns
_COOKIE_FINGERPRINTS = [
    (r"wp_", "WordPress", "CMS"),
    (r"wordpress", "WordPress", "CMS"),
    (r"drupal", "Drupal", "CMS"),
    (r"joomla", "Joomla", "CMS"),
    (r"laravel_session", "Laravel", "Framework"),
    (r"django", "Django", "Framework"),
    (r"rails", "Ruby on Rails", "Framework"),
    (r"phpsessid", "PHP", "Language"),
    (r"jsessionid", "Java", "Language"),
    (r"asp\.net", "ASP.NET", "Framework"),
    (r"__cfduid|__cf_bm", "Cloudflare", "CDN"),
    (r"incap_ses", "Imperva/Incapsula", "WAF"),
    (r"visid_incap", "Imperva/Incapsula", "WAF"),
    (r"akamai", "Akamai", "CDN"),
]


def _fetch_http_headers(domain: str, timeout: float = 8.0) -> dict:
    """Fetch HTTP response headers from a domain via HEAD request."""
    url = f"https://{domain}/"
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "familiar/0.1"})
        with urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"success": True, "status_code": resp.status, "headers": headers}
    except Exception:
        # Retry with HTTP if HTTPS fails
        try:
            url = f"http://{domain}/"
            req = Request(url, method="HEAD", headers={"User-Agent": "familiar/0.1"})
            with urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return {"success": True, "status_code": resp.status, "headers": headers}
        except Exception as e:
            return {"success": False, "error": str(e)}


@tool
def website_fingerprint(domain: str) -> str:
    """Identify web technologies, CMS platforms, frameworks, CDN providers, and
    security headers by analyzing HTTP response headers and cookies. Detects
    server software, language/runtime, CMS, caching layers, and security posture."""
    domain = domain.lower().strip()

    # Fetch HTTP headers and DNS data concurrently
    header_data, cname_records, txt_records = parallel_calls(
        (_fetch_http_headers, domain),
        (seer.dig, domain, "CNAME"),
        (seer.dig, domain, "TXT"),
    )

    technologies = []
    seen_techs = set()  # Deduplicate

    def _add_tech(name, category, evidence, confidence="high"):
        key = f"{name}:{category}"
        if key not in seen_techs:
            seen_techs.add(key)
            technologies.append({
                "name": name,
                "category": category,
                "evidence": evidence,
                "confidence": confidence,
            })

    security_headers = {}
    raw_headers = {}

    if header_data and isinstance(header_data, dict) and header_data.get("success"):
        headers = header_data.get("headers", {})
        raw_headers = dict(headers)

        # Header-based detection
        for header_field, pattern, tech_name, category in _TECH_FINGERPRINTS:
            value = headers.get(header_field, "")
            if value and re.search(pattern, value, re.IGNORECASE):
                if category == "Security Header":
                    security_headers[tech_name] = value
                else:
                    version_match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", value)
                    evidence = f"{header_field}: {value[:100]}"
                    _add_tech(
                        f"{tech_name}/{version_match.group()}" if version_match else tech_name,
                        category,
                        evidence,
                    )

        # Cookie-based detection
        cookies = headers.get("set-cookie", "")
        for pattern, tech_name, category in _COOKIE_FINGERPRINTS:
            if re.search(pattern, cookies, re.IGNORECASE):
                _add_tech(tech_name, category, f"Cookie pattern: {pattern}", confidence="medium")

    # DNS-based detection (CNAME fingerprinting)
    if cname_records and isinstance(cname_records, list):
        for rec in cname_records:
            if isinstance(rec, dict):
                data = rec.get("data", rec)
                target = ""
                if isinstance(data, dict):
                    target = data.get("target", data.get("cname", "")).lower().rstrip(".")
                else:
                    target = str(data).lower().rstrip(".")

                if "shopify" in target:
                    _add_tech("Shopify", "E-Commerce Platform", f"CNAME → {target}")
                elif "squarespace" in target:
                    _add_tech("Squarespace", "Website Builder", f"CNAME → {target}")
                elif "wixdns" in target or "wixsite" in target:
                    _add_tech("Wix", "Website Builder", f"CNAME → {target}")
                elif "ghost.io" in target:
                    _add_tech("Ghost", "CMS", f"CNAME → {target}")
                elif "webflow" in target:
                    _add_tech("Webflow", "Website Builder", f"CNAME → {target}")
                elif "github.io" in target:
                    _add_tech("GitHub Pages", "Hosting", f"CNAME → {target}")
                elif "netlify" in target:
                    _add_tech("Netlify", "Platform", f"CNAME → {target}")
                elif "vercel" in target:
                    _add_tech("Vercel", "Platform", f"CNAME → {target}")

    # TXT-based technology detection
    if txt_records and isinstance(txt_records, list):
        for rec in txt_records:
            txt = _extract_txt_value(rec)
            txt_lower = txt.lower()
            if "google-site-verification" in txt_lower:
                _add_tech("Google Search Console", "SEO/Analytics", "TXT verification record", confidence="medium")
            elif re.match(r"ms=ms\d", txt_lower):
                _add_tech("Microsoft 365", "Email/Productivity", "TXT verification record", confidence="medium")
            elif "facebook-domain-verification" in txt_lower:
                _add_tech("Meta/Facebook", "Advertising", "TXT verification record", confidence="medium")
            elif "apple-domain-verification" in txt_lower:
                _add_tech("Apple", "Platform", "TXT verification record", confidence="medium")
            elif "atlassian-domain-verification" in txt_lower:
                _add_tech("Atlassian", "Productivity", "TXT verification record", confidence="medium")
            elif "docusign" in txt_lower:
                _add_tech("DocuSign", "Business Tool", "TXT verification record", confidence="medium")

    return json.dumps({
        "domain": domain,
        "technologies": technologies,
        "security_headers": security_headers,
        "security_header_count": len(security_headers),
        "total_technologies": len(technologies),
        "headers_available": bool(raw_headers),
    }, default=str)


SECURITY_TOOLS = [
    domain_reputation_check,
    zone_transfer_test,
    mta_sts_check,
    dane_tlsa_check,
    website_fingerprint,
]
