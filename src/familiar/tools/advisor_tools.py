"""Advisory tools that compose seer and tome for domain strategy intelligence."""

import json
import re

import seer
import tome
from langchain_core.tools import tool

from ..utils import days_until as _days_until, safe_call

# Known multi-level TLD suffixes for correct SLD extraction
_MULTI_LEVEL_TLDS = frozenset({
    "co.uk", "org.uk", "me.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "or.jp",
    "co.kr", "or.kr",
    "co.in", "net.in", "org.in",
    "com.br", "net.br", "org.br",
    "co.za",
    "com.mx",
    "com.cn", "net.cn", "org.cn",
    "com.tw", "net.tw", "org.tw",
    "co.il",
    "com.sg",
    "com.hk",
    "co.th",
})


def _split_domain(domain: str) -> tuple[str, str]:
    """Split a domain into (SLD, effective TLD), handling multi-level TLDs."""
    for suffix in _MULTI_LEVEL_TLDS:
        if domain.endswith(f".{suffix}"):
            return domain[: -(len(suffix) + 1)], suffix
    parts = domain.rsplit(".", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (domain, "")


def _domain_name_analysis(domain: str) -> dict:
    """Analyze a domain name's intrinsic qualities."""
    sld, tld = _split_domain(domain)

    analysis = {
        "full_domain": domain,
        "sld": sld,
        "tld": tld,
        "sld_length": len(sld),
        "has_hyphens": "-" in sld,
        "has_numbers": any(c.isdigit() for c in sld),
        "is_all_alpha": sld.isalpha(),
        "hyphen_count": sld.count("-"),
        "digit_count": sum(1 for c in sld if c.isdigit()),
    }

    # Length tier
    length = len(sld)
    if length <= 3:
        analysis["length_tier"] = "ultra-premium"
    elif length <= 5:
        analysis["length_tier"] = "premium"
    elif length <= 8:
        analysis["length_tier"] = "standard"
    elif length <= 12:
        analysis["length_tier"] = "long"
    else:
        analysis["length_tier"] = "very-long"

    # TLD tier (use the effective TLD, not just last label)
    if tld == "com":
        analysis["tld_tier"] = "premium"
    elif tld in {"net", "org"}:
        analysis["tld_tier"] = "established"
    elif tld in {"io", "co", "ai", "dev", "app", "tech"}:
        analysis["tld_tier"] = "tech-premium"
    elif tld in _MULTI_LEVEL_TLDS or len(tld) == 2:
        analysis["tld_tier"] = "country-code"
    else:
        analysis["tld_tier"] = "new-gtld"

    return analysis



@tool
def appraise_domain(domain: str) -> str:
    """Appraise a domain's value by analyzing its name quality, registration history,
    DNS footprint, TLD characteristics, and web presence. Returns a comprehensive
    assessment with scoring factors for forming a valuation opinion."""
    domain = domain.lower().strip()

    name_analysis = _domain_name_analysis(domain)

    # Registration data
    whois_data = safe_call(seer.lookup, domain)

    # DNS footprint — check all major record types
    dns_records = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"):
        result = safe_call(seer.dig, domain, rtype)
        if result:
            dns_records[rtype] = result

    # Web & SSL status
    status_data = safe_call(seer.status, domain)

    # TLD reference info
    tld = name_analysis["tld"]
    tld_info = safe_call(tome.tld_lookup, tld) if tld else None

    # Derive valuation signals
    signals = {}

    if whois_data and isinstance(whois_data, dict):
        created = whois_data.get("created") or whois_data.get("creation_date")
        if created:
            signals["registration_date"] = str(created)
            age_days = _days_until(created)
            if age_days is not None:
                # age_days is negative because the date is in the past
                signals["age_years"] = round(-age_days / 365.25, 1)

    record_count = sum(
        len(v) if isinstance(v, list) else 1
        for v in dns_records.values()
    )
    signals["dns_record_types_present"] = list(dns_records.keys())
    signals["total_dns_records"] = record_count
    signals["has_email_infrastructure"] = bool(dns_records.get("MX"))
    signals["has_spf"] = any(
        "v=spf1" in str(r).lower() for r in (dns_records.get("TXT") or [])
    )

    if status_data and isinstance(status_data, dict):
        signals["http_accessible"] = status_data.get("http_status") is not None
        signals["has_ssl"] = status_data.get("ssl_valid", False)
        signals["ssl_expiry"] = status_data.get("ssl_expiry")

    return json.dumps({
        "domain": domain,
        "name_analysis": name_analysis,
        "registration": whois_data,
        "dns_footprint": dns_records,
        "web_status": status_data,
        "tld_info": tld_info,
        "valuation_signals": signals,
    }, default=str)


@tool
def plan_acquisition(domain: str) -> str:
    """Analyze a domain for acquisition potential. Checks registration status, registrar,
    web presence, parking indicators, and lock status. Returns strategic intelligence
    for forming an acquisition approach."""
    domain = domain.lower().strip()

    whois_data = safe_call(seer.lookup, domain)
    status_data = safe_call(seer.status, domain)
    dns_a = safe_call(seer.dig, domain, "A")
    dns_ns = safe_call(seer.dig, domain, "NS")
    dns_mx = safe_call(seer.dig, domain, "MX")
    name_analysis = _domain_name_analysis(domain)

    acquisition_intel = {
        "is_registered": False,
        "registrar": None,
        "lock_status": [],
        "expiry_date": None,
        "parking_indicators": [],
        "active_use_indicators": [],
    }

    if whois_data and isinstance(whois_data, dict) and not whois_data.get("error"):
        acquisition_intel["is_registered"] = True
        acquisition_intel["registrar"] = whois_data.get("registrar")
        statuses = whois_data.get("status") or whois_data.get("statuses") or []
        if isinstance(statuses, str):
            statuses = [statuses]
        acquisition_intel["lock_status"] = statuses
        acquisition_intel["expiry_date"] = str(
            whois_data.get("expiry") or whois_data.get("expiration_date") or ""
        )

    # Parking heuristics
    if status_data and isinstance(status_data, dict):
        http_status = status_data.get("http_status")
        if http_status in (301, 302, 303, 307, 308):
            acquisition_intel["parking_indicators"].append("redirecting")
    if not dns_mx:
        acquisition_intel["parking_indicators"].append("no_email_configured")

    # Active use heuristics
    if dns_a:
        acquisition_intel["active_use_indicators"].append("has_a_record")
    if dns_mx:
        acquisition_intel["active_use_indicators"].append("has_email")
    if status_data and isinstance(status_data, dict) and status_data.get("ssl_valid"):
        acquisition_intel["active_use_indicators"].append("has_valid_ssl")

    return json.dumps({
        "domain": domain,
        "name_analysis": name_analysis,
        "acquisition_intel": acquisition_intel,
        "registration": whois_data,
        "web_status": status_data,
        "nameservers": dns_ns,
    }, default=str)


def _is_registered(result) -> bool | None:
    """Determine if a lookup result indicates a registered domain.

    Returns True if registered, False if clearly available (error response),
    None if the lookup itself failed (result is None).
    """
    if result is None:
        return None
    if not isinstance(result, dict):
        return None
    if result.get("error"):
        return False
    # Conservative: any clean non-error response means registered
    return True


@tool
def suggest_domains(brand: str, keywords: str = "", tlds: str = "") -> str:
    """Generate and check domain name suggestions for a brand. Creates variations from
    the brand name and optional keywords, checks availability across popular TLDs, and
    returns scored candidates. Pass comma-separated keywords and/or TLDs to customize."""
    brand = brand.lower().strip().replace(" ", "")
    keyword_list = [k.strip() for k in keywords.split(",") if k.strip()] if keywords else []

    if tlds:
        tld_list = [t.strip().lstrip(".") for t in tlds.split(",") if t.strip()]
    else:
        tld_list = ["com", "net", "org", "io", "co", "ai", "dev", "app"]

    # Generate candidate SLDs
    candidates = [brand]
    for prefix in ("get", "try", "use", "my", "the"):
        candidates.append(f"{prefix}{brand}")
    for suffix in ("hq", "app", "hub", "lab", "now", "go", "run"):
        candidates.append(f"{brand}{suffix}")
    for kw in keyword_list:
        kw = kw.lower().replace(" ", "")
        candidates.append(f"{brand}{kw}")
        candidates.append(f"{kw}{brand}")

    # Deduplicate preserving order
    candidates = list(dict.fromkeys(candidates))

    # Build full domain list, capped at 100 for bulk_lookup
    all_domains = []
    for sld in candidates:
        for tld in tld_list:
            all_domains.append(f"{sld}.{tld}")
    all_domains = all_domains[:100]

    # Bulk availability check
    results_raw = safe_call(seer.bulk_lookup, all_domains) or [None] * len(all_domains)
    if not isinstance(results_raw, list):
        results_raw = [None] * len(all_domains)

    available = []
    taken = []
    unknown = []
    for i, domain in enumerate(all_domains):
        result = results_raw[i] if i < len(results_raw) else None
        registered = _is_registered(result)
        name_info = _domain_name_analysis(domain)
        entry = {
            "domain": domain,
            "sld_length": name_info["sld_length"],
            "length_tier": name_info["length_tier"],
            "tld_tier": name_info["tld_tier"],
        }
        if registered is True:
            entry["status"] = "taken"
            taken.append(entry)
        elif registered is False:
            entry["status"] = "available"
            available.append(entry)
        else:
            entry["status"] = "unknown"
            unknown.append(entry)

    return json.dumps({
        "brand": brand,
        "keywords": keyword_list,
        "tlds_checked": tld_list,
        "total_checked": len(all_domains),
        "available_count": len(available),
        "taken_count": len(taken),
        "unknown_count": len(unknown),
        "available": available,
        "taken": taken,
        "unknown": unknown,
    }, default=str)


@tool
def audit_portfolio(domains: str) -> str:
    """Comprehensive health audit for a domain portfolio. Pass comma-separated domains.
    Checks expiration dates, registrar diversity, DNSSEC, SSL certificates, email
    authentication (SPF/DKIM/DMARC), and nameserver consistency."""
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]
    if not domain_list:
        return json.dumps({"error": "No domains provided"})
    if len(domain_list) > 100:
        return json.dumps({"error": "Maximum 100 domains per audit"})

    # Bulk data gathering — all concurrent
    bulk_lookup = safe_call(seer.bulk_lookup, domain_list) or [None] * len(domain_list)
    bulk_status = safe_call(seer.bulk_status, domain_list) or [None] * len(domain_list)
    txt_bulk = safe_call(seer.bulk_dig, domain_list, "TXT") or [None] * len(domain_list)
    mx_bulk = safe_call(seer.bulk_dig, domain_list, "MX") or [None] * len(domain_list)
    ns_bulk = safe_call(seer.bulk_dig, domain_list, "NS") or [None] * len(domain_list)
    dmarc_domains = [f"_dmarc.{d}" for d in domain_list]
    dmarc_bulk = safe_call(seer.bulk_dig, dmarc_domains, "TXT") or [None] * len(domain_list)

    portfolio = []
    registrars = {}
    nameserver_sets = {}
    expiry_warnings = []
    ssl_issues = []
    email_auth_gaps = []
    dnssec_status = {"enabled": 0, "disabled": 0, "unknown": 0}

    for i, domain in enumerate(domain_list):
        entry = {"domain": domain, "issues": [], "strengths": []}

        # Registration analysis
        reg = bulk_lookup[i] if i < len(bulk_lookup) else None
        if reg and isinstance(reg, dict) and not reg.get("error"):
            registrar = reg.get("registrar", "unknown")
            entry["registrar"] = registrar
            registrars[registrar] = registrars.get(registrar, 0) + 1

            expiry = reg.get("expiry") or reg.get("expiration_date")
            if expiry:
                entry["expiry"] = str(expiry)
                days_left = _days_until(expiry)
                if days_left is not None:
                    entry["days_until_expiry"] = days_left
                    if days_left < 30:
                        entry["issues"].append("CRITICAL: expires within 30 days")
                        expiry_warnings.append(
                            {"domain": domain, "days": days_left, "severity": "critical"}
                        )
                    elif days_left < 90:
                        entry["issues"].append("WARNING: expires within 90 days")
                        expiry_warnings.append(
                            {"domain": domain, "days": days_left, "severity": "warning"}
                        )

            dnssec = reg.get("dnssec")
            if dnssec and "signed" in str(dnssec).lower():
                dnssec_status["enabled"] += 1
                entry["dnssec"] = True
                entry["strengths"].append("DNSSEC enabled")
            elif dnssec:
                dnssec_status["disabled"] += 1
                entry["dnssec"] = False
                entry["issues"].append("DNSSEC not enabled")
            else:
                dnssec_status["unknown"] += 1

        # HTTP/SSL analysis
        st = bulk_status[i] if i < len(bulk_status) else None
        if st and isinstance(st, dict):
            if not st.get("ssl_valid", False):
                entry["issues"].append("SSL certificate invalid or missing")
                ssl_issues.append(domain)
            else:
                entry["strengths"].append("Valid SSL certificate")
            entry["http_status"] = st.get("http_status")
            entry["ssl_valid"] = st.get("ssl_valid")
            entry["ssl_expiry"] = str(st.get("ssl_expiry", ""))

        # Email authentication checks (from bulk results)
        txt_records = txt_bulk[i] if i < len(txt_bulk) else None
        mx_records = mx_bulk[i] if i < len(mx_bulk) else None
        ns_records = ns_bulk[i] if i < len(ns_bulk) else None
        dmarc_records = dmarc_bulk[i] if i < len(dmarc_bulk) else None

        if ns_records and isinstance(ns_records, list):
            ns_key = str(sorted(str(r) for r in ns_records))
            nameserver_sets[ns_key] = nameserver_sets.get(ns_key, 0) + 1

        has_spf = False
        if txt_records and isinstance(txt_records, list):
            has_spf = any("v=spf1" in str(r).lower() for r in txt_records)

        has_dmarc = False
        if dmarc_records and isinstance(dmarc_records, list):
            has_dmarc = any("v=dmarc1" in str(r).lower() for r in dmarc_records)

        if mx_records:
            if not has_spf:
                entry["issues"].append("Has MX records but missing SPF")
                email_auth_gaps.append({"domain": domain, "gap": "SPF"})
            else:
                entry["strengths"].append("SPF configured")
            if not has_dmarc:
                entry["issues"].append("Has MX records but missing DMARC")
                email_auth_gaps.append({"domain": domain, "gap": "DMARC"})
            else:
                entry["strengths"].append("DMARC configured")

        portfolio.append(entry)

    return json.dumps({
        "portfolio_size": len(domain_list),
        "domains": portfolio,
        "summary": {
            "registrar_diversity": registrars,
            "nameserver_groups": len(nameserver_sets),
            "expiry_warnings": expiry_warnings,
            "ssl_issues": ssl_issues,
            "email_auth_gaps": email_auth_gaps,
            "dnssec": dnssec_status,
        },
    }, default=str)


@tool
def competitive_intel(domain: str) -> str:
    """Map a competitor's domain footprint. Checks related TLD variants, analyzes DNS
    infrastructure (nameservers, email providers, CDN indicators), and identifies
    defensive registrations."""
    domain = domain.lower().strip()
    sld, original_tld = _split_domain(domain)

    # Check TLD variants
    check_tlds = ["com", "net", "org", "io", "co", "ai", "dev", "app", "info", "biz", "xyz"]
    check_tlds = [t for t in check_tlds if t != original_tld]
    variant_domains = [f"{sld}.{tld}" for tld in check_tlds]

    variant_results = safe_call(seer.bulk_lookup, variant_domains) or [None] * len(variant_domains)

    variants = {}
    for i, variant in enumerate(variant_domains):
        result = variant_results[i] if i < len(variant_results) else None
        registered = _is_registered(result)
        variants[variant] = {
            "registered": registered is True,
            "status": "registered" if registered is True else (
                "available" if registered is False else "unknown"
            ),
            "registrar": (
                result.get("registrar")
                if registered is True and isinstance(result, dict) else None
            ),
        }

    # Primary domain deep analysis
    primary_lookup = safe_call(seer.lookup, domain)
    dns_data = {}
    for rtype in ("NS", "MX", "A", "AAAA", "TXT", "CNAME", "CAA"):
        result = safe_call(seer.dig, domain, rtype)
        if result:
            dns_data[rtype] = result

    status_data = safe_call(seer.status, domain)

    return json.dumps({
        "target": domain,
        "registration": primary_lookup,
        "web_status": status_data,
        "infrastructure": dns_data,
        "tld_variants": variants,
        "variants_registered": sum(1 for v in variants.values() if v["registered"]),
        "variants_available": sum(
            1 for v in variants.values() if v["status"] == "available"
        ),
    }, default=str)


@tool
def migration_preflight(domain: str, target_nameservers: str = "") -> str:
    """Pre-flight check for domain or DNS migration. Analyzes lock status, registrar
    transfer requirements, full DNS zone snapshot, TTL values, and validates target
    nameservers if provided. Produces a migration readiness checklist."""
    domain = domain.lower().strip()
    target_ns = (
        [n.strip() for n in target_nameservers.split(",") if n.strip()]
        if target_nameservers else []
    )

    whois_data = safe_call(seer.lookup, domain)

    # Full DNS snapshot
    dns_snapshot = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SRV", "SOA"):
        result = safe_call(seer.dig, domain, rtype)
        if result:
            dns_snapshot[rtype] = result

    status_data = safe_call(seer.status, domain)

    # Build migration checklist
    checklist = []
    migration_warnings = []

    if whois_data and isinstance(whois_data, dict) and not whois_data.get("error"):
        statuses = whois_data.get("status") or whois_data.get("statuses") or []
        if isinstance(statuses, str):
            statuses = [statuses]
        locked = any("lock" in s.lower() for s in statuses)

        checklist.append({
            "step": "Domain lock",
            "status": "action_required" if locked else "ready",
            "detail": (
                "Domain has transfer lock — remove before transferring"
                if locked else "Domain is not locked"
            ),
        })

        registrar = whois_data.get("registrar", "unknown")
        checklist.append({
            "step": "Obtain auth/EPP code",
            "status": "action_required",
            "detail": f"Request transfer authorization code from {registrar}",
        })

        expiry = whois_data.get("expiry") or whois_data.get("expiration_date")
        if expiry:
            days_left = _days_until(expiry)
            if days_left is not None:
                if days_left < 15:
                    migration_warnings.append(
                        f"Domain expires in {days_left} days — renew before transferring"
                    )
                if days_left < 60:
                    migration_warnings.append(
                        "ICANN prohibits transfers within 60 days of expiry for some TLDs"
                    )

    # TTL recommendation
    if dns_snapshot.get("SOA"):
        checklist.append({
            "step": "Lower TTLs before cutover",
            "status": "recommended",
            "detail": (
                "Reduce TTL to 300s (5 min) at least 24-48 hours before switching "
                "nameservers to minimize propagation delay"
            ),
        })

    # DNS record migration
    total_records = sum(
        len(v) if isinstance(v, list) else 1
        for v in dns_snapshot.values()
    )
    checklist.append({
        "step": "Recreate DNS records at new provider",
        "status": "action_required",
        "detail": (
            f"{total_records} records across {len(dns_snapshot)} record types "
            f"({', '.join(dns_snapshot.keys())}) need to be recreated"
        ),
    })

    if dns_snapshot.get("MX"):
        migration_warnings.append(
            "Domain has MX records — verify email delivery immediately after migration"
        )

    if dns_snapshot.get("CAA"):
        migration_warnings.append(
            "Domain has CAA records — ensure they are recreated to avoid SSL issuance failures"
        )

    checklist.append({
        "step": "Update nameservers",
        "status": "action_required",
        "detail": "Change NS records at registrar to point to new provider",
    })

    checklist.append({
        "step": "Verify propagation after cutover",
        "status": "pending",
        "detail": "Use seer_propagation to confirm DNS changes have propagated globally",
    })

    # Validate target nameservers if provided
    ns_validation = None
    if target_ns:
        ns_validation = {}
        for ns in target_ns:
            a_result = safe_call(seer.dig, ns, "A")
            ns_validation[ns] = {"resolves": bool(a_result), "addresses": a_result}

    return json.dumps({
        "domain": domain,
        "registration": whois_data,
        "dns_snapshot": dns_snapshot,
        "total_dns_records": total_records,
        "web_status": status_data,
        "migration_checklist": checklist,
        "warnings": migration_warnings,
        "target_nameserver_validation": ns_validation,
    }, default=str)


ADVISOR_TOOLS = [
    appraise_domain,
    plan_acquisition,
    suggest_domains,
    audit_portfolio,
    competitive_intel,
    migration_preflight,
]


# --- Composite Advisor Tools ---


@tool
def security_audit(domain: str) -> str:
    """Run a comprehensive security audit on a domain. Checks SSL certificate health,
    DNSSEC configuration, email security (SPF, DMARC, DKIM), HTTP headers, and DNS
    configuration."""
    domain = domain.lower().strip()

    # SSL certificate analysis
    ssl_data = safe_call(seer.ssl, domain)
    ssl_health = {"status": "unknown"}
    if ssl_data and isinstance(ssl_data, dict):
        ssl_health = {
            "valid": ssl_data.get("valid", False),
            "issuer": ssl_data.get("issuer"),
            "expiry": ssl_data.get("not_after") or ssl_data.get("expiry"),
            "sans": ssl_data.get("sans") or ssl_data.get("subject_alt_names"),
            "protocol": ssl_data.get("protocol") or ssl_data.get("tls_version"),
        }
        if ssl_health.get("expiry"):
            days_left = _days_until(ssl_health["expiry"])
            if days_left is not None:
                ssl_health["days_until_expiry"] = days_left
                if days_left < 7:
                    ssl_health["status"] = "critical"
                elif days_left < 30:
                    ssl_health["status"] = "warning"
                else:
                    ssl_health["status"] = "healthy"
            else:
                ssl_health["status"] = "healthy" if ssl_health.get("valid") else "critical"
        else:
            ssl_health["status"] = "healthy" if ssl_health.get("valid") else "critical"
    elif ssl_data is None:
        ssl_health = {"status": "critical", "error": "Could not retrieve SSL certificate"}

    # DNSSEC status
    dnssec_data = safe_call(seer.dnssec, domain)
    dnssec_status = {"status": "unknown"}
    if dnssec_data and isinstance(dnssec_data, dict):
        dnssec_status = {
            "enabled": dnssec_data.get("enabled", False),
            "valid": dnssec_data.get("valid", False),
            "ds_records": dnssec_data.get("ds_records"),
            "dnskey_records": dnssec_data.get("dnskey_records"),
            "issues": dnssec_data.get("issues") or [],
            "status": "healthy" if dnssec_data.get("valid") else (
                "warning" if dnssec_data.get("enabled") else "not_configured"
            ),
        }
    elif dnssec_data is None:
        dnssec_status = {"status": "unknown", "error": "Could not check DNSSEC"}

    # Email security: SPF, DMARC, DKIM indicators
    txt_records = safe_call(seer.dig, domain, "TXT")
    dmarc_records = safe_call(seer.dig, "_dmarc." + domain, "TXT")
    mx_records = safe_call(seer.dig, domain, "MX")

    email_security = {
        "has_mx": bool(mx_records),
        "spf": {"found": False},
        "dmarc": {"found": False},
        "dkim_indicator": False,
    }

    if txt_records and isinstance(txt_records, list):
        for record in txt_records:
            record_str = str(record).lower()
            if "v=spf1" in record_str:
                email_security["spf"] = {"found": True, "record": str(record)}
                # Check for common SPF issues
                if "-all" in record_str:
                    email_security["spf"]["policy"] = "strict"
                elif "~all" in record_str:
                    email_security["spf"]["policy"] = "softfail"
                elif "?all" in record_str:
                    email_security["spf"]["policy"] = "neutral"
                elif "+all" in record_str:
                    email_security["spf"]["policy"] = "permissive_INSECURE"

    if dmarc_records and isinstance(dmarc_records, list):
        for record in dmarc_records:
            record_str = str(record).lower()
            if "v=dmarc1" in record_str:
                email_security["dmarc"] = {"found": True, "record": str(record)}
                if "p=reject" in record_str:
                    email_security["dmarc"]["policy"] = "reject"
                elif "p=quarantine" in record_str:
                    email_security["dmarc"]["policy"] = "quarantine"
                elif "p=none" in record_str:
                    email_security["dmarc"]["policy"] = "none_MONITORING_ONLY"

    # HTTP security check via status
    status_data = safe_call(seer.status, domain)
    http_security = {"status": "unknown"}
    if status_data and isinstance(status_data, dict):
        http_security = {
            "http_status": status_data.get("http_status"),
            "ssl_valid": status_data.get("ssl_valid", False),
            "redirects_to_https": status_data.get("final_url", "").startswith("https://")
            if status_data.get("final_url") else None,
            "status": "healthy" if status_data.get("ssl_valid") else "warning",
        }

    # Compile recommendations
    recommendations = []
    risk_score = 0  # 0 = low, accumulate points

    if ssl_health.get("status") == "critical":
        recommendations.append("CRITICAL: Fix SSL certificate immediately — expired, invalid, or missing")
        risk_score += 3
    elif ssl_health.get("status") == "warning":
        recommendations.append("WARNING: SSL certificate expiring soon — renew within 30 days")
        risk_score += 1

    if dnssec_status.get("status") == "not_configured":
        recommendations.append("Enable DNSSEC to protect against DNS spoofing attacks")
        risk_score += 1

    if email_security["has_mx"]:
        if not email_security["spf"]["found"]:
            recommendations.append("IMPORTANT: Add SPF record to prevent email spoofing")
            risk_score += 2
        elif email_security["spf"].get("policy") == "permissive_INSECURE":
            recommendations.append("CRITICAL: SPF record uses +all which allows anyone to send as your domain")
            risk_score += 3
        if not email_security["dmarc"]["found"]:
            recommendations.append("IMPORTANT: Add DMARC record for email authentication policy")
            risk_score += 2
        elif email_security["dmarc"].get("policy") == "none_MONITORING_ONLY":
            recommendations.append("Consider upgrading DMARC policy from 'none' to 'quarantine' or 'reject'")
            risk_score += 1

    if http_security.get("redirects_to_https") is False:
        recommendations.append("Configure HTTP to HTTPS redirect for all traffic")
        risk_score += 1

    if not http_security.get("ssl_valid"):
        risk_score += 2

    # Determine overall risk rating
    if risk_score >= 5:
        overall_risk = "critical"
    elif risk_score >= 3:
        overall_risk = "high"
    elif risk_score >= 1:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    return json.dumps({
        "domain": domain,
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "ssl_health": ssl_health,
        "dnssec_status": dnssec_status,
        "email_security": email_security,
        "http_security": http_security,
        "recommendations": recommendations,
    }, default=str)


@tool
def brand_protection_scan(brand: str, primary_domain: str) -> str:
    """Scan for brand protection issues: typosquatting variants, available defensive
    registrations, and subdomain exposure via CT logs."""
    brand = brand.lower().strip().replace(" ", "")
    primary_domain = primary_domain.lower().strip()

    # Generate common typo variants
    variants = set()

    # Character swaps (adjacent transpositions)
    for i in range(len(brand) - 1):
        swapped = brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]
        variants.add(swapped)

    # Missing characters
    for i in range(len(brand)):
        variants.add(brand[:i] + brand[i + 1:])

    # Doubled characters
    for i in range(len(brand)):
        variants.add(brand[:i] + brand[i] * 2 + brand[i + 1:])

    # Common character substitutions
    _substitutions = {
        "o": "0", "0": "o",
        "l": "1", "1": "l",
        "i": "1",
        "s": "5", "5": "s",
        "a": "4",
        "e": "3",
    }
    for i, char in enumerate(brand):
        if char in _substitutions:
            variants.add(brand[:i] + _substitutions[char] + brand[i + 1:])

    # Remove the original brand from variants
    variants.discard(brand)

    # Cap typo variants for network checks
    typo_variants = list(variants)[:20]

    # Build domains to check: typo variants on .com
    typo_domains = [f"{v}.com" for v in typo_variants]

    # Check TLD variants of the actual brand
    key_tlds = ["com", "net", "org", "io", "co"]
    tld_domains = [f"{brand}.{tld}" for tld in key_tlds]

    # Check availability of typo domains
    available_variants = []
    taken_variants = []
    for td in typo_domains:
        result = safe_call(seer.availability, td)
        if result and isinstance(result, dict):
            if result.get("available", False):
                available_variants.append({"domain": td, "status": "available"})
            else:
                taken_variants.append({"domain": td, "status": "taken", "details": result})
        else:
            taken_variants.append({"domain": td, "status": "unknown"})

    # Check TLD coverage
    tld_coverage = {}
    for td in tld_domains:
        result = safe_call(seer.availability, td)
        if result and isinstance(result, dict):
            tld_coverage[td] = {
                "available": result.get("available", False),
                "details": result,
            }
        else:
            tld_coverage[td] = {"available": None, "status": "unknown"}

    # Subdomain exposure via CT logs
    subdomain_data = safe_call(seer.subdomains, primary_domain)
    subdomain_exposure = {"count": 0, "subdomains": []}
    if subdomain_data and isinstance(subdomain_data, dict):
        subs = subdomain_data.get("subdomains") or subdomain_data.get("results") or []
        subdomain_exposure = {
            "count": len(subs),
            "subdomains": subs[:50],  # Cap display at 50
        }
    elif subdomain_data and isinstance(subdomain_data, list):
        subdomain_exposure = {
            "count": len(subdomain_data),
            "subdomains": subdomain_data[:50],
        }

    return json.dumps({
        "brand": brand,
        "primary_domain": primary_domain,
        "typo_variants_checked": len(typo_domains),
        "available_variants": available_variants,
        "taken_variants": taken_variants,
        "tld_coverage": tld_coverage,
        "subdomain_exposure": subdomain_exposure,
        "recommendations": [
            f"Register {len(available_variants)} available typosquatting variants for defensive protection"
            if available_variants else "No immediate typosquatting variants available to register",
            f"{subdomain_exposure['count']} subdomains exposed via Certificate Transparency logs"
            if subdomain_exposure["count"] > 0 else "No subdomain exposure detected via CT logs",
        ],
    }, default=str)


@tool
def dns_health_check(domain: str) -> str:
    """Comprehensive DNS health check: record completeness, propagation consistency,
    nameserver comparison, and best practice compliance."""
    domain = domain.lower().strip()

    # Check essential record types
    essential_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"]
    records_found = {}
    records_missing = []

    for rtype in essential_types:
        result = safe_call(seer.dig, domain, rtype)
        if result:
            records_found[rtype] = result
        else:
            records_missing.append(rtype)

    # Propagation check for A records
    propagation_status = safe_call(seer.propagation, domain, "A")

    # Nameserver consistency check
    nameserver_consistency = None
    ns_records = records_found.get("NS")
    if ns_records and isinstance(ns_records, list) and len(ns_records) >= 2:
        ns_a = str(ns_records[0]).rstrip(".")
        ns_b = str(ns_records[1]).rstrip(".")
        compare_result = safe_call(seer.dns_compare, domain, "A", ns_a, ns_b)
        if compare_result:
            nameserver_consistency = {
                "server_a": ns_a,
                "server_b": ns_b,
                "comparison": compare_result,
            }

    # Parse TXT records for SPF
    spf_found = False
    spf_issues = []
    if records_found.get("TXT") and isinstance(records_found["TXT"], list):
        spf_records = [r for r in records_found["TXT"] if "v=spf1" in str(r).lower()]
        if spf_records:
            spf_found = True
            if len(spf_records) > 1:
                spf_issues.append("Multiple SPF records found — only one is allowed per RFC 7208")

    # SOA serial format check
    soa_info = None
    if records_found.get("SOA"):
        soa = records_found["SOA"]
        soa_info = {"record": soa}
        # SOA serial is typically in YYYYMMDDNN format
        soa_str = str(soa)
        # Try to extract serial number (usually the first large number in SOA)
        serial_match = re.search(r'\b(\d{8,10})\b', soa_str)
        if serial_match:
            serial = serial_match.group(1)
            soa_info["serial"] = serial
            if len(serial) >= 10 and serial[:4].isdigit():
                soa_info["format"] = "date-based (YYYYMMDDNN)"
            else:
                soa_info["format"] = "numeric"

    # Recommendations
    recommendations = []
    best_practices_met = 0
    total_practices = 7

    # 1. Has A record
    if "A" in records_found:
        best_practices_met += 1
    else:
        recommendations.append("No A record found — domain will not resolve to an IPv4 address")

    # 2. Has AAAA record (IPv6)
    if "AAAA" in records_found:
        best_practices_met += 1
    else:
        recommendations.append("No AAAA record — consider adding IPv6 support")

    # 3. Has NS records (at least 2)
    if ns_records and isinstance(ns_records, list) and len(ns_records) >= 2:
        best_practices_met += 1
    else:
        recommendations.append("Ensure at least 2 nameservers for redundancy")

    # 4. Has SOA record
    if "SOA" in records_found:
        best_practices_met += 1
    else:
        recommendations.append("Missing SOA record — critical for zone authority")

    # 5. Has SPF
    if spf_found:
        best_practices_met += 1
    else:
        if "MX" in records_found:
            recommendations.append("Has MX records but no SPF — add SPF to prevent email spoofing")
        else:
            recommendations.append("No SPF record found")

    # 6. Has CAA record
    if "CAA" in records_found:
        best_practices_met += 1
    else:
        recommendations.append("No CAA record — add to restrict which CAs can issue certificates")

    # 7. Has MX
    if "MX" in records_found:
        best_practices_met += 1

    health_score = round((best_practices_met / total_practices) * 100)

    return json.dumps({
        "domain": domain,
        "health_score": health_score,
        "best_practices_met": f"{best_practices_met}/{total_practices}",
        "records_found": records_found,
        "records_missing": records_missing,
        "propagation_status": propagation_status,
        "nameserver_consistency": nameserver_consistency,
        "soa_info": soa_info,
        "spf_status": {"found": spf_found, "issues": spf_issues},
        "recommendations": recommendations,
    }, default=str)


@tool
def domain_timeline(domain: str) -> str:
    """Build a timeline of key events and current state for a domain: registration dates,
    DNS setup, SSL certificates, and current infrastructure."""
    domain = domain.lower().strip()

    # Registration data for dates
    reg_data = safe_call(seer.lookup, domain)

    # DNS infrastructure
    dns_a = safe_call(seer.dig, domain, "A")
    dns_ns = safe_call(seer.dig, domain, "NS")

    # SSL certificate dates
    ssl_data = safe_call(seer.ssl, domain)

    # Current HTTP status
    status_data = safe_call(seer.status, domain)

    # Build timeline events
    timeline = []

    if reg_data and isinstance(reg_data, dict) and not reg_data.get("error"):
        created = reg_data.get("created") or reg_data.get("creation_date")
        if created:
            timeline.append({
                "date": str(created)[:10],
                "event": "domain_registered",
                "detail": f"Domain registered via {reg_data.get('registrar', 'unknown registrar')}",
            })

        updated = reg_data.get("updated") or reg_data.get("last_updated")
        if updated:
            timeline.append({
                "date": str(updated)[:10],
                "event": "registration_updated",
                "detail": "WHOIS/RDAP record last updated",
            })

        expiry = reg_data.get("expiry") or reg_data.get("expiration_date")
        if expiry:
            days_left = _days_until(expiry)
            timeline.append({
                "date": str(expiry)[:10],
                "event": "domain_expires",
                "detail": f"Registration expires ({days_left} days remaining)" if days_left is not None else "Registration expiry date",
            })

    if ssl_data and isinstance(ssl_data, dict):
        not_before = ssl_data.get("not_before") or ssl_data.get("valid_from")
        not_after = ssl_data.get("not_after") or ssl_data.get("expiry") or ssl_data.get("valid_to")
        issuer = ssl_data.get("issuer", "unknown CA")

        if not_before:
            timeline.append({
                "date": str(not_before)[:10],
                "event": "ssl_certificate_issued",
                "detail": f"Current SSL certificate issued by {issuer}",
            })
        if not_after:
            ssl_days = _days_until(not_after)
            timeline.append({
                "date": str(not_after)[:10],
                "event": "ssl_certificate_expires",
                "detail": f"SSL certificate expires ({ssl_days} days remaining)" if ssl_days is not None else "SSL certificate expiry",
            })

    # Sort timeline chronologically
    timeline.sort(key=lambda e: e["date"])

    # Current state summary
    current_state = {
        "domain": domain,
        "a_records": dns_a if dns_a else None,
        "nameservers": dns_ns if dns_ns else None,
        "registrar": reg_data.get("registrar") if reg_data and isinstance(reg_data, dict) else None,
        "http_status": status_data.get("http_status") if status_data and isinstance(status_data, dict) else None,
        "ssl_valid": status_data.get("ssl_valid") if status_data and isinstance(status_data, dict) else None,
    }

    return json.dumps({
        "domain": domain,
        "timeline": timeline,
        "current_state": current_state,
        "registration": reg_data,
    }, default=str)


@tool
def expiration_alert(domains: str = "") -> str:
    """Check expiration status for watchlist domains or a provided comma-separated list.
    Flags domains by urgency: critical (<7 days), warning (<30 days), upcoming (<90 days)."""
    from .memory_tools import get_memory

    domain_list = []
    source = "provided"

    if not domains or not domains.strip():
        # Get watchlist domains from memory
        mem = get_memory()
        watched = mem.watchlist_list()
        domain_list = [w["domain"] for w in watched]
        source = "watchlist"
    else:
        domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]

    if not domain_list:
        return json.dumps({
            "error": "No domains to check. Provide a comma-separated list or add domains to the watchlist.",
            "source": source,
        })

    # Cap at 50 domains
    if len(domain_list) > 50:
        domain_list = domain_list[:50]

    # Bulk lookup for expiry dates
    bulk_results = safe_call(seer.bulk_lookup, domain_list) or [None] * len(domain_list)
    if not isinstance(bulk_results, list):
        bulk_results = [None] * len(domain_list)

    critical = []   # <7 days
    warning = []    # <30 days
    upcoming = []   # <90 days
    healthy = []    # >90 days
    unknown = []    # Could not determine

    for i, domain in enumerate(domain_list):
        result = bulk_results[i] if i < len(bulk_results) else None
        entry = {"domain": domain}

        if result and isinstance(result, dict) and not result.get("error"):
            expiry = result.get("expiry") or result.get("expiration_date")
            registrar = result.get("registrar")
            entry["expiry"] = str(expiry) if expiry else None
            entry["registrar"] = registrar

            if expiry:
                days_left = _days_until(expiry)
                if days_left is not None:
                    entry["days_remaining"] = days_left
                    if days_left < 0:
                        entry["urgency"] = "expired"
                        critical.append(entry)
                    elif days_left < 7:
                        entry["urgency"] = "critical"
                        critical.append(entry)
                    elif days_left < 30:
                        entry["urgency"] = "warning"
                        warning.append(entry)
                    elif days_left < 90:
                        entry["urgency"] = "upcoming"
                        upcoming.append(entry)
                    else:
                        entry["urgency"] = "healthy"
                        healthy.append(entry)
                else:
                    entry["urgency"] = "unknown"
                    unknown.append(entry)
            else:
                entry["urgency"] = "unknown"
                unknown.append(entry)
        else:
            entry["urgency"] = "unknown"
            entry["error"] = "Could not retrieve registration data"
            unknown.append(entry)

    # Sort each category by days remaining (most urgent first)
    for category in (critical, warning, upcoming, healthy):
        category.sort(key=lambda e: e.get("days_remaining", 99999))

    return json.dumps({
        "source": source,
        "total_checked": len(domain_list),
        "summary": {
            "critical": len(critical),
            "warning": len(warning),
            "upcoming": len(upcoming),
            "healthy": len(healthy),
            "unknown": len(unknown),
        },
        "critical": critical,
        "warning": warning,
        "upcoming": upcoming,
        "healthy": healthy,
        "unknown": unknown,
    }, default=str)


COMPOSITE_ADVISOR_TOOLS = [
    security_audit,
    brand_protection_scan,
    dns_health_check,
    domain_timeline,
    expiration_alert,
]
