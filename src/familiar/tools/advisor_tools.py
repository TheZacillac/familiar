"""Advisory tools that compose seer and tome for domain strategy intelligence."""

import json
import re

import seer
import tome
from langchain_core.tools import tool

from ..utils import days_until as _days_until, parallel_calls, safe_call


def _unwrap_bulk(raw) -> dict | list | None:
    """Unwrap a seer BulkResult wrapper to extract the inner payload.

    seer.bulk_* APIs return Vec<BulkResult> where each element is:
        {operation: {...}, success: bool, data: <payload>, error: str|None, duration_ms: int}

    Returns the ``data`` value when the result indicates success, or None otherwise.
    """
    if raw and isinstance(raw, dict) and raw.get("success"):
        return raw.get("data")
    return None


def _get_cert(status_data) -> dict:
    """Extract the certificate dict from a seer.status() response.

    seer.status() returns {certificate: {is_valid, days_until_expiry, ...}}.
    Returns an empty dict if not available.
    """
    if status_data and isinstance(status_data, dict):
        cert = status_data.get("certificate")
        if cert and isinstance(cert, dict):
            return cert
    return {}


def _extract_registration(lookup_result) -> dict:
    """Normalize a seer.lookup() result into a flat registration dict.

    seer.lookup() returns a tagged enum: {source: "whois"/"rdap", data: {...}}.
    For WHOIS, data contains registrar, creation_date, expiration_date, etc.
    For RDAP, data uses RFC 7483 structure (events, entities, camelCase).
    This function normalizes both into a common flat dict.
    """
    if not lookup_result or not isinstance(lookup_result, dict):
        return {}

    source = lookup_result.get("source", "")
    data = lookup_result.get("data")
    if not data or not isinstance(data, dict):
        return {"source": source}

    if source == "whois":
        return {
            "source": "whois",
            "domain": data.get("domain"),
            "registrar": data.get("registrar"),
            "registrant": data.get("registrant"),
            "organization": data.get("organization"),
            "creation_date": data.get("creation_date"),
            "expiration_date": data.get("expiration_date"),
            "updated_date": data.get("updated_date"),
            "nameservers": data.get("nameservers", []),
            "statuses": data.get("status", []),
            "dnssec": data.get("dnssec"),
        }

    if source == "rdap":
        reg = {
            "source": "rdap",
            "domain": data.get("ldhName") or data.get("unicodeName"),
            "nameservers": [],
            "statuses": data.get("status", []),
        }
        # Extract dates from RDAP events
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate")
            if action == "registration":
                reg["creation_date"] = date
            elif action == "expiration":
                reg["expiration_date"] = date
            elif action in ("last changed", "last update of RDAP database"):
                reg.setdefault("updated_date", date)
        # Extract registrar from entities
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                # Try vcardArray first, fall back to handle
                vcard = entity.get("vcardArray")
                if vcard and isinstance(vcard, list) and len(vcard) > 1:
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            reg["registrar"] = item[3]
                            break
                if "registrar" not in reg:
                    reg["registrar"] = entity.get("handle")
        # Extract nameservers
        for ns in data.get("nameservers", []):
            if isinstance(ns, dict):
                name = ns.get("ldhName", "")
                if name:
                    reg["nameservers"].append(name)
        # DNSSEC
        secure_dns = data.get("secureDNS") or data.get("secureDns")
        if secure_dns and isinstance(secure_dns, dict):
            reg["dnssec"] = "yes" if secure_dns.get("delegationSigned") else "unsigned"
        # Also check for whois_fallback data
        fallback = lookup_result.get("whois_fallback")
        if fallback and isinstance(fallback, dict):
            if not reg.get("registrar"):
                reg["registrar"] = fallback.get("registrar")
            if not reg.get("expiration_date"):
                reg["expiration_date"] = fallback.get("expiration_date")
            if not reg.get("creation_date"):
                reg["creation_date"] = fallback.get("creation_date")
        return reg

    # Available variant or unknown source
    return {"source": source}

# Known multi-level TLD suffixes for correct SLD extraction
_MULTI_LEVEL_TLDS = frozenset({
    "co.uk", "org.uk", "me.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
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
    "com.ar",
    "co.id", "or.id",
    "com.co", "net.co",
    "com.tr", "org.tr",
    "com.ph",
    "com.my",
    "com.ng",
    "co.ke",
})


# --- EPP Status Code Classification (RFC 5731) ---

_EPP_TRANSFER_LOCKS = frozenset({
    "clienttransferprohibited",
    "servertransferprohibited",
})

_EPP_ALL_LOCKS = frozenset({
    "clienttransferprohibited",
    "servertransferprohibited",
    "clientdeleteprohibited",
    "serverdeleteprohibited",
    "clientupdateprohibited",
    "serverupdateprohibited",
    "clientrenewprohibited",
    "serverrenewprohibited",
})

_EPP_HOLDS = frozenset({
    "clienthold",
    "serverhold",
})


def _normalize_epp_status(status: str) -> str:
    """Normalize an EPP status string to its canonical lowercase form.

    Handles formats like:
    - 'clientTransferProhibited' (standard)
    - 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited' (with URL)
    - 'https://icann.org/epp#clientTransferProhibited' (URL-only)
    """
    s = status.strip()
    # Extract from URL fragment (e.g., https://icann.org/epp#clientTransferProhibited)
    if "#" in s:
        s = s.rsplit("#", 1)[-1]
    # Take first token to strip trailing URLs
    s = s.split()[0]
    return s.lower()


def _classify_epp_statuses(raw_statuses: list) -> dict:
    """Classify raw EPP status strings into structured categories."""
    normalized = [_normalize_epp_status(s) for s in raw_statuses]

    transfer_locks = [s for s in normalized if s in _EPP_TRANSFER_LOCKS]
    all_locks = [s for s in normalized if s in _EPP_ALL_LOCKS]
    holds = [s for s in normalized if s in _EPP_HOLDS]

    return {
        "raw": raw_statuses,
        "normalized": normalized,
        "transfer_locks": transfer_locks,
        "all_locks": all_locks,
        "holds": holds,
        "is_transfer_locked": bool(transfer_locks),
        "is_held": bool(holds),
    }


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
    elif tld in {"edu", "gov", "mil", "int"}:
        analysis["tld_tier"] = "restricted"
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
    tld = name_analysis["tld"]

    # Fan out all independent network calls concurrently
    rtypes = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA")
    call_specs = (
        [(seer.dig, domain, rt) for rt in rtypes]
        + [(seer.lookup, domain), (seer.status, domain)]
        + ([(tome.tld_lookup, tld)] if tld else [])
    )
    results = parallel_calls(*call_specs)

    dns_records = {}
    for i, rtype in enumerate(rtypes):
        if results[i]:
            dns_records[rtype] = results[i]
    whois_data = _extract_registration(results[len(rtypes)])
    status_data = results[len(rtypes) + 1]
    tld_info = results[len(rtypes) + 2] if tld else None

    # Derive valuation signals
    signals = {}

    if whois_data and isinstance(whois_data, dict):
        created = whois_data.get("creation_date")
        if created:
            signals["registration_date"] = str(created)[:10]
            age_days = _days_until(created)
            if age_days is not None:
                # age_days is negative because the date is in the past
                signals["age_years"] = round(-age_days / 365.25, 1)

        expiry = whois_data.get("expiration_date")
        if expiry:
            signals["expiration_date"] = str(expiry)[:10]
            expiry_days = _days_until(expiry)
            if expiry_days is not None:
                signals["years_until_expiry"] = round(expiry_days / 365.25, 1)

        updated = whois_data.get("updated_date")
        if updated:
            signals["last_updated"] = str(updated)[:10]

        # Registration span is NOT the same as renewal term — WHOIS only shows
        # the current expiry, not how many times the domain has been renewed.
        signals["_note"] = (
            "age_years and years_until_expiry are computed from registration and "
            "expiry dates. Do not infer renewal history — WHOIS does not record "
            "individual renewal events."
        )

    record_count = sum(
        len(v) if isinstance(v, list) else 1
        for v in dns_records.values()
    )
    signals["dns_record_types_present"] = list(dns_records.keys())
    signals["total_dns_records"] = record_count
    signals["has_email_infrastructure"] = bool(dns_records.get("MX"))
    signals["has_spf"] = any(
        "v=spf1" in (r.get("data", {}).get("text", "") if isinstance(r, dict) else str(r)).lower()
        for r in (dns_records.get("TXT") or [])
    )

    if status_data and isinstance(status_data, dict):
        signals["http_accessible"] = status_data.get("http_status") is not None
        cert = _get_cert(status_data)
        signals["has_ssl"] = cert.get("is_valid", False)
        signals["ssl_expiry"] = cert.get("valid_until")

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

    name_analysis = _domain_name_analysis(domain)
    lookup_raw, status_data, dns_a, dns_ns, dns_mx = parallel_calls(
        (seer.lookup, domain),
        (seer.status, domain),
        (seer.dig, domain, "A"),
        (seer.dig, domain, "NS"),
        (seer.dig, domain, "MX"),
    )
    whois_data = _extract_registration(lookup_raw)

    acquisition_intel = {
        "is_registered": False,
        "registrar": None,
        "epp_statuses": [],
        "epp_classification": {},
        "expiry_date": None,
        "parking_indicators": [],
        "active_use_indicators": [],
    }

    if whois_data and isinstance(whois_data, dict) and not whois_data.get("error"):
        acquisition_intel["is_registered"] = True
        acquisition_intel["registrar"] = whois_data.get("registrar")
        statuses = whois_data.get("statuses") or []
        if isinstance(statuses, str):
            statuses = [statuses]
        acquisition_intel["epp_statuses"] = statuses
        acquisition_intel["epp_classification"] = _classify_epp_statuses(statuses)
        acquisition_intel["expiry_date"] = str(
            whois_data.get("expiration_date") or ""
        )

    # Parking heuristics (only meaningful for registered domains)
    if acquisition_intel["is_registered"]:
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
    if _get_cert(status_data).get("is_valid"):
        acquisition_intel["active_use_indicators"].append("has_valid_ssl")

    # Deterministic acquisition difficulty score
    difficulty = _compute_acquisition_difficulty(
        acquisition_intel, name_analysis,
    )

    return json.dumps({
        "domain": domain,
        "name_analysis": name_analysis,
        "acquisition_intel": acquisition_intel,
        "acquisition_difficulty": difficulty,
        "registration": whois_data,
        "web_status": status_data,
        "nameservers": dns_ns,
    }, default=str)


def _compute_acquisition_difficulty(acquisition_intel: dict, name_analysis: dict) -> dict:
    """Compute a deterministic acquisition difficulty assessment (0-10 scale)."""
    if not acquisition_intel["is_registered"]:
        return {"score": 0, "rating": "available", "factors": ["Domain is not registered"]}

    score = 0
    factors = []

    # EPP lock-based difficulty
    epp = acquisition_intel.get("epp_classification", {})
    if epp.get("is_transfer_locked"):
        score += 2
        factors.append("Transfer lock active")
    if epp.get("is_held"):
        score += 3
        factors.append("Domain is on hold (registry or registrar action)")
    lock_count = len(epp.get("all_locks", []))
    if lock_count > 2:
        score += 1
        factors.append(f"{lock_count} lock statuses present")

    # Active use signals
    indicators = acquisition_intel.get("active_use_indicators", [])
    if "has_email" in indicators:
        score += 2
        factors.append("Active email infrastructure")
    if "has_valid_ssl" in indicators:
        score += 1
        factors.append("Valid SSL certificate (active maintenance)")
    if "has_a_record" in indicators and "has_email" not in indicators:
        score += 1
        factors.append("Has A record (resolves)")

    # Name quality — premium names are harder to acquire
    length_tier = name_analysis.get("length_tier", "")
    if length_tier == "ultra-premium":
        score += 2
        factors.append("Ultra-premium name length (1-3 chars)")
    elif length_tier == "premium":
        score += 1
        factors.append("Premium name length (4-5 chars)")

    tld_tier = name_analysis.get("tld_tier", "")
    if tld_tier == "premium":
        score += 1
        factors.append(".com TLD (highest demand)")

    # Parking indicators suggest easier acquisition
    parking = acquisition_intel.get("parking_indicators", [])
    if parking:
        score -= 1
        factors.append(f"Parking signals: {', '.join(parking)}")

    score = max(0, min(10, score))

    if score <= 2:
        rating = "low"
    elif score <= 4:
        rating = "moderate"
    elif score <= 6:
        rating = "high"
    else:
        rating = "very-high"

    return {"score": score, "rating": rating, "factors": factors}


_NOT_FOUND_PATTERNS = (
    "no match",
    "not found",
    "no entries found",
    "no data found",
    "domain not found",
    "no information available",
    "is free",
    "status: free",
    "no object found",
    "nothing found",
    "no results",
)

_TRANSIENT_ERROR_PATTERNS = (
    "rate limit",
    "timeout",
    "timed out",
    "connection",
    "refused",
    "too many",
    "server error",
    "503",
    "429",
    "network",
    "unavailable",
)


def _is_registered(result) -> bool | None:
    """Determine if a lookup result indicates a registered domain.

    seer.lookup / bulk_lookup returns a tagged enum: {source: "rdap"/"whois"/"available"}.
    - "rdap" or "whois" source → registered
    - "available" source → not registered
    - error / None → ambiguous

    Returns True if registered, False if clearly available, None if ambiguous.
    """
    if result is None:
        return None
    if not isinstance(result, dict):
        return None
    # Handle the seer LookupResult tagged enum
    source = result.get("source")
    if source in ("rdap", "whois"):
        return True
    if source == "available":
        return False
    # Fallback for error responses or unexpected formats
    error = result.get("error")
    if error:
        error_lower = str(error).lower()
        if any(p in error_lower for p in _TRANSIENT_ERROR_PATTERNS):
            return None
        if any(p in error_lower for p in _NOT_FOUND_PATTERNS):
            return False
    return None


@tool
def suggest_domains(brand: str, keywords: str = "", tlds: str = "") -> str:
    """Generate and check domain name suggestions for a brand. Creates variations from
    the brand name and optional keywords, checks availability across popular TLDs, and
    returns scored candidates. Pass comma-separated keywords and/or TLDs to customize."""
    brand = brand.lower().strip().replace(" ", "")
    if not brand:
        return json.dumps({"error": "Brand name cannot be empty"})
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
        raw = results_raw[i] if i < len(results_raw) else None
        result = _unwrap_bulk(raw) if raw and isinstance(raw, dict) and "operation" in raw else raw
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
    dmarc_domains = [f"_dmarc.{d}" for d in domain_list]
    _none_list = [None] * len(domain_list)
    (bulk_lookup, bulk_status, txt_bulk, mx_bulk, ns_bulk, dmarc_bulk) = [
        r or _none_list for r in parallel_calls(
            (seer.bulk_lookup, domain_list),
            (seer.bulk_status, domain_list),
            (seer.bulk_dig, domain_list, "TXT"),
            (seer.bulk_dig, domain_list, "MX"),
            (seer.bulk_dig, domain_list, "NS"),
            (seer.bulk_dig, dmarc_domains, "TXT"),
        )
    ]

    portfolio = []
    registrars = {}
    nameserver_sets = {}
    expiry_warnings = []
    ssl_issues = []
    email_auth_gaps = []
    dnssec_status = {"enabled": 0, "disabled": 0, "unknown": 0}

    for i, domain in enumerate(domain_list):
        entry = {"domain": domain, "issues": [], "strengths": []}

        # Registration analysis — unwrap BulkResult, then normalize via _extract_registration
        raw_lookup = bulk_lookup[i] if i < len(bulk_lookup) else None
        lookup_data = _unwrap_bulk(raw_lookup)
        reg = _extract_registration(lookup_data)
        if reg and reg.get("source"):
            registrar = reg.get("registrar", "unknown")
            entry["registrar"] = registrar
            registrars[registrar] = registrars.get(registrar, 0) + 1

            expiry = reg.get("expiration_date")
            if expiry:
                entry["expiry"] = str(expiry)
                days_left = _days_until(expiry)
                if days_left is not None:
                    entry["days_until_expiry"] = days_left
                    if days_left < 7:
                        entry["issues"].append("CRITICAL: expires within 7 days")
                        expiry_warnings.append(
                            {"domain": domain, "days": days_left, "severity": "critical"}
                        )
                    elif days_left < 30:
                        entry["issues"].append("WARNING: expires within 30 days")
                        expiry_warnings.append(
                            {"domain": domain, "days": days_left, "severity": "warning"}
                        )
                    elif days_left < 90:
                        entry["issues"].append("NOTICE: expires within 90 days")
                        expiry_warnings.append(
                            {"domain": domain, "days": days_left, "severity": "upcoming"}
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

        # HTTP/SSL analysis — unwrap BulkResult
        raw_status = bulk_status[i] if i < len(bulk_status) else None
        st = _unwrap_bulk(raw_status)
        if st and isinstance(st, dict):
            cert = _get_cert(st)
            if not cert.get("is_valid", False):
                entry["issues"].append("SSL certificate invalid or missing")
                ssl_issues.append(domain)
            else:
                entry["strengths"].append("Valid SSL certificate")
            entry["http_status"] = st.get("http_status")
            entry["ssl_valid"] = cert.get("is_valid", False)
            entry["ssl_expiry"] = str(cert.get("valid_until", ""))

        # Email authentication checks (from bulk results) — unwrap BulkResult
        raw_txt = txt_bulk[i] if i < len(txt_bulk) else None
        txt_records = _unwrap_bulk(raw_txt)
        raw_mx = mx_bulk[i] if i < len(mx_bulk) else None
        mx_records = _unwrap_bulk(raw_mx)
        raw_ns = ns_bulk[i] if i < len(ns_bulk) else None
        ns_records = _unwrap_bulk(raw_ns)
        raw_dmarc = dmarc_bulk[i] if i < len(dmarc_bulk) else None
        dmarc_records = _unwrap_bulk(raw_dmarc)

        if ns_records and isinstance(ns_records, list):
            ns_key = str(sorted(
                r.get("data", {}).get("nameserver", str(r)) if isinstance(r, dict) else str(r)
                for r in ns_records
            ))
            nameserver_sets[ns_key] = nameserver_sets.get(ns_key, 0) + 1

        has_spf = False
        if txt_records and isinstance(txt_records, list):
            has_spf = any(
                "v=spf1" in (r.get("data", {}).get("text", "") if isinstance(r, dict) else str(r)).lower()
                for r in txt_records
            )

        has_dmarc = False
        if dmarc_records and isinstance(dmarc_records, list):
            has_dmarc = any(
                "v=dmarc1" in (r.get("data", {}).get("text", "") if isinstance(r, dict) else str(r)).lower()
                for r in dmarc_records
            )

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
        raw = variant_results[i] if i < len(variant_results) else None
        result = _unwrap_bulk(raw) if raw and isinstance(raw, dict) and "operation" in raw else raw
        registered = _is_registered(result)
        variants[variant] = {
            "registered": registered is True,
            "status": "registered" if registered is True else (
                "available" if registered is False else "unknown"
            ),
            "registrar": (
                _extract_registration(result).get("registrar")
                if registered is True else None
            ),
        }

    # Primary domain deep analysis — fan out all calls concurrently
    ci_rtypes = ("NS", "MX", "A", "AAAA", "TXT", "CNAME", "CAA")
    ci_results = parallel_calls(
        *[(seer.dig, domain, rt) for rt in ci_rtypes],
        (seer.lookup, domain),
        (seer.status, domain),
    )
    dns_data = {}
    for i, rtype in enumerate(ci_rtypes):
        if ci_results[i]:
            dns_data[rtype] = ci_results[i]
    primary_lookup = _extract_registration(ci_results[len(ci_rtypes)])
    status_data = ci_results[len(ci_rtypes) + 1]

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
        "variants_unknown": sum(
            1 for v in variants.values() if v["status"] == "unknown"
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

    # Fan out all independent lookups concurrently
    mp_rtypes = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SRV", "SOA")
    mp_results = parallel_calls(
        *[(seer.dig, domain, rt) for rt in mp_rtypes],
        (seer.lookup, domain),
        (seer.status, domain),
    )
    dns_snapshot = {}
    for i, rtype in enumerate(mp_rtypes):
        if mp_results[i]:
            dns_snapshot[rtype] = mp_results[i]
    whois_data = _extract_registration(mp_results[len(mp_rtypes)])
    status_data = mp_results[len(mp_rtypes) + 1]

    # Build migration checklist
    checklist = []
    migration_warnings = []

    if whois_data and isinstance(whois_data, dict) and not whois_data.get("error"):
        statuses = whois_data.get("statuses") or []
        if isinstance(statuses, str):
            statuses = [statuses]
        epp = _classify_epp_statuses(statuses)
        transfer_locked = epp["is_transfer_locked"]

        lock_detail = "Domain is not transfer-locked"
        if transfer_locked:
            locks = ", ".join(epp["transfer_locks"])
            lock_detail = f"Transfer lock active ({locks}) — remove before transferring"

        checklist.append({
            "step": "Domain lock",
            "status": "action_required" if transfer_locked else "ready",
            "detail": lock_detail,
        })

        if epp["is_held"]:
            holds = ", ".join(epp["holds"])
            migration_warnings.append(
                f"Domain is on hold ({holds}) — resolve with registrar/registry before transfer"
            )

        registrar = whois_data.get("registrar", "unknown")
        checklist.append({
            "step": "Obtain auth/EPP code",
            "status": "action_required",
            "detail": f"Request transfer authorization code from {registrar}",
        })

        expiry = whois_data.get("expiration_date")
        if expiry:
            days_left = _days_until(expiry)
            if days_left is not None:
                if days_left < 15:
                    migration_warnings.append(
                        f"Domain expires in {days_left} days — renew before transferring"
                    )
                elif days_left < 60:
                    migration_warnings.append(
                        f"Domain expires in {days_left} days — consider renewing first "
                        "to avoid expiration during the transfer process"
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

    # Validate target nameservers if provided (concurrently)
    ns_validation = None
    if target_ns:
        ns_a_results = parallel_calls(*[(seer.dig, ns, "A") for ns in target_ns])
        ns_validation = {
            ns: {"resolves": bool(r), "addresses": r}
            for ns, r in zip(target_ns, ns_a_results)
        }

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

    # Fan out all independent network calls concurrently
    ssl_data, dnssec_data, txt_records, dmarc_records, mx_records, status_data = parallel_calls(
        (seer.ssl, domain),
        (seer.dnssec, domain),
        (seer.dig, domain, "TXT"),
        (seer.dig, "_dmarc." + domain, "TXT"),
        (seer.dig, domain, "MX"),
        (seer.status, domain),
    )

    # SSL certificate analysis
    ssl_health = {"status": "unknown"}
    if ssl_data and isinstance(ssl_data, dict):
        # SslReport: is_valid, days_until_expiry, chain[], san_names[], protocol_version
        # CertDetail (chain[0]): issuer, subject, valid_from, valid_until, key_type, key_bits
        leaf = {}
        chain = ssl_data.get("chain", [])
        if chain and isinstance(chain, list) and len(chain) > 0:
            leaf = chain[0] if isinstance(chain[0], dict) else {}
        ssl_health = {
            "valid": ssl_data.get("is_valid", False),
            "issuer": leaf.get("issuer"),
            "expiry": leaf.get("valid_until"),
            "sans": ssl_data.get("san_names"),
            "protocol": ssl_data.get("protocol_version"),
        }
        is_valid = ssl_health.get("valid", False)
        if ssl_health.get("expiry"):
            days_left = _days_until(ssl_health["expiry"])
            if days_left is not None:
                ssl_health["days_until_expiry"] = days_left
                if not is_valid:
                    ssl_health["status"] = "critical"
                elif days_left < 7:
                    ssl_health["status"] = "critical"
                elif days_left < 30:
                    ssl_health["status"] = "warning"
                else:
                    ssl_health["status"] = "healthy"
            else:
                ssl_health["status"] = "healthy" if is_valid else "critical"
        else:
            ssl_health["status"] = "healthy" if is_valid else "critical"
    elif ssl_data is None:
        ssl_health = {"status": "critical", "error": "Could not retrieve SSL certificate"}

    # DNSSEC status (dnssec_data already fetched above)
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
    # (txt_records, dmarc_records, mx_records already fetched above)
    email_security = {
        "has_mx": bool(mx_records),
        "spf": {"found": False},
        "dmarc": {"found": False},
        "dkim_indicator": False,
    }

    if txt_records and isinstance(txt_records, list):
        for record in txt_records:
            record_text = record.get("data", {}).get("text", "") if isinstance(record, dict) else str(record)
            record_str = record_text.lower()
            if "v=spf1" in record_str:
                email_security["spf"] = {"found": True, "record": record_text}
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
            record_text = record.get("data", {}).get("text", "") if isinstance(record, dict) else str(record)
            record_str = record_text.lower()
            if "v=dmarc1" in record_str:
                email_security["dmarc"] = {"found": True, "record": record_text}
                if "p=reject" in record_str:
                    email_security["dmarc"]["policy"] = "reject"
                elif "p=quarantine" in record_str:
                    email_security["dmarc"]["policy"] = "quarantine"
                elif "p=none" in record_str:
                    email_security["dmarc"]["policy"] = "none_MONITORING_ONLY"

    # HTTP security check via status (status_data already fetched above)
    http_security = {"status": "unknown"}
    if status_data and isinstance(status_data, dict):
        status_cert = _get_cert(status_data)
        status_ssl_valid = status_cert.get("is_valid", False)
        http_security = {
            "http_status": status_data.get("http_status"),
            "ssl_valid": status_ssl_valid,
            "status": "healthy" if status_ssl_valid else "warning",
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

    # Only penalize SSL via http_security if ssl_health hasn't already penalized
    if (status_data is not None
            and not http_security.get("ssl_valid")
            and ssl_health.get("status") not in ("critical", "warning")):
        risk_score += 1

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

    # Common character substitutions (single-char homoglyphs)
    _substitutions = {
        "o": ["0"],
        "0": ["o"],
        "l": ["1", "i"],
        "1": ["l", "i"],
        "i": ["1", "l"],
        "s": ["5"],
        "5": ["s"],
        "a": ["4"],
        "e": ["3"],
    }
    for i, char in enumerate(brand):
        if char in _substitutions:
            for sub in _substitutions[char]:
                variants.add(brand[:i] + sub + brand[i + 1:])

    # Multi-character homoglyph substitutions (rn→m, vv→w, cl→d)
    _multi_subs = {
        "rn": "m", "m": "rn",
        "vv": "w", "w": "vv",
        "cl": "d", "d": "cl",
    }
    for pattern, replacement in _multi_subs.items():
        if pattern in brand:
            variants.add(brand.replace(pattern, replacement, 1))

    # Remove the original brand from variants
    variants.discard(brand)

    # Cap typo variants for network checks
    typo_variants = list(variants)[:30]

    # Check typo variants across key TLDs (not just .com)
    typo_tlds = ["com", "net", "org", "co"]
    typo_domains = [f"{v}.{tld}" for v in typo_variants for tld in typo_tlds]
    typo_domains = typo_domains[:100]  # Cap for bulk availability

    # Check TLD variants of the actual brand
    key_tlds = ["com", "net", "org", "io", "co"]
    tld_domains = [f"{brand}.{tld}" for tld in key_tlds]

    # Check all availability + subdomains concurrently
    all_check_domains = typo_domains + tld_domains
    avail_results = parallel_calls(
        *[(seer.availability, d) for d in all_check_domains],
        (seer.subdomains, primary_domain),
    )
    subdomain_data = avail_results[-1]

    # Split results back into typo vs TLD groups
    available_variants = []
    taken_variants = []
    check_failed = []
    for i, td in enumerate(typo_domains):
        result = avail_results[i]
        if result and isinstance(result, dict):
            if result.get("available", False):
                available_variants.append({"domain": td, "status": "available"})
            else:
                taken_variants.append({"domain": td, "status": "taken", "details": result})
        else:
            check_failed.append({"domain": td, "status": "unknown", "reason": "availability check failed"})

    tld_coverage = {}
    for i, td in enumerate(tld_domains):
        result = avail_results[len(typo_domains) + i]
        if result and isinstance(result, dict):
            tld_coverage[td] = {
                "available": result.get("available", False),
                "details": result,
            }
        else:
            tld_coverage[td] = {"available": None, "status": "unknown"}
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
        "check_failed": check_failed,
        "tld_coverage": tld_coverage,
        "subdomain_exposure": subdomain_exposure,
        "recommendations": [
            f"Register {len(available_variants)} available typosquatting variants for defensive protection"
            + (f" ({len(check_failed)} variants could not be checked)" if check_failed else "")
            if available_variants or check_failed
            else "No immediate typosquatting variants available to register",
            f"{subdomain_exposure['count']} subdomains exposed via Certificate Transparency logs"
            if subdomain_exposure["count"] > 0 else "No subdomain exposure detected via CT logs",
        ],
    }, default=str)


@tool
def dns_health_check(domain: str) -> str:
    """Comprehensive DNS health check: record completeness, propagation consistency,
    nameserver comparison, and best practice compliance."""
    domain = domain.lower().strip()

    # Check essential record types + propagation concurrently
    essential_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"]
    dhc_results = parallel_calls(
        *[(seer.dig, domain, rt) for rt in essential_types],
        (seer.propagation, domain, "A"),
    )
    records_found = {}
    records_missing = []
    for i, rtype in enumerate(essential_types):
        if dhc_results[i]:
            records_found[rtype] = dhc_results[i]
        else:
            records_missing.append(rtype)
    propagation_status = dhc_results[len(essential_types)]

    # Nameserver consistency check
    nameserver_consistency = None
    ns_records = records_found.get("NS")
    if ns_records and isinstance(ns_records, list) and len(ns_records) >= 2:
        ns_a = (ns_records[0].get("data", {}).get("nameserver", "") if isinstance(ns_records[0], dict) else str(ns_records[0])).rstrip(".")
        ns_b = (ns_records[1].get("data", {}).get("nameserver", "") if isinstance(ns_records[1], dict) else str(ns_records[1])).rstrip(".")
        compare_result = safe_call(seer.dns_compare, domain, "A", ns_a, ns_b) if ns_a and ns_b else None
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
        spf_records = [
            r for r in records_found["TXT"]
            if "v=spf1" in (r.get("data", {}).get("text", "") if isinstance(r, dict) else str(r)).lower()
        ]
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

    # Weighted health scoring — critical records are worth more
    recommendations = []
    score = 0
    max_score = 0

    # Critical records (weight 3)
    max_score += 3
    has_a = "A" in records_found
    has_aaaa = "AAAA" in records_found
    if has_a or has_aaaa:
        score += 3
        if not has_a and has_aaaa:
            recommendations.append("IPv6-only (AAAA but no A record) — ensure IPv4 clients have a fallback")
    else:
        recommendations.append("No A or AAAA record — domain will not resolve to any IP address")

    max_score += 3
    if "SOA" in records_found:
        score += 3
    else:
        recommendations.append("Missing SOA record — critical for zone authority")

    max_score += 3
    if ns_records and isinstance(ns_records, list) and len(ns_records) >= 2:
        score += 3
    else:
        recommendations.append("Ensure at least 2 nameservers for redundancy")

    # Important records (weight 2)
    # SPF only relevant when MX exists
    has_mx = "MX" in records_found
    if has_mx:
        max_score += 2
        if spf_found:
            score += 2
        else:
            recommendations.append("Has MX records but no SPF — add SPF to prevent email spoofing")

    max_score += 2
    if "CAA" in records_found:
        score += 2
    else:
        recommendations.append("No CAA record — consider adding to restrict certificate issuance")

    # Optional records (weight 1)
    max_score += 1
    if has_aaaa:
        score += 1
    elif has_a:
        recommendations.append("No AAAA record — consider adding IPv6 support")

    max_score += 1
    if has_mx:
        score += 1

    health_score = round((score / max_score) * 100) if max_score > 0 else 0

    return json.dumps({
        "domain": domain,
        "health_score": health_score,
        "score_detail": f"{score}/{max_score} (weighted)",
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

    # Fan out all independent lookups concurrently
    lookup_raw, dns_a, dns_ns, ssl_data, status_data = parallel_calls(
        (seer.lookup, domain),
        (seer.dig, domain, "A"),
        (seer.dig, domain, "NS"),
        (seer.ssl, domain),
        (seer.status, domain),
    )
    reg_data = _extract_registration(lookup_raw)

    # Build timeline events
    timeline = []

    if reg_data and isinstance(reg_data, dict) and not reg_data.get("error"):
        created = reg_data.get("creation_date")
        if created:
            timeline.append({
                "date": str(created)[:10],
                "event": "domain_registered",
                "detail": f"Domain registered via {reg_data.get('registrar', 'unknown registrar')}",
            })

        updated = reg_data.get("updated_date")
        if updated:
            timeline.append({
                "date": str(updated)[:10],
                "event": "registration_updated",
                "detail": "WHOIS/RDAP record last updated",
            })

        expiry = reg_data.get("expiration_date")
        if expiry:
            days_left = _days_until(expiry)
            timeline.append({
                "date": str(expiry)[:10],
                "event": "domain_expires",
                "detail": (
                    f"Registration expired {abs(days_left)} days ago" if days_left is not None and days_left < 0
                    else f"Registration expires ({days_left} days remaining)" if days_left is not None
                    else "Registration expiry date"
                ),
            })

    if ssl_data and isinstance(ssl_data, dict):
        # SslReport has chain[] with CertDetail items; dates and issuer live on chain[0]
        ssl_chain = ssl_data.get("chain", [])
        ssl_leaf = ssl_chain[0] if ssl_chain and isinstance(ssl_chain, list) and isinstance(ssl_chain[0], dict) else {}
        not_before = ssl_leaf.get("valid_from")
        not_after = ssl_leaf.get("valid_until")
        issuer = ssl_leaf.get("issuer", "unknown CA")

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
                "detail": (
                    f"SSL certificate expired {abs(ssl_days)} days ago" if ssl_days is not None and ssl_days < 0
                    else f"SSL certificate expires ({ssl_days} days remaining)" if ssl_days is not None
                    else "SSL certificate expiry"
                ),
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
        "ssl_valid": _get_cert(status_data).get("is_valid") if status_data else None,
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

    expired = []    # already expired (days < 0)
    critical = []   # <7 days
    warning = []    # <30 days
    upcoming = []   # <90 days
    healthy = []    # >90 days
    unknown = []    # Could not determine

    for i, domain in enumerate(domain_list):
        raw = bulk_results[i] if i < len(bulk_results) else None
        result = _unwrap_bulk(raw) if raw and isinstance(raw, dict) and "operation" in raw else raw
        entry = {"domain": domain}

        reg = _extract_registration(result)
        if reg and reg.get("source"):
            expiry = reg.get("expiration_date")
            registrar = reg.get("registrar")
            entry["expiry"] = str(expiry) if expiry else None
            entry["registrar"] = registrar

            if expiry:
                days_left = _days_until(expiry)
                if days_left is not None:
                    entry["days_remaining"] = days_left
                    if days_left < 0:
                        entry["urgency"] = "expired"
                        expired.append(entry)
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

    # Sort each category by days remaining (most urgent first).
    # expired uses reverse=True so most-recently-expired (-1 days) appears before
    # long-expired (-365 days), since the recently-expired may still be in grace period.
    expired.sort(key=lambda e: e.get("days_remaining", 99999), reverse=True)
    for category in (critical, warning, upcoming, healthy):
        category.sort(key=lambda e: e.get("days_remaining", 99999))

    return json.dumps({
        "source": source,
        "total_checked": len(domain_list),
        "summary": {
            "expired": len(expired),
            "critical": len(critical),
            "warning": len(warning),
            "upcoming": len(upcoming),
            "healthy": len(healthy),
            "unknown": len(unknown),
        },
        "expired": expired,
        "critical": critical,
        "warning": warning,
        "upcoming": upcoming,
        "healthy": healthy,
        "unknown": unknown,
    }, default=str)


def _audit_one(domain: str) -> dict:
    """Gather all security signals for a single domain (used by compare_security).

    Returns a dict with ssl, dnssec, email, http, dns_zone, infrastructure
    sections plus an overall risk_score.
    """
    # Fan out every probe for this domain concurrently
    (ssl_data, dnssec_data, txt_records, dmarc_records, mx_records,
     ns_records, caa_records, a_records, cname_records, status_data) = parallel_calls(
        (seer.ssl, domain),
        (seer.dnssec, domain),
        (seer.dig, domain, "TXT"),
        (seer.dig, f"_dmarc.{domain}", "TXT"),
        (seer.dig, domain, "MX"),
        (seer.dig, domain, "NS"),
        (seer.dig, domain, "CAA"),
        (seer.dig, domain, "A"),
        (seer.dig, domain, "CNAME"),
        (seer.status, domain),
    )

    risk_score = 0

    # --- SSL ---
    ssl_section = {"status": "unknown", "valid": False}
    if ssl_data and isinstance(ssl_data, dict):
        chain = ssl_data.get("chain", [])
        leaf = chain[0] if chain and isinstance(chain, list) and isinstance(chain[0], dict) else {}
        ssl_section = {
            "valid": ssl_data.get("is_valid", False),
            "issuer": leaf.get("issuer"),
            "expiry": leaf.get("valid_until"),
            "key_type": leaf.get("key_type"),
            "key_bits": leaf.get("key_bits"),
            "protocol": ssl_data.get("protocol_version"),
            "san_count": len(ssl_data.get("san_names") or []),
        }
        days_left = _days_until(leaf.get("valid_until")) if leaf.get("valid_until") else None
        if days_left is not None:
            ssl_section["days_until_expiry"] = days_left
        if not ssl_section["valid"]:
            ssl_section["status"] = "critical"
            risk_score += 3
        elif days_left is not None and days_left < 7:
            ssl_section["status"] = "critical"
            risk_score += 3
        elif days_left is not None and days_left < 30:
            ssl_section["status"] = "warning"
            risk_score += 1
        else:
            ssl_section["status"] = "healthy"
    elif ssl_data is None:
        ssl_section = {"status": "error", "valid": False, "error": "Could not retrieve certificate"}
        risk_score += 3

    # --- DNSSEC ---
    dnssec_section = {"status": "unknown", "enabled": False}
    if dnssec_data and isinstance(dnssec_data, dict):
        enabled = dnssec_data.get("enabled", False) or dnssec_data.get("has_ds_records", False)
        valid = dnssec_data.get("valid", False)
        dnssec_section = {
            "enabled": enabled,
            "valid": valid,
            "issues": dnssec_data.get("issues") or [],
            "status": "healthy" if valid else ("warning" if enabled else "not_configured"),
        }
        if not enabled:
            risk_score += 1
        elif not valid:
            risk_score += 2

    # --- Email auth ---
    email_section = {"has_mx": bool(mx_records), "spf": "missing", "dmarc": "missing"}
    if txt_records and isinstance(txt_records, list):
        for rec in txt_records:
            txt = rec.get("data", {}).get("text", "") if isinstance(rec, dict) else str(rec)
            if "v=spf1" in txt.lower():
                if "-all" in txt.lower():
                    email_section["spf"] = "strict"
                elif "~all" in txt.lower():
                    email_section["spf"] = "softfail"
                elif "+all" in txt.lower():
                    email_section["spf"] = "permissive_INSECURE"
                    risk_score += 3
                else:
                    email_section["spf"] = "present"
                break
    if dmarc_records and isinstance(dmarc_records, list):
        for rec in dmarc_records:
            txt = rec.get("data", {}).get("text", "") if isinstance(rec, dict) else str(rec)
            if "v=dmarc1" in txt.lower():
                if "p=reject" in txt.lower():
                    email_section["dmarc"] = "reject"
                elif "p=quarantine" in txt.lower():
                    email_section["dmarc"] = "quarantine"
                elif "p=none" in txt.lower():
                    email_section["dmarc"] = "none"
                    risk_score += 1
                else:
                    email_section["dmarc"] = "present"
                break
    if email_section["has_mx"]:
        if email_section["spf"] == "missing":
            risk_score += 2
        if email_section["dmarc"] == "missing":
            risk_score += 2

    # --- CAA ---
    caa_section = {"has_records": bool(caa_records), "has_issuewild": False, "has_iodef": False}
    if caa_records and isinstance(caa_records, list):
        for rec in caa_records:
            data = rec.get("data", rec) if isinstance(rec, dict) else {}
            if isinstance(data, dict):
                tag = data.get("tag", "")
                if tag == "issuewild":
                    caa_section["has_issuewild"] = True
                elif tag == "iodef":
                    caa_section["has_iodef"] = True
    if not caa_section["has_records"]:
        risk_score += 1

    # --- Nameservers ---
    ns_list = []
    if ns_records and isinstance(ns_records, list):
        for rec in ns_records:
            ns = (rec.get("data", rec) if isinstance(rec, dict) else {})
            if isinstance(ns, dict):
                ns_list.append(ns.get("nameserver", "").rstrip("."))
            else:
                ns_list.append(str(ns).rstrip("."))
    ns_section = {"count": len(ns_list), "nameservers": ns_list[:6]}
    if len(ns_list) < 2:
        risk_score += 2

    # --- Infrastructure ---
    from .pentest_tools import _identify_cdn_from_cname, _identify_hosting
    infra_section = {"cdn_waf": [], "hosting": []}
    if cname_records and isinstance(cname_records, list):
        for rec in cname_records:
            data = rec.get("data", rec) if isinstance(rec, dict) else {}
            target = (data.get("target", "") if isinstance(data, dict) else str(data)).lower().rstrip(".")
            cdn = _identify_cdn_from_cname(target)
            if cdn and cdn not in infra_section["cdn_waf"]:
                infra_section["cdn_waf"].append(cdn)
    if a_records and isinstance(a_records, list):
        for rec in a_records:
            data = rec.get("data", rec) if isinstance(rec, dict) else {}
            ip = (data.get("address", "") if isinstance(data, dict) else str(data))
            provider = _identify_hosting(str(ip))
            if provider and provider not in infra_section["hosting"]:
                infra_section["hosting"].append(provider)

    # --- HTTP ---
    http_section = {"status": "unknown"}
    if status_data and isinstance(status_data, dict):
        cert = _get_cert(status_data)
        ssl_valid = cert.get("is_valid", False)
        http_section = {
            "http_status": status_data.get("http_status"),
            "ssl_valid": ssl_valid,
            "status": "healthy" if ssl_valid else "warning",
        }
        if not ssl_valid and ssl_section.get("status") not in ("critical", "warning"):
            risk_score += 1

    # --- Overall ---
    if risk_score >= 8:
        overall = "critical"
    elif risk_score >= 5:
        overall = "high"
    elif risk_score >= 2:
        overall = "medium"
    else:
        overall = "low"

    return {
        "domain": domain,
        "overall_risk": overall,
        "risk_score": risk_score,
        "ssl": ssl_section,
        "dnssec": dnssec_section,
        "email_auth": email_section,
        "caa": caa_section,
        "nameservers": ns_section,
        "infrastructure": infra_section,
        "http": http_section,
    }


_STATUS_RANK = {"critical": 0, "error": 0, "warning": 1, "not_configured": 2, "unknown": 3, "healthy": 4}

# SPF / DMARC strength ordering (higher index = stronger)
_SPF_RANK = {"missing": 0, "present": 1, "neutral": 1, "permissive_INSECURE": 0, "softfail": 2, "strict": 3}
_DMARC_RANK = {"missing": 0, "present": 1, "none": 1, "quarantine": 2, "reject": 3}


def _summarize_ssl(ssl: dict) -> str:
    """One-liner summary of an SSL audit section."""
    st = ssl.get("status", "unknown")
    if st in ("error", "unknown"):
        return ssl.get("error", "No certificate retrieved")
    parts = []
    if ssl.get("valid"):
        parts.append("Valid")
    else:
        parts.append("INVALID")
    days = ssl.get("days_until_expiry")
    if days is not None:
        parts.append(f"{days}d until expiry")
    kt = ssl.get("key_type")
    kb = ssl.get("key_bits")
    if kt:
        parts.append(f"{kt}-{kb}" if kb else kt)
    issuer = ssl.get("issuer", "")
    # Extract just the CN from the issuer string
    if "CN=" in issuer:
        cn = issuer.split("CN=")[-1].split(",")[0].strip()
        parts.append(cn)
    elif issuer:
        parts.append(issuer[:40])
    sans = ssl.get("san_count")
    if sans and sans > 1:
        parts.append(f"{sans} SANs")
    return ", ".join(parts)


def _summarize_dnssec(dnssec: dict) -> str:
    st = dnssec.get("status", "unknown")
    if st == "healthy":
        return "Enabled and valid"
    if st == "warning":
        issues = dnssec.get("issues", [])
        return f"Enabled but incomplete ({issues[0]})" if issues else "Enabled but not fully valid"
    if st == "not_configured":
        return "Not configured"
    return "Unknown"


def _summarize_email(email: dict) -> str:
    parts = []
    spf = email.get("spf", "missing")
    dmarc = email.get("dmarc", "missing")
    parts.append(f"SPF: {spf}")
    parts.append(f"DMARC: {dmarc}")
    if not email.get("has_mx"):
        parts.append("(no MX)")
    return " | ".join(parts)


def _summarize_caa(caa: dict) -> str:
    if not caa.get("has_records"):
        return "No CAA records"
    tags = []
    if caa.get("has_issuewild"):
        tags.append("issuewild")
    if caa.get("has_iodef"):
        tags.append("iodef")
    return f"Present{' (' + ', '.join(tags) + ')' if tags else ' (no issuewild/iodef)'}"


def _summarize_ns(ns: dict) -> str:
    count = ns.get("count", 0)
    names = ns.get("nameservers", [])
    if count == 0:
        return "None found"
    preview = ", ".join(names[:3])
    if count > 3:
        preview += f" (+{count - 3} more)"
    return f"{count} NS: {preview}"


def _summarize_infra(infra: dict) -> str:
    parts = []
    cdns = infra.get("cdn_waf", [])
    hosts = infra.get("hosting", [])
    if cdns:
        parts.append("CDN/WAF: " + ", ".join(cdns))
    if hosts:
        parts.append("Hosting: " + ", ".join(hosts))
    return " | ".join(parts) if parts else "No CDN/WAF or hosting detected"


def _summarize_http(http: dict) -> str:
    st = http.get("status", "unknown")
    code = http.get("http_status")
    ssl_ok = http.get("ssl_valid")
    parts = []
    if code is not None:
        parts.append(f"HTTP {code}")
    else:
        parts.append("No HTTP response")
    if ssl_ok:
        parts.append("SSL valid")
    elif ssl_ok is False:
        parts.append("SSL invalid")
    return " | ".join(parts)


def _verdict(val_a, val_b, name_a: str, name_b: str, *,
             higher_is_better=False, lower_is_better=False,
             status_field=False, rank_map=None) -> str:
    """Return the winning domain name, 'equal', or 'different'."""
    if val_a == val_b:
        return "equal"
    if rank_map is not None:
        ra = rank_map.get(val_a, -1)
        rb = rank_map.get(val_b, -1)
        if ra > rb:
            return name_a
        if rb > ra:
            return name_b
        return "equal"
    if status_field:
        ra = _STATUS_RANK.get(val_a, 3)
        rb = _STATUS_RANK.get(val_b, 3)
        if ra > rb:
            return name_a
        if rb > ra:
            return name_b
        return "equal"
    if isinstance(val_a, (int, float)) and isinstance(val_b, (int, float)):
        if higher_is_better:
            return name_a if val_a > val_b else name_b
        if lower_is_better:
            return name_a if val_a < val_b else name_b
    if isinstance(val_a, bool) and isinstance(val_b, bool):
        if val_a and not val_b:
            return name_a
        if val_b and not val_a:
            return name_b
    return "different"


@tool
def compare_security(domain_a: str, domain_b: str) -> str:
    """Deep side-by-side security comparison of two domains. Audits both domains
    concurrently across SSL/TLS, DNSSEC, email authentication (SPF/DMARC),
    CAA policy, nameserver redundancy, CDN/WAF presence, and HTTP posture.
    Returns a pre-formatted comparison table with per-category verdicts and
    an overall winner."""
    domain_a = domain_a.lower().strip()
    domain_b = domain_b.lower().strip()

    # Run both full audits concurrently
    audit_a, audit_b = parallel_calls(
        (_audit_one, domain_a),
        (_audit_one, domain_b),
    )

    # Build category-level comparison with pre-summarized one-liners.
    # Verdicts use the actual domain name so the LLM never has to decode
    # abstract A/B labels.
    categories = [
        {
            "category": "SSL/TLS",
            domain_a: _summarize_ssl(audit_a["ssl"]),
            domain_b: _summarize_ssl(audit_b["ssl"]),
            "winner": _verdict(audit_a["ssl"]["status"], audit_b["ssl"]["status"],
                               domain_a, domain_b, status_field=True),
        },
        {
            "category": "DNSSEC",
            domain_a: _summarize_dnssec(audit_a["dnssec"]),
            domain_b: _summarize_dnssec(audit_b["dnssec"]),
            "winner": _verdict(audit_a["dnssec"]["status"], audit_b["dnssec"]["status"],
                               domain_a, domain_b, status_field=True),
        },
        {
            "category": "Email Auth",
            domain_a: _summarize_email(audit_a["email_auth"]),
            domain_b: _summarize_email(audit_b["email_auth"]),
            "winner": _verdict(
                _SPF_RANK.get(audit_a["email_auth"]["spf"], 0) + _DMARC_RANK.get(audit_a["email_auth"]["dmarc"], 0),
                _SPF_RANK.get(audit_b["email_auth"]["spf"], 0) + _DMARC_RANK.get(audit_b["email_auth"]["dmarc"], 0),
                domain_a, domain_b, higher_is_better=True,
            ),
        },
        {
            "category": "CAA Policy",
            domain_a: _summarize_caa(audit_a["caa"]),
            domain_b: _summarize_caa(audit_b["caa"]),
            "winner": _verdict(audit_a["caa"]["has_records"], audit_b["caa"]["has_records"],
                               domain_a, domain_b),
        },
        {
            "category": "Nameservers",
            domain_a: _summarize_ns(audit_a["nameservers"]),
            domain_b: _summarize_ns(audit_b["nameservers"]),
            "winner": _verdict(
                audit_a["nameservers"]["count"], audit_b["nameservers"]["count"],
                domain_a, domain_b, higher_is_better=True,
            ),
        },
        {
            "category": "Infrastructure",
            domain_a: _summarize_infra(audit_a["infrastructure"]),
            domain_b: _summarize_infra(audit_b["infrastructure"]),
            "winner": _verdict(
                bool(audit_a["infrastructure"]["cdn_waf"]),
                bool(audit_b["infrastructure"]["cdn_waf"]),
                domain_a, domain_b,
            ),
        },
        {
            "category": "HTTP",
            domain_a: _summarize_http(audit_a["http"]),
            domain_b: _summarize_http(audit_b["http"]),
            "winner": _verdict(audit_a["http"]["status"], audit_b["http"]["status"],
                               domain_a, domain_b, status_field=True),
        },
    ]

    # Tally verdicts
    a_wins = sum(1 for c in categories if c["winner"] == domain_a)
    b_wins = sum(1 for c in categories if c["winner"] == domain_b)
    ties = sum(1 for c in categories if c["winner"] in ("equal", "different"))

    score_a = audit_a["risk_score"]
    score_b = audit_b["risk_score"]
    if score_a < score_b:
        winner = domain_a
    elif score_b < score_a:
        winner = domain_b
    else:
        winner = "tie"

    return json.dumps({
        "domain_a": domain_a,
        "domain_b": domain_b,
        "comparison": categories,
        "scores": {
            domain_a: {"risk_score": score_a, "overall_risk": audit_a["overall_risk"]},
            domain_b: {"risk_score": score_b, "overall_risk": audit_b["overall_risk"]},
        },
        "tally": {f"{domain_a} wins": a_wins, f"{domain_b} wins": b_wins, "equal": ties},
        "winner": winner,
        "risk_margin": abs(score_a - score_b),
    }, default=str)


COMPOSITE_ADVISOR_TOOLS = [
    security_audit,
    brand_protection_scan,
    dns_health_check,
    domain_timeline,
    expiration_alert,
    compare_security,
]
