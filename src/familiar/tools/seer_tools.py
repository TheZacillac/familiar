"""Seer domain intelligence tools wrapped for LangChain."""

import json
import logging
import time
from typing import Optional

import seer
from langchain_core.tools import tool

logger = logging.getLogger("familiar.tools.seer")


def _seer_call(fn, *args, op: str, **kwargs) -> str:
    """Time, log, and serialize a seer call.

    On success, returns ``json.dumps(result, default=str)``. On failure,
    returns ``json.dumps({"error": str(e), "error_type": type(e).__name__})``
    so the LLM can distinguish e.g. a timeout from an NXDOMAIN from a
    library bug. The ``op`` string is used for log lines and should
    identify the tool by name (``"seer_lookup"``, etc).
    """
    start = time.monotonic()
    logger.debug("%s called", op)
    try:
        result = fn(*args, **kwargs)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("%s completed: elapsed_ms=%.1f", op, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning(
            "%s failed: elapsed_ms=%.1f error_type=%s error=%s",
            op, elapsed, type(e).__name__, e,
        )
        return json.dumps({"error": str(e), "error_type": type(e).__name__})


@tool
def seer_lookup(domain: str) -> str:
    """Smart domain lookup — tries RDAP first, falls back to WHOIS. Returns registration data with source indicator."""
    return _seer_call(seer.lookup, domain, op="seer_lookup")


@tool
def seer_whois(domain: str) -> str:
    """Look up WHOIS information for a domain. Returns registrar, dates, nameservers, and status."""
    return _seer_call(seer.whois, domain, op="seer_whois")


@tool
def seer_rdap_domain(domain: str) -> str:
    """Look up RDAP information for a domain. Returns structured registration data including registrar, dates, and DNSSEC status."""
    return _seer_call(seer.rdap_domain, domain, op="seer_rdap_domain")


@tool
def seer_rdap(query: str) -> str:
    """Auto-routing RDAP lookup for a domain, IP address, or ASN. Classification happens in Rust so domains starting with 'AS' (e.g. as1234.io) are not misrouted to the ASN endpoint. Use when the query type is not known in advance."""
    return _seer_call(seer.rdap, query, op="seer_rdap")


@tool
def seer_info(domain: str) -> str:
    """Lightweight domain metadata summary. Returns a flat, registrar-agnostic view (domain, registrar, creation/expiration, nameservers, status) derived from the smart lookup. Cheaper than seer_lookup when only a summary is needed."""
    return _seer_call(seer.info, domain, op="seer_info")


@tool
def seer_rdap_ip(ip: str) -> str:
    """Look up RDAP information for an IP address. Returns network range, country, and responsible organization."""
    return _seer_call(seer.rdap_ip, ip, op="seer_rdap_ip")


@tool
def seer_rdap_asn(asn: int) -> str:
    """Look up RDAP information for an Autonomous System Number (ASN). Returns organization and network range info."""
    return _seer_call(seer.rdap_asn, asn, op="seer_rdap_asn")


@tool
def seer_dig(domain: str, record_type: str = "A", nameserver: Optional[str] = None) -> str:
    """Query DNS records for a domain (like the dig command). Supports record types: A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR, SRV, ANY."""
    return _seer_call(seer.dig, domain, record_type, nameserver, op="seer_dig")


@tool
def seer_propagation(domain: str, record_type: str = "A") -> str:
    """Check DNS propagation across global DNS servers. Shows which servers have the record and identifies inconsistencies."""
    return _seer_call(seer.propagation, domain, record_type, op="seer_propagation")


@tool
def seer_status(domain: str) -> str:
    """Check domain health: HTTP accessibility, SSL certificate validity, and domain expiration."""
    return _seer_call(seer.status, domain, op="seer_status")


@tool
def seer_bulk_lookup(domains: list[str], concurrency: int = 10) -> str:
    """Smart lookup for multiple domains at once (RDAP first, WHOIS fallback). Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_lookup, domains, concurrency, op="seer_bulk_lookup")


@tool
def seer_bulk_whois(domains: list[str], concurrency: int = 10) -> str:
    """WHOIS lookup for multiple domains at once. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_whois, domains, concurrency, op="seer_bulk_whois")


@tool
def seer_bulk_dig(domains: list[str], record_type: str = "A", concurrency: int = 10) -> str:
    """Query DNS records for multiple domains at once. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_dig, domains, record_type, concurrency, op="seer_bulk_dig")


@tool
def seer_bulk_status(domains: list[str], concurrency: int = 10) -> str:
    """Check health status for multiple domains at once. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_status, domains, concurrency, op="seer_bulk_status")


@tool
def seer_bulk_propagation(domains: list[str], record_type: str = "A", concurrency: int = 5) -> str:
    """Check DNS propagation for multiple domains across global DNS servers. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_propagation, domains, record_type, concurrency, op="seer_bulk_propagation")


@tool
def seer_availability(domain: str) -> str:
    """Check if a domain is available for registration. Returns availability status with confidence level and detection method."""
    return _seer_call(seer.availability, domain, op="seer_availability")


@tool
def seer_subdomains(domain: str) -> str:
    """Enumerate subdomains of a domain using Certificate Transparency logs. Returns discovered subdomains and count."""
    return _seer_call(seer.subdomains, domain, op="seer_subdomains")


@tool
def seer_ssl(domain: str) -> str:
    """Analyze SSL/TLS certificate for a domain. Returns certificate chain, validity, expiry, SANs, and protocol details."""
    return _seer_call(seer.ssl, domain, op="seer_ssl")


@tool
def seer_dnssec(domain: str) -> str:
    """Check DNSSEC configuration for a domain. Returns DS/DNSKEY records, validation status, and any issues found."""
    return _seer_call(seer.dnssec, domain, op="seer_dnssec")


@tool
def seer_dns_compare(domain: str, record_type: str, server_a: str, server_b: str) -> str:
    """Compare DNS records for a domain between two nameservers. Shows matching records, differences, and records unique to each server."""
    return _seer_call(seer.dns_compare, domain, record_type, server_a, server_b, op="seer_dns_compare")


@tool
def seer_dns_follow(domain: str, record_type: str = "A", nameserver: Optional[str] = None, iterations: int = 3, interval_minutes: float = 1.0) -> str:
    """Monitor DNS record changes over time. Queries the record repeatedly at the specified interval and reports changes between iterations."""
    iterations = max(1, min(iterations, 10))
    interval_minutes = max(0.1, min(interval_minutes, 5.0))
    return _seer_call(
        seer.dns_follow, domain, record_type, nameserver, iterations, interval_minutes,
        op="seer_dns_follow",
    )


@tool
def seer_diff(domain_a: str, domain_b: str) -> str:
    """Compare two domains side-by-side across registration, DNS, and SSL. Shows differences in registrar, nameservers, A records, and certificates."""
    return _seer_call(seer.diff, domain_a, domain_b, op="seer_diff")


@tool
def seer_bulk_availability(domains: list[str] | str, concurrency: int = 10) -> str:
    """Check domain registration availability in bulk. Each result includes available (bool), confidence level, and check method. Uses concurrent RDAP/WHOIS checks for speed. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    # The `| str` in the type hint is what lets Pydantic accept a JSON-string
    # literal so the shim below stays reachable for LLMs that emit one.
    if isinstance(domains, str):
        try:
            domains = json.loads(domains)
        except json.JSONDecodeError:
            return json.dumps({"error": "domains must be a list of strings"})
    # Guard against a JSON literal like `"foo.com"` decoding to a string,
    # which would otherwise make ``seer.bulk_availability`` iterate characters.
    if not isinstance(domains, list):
        return json.dumps({"error": "domains must be a list of strings"})
    return _seer_call(seer.bulk_availability, domains, concurrency, op="seer_bulk_availability")


@tool
def seer_bulk_ssl(domains: list[str], concurrency: int = 10) -> str:
    """Deep SSL/TLS chain inspection for multiple domains at once. Returns full certificate chain, validity, expiry, SANs, and protocol details per domain — same payload as seer_ssl. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_ssl, domains, concurrency, op="seer_bulk_ssl")


@tool
def seer_bulk_info(domains: list[str], concurrency: int = 10) -> str:
    """Lightweight bulk metadata lookup for multiple domains. Returns a flat domain-info summary (registrar, dates, nameservers, status) per domain. Cheaper than seer_bulk_lookup when only a summary is needed. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    return _seer_call(seer.bulk_info, domains, concurrency, op="seer_bulk_info")


SEER_TOOLS = [
    seer_lookup,
    seer_info,
    seer_whois,
    seer_rdap,
    seer_rdap_domain,
    seer_rdap_ip,
    seer_rdap_asn,
    seer_dig,
    seer_propagation,
    seer_status,
    seer_availability,
    seer_subdomains,
    seer_ssl,
    seer_dnssec,
    seer_dns_compare,
    seer_dns_follow,
    seer_diff,
    seer_bulk_lookup,
    seer_bulk_info,
    seer_bulk_whois,
    seer_bulk_dig,
    seer_bulk_status,
    seer_bulk_propagation,
    seer_bulk_ssl,
    seer_bulk_availability,
]
