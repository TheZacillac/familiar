"""Seer domain intelligence tools wrapped for LangChain."""

import json
import logging
import time
from typing import Optional

import seer
from langchain_core.tools import tool

logger = logging.getLogger("familiar.tools.seer")


@tool
def seer_lookup(domain: str) -> str:
    """Smart domain lookup — tries RDAP first, falls back to WHOIS. Returns registration data with source indicator."""
    start = time.monotonic()
    logger.debug("seer_lookup called: domain=%s", domain)
    try:
        result = seer.lookup(domain)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_lookup completed: domain=%s elapsed_ms=%.1f", domain, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_lookup failed: domain=%s elapsed_ms=%.1f error=%s", domain, elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_whois(domain: str) -> str:
    """Look up WHOIS information for a domain. Returns registrar, dates, nameservers, and status."""
    start = time.monotonic()
    logger.debug("seer_whois called: domain=%s", domain)
    try:
        result = seer.whois(domain)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_whois completed: domain=%s elapsed_ms=%.1f", domain, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_whois failed: domain=%s elapsed_ms=%.1f error=%s", domain, elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_rdap_domain(domain: str) -> str:
    """Look up RDAP information for a domain. Returns structured registration data including registrar, dates, and DNSSEC status."""
    start = time.monotonic()
    logger.debug("seer_rdap_domain called: domain=%s", domain)
    try:
        result = seer.rdap_domain(domain)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_rdap_domain completed: domain=%s elapsed_ms=%.1f", domain, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_rdap_domain failed: domain=%s elapsed_ms=%.1f error=%s", domain, elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_rdap_ip(ip: str) -> str:
    """Look up RDAP information for an IP address. Returns network range, country, and responsible organization."""
    logger.debug("seer_rdap_ip called: ip=%s", ip)
    try:
        return json.dumps(seer.rdap_ip(ip), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_rdap_asn(asn: int) -> str:
    """Look up RDAP information for an Autonomous System Number (ASN). Returns organization and network range info."""
    logger.debug("seer_rdap_asn called: asn=%s", asn)
    try:
        return json.dumps(seer.rdap_asn(asn), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dig(domain: str, record_type: str = "A", nameserver: Optional[str] = None) -> str:
    """Query DNS records for a domain (like the dig command). Supports record types: A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR, SRV, ANY."""
    start = time.monotonic()
    logger.debug("seer_dig called: domain=%s record_type=%s nameserver=%s", domain, record_type, nameserver)
    try:
        result = seer.dig(domain, record_type, nameserver)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_dig completed: domain=%s record_type=%s elapsed_ms=%.1f", domain, record_type, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_dig failed: domain=%s record_type=%s elapsed_ms=%.1f error=%s", domain, record_type, elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_propagation(domain: str, record_type: str = "A") -> str:
    """Check DNS propagation across global DNS servers. Shows which servers have the record and identifies inconsistencies."""
    start = time.monotonic()
    logger.debug("seer_propagation called: domain=%s record_type=%s", domain, record_type)
    try:
        result = seer.propagation(domain, record_type)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_propagation completed: domain=%s record_type=%s elapsed_ms=%.1f", domain, record_type, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_propagation failed: domain=%s record_type=%s elapsed_ms=%.1f error=%s", domain, record_type, elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_status(domain: str) -> str:
    """Check domain health: HTTP accessibility, SSL certificate validity, and domain expiration."""
    start = time.monotonic()
    logger.debug("seer_status called: domain=%s", domain)
    try:
        result = seer.status(domain)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_status completed: domain=%s elapsed_ms=%.1f", domain, elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_status failed: domain=%s elapsed_ms=%.1f error=%s", domain, elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_lookup(domains: list[str], concurrency: int = 10) -> str:
    """Smart lookup for multiple domains at once (RDAP first, WHOIS fallback). Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    start = time.monotonic()
    logger.debug("seer_bulk_lookup called: count=%d concurrency=%d", len(domains), concurrency)
    try:
        result = seer.bulk_lookup(domains, concurrency)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_bulk_lookup completed: count=%d elapsed_ms=%.1f", len(domains), elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_bulk_lookup failed: count=%d elapsed_ms=%.1f error=%s", len(domains), elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_whois(domains: list[str], concurrency: int = 10) -> str:
    """WHOIS lookup for multiple domains at once. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    start = time.monotonic()
    logger.debug("seer_bulk_whois called: count=%d concurrency=%d", len(domains), concurrency)
    try:
        result = seer.bulk_whois(domains, concurrency)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_bulk_whois completed: count=%d elapsed_ms=%.1f", len(domains), elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_bulk_whois failed: count=%d elapsed_ms=%.1f error=%s", len(domains), elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_dig(domains: list[str], record_type: str = "A", concurrency: int = 10) -> str:
    """Query DNS records for multiple domains at once. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    start = time.monotonic()
    logger.debug("seer_bulk_dig called: count=%d record_type=%s concurrency=%d", len(domains), record_type, concurrency)
    try:
        result = seer.bulk_dig(domains, record_type, concurrency)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_bulk_dig completed: count=%d elapsed_ms=%.1f", len(domains), elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_bulk_dig failed: count=%d elapsed_ms=%.1f error=%s", len(domains), elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_status(domains: list[str], concurrency: int = 10) -> str:
    """Check health status for multiple domains at once. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    start = time.monotonic()
    logger.debug("seer_bulk_status called: count=%d concurrency=%d", len(domains), concurrency)
    try:
        result = seer.bulk_status(domains, concurrency)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_bulk_status completed: count=%d elapsed_ms=%.1f", len(domains), elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_bulk_status failed: count=%d elapsed_ms=%.1f error=%s", len(domains), elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_propagation(domains: list[str], record_type: str = "A", concurrency: int = 5) -> str:
    """Check DNS propagation for multiple domains across global DNS servers. Recommended max 100 domains for performance."""
    concurrency = max(1, min(concurrency, 50))
    start = time.monotonic()
    logger.debug("seer_bulk_propagation called: count=%d record_type=%s concurrency=%d", len(domains), record_type, concurrency)
    try:
        result = seer.bulk_propagation(domains, record_type, concurrency)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("seer_bulk_propagation completed: count=%d elapsed_ms=%.1f", len(domains), elapsed)
        return json.dumps(result, default=str)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.warning("seer_bulk_propagation failed: count=%d elapsed_ms=%.1f error=%s", len(domains), elapsed, e)
        return json.dumps({"error": str(e)})


@tool
def seer_availability(domain: str) -> str:
    """Check if a domain is available for registration. Returns availability status with confidence level and detection method."""
    logger.debug("seer_availability called: domain=%s", domain)
    try:
        return json.dumps(seer.availability(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_subdomains(domain: str) -> str:
    """Enumerate subdomains of a domain using Certificate Transparency logs. Returns discovered subdomains and count."""
    logger.debug("seer_subdomains called: domain=%s", domain)
    try:
        return json.dumps(seer.subdomains(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_ssl(domain: str) -> str:
    """Analyze SSL/TLS certificate for a domain. Returns certificate chain, validity, expiry, SANs, and protocol details."""
    logger.debug("seer_ssl called: domain=%s", domain)
    try:
        return json.dumps(seer.ssl(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dnssec(domain: str) -> str:
    """Check DNSSEC configuration for a domain. Returns DS/DNSKEY records, validation status, and any issues found."""
    logger.debug("seer_dnssec called: domain=%s", domain)
    try:
        return json.dumps(seer.dnssec(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dns_compare(domain: str, record_type: str, server_a: str, server_b: str) -> str:
    """Compare DNS records for a domain between two nameservers. Shows matching records, differences, and records unique to each server."""
    logger.debug("seer_dns_compare called: domain=%s record_type=%s", domain, record_type)
    try:
        return json.dumps(seer.dns_compare(domain, record_type, server_a, server_b), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dns_follow(domain: str, record_type: str = "A", nameserver: Optional[str] = None, iterations: int = 3, interval_minutes: float = 1.0) -> str:
    """Monitor DNS record changes over time. Queries the record repeatedly at the specified interval and reports changes between iterations."""
    iterations = max(1, min(iterations, 10))
    interval_minutes = max(0.1, min(interval_minutes, 5.0))
    logger.debug("seer_dns_follow called: domain=%s record_type=%s iterations=%d", domain, record_type, iterations)
    try:
        return json.dumps(seer.dns_follow(domain, record_type, nameserver, iterations, interval_minutes), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_diff(domain_a: str, domain_b: str) -> str:
    """Compare two domains side-by-side across registration, DNS, and SSL. Shows differences in registrar, nameservers, A records, and certificates."""
    logger.debug("seer_diff called: domain_a=%s domain_b=%s", domain_a, domain_b)
    try:
        return json.dumps(seer.diff(domain_a, domain_b), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_availability(domains: str, concurrency: int = 10) -> str:
    """Check domain registration availability in bulk. Pass domains as a JSON list
    of strings. Each result includes available (bool), confidence level, and check
    method. Uses concurrent RDAP/WHOIS checks for speed."""
    logger.debug("seer_bulk_availability called: concurrency=%d", concurrency)
    try:
        domain_list = json.loads(domains) if isinstance(domains, str) else domains
        return json.dumps(seer.bulk_availability(domain_list, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


SEER_TOOLS = [
    seer_lookup,
    seer_whois,
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
    seer_bulk_whois,
    seer_bulk_dig,
    seer_bulk_status,
    seer_bulk_propagation,
    seer_bulk_availability,
]
