"""Seer domain intelligence tools wrapped for LangChain."""

import json
from typing import Optional

import seer
from langchain_core.tools import tool


@tool
def seer_lookup(domain: str) -> str:
    """Smart domain lookup — tries RDAP first, falls back to WHOIS. Returns registration data with source indicator."""
    try:
        return json.dumps(seer.lookup(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_whois(domain: str) -> str:
    """Look up WHOIS information for a domain. Returns registrar, dates, nameservers, and status."""
    try:
        return json.dumps(seer.whois(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_rdap_domain(domain: str) -> str:
    """Look up RDAP information for a domain. Returns structured registration data including registrar, dates, and DNSSEC status."""
    try:
        return json.dumps(seer.rdap_domain(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_rdap_ip(ip: str) -> str:
    """Look up RDAP information for an IP address. Returns network range, country, and responsible organization."""
    try:
        return json.dumps(seer.rdap_ip(ip), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_rdap_asn(asn: int) -> str:
    """Look up RDAP information for an Autonomous System Number (ASN). Returns organization and network range info."""
    try:
        return json.dumps(seer.rdap_asn(asn), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dig(domain: str, record_type: str = "A", nameserver: Optional[str] = None) -> str:
    """Query DNS records for a domain (like the dig command). Supports record types: A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR, SRV, ANY."""
    try:
        return json.dumps(seer.dig(domain, record_type, nameserver), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_propagation(domain: str, record_type: str = "A") -> str:
    """Check DNS propagation across global DNS servers. Shows which servers have the record and identifies inconsistencies."""
    try:
        return json.dumps(seer.propagation(domain, record_type), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_status(domain: str) -> str:
    """Check domain health: HTTP accessibility, SSL certificate validity, and domain expiration."""
    try:
        return json.dumps(seer.status(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_lookup(domains: list[str], concurrency: int = 10) -> str:
    """Smart lookup for multiple domains at once (RDAP first, WHOIS fallback). Recommended max 100 domains for performance."""
    try:
        return json.dumps(seer.bulk_lookup(domains, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_whois(domains: list[str], concurrency: int = 10) -> str:
    """WHOIS lookup for multiple domains at once. Recommended max 100 domains for performance."""
    try:
        return json.dumps(seer.bulk_whois(domains, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_dig(domains: list[str], record_type: str = "A", concurrency: int = 10) -> str:
    """Query DNS records for multiple domains at once. Recommended max 100 domains for performance."""
    try:
        return json.dumps(seer.bulk_dig(domains, record_type, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_status(domains: list[str], concurrency: int = 10) -> str:
    """Check health status for multiple domains at once. Recommended max 100 domains for performance."""
    try:
        return json.dumps(seer.bulk_status(domains, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_bulk_propagation(domains: list[str], record_type: str = "A", concurrency: int = 5) -> str:
    """Check DNS propagation for multiple domains across global DNS servers. Recommended max 100 domains for performance."""
    try:
        return json.dumps(seer.bulk_propagation(domains, record_type, concurrency), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_availability(domain: str) -> str:
    """Check if a domain is available for registration. Returns availability status with confidence level and detection method."""
    try:
        return json.dumps(seer.availability(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_subdomains(domain: str) -> str:
    """Enumerate subdomains of a domain using Certificate Transparency logs. Returns discovered subdomains and count."""
    try:
        return json.dumps(seer.subdomains(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_ssl(domain: str) -> str:
    """Analyze SSL/TLS certificate for a domain. Returns certificate chain, validity, expiry, SANs, and protocol details."""
    try:
        return json.dumps(seer.ssl(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dnssec(domain: str) -> str:
    """Check DNSSEC configuration for a domain. Returns DS/DNSKEY records, validation status, and any issues found."""
    try:
        return json.dumps(seer.dnssec(domain), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dns_compare(domain: str, record_type: str, server_a: str, server_b: str) -> str:
    """Compare DNS records for a domain between two nameservers. Shows matching records, differences, and records unique to each server."""
    try:
        return json.dumps(seer.dns_compare(domain, record_type, server_a, server_b), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_dns_follow(domain: str, record_type: str = "A", nameserver: Optional[str] = None, iterations: int = 3, interval_minutes: float = 1.0) -> str:
    """Monitor DNS record changes over time. Queries the record repeatedly at the specified interval and reports changes between iterations."""
    try:
        return json.dumps(seer.dns_follow(domain, record_type, nameserver, iterations, interval_minutes), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def seer_diff(domain_a: str, domain_b: str) -> str:
    """Compare two domains side-by-side across registration, DNS, and SSL. Shows differences in registrar, nameservers, A records, and certificates."""
    try:
        return json.dumps(seer.diff(domain_a, domain_b), default=str)
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
]
