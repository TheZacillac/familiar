"""Seer domain intelligence tools wrapped for LangChain."""

import json
from typing import Optional

import seer
from langchain_core.tools import tool


@tool
def seer_lookup(domain: str) -> str:
    """Smart domain lookup — tries RDAP first, falls back to WHOIS. Returns registration data with source indicator."""
    return json.dumps(seer.lookup(domain), default=str)


@tool
def seer_whois(domain: str) -> str:
    """Look up WHOIS information for a domain. Returns registrar, dates, nameservers, and status."""
    return json.dumps(seer.whois(domain), default=str)


@tool
def seer_rdap_domain(domain: str) -> str:
    """Look up RDAP information for a domain. Returns structured registration data including registrar, dates, and DNSSEC status."""
    return json.dumps(seer.rdap_domain(domain), default=str)


@tool
def seer_rdap_ip(ip: str) -> str:
    """Look up RDAP information for an IP address. Returns network range, country, and responsible organization."""
    return json.dumps(seer.rdap_ip(ip), default=str)


@tool
def seer_rdap_asn(asn: int) -> str:
    """Look up RDAP information for an Autonomous System Number (ASN). Returns organization and network range info."""
    return json.dumps(seer.rdap_asn(asn), default=str)


@tool
def seer_dig(domain: str, record_type: str = "A", nameserver: Optional[str] = None) -> str:
    """Query DNS records for a domain (like the dig command). Supports record types: A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR, SRV, ANY."""
    return json.dumps(seer.dig(domain, record_type, nameserver), default=str)


@tool
def seer_propagation(domain: str, record_type: str = "A") -> str:
    """Check DNS propagation across global DNS servers. Shows which servers have the record and identifies inconsistencies."""
    return json.dumps(seer.propagation(domain, record_type), default=str)


@tool
def seer_status(domain: str) -> str:
    """Check domain health: HTTP accessibility, SSL certificate validity, and domain expiration."""
    return json.dumps(seer.status(domain), default=str)


@tool
def seer_bulk_lookup(domains: list[str], concurrency: int = 10) -> str:
    """Smart lookup for multiple domains at once (RDAP first, WHOIS fallback). Max 100 domains."""
    return json.dumps(seer.bulk_lookup(domains, concurrency), default=str)


@tool
def seer_bulk_whois(domains: list[str], concurrency: int = 10) -> str:
    """WHOIS lookup for multiple domains at once. Max 100 domains."""
    return json.dumps(seer.bulk_whois(domains, concurrency), default=str)


@tool
def seer_bulk_dig(domains: list[str], record_type: str = "A", concurrency: int = 10) -> str:
    """Query DNS records for multiple domains at once. Max 100 domains."""
    return json.dumps(seer.bulk_dig(domains, record_type, concurrency), default=str)


@tool
def seer_bulk_status(domains: list[str], concurrency: int = 10) -> str:
    """Check health status for multiple domains at once. Max 100 domains."""
    return json.dumps(seer.bulk_status(domains, concurrency), default=str)


@tool
def seer_bulk_propagation(domains: list[str], record_type: str = "A", concurrency: int = 5) -> str:
    """Check DNS propagation for multiple domains across global DNS servers. Max 100 domains."""
    return json.dumps(seer.bulk_propagation(domains, record_type, concurrency), default=str)


SEER_TOOLS = [
    seer_lookup,
    seer_whois,
    seer_rdap_domain,
    seer_rdap_ip,
    seer_rdap_asn,
    seer_dig,
    seer_propagation,
    seer_status,
    seer_bulk_lookup,
    seer_bulk_whois,
    seer_bulk_dig,
    seer_bulk_status,
    seer_bulk_propagation,
]
