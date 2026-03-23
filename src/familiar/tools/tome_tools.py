"""Tome reference data tools wrapped for LangChain."""

import json

import tome
from langchain_core.tools import tool


@tool
def tome_tld_lookup(tld: str) -> str:
    """Look up detailed information about a top-level domain (TLD). Returns type, registry, DNSSEC support, restrictions, etc."""
    result = tome.tld_lookup(tld)
    if result is None:
        return json.dumps({"error": f"No TLD found matching '{tld}'"})
    return json.dumps(result, default=str)


@tool
def tome_tld_search(query: str) -> str:
    """Search for TLDs by partial match. Useful for finding TLDs related to a keyword."""
    return json.dumps(tome.tld_search(query), default=str)


@tool
def tome_record_lookup(query: str) -> str:
    """Look up a DNS record type by name (e.g. 'A', 'MX') or numeric code. Returns description, format, RFCs, and related types."""
    result = tome.record_lookup(query)
    if result is None:
        return json.dumps({"error": f"No record type found matching '{query}'"})
    return json.dumps(result, default=str)


@tool
def tome_record_search(query: str) -> str:
    """Search for DNS record types by partial match."""
    return json.dumps(tome.record_search(query), default=str)


@tool
def tome_glossary_lookup(term: str) -> str:
    """Look up a domain name industry term or abbreviation (e.g. 'DNSSEC', 'registrar', 'EPP'). Returns definition, category, and related terms."""
    result = tome.glossary_lookup(term)
    if result is None:
        return json.dumps({"error": f"No glossary term found matching '{term}'"})
    return json.dumps(result, default=str)


@tool
def tome_glossary_search(query: str) -> str:
    """Search the domain name industry glossary by partial match."""
    return json.dumps(tome.glossary_search(query), default=str)


TOME_TOOLS = [
    tome_tld_lookup,
    tome_tld_search,
    tome_record_lookup,
    tome_record_search,
    tome_glossary_lookup,
    tome_glossary_search,
]
