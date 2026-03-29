"""Tome reference data tools wrapped for LangChain."""

import json
import logging

import tome
from langchain_core.tools import tool

logger = logging.getLogger("familiar.tools.tome")


@tool
def tome_tld_lookup(tld: str) -> str:
    """Look up detailed information about a top-level domain (TLD). Returns type, registry, DNSSEC support, restrictions, etc."""
    logger.debug("tome_tld_lookup called: tld=%s", tld)
    try:
        result = tome.tld_lookup(tld)
        if result is None:
            return json.dumps({"error": f"No TLD found matching '{tld}'"})
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_tld_search(query: str) -> str:
    """Search for TLDs by partial match. Useful for finding TLDs related to a keyword."""
    logger.debug("tome_tld_search called: query=%s", query)
    try:
        return json.dumps(tome.tld_search(query), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_record_lookup(query: str) -> str:
    """Look up a DNS record type by name (e.g. 'A', 'MX') or numeric code. Returns description, format, RFCs, and related types."""
    logger.debug("tome_record_lookup called: query=%s", query)
    try:
        result = tome.record_lookup(query)
        if result is None:
            return json.dumps({"error": f"No record type found matching '{query}'"})
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_record_search(query: str) -> str:
    """Search for DNS record types by partial match."""
    logger.debug("tome_record_search called: query=%s", query)
    try:
        return json.dumps(tome.record_search(query), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_glossary_lookup(term: str) -> str:
    """Look up a domain name industry term or abbreviation (e.g. 'DNSSEC', 'registrar', 'EPP'). Returns definition, category, and related terms."""
    logger.debug("tome_glossary_lookup called: term=%s", term)
    try:
        result = tome.glossary_lookup(term)
        if result is None:
            return json.dumps({"error": f"No glossary term found matching '{term}'"})
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_glossary_search(query: str) -> str:
    """Search the domain name industry glossary by partial match."""
    logger.debug("tome_glossary_search called: query=%s", query)
    try:
        return json.dumps(tome.glossary_search(query), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_tld_overview(tld: str) -> str:
    """Get a comprehensive overview of a TLD including registry operator, country mapping, WHOIS/RDAP servers, registration model, DNSSEC, and transfer rules."""
    logger.debug("tome_tld_overview called: tld=%s", tld)
    try:
        result = tome.tld_overview(tld)
        if result is None:
            return json.dumps({"error": f"No TLD found matching '{tld}'"})
        return json.dumps(result, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_tld_list_by_type(tld_type: str) -> str:
    """List all TLDs of a given type: 'gTLD' (generic), 'ccTLD' (country-code), or 'nTLD' (new generic). Returns a list of all matching TLDs."""
    logger.debug("tome_tld_list_by_type called: tld_type=%s", tld_type)
    try:
        return json.dumps(tome.tld_list_by_type(tld_type), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_tld_count() -> str:
    """Return the total number of TLDs in the Tome reference database."""
    logger.debug("tome_tld_count called")
    try:
        return json.dumps({"count": tome.tld_count()})
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def tome_record_by_status(status: str) -> str:
    """Filter DNS record types by IANA status. Valid statuses: 'Active', 'Experimental', 'Obsolete', 'Reserved'. Returns all record types matching the given status."""
    logger.debug("tome_record_by_status called: status=%s", status)
    try:
        return json.dumps(tome.record_by_status(status), default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


TOME_TOOLS = [
    tome_tld_lookup,
    tome_tld_search,
    tome_tld_overview,
    tome_tld_list_by_type,
    tome_tld_count,
    tome_record_lookup,
    tome_record_search,
    tome_record_by_status,
    tome_glossary_lookup,
    tome_glossary_search,
]
