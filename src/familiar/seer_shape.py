"""Anti-corruption layer for seer's DNS record shape.

seer >=0.24 nests record fields under ``data.value``:

    {"data": {"record_type": "NS", "value": {"nameserver": "ns1.example.com."}},
     "name": "example.com", "record_type": "NS", "ttl": 300}

Older releases (and many test fixtures) place fields directly on ``data``:

    {"data": {"nameserver": "ns1.example.com."}}

Consumers should never reach into either shape directly.  Always go through
the accessors here so future seer schema changes have a single migration
point.
"""

from __future__ import annotations


def record_value_dict(record) -> dict | None:
    """Return the inner field dict from a seer DNS record.

    Returns the ``data.value`` sub-dict when present (seer >=0.24), falls
    back to ``data`` for older shapes, and ``None`` when the record isn't
    a dict at all.
    """
    if not isinstance(record, dict):
        return None
    data = record.get("data", record)
    if not isinstance(data, dict):
        return None
    inner = data.get("value")
    if isinstance(inner, dict):
        return inner
    return data


def record_field(record, field: str, default: str = "") -> str:
    """Extract a string field from a seer DNS record.

    Use for non-TXT records: ``nameserver`` for NS, ``target`` for CNAME,
    ``address`` for A/AAAA, ``exchange`` for MX, CAA ``tag``/``value``, etc.
    Always returns a string — missing fields return ``default``.
    """
    fields = record_value_dict(record)
    if fields is not None:
        return str(fields.get(field, default))
    if isinstance(record, dict):
        return default
    return str(record)


def unwrap_bulk(raw) -> dict | list | None:
    """Unwrap a seer BulkResult wrapper to extract the inner payload.

    seer.bulk_* APIs return ``Vec<BulkResult>`` where each element is::

        {operation: {...}, success: bool, data: <payload>,
         error: str | None, duration_ms: int}

    Returns the ``data`` value when the result indicates success, ``None``
    otherwise.
    """
    if raw and isinstance(raw, dict) and raw.get("success"):
        return raw.get("data")
    return None


def status_certificate(status_data) -> dict:
    """Extract the certificate dict from a seer.status() response.

    seer.status() returns ``{certificate: {is_valid, days_until_expiry, ...}}``.
    Returns an empty dict if the response is missing or malformed.
    """
    if status_data and isinstance(status_data, dict):
        cert = status_data.get("certificate")
        if cert and isinstance(cert, dict):
            return cert
    return {}


def lookup_to_registration(lookup_result) -> dict:
    """Normalize a seer.lookup() result into a flat registration dict.

    seer.lookup() returns a tagged enum: ``{source: "whois"|"rdap", data: {...}}``.
    For WHOIS, data contains registrar, creation_date, expiration_date, etc.
    For RDAP, data uses RFC 7483 structure (events, entities, camelCase).
    This function normalises both into a common flat shape so downstream
    tools don't need to branch on source.
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


def record_text(record) -> str:
    """Extract the text value from a seer TXT record.

    Strips surrounding whitespace and any wrapping quote characters that some
    DNS responses include verbatim (e.g. ``"v=spf1 ..."``).
    """
    if isinstance(record, dict):
        fields = record_value_dict(record)
        if fields is not None:
            value = fields.get("text")
            if value is None:
                # Some shapes use "value" as the text key
                value = fields.get("value", str(fields))
        else:
            data = record.get("data", record)
            value = str(data)
    else:
        value = str(record)
    value = str(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1].strip()
    return value
