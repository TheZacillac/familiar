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
