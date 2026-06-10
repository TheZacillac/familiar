"""Shared SPF/DMARC record parsing primitives.

One tag-aware tokenizer for every consumer (pentest deep audit,
security_audit, compare_security). Substring matching like
``"p=none" in txt`` misfires on values such as ``sp=none`` or
``p=nonexistent`` — these helpers parse the record structure instead.
"""

from __future__ import annotations


def parse_dmarc_tags(dmarc_text: str) -> dict[str, str]:
    """Tokenize ``v=DMARC1; p=reject; rua=...`` into ``{tag: value}``.

    Tags are lowercased and stripped; values are stripped but keep their
    case (rua/ruf URIs are case-sensitive). Malformed segments without an
    ``=`` are skipped.
    """
    tags: dict[str, str] = {}
    for part in dmarc_text.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def parse_spf_all_qualifier(spf_text: str) -> str | None:
    """Return the qualifier of the SPF ``all`` mechanism, or None.

    ``"+"``, ``"-"``, ``"~"``, or ``"?"`` when an ``all`` mechanism is
    present (a bare ``all`` is ``+all`` per RFC 7208 §4.6.2); None when
    the record has no terminal ``all`` (e.g. it ends in ``redirect=``).
    Only whole tokens count — ``include:ball.example`` is not ``all``.
    """
    for token in spf_text.split():
        t = token.lower()
        if t == "all":
            return "+"
        if len(t) == 4 and t.endswith("all") and t[0] in "+-~?":
            return t[0]
    return None
