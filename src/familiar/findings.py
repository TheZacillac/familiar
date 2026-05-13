"""Finding severity ontology shared across pentest and security tools.

Each scanning tool emits ``findings``: a list of dicts with at minimum a
``severity`` key drawn from the canonical CRITICAL/HIGH/MEDIUM/LOW/INFO
hierarchy. Centralising the order and sort key here means new tools — or
new severities — only need to update one place.
"""

from __future__ import annotations

# Canonical severity tiers in descending order of urgency.
SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Lookup map from severity → sort priority. Unknown severities sort last
# (defensive — better than KeyError when an upstream tool emits something
# unexpected).
_SEVERITY_PRIORITY: dict[str, int] = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
_UNKNOWN_PRIORITY: int = len(SEVERITY_ORDER)


def severity_priority(severity: str | None) -> int:
    """Return the sort priority for a severity string (lower = more urgent)."""
    if severity is None:
        return _UNKNOWN_PRIORITY
    return _SEVERITY_PRIORITY.get(severity, _UNKNOWN_PRIORITY)


def sort_findings(findings: list[dict]) -> list[dict]:
    """Return *findings* sorted CRITICAL → INFO. Stable for ties.

    Tolerates findings without a ``severity`` key (they sort to the end).
    """
    return sorted(findings, key=lambda f: severity_priority(f.get("severity")))


def severity_counts(findings: list[dict]) -> dict[str, int]:
    """Return a {severity: count} dict initialised with every canonical tier."""
    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts
