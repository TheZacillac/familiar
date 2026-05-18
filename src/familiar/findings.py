"""Finding severity ontology shared across pentest and security tools.

Each scanning tool emits ``findings``: a list of dicts with at minimum a
``severity`` key drawn from the canonical CRITICAL/HIGH/MEDIUM/LOW/INFO
hierarchy. Centralising the order, the sort key, and the constructor here
means new tools — or new severities — only need to update one place, and
typos in finding keys surface as test failures instead of silently
corrupting the aggregated report.
"""

from __future__ import annotations

import logging
import os
from typing import TypedDict

logger = logging.getLogger("familiar")

# Canonical severity tiers in descending order of urgency.
SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITIES = frozenset(SEVERITY_ORDER)


class Finding(TypedDict, total=False):
    """Canonical shape of an entry in a tool's ``findings`` list.

    ``severity`` and ``finding`` are required at construction time (enforced
    by :func:`make_finding`); the others are optional but ubiquitous.
    Additional keys (``category``, ``source``, ``cve``, etc.) are tolerated
    — TypedDict ``total=False`` means it documents the shape without
    rejecting extras.
    """

    severity: str
    finding: str
    detail: str
    recommendation: str
    category: str
    source: str


def make_finding(
    severity: str,
    finding: str,
    *,
    detail: str | None = None,
    recommendation: str | None = None,
    **extra,
) -> Finding:
    """Canonical constructor for a finding dict.

    Validates that ``severity`` is one of :data:`SEVERITY_ORDER` and that
    ``finding`` is a non-empty string.  Extra keyword arguments pass
    through unchanged so callers can attach ``category``, ``source``,
    ``cve``, etc.
    """
    if severity not in _SEVERITIES:
        raise ValueError(
            f"Unknown severity {severity!r}; must be one of {SEVERITY_ORDER}"
        )
    if not isinstance(finding, str) or not finding.strip():
        raise ValueError("Finding 'finding' field must be a non-empty string")
    out: Finding = {"severity": severity, "finding": finding}
    if detail is not None:
        out["detail"] = detail
    if recommendation is not None:
        out["recommendation"] = recommendation
    out.update(extra)  # type: ignore[typeddict-item]
    return out


def _validate_finding_shape(f: dict) -> str | None:
    """Return a complaint string if ``f`` has the wrong shape, else None."""
    if not isinstance(f, dict):
        return f"expected dict, got {type(f).__name__}"
    sev = f.get("severity")
    if sev not in _SEVERITIES:
        return f"invalid severity {sev!r} (must be one of {SEVERITY_ORDER})"
    text = f.get("finding")
    if not isinstance(text, str) or not text.strip():
        return "missing or empty 'finding' field"
    return None


# Validation policy: raise inside pytest (so typos fail tests), log
# elsewhere (so a stray bad finding doesn't crash the agent in
# production).  Override with FAMILIAR_FINDING_STRICT=1 to force raises.
def _strict_mode() -> bool:
    if os.environ.get("FAMILIAR_FINDING_STRICT") == "1":
        return True
    return "PYTEST_CURRENT_TEST" in os.environ

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
    Also validates each finding's shape — under pytest (or with
    ``FAMILIAR_FINDING_STRICT=1``) malformed findings raise; in production
    they log a warning so a single bad entry doesn't crash the report.
    """
    strict = _strict_mode()
    for f in findings:
        problem = _validate_finding_shape(f)
        if problem:
            msg = f"Malformed finding: {problem} — {f!r}"
            if strict:
                raise ValueError(msg)
            logger.warning(msg)
    return sorted(findings, key=lambda f: severity_priority(f.get("severity")))


def severity_counts(findings: list[dict]) -> dict[str, int]:
    """Return a {severity: count} dict initialised with every canonical tier."""
    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts
