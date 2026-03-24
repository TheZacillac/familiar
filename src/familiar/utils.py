"""Shared utilities for Familiar."""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("familiar")


def safe_call(fn, *args, **kwargs):
    """Call a function, returning None on failure with debug logging."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.debug("Call to %s failed: %s", fn.__name__, e)
        return None


def days_until(raw) -> int | None:
    """Return days from now until a WHOIS/RDAP date, or None if unparseable.

    Parses the first 10 characters of the input as an ISO date, treats it as
    UTC, and returns the number of whole days remaining. Negative values mean
    the date is in the past.
    """
    try:
        dt = datetime.fromisoformat(str(raw)[:10]).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        return (dt - now).days
    except (ValueError, TypeError):
        return None
