"""Shared utilities for Familiar."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import config

logger = logging.getLogger("familiar")

# Shared thread pool for parallel seer calls.  Seer's Rust core releases
# the GIL during I/O (tokio), so real parallelism is achieved here.
# Lazily initialized so that config is not loaded at import time (before
# agent.py has a chance to parse .env and load the config file).
_EXECUTOR: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=config.max_workers(),
            thread_name_prefix="familiar",
        )
    return _EXECUTOR


def safe_call(fn, *args, **kwargs):
    """Call a function, returning None on failure with debug logging."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.debug("Call to %s failed: %s", getattr(fn, "__name__", repr(fn)), e)
        return None


def parallel_calls(*call_specs):
    """Execute multiple (fn, *args) tuples concurrently, returning results in order.

    Each element of *call_specs* is a tuple of ``(fn, arg1, arg2, ...)``.
    Results are returned as a list in the same order as the input specs.
    Failed calls return ``None`` (same semantics as ``safe_call``).

    Example::

        a_recs, mx_recs, ns_recs = parallel_calls(
            (seer.dig, domain, "A"),
            (seer.dig, domain, "MX"),
            (seer.dig, domain, "NS"),
        )
    """
    if not call_specs:
        return []
    # Fast path: single call, skip pool overhead
    if len(call_specs) == 1:
        fn, *args = call_specs[0]
        return [safe_call(fn, *args)]

    results = [None] * len(call_specs)
    futures = {}
    for idx, spec in enumerate(call_specs):
        fn, *args = spec
        future = _get_executor().submit(safe_call, fn, *args)
        futures[future] = idx

    for future in as_completed(futures):
        results[futures[future]] = future.result()
    return results


def days_until(raw) -> int | None:
    """Return days from now until a WHOIS/RDAP date, or None if unparseable.

    Attempts to parse the full ISO 8601 string (preserving timezone offset)
    before falling back to a date-only parse.  Returns the number of whole
    days remaining.  Negative values mean the date is in the past.
    """
    try:
        s = str(raw)
        # Try full ISO parse first — preserves timezone offset (Python 3.11+)
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            # Fall back to date-only (first 10 chars), assume UTC
            dt = datetime.fromisoformat(s[:10])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (dt - now).days
    except (ValueError, TypeError):
        return None
