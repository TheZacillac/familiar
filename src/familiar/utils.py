"""Shared utilities for Familiar."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

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


def safe_call(fn, *args, _errors: list | None = None, _op: str | None = None, **kwargs):
    """Call a function, returning None on failure with debug logging.

    When *_errors* is a list, failures append a structured record
    ``{"op": _op or fn.__name__, "error": str(e), "type": type(e).__name__}``
    so callers can surface upstream failures to the LLM instead of
    silently returning empty results. Pass a unique *_op* string when
    *fn.__name__* alone isn't enough to identify the call site (e.g.
    multiple ``seer.dig`` calls in one tool).
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        op_name = _op or getattr(fn, "__name__", repr(fn))
        if _errors is not None:
            # Caller is collecting errors and will surface them — debug is fine.
            logger.debug("Call to %s failed: %s", op_name, e)
            _errors.append({
                "op": op_name,
                "error": str(e),
                "type": type(e).__name__,
            })
        else:
            # No collector — failure would otherwise vanish silently.
            logger.warning("Call to %s failed (no error collector): %s", op_name, e)
        return None


def parallel_calls(*call_specs, errors: list | None = None):
    """Execute multiple (fn, *args) tuples concurrently, returning results in order.

    Each element of *call_specs* is a tuple of ``(fn, arg1, arg2, ...)``.
    Results are returned as a list in the same order as the input specs.
    Failed calls return ``None`` (same semantics as ``safe_call``).

    When *errors* is provided, failures from any child call are recorded
    into the shared list (thread-safe — ``list.append`` is atomic in
    CPython). The recorded ``op`` defaults to ``fn.__name__ + args[1:]``
    so multiple ``seer.dig`` calls remain distinguishable.

    Example::

        a_recs, mx_recs, ns_recs = parallel_calls(
            (seer.dig, domain, "A"),
            (seer.dig, domain, "MX"),
            (seer.dig, domain, "NS"),
        )
    """
    if not call_specs:
        return []

    def _op_label(spec):
        fn = spec[0]
        name = getattr(fn, "__name__", repr(fn))
        tail = spec[1:]
        # Compact: "seer.dig(zac.app, NS)" rather than full repr
        if tail:
            return f"{name}({', '.join(str(a) for a in tail)})"
        return name

    # Fast path: single call, skip pool overhead
    if len(call_specs) == 1:
        fn, *args = call_specs[0]
        return [safe_call(fn, *args, _errors=errors, _op=_op_label(call_specs[0]))]

    results = [None] * len(call_specs)
    futures = {}
    for idx, spec in enumerate(call_specs):
        fn, *args = spec
        future = _get_executor().submit(
            safe_call, fn, *args, _errors=errors, _op=_op_label(spec)
        )
        futures[future] = idx

    for future in as_completed(futures):
        results[futures[future]] = future.result()
    return results


def ssl_probe_error(ssl_data) -> str | None:
    """Return the probe-failure message when *ssl_data* is a ``_try_ssl``
    sentinel, else ``None``.

    Companion to each consumer module's local ``_try_ssl`` wrapper.
    Composite tools call this to branch between "the probe failed (so we
    cannot make any claim about the cert)" and "the probe succeeded (so
    ``is_valid`` etc. are authoritative)". A failed probe is NOT
    equivalent to a missing certificate — many of the failure modes are
    DNS, transport, or local-resolver issues that say nothing about the
    real certificate.

    The per-module ``_try_ssl`` lives next to each tool's ``seer`` import
    so ``@patch("module.seer")`` keeps working in tests.
    """
    if isinstance(ssl_data, dict) and "_ssl_error" in ssl_data:
        return ssl_data["_ssl_error"]
    return None


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
            dt = dt.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        return (dt - now).days
    except (ValueError, TypeError):
        return None
