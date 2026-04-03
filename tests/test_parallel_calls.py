"""Test 3: parallel_calls() ordering, concurrency, and failure handling.

Validates that results are returned in the exact order of input specs,
that the single-call fast path works, and that failures in one call
don't corrupt others.
"""

import time

import pytest

from familiar.utils import parallel_calls


class TestResultOrdering:
    """Results must match input order regardless of completion order."""

    def test_preserves_order(self):
        """Three calls returning distinct values must come back in order."""
        results = parallel_calls(
            (lambda: "first",),
            (lambda: "second",),
            (lambda: "third",),
        )
        assert results == ["first", "second", "third"]

    def test_preserves_order_with_varied_timing(self):
        """Even if earlier calls take longer, ordering is preserved."""
        def slow():
            time.sleep(0.05)
            return "slow"

        def fast():
            return "fast"

        results = parallel_calls(
            (slow,),
            (fast,),
            (slow,),
            (fast,),
        )
        assert results == ["slow", "fast", "slow", "fast"]

    def test_many_calls_ordering(self):
        """Verify ordering with many concurrent calls."""
        specs = [(lambda i=i: i,) for i in range(20)]
        results = parallel_calls(*specs)
        assert results == list(range(20))


class TestEmptyAndSingleCall:
    """Edge cases: no calls and single-call fast path."""

    def test_empty_returns_empty_list(self):
        assert parallel_calls() == []

    def test_single_call_fast_path(self):
        """Single call should bypass ThreadPoolExecutor."""
        result = parallel_calls((lambda: 42,))
        assert result == [42]

    def test_single_call_with_args(self):
        result = parallel_calls((pow, 2, 10))
        assert result == [1024]


class TestFailureIsolation:
    """One failing call must not affect others."""

    def test_failed_call_returns_none(self):
        def boom():
            raise ValueError("oops")

        results = parallel_calls(
            (lambda: "ok",),
            (boom,),
            (lambda: "also_ok",),
        )
        assert results == ["ok", None, "also_ok"]

    def test_all_failures_returns_all_none(self):
        def boom():
            raise RuntimeError("fail")

        results = parallel_calls((boom,), (boom,), (boom,))
        assert results == [None, None, None]

    def test_mixed_success_failure_preserves_positions(self):
        results = parallel_calls(
            (lambda: 1,),
            (lambda: 1 / 0,),  # ZeroDivisionError
            (lambda: 3,),
            (lambda: [][0],),  # IndexError
            (lambda: 5,),
        )
        assert results == [1, None, 3, None, 5]


class TestArgumentPassing:
    """Verify args are correctly unpacked from call specs."""

    def test_positional_args(self):
        results = parallel_calls(
            (max, 1, 2, 3),
            (min, 10, 20, 30),
        )
        assert results == [3, 10]

    def test_function_with_string_arg(self):
        results = parallel_calls(
            (str.upper, "hello"),
            (str.lower, "WORLD"),
        )
        assert results == ["HELLO", "world"]
