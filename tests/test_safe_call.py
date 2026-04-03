"""Test 2: safe_call() error containment and pass-through reliability.

Ensures that safe_call faithfully returns results on success and silently
returns None on any exception, preventing tool crashes from propagating.
"""

import pytest

from familiar.utils import safe_call


class TestSuccessPassThrough:
    """Verify safe_call transparently returns function results."""

    def test_returns_string(self):
        assert safe_call(str.upper, "hello") == "HELLO"

    def test_returns_int(self):
        assert safe_call(int, "42") == 42

    def test_returns_dict(self):
        def make_dict():
            return {"key": "value"}
        assert safe_call(make_dict) == {"key": "value"}

    def test_returns_none_from_function(self):
        """A function that returns None should not be confused with failure."""
        result = safe_call(lambda: None)
        assert result is None

    def test_returns_list(self):
        assert safe_call(list, "abc") == ["a", "b", "c"]

    def test_passes_kwargs(self):
        def fn(a, b=10):
            return a + b
        assert safe_call(fn, 5, b=20) == 25


class TestExceptionContainment:
    """Verify safe_call swallows exceptions and returns None."""

    def test_value_error_returns_none(self):
        result = safe_call(int, "not_a_number")
        assert result is None

    def test_type_error_returns_none(self):
        def needs_args(a, b):
            return a + b
        result = safe_call(needs_args)  # missing required args
        assert result is None

    def test_key_error_returns_none(self):
        def bad_lookup():
            return {}["missing"]
        assert safe_call(bad_lookup) is None

    def test_runtime_error_returns_none(self):
        def blow_up():
            raise RuntimeError("boom")
        assert safe_call(blow_up) is None

    def test_zero_division_returns_none(self):
        assert safe_call(lambda: 1 / 0) is None

    def test_attribute_error_returns_none(self):
        assert safe_call(lambda: None.nonexistent) is None
