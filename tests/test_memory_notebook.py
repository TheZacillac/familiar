"""Test 4: Memory domain notebook CRUD operations.

Tests insert, update, tag merging, note appending, domain normalization,
and recall ordering to ensure the domain notebook stores and retrieves
data accurately.
"""

import pytest


class TestRememberAndRecall:
    """Basic insert and retrieve operations."""

    def test_remember_new_domain(self, memory):
        result = memory.remember_domain("example.com", notes="First look", tags="test")
        assert result is not None
        assert result["domain"] == "example.com"
        assert result["notes"] == "First look"
        assert result["tags"] == "test"
        assert result["first_seen"] == result["last_seen"]

    def test_recall_existing_domain(self, memory):
        memory.remember_domain("example.com", notes="stored")
        result = memory.recall_domain("example.com")
        assert result is not None
        assert result["notes"] == "stored"

    def test_recall_missing_domain_returns_none(self, memory):
        assert memory.recall_domain("nonexistent.com") is None

    def test_recall_all_empty(self, memory):
        assert memory.recall_all_domains() == []


class TestDomainNormalization:
    """Domain input should be lowercased and stripped."""

    def test_uppercase_normalized(self, memory):
        memory.remember_domain("EXAMPLE.COM", notes="upper")
        result = memory.recall_domain("example.com")
        assert result is not None
        assert result["domain"] == "example.com"

    def test_whitespace_stripped(self, memory):
        memory.remember_domain("  example.com  ", notes="padded")
        result = memory.recall_domain("example.com")
        assert result is not None

    def test_recall_normalizes_too(self, memory):
        memory.remember_domain("example.com", notes="test")
        result = memory.recall_domain("  EXAMPLE.COM  ")
        assert result is not None
        assert result["domain"] == "example.com"


class TestNoteAppending:
    """Subsequent remembers should append notes, not replace."""

    def test_notes_appended(self, memory):
        memory.remember_domain("example.com", notes="First note")
        memory.remember_domain("example.com", notes="Second note")
        result = memory.recall_domain("example.com")
        assert "First note" in result["notes"]
        assert "Second note" in result["notes"]

    def test_empty_note_does_not_add_blank_line(self, memory):
        memory.remember_domain("example.com", notes="Original")
        memory.remember_domain("example.com", notes="")
        result = memory.recall_domain("example.com")
        assert result["notes"] == "Original"


class TestTagMerging:
    """Tags should be merged as a set union, sorted alphabetically."""

    def test_tags_merged(self, memory):
        memory.remember_domain("example.com", tags="dns,ssl")
        memory.remember_domain("example.com", tags="ssl,security")
        result = memory.recall_domain("example.com")
        tags = set(result["tags"].split(","))
        assert tags == {"dns", "ssl", "security"}

    def test_duplicate_tags_deduplicated(self, memory):
        memory.remember_domain("example.com", tags="a,b,a,b")
        result = memory.recall_domain("example.com")
        tags = result["tags"].split(",")
        assert len(tags) == len(set(tags))

    def test_empty_tags_on_new_domain(self, memory):
        memory.remember_domain("example.com", tags="")
        result = memory.recall_domain("example.com")
        assert result["tags"] == ""

    def test_tags_sorted(self, memory):
        memory.remember_domain("example.com", tags="zebra,apple,mango")
        result = memory.recall_domain("example.com")
        assert result["tags"] == "apple,mango,zebra"


class TestTimestamps:
    """first_seen should be immutable; last_seen should update."""

    def test_first_seen_immutable(self, memory):
        memory.remember_domain("example.com", notes="first")
        first = memory.recall_domain("example.com")["first_seen"]

        memory.remember_domain("example.com", notes="second")
        result = memory.recall_domain("example.com")
        assert result["first_seen"] == first

    def test_last_seen_updates(self, memory):
        memory.remember_domain("example.com", notes="first")
        first_seen_at = memory.recall_domain("example.com")["last_seen"]

        import time
        time.sleep(0.01)

        memory.remember_domain("example.com", notes="second")
        result = memory.recall_domain("example.com")
        assert result["last_seen"] >= first_seen_at


class TestRecallAllOrdering:
    """recall_all_domains should return most recently seen first."""

    def test_ordering_by_last_seen(self, memory):
        import time
        memory.remember_domain("old.com", notes="old")
        time.sleep(0.01)
        memory.remember_domain("new.com", notes="new")
        time.sleep(0.01)
        memory.remember_domain("newest.com", notes="newest")

        all_domains = memory.recall_all_domains()
        assert len(all_domains) == 3
        assert all_domains[0]["domain"] == "newest.com"
        assert all_domains[2]["domain"] == "old.com"


class TestClosedConnection:
    """Every public method must fail cleanly (RuntimeError) after close().

    close() runs via atexit while pool threads may still be mid-tool-call;
    an unguarded method would surface an AttributeError on self._conn
    instead of a clear "database is closed" error.
    """

    def test_methods_raise_runtime_error_after_close(self, memory):
        memory.close()
        cases = [
            (memory.remember_domain, ("x.com",)),
            (memory.recall_domain, ("x.com",)),
            (memory.recall_all_domains, ()),
            (memory.tag_search, ("tag",)),
            (memory.watchlist_add, ("x.com",)),
            (memory.watchlist_remove, ("x.com",)),
            (memory.watchlist_list, ()),
            (memory.watchlist_update_status, ("x.com", {"ok": True})),
            (memory.get_preference, ("k",)),
            (memory.set_preference, ("k", "v")),
            (memory.save_snapshot, ("x.com", {"a": 1})),
            (memory.list_snapshots, ("x.com",)),
            (memory.diff_snapshots, (1, 2)),
        ]
        for fn, args in cases:
            with pytest.raises(RuntimeError, match="closed"):
                fn(*args)

    def test_close_is_idempotent(self, memory):
        memory.close()
        memory.close()  # second close must not raise
