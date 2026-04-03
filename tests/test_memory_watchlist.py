"""Test 5: Memory watchlist operations.

Tests add, remove, duplicate detection, status updates, and list ordering
for the watchlist that monitors domain health over time.
"""

import json

import pytest


class TestWatchlistAdd:
    """Adding domains to the watchlist."""

    def test_add_new_domain(self, memory):
        result = memory.watchlist_add("example.com")
        assert result["domain"] == "example.com"
        assert result["status"] == "added"
        assert "added" in result  # timestamp present

    def test_add_duplicate_returns_already_watching(self, memory):
        memory.watchlist_add("example.com")
        result = memory.watchlist_add("example.com")
        assert result["status"] == "already_watching"

    def test_add_normalizes_domain(self, memory):
        memory.watchlist_add("  EXAMPLE.COM  ")
        result = memory.watchlist_add("example.com")
        assert result["status"] == "already_watching"


class TestWatchlistRemove:
    """Removing domains from the watchlist."""

    def test_remove_existing(self, memory):
        memory.watchlist_add("example.com")
        result = memory.watchlist_remove("example.com")
        assert result["status"] == "removed"

    def test_remove_nonexistent(self, memory):
        result = memory.watchlist_remove("nothere.com")
        assert result["status"] == "not_found"

    def test_remove_then_readd(self, memory):
        memory.watchlist_add("example.com")
        memory.watchlist_remove("example.com")
        result = memory.watchlist_add("example.com")
        assert result["status"] == "added"


class TestWatchlistList:
    """Listing watched domains."""

    def test_empty_list(self, memory):
        assert memory.watchlist_list() == []

    def test_list_returns_all(self, memory):
        memory.watchlist_add("a.com")
        memory.watchlist_add("b.com")
        memory.watchlist_add("c.com")
        listed = memory.watchlist_list()
        domains = {item["domain"] for item in listed}
        assert domains == {"a.com", "b.com", "c.com"}

    def test_list_order_newest_first(self, memory):
        import time
        memory.watchlist_add("first.com")
        time.sleep(0.01)
        memory.watchlist_add("second.com")
        time.sleep(0.01)
        memory.watchlist_add("third.com")

        listed = memory.watchlist_list()
        assert listed[0]["domain"] == "third.com"
        assert listed[2]["domain"] == "first.com"


class TestWatchlistStatusUpdates:
    """Status persistence after watchlist checks."""

    def test_update_status_stores_json(self, memory):
        memory.watchlist_add("example.com")
        status = {"http_ok": True, "ssl_valid": True, "days_until_expiry": 90}
        memory.watchlist_update_status("example.com", status)

        listed = memory.watchlist_list()
        entry = listed[0]
        assert entry["last_checked"] is not None
        stored = json.loads(entry["last_status"])
        assert stored["http_ok"] is True
        assert stored["days_until_expiry"] == 90

    def test_update_status_updates_last_checked(self, memory):
        memory.watchlist_add("example.com")
        assert memory.watchlist_list()[0]["last_checked"] is None

        memory.watchlist_update_status("example.com", {"ok": True})
        assert memory.watchlist_list()[0]["last_checked"] is not None

    def test_multiple_status_updates_overwrite(self, memory):
        memory.watchlist_add("example.com")
        memory.watchlist_update_status("example.com", {"check": 1})
        memory.watchlist_update_status("example.com", {"check": 2})

        stored = json.loads(memory.watchlist_list()[0]["last_status"])
        assert stored["check"] == 2
