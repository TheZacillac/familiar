import json
import time

import pytest
from familiar.memory import Memory


class TestMemorySnapshots:
    """Tests for the domain_snapshots table and diff functionality."""

    @pytest.fixture()
    def memory(self, tmp_path):
        db_path = tmp_path / "test_snapshots.db"
        mem = Memory(db_path=db_path)
        yield mem
        mem.close()

    def test_save_snapshot(self, memory):
        data = {"registrar": "Example Inc", "nameservers": ["ns1.example.com"], "ssl_valid": True}
        result = memory.save_snapshot("example.com", data)
        assert result["domain"] == "example.com"
        assert result["snapshot_id"] is not None
        assert "captured_at" in result

    def test_list_snapshots(self, memory):
        memory.save_snapshot("example.com", {"registrar": "A"})
        time.sleep(0.01)
        memory.save_snapshot("example.com", {"registrar": "B"})
        snapshots = memory.list_snapshots("example.com")
        assert len(snapshots) == 2
        # Most recent first
        assert json.loads(snapshots[0]["data"])["registrar"] == "B"

    def test_list_snapshots_empty(self, memory):
        snapshots = memory.list_snapshots("nonexistent.com")
        assert snapshots == []

    def test_diff_snapshots(self, memory):
        s1 = memory.save_snapshot("example.com", {
            "registrar": "Old Registrar",
            "nameservers": ["ns1.old.com", "ns2.old.com"],
            "ssl_valid": True,
        })
        s2 = memory.save_snapshot("example.com", {
            "registrar": "New Registrar",
            "nameservers": ["ns1.new.com", "ns2.new.com"],
            "ssl_valid": True,
        })
        diff = memory.diff_snapshots(s1["snapshot_id"], s2["snapshot_id"])
        assert diff["domain"] == "example.com"
        assert len(diff["changes"]) >= 1
        # registrar changed
        reg_change = [c for c in diff["changes"] if c["field"] == "registrar"]
        assert len(reg_change) == 1
        assert reg_change[0]["old"] == "Old Registrar"
        assert reg_change[0]["new"] == "New Registrar"
        # ssl_valid didn't change — should not appear
        ssl_changes = [c for c in diff["changes"] if c["field"] == "ssl_valid"]
        assert len(ssl_changes) == 0

    def test_diff_snapshots_invalid_id(self, memory):
        with pytest.raises(ValueError, match="not found"):
            memory.diff_snapshots(999, 998)

    def test_get_latest_snapshot(self, memory):
        memory.save_snapshot("example.com", {"version": 1})
        time.sleep(0.01)
        memory.save_snapshot("example.com", {"version": 2})
        latest = memory.get_latest_snapshot("example.com")
        assert json.loads(latest["data"])["version"] == 2

    def test_get_latest_snapshot_none(self, memory):
        result = memory.get_latest_snapshot("missing.com")
        assert result is None
