import json
from unittest.mock import MagicMock, patch

from familiar.tools.memory_tools import snapshot_domain, diff_snapshots


class TestSnapshotDomain:
    """Tests for the snapshot_domain tool wrapper."""

    @patch("familiar.tools.memory_tools.seer")
    @patch("familiar.tools.memory_tools.get_memory")
    def test_captures_snapshot(self, mock_get_memory, mock_seer):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.save_snapshot.return_value = {
            "domain": "example.com",
            "snapshot_id": 1,
            "captured_at": "2026-03-29T00:00:00+00:00",
        }
        mock_mem.remember_domain.return_value = {}
        mock_seer.lookup.return_value = {"source": "rdap", "data": {"registrar": "Test"}}
        mock_seer.status.return_value = {"http_status": 200}
        mock_seer.dig.return_value = [{"data": {"nameserver": "ns1.test.com."}}]
        mock_seer.dnssec.return_value = {"status": "secure"}

        result = json.loads(snapshot_domain.invoke({"domain": "example.com"}))
        assert result["snapshot_id"] == 1
        assert result["domain"] == "example.com"
        mock_mem.save_snapshot.assert_called_once()

    @patch("familiar.tools.memory_tools.seer")
    @patch("familiar.tools.memory_tools.get_memory")
    def test_error_returns_json(self, mock_get_memory, mock_seer):
        mock_seer.lookup.side_effect = RuntimeError("network error")
        mock_seer.status.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.dnssec.return_value = None
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.save_snapshot.return_value = {
            "domain": "fail.com", "snapshot_id": 2, "captured_at": "2026-03-29T00:00:00+00:00",
        }
        mock_mem.remember_domain.return_value = {}
        # Should still save whatever data it gathered, not crash
        result = json.loads(snapshot_domain.invoke({"domain": "fail.com"}))
        assert "snapshot_id" in result


class TestDiffSnapshots:
    """Tests for the diff_snapshots tool wrapper."""

    @patch("familiar.tools.memory_tools.get_memory")
    def test_returns_diff(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.diff_snapshots.return_value = {
            "domain": "example.com",
            "snapshot_a": {"id": 1, "captured_at": "2026-03-01"},
            "snapshot_b": {"id": 2, "captured_at": "2026-03-29"},
            "changes": [{"field": "registrar", "old": "A", "new": "B"}],
            "total_changes": 1,
        }
        result = json.loads(diff_snapshots.invoke({"snapshot_id_a": "1", "snapshot_id_b": "2"}))
        assert result["total_changes"] == 1
        assert result["changes"][0]["field"] == "registrar"

    @patch("familiar.tools.memory_tools.get_memory")
    def test_invalid_id(self, mock_get_memory):
        mock_mem = MagicMock()
        mock_get_memory.return_value = mock_mem
        mock_mem.diff_snapshots.side_effect = ValueError("Snapshot 999 not found")
        result = json.loads(diff_snapshots.invoke({"snapshot_id_a": "999", "snapshot_id_b": "1"}))
        assert "error" in result
