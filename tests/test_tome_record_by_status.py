import json
from unittest.mock import patch

from familiar.tools.tome_tools import tome_record_by_status


class TestTomeRecordByStatus:
    """Tests for the tome_record_by_status tool wrapper."""

    @patch("familiar.tools.tome_tools.tome")
    def test_returns_matching_records(self, mock_tome):
        mock_tome.record_by_status.return_value = [
            {"name": "A", "type_code": 1, "status": "Active"},
            {"name": "AAAA", "type_code": 28, "status": "Active"},
        ]
        result = json.loads(tome_record_by_status.invoke({"status": "Active"}))
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "A"

    @patch("familiar.tools.tome_tools.tome")
    def test_empty_result(self, mock_tome):
        mock_tome.record_by_status.return_value = []
        result = json.loads(tome_record_by_status.invoke({"status": "Experimental"}))
        assert result == []

    @patch("familiar.tools.tome_tools.tome")
    def test_error_returns_json(self, mock_tome):
        mock_tome.record_by_status.side_effect = RuntimeError("db error")
        result = json.loads(tome_record_by_status.invoke({"status": "Active"}))
        assert "error" in result
