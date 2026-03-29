import json
from unittest.mock import patch

from familiar.tools.seer_tools import seer_bulk_availability


class TestSeerBulkAvailability:
    """Tests for the seer_bulk_availability tool wrapper."""

    @patch("familiar.tools.seer_tools.seer")
    def test_returns_availability_results(self, mock_seer):
        mock_seer.bulk_availability.return_value = [
            {
                "operation": {"Avail": {"domain": "fresh-startup.com"}},
                "success": True,
                "data": {"domain": "fresh-startup.com", "available": True, "confidence": "high", "method": "rdap"},
                "error": None,
                "duration_ms": 312,
            },
            {
                "operation": {"Avail": {"domain": "google.com"}},
                "success": True,
                "data": {"domain": "google.com", "available": False, "confidence": "high", "method": "rdap"},
                "error": None,
                "duration_ms": 205,
            },
        ]
        result = json.loads(seer_bulk_availability.invoke({"domains": '["fresh-startup.com", "google.com"]'}))
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["data"]["available"] is True
        assert result[1]["data"]["available"] is False

    @patch("familiar.tools.seer_tools.seer")
    def test_passes_concurrency(self, mock_seer):
        mock_seer.bulk_availability.return_value = []
        seer_bulk_availability.invoke({"domains": '["a.com"]', "concurrency": "5"})
        mock_seer.bulk_availability.assert_called_once_with(["a.com"], 5)

    @patch("familiar.tools.seer_tools.seer")
    def test_error_returns_json(self, mock_seer):
        mock_seer.bulk_availability.side_effect = RuntimeError("bulk fail")
        result = json.loads(seer_bulk_availability.invoke({"domains": '["fail.com"]'}))
        assert "error" in result
