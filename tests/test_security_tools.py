import json
from unittest.mock import patch

from familiar.tools.security_tools import domain_reputation_check


class TestDomainReputationCheck:
    """Tests for the domain_reputation_check tool."""

    @patch("familiar.tools.security_tools.seer")
    def test_clean_domain(self, mock_seer):
        mock_seer.dig.return_value = []  # No blocklist hits
        result = json.loads(domain_reputation_check.invoke({"domain": "clean-example.com"}))
        assert result["domain"] == "clean-example.com"
        assert result["listed_count"] == 0
        assert result["overall_status"] == "clean"
        assert isinstance(result["checks"], list)
        assert len(result["checks"]) > 0

    @patch("familiar.tools.security_tools.seer")
    def test_listed_domain(self, mock_seer):
        def _dig_side_effect(query, record_type="A", nameserver=None):
            if "zen.spamhaus.org" in query:
                return [{"data": {"address": "127.0.0.2"}, "record_type": "A"}]
            if "dbl.spamhaus.org" in query:
                return [{"data": {"address": "127.0.1.2"}, "record_type": "A"}]
            return []
        mock_seer.dig.side_effect = _dig_side_effect
        result = json.loads(domain_reputation_check.invoke({"domain": "bad-actor.com"}))
        assert result["listed_count"] >= 1
        assert result["overall_status"] == "listed"
        listed = [c for c in result["checks"] if c["listed"]]
        assert len(listed) >= 1

    @patch("familiar.tools.security_tools.seer")
    def test_error_returns_json(self, mock_seer):
        mock_seer.dig.side_effect = RuntimeError("DNS fail")
        result = json.loads(domain_reputation_check.invoke({"domain": "fail.com"}))
        assert result["domain"] == "fail.com"
        # Should handle errors gracefully per-blocklist, not crash entirely
        assert "checks" in result
