import json
from unittest.mock import patch

from familiar.tools.security_tools import dane_tlsa_check, domain_reputation_check, mta_sts_check, website_fingerprint, zone_transfer_test


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


class TestZoneTransferTest:
    """Tests for the zone_transfer_test tool."""

    @patch("familiar.tools.security_tools.seer")
    @patch("familiar.tools.security_tools._attempt_axfr")
    def test_secure_domain(self, mock_axfr, mock_seer):
        mock_seer.dig.return_value = [
            {"data": {"nameserver": "ns1.example.com."}, "record_type": "NS"},
            {"data": {"nameserver": "ns2.example.com."}, "record_type": "NS"},
        ]
        mock_axfr.return_value = {"success": False, "error": "Transfer refused"}
        result = json.loads(zone_transfer_test.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        assert result["vulnerable"] is False
        assert len(result["nameservers_tested"]) == 2

    @patch("familiar.tools.security_tools.seer")
    @patch("familiar.tools.security_tools._attempt_axfr")
    def test_vulnerable_domain(self, mock_axfr, mock_seer):
        mock_seer.dig.return_value = [
            {"data": {"nameserver": "ns1.example.com."}, "record_type": "NS"},
        ]
        mock_axfr.return_value = {
            "success": True,
            "record_count": 42,
            "records_sample": ["example.com. 3600 IN A 93.184.216.34"],
        }
        result = json.loads(zone_transfer_test.invoke({"domain": "example.com"}))
        assert result["vulnerable"] is True
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "CRITICAL"

    @patch("familiar.tools.security_tools.seer")
    def test_no_nameservers(self, mock_seer):
        mock_seer.dig.return_value = []
        result = json.loads(zone_transfer_test.invoke({"domain": "noname.com"}))
        assert result["vulnerable"] is False
        assert len(result["nameservers_tested"]) == 0


class TestMtaStsCheck:
    """Tests for the mta_sts_check tool."""

    @patch("familiar.tools.security_tools._fetch_mta_sts_policy")
    @patch("familiar.tools.security_tools.seer")
    def test_full_mta_sts(self, mock_seer, mock_fetch):
        def _dig(query, record_type="A", nameserver=None):
            if "_mta-sts" in query:
                return [{"data": {"text": "v=STSv1; id=20240101"}, "record_type": "TXT"}]
            if "_smtp._tls" in query:
                return [{"data": {"text": "v=TLSRPTv1; rua=mailto:tls@example.com"}, "record_type": "TXT"}]
            if record_type == "MX":
                return [{"data": {"exchange": "mail.example.com.", "preference": 10}, "record_type": "MX"}]
            return []
        mock_seer.dig.side_effect = _dig
        mock_fetch.return_value = {
            "success": True,
            "policy": "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400",
        }
        result = json.loads(mta_sts_check.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        assert result["mta_sts"]["txt_record"]["found"] is True
        assert result["mta_sts"]["policy"]["found"] is True
        assert result["tls_rpt"]["found"] is True

    @patch("familiar.tools.security_tools._fetch_mta_sts_policy")
    @patch("familiar.tools.security_tools.seer")
    def test_no_mta_sts(self, mock_seer, mock_fetch):
        def _dig(query, record_type="A", nameserver=None):
            if record_type == "MX":
                return [{"data": {"exchange": "mail.no-sts.com.", "preference": 10}, "record_type": "MX"}]
            return []
        mock_seer.dig.side_effect = _dig
        mock_fetch.return_value = {"success": False, "error": "404"}
        result = json.loads(mta_sts_check.invoke({"domain": "no-sts.com"}))
        assert result["mta_sts"]["txt_record"]["found"] is False
        assert result["mta_sts"]["policy"]["found"] is False
        assert result["tls_rpt"]["found"] is False
        assert any(f["severity"] in ("MEDIUM", "LOW") for f in result["findings"])


class TestDaneTlsaCheck:
    """Tests for the dane_tlsa_check tool."""

    @patch("familiar.tools.security_tools.seer")
    def test_no_tlsa(self, mock_seer):
        mock_seer.dig.return_value = []
        mock_seer.ssl.return_value = {"is_valid": True, "chain": [{"subject": "example.com"}]}
        mock_seer.dnssec.return_value = {"status": "insecure"}
        result = json.loads(dane_tlsa_check.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        assert result["dane_configured"] is False

    @patch("familiar.tools.security_tools.seer")
    def test_with_tlsa_records(self, mock_seer):
        def _dig(query, record_type="A", nameserver=None):
            if record_type == "TLSA":
                return [{"data": {"usage": 3, "selector": 1, "matching_type": 1,
                         "certificate_data": "abc123"}, "record_type": "TLSA"}]
            return []
        mock_seer.dig.side_effect = _dig
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "chain": [{"subject": "example.com", "key_type": "EC", "key_bits": 256}],
        }
        mock_seer.dnssec.return_value = {"status": "secure"}
        result = json.loads(dane_tlsa_check.invoke({"domain": "example.com"}))
        assert result["dane_configured"] is True
        assert len(result["tlsa_records"]) >= 1

    @patch("familiar.tools.security_tools.seer")
    def test_smtp_port(self, mock_seer):
        mock_seer.dig.return_value = []
        mock_seer.ssl.return_value = None
        mock_seer.dnssec.return_value = {"status": "insecure"}
        result = json.loads(dane_tlsa_check.invoke({"domain": "mail.example.com", "port": "25"}))
        assert result["port"] == 25
        mock_seer.dig.assert_any_call("_25._tcp.mail.example.com", "TLSA")


class TestWebsiteFingerprint:
    """Tests for the website_fingerprint tool."""

    @patch("familiar.tools.security_tools._fetch_http_headers")
    @patch("familiar.tools.security_tools.seer")
    def test_detects_technologies(self, mock_seer, mock_fetch):
        mock_seer.dig.return_value = []
        mock_seer.status.return_value = {"http_status": 200}
        mock_fetch.return_value = {
            "success": True,
            "status_code": 200,
            "headers": {
                "server": "nginx/1.24",
                "x-powered-by": "PHP/8.2",
                "set-cookie": "wp_session=abc123",
            },
        }
        result = json.loads(website_fingerprint.invoke({"domain": "example.com"}))
        assert result["domain"] == "example.com"
        techs = result["technologies"]
        tech_names = [t["name"] for t in techs]
        # Should detect nginx and PHP from headers
        assert any("nginx" in name for name in tech_names)
        assert any("PHP" in name for name in tech_names)

    @patch("familiar.tools.security_tools._fetch_http_headers")
    @patch("familiar.tools.security_tools.seer")
    def test_unreachable_site(self, mock_seer, mock_fetch):
        mock_seer.dig.return_value = []
        mock_seer.status.return_value = {"http_status": None}
        mock_fetch.return_value = {"success": False, "error": "Connection refused"}
        result = json.loads(website_fingerprint.invoke({"domain": "down.com"}))
        assert result["total_technologies"] == 0
