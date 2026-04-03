"""Test 18: HTTP/HTTPS security scan accuracy.

Validates that http_security_scan and ssl_deep_scan correctly classify
findings by severity, compute grades accurately, handle edge cases in
SSL certificate data, produce reliable security assessments, and correctly
process www subdomains through the same code paths as bare domains.
"""

import json
from unittest.mock import call, patch

import pytest

from familiar.tools.pentest_tools import http_security_scan, ssl_deep_scan, subdomain_takeover_scan


# ---------------------------------------------------------------------------
# http_security_scan
# ---------------------------------------------------------------------------


class TestHttpSecurityGrading:
    """Grade must reflect the highest-severity finding present."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_grade_a_healthy_domain(self, mock_seer):
        """Valid cert, good status, CAA present => grade A."""
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 90},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA"}],
        }
        mock_seer.dig.return_value = [
            {"data": {"tag": "issue", "value": "letsencrypt.org"}},
            {"data": {"tag": "iodef", "value": "mailto:security@example.com"}},
        ]
        result = json.loads(http_security_scan.invoke({"domain": "example.com"}))
        assert result["grade"] == "A"
        assert result["checks_passed"] >= 3

    @patch("familiar.tools.pentest_tools.seer")
    def test_grade_f_invalid_ssl(self, mock_seer):
        """Invalid SSL certificate => CRITICAL finding => grade F."""
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": False},
        }
        mock_seer.ssl.return_value = {"is_valid": False, "chain": []}
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "bad.com"}))
        assert result["grade"] == "F"
        critical = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
        assert len(critical) >= 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_grade_d_no_https(self, mock_seer):
        """No valid cert but server reachable => HIGH finding => grade D."""
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": False},
        }
        mock_seer.ssl.return_value = None
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "nossl.com"}))
        assert result["grade"] in ("D", "F")
        categories = {f["category"] for f in result["findings"]}
        assert "HTTPS" in categories or "SSL" in categories

    @patch("familiar.tools.pentest_tools.seer")
    def test_grade_c_no_caa_only(self, mock_seer):
        """Valid SSL but no CAA records => MEDIUM finding => grade C."""
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 120},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 120,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA"}],
        }
        mock_seer.dig.return_value = []  # No CAA records
        result = json.loads(http_security_scan.invoke({"domain": "nocaa.com"}))
        assert result["grade"] == "C"
        caa_findings = [f for f in result["findings"] if f["category"] == "CAA"]
        assert len(caa_findings) == 1
        assert caa_findings[0]["severity"] == "MEDIUM"


class TestHttpSslCertificateExpiry:
    """SSL certificate expiry thresholds in http_security_scan."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_expiring_within_7_days_critical(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 5},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 5,
            "chain": [{"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "SHA256withRSA"}],
        }
        mock_seer.dig.return_value = [{"data": {"tag": "issue", "value": "letsencrypt.org"}}]
        result = json.loads(http_security_scan.invoke({"domain": "expiring.com"}))
        ssl_findings = [f for f in result["findings"] if f["category"] == "SSL"]
        critical_ssl = [f for f in ssl_findings if f["severity"] == "CRITICAL"]
        assert len(critical_ssl) >= 1
        assert "5 days" in critical_ssl[0]["finding"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_expiring_within_30_days_high(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 15},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 15,
            "chain": [{"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "SHA256withRSA"}],
        }
        mock_seer.dig.return_value = [{"data": {"tag": "issue", "value": "letsencrypt.org"}}]
        result = json.loads(http_security_scan.invoke({"domain": "soonexpiry.com"}))
        ssl_findings = [f for f in result["findings"] if f["category"] == "SSL"]
        high_ssl = [f for f in ssl_findings if f["severity"] == "HIGH"]
        assert len(high_ssl) >= 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_expired_critical(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": -10},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,  # may still return data even if expired
            "days_until_expiry": -10,
            "chain": [],
        }
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "expired.com"}))
        ssl_findings = [f for f in result["findings"] if f["category"] == "SSL"]
        expired = [f for f in ssl_findings if "expired" in f["finding"].lower()]
        assert len(expired) >= 1


class TestHttpWeakCrypto:
    """Weak key sizes and deprecated algorithms must be flagged."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_weak_rsa_key_critical(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 90},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "RSA", "key_bits": 1024, "signature_algorithm": "SHA256withRSA"}],
        }
        mock_seer.dig.return_value = [{"data": {"tag": "issue", "value": "ca.example.com"}}]
        result = json.loads(http_security_scan.invoke({"domain": "weak.com"}))
        weak_findings = [f for f in result["findings"] if "1024" in f.get("finding", "")]
        assert len(weak_findings) == 1
        assert weak_findings[0]["severity"] == "CRITICAL"

    @patch("familiar.tools.pentest_tools.seer")
    def test_sha1_signature_high(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 90},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "sha-1WithRSAEncryption"}],
        }
        mock_seer.dig.return_value = [{"data": {"tag": "issue", "value": "ca.example.com"}}]
        result = json.loads(http_security_scan.invoke({"domain": "sha1.com"}))
        sha1_findings = [f for f in result["findings"] if "sha-1" in f.get("finding", "").lower()]
        assert len(sha1_findings) == 1
        assert sha1_findings[0]["severity"] == "HIGH"


class TestHttpServerUnreachable:
    """Unreachable server should produce INFO-level SSL finding, not CRITICAL."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_unreachable_server_ssl_downgraded(self, mock_seer):
        mock_seer.status.return_value = None
        mock_seer.ssl.return_value = None
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "down.com"}))
        # HTTP finding should be HIGH
        http_findings = [f for f in result["findings"] if f["category"] == "HTTP"]
        assert any(f["severity"] == "HIGH" for f in http_findings)
        # SSL finding should be INFO, not CRITICAL (server was unreachable)
        ssl_findings = [f for f in result["findings"] if f["category"] == "SSL"]
        assert all(f["severity"] != "CRITICAL" for f in ssl_findings)

    @patch("familiar.tools.pentest_tools.seer")
    def test_reachable_server_no_ssl_critical(self, mock_seer):
        """Server reachable but no SSL => CRITICAL (not downgraded)."""
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": False},
        }
        mock_seer.ssl.return_value = None
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "http-only.com"}))
        ssl_findings = [f for f in result["findings"] if f["category"] == "SSL"]
        assert any(f["severity"] == "CRITICAL" for f in ssl_findings)


class TestHttpCaaRecords:
    """CAA record handling accuracy."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_caa_present_with_iodef(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 90},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True, "days_until_expiry": 90,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA"}],
        }
        mock_seer.dig.return_value = [
            {"data": {"tag": "issue", "value": "letsencrypt.org"}},
            {"data": {"tag": "iodef", "value": "mailto:sec@example.com"}},
        ]
        result = json.loads(http_security_scan.invoke({"domain": "good-caa.com"}))
        caa_findings = [f for f in result["findings"] if f["category"] == "CAA"]
        assert len(caa_findings) == 0  # No CAA issues

    @patch("familiar.tools.pentest_tools.seer")
    def test_caa_present_without_iodef(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 90},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True, "days_until_expiry": 90,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA"}],
        }
        mock_seer.dig.return_value = [
            {"data": {"tag": "issue", "value": "letsencrypt.org"}},
        ]
        result = json.loads(http_security_scan.invoke({"domain": "partial-caa.com"}))
        caa_findings = [f for f in result["findings"] if f["category"] == "CAA"]
        assert len(caa_findings) == 1
        assert caa_findings[0]["severity"] == "LOW"
        assert "iodef" in caa_findings[0]["finding"].lower()


class TestHttpHeaderChecklist:
    """The header checklist must always be present."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_header_checklist_present(self, mock_seer):
        mock_seer.status.return_value = {"http_status": 200, "certificate": {"is_valid": True}}
        mock_seer.ssl.return_value = {"is_valid": True, "days_until_expiry": 90, "chain": []}
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "example.com"}))
        assert "header_checklist" in result
        headers = {h["header"] for h in result["header_checklist"]}
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers
        assert "X-Content-Type-Options" in headers
        assert "X-Frame-Options" in headers
        assert "Referrer-Policy" in headers
        assert "Permissions-Policy" in headers


class TestHttpFindingsSortOrder:
    """Findings must be sorted by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_findings_sorted_by_severity(self, mock_seer):
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": False},
        }
        mock_seer.ssl.return_value = {
            "is_valid": False,
            "days_until_expiry": -5,
            "chain": [{"key_type": "RSA", "key_bits": 1024, "signature_algorithm": "sha-1WithRSA"}],
        }
        mock_seer.dig.return_value = []
        result = json.loads(http_security_scan.invoke({"domain": "terrible.com"}))
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        findings = result["findings"]
        for i in range(len(findings) - 1):
            cur = severity_order.index(findings[i]["severity"])
            nxt = severity_order.index(findings[i + 1]["severity"])
            assert cur <= nxt, f"{findings[i]['severity']} should come before {findings[i+1]['severity']}"


# ---------------------------------------------------------------------------
# ssl_deep_scan
# ---------------------------------------------------------------------------


class TestSslDeepScanNoCert:
    """No SSL certificate — behaviour depends on DNS reachability."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_cert_unreachable_returns_info(self, mock_seer):
        """Domain with no routable IP → INFO (not a cert issue)."""
        mock_seer.ssl.return_value = None
        mock_seer.dig.return_value = None
        result = json.loads(ssl_deep_scan.invoke({"domain": "nossl.com"}))
        assert "error" in result
        assert result["findings"][0]["severity"] == "INFO"

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_cert_reachable_returns_critical(self, mock_seer):
        """Domain with routable IP but no cert → CRITICAL."""
        mock_seer.ssl.return_value = None
        mock_seer.dig.side_effect = lambda domain, rtype, *a: (
            [{"data": {"address": "93.184.216.34"}}] if rtype == "A" else []
        )
        result = json.loads(ssl_deep_scan.invoke({"domain": "nossl.com"}))
        assert "error" in result
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"

    @patch("familiar.tools.pentest_tools.seer")
    def test_non_dict_ssl_returns_error(self, mock_seer):
        mock_seer.ssl.return_value = "unexpected"
        mock_seer.dig.return_value = None
        result = json.loads(ssl_deep_scan.invoke({"domain": "weird.com"}))
        assert "error" in result


class TestSslDeepScanExpiry:
    """SSL expiry threshold accuracy in ssl_deep_scan."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_expired_cert_critical(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": -30,
            "chain": [],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "expired.com"}))
        critical = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
        assert any("expired" in f["finding"].lower() for f in critical)

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_7_days_critical(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 3,
            "chain": [],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "urgent.com"}))
        critical = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
        assert any("3 days" in f["finding"] for f in critical)

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_30_days_high(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 20,
            "chain": [],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "soon.com"}))
        high = [f for f in result["findings"] if f["severity"] == "HIGH"]
        assert any("20 days" in f["finding"] for f in high)

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_90_days_medium(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 60,
            "chain": [],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "ok.com"}))
        medium = [f for f in result["findings"] if f["severity"] == "MEDIUM"]
        assert any("60 days" in f["finding"] for f in medium)

    @patch("familiar.tools.pentest_tools.seer")
    def test_cert_healthy_no_expiry_finding(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 180,
            "chain": [],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "healthy.com"}))
        expiry = [f for f in result["findings"] if "expires" in f.get("finding", "").lower()]
        assert len(expiry) == 0


class TestSslDeepScanChainAnalysis:
    """Certificate chain key strength and algorithm checks."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_weak_rsa_1024_critical(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "RSA", "key_bits": 1024, "signature_algorithm": "SHA256withRSA",
                        "subject": "weak.com", "issuer": "CA"}],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "weak.com"}))
        weak = [f for f in result["findings"] if "1024" in f.get("finding", "")]
        assert len(weak) == 1
        assert weak[0]["severity"] == "CRITICAL"

    @patch("familiar.tools.pentest_tools.seer")
    def test_rsa_2048_info(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "SHA256withRSA",
                        "subject": "ok.com", "issuer": "CA"}],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "ok.com"}))
        rsa_info = [f for f in result["findings"] if "2048" in f.get("finding", "")]
        assert len(rsa_info) == 1
        assert rsa_info[0]["severity"] == "INFO"

    @patch("familiar.tools.pentest_tools.seer")
    def test_ecdsa_info(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA",
                        "subject": "good.com", "issuer": "CA"}],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "good.com"}))
        ec_info = [f for f in result["findings"] if "ECDSA" in f.get("finding", "")]
        assert len(ec_info) == 1
        assert ec_info[0]["severity"] == "INFO"

    @patch("familiar.tools.pentest_tools.seer")
    def test_sha1_signature_critical(self, mock_seer):
        # Code checks for "sha-1" (with hyphen) in sig_algo.lower()
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "sha-1WithRSAEncryption",
                        "subject": "old.com", "issuer": "CA"}],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "old.com"}))
        sha1 = [f for f in result["findings"] if "sha-1" in f.get("finding", "").lower()]
        assert len(sha1) >= 1
        assert sha1[0]["severity"] == "CRITICAL"

    @patch("familiar.tools.pentest_tools.seer")
    def test_md5_signature_critical(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "RSA", "key_bits": 2048, "signature_algorithm": "md5WithRSAEncryption",
                        "subject": "ancient.com", "issuer": "CA"}],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "ancient.com"}))
        md5 = [f for f in result["findings"] if "md5" in f.get("finding", "").lower()]
        assert len(md5) >= 1
        assert md5[0]["severity"] == "CRITICAL"


class TestSslDeepScanInvalidCert:
    """Invalid certificate should be flagged, and expiry skipped."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_invalid_cert_no_expiry_finding(self, mock_seer):
        """When cert is invalid, expiry findings are suppressed."""
        mock_seer.ssl.return_value = {
            "is_valid": False,
            "days_until_expiry": -30,
            "chain": [],
            "san_names": [],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "invalid.com"}))
        findings = result["findings"]
        invalid_f = [f for f in findings if "invalid" in f.get("finding", "").lower()]
        assert len(invalid_f) == 1
        assert invalid_f[0]["severity"] == "CRITICAL"
        # Expiry should NOT be reported when cert is already invalid
        expiry_f = [f for f in findings if "expire" in f.get("finding", "").lower()]
        assert len(expiry_f) == 0


class TestSslDeepScanJsonOutput:
    """All outputs must be valid parseable JSON."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_valid_json_on_success(self, mock_seer):
        mock_seer.ssl.return_value = {
            "is_valid": True, "days_until_expiry": 90,
            "chain": [], "san_names": ["example.com"],
        }
        result = ssl_deep_scan.invoke({"domain": "example.com"})
        parsed = json.loads(result)
        assert "domain" in parsed

    @patch("familiar.tools.pentest_tools.seer")
    def test_valid_json_on_failure(self, mock_seer):
        mock_seer.ssl.return_value = None
        result = ssl_deep_scan.invoke({"domain": "fail.com"})
        parsed = json.loads(result)
        assert "error" in parsed


# ---------------------------------------------------------------------------
# www subdomain handling
# ---------------------------------------------------------------------------


class TestWwwSubdomainHttpScan:
    """www subdomains must be scanned through the same code paths as bare domains."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_domain_scanned_as_given(self, mock_seer):
        """http_security_scan must use the exact domain, including www prefix."""
        mock_seer.status.return_value = {
            "http_status": 200,
            "certificate": {"is_valid": True, "days_until_expiry": 90},
        }
        mock_seer.ssl.return_value = {
            "is_valid": True, "days_until_expiry": 90,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA"}],
        }
        mock_seer.dig.return_value = [{"data": {"tag": "issue", "value": "letsencrypt.org"}}]
        result = json.loads(http_security_scan.invoke({"domain": "www.example.com"}))
        assert result["domain"] == "www.example.com"
        # Verify seer was called with the www subdomain
        mock_seer.status.assert_called_once_with("www.example.com")
        mock_seer.ssl.assert_called_once_with("www.example.com")

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_ssl_scan_normalizes_to_bare(self, mock_seer):
        """ssl_deep_scan on www.example.com normalizes to bare domain and scans both."""
        mock_seer.ssl.return_value = {
            "is_valid": True, "days_until_expiry": 90,
            "chain": [], "san_names": ["www.example.com", "example.com"],
        }
        mock_seer.dig.return_value = [{"data": {"address": "93.184.216.34"}}]
        result = json.loads(ssl_deep_scan.invoke({"domain": "www.example.com"}))
        # Normalizes www.example.com → example.com as the primary domain
        assert result["domain"] == "example.com"
        # Both bare and www are scanned
        ssl_calls = [c.args[0] for c in mock_seer.ssl.call_args_list]
        assert "example.com" in ssl_calls
        assert "www.example.com" in ssl_calls

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_cname_to_bare_domain_safe(self, mock_seer):
        """www pointing via CNAME to the bare domain is safe, not a takeover."""
        mock_seer.subdomains.return_value = {"subdomains": ["www.example.com"]}
        # Phase 1: www has a CNAME to example.com (not a third-party service)
        def dig_side_effect(domain, record_type, *args):
            if record_type == "CNAME" and domain == "www.example.com":
                return [{"data": {"target": "example.com"}}]
            if record_type == "A" and domain == "example.com":
                return [{"data": {"address": "93.184.216.34"}}]
            return []
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        assert result["subdomains_checked"] == 1
        assert len(result["vulnerable"]) == 0
        assert len(result["potentially_vulnerable"]) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_cname_to_cdn_resolving_safe(self, mock_seer):
        """www pointing to a CDN that resolves is safe (not dangling)."""
        mock_seer.subdomains.return_value = {"subdomains": ["www.example.com"]}
        def dig_side_effect(domain, record_type, *args):
            if record_type == "CNAME" and domain == "www.example.com":
                return [{"data": {"target": "d1234.cloudfront.net"}}]
            if record_type == "A" and domain == "d1234.cloudfront.net":
                return [{"data": {"address": "13.32.100.1"}}]
            return []
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        # CloudFront CNAME that resolves => potentially vulnerable (MEDIUM) not HIGH
        assert len(result["vulnerable"]) == 0
        if result["potentially_vulnerable"]:
            assert result["potentially_vulnerable"][0]["risk"] == "MEDIUM"

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_cname_dangling_to_s3_vulnerable(self, mock_seer):
        """www pointing to a non-resolving S3 bucket is a HIGH takeover risk."""
        mock_seer.subdomains.return_value = {"subdomains": ["www.example.com"]}
        def dig_side_effect(domain, record_type, *args):
            if record_type == "CNAME" and domain == "www.example.com":
                return [{"data": {"target": "www-example.s3.amazonaws.com"}}]
            if record_type == "A" and domain == "www-example.s3.amazonaws.com":
                return None  # NXDOMAIN - bucket doesn't exist
            return []
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        assert len(result["vulnerable"]) == 1
        vuln = result["vulnerable"][0]
        assert vuln["subdomain"] == "www.example.com"
        assert vuln["risk"] == "HIGH"
        assert "S3" in vuln["service"] or "AWS" in vuln["service"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_cname_dangling_to_github_pages(self, mock_seer):
        """www pointing to unclaimed GitHub Pages is a HIGH takeover risk."""
        mock_seer.subdomains.return_value = {"subdomains": ["www.example.com"]}
        def dig_side_effect(domain, record_type, *args):
            if record_type == "CNAME" and domain == "www.example.com":
                return [{"data": {"target": "example.github.io"}}]
            if record_type == "A" and domain == "example.github.io":
                return None  # No A record - unclaimed
            return []
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        assert len(result["vulnerable"]) == 1
        assert result["vulnerable"][0]["risk"] == "HIGH"
        assert "GitHub" in result["vulnerable"][0]["service"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_cname_dangling_to_heroku(self, mock_seer):
        """www pointing to unclaimed Heroku app is a HIGH takeover risk."""
        mock_seer.subdomains.return_value = {"subdomains": ["www.example.com"]}
        def dig_side_effect(domain, record_type, *args):
            if record_type == "CNAME" and domain == "www.example.com":
                return [{"data": {"target": "myapp.herokuapp.com"}}]
            if record_type == "A" and domain == "myapp.herokuapp.com":
                return None
            return []
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        assert len(result["vulnerable"]) == 1
        assert "Heroku" in result["vulnerable"][0]["service"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_among_multiple_subdomains(self, mock_seer):
        """www should be checked alongside other subdomains without special treatment."""
        mock_seer.subdomains.return_value = {
            "subdomains": ["www.example.com", "api.example.com", "mail.example.com"]
        }
        def dig_side_effect(domain, record_type, *args):
            if record_type == "CNAME":
                return []  # No CNAMEs for any
            if record_type == "A":
                return [{"data": {"address": "93.184.216.34"}}]
            return []
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        assert result["subdomains_checked"] == 3
        assert len(result["vulnerable"]) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_no_records_at_all(self, mock_seer):
        """www with no CNAME and no A record is an error, not a vulnerability."""
        mock_seer.subdomains.return_value = {"subdomains": ["www.example.com"]}
        def dig_side_effect(domain, record_type, *args):
            return None  # No records for anything
        mock_seer.dig.side_effect = dig_side_effect
        result = json.loads(subdomain_takeover_scan.invoke({"domain": "example.com"}))
        assert len(result["vulnerable"]) == 0
        assert result["error_count"] == 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_ssl_cert_covers_both_bare_and_www(self, mock_seer):
        """SAN list including both bare and www should be reflected in scan output."""
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 120,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA",
                        "subject": "example.com", "issuer": "Let's Encrypt"}],
            "san_names": ["example.com", "www.example.com"],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "www.example.com"}))
        san = result.get("san_analysis", {})
        assert san.get("count") == 2
        assert "example.com" in san.get("names", [])
        assert "www.example.com" in san.get("names", [])

    @patch("familiar.tools.pentest_tools.seer")
    def test_www_wildcard_cert_covers_www(self, mock_seer):
        """A wildcard *.example.com cert should show wildcard coverage."""
        mock_seer.ssl.return_value = {
            "is_valid": True,
            "days_until_expiry": 90,
            "chain": [{"key_type": "EC", "key_bits": 256, "signature_algorithm": "SHA256withECDSA",
                        "subject": "*.example.com", "issuer": "DigiCert"}],
            "san_names": ["*.example.com", "example.com"],
        }
        result = json.loads(ssl_deep_scan.invoke({"domain": "www.example.com"}))
        san = result.get("san_analysis", {})
        assert san.get("has_wildcard") is True
        assert "*.example.com" in san.get("wildcard_names", [])
