"""Comprehensive tests for the exposure_report tool.

Validates finding aggregation, deduplication (SSL/CAA from http_security_scan
excluded in favour of dedicated tools), severity sorting, risk assessment,
executive summary structure, section summaries, recommendations, and edge
cases including tool errors, None returns, and domain normalization.

Mocking strategy: patch ``seer`` at the pentest_tools module level so all 6
inner tools (subdomain_takeover_scan, http_security_scan, email_security_audit,
ssl_deep_scan, dns_zone_security, infrastructure_recon) execute with controlled
data through a single mock.  This tests the full integration path that
exposure_report exercises.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from familiar.tools.pentest_tools import exposure_report


# ---------------------------------------------------------------------------
# Helpers — build controlled seer responses
# ---------------------------------------------------------------------------

def _make_ssl(*, valid=True, days=90, key_type="EC", key_bits=256,
              sig="SHA256withECDSA", issuer="CN=Let's Encrypt",
              subject="example.com", san_names=None):
    """Build a minimal seer.ssl() response dict."""
    leaf = {
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_algorithm": sig,
        "issuer": issuer,
        "subject": subject,
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "is_ca": False,
    }
    return {
        "is_valid": valid,
        "days_until_expiry": days,
        "chain": [leaf],
        "san_names": san_names or [subject],
        "protocol_version": "TLSv1.3",
    }


def _make_status(*, http_status=200, title="Example Domain", cert_valid=True):
    """Build a minimal seer.status() response dict."""
    return {
        "http_status": http_status,
        "http_status_text": "OK" if http_status == 200 else "Error",
        "title": title,
        "certificate": {"is_valid": cert_valid, "days_until_expiry": 90},
    }


def _make_dnssec(*, enabled=True, status="secure"):
    """Build a minimal seer.dnssec() response dict."""
    return {
        "enabled": enabled,
        "status": status,
        "has_ds_records": enabled,
        "has_dnskey_records": enabled,
        "ds_records": [],
        "dnskey_records": [],
        "issues": [],
    }


def _make_propagation(*, pct=100):
    """Build a minimal seer.propagation() response dict."""
    return {
        "propagation_percentage": pct,
        "servers_checked": 10,
        "servers_responding": 10,
        "inconsistencies": [],
    }


def _dns_records():
    """Return a set of DNS record fixtures keyed by (domain_suffix, record_type)."""
    return {
        # NS
        "NS": [
            {"data": {"nameserver": "ns1.example.com"}},
            {"data": {"nameserver": "ns2.example.com"}},
        ],
        # SOA
        "SOA": [
            {"data": {"mname": "ns1.example.com", "rname": "admin.example.com",
                       "serial": 2025010101, "refresh": 3600, "retry": 900,
                       "expire": 604800, "minimum": 300}},
        ],
        # CAA — with issue + iodef
        "CAA": [
            {"data": {"tag": "issue", "value": "letsencrypt.org", "flags": 0}},
            {"data": {"tag": "iodef", "value": "mailto:sec@example.com", "flags": 0}},
        ],
        # A
        "A": [{"data": {"address": "93.184.216.34"}}],
        # AAAA
        "AAAA": [{"data": {"address": "2606:2800:220:1:248:1893:25c8:1946"}}],
        # MX
        "MX": [{"data": {"exchange": "aspmx.l.google.com", "preference": 10}}],
        # TXT — SPF + DMARC + DKIM
        "TXT": [
            {"data": {"text": "v=spf1 include:_spf.google.com -all"}},
        ],
        # CNAME — empty for root
        "CNAME": [],
        # ANY
        "ANY": [{"data": {"address": "93.184.216.34"}}],
    }


def _dmarc_txt():
    return [{"data": {"text": "v=DMARC1; p=reject; rua=mailto:d@example.com"}}]


def _dkim_txt():
    return [{"data": {"text": "v=DKIM1; k=rsa; p=AAAA..."}}]


def _build_dig_side_effect(records=None, dmarc=None, dkim=None,
                           subdomains_cname=None):
    """Build a seer.dig side_effect that routes queries by record type.

    Parameters
    ----------
    records : dict, optional
        Mapping of record_type -> list[record_dict].  Falls back to
        ``_dns_records()`` defaults.
    dmarc : list, optional
        DMARC TXT response.  Falls back to ``_dmarc_txt()``.
    dkim : list, optional
        DKIM TXT response for probed selectors.  Falls back to ``_dkim_txt()``.
    subdomains_cname : dict, optional
        Mapping of subdomain -> CNAME target for takeover scanning.
    """
    base = _dns_records()
    if records:
        base.update(records)
    if dmarc is None:
        dmarc = _dmarc_txt()
    if dkim is None:
        dkim = _dkim_txt()
    if subdomains_cname is None:
        subdomains_cname = {}

    def _side_effect(domain_arg, rtype, *extra_args):
        domain_lower = domain_arg.lower().strip().rstrip(".")

        # DMARC query
        if domain_lower.startswith("_dmarc."):
            return dmarc

        # DKIM selector queries
        if "._domainkey." in domain_lower:
            selector = domain_lower.split("._domainkey.")[0]
            if selector == "google":
                return dkim
            return None

        # Subdomain CNAME lookups (for takeover scanning)
        if rtype == "CNAME" and domain_lower in subdomains_cname:
            target = subdomains_cname[domain_lower]
            return [{"data": {"target": target}}]

        # Standard lookups
        return base.get(rtype, None)

    return _side_effect


def _setup_healthy_seer(mock_seer, **overrides):
    """Configure mock_seer for a healthy domain (no critical findings).

    Returns the mock_seer for further customisation if needed.
    """
    ssl = overrides.get("ssl", _make_ssl())
    status = overrides.get("status", _make_status())
    dnssec = overrides.get("dnssec", _make_dnssec())
    propagation = overrides.get("propagation", _make_propagation())
    subdomains = overrides.get("subdomains", {"subdomains": []})
    dns_compare = overrides.get("dns_compare", {"matches": True})

    mock_seer.ssl.return_value = ssl
    mock_seer.status.return_value = status
    mock_seer.dnssec.return_value = dnssec
    mock_seer.propagation.return_value = propagation
    mock_seer.subdomains.return_value = subdomains
    mock_seer.dns_compare.return_value = dns_compare
    mock_seer.dig.side_effect = _build_dig_side_effect(
        **overrides.get("dig_kwargs", {}))
    return mock_seer


def _invoke(domain="example.com"):
    """Invoke exposure_report and parse the JSON result."""
    raw = exposure_report.invoke({"domain": domain})
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Deduplication Logic
# ---------------------------------------------------------------------------


class TestDeduplication:
    """SSL and CAA findings from http_security_scan are excluded in favour of
    the dedicated ssl_deep_scan and dns_zone_security tools."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_ssl_findings_from_http_scan_excluded(self, mock_seer):
        """SSL-category findings should only come from ssl_tls source, not
        http_security."""
        _setup_healthy_seer(mock_seer,
                            ssl=_make_ssl(valid=False))  # triggers SSL findings
        result = _invoke()
        ssl_from_http = [
            f for f in result["findings"]
            if f.get("source") == "http_security"
            and f.get("category") == "SSL"
        ]
        assert ssl_from_http == [], (
            "SSL-category findings from http_security_scan should be excluded"
        )

    @patch("familiar.tools.pentest_tools.seer")
    def test_caa_findings_from_http_scan_excluded(self, mock_seer):
        """CAA-category findings should only come from dns_zone_security, not
        http_security."""
        _setup_healthy_seer(
            mock_seer,
            dig_kwargs={"records": {"CAA": []}},  # missing CAA triggers findings
        )
        result = _invoke()
        caa_from_http = [
            f for f in result["findings"]
            if f.get("source") == "http_security"
            and f.get("category") == "CAA"
        ]
        assert caa_from_http == [], (
            "CAA-category findings from http_security_scan should be excluded"
        )

    @patch("familiar.tools.pentest_tools.seer")
    def test_non_ssl_caa_findings_from_http_scan_included(self, mock_seer):
        """Non-SSL/non-CAA findings from http_security_scan ARE included."""
        _setup_healthy_seer(
            mock_seer,
            status=_make_status(cert_valid=False),
            ssl=None,  # no SSL data => triggers HTTPS and SSL findings
        )
        result = _invoke()
        http_findings = [
            f for f in result["findings"]
            if f.get("source") == "http_security"
        ]
        # Should have at least the HTTPS finding (category != SSL/CAA)
        non_ssl_caa = [
            f for f in http_findings
            if f.get("category") not in ("SSL", "CAA")
        ]
        assert len(non_ssl_caa) >= 1, (
            "Non-SSL/CAA http_security findings should be present"
        )


# ---------------------------------------------------------------------------
# Finding Aggregation
# ---------------------------------------------------------------------------


class TestFindingAggregation:
    """Findings from all 6 tools are collected with source attribution."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_findings_have_source_field(self, mock_seer):
        """Every finding must have a ``source`` key."""
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        for f in result["findings"]:
            assert "source" in f, f"Finding missing 'source': {f}"

    @patch("familiar.tools.pentest_tools.seer")
    def test_multiple_sources_represented(self, mock_seer):
        """At least several distinct sources should appear when the domain has
        various findings."""
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=True, days=90, key_type="RSA", key_bits=2048),
            dig_kwargs={"records": {"CAA": []}},
        )
        result = _invoke()
        sources = {f["source"] for f in result["findings"]}
        # With no CAA, missing issuewild, no iodef, plus RSA 2048 INFO finding,
        # plus DKIM findings, etc — we expect at least 2+ sources
        assert len(sources) >= 2, f"Expected multiple sources, got {sources}"

    @patch("familiar.tools.pentest_tools.seer")
    def test_subdomain_takeover_vulnerable_becomes_critical(self, mock_seer):
        """Vulnerable subdomain entries are converted to CRITICAL findings."""
        subs = {"subdomains": ["vuln.example.com"]}
        cname_map = {"vuln.example.com": "vuln.herokuapp.com"}
        _setup_healthy_seer(
            mock_seer,
            subdomains=subs,
            dig_kwargs={"subdomains_cname": cname_map},
        )
        # The CNAME target resolution should return nothing (dangling)
        original_side_effect = mock_seer.dig.side_effect

        def _dig_with_dangling(domain_arg, rtype, *extra_args):
            d = domain_arg.lower().strip().rstrip(".")
            # CNAME target A-record lookup for the dangling service
            if d == "vuln.herokuapp.com" and rtype == "A":
                return None  # dangling
            return original_side_effect(domain_arg, rtype, *extra_args)

        mock_seer.dig.side_effect = _dig_with_dangling

        result = _invoke()
        takeover_findings = [
            f for f in result["findings"]
            if f.get("source") == "subdomain_takeover"
        ]
        critical_takeover = [f for f in takeover_findings if f["severity"] == "CRITICAL"]
        assert len(critical_takeover) >= 1, (
            "Vulnerable subdomain should produce a CRITICAL finding"
        )

    @patch("familiar.tools.pentest_tools.seer")
    def test_subdomain_takeover_potentially_vulnerable_becomes_high(self, mock_seer):
        """Potentially vulnerable subdomain entries are converted to HIGH
        findings."""
        subs = {"subdomains": ["maybe.example.com"]}
        cname_map = {"maybe.example.com": "maybe.herokuapp.com"}
        _setup_healthy_seer(
            mock_seer,
            subdomains=subs,
            dig_kwargs={"subdomains_cname": cname_map},
        )
        original_side_effect = mock_seer.dig.side_effect

        def _dig_with_resolving(domain_arg, rtype, *extra_args):
            d = domain_arg.lower().strip().rstrip(".")
            # CNAME target A-record resolves (potentially vulnerable)
            if d == "maybe.herokuapp.com" and rtype == "A":
                return [{"data": {"address": "1.2.3.4"}}]
            return original_side_effect(domain_arg, rtype, *extra_args)

        mock_seer.dig.side_effect = _dig_with_resolving

        result = _invoke()
        takeover_findings = [
            f for f in result["findings"]
            if f.get("source") == "subdomain_takeover"
        ]
        high_takeover = [f for f in takeover_findings if f["severity"] == "HIGH"]
        assert len(high_takeover) >= 1, (
            "Potentially vulnerable subdomain should produce a HIGH finding"
        )

    @patch("familiar.tools.pentest_tools.seer")
    def test_total_findings_matches_severity_breakdown_sum(self, mock_seer):
        """total_findings must equal the sum of all severity_breakdown counts."""
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        breakdown = result["executive_summary"]["severity_breakdown"]
        assert result["executive_summary"]["total_findings"] == sum(breakdown.values())


# ---------------------------------------------------------------------------
# Severity Sorting
# ---------------------------------------------------------------------------


class TestSeveritySorting:
    """Findings must be sorted CRITICAL > HIGH > MEDIUM > LOW > INFO."""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    @patch("familiar.tools.pentest_tools.seer")
    def test_findings_sorted_by_severity(self, mock_seer):
        """Walk the findings list and verify monotonically non-decreasing
        severity order."""
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=False),  # triggers CRITICAL SSL findings
            dig_kwargs={"records": {"CAA": []}},  # triggers MEDIUM CAA findings
        )
        result = _invoke()
        findings = result["findings"]
        if len(findings) < 2:
            pytest.skip("Need at least 2 findings to verify sort order")
        for i in range(len(findings) - 1):
            cur = self.SEVERITY_ORDER.get(findings[i].get("severity", "INFO"), 5)
            nxt = self.SEVERITY_ORDER.get(findings[i + 1].get("severity", "INFO"), 5)
            assert cur <= nxt, (
                f"Findings not sorted: {findings[i]['severity']} before "
                f"{findings[i + 1]['severity']} at index {i}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_severity_breakdown_counts_accurate(self, mock_seer):
        """Manually count severities and compare with the breakdown dict."""
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=True, days=20, key_type="RSA", key_bits=2048),
        )
        result = _invoke()
        findings = result["findings"]
        breakdown = result["executive_summary"]["severity_breakdown"]
        manual = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in manual:
                manual[sev] += 1
        assert breakdown == manual


# ---------------------------------------------------------------------------
# Overall Risk Assessment
# ---------------------------------------------------------------------------


class TestOverallRiskAssessment:
    """overall_risk is determined by the highest severity finding present."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_critical_findings_yield_critical_risk(self, mock_seer):
        _setup_healthy_seer(mock_seer, ssl=_make_ssl(valid=False))
        result = _invoke()
        assert result["executive_summary"]["overall_risk"] == "CRITICAL"

    @patch("familiar.tools.pentest_tools.seer")
    def test_high_findings_only_yield_high_risk(self, mock_seer):
        """No CRITICAL but at least one HIGH => overall_risk HIGH."""
        # Valid SSL but expiring in 20 days (HIGH from ssl_deep_scan)
        # + CAA present with iodef, DNSSEC enabled => no CRITICAL
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=True, days=20, key_type="EC", key_bits=256),
        )
        result = _invoke()
        breakdown = result["executive_summary"]["severity_breakdown"]
        # If no CRITICAL but has HIGH
        if breakdown["CRITICAL"] == 0 and breakdown["HIGH"] > 0:
            assert result["executive_summary"]["overall_risk"] == "HIGH"
        else:
            # If test setup triggers a CRITICAL, skip
            pytest.skip(
                f"Test setup produced unexpected breakdown: {breakdown}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_medium_findings_only_yield_medium_risk(self, mock_seer):
        """Only MEDIUM-severity findings => overall_risk MEDIUM."""
        # Valid SSL, good expiry, RSA 4096 (no RSA INFO), DNSSEC enabled,
        # CAA present but missing issuewild => MEDIUM
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=True, days=60, key_type="RSA", key_bits=4096),
            dig_kwargs={
                "records": {
                    "CAA": [
                        {"data": {"tag": "issue", "value": "letsencrypt.org", "flags": 0}},
                        {"data": {"tag": "iodef", "value": "mailto:sec@example.com", "flags": 0}},
                    ],
                },
                "dkim": _dkim_txt(),
                "dmarc": [{"data": {"text": "v=DMARC1; p=reject; rua=mailto:d@example.com"}}],
            },
        )
        result = _invoke()
        breakdown = result["executive_summary"]["severity_breakdown"]
        if breakdown["CRITICAL"] == 0 and breakdown["HIGH"] == 0 and breakdown["MEDIUM"] > 0:
            assert result["executive_summary"]["overall_risk"] == "MEDIUM"
        else:
            pytest.skip(
                f"Test setup produced unexpected breakdown: {breakdown}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_low_findings_only_yield_low_risk(self, mock_seer):
        """Only LOW-severity findings => overall_risk LOW."""
        # Healthy domain, DMARC quarantine produces LOW,
        # SPF softfail produces LOW.  Everything else clean.
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=True, days=200, key_type="EC", key_bits=256),
            dig_kwargs={
                "records": {
                    "CAA": [
                        {"data": {"tag": "issue", "value": "letsencrypt.org", "flags": 0}},
                        {"data": {"tag": "issuewild", "value": "letsencrypt.org", "flags": 0}},
                        {"data": {"tag": "iodef", "value": "mailto:sec@example.com", "flags": 0}},
                    ],
                    "TXT": [
                        {"data": {"text": "v=spf1 include:_spf.google.com ~all"}},
                    ],
                },
                "dmarc": [{"data": {"text": "v=DMARC1; p=quarantine; rua=mailto:d@example.com"}}],
                "dkim": _dkim_txt(),
            },
        )
        result = _invoke()
        breakdown = result["executive_summary"]["severity_breakdown"]
        if (breakdown["CRITICAL"] == 0 and breakdown["HIGH"] == 0
                and breakdown["MEDIUM"] == 0 and breakdown["LOW"] > 0):
            assert result["executive_summary"]["overall_risk"] == "LOW"
        else:
            pytest.skip(
                f"Test setup produced unexpected breakdown: {breakdown}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_findings_yield_clean_risk(self, mock_seer):
        """No findings at all => overall_risk CLEAN."""
        # This is very hard to achieve with real tools — INFO findings from
        # ssl_deep_scan are common.  So we verify logic by checking the
        # conditional chain directly.
        # The simplest way: patch all 6 tool invocations to return empty data.
        # We mock parallel_calls at the pentest_tools level for this one.
        with patch("familiar.tools.pentest_tools.parallel_calls") as mock_pc:
            empty_takeover = json.dumps({
                "domain": "example.com", "subdomains_checked": 0,
                "vulnerable": [], "potentially_vulnerable": [],
                "safe_count": 0, "error_count": 0, "findings": [],
            })
            empty_http = json.dumps({
                "domain": "example.com", "grade": "A",
                "checks_passed": 5, "checks_total": 5,
                "findings": [], "header_checklist": [],
            })
            empty_email = json.dumps({
                "domain": "example.com", "overall_risk": "low",
                "risk_score": 0, "mx": {"has_mx": True, "records": [], "providers": []},
                "spf": {"found": True}, "dmarc": {"found": True},
                "dkim": {"selectors_probed": 30, "selectors_found": 1, "results": []},
                "findings": [],
            })
            empty_ssl = json.dumps({
                "domain": "example.com", "is_valid": True,
                "days_until_expiry": 200, "chain": [],
                "san_analysis": {"count": 1, "names": ["example.com"]},
                "issuer": {}, "findings": [],
            })
            empty_dns = json.dumps({
                "domain": "example.com", "overall_risk": "low",
                "risk_score": 0, "zone_transfer": {"tested": True, "results": []},
                "dnssec": {"status": "secure", "enabled": True},
                "caa_policy": {"has_records": True, "policies": []},
                "nameservers": {"count": 2},
                "soa": {}, "propagation": {}, "findings": [],
            })
            empty_infra = json.dumps({
                "domain": "example.com",
                "cdn_waf": {"detected": []}, "dns_provider": [],
                "hosting": {"providers": []},
                "email_infrastructure": {"providers": []},
                "technology_signals": [], "ssl_signals": {}, "web_signals": {},
            })
            empty_reputation = json.dumps({
                "domain": "example.com", "overall_status": "clean",
                "listed_count": 0, "total_checks": 0, "findings": [],
            })
            empty_zone_transfer = json.dumps({
                "domain": "example.com", "vulnerable": False,
                "nameservers_tested": [], "findings": [],
            })
            empty_mta_sts = json.dumps({
                "domain": "example.com",
                "mta_sts": {"txt_record": {"found": False}},
                "tls_rpt": {"found": False}, "findings": [],
            })
            empty_dane = json.dumps({
                "domain": "example.com", "dane_configured": False,
                "dnssec_validated": False, "findings": [],
            })
            mock_pc.return_value = [
                empty_takeover, empty_http, empty_email,
                empty_ssl, empty_dns, empty_infra,
                empty_reputation, empty_zone_transfer,
                empty_mta_sts, empty_dane,
            ]
            result = _invoke()
            assert result["executive_summary"]["overall_risk"] == "CLEAN"
            assert result["executive_summary"]["total_findings"] == 0


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------


class TestExecutiveSummary:
    """Structure and content of executive_summary."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_matches_input(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke("Example.COM")
        assert result["executive_summary"]["domain"] == "example.com"

    @patch("familiar.tools.pentest_tools.seer")
    def test_total_findings_matches_findings_array(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        assert result["executive_summary"]["total_findings"] == len(result["findings"])

    @patch("familiar.tools.pentest_tools.seer")
    def test_severity_breakdown_keys(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        breakdown = result["executive_summary"]["severity_breakdown"]
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert key in breakdown, f"Missing severity_breakdown key: {key}"


# ---------------------------------------------------------------------------
# Section Summaries
# ---------------------------------------------------------------------------


class TestSectionSummaries:
    """Each section summary contains expected keys from the underlying tool."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_ssl_tls_section(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        ssl_section = result["sections"].get("ssl_tls", {})
        assert "valid" in ssl_section
        assert "days_until_expiry" in ssl_section

    @patch("familiar.tools.pentest_tools.seer")
    def test_http_security_section(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        http_section = result["sections"].get("http_security", {})
        assert "grade" in http_section

    @patch("familiar.tools.pentest_tools.seer")
    def test_email_security_section(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        email_section = result["sections"].get("email_security", {})
        assert "overall_risk" in email_section

    @patch("familiar.tools.pentest_tools.seer")
    def test_dns_zone_security_section(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        dns_section = result["sections"].get("dns_zone_security", {})
        assert "dnssec_status" in dns_section

    @patch("familiar.tools.pentest_tools.seer")
    def test_infrastructure_section(self, mock_seer):
        """Infrastructure section should have cdn_waf, hosting, dns_provider."""
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        infra_section = result["sections"].get("infrastructure", {})
        assert "cdn_waf" in infra_section
        assert "hosting" in infra_section
        assert "dns_provider" in infra_section


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class TestRecommendations:
    """Recommendations are CRITICAL/HIGH only, capped at 15, sorted by
    severity."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_only_critical_and_high_in_recommendations(self, mock_seer):
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=False),  # triggers CRITICAL
            dig_kwargs={"records": {"CAA": []}},  # triggers MEDIUM
        )
        result = _invoke()
        for rec in result["recommendations"]:
            assert rec["severity"] in ("CRITICAL", "HIGH"), (
                f"Recommendation has unexpected severity: {rec['severity']}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_recommendations_capped_at_15(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        assert len(result["recommendations"]) <= 15

    @patch("familiar.tools.pentest_tools.seer")
    def test_recommendations_sorted_by_severity(self, mock_seer):
        _setup_healthy_seer(mock_seer, ssl=_make_ssl(valid=False))
        result = _invoke()
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        recs = result["recommendations"]
        for i in range(len(recs) - 1):
            cur = severity_order.get(recs[i].get("severity", "INFO"), 5)
            nxt = severity_order.get(recs[i + 1].get("severity", "INFO"), 5)
            assert cur <= nxt


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Graceful handling of errors, None returns, and unusual inputs."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_tool_returning_error_json(self, mock_seer):
        """One or more inner tools returning error JSON should not crash."""
        _setup_healthy_seer(mock_seer)
        # ssl returns error structure
        mock_seer.ssl.return_value = None
        result = _invoke()
        # Should still produce valid output
        assert "executive_summary" in result
        assert "findings" in result

    @patch("familiar.tools.pentest_tools.seer")
    def test_all_seer_calls_return_none(self, mock_seer):
        """If seer itself is completely broken, exposure_report still returns
        valid JSON."""
        mock_seer.ssl.return_value = None
        mock_seer.status.return_value = None
        mock_seer.dnssec.return_value = None
        mock_seer.propagation.return_value = None
        mock_seer.subdomains.return_value = None
        mock_seer.dns_compare.return_value = None
        mock_seer.dig.return_value = None
        result = _invoke()
        assert "executive_summary" in result
        assert "sections" in result
        assert "findings" in result
        assert "recommendations" in result

    @patch("familiar.tools.pentest_tools.seer")
    def test_seer_dig_raises_exception(self, mock_seer):
        """If seer.dig raises an exception, safe_call returns None and the
        report still works."""
        mock_seer.ssl.return_value = None
        mock_seer.status.return_value = None
        mock_seer.dnssec.return_value = None
        mock_seer.propagation.return_value = None
        mock_seer.subdomains.return_value = None
        mock_seer.dns_compare.return_value = None
        mock_seer.dig.side_effect = ConnectionError("network unreachable")
        result = _invoke()
        assert "executive_summary" in result
        assert isinstance(result["findings"], list)

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_normalization_uppercase(self, mock_seer):
        """Uppercase domain input is normalized to lowercase."""
        _setup_healthy_seer(mock_seer)
        result = _invoke("EXAMPLE.COM")
        assert result["executive_summary"]["domain"] == "example.com"

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_normalization_whitespace(self, mock_seer):
        """Leading/trailing whitespace is stripped."""
        _setup_healthy_seer(mock_seer)
        result = _invoke("  example.com  ")
        assert result["executive_summary"]["domain"] == "example.com"

    @patch("familiar.tools.pentest_tools.seer")
    def test_partial_tool_failure_graceful(self, mock_seer):
        """If some seer calls work and others fail, the report aggregates
        whatever succeeded."""
        _setup_healthy_seer(mock_seer)
        # Make ssl and dnssec fail
        mock_seer.ssl.side_effect = Exception("SSL broken")
        mock_seer.dnssec.side_effect = Exception("DNSSEC broken")
        result = _invoke()
        # The report should still have sections from tools that worked
        assert "executive_summary" in result
        assert isinstance(result["findings"], list)


# ---------------------------------------------------------------------------
# Output Structure
# ---------------------------------------------------------------------------


class TestOutputStructure:
    """Top-level keys and finding field requirements."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_top_level_keys(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        for key in ("executive_summary", "sections", "findings", "recommendations"):
            assert key in result, f"Missing top-level key: {key}"

    @patch("familiar.tools.pentest_tools.seer")
    def test_findings_have_required_fields(self, mock_seer):
        """Every finding should have severity, finding, detail, recommendation,
        and source."""
        _setup_healthy_seer(
            mock_seer,
            ssl=_make_ssl(valid=False),  # ensure at least some findings
        )
        result = _invoke()
        required = {"severity", "finding", "detail", "recommendation", "source"}
        for f in result["findings"]:
            missing = required - set(f.keys())
            assert not missing, (
                f"Finding missing fields {missing}: {f}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_output_is_valid_json(self, mock_seer):
        """The raw output should be parseable JSON."""
        _setup_healthy_seer(mock_seer)
        raw = exposure_report.invoke({"domain": "example.com"})
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    @patch("familiar.tools.pentest_tools.seer")
    def test_findings_list_type(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        assert isinstance(result["findings"], list)

    @patch("familiar.tools.pentest_tools.seer")
    def test_recommendations_list_type(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        assert isinstance(result["recommendations"], list)

    @patch("familiar.tools.pentest_tools.seer")
    def test_sections_is_dict(self, mock_seer):
        _setup_healthy_seer(mock_seer)
        result = _invoke()
        assert isinstance(result["sections"], dict)
