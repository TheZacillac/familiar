"""Tests for all 12 advisor tool functions in familiar.tools.advisor_tools.

Mocks familiar.tools.advisor_tools.seer and familiar.tools.advisor_tools.tome
to avoid real network calls. Each tool is invoked via .invoke() (LangChain @tool).

Strategic tools (6): appraise_domain, plan_acquisition, suggest_domains,
                     audit_portfolio, competitive_intel, migration_preflight
Composite tools (6): security_audit, brand_protection_scan, dns_health_check,
                     domain_timeline, expiration_alert, compare_security
"""

import json
from unittest.mock import patch

import pytest

from familiar.tools.advisor_tools import (
    appraise_domain,
    audit_portfolio,
    brand_protection_scan,
    compare_security,
    competitive_intel,
    dns_health_check,
    domain_timeline,
    expiration_alert,
    migration_preflight,
    plan_acquisition,
    security_audit,
    suggest_domains,
)


# ---------------------------------------------------------------------------
# Helpers — reusable mock return values
# ---------------------------------------------------------------------------

def _whois_lookup(domain="example.com", **overrides):
    """Valid WHOIS lookup result."""
    base = {
        "source": "whois",
        "data": {
            "domain": domain,
            "registrar": "Test Registrar Inc.",
            "registrant": "Test Owner",
            "organization": "Test Org",
            "creation_date": "2010-01-15T00:00:00Z",
            "expiration_date": "2028-01-15T00:00:00Z",
            "updated_date": "2024-06-01T00:00:00Z",
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "status": ["clientTransferProhibited", "clientDeleteProhibited"],
            "dnssec": "unsigned",
        },
    }
    base["data"].update(overrides)
    return base


def _status_data(http_status=200, ssl_valid=True):
    return {
        "http_status": http_status,
        "certificate": {
            "is_valid": ssl_valid,
            "days_until_expiry": 90,
            "valid_until": "2027-06-01T00:00:00Z",
        },
    }


def _a_records():
    return [{"data": {"address": "1.2.3.4"}}]


def _aaaa_records():
    return [{"data": {"address": "2001:db8::1"}}]


def _mx_records():
    return [{"data": {"exchange": "mail.example.com", "preference": 10}}]


def _ns_records():
    return [
        {"data": {"nameserver": "ns1.example.com."}},
        {"data": {"nameserver": "ns2.example.com."}},
    ]


def _txt_records_spf():
    return [{"data": {"text": "v=spf1 include:_spf.google.com -all"}}]


def _txt_records_dmarc():
    return [{"data": {"text": "v=DMARC1; p=reject; rua=mailto:d@example.com"}}]


def _soa_record():
    return [{"data": {"mname": "ns1.example.com", "serial": "2024060101"}}]


def _caa_records():
    return [{"data": {"tag": "issue", "value": "letsencrypt.org"}}]


def _ssl_report(valid=True, expiry="2027-06-01T00:00:00Z"):
    return {
        "is_valid": valid,
        "chain": [
            {
                "issuer": "CN=Let's Encrypt Authority X3",
                "subject": "CN=example.com",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": expiry,
                "key_type": "RSA",
                "key_bits": 2048,
            }
        ],
        "san_names": ["example.com", "www.example.com"],
        "protocol_version": "TLSv1.3",
    }


def _dnssec_data(enabled=True, valid=True):
    return {
        "enabled": enabled,
        "valid": valid,
        "ds_records": [{"keytag": 12345}],
        "dnskey_records": [{"flags": 257}],
        "issues": [] if valid else ["Signature expired"],
    }


def _bulk_result(data, success=True):
    """Wrap data in the BulkResult envelope seer.bulk_* returns."""
    return {
        "operation": {"domain": "test"},
        "success": success,
        "data": data,
        "error": None,
        "duration_ms": 42,
    }


def _dig_router(**overrides):
    """Return a side_effect function that routes seer.dig calls by record type.

    Pass record_type=return_value keyword args.  Unrecognised types return None.
    """
    mapping = overrides

    def _route(domain, rtype=None, *args, **kwargs):
        # Handle positional or keyword record type
        key = rtype or "A"
        # Handle _dmarc. prefix
        if domain.startswith("_dmarc."):
            key = "_dmarc.TXT"
        return mapping.get(key)

    return _route


# ===================================================================
# 1. appraise_domain
# ===================================================================

class TestAppraiseDomain:

    @patch("familiar.tools.advisor_tools.tome")
    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_structure(self, mock_seer, mock_tome):
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), AAAA=_aaaa_records(), MX=_mx_records(),
            NS=_ns_records(), TXT=_txt_records_spf(), CNAME=None,
            CAA=_caa_records(), SOA=_soa_record(),
        )
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.status.return_value = _status_data()
        mock_tome.tld_lookup.return_value = {"tld": "com", "type": "generic"}

        result = json.loads(appraise_domain.invoke({"domain": "Example.COM"}))

        assert result["domain"] == "example.com"  # normalized
        assert "name_analysis" in result
        assert "registration" in result
        assert "dns_footprint" in result
        assert "valuation_signals" in result
        assert "web_status" in result
        assert "tld_info" in result

    @patch("familiar.tools.advisor_tools.tome")
    @patch("familiar.tools.advisor_tools.seer")
    def test_valuation_signals_dns_email(self, mock_seer, mock_tome):
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), MX=_mx_records(), TXT=_txt_records_spf(),
        )
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.status.return_value = _status_data()
        mock_tome.tld_lookup.return_value = None

        result = json.loads(appraise_domain.invoke({"domain": "example.com"}))
        signals = result["valuation_signals"]

        assert signals["has_email_infrastructure"] is True
        assert signals["has_spf"] is True
        assert signals["has_ssl"] is True

    @patch("familiar.tools.advisor_tools.tome")
    @patch("familiar.tools.advisor_tools.seer")
    def test_all_none_returns_gracefully(self, mock_seer, mock_tome):
        mock_seer.dig.return_value = None
        mock_seer.lookup.return_value = None
        mock_seer.status.return_value = None
        mock_tome.tld_lookup.return_value = None

        result = json.loads(appraise_domain.invoke({"domain": "ghost.xyz"}))

        assert result["domain"] == "ghost.xyz"
        assert result["name_analysis"]["sld"] == "ghost"
        assert result["registration"] == {}
        assert result["dns_footprint"] == {}

    @patch("familiar.tools.advisor_tools.tome")
    @patch("familiar.tools.advisor_tools.seer")
    def test_domain_normalization_strip_whitespace(self, mock_seer, mock_tome):
        mock_seer.dig.return_value = None
        mock_seer.lookup.return_value = None
        mock_seer.status.return_value = None
        mock_tome.tld_lookup.return_value = None

        result = json.loads(appraise_domain.invoke({"domain": "  UPPER.COM  "}))
        assert result["domain"] == "upper.com"


# ===================================================================
# 2. plan_acquisition
# ===================================================================

class TestPlanAcquisition:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_registered_domain(self, mock_seer):
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.status.return_value = _status_data()
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), NS=_ns_records(), MX=_mx_records(),
        )

        result = json.loads(plan_acquisition.invoke({"domain": "example.com"}))

        assert result["domain"] == "example.com"
        assert result["acquisition_intel"]["is_registered"] is True
        assert result["acquisition_intel"]["registrar"] == "Test Registrar Inc."
        assert "acquisition_difficulty" in result
        assert isinstance(result["acquisition_difficulty"]["score"], int)
        assert result["acquisition_difficulty"]["score"] >= 0
        assert result["acquisition_difficulty"]["score"] <= 10

    @patch("familiar.tools.advisor_tools.seer")
    def test_unregistered_domain(self, mock_seer):
        # seer.lookup returns None for domains that don't exist;
        # _extract_registration(None) returns {}, which is falsy → is_registered=False
        mock_seer.lookup.return_value = None
        mock_seer.status.return_value = None
        mock_seer.dig.return_value = None

        result = json.loads(plan_acquisition.invoke({"domain": "available-domain.com"}))

        assert result["acquisition_intel"]["is_registered"] is False
        assert result["acquisition_difficulty"]["score"] == 0
        assert result["acquisition_difficulty"]["rating"] == "available"

    @patch("familiar.tools.advisor_tools.seer")
    def test_parking_indicators_redirect(self, mock_seer):
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.status.return_value = {"http_status": 301, "certificate": {"is_valid": False}}
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), NS=_ns_records(), MX=None,
        )

        result = json.loads(plan_acquisition.invoke({"domain": "parked.com"}))
        parking = result["acquisition_intel"]["parking_indicators"]

        assert "redirecting" in parking
        assert "no_email_configured" in parking

    @patch("familiar.tools.advisor_tools.seer")
    def test_domain_normalization(self, mock_seer):
        mock_seer.lookup.return_value = None
        mock_seer.status.return_value = None
        mock_seer.dig.return_value = None

        result = json.loads(plan_acquisition.invoke({"domain": "  TEST.COM  "}))
        assert result["domain"] == "test.com"


# ===================================================================
# 3. suggest_domains
# ===================================================================

class TestSuggestDomains:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_default_tlds(self, mock_seer):
        # All results come back as available
        mock_seer.bulk_lookup.return_value = [
            {"source": "available"} for _ in range(100)
        ]

        result = json.loads(suggest_domains.invoke({"brand": "acme"}))

        assert result["brand"] == "acme"
        assert result["tlds_checked"] == ["com", "net", "org", "io", "co", "ai", "dev", "app"]
        assert result["available_count"] > 0
        assert isinstance(result["available"], list)
        assert isinstance(result["taken"], list)
        assert isinstance(result["unknown"], list)

    @patch("familiar.tools.advisor_tools.seer")
    def test_with_keywords_and_custom_tlds(self, mock_seer):
        mock_seer.bulk_lookup.return_value = [
            {"source": "available"} for _ in range(100)
        ]

        result = json.loads(suggest_domains.invoke({
            "brand": "acme",
            "keywords": "cloud, api",
            "tlds": ".com, .io",
        }))

        assert result["keywords"] == ["cloud", "api"]
        assert result["tlds_checked"] == ["com", "io"]
        # Brand+keyword combos should be generated
        avail_domains = [e["domain"] for e in result["available"]]
        assert any("acmecloud" in d for d in avail_domains)
        assert any("acmeapi" in d for d in avail_domains)

    @patch("familiar.tools.advisor_tools.seer")
    def test_mixed_availability_results(self, mock_seer):
        mock_seer.bulk_lookup.return_value = [
            {"source": "whois", "data": {"domain": "acme.com"}},  # taken
            {"source": "available"},  # available
            None,  # unknown
        ] + [{"source": "available"}] * 97

        result = json.loads(suggest_domains.invoke({"brand": "acme"}))

        assert result["taken_count"] >= 1
        assert result["available_count"] >= 1
        assert result["unknown_count"] >= 1

    @patch("familiar.tools.advisor_tools.seer")
    def test_bulk_lookup_failure(self, mock_seer):
        mock_seer.bulk_lookup.side_effect = RuntimeError("API down")

        result = json.loads(suggest_domains.invoke({"brand": "fail"}))

        # All should be unknown since bulk_lookup failed
        assert result["unknown_count"] == result["total_checked"]


# ===================================================================
# 4. audit_portfolio
# ===================================================================

class TestAuditPortfolio:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_multiple_domains(self, mock_seer):
        domains = "example.com, test.org"
        lookup_data = _whois_lookup()
        status_data = _status_data()

        mock_seer.bulk_lookup.return_value = [
            _bulk_result(lookup_data),
            _bulk_result(lookup_data),
        ]
        mock_seer.bulk_status.return_value = [
            _bulk_result(status_data),
            _bulk_result(status_data),
        ]
        mock_seer.bulk_dig.side_effect = [
            # TXT
            [_bulk_result(_txt_records_spf()), _bulk_result(_txt_records_spf())],
            # MX
            [_bulk_result(_mx_records()), _bulk_result(_mx_records())],
            # NS
            [_bulk_result(_ns_records()), _bulk_result(_ns_records())],
            # DMARC
            [_bulk_result(_txt_records_dmarc()), _bulk_result(_txt_records_dmarc())],
        ]

        result = json.loads(audit_portfolio.invoke({"domains": domains}))

        assert result["portfolio_size"] == 2
        assert len(result["domains"]) == 2
        assert "summary" in result
        assert "registrar_diversity" in result["summary"]
        assert "expiry_warnings" in result["summary"]

    @patch("familiar.tools.advisor_tools.seer")
    def test_empty_domains_error(self, mock_seer):
        result = json.loads(audit_portfolio.invoke({"domains": ""}))
        assert "error" in result

    @patch("familiar.tools.advisor_tools.seer")
    def test_too_many_domains(self, mock_seer):
        domains = ", ".join([f"d{i}.com" for i in range(101)])
        result = json.loads(audit_portfolio.invoke({"domains": domains}))
        assert "error" in result
        assert "100" in result["error"]

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_bulk_none(self, mock_seer):
        mock_seer.bulk_lookup.return_value = None
        mock_seer.bulk_status.return_value = None
        mock_seer.bulk_dig.return_value = None

        result = json.loads(audit_portfolio.invoke({"domains": "a.com, b.com"}))

        assert result["portfolio_size"] == 2
        assert len(result["domains"]) == 2
        # Should not crash — domains just have no data


# ===================================================================
# 5. competitive_intel
# ===================================================================

class TestCompetitiveIntel:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_structure(self, mock_seer):
        mock_seer.bulk_lookup.return_value = [
            {"source": "whois", "data": {"domain": "competitor.net", "registrar": "Reg"}}
            for _ in range(10)
        ]
        mock_seer.dig.side_effect = _dig_router(
            NS=_ns_records(), MX=_mx_records(), A=_a_records(),
            AAAA=_aaaa_records(), TXT=_txt_records_spf(),
            CNAME=None, CAA=_caa_records(),
        )
        mock_seer.lookup.return_value = _whois_lookup("competitor.com")
        mock_seer.status.return_value = _status_data()

        result = json.loads(competitive_intel.invoke({"domain": "competitor.com"}))

        assert result["target"] == "competitor.com"
        assert "tld_variants" in result
        assert "infrastructure" in result
        assert "registration" in result
        assert "variants_registered" in result
        assert "variants_available" in result

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_variants_available(self, mock_seer):
        mock_seer.bulk_lookup.return_value = [
            {"source": "available"} for _ in range(10)
        ]
        mock_seer.dig.return_value = None
        mock_seer.lookup.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(competitive_intel.invoke({"domain": "unique-brand.com"}))

        assert result["variants_available"] > 0
        assert result["variants_registered"] == 0


# ===================================================================
# 6. migration_preflight
# ===================================================================

class TestMigrationPreflight:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_full_zone(self, mock_seer):
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), AAAA=_aaaa_records(), MX=_mx_records(),
            NS=_ns_records(), TXT=_txt_records_spf(), CNAME=None,
            CAA=_caa_records(), SRV=None, SOA=_soa_record(),
        )
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.status.return_value = _status_data()

        result = json.loads(migration_preflight.invoke({"domain": "example.com"}))

        assert result["domain"] == "example.com"
        assert "migration_checklist" in result
        assert "dns_snapshot" in result
        assert "registration" in result
        assert "warnings" in result
        assert isinstance(result["migration_checklist"], list)
        assert len(result["migration_checklist"]) > 0

    @patch("familiar.tools.advisor_tools.seer")
    def test_transfer_lock_detected(self, mock_seer):
        mock_seer.dig.side_effect = _dig_router(SOA=_soa_record())
        mock_seer.lookup.return_value = _whois_lookup()  # has clientTransferProhibited
        mock_seer.status.return_value = _status_data()

        result = json.loads(migration_preflight.invoke({"domain": "locked.com"}))

        lock_steps = [s for s in result["migration_checklist"] if s["step"] == "Domain lock"]
        assert len(lock_steps) == 1
        assert lock_steps[0]["status"] == "action_required"

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_none_graceful(self, mock_seer):
        mock_seer.dig.return_value = None
        mock_seer.lookup.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(migration_preflight.invoke({"domain": "offline.com"}))

        assert result["domain"] == "offline.com"
        assert result["dns_snapshot"] == {}


# ===================================================================
# 7. security_audit
# ===================================================================

class TestSecurityAudit:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_all_healthy(self, mock_seer):
        mock_seer.ssl.return_value = _ssl_report(valid=True)
        mock_seer.dnssec.return_value = _dnssec_data(enabled=True, valid=True)
        mock_seer.dig.side_effect = _dig_router(
            TXT=_txt_records_spf(),
            MX=_mx_records(),
            **{"_dmarc.TXT": _txt_records_dmarc()},
        )
        mock_seer.status.return_value = _status_data()

        result = json.loads(security_audit.invoke({"domain": "secure.com"}))

        assert result["domain"] == "secure.com"
        assert "ssl_health" in result
        assert "dnssec_status" in result
        assert "email_security" in result
        assert "http_security" in result
        assert "risk_score" in result
        assert "overall_risk" in result
        assert result["ssl_health"]["status"] == "healthy"
        assert result["risk_score"] == 0
        assert result["overall_risk"] == "low"

    @patch("familiar.tools.advisor_tools.seer")
    def test_risk_score_critical_ssl(self, mock_seer):
        mock_seer.ssl.return_value = _ssl_report(valid=False, expiry="2020-01-01T00:00:00Z")
        mock_seer.dnssec.return_value = _dnssec_data(enabled=False, valid=False)
        mock_seer.dig.side_effect = _dig_router(TXT=None, MX=_mx_records())
        mock_seer.status.return_value = _status_data(ssl_valid=False)

        result = json.loads(security_audit.invoke({"domain": "insecure.com"}))

        # SSL critical (+3), DNSSEC not_configured (+1), missing SPF (+2), missing DMARC (+2)
        assert result["risk_score"] >= 5
        assert result["overall_risk"] in ("critical", "high")
        assert result["ssl_health"]["status"] == "critical"

    @patch("familiar.tools.advisor_tools.seer")
    def test_ssl_none_returns_critical(self, mock_seer):
        mock_seer.ssl.return_value = None
        mock_seer.dnssec.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(security_audit.invoke({"domain": "down.com"}))

        assert result["ssl_health"]["status"] == "critical"
        assert result["ssl_health"]["error"] == "Could not retrieve SSL certificate"

    @patch("familiar.tools.advisor_tools.seer")
    def test_email_spf_policy_detection(self, mock_seer):
        mock_seer.ssl.return_value = _ssl_report()
        mock_seer.dnssec.return_value = _dnssec_data()
        spf_softfail = [{"data": {"text": "v=spf1 include:example.com ~all"}}]
        mock_seer.dig.side_effect = _dig_router(
            TXT=spf_softfail,
            MX=_mx_records(),
            **{"_dmarc.TXT": _txt_records_dmarc()},
        )
        mock_seer.status.return_value = _status_data()

        result = json.loads(security_audit.invoke({"domain": "softfail.com"}))

        assert result["email_security"]["spf"]["found"] is True
        assert result["email_security"]["spf"]["policy"] == "softfail"


# ===================================================================
# 8. brand_protection_scan
# ===================================================================

class TestBrandProtectionScan:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_structure(self, mock_seer):
        # availability checks return available
        mock_seer.availability.return_value = {"available": True}
        mock_seer.subdomains.return_value = {
            "subdomains": ["www.example.com", "api.example.com"],
        }

        result = json.loads(brand_protection_scan.invoke({
            "brand": "example",
            "primary_domain": "example.com",
        }))

        assert result["brand"] == "example"
        assert result["primary_domain"] == "example.com"
        assert "available_variants" in result
        assert "taken_variants" in result
        assert "tld_coverage" in result
        assert "subdomain_exposure" in result
        assert result["subdomain_exposure"]["count"] == 2

    @patch("familiar.tools.advisor_tools.seer")
    def test_taken_typosquat_detected(self, mock_seer):
        # First typo domain comes back as taken
        mock_seer.availability.return_value = {"available": False}
        mock_seer.subdomains.return_value = None

        result = json.loads(brand_protection_scan.invoke({
            "brand": "google",
            "primary_domain": "google.com",
        }))

        assert len(result["taken_variants"]) > 0

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_none_graceful(self, mock_seer):
        mock_seer.availability.return_value = None
        mock_seer.subdomains.return_value = None

        result = json.loads(brand_protection_scan.invoke({
            "brand": "test",
            "primary_domain": "test.com",
        }))

        # Should not crash; failed checks go to check_failed
        assert result["brand"] == "test"
        assert isinstance(result["check_failed"], list)


# ===================================================================
# 9. dns_health_check
# ===================================================================

class TestDnsHealthCheck:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_full_zone(self, mock_seer):
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), AAAA=_aaaa_records(), MX=_mx_records(),
            NS=_ns_records(), SOA=_soa_record(), TXT=_txt_records_spf(),
            CAA=_caa_records(),
        )
        mock_seer.propagation.return_value = {"consistent": True, "resolvers": 10}
        mock_seer.dns_compare.return_value = {"match": True}

        result = json.loads(dns_health_check.invoke({"domain": "healthy.com"}))

        assert result["domain"] == "healthy.com"
        assert "health_score" in result
        assert result["health_score"] > 0
        assert "records_found" in result
        assert "records_missing" in result
        assert "propagation_status" in result
        assert "recommendations" in result

    @patch("familiar.tools.advisor_tools.seer")
    def test_missing_records_flagged(self, mock_seer):
        # Only A record present
        mock_seer.dig.side_effect = _dig_router(A=_a_records())
        mock_seer.propagation.return_value = None
        mock_seer.dns_compare.return_value = None

        result = json.loads(dns_health_check.invoke({"domain": "sparse.com"}))

        assert "SOA" in result["records_missing"]
        assert len(result["recommendations"]) > 0
        # Score should be low since many records are missing
        assert result["health_score"] < 80

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_none_graceful(self, mock_seer):
        mock_seer.dig.return_value = None
        mock_seer.propagation.return_value = None

        result = json.loads(dns_health_check.invoke({"domain": "empty.com"}))

        assert result["domain"] == "empty.com"
        assert result["health_score"] == 0
        assert len(result["records_missing"]) == 7  # All essential types missing

    @patch("familiar.tools.advisor_tools.seer")
    def test_domain_normalization(self, mock_seer):
        mock_seer.dig.return_value = None
        mock_seer.propagation.return_value = None

        result = json.loads(dns_health_check.invoke({"domain": "  DNS.ORG  "}))
        assert result["domain"] == "dns.org"


# ===================================================================
# 10. domain_timeline
# ===================================================================

class TestDomainTimeline:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_events_sorted(self, mock_seer):
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.dig.side_effect = _dig_router(
            A=_a_records(), NS=_ns_records(),
        )
        mock_seer.ssl.return_value = _ssl_report()
        mock_seer.status.return_value = _status_data()

        result = json.loads(domain_timeline.invoke({"domain": "example.com"}))

        assert result["domain"] == "example.com"
        assert "timeline" in result
        assert "current_state" in result
        assert "registration" in result
        assert len(result["timeline"]) >= 2  # at least creation + expiry
        # Verify chronological sort
        dates = [e["date"] for e in result["timeline"]]
        assert dates == sorted(dates)

    @patch("familiar.tools.advisor_tools.seer")
    def test_ssl_events_included(self, mock_seer):
        mock_seer.lookup.return_value = _whois_lookup()
        mock_seer.dig.return_value = None
        mock_seer.ssl.return_value = _ssl_report()
        mock_seer.status.return_value = _status_data()

        result = json.loads(domain_timeline.invoke({"domain": "example.com"}))

        event_types = [e["event"] for e in result["timeline"]]
        assert "ssl_certificate_issued" in event_types
        assert "ssl_certificate_expires" in event_types

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_none_graceful(self, mock_seer):
        mock_seer.lookup.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.ssl.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(domain_timeline.invoke({"domain": "gone.com"}))

        assert result["domain"] == "gone.com"
        assert result["timeline"] == []

    @patch("familiar.tools.advisor_tools.seer")
    def test_domain_normalization(self, mock_seer):
        mock_seer.lookup.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.ssl.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(domain_timeline.invoke({"domain": "  TIMELINE.IO  "}))
        assert result["domain"] == "timeline.io"


# ===================================================================
# 11. expiration_alert
# ===================================================================

class TestExpirationAlert:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_provided_domains(self, mock_seer):
        mock_seer.bulk_lookup.return_value = [
            _whois_lookup("healthy.com"),
            _whois_lookup("expiring.com", expiration_date="2026-04-01T00:00:00Z"),
        ]

        result = json.loads(expiration_alert.invoke({"domains": "healthy.com, expiring.com"}))

        assert result["source"] == "provided"
        assert result["total_checked"] == 2
        assert "summary" in result
        assert "healthy" in result
        assert "critical" in result
        assert "warning" in result

    @patch("familiar.tools.advisor_tools.seer")
    def test_critical_expiration_detected(self, mock_seer):
        # Domain expiring in 3 days
        mock_seer.bulk_lookup.return_value = [
            _whois_lookup("urgent.com", expiration_date="2026-03-30T00:00:00Z"),
        ]

        result = json.loads(expiration_alert.invoke({"domains": "urgent.com"}))

        assert result["summary"]["critical"] == 1
        assert len(result["critical"]) == 1
        assert result["critical"][0]["domain"] == "urgent.com"

    @patch("familiar.tools.memory_tools.get_memory")
    @patch("familiar.tools.advisor_tools.seer")
    def test_empty_domains_no_watchlist(self, mock_seer, mock_get_memory):
        mock_get_memory.return_value.watchlist_list.return_value = []
        result = json.loads(expiration_alert.invoke({"domains": ""}))
        assert "error" in result
        assert result["source"] == "watchlist"

    @patch("familiar.tools.advisor_tools.seer")
    def test_bulk_lookup_failure(self, mock_seer):
        mock_seer.bulk_lookup.return_value = None

        result = json.loads(expiration_alert.invoke({"domains": "fail.com"}))

        assert result["total_checked"] == 1
        assert result["summary"]["unknown"] == 1


# ===================================================================
# 12. compare_security
# ===================================================================

class TestCompareSecurity:

    @patch("familiar.tools.advisor_tools.seer")
    def test_happy_path_both_domains(self, mock_seer):
        mock_seer.ssl.return_value = _ssl_report()
        mock_seer.dnssec.return_value = _dnssec_data()
        mock_seer.dig.side_effect = _dig_router(
            TXT=_txt_records_spf(),
            MX=_mx_records(),
            NS=_ns_records(),
            CAA=_caa_records(),
            A=_a_records(),
            CNAME=None,
            **{"_dmarc.TXT": _txt_records_dmarc()},
        )
        mock_seer.status.return_value = _status_data()

        result = json.loads(compare_security.invoke({
            "domain_a": "alpha.com",
            "domain_b": "beta.com",
        }))

        assert result["domain_a"] == "alpha.com"
        assert result["domain_b"] == "beta.com"
        assert "comparison" in result
        assert "scores" in result
        assert "tally" in result
        assert "winner" in result
        assert "alpha.com" in result["scores"]
        assert "beta.com" in result["scores"]
        # Both should have the same score since same mocks
        assert result["winner"] == "tie"

    @patch("familiar.tools.advisor_tools.seer")
    def test_one_domain_stronger(self, mock_seer):
        call_count = {"n": 0}

        def ssl_side_effect(domain):
            # First domain gets valid SSL, second gets None
            call_count["n"] += 1
            if "alpha" in domain:
                return _ssl_report(valid=True)
            return None

        def dnssec_side_effect(domain):
            if "alpha" in domain:
                return _dnssec_data(enabled=True, valid=True)
            return _dnssec_data(enabled=False, valid=False)

        def status_side_effect(domain):
            if "alpha" in domain:
                return _status_data(ssl_valid=True)
            return _status_data(ssl_valid=False)

        mock_seer.ssl.side_effect = ssl_side_effect
        mock_seer.dnssec.side_effect = dnssec_side_effect
        mock_seer.dig.side_effect = _dig_router(
            TXT=_txt_records_spf(), MX=_mx_records(),
            NS=_ns_records(), CAA=_caa_records(),
            A=_a_records(), CNAME=None,
            **{"_dmarc.TXT": _txt_records_dmarc()},
        )
        mock_seer.status.side_effect = status_side_effect

        result = json.loads(compare_security.invoke({
            "domain_a": "alpha.com",
            "domain_b": "beta.com",
        }))

        # alpha.com should have lower risk_score -> winner
        alpha_score = result["scores"]["alpha.com"]["risk_score"]
        beta_score = result["scores"]["beta.com"]["risk_score"]
        assert alpha_score < beta_score
        assert result["winner"] == "alpha.com"

    @patch("familiar.tools.advisor_tools.seer")
    def test_domain_normalization(self, mock_seer):
        mock_seer.ssl.return_value = None
        mock_seer.dnssec.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(compare_security.invoke({
            "domain_a": "  ALPHA.COM  ",
            "domain_b": "  BETA.COM  ",
        }))

        assert result["domain_a"] == "alpha.com"
        assert result["domain_b"] == "beta.com"

    @patch("familiar.tools.advisor_tools.seer")
    def test_all_none_no_crash(self, mock_seer):
        mock_seer.ssl.return_value = None
        mock_seer.dnssec.return_value = None
        mock_seer.dig.return_value = None
        mock_seer.status.return_value = None

        result = json.loads(compare_security.invoke({
            "domain_a": "down1.com",
            "domain_b": "down2.com",
        }))

        assert result["domain_a"] == "down1.com"
        assert result["domain_b"] == "down2.com"
        assert "comparison" in result
        # Both should have same high risk score
        assert result["winner"] == "tie"
