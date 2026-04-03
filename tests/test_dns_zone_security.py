"""Tests for dns_zone_security pentest tool.

Validates DNSSEC chain analysis, CAA certificate policy, nameserver delegation
consistency, SOA configuration review, zone transfer (ANY query) testing,
propagation consistency, risk scoring, and load-balance detection logic.
"""

import json
from unittest.mock import patch

import pytest

from familiar.tools.pentest_tools import dns_zone_security


# ---------------------------------------------------------------------------
# Helpers: reusable mock data builders
# ---------------------------------------------------------------------------

def _ns_records(*names):
    """Build NS record list."""
    return [{"data": {"nameserver": ns}} for ns in names]


def _soa_record(refresh=3600, retry=900, expire=1209600, minimum=3600):
    """Build a single-element SOA record list."""
    return [{"data": {
        "mname": "ns1.example.com",
        "rname": "admin.example.com",
        "serial": 2024010101,
        "refresh": refresh,
        "retry": retry,
        "expire": expire,
        "minimum": minimum,
    }}]


def _caa_records(tags):
    """Build CAA record list from tag tuples: [(tag, value), ...]."""
    return [{"data": {"tag": t, "value": v, "flags": 0}} for t, v in tags]


def _a_records(*ips):
    """Build A record list."""
    return [{"data": {"address": ip}} for ip in ips]


def _cname_records(*targets):
    """Build CNAME record list."""
    return [{"data": {"target": t}} for t in targets]


def _dnssec_data(enabled=True, status="healthy", has_ds=True, has_dnskey=True, issues=None):
    """Build DNSSEC response dict."""
    return {
        "enabled": enabled,
        "status": status,
        "has_ds_records": has_ds,
        "has_dnskey_records": has_dnskey,
        "ds_records": ["ds1"] if has_ds else [],
        "dnskey_records": ["key1"] if has_dnskey else [],
        "issues": issues or [],
    }


def _propagation_data(pct=100, inconsistencies=None, servers_checked=10, servers_responding=10):
    """Build propagation response dict."""
    return {
        "propagation_percentage": pct,
        "inconsistencies": inconsistencies or [],
        "servers_checked": servers_checked,
        "servers_responding": servers_responding,
    }


def _dns_compare_result(matches=True):
    """Build dns_compare response dict."""
    return {"matches": matches, "records_a": ["1.2.3.4"], "records_b": ["1.2.3.4"] if matches else ["5.6.7.8"]}


def _make_dig_side_effect(
    ns=None, soa=None, caa=None, a=None, cname=None, any_results=None,
):
    """Return a side_effect function for seer.dig that routes based on args.

    Parameters
    ----------
    any_results : dict | list | None
        If a dict, maps nameserver name -> result list for ANY queries.
        If a list, all ANY queries return the same list.
        If None, ANY queries return [].
    """
    def _side_effect(domain, rtype, *extra_args):
        # 3-arg form: dig(domain, "ANY", ns_name)
        if rtype == "ANY":
            if any_results is None:
                return []
            if isinstance(any_results, dict):
                ns_name = extra_args[0] if extra_args else None
                return any_results.get(ns_name, [])
            return any_results
        mapping = {
            "NS": ns,
            "SOA": soa,
            "CAA": caa,
            "A": a,
            "CNAME": cname,
        }
        return mapping.get(rtype)
    return _side_effect


# Default "healthy" baseline — DNSSEC valid, CAA complete, 2 NS, good SOA
_HEALTHY_NS = _ns_records("ns1.example.com", "ns2.example.com")
_HEALTHY_SOA = _soa_record()
_HEALTHY_CAA = _caa_records([("issue", "letsencrypt.org"), ("issuewild", ";"), ("iodef", "mailto:sec@example.com")])
_HEALTHY_A = _a_records("93.184.216.34")
_HEALTHY_DNSSEC = _dnssec_data(enabled=True, status="healthy")
_HEALTHY_PROPAGATION = _propagation_data(pct=100)


def _invoke(domain="example.com"):
    """Invoke the tool and parse the JSON result."""
    raw = dns_zone_security.invoke({"domain": domain})
    return json.loads(raw)


def _finding_severities(result):
    """Return list of severity strings from findings."""
    return [f["severity"] for f in result.get("findings", [])]


def _findings_by_severity(result, severity):
    """Return findings matching a given severity."""
    return [f for f in result.get("findings", []) if f["severity"] == severity]


def _findings_containing(result, substring):
    """Return findings whose 'finding' text contains substring (case-insensitive)."""
    return [f for f in result.get("findings", [])
            if substring.lower() in f.get("finding", "").lower()]


# ===================================================================
# DNSSEC Tests
# ===================================================================


class TestDnssec:
    """DNSSEC analysis and finding classification."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_dnssec_healthy(self, mock_seer):
        """1. DNSSEC enabled and valid => 'healthy' status, no DNSSEC findings."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _dnssec_data(enabled=True, status="healthy")
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["dnssec"]["status"] == "healthy"
        assert result["dnssec"]["enabled"] is True
        dnssec_findings = _findings_containing(result, "DNSSEC")
        assert len(dnssec_findings) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_dnssec_partial_chain(self, mock_seer):
        """2. DNSSEC enabled but partial => HIGH finding (incomplete chain)."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _dnssec_data(enabled=True, status="partial")
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        high = _findings_containing(result, "DNSSEC chain is incomplete")
        assert len(high) == 1
        assert high[0]["severity"] == "HIGH"

    @patch("familiar.tools.pentest_tools.seer")
    def test_dnssec_not_enabled(self, mock_seer):
        """3. DNSSEC not enabled => MEDIUM finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _dnssec_data(enabled=False, status="disabled", has_ds=False, has_dnskey=False)
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        medium = _findings_containing(result, "DNSSEC is not configured")
        assert len(medium) == 1
        assert medium[0]["severity"] == "MEDIUM"

    @patch("familiar.tools.pentest_tools.seer")
    def test_dnssec_none_graceful(self, mock_seer):
        """4. DNSSEC data None => unknown status, no crash."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = None
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["dnssec"]["status"] == "unknown"
        # No DNSSEC-specific findings when data is None — status is simply unknown
        dnssec_findings = _findings_containing(result, "DNSSEC")
        assert len(dnssec_findings) == 0


# ===================================================================
# CAA Policy Tests
# ===================================================================


class TestCaaPolicy:
    """CAA record analysis and policy gap detection."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_caa_complete(self, mock_seer):
        """5. CAA with issue + issuewild + iodef => all flags true, no CAA findings."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA,
            caa=_caa_records([("issue", "letsencrypt.org"), ("issuewild", ";"), ("iodef", "mailto:sec@x.com")]),
            a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["caa_policy"]["has_records"] is True
        assert len(result["caa_policy"]["policies"]) == 3
        caa_findings = _findings_containing(result, "CAA") + _findings_containing(result, "issuewild") + _findings_containing(result, "iodef")
        assert len(caa_findings) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_caa_no_issuewild(self, mock_seer):
        """6. CAA present but no issuewild => MEDIUM finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA,
            caa=_caa_records([("issue", "letsencrypt.org"), ("iodef", "mailto:sec@x.com")]),
            a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        findings = _findings_containing(result, "issuewild")
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    @patch("familiar.tools.pentest_tools.seer")
    def test_caa_no_iodef(self, mock_seer):
        """7. CAA present but no iodef => LOW finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA,
            caa=_caa_records([("issue", "letsencrypt.org"), ("issuewild", ";")]),
            a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        findings = _findings_containing(result, "iodef")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_caa_records(self, mock_seer):
        """8. No CAA records => MEDIUM finding (any CA can issue)."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=None, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["caa_policy"]["has_records"] is False
        findings = _findings_containing(result, "No CAA records")
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"


# ===================================================================
# Nameserver Tests
# ===================================================================


class TestNameservers:
    """Nameserver count, consistency, and delegation checks."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_single_ns_high_finding(self, mock_seer):
        """9. Single nameserver => HIGH finding (SPOF)."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_ns_records("ns1.example.com"), soa=_HEALTHY_SOA,
            caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION

        result = _invoke()
        findings = _findings_containing(result, "nameserver")
        high = [f for f in findings if f["severity"] == "HIGH" and "single point" in f["detail"].lower()]
        assert len(high) >= 1
        assert result["nameservers"]["count"] == 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_two_ns_no_spof_finding(self, mock_seer):
        """10. Two+ nameservers => no SPOF HIGH finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["nameservers"]["count"] == 2
        spof = [f for f in result["findings"] if "single point" in f.get("detail", "").lower()]
        assert len(spof) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_ns_consistent(self, mock_seer):
        """11. NS records consistent (dns_compare matches=true) => no inconsistency finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        inconsistent = _findings_containing(result, "inconsistent")
        assert len(inconsistent) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_ns_inconsistent_no_cdn(self, mock_seer):
        """12. NS records inconsistent without CDN => HIGH finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_a_records("93.184.216.34"),  # single A, no CDN
            cname=None,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=False)

        result = _invoke()
        inconsistent = _findings_containing(result, "inconsistent")
        assert len(inconsistent) >= 1
        assert inconsistent[0]["severity"] == "HIGH"

    @patch("familiar.tools.pentest_tools.seer")
    def test_ns_inconsistent_with_cdn(self, mock_seer):
        """13. NS records inconsistent WITH CDN => INFO finding (expected variance)."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_HEALTHY_A,
            cname=_cname_records("cdn.cloudflare.net"),
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=False)

        result = _invoke()
        info = [f for f in result["findings"]
                if f["severity"] == "INFO" and "intentional" in f["finding"].lower()]
        assert len(info) >= 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_ns_inconsistent_multi_a_roundrobin(self, mock_seer):
        """14. NS records inconsistent with multiple A records => INFO (round-robin detected)."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_a_records("1.2.3.4", "5.6.7.8"),
            cname=None,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=False)

        result = _invoke()
        info = [f for f in result["findings"]
                if f["severity"] == "INFO" and "intentional" in f["finding"].lower()]
        assert len(info) >= 1


# ===================================================================
# SOA Configuration Tests
# ===================================================================


class TestSoaConfiguration:
    """SOA record parameter validation."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_soa_retry_exceeds_refresh(self, mock_seer):
        """15. SOA retry > refresh => MEDIUM finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS,
            soa=_soa_record(refresh=900, retry=3600),  # retry > refresh
            caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        findings = _findings_containing(result, "retry interval exceeds refresh")
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    @patch("familiar.tools.pentest_tools.seer")
    def test_soa_low_expire(self, mock_seer):
        """16. SOA expire < 604800 => LOW finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS,
            soa=_soa_record(expire=86400),  # 1 day, well under 7
            caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        findings = _findings_containing(result, "expire value is low")
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"

    @patch("familiar.tools.pentest_tools.seer")
    def test_soa_normal_values(self, mock_seer):
        """17. Normal SOA values => no SOA findings."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        soa_findings = _findings_containing(result, "SOA")
        assert len(soa_findings) == 0


# ===================================================================
# Zone Transfer / ANY Query Tests
# ===================================================================


class TestZoneTransfer:
    """ANY query enumeration and RFC 8482 compliance."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_any_large_response(self, mock_seer):
        """18. ANY query returns >15 records => LOW finding (RFC 8482 non-compliant)."""
        big_any = [{"data": {"address": f"1.2.3.{i}"}} for i in range(20)]
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_ns_records("ns1.example.com"),
            soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
            any_results={"ns1.example.com": big_any},
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION

        result = _invoke()
        findings = _findings_containing(result, "RFC 8482")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "LOW"
        # Verify zone_transfer results captured
        zt = result["zone_transfer"]
        assert zt["tested"] is True
        permissive = [r for r in zt["results"] if r["status"] == "permissive_any"]
        assert len(permissive) == 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_any_small_response(self, mock_seer):
        """19. ANY query returns <=15 records => no finding."""
        small_any = [{"data": {"address": f"1.2.3.{i}"}} for i in range(5)]
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_ns_records("ns1.example.com"),
            soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
            any_results={"ns1.example.com": small_any},
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION

        result = _invoke()
        findings = _findings_containing(result, "RFC 8482")
        assert len(findings) == 0
        compliant = [r for r in result["zone_transfer"]["results"] if r["status"] == "rfc8482_compliant"]
        assert len(compliant) == 1


# ===================================================================
# Propagation Tests
# ===================================================================


class TestPropagation:
    """DNS propagation consistency analysis."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_full_propagation(self, mock_seer):
        """20. 100% propagation => no propagation finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _propagation_data(pct=100)
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        prop_findings = _findings_containing(result, "propagation")
        assert len(prop_findings) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_partial_propagation_no_cdn(self, mock_seer):
        """21. <100% propagation without CDN => MEDIUM finding."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_a_records("93.184.216.34"),
            cname=None,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _propagation_data(
            pct=80, inconsistencies=["resolver1", "resolver2"],
        )
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        prop_findings = _findings_containing(result, "propagation")
        assert len(prop_findings) >= 1
        assert prop_findings[0]["severity"] == "MEDIUM"

    @patch("familiar.tools.pentest_tools.seer")
    def test_partial_propagation_with_cdn(self, mock_seer):
        """22. <100% propagation WITH CDN => INFO finding (expected variance)."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_HEALTHY_A,
            cname=_cname_records("cdn.cloudflare.net"),
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _propagation_data(
            pct=85, inconsistencies=["resolver1"],
        )
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        prop_findings = _findings_containing(result, "propagation")
        assert len(prop_findings) >= 1
        assert prop_findings[0]["severity"] == "INFO"


# ===================================================================
# Risk Score Tests
# ===================================================================


class TestRiskScore:
    """Overall risk classification from accumulated risk_score."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_critical_risk(self, mock_seer):
        """23. risk_score >= 6 => 'critical'."""
        # Accumulate risk: no DNSSEC (+1), no CAA (+1), single NS (+2),
        # partial DNSSEC issues (+2 for two issues) = 6
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_ns_records("ns1.example.com"),  # single NS => +2
            soa=_HEALTHY_SOA, caa=None,  # no CAA => +1
            a=_a_records("93.184.216.34"), cname=None,
        )
        mock_seer.dnssec.return_value = _dnssec_data(
            enabled=True, status="partial",  # partial => +2
            issues=["expired RRSIG"],  # +1 per issue
        )
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION

        result = _invoke()
        assert result["risk_score"] >= 6
        assert result["overall_risk"] == "critical"

    @patch("familiar.tools.pentest_tools.seer")
    def test_high_risk(self, mock_seer):
        """24. risk_score >= 4 => 'high'."""
        # partial DNSSEC (+2) + no CAA (+1) + DNSSEC issue (+1) = 4
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=None,
            a=_a_records("93.184.216.34"), cname=None,
        )
        mock_seer.dnssec.return_value = _dnssec_data(
            enabled=True, status="partial", issues=["weak algorithm"],
        )
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["risk_score"] >= 4
        assert result["overall_risk"] == "high"

    @patch("familiar.tools.pentest_tools.seer")
    def test_medium_risk(self, mock_seer):
        """25. risk_score >= 2 => 'medium'."""
        # no DNSSEC (+1) + no CAA (+1) = 2
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=None,
            a=_HEALTHY_A, cname=None,
        )
        mock_seer.dnssec.return_value = _dnssec_data(enabled=False, status="disabled", has_ds=False, has_dnskey=False)
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["risk_score"] >= 2
        assert result["overall_risk"] == "medium"

    @patch("familiar.tools.pentest_tools.seer")
    def test_low_risk(self, mock_seer):
        """26. risk_score < 2 => 'low'."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["risk_score"] < 2
        assert result["overall_risk"] == "low"

    @patch("familiar.tools.pentest_tools.seer")
    def test_healthy_zone_low_risk(self, mock_seer):
        """27. Healthy zone (DNSSEC valid, CAA, 2+ NS, consistent) => 'low'."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = _invoke()
        assert result["overall_risk"] == "low"
        assert result["risk_score"] == 0
        assert result["dnssec"]["status"] == "healthy"
        assert result["caa_policy"]["has_records"] is True
        assert result["nameservers"]["count"] == 2
        assert len(result["findings"]) == 0


# ===================================================================
# Edge Cases
# ===================================================================


class TestEdgeCases:
    """Graceful handling of missing or unusual data."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_all_seer_calls_none(self, mock_seer):
        """28. All seer calls return None => graceful handling, no crash."""
        mock_seer.dig.return_value = None
        mock_seer.dnssec.return_value = None
        mock_seer.propagation.return_value = None
        mock_seer.dns_compare.return_value = None

        result = _invoke()
        assert result["domain"] == "example.com"
        assert result["overall_risk"] in ("low", "medium", "high", "critical")
        # Should have at least the "no CAA" finding since caa_records is None
        assert result["caa_policy"]["has_records"] is False

    @patch("familiar.tools.pentest_tools.seer")
    def test_empty_ns_no_zone_transfer(self, mock_seer):
        """29. Empty NS list => zone_transfer not tested."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=None, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION

        result = _invoke()
        assert result["zone_transfer"]["tested"] is False
        assert result["nameservers"]["count"] == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_normalization(self, mock_seer):
        """30. Domain with uppercase and whitespace is normalized."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA, a=_HEALTHY_A,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=True)

        result = json.loads(dns_zone_security.invoke({"domain": "  EXAMPLE.COM  "}))
        assert result["domain"] == "example.com"


# ===================================================================
# Load-Balance Detection Tests
# ===================================================================


class TestLoadBalanceDetection:
    """CDN, GeoDNS, and round-robin detection for mismatch triage."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_cdn_via_cname_cloudflare(self, mock_seer):
        """31. CDN via CNAME (cloudflare.net) => inconsistency downgraded to INFO."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_HEALTHY_A,
            cname=_cname_records("proxy.cloudflare.net"),
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _propagation_data(
            pct=90, inconsistencies=["resolver1"],
        )
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=False)

        result = _invoke()
        # NS inconsistency should be INFO, not HIGH
        ns_mismatch = [f for f in result["findings"]
                       if "different a records" in f.get("finding", "").lower()
                       or "inconsistent" in f.get("finding", "").lower()]
        for f in ns_mismatch:
            assert f["severity"] == "INFO", f"Expected INFO but got {f['severity']} for: {f['finding']}"
        # Propagation should also be INFO
        prop_findings = _findings_containing(result, "propagation")
        for f in prop_findings:
            assert f["severity"] == "INFO"

    @patch("familiar.tools.pentest_tools.seer")
    def test_geodns_provider_awsdns(self, mock_seer):
        """32. GeoDNS NS provider (awsdns) => inconsistency downgraded to INFO."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_ns_records("ns-123.awsdns-45.com", "ns-678.awsdns-90.org"),
            soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_a_records("93.184.216.34"),  # single A, non-CDN IP
            cname=None,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=False)

        result = _invoke()
        ns_mismatch = [f for f in result["findings"]
                       if "different a records" in f.get("finding", "").lower()
                       or "inconsistent" in f.get("finding", "").lower()]
        for f in ns_mismatch:
            assert f["severity"] == "INFO"

    @patch("familiar.tools.pentest_tools.seer")
    def test_multi_a_records_roundrobin(self, mock_seer):
        """33. Multiple A records (round-robin) => inconsistency downgraded to INFO."""
        mock_seer.dig.side_effect = _make_dig_side_effect(
            ns=_HEALTHY_NS, soa=_HEALTHY_SOA, caa=_HEALTHY_CAA,
            a=_a_records("1.2.3.4", "5.6.7.8", "9.10.11.12"),
            cname=None,
        )
        mock_seer.dnssec.return_value = _HEALTHY_DNSSEC
        mock_seer.propagation.return_value = _HEALTHY_PROPAGATION
        mock_seer.dns_compare.return_value = _dns_compare_result(matches=False)

        result = _invoke()
        ns_mismatch = [f for f in result["findings"]
                       if "different a records" in f.get("finding", "").lower()
                       or "inconsistent" in f.get("finding", "").lower()]
        for f in ns_mismatch:
            assert f["severity"] == "INFO"
        # Verify detail mentions round-robin
        info_detail = [f for f in ns_mismatch if "round-robin" in f.get("detail", "").lower()]
        assert len(info_detail) >= 1
