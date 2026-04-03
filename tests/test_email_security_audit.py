"""Comprehensive tests for email_security_audit in familiar.tools.pentest_tools.

Covers SPF analysis (qualifiers, mechanisms, lookup limits, multiples), DMARC
analysis (policies, reporting, alignment, pct), DKIM selector probing, MX
provider detection, risk scoring, overall ratings, and edge cases.
"""

import json
from unittest.mock import patch

from familiar.tools.pentest_tools import _DKIM_SELECTORS, email_security_audit

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN = "test.com"


def _make_txt(text: str) -> list[dict]:
    """Return a single-record TXT response list."""
    return [{"data": {"text": text}}]


def _make_mx(*exchanges: str) -> list[dict]:
    """Return an MX response list with the given exchange hostnames."""
    return [{"data": {"exchange": ex}} for ex in exchanges]


def _build_dig_side_effect(
    *,
    spf: str | list[str] | None = None,
    mx: list[dict] | None = None,
    dmarc: str | None = None,
    dkim_selectors: dict[str, str] | None = None,
    domain: str = DOMAIN,
):
    """Build a side_effect function for seer.dig that routes by domain and record type.

    Parameters
    ----------
    spf : str or list[str] or None
        SPF record text(s). If a list, multiple TXT records are returned.
    mx : list[dict] or None
        Pre-built MX record list (use _make_mx()).
    dmarc : str or None
        DMARC record text.
    dkim_selectors : dict[str, str] or None
        Mapping of selector name -> DKIM record text for selectors that should
        return a record.  All other selectors return [].
    domain : str
        The base domain.
    """
    dkim_selectors = dkim_selectors or {}

    def side_effect(query_domain, record_type, *args):
        if record_type == "TXT" and query_domain == domain:
            if spf is None:
                return []
            if isinstance(spf, list):
                return [{"data": {"text": s}} for s in spf]
            return _make_txt(spf)
        if record_type == "MX" and query_domain == domain:
            return mx if mx is not None else []
        if record_type == "TXT" and query_domain == f"_dmarc.{domain}":
            if dmarc is None:
                return []
            return _make_txt(dmarc)
        if record_type == "TXT" and "_domainkey" in query_domain:
            for sel, txt in dkim_selectors.items():
                if f"{sel}._domainkey.{domain}" == query_domain:
                    return _make_txt(txt)
            return []
        return []

    return side_effect


def _invoke(domain: str = DOMAIN) -> dict:
    """Invoke email_security_audit and return parsed JSON."""
    raw = email_security_audit.invoke({"domain": domain})
    return json.loads(raw)


def _find_findings(result: dict, *, severity: str | None = None, substr: str | None = None) -> list[dict]:
    """Filter findings by severity and/or substring in finding text."""
    findings = result.get("findings", [])
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if substr:
        findings = [f for f in findings if substr.lower() in f["finding"].lower()]
    return findings


# ===========================================================================
# SPF Analysis
# ===========================================================================


class TestSpfStrict:
    """Test 1: Strict SPF (-all) -> 'fail (strict)', no softfail note."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_strict_all_qualifier(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 include:_spf.google.com -all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "fail (strict)"
        # No softfail LOW finding
        softfail = _find_findings(result, severity="LOW", substr="softfail")
        assert len(softfail) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_strict_spf_no_penalty(self, mock_seer):
        """Strict -all should not add to risk_score for the all mechanism."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        # No finding about the all qualifier
        all_findings = _find_findings(result, substr="all")
        spf_all_findings = [f for f in all_findings if "spf" in f["finding"].lower() and "all" in f["finding"].lower()]
        assert len(spf_all_findings) == 0


class TestSpfSoftfail:
    """Test 2: Softfail SPF (~all) -> 'softfail', LOW finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_softfail_qualifier(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 include:_spf.google.com ~all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "softfail"
        low = _find_findings(result, severity="LOW", substr="softfail")
        assert len(low) == 1


class TestSpfNeutral:
    """Test 3: Neutral SPF (?all) -> 'neutral (weak)', HIGH finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_neutral_qualifier(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 include:_spf.google.com ?all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "neutral (weak)"
        high = _find_findings(result, severity="HIGH", substr="neutral")
        assert len(high) == 1


class TestSpfPermissive:
    """Test 4: Permissive SPF (+all) -> CRITICAL, risk_score += 4."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_plus_all_critical(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 +all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "pass (INSECURE — allows any sender)"
        crit = _find_findings(result, severity="CRITICAL", substr="+all")
        assert len(crit) == 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_plus_all_adds_4_to_risk(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 +all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        # +all contributes 4 to risk_score
        assert result["risk_score"] >= 4


class TestSpfBareAll:
    """Test 5: Bare 'all' (no qualifier) -> same as +all per RFC 7208."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_bare_all_treated_as_plus_all(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "pass (INSECURE — allows any sender)"
        crit = _find_findings(result, severity="CRITICAL", substr="allows anyone")
        assert len(crit) == 1


class TestSpfMissingAll:
    """Test 6: SPF with no 'all' mechanism -> 'missing', HIGH finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_missing_all_qualifier(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 include:_spf.google.com",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "missing"
        high = _find_findings(result, severity="HIGH", substr="no 'all' mechanism")
        assert len(high) == 1


class TestSpfRedirect:
    """Test 7: SPF with redirect= -> 'redirect', no missing complaint."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_redirect_qualifier(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 redirect=_spf.example.com",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["all_qualifier"] == "redirect"
        # No "missing" complaint
        missing_findings = _find_findings(result, substr="no 'all' mechanism")
        assert len(missing_findings) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_redirect_counts_as_lookup(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 redirect=_spf.example.com",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["dns_lookup_count"] >= 1
        redirect_mechs = [m for m in result["spf"]["mechanisms"] if m["type"] == "redirect"]
        assert len(redirect_mechs) == 1
        assert redirect_mechs[0]["dns_lookup"] is True


class TestSpfLookupLimit:
    """Test 8: SPF lookup count > 10 -> HIGH finding about RFC 7208 limit."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_exceeds_10_lookups(self, mock_seer):
        # Build an SPF with 11 include mechanisms
        includes = " ".join(f"include:_spf{i}.example.com" for i in range(11))
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=f"v=spf1 {includes} -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["lookup_limit_exceeded"] is True
        assert result["spf"]["dns_lookup_count"] == 11
        high = _find_findings(result, severity="HIGH", substr="10-lookup limit")
        assert len(high) == 1

    @patch("familiar.tools.pentest_tools.seer")
    def test_exactly_10_lookups_ok(self, mock_seer):
        includes = " ".join(f"include:_spf{i}.example.com" for i in range(10))
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=f"v=spf1 {includes} -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["lookup_limit_exceeded"] is False
        assert result["spf"]["dns_lookup_count"] == 10
        high = _find_findings(result, severity="HIGH", substr="10-lookup limit")
        assert len(high) == 0


class TestSpfMultipleRecords:
    """Test 9: Multiple SPF records -> HIGH finding (PermError)."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_multiple_spf_records(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=["v=spf1 include:a.com -all", "v=spf1 include:b.com -all"],
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        high = _find_findings(result, severity="HIGH", substr="Multiple SPF")
        assert len(high) == 1
        assert "PermError" in high[0]["detail"]


class TestSpfMissingWithMx:
    """Test 10: No SPF record with MX -> CRITICAL (anyone can spoof)."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_spf_with_mx_critical(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=None,
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        crit = _find_findings(result, severity="CRITICAL", substr="No SPF record")
        assert len(crit) == 1


class TestSpfMissingWithoutMx:
    """Test 11: No SPF without MX -> no CRITICAL (mail-less domain)."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_spf_no_mx_no_critical(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=None,
            mx=None,
            dmarc=None,
        )
        result = _invoke()
        crit = _find_findings(result, severity="CRITICAL", substr="No SPF record")
        assert len(crit) == 0


class TestSpfMechanismParsing:
    """Test 12: SPF mechanisms parsed: include, ip4, ip6, a, mx, ptr, exists, redirect."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_all_mechanism_types(self, mock_seer):
        spf = (
            "v=spf1 include:_spf.google.com ip4:192.168.1.0/24 ip6:2001:db8::/32 "
            "a mx ptr:mail.test.com exists:%{i}.bl.test.com redirect=_spf.other.com"
        )
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=spf,
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        mechs = result["spf"]["mechanisms"]
        types = {m["type"] for m in mechs}
        assert "include" in types
        assert "ip4" in types
        assert "ip6" in types
        assert "a" in types
        assert "mx" in types
        assert "ptr" in types
        assert "exists" in types
        assert "redirect" in types

    @patch("familiar.tools.pentest_tools.seer")
    def test_dns_lookup_flags(self, mock_seer):
        """Mechanisms that require DNS lookups should have dns_lookup=True."""
        spf = (
            "v=spf1 include:_spf.google.com ip4:1.2.3.4 a mx "
            "ptr:mail.test.com exists:%{i}.bl.test.com -all"
        )
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=spf,
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        mechs = result["spf"]["mechanisms"]
        for m in mechs:
            if m["type"] in ("include", "a", "mx", "ptr", "exists", "redirect"):
                assert m["dns_lookup"] is True, f"{m['type']} should require DNS lookup"
            elif m["type"] in ("ip4", "ip6", "all"):
                assert m["dns_lookup"] is False, f"{m['type']} should not require DNS lookup"

    @patch("familiar.tools.pentest_tools.seer")
    def test_bare_a_and_mx_are_lookups(self, mock_seer):
        """Bare 'a' and 'mx' (no arguments) are still DNS lookups per RFC 7208."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 a mx -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["dns_lookup_count"] == 2
        mechs = result["spf"]["mechanisms"]
        a_mech = [m for m in mechs if m["type"] == "a"]
        mx_mech = [m for m in mechs if m["type"] == "mx"]
        assert len(a_mech) == 1 and a_mech[0]["dns_lookup"] is True
        assert len(mx_mech) == 1 and mx_mech[0]["dns_lookup"] is True

    @patch("familiar.tools.pentest_tools.seer")
    def test_a_with_argument_is_lookup(self, mock_seer):
        """'a:other.com' is a DNS lookup."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 a:other.com mx:other.com -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["spf"]["dns_lookup_count"] == 2


# ===========================================================================
# DMARC Analysis
# ===========================================================================


class TestDmarcReject:
    """Test 13: DMARC policy=reject -> strongest, no HIGH finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_reject_policy_no_high(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["policy"] == "reject"
        # No policy-related HIGH finding
        policy_high = _find_findings(result, severity="HIGH", substr="policy")
        assert len(policy_high) == 0


class TestDmarcQuarantine:
    """Test 14: DMARC policy=quarantine -> LOW finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_quarantine_low_finding(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=quarantine; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["policy"] == "quarantine"
        low = _find_findings(result, severity="LOW", substr="quarantine")
        assert len(low) == 1


class TestDmarcNone:
    """Test 15: DMARC policy=none -> HIGH finding (monitoring only)."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_none_policy_high(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=none; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["policy"] == "none"
        high = _find_findings(result, severity="HIGH", substr="monitoring only")
        assert len(high) == 1


class TestDmarcMissingWithMx:
    """Test 16: DMARC missing with MX -> CRITICAL."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_dmarc_with_mx_critical(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc=None,
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["found"] is False
        crit = _find_findings(result, severity="CRITICAL", substr="No DMARC record")
        assert len(crit) == 1


class TestDmarcMissingWithoutMx:
    """Test 17: DMARC missing without MX -> no CRITICAL."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_dmarc_no_mx_no_critical(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=None,
            mx=None,
            dmarc=None,
        )
        result = _invoke()
        assert result["dmarc"]["found"] is False
        crit = _find_findings(result, severity="CRITICAL", substr="No DMARC record")
        assert len(crit) == 0


class TestDmarcReporting:
    """Tests 18-19: DMARC rua reporting presence/absence."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_rua_present_no_finding(self, mock_seer):
        """Test 18: DMARC with rua -> no 'missing reporting' finding."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["aggregate_reports"] == "mailto:d@test.com"
        reporting_findings = _find_findings(result, substr="reporting")
        assert len(reporting_findings) == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_rua_absent_medium_finding(self, mock_seer):
        """Test 19: DMARC without rua -> MEDIUM finding."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["aggregate_reports"] == "not configured"
        medium = _find_findings(result, severity="MEDIUM", substr="reporting")
        assert len(medium) == 1


class TestDmarcPct:
    """Test 20: DMARC pct != 100 -> MEDIUM finding about partial enforcement."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_pct_50_medium_finding(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; pct=50; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["percentage"] == "50"
        medium = _find_findings(result, severity="MEDIUM", substr="50%")
        assert len(medium) == 1
        assert "50%" in medium[0]["detail"] or "50%" in medium[0]["finding"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_pct_100_no_finding(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; pct=100; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        medium = _find_findings(result, severity="MEDIUM", substr="% of messages")
        assert len(medium) == 0


class TestDmarcAlignment:
    """Test 21: DMARC alignment modes parsed (adkim, aspf)."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_strict_alignment(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["dkim_alignment"] == "strict"
        assert result["dmarc"]["spf_alignment"] == "strict"

    @patch("familiar.tools.pentest_tools.seer")
    def test_relaxed_alignment_default(self, mock_seer):
        """When adkim/aspf are not set, default to relaxed."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["dkim_alignment"] == "relaxed"
        assert result["dmarc"]["spf_alignment"] == "relaxed"

    @patch("familiar.tools.pentest_tools.seer")
    def test_subdomain_policy(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["dmarc"]["subdomain_policy"] == "quarantine"


# ===========================================================================
# DKIM Analysis
# ===========================================================================


class TestDkimFound:
    """Test 22: DKIM found for 'google' selector -> captured in results."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_google_selector_found(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"},
        )
        result = _invoke()
        assert result["dkim"]["selectors_found"] >= 1
        selectors = [r["selector"] for r in result["dkim"]["results"]]
        assert "google" in selectors


class TestDkimMissingWithMx:
    """Test 23: No DKIM found with MX -> HIGH finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_dkim_with_mx_high(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={},  # No DKIM found
        )
        result = _invoke()
        assert result["dkim"]["selectors_found"] == 0
        high = _find_findings(result, severity="HIGH", substr="No DKIM")
        assert len(high) == 1


class TestDkimMissingWithoutMx:
    """Test 24: No DKIM found without MX -> no HIGH finding."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_dkim_no_mx_no_finding(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=None,
            mx=None,
            dmarc=None,
            dkim_selectors={},
        )
        result = _invoke()
        assert result["dkim"]["selectors_found"] == 0
        high = _find_findings(result, severity="HIGH", substr="No DKIM")
        assert len(high) == 0


class TestDkimMultipleSelectors:
    """Test 25: Multiple DKIM selectors found -> all captured."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_multiple_selectors(self, mock_seer):
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={
                "google": "v=DKIM1; k=rsa; p=MIGfMA0...",
                "selector1": "v=DKIM1; k=rsa; p=ABCDE...",
                "default": "v=DKIM1; k=rsa; p=ZYXWV...",
            },
        )
        result = _invoke()
        assert result["dkim"]["selectors_found"] == 3
        selectors = {r["selector"] for r in result["dkim"]["results"]}
        assert selectors == {"google", "selector1", "default"}

    @patch("familiar.tools.pentest_tools.seer")
    def test_dkim_selectors_probed_count(self, mock_seer):
        """The probed count should match the total number of DKIM selectors."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
        )
        result = _invoke()
        assert result["dkim"]["selectors_probed"] == len(_DKIM_SELECTORS)


# ===========================================================================
# MX Provider Detection
# ===========================================================================


class TestMxProviderDetection:
    """Tests 26-29: MX provider identification."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_google_workspace(self, mock_seer):
        """Test 26: Google MX -> 'Google Workspace'."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("aspmx.l.google.com", "alt1.aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["mx"]["has_mx"] is True
        assert "Google Workspace" in result["mx"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_microsoft_365(self, mock_seer):
        """Test 27: Microsoft MX -> 'Microsoft 365'."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("test-com.mail.protection.outlook.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"selector1": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["mx"]["has_mx"] is True
        assert "Microsoft 365" in result["mx"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_proton_mail(self, mock_seer):
        """Test 28: Proton MX -> 'Proton Mail'."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mail.protonmail.ch"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"protonmail": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["mx"]["has_mx"] is True
        assert "Proton Mail" in result["mx"]["providers"]

    @patch("familiar.tools.pentest_tools.seer")
    def test_no_mx_records(self, mock_seer):
        """Test 29: No MX records -> has_mx: false."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=None,
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
        )
        result = _invoke()
        assert result["mx"]["has_mx"] is False
        assert result["mx"]["records"] == []
        assert result["mx"]["providers"] == []


# ===========================================================================
# Risk Score and Overall Rating
# ===========================================================================


class TestRiskScoreRatings:
    """Tests 30-34: Overall risk rating thresholds."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_critical_risk(self, mock_seer):
        """Test 30: risk_score >= 6 -> overall_risk: 'critical'."""
        # +all (4) + no DMARC with MX (3) = 7 => critical
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 +all",
            mx=_make_mx("mx.test.com"),
            dmarc=None,
        )
        result = _invoke()
        assert result["risk_score"] >= 6
        assert result["overall_risk"] == "critical"

    @patch("familiar.tools.pentest_tools.seer")
    def test_high_risk(self, mock_seer):
        """Test 31: risk_score >= 4 -> overall_risk: 'high'."""
        # +all (4) with good DMARC => risk_score = 4
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 +all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["risk_score"] >= 4
        assert result["overall_risk"] in ("high", "critical")

    @patch("familiar.tools.pentest_tools.seer")
    def test_medium_risk(self, mock_seer):
        """Test 32: risk_score >= 2 -> overall_risk: 'medium'."""
        # ?all (2) with good DMARC => risk_score = 2
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 ?all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["risk_score"] >= 2
        assert result["overall_risk"] == "medium"

    @patch("familiar.tools.pentest_tools.seer")
    def test_low_risk(self, mock_seer):
        """Test 33: risk_score < 2 -> overall_risk: 'low'."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = _invoke()
        assert result["risk_score"] < 2
        assert result["overall_risk"] == "low"

    @patch("familiar.tools.pentest_tools.seer")
    def test_healthy_domain_low_risk(self, mock_seer):
        """Test 34: Fully healthy domain (reject + strict SPF + DKIM) -> 'low'."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 include:_spf.google.com -all",
            mx=_make_mx("aspmx.l.google.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com; adkim=s; aspf=s",
            dkim_selectors={
                "google": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
            },
        )
        result = _invoke()
        assert result["overall_risk"] == "low"
        assert result["risk_score"] == 0
        assert result["spf"]["all_qualifier"] == "fail (strict)"
        assert result["dmarc"]["policy"] == "reject"
        assert result["dkim"]["selectors_found"] >= 1
        assert len(result["findings"]) == 0


# ===========================================================================
# Edge Cases
# ===========================================================================


class TestEdgeCases:
    """Tests 35-37: Graceful handling of None, empty, and malformed inputs."""

    @patch("familiar.tools.pentest_tools.seer")
    def test_all_seer_calls_return_none(self, mock_seer):
        """Test 35: All seer calls return None -> graceful handling."""
        mock_seer.dig.return_value = None
        result = _invoke()
        # Should not crash
        assert result["domain"] == DOMAIN
        assert result["overall_risk"] in ("low", "medium", "high", "critical")
        assert result["mx"]["has_mx"] is False
        assert result["spf"]["found"] is False
        assert result["dmarc"]["found"] is False
        assert result["dkim"]["selectors_found"] == 0

    @patch("familiar.tools.pentest_tools.seer")
    def test_empty_txt_records(self, mock_seer):
        """Test 36: Empty TXT records -> no crash."""
        def side_effect(query_domain, record_type, *args):
            if record_type == "TXT" and query_domain == DOMAIN:
                return [{"data": {"text": ""}}]
            if record_type == "MX":
                return _make_mx("mx.test.com")
            if record_type == "TXT" and query_domain == f"_dmarc.{DOMAIN}":
                return [{"data": {"text": ""}}]
            return []

        mock_seer.dig.side_effect = side_effect
        result = _invoke()
        assert result["domain"] == DOMAIN
        assert result["spf"]["found"] is False

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_normalization_uppercase(self, mock_seer):
        """Test 37a: Uppercase domain is normalized to lowercase."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = json.loads(email_security_audit.invoke({"domain": "TEST.COM"}))
        assert result["domain"] == "test.com"

    @patch("familiar.tools.pentest_tools.seer")
    def test_domain_normalization_whitespace(self, mock_seer):
        """Test 37b: Whitespace-padded domain is trimmed."""
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf="v=spf1 -all",
            mx=_make_mx("mx.test.com"),
            dmarc="v=DMARC1; p=reject; rua=mailto:d@test.com",
            dkim_selectors={"google": "v=DKIM1; k=rsa; p=MIG..."},
        )
        result = json.loads(email_security_audit.invoke({"domain": "  test.com  "}))
        assert result["domain"] == "test.com"

    @patch("familiar.tools.pentest_tools.seer")
    def test_seer_dig_returns_empty_list(self, mock_seer):
        """Empty lists for all queries are handled gracefully."""
        mock_seer.dig.return_value = []
        result = _invoke()
        assert result["domain"] == DOMAIN
        assert result["mx"]["has_mx"] is False
        assert result["spf"]["found"] is False
        assert result["dmarc"]["found"] is False

    @patch("familiar.tools.pentest_tools.seer")
    def test_findings_sorted_by_severity(self, mock_seer):
        """Findings are ordered CRITICAL > HIGH > MEDIUM > LOW."""
        # Create a scenario with mixed severities:
        # no SPF + MX (CRITICAL), no DMARC + MX (CRITICAL), no DKIM + MX (HIGH)
        mock_seer.dig.side_effect = _build_dig_side_effect(
            spf=None,
            mx=_make_mx("mx.test.com"),
            dmarc=None,
            dkim_selectors={},
        )
        result = _invoke()
        severities = [f["severity"] for f in result["findings"]]
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for i in range(len(severities) - 1):
            assert severity_order[severities[i]] <= severity_order[severities[i + 1]], (
                f"Findings not sorted: {severities[i]} before {severities[i + 1]}"
            )

    @patch("familiar.tools.pentest_tools.seer")
    def test_non_spf_txt_records_ignored(self, mock_seer):
        """Non-SPF TXT records (e.g. verification strings) are not parsed as SPF."""
        def side_effect(query_domain, record_type, *args):
            if record_type == "TXT" and query_domain == DOMAIN:
                return [
                    {"data": {"text": "google-site-verification=abc123"}},
                    {"data": {"text": "v=spf1 include:_spf.google.com -all"}},
                ]
            if record_type == "MX" and query_domain == DOMAIN:
                return _make_mx("aspmx.l.google.com")
            if record_type == "TXT" and query_domain == f"_dmarc.{DOMAIN}":
                return _make_txt("v=DMARC1; p=reject; rua=mailto:d@test.com")
            if "_domainkey" in query_domain and record_type == "TXT":
                if "google._domainkey" in query_domain:
                    return _make_txt("v=DKIM1; k=rsa; p=MIG...")
                return []
            return []

        mock_seer.dig.side_effect = side_effect
        result = _invoke()
        # Only one SPF record should be detected
        assert result["spf"]["found"] is True
        assert result["spf"]["all_qualifier"] == "fail (strict)"
        multi_spf = _find_findings(result, substr="Multiple SPF")
        assert len(multi_spf) == 0
